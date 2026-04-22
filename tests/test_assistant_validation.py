"""Tests for the assistant vulnerability-validation agent and helpers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from oasis.agent.assistant_invoke import (
    coerce_investigation_budget,
    invoke_assistant_validation,
)
from oasis.helpers.assistant.authz.authz import (
    authz_hits_in_root,
    evaluate_required_controls,
)
from oasis.helpers.assistant.scan.config_audit import run_config_audit
from oasis.helpers.assistant.scan.crypto_scan import run_crypto_scan
from oasis.helpers.assistant.scan.entrypoints import discover_entry_points
from oasis.helpers.assistant.scan.log_filter import run_log_filter_scan
from oasis.helpers.assistant.scan.mitigations import find_mitigations_in_root
import oasis.helpers.assistant.scan.taint as assistant_taint
from oasis.helpers.assistant.scan.secret_scan import run_secret_scan
from oasis.helpers.assistant.scan.trace import (
    enclosing_symbol,
    trace_to_entry_points,
)
from oasis.helpers.assistant.think.investigation_synth import (
    compact_investigation_for_llm,
    enrich_investigation_with_llm_narrative,
)
from oasis.helpers.assistant.verdict.verdict import VerdictInputs, compute_verdict
from oasis.helpers.vuln.validation_patterns import PATTERNS_VERSION
from oasis.helpers.vuln.taxonomy import (
    ALL_VULN_NAMES,
    VulnFamily,
    get_descriptor,
)
from oasis.schemas.analysis import (
    AssistantInvestigationResult,
    AuthzCheckHit,
    CallHop,
    Citation,
    ConfigFinding,
    ControlCheck,
    EntryPointHit,
    ExecutionPath,
    InvestigationScope,
    MitigationHit,
    TaintFlow,
)


def _write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class TestVulnTaxonomy(unittest.TestCase):
    def test_every_vulnerability_has_descriptor(self) -> None:
        """All 25 OASIS vulnerabilities must have a descriptor registered."""
        self.assertEqual(len(ALL_VULN_NAMES), 25)
        for name in ALL_VULN_NAMES:
            descriptor = get_descriptor(name)
            self.assertIsNotNone(descriptor)
            self.assertIn(descriptor.family, set(VulnFamily))

    def test_unknown_vuln_returns_none(self) -> None:
        self.assertIsNone(get_descriptor("Not A Vulnerability"))

    def test_patterns_version_positive(self) -> None:
        self.assertGreater(PATTERNS_VERSION, 0)


class TestEntryPoints(unittest.TestCase):
    def test_flask_route_detected_and_cached(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write(
                root,
                "app.py",
                "from flask import Flask\napp = Flask(__name__)\n"
                "@app.route('/hello')\ndef hello():\n    return 'hi'\n",
            )
            grouped = discover_entry_points(root)
            self.assertIn("flask", grouped)
            self.assertTrue(grouped["flask"])
            grouped2 = discover_entry_points(root)
            self.assertEqual(len(grouped2["flask"]), len(grouped["flask"]))

    def test_aspnet_controller_route_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write(
                root,
                "Controllers/UsersController.cs",
                "[ApiController]\n"
                "[Route(\"api/users\")]\n"
                "public class UsersController : ControllerBase {\n"
                "  [HttpGet(\"{id}\")]\n"
                "  public IActionResult Get(int id) { return Ok(); }\n"
                "}\n",
            )
            grouped = discover_entry_points(root)
            self.assertIn("aspnet", grouped)
            self.assertTrue(grouped["aspnet"])

    def test_wpf_event_handler_detected_as_entry_point(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write(
                root,
                "ViewModels/LoginViewModel.vb",
                "Public Class LoginViewModel\n"
                "  Public Sub Button_Click(sender As Object, e As EventArgs)\n"
                "  End Sub\n"
                "End Class\n",
            )
            grouped = discover_entry_points(root)
            self.assertIn("winforms_wpf_maui", grouped)
            self.assertTrue(grouped["winforms_wpf_maui"])


class TestDotNetSinks(unittest.TestCase):
    def test_ado_net_sql_command_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "Repo.cs",
                "using System.Data.SqlClient;\n"
                "public class Repo {\n"
                "  public void Run(string name) {\n"
                "    var cmd = new SqlCommand(\"SELECT * FROM U WHERE n='\" + name + \"'\", conn);\n"
                "    cmd.ExecuteReader();\n"
                "  }\n"
                "}\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 4, ("sql_execute",), ("http_params",)
            )
            self.assertEqual(flows, [])
            from oasis.helpers.assistant.scan.scan_utils import (
                compile_groups,
                scan_patterns_best_effort,
            )
            from oasis.helpers.vuln.validation_patterns import SINKS

            compiled = compile_groups({"sql_execute": SINKS["sql_execute"]})
            hits = scan_patterns_best_effort(p.parent, compiled)
            kinds = {h.pattern_key for h in hits}
            self.assertIn("sql_execute", kinds)


class TestTraceAndTaint(unittest.TestCase):
    def test_enclosing_symbol_python(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(Path(td), "m.py", "def foo():\n    a = 1\n    return a\n")
            self.assertEqual(enclosing_symbol(p, 2), "foo")

    def test_taint_flow_sqli_to_cursor_execute(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "app.py",
                "from flask import request\n"
                "def search():\n"
                "    q = request.args.get('q')\n"
                "    cursor.execute('SELECT * FROM t WHERE x = ' + q)\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 4, ("sql_execute",), ("http_params",)
            )
            self.assertTrue(flows)
            self.assertEqual(flows[0].sink_kind, "sql_execute")
            self.assertEqual(flows[0].source_kind, "http_params")

    def test_taint_flow_go_short_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "handler.go",
                "func search() {\n"
                "    q := request.args.get('q')\n"
                "    cursor.execute(q)\n"
                "}\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 3, ("sql_execute",), ("http_params",)
            )
            self.assertTrue(flows)
            self.assertEqual(flows[0].source_kind, "http_params")

    def test_taint_flow_java_typed_lhs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "Search.java",
                "void search() {\n"
                '    String q = request.args.get("q");\n'
                "    cursor.execute(q);\n"
                "}\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 3, ("sql_execute",), ("http_params",)
            )
            self.assertTrue(flows)
            self.assertEqual(flows[0].source_kind, "http_params")

    def test_taint_flow_php_dollar_var(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "search.php",
                "<?php\n"
                "function search() {\n"
                "    $q = request.args.get('q');\n"
                "    cursor.execute($q);\n"
                "}\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 4, ("sql_execute",), ("http_params",)
            )
            self.assertTrue(flows)
            self.assertEqual(flows[0].source_kind, "http_params")

    def test_taint_flow_ruby_instance_var(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "search.rb",
                "def search\n"
                "  @q = request.args.get('q')\n"
                "  cursor.execute(@q)\n"
                "end\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 3, ("sql_execute",), ("http_params",)
            )
            self.assertTrue(flows)
            self.assertEqual(flows[0].source_kind, "http_params")

    def test_trace_links_to_entry_point(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app = _write(
                root,
                "app.py",
                "from flask import Flask, request\n"
                "app = Flask(__name__)\n"
                "@app.route('/q')\n"
                "def handler():\n"
                "    cursor.execute('x')\n",
            )
            grouped = discover_entry_points(root)
            paths = trace_to_entry_points(root, app, 5, grouped)
            self.assertTrue(paths)
            self.assertIsNotNone(paths[0].entry_point)


class TestMitigationsAndControls(unittest.TestCase):
    def test_parameterized_sql_counted_as_nullifying(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _write(
                Path(td),
                "db.py",
                "def q():\n    cursor.execute('SELECT 1 WHERE x=%s', (x,))\n",
            )
            hits = find_mitigations_in_root(Path(td), ["sql_parameterized"])
            self.assertTrue(hits)
            self.assertTrue(any(h.nullifies for h in hits))

    def test_control_checks_detect_missing_login_required(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _write(Path(td), "noauth.py", "def get_item(id):\n    return Model.objects.get(id=id)\n")
            hits = authz_hits_in_root(Path(td), ["login_required", "ownership_check"])
            checks = evaluate_required_controls(hits, ["login_required", "ownership_check"])
            self.assertEqual(len(checks), 2)
            self.assertTrue(all(not c.present for c in checks))


class TestConfigSecretsCrypto(unittest.TestCase):
    def test_config_audit_detects_debug_true(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _write(Path(td), "settings.py", "DEBUG = True\n")
            findings = run_config_audit(Path(td))
            self.assertTrue(any(f.kind == "debug_enabled" for f in findings))

    def test_secret_scan_detects_private_key_header(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _write(Path(td), "k.txt", "-----BEGIN RSA PRIVATE KEY-----\nblob\n")
            # .txt is not in default extensions; write a .py with same sentinel to exercise.
            _write(Path(td), "k.py", "KEY = '''-----BEGIN RSA PRIVATE KEY-----'''\n")
            findings = run_secret_scan(Path(td))
            self.assertTrue(any(f.kind == "private_key" for f in findings))

    def test_crypto_scan_detects_md5(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _write(Path(td), "h.py", "import hashlib\nhashlib.md5(b'x')\n")
            findings = run_crypto_scan(Path(td))
            self.assertTrue(any(f.kind == "weak_hash_md5" for f in findings))

    def test_log_filter_detects_logged_password(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _write(Path(td), "a.py", "import logging\nlogging.info('user %s password=%s', u, password)\n")
            findings = run_log_filter_scan(Path(td))
            self.assertTrue(findings)


class TestVerdict(unittest.TestCase):
    def test_verdict_fully_mitigated_when_nullifying_mitigation(self) -> None:
        descriptor = get_descriptor("SQL Injection")
        assert descriptor is not None
        cit = Citation(file_path="f.py", start_line=1, end_line=1, snippet="x")
        inputs = VerdictInputs(
            vulnerability_name="SQL Injection",
            descriptor=descriptor,
            mitigations=[MitigationHit(kind="sql_parameterized", citation=cit, nullifies=True)],
        )
        result = compute_verdict(inputs)
        self.assertEqual(result.status, "fully_mitigated")

    def test_verdict_error_when_only_errors(self) -> None:
        descriptor = get_descriptor("SQL Injection")
        assert descriptor is not None
        inputs = VerdictInputs(
            vulnerability_name="SQL Injection",
            descriptor=descriptor,
            errors=["boom"],
        )
        result = compute_verdict(inputs)
        self.assertEqual(result.status, "error")


class TestInvoke(unittest.TestCase):
    def test_coerce_investigation_budget_clamp(self) -> None:
        self.assertEqual(coerce_investigation_budget("not-a-number"), 20.0)
        self.assertEqual(coerce_investigation_budget(0.1), 2.0)
        self.assertEqual(coerce_investigation_budget(500), 120.0)

    def test_invoke_end_to_end_sqli(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app = _write(
                root,
                "app.py",
                "from flask import Flask, request\n"
                "app = Flask(__name__)\n"
                "@app.route('/search')\n"
                "def search():\n"
                "    q = request.args.get('q')\n"
                "    cursor.execute('SELECT * FROM t WHERE x = ' + q)\n"
                "    return 'ok'\n",
            )
            result = invoke_assistant_validation(
                vulnerability_name="SQL Injection",
                scan_root=root,
                sink_file=app,
                sink_line=6,
                budget_seconds=5,
            )
            self.assertIsInstance(result, AssistantInvestigationResult)
            self.assertEqual(result.family, "flow")
            self.assertIn(
                result.validation_backend,
                {"graph", "sequential", "sequential_fallback"},
            )
            self.assertIn(
                result.status,
                {"confirmed_exploitable", "likely_exploitable", "partial_mitigation"},
            )

    def test_invoke_end_to_end_idor_missing_controls(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app = _write(
                root,
                "app.py",
                "from flask import Flask, request\n"
                "app = Flask(__name__)\n"
                "@app.route('/item/<int:id>')\n"
                "def item(id):\n"
                "    return Model.objects.get(id=id)\n",
            )
            result = invoke_assistant_validation(
                vulnerability_name="Insecure Direct Object Reference",
                scan_root=root,
                sink_file=app,
                sink_line=5,
                budget_seconds=5,
            )
            self.assertEqual(result.family, "access")
            missing = [c.kind for c in result.control_checks if not c.present]
            self.assertIn("login_required", missing)

    def test_invoke_config_family_runs_audit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write(root, "settings.py", "DEBUG = True\nALLOWED_HOSTS = ['*']\n")
            result = invoke_assistant_validation(
                vulnerability_name="Security Misconfiguration",
                scan_root=root,
                budget_seconds=5,
            )
            self.assertEqual(result.family, "config")
            self.assertTrue(result.config_findings)


class TestSchemaRoundtrip(unittest.TestCase):
    def test_assistant_investigation_result_roundtrip(self) -> None:
        cit = Citation(file_path="a.py", start_line=1, end_line=1, snippet="x")
        result = AssistantInvestigationResult(
            vulnerability_name="SQL Injection",
            family="flow",
            status="confirmed_exploitable",
            confidence=0.9,
            summary="s",
            entry_points=[EntryPointHit(framework="flask", label="flask_route", route="/x", citation=cit)],
            execution_paths=[ExecutionPath(entry_point=None, hops=[CallHop(symbol="f", citation=cit)], reached_sink=True)],
            taint_flows=[TaintFlow(source_kind="http_params", sink_kind="sql_execute", source_citation=cit, sink_citation=cit)],
            mitigations=[MitigationHit(kind="sql_parameterized", citation=cit, nullifies=True)],
            authz_checks=[AuthzCheckHit(kind="login_required", citation=cit)],
            control_checks=[ControlCheck(kind="login_required", present=True, citations=[cit])],
            config_findings=[ConfigFinding(kind="debug_enabled", severity="high", citation=cit)],
        )
        dumped = result.model_dump()
        restored = AssistantInvestigationResult.model_validate(dumped)
        self.assertEqual(restored.status, "confirmed_exploitable")
        self.assertEqual(restored.control_checks[0].kind, "login_required")

    def test_investigation_scope_roundtrip(self) -> None:
        scope = InvestigationScope(
            scan_root="/tmp/project",
            sink_file="src/repo.cs",
            sink_line=42,
            vulnerability_name="SQL Injection",
            family="flow",
        )
        result = AssistantInvestigationResult(
            vulnerability_name="SQL Injection",
            family="flow",
            status="unreachable",
            confidence=0.55,
            summary="no entry point found",
            scope=scope,
        )
        restored = AssistantInvestigationResult.model_validate(result.model_dump())
        self.assertIsNotNone(restored.scope)
        assert restored.scope is not None  # for type narrowing
        self.assertEqual(restored.scope.sink_file, "src/repo.cs")
        self.assertEqual(restored.scope.sink_line, 42)
        self.assertEqual(restored.scope.family, "flow")


class TestInvestigationSynth(unittest.TestCase):
    def test_compact_investigation_truncates_long_lists(self) -> None:
        cit = Citation(file_path="a.py", start_line=1, end_line=1, snippet="x")
        eps = [
            EntryPointHit(framework="flask", label="r", route=f"/{i}", citation=cit)
            for i in range(30)
        ]
        result = AssistantInvestigationResult(
            vulnerability_name="XSS",
            family="flow",
            status="likely_exploitable",
            confidence=0.5,
            summary="summary",
            entry_points=eps,
        )
        compact = compact_investigation_for_llm(result)
        self.assertLessEqual(len(compact["entry_points"]), 16)
        last = compact["entry_points"][-1]
        self.assertIsInstance(last, dict)
        self.assertTrue(last.get("_truncated"))

    def test_enrich_sets_narrative_from_llm_response(self) -> None:
        class _FakeOllama:
            def chat(self, model, messages, options=None, **kwargs):
                return {"message": {"content": "## Brief\n\nHello **world**."}}

        cit = Citation(file_path="a.py", start_line=1, end_line=1, snippet="x")
        base = AssistantInvestigationResult(
            vulnerability_name="XSS",
            family="flow",
            status="likely_exploitable",
            confidence=0.5,
            summary="deterministic",
            citations=[cit],
        )
        out = enrich_investigation_with_llm_narrative(
            base,
            ollama_manager=_FakeOllama(),  # type: ignore[arg-type]
            chat_model="fake-model",
        )
        self.assertIn("Brief", out.narrative_markdown)
        self.assertEqual(out.synthesis_model, "fake-model")
        self.assertIsNone(out.synthesis_error)

    def test_enrich_no_op_when_model_empty(self) -> None:
        cit = Citation(file_path="a.py", start_line=1, end_line=1, snippet="x")
        base = AssistantInvestigationResult(
            vulnerability_name="XSS",
            family="flow",
            status="likely_exploitable",
            confidence=0.5,
            summary="x",
            citations=[cit],
        )
        out = enrich_investigation_with_llm_narrative(
            base,
            ollama_manager=object(),  # type: ignore[arg-type]
            chat_model="   ",
        )
        self.assertEqual(out.narrative_markdown, "")
        self.assertIsNone(out.synthesis_model)


class TestAssistantTaintAssignmentParsing(unittest.TestCase):
    def test_generic_fallback_rejects_logical_and_lhs(self) -> None:
        self.assertIsNone(assistant_taint._parse_assignment("foo && bar = baz"))

    def test_generic_fallback_rejects_comparison_tokens_in_lhs(self) -> None:
        self.assertIsNone(assistant_taint._parse_assignment("if (c == d && e = f"))

    def test_generic_fallback_rejects_ternary_heuristic(self) -> None:
        self.assertIsNone(assistant_taint._parse_assignment("x ? y : z = answer"))

    def test_js_like_simple_assignment(self) -> None:
        parsed = assistant_taint._parse_assignment('value = request.args.get("q")')
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed[0], "value")

    def test_go_short_decl_assignment(self) -> None:
        parsed = assistant_taint._parse_assignment('id := uuid.New().String()')
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed[0], "id")

    def test_generic_fallback_accepts_typed_lhs(self) -> None:
        parsed = assistant_taint._parse_assignment(
            'final String payload = req.getParameter("id")'
        )
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed[0], "payload")

    def test_generic_fallback_accepts_rhs_ternary(self) -> None:
        parsed = assistant_taint._parse_assignment("Result r = cond ? x : y")
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed[0], "r")

    def test_generic_fallback_rejects_member_lhs(self) -> None:
        self.assertIsNone(assistant_taint._parse_assignment("self.foo = bar"))

    def test_generic_fallback_rejects_subscript_lhs(self) -> None:
        self.assertIsNone(assistant_taint._parse_assignment("items[i] = x"))

    def test_generic_fallback_rejects_tuple_unpack_lhs(self) -> None:
        self.assertIsNone(assistant_taint._parse_assignment("a, b = pair"))


class TestAssistantTaintVariableOnSinkLine(unittest.TestCase):
    def test_php_var_plain(self) -> None:
        self.assertTrue(
            assistant_taint._variable_referenced_on_sink_line("$u", 'cursor.execute($u)')
        )

    def test_php_var_arrow(self) -> None:
        self.assertTrue(
            assistant_taint._variable_referenced_on_sink_line(
                "$row", '$db->query($row["id"])'
            )
        )

    def test_php_var_bracket(self) -> None:
        self.assertTrue(
            assistant_taint._variable_referenced_on_sink_line("$k", "x($data[$k])")
        )

    def test_php_var_interpolated_braces(self) -> None:
        self.assertTrue(
            assistant_taint._variable_referenced_on_sink_line(
                "$id", 'echo "x${id}y";'
            )
        )

    def test_ruby_ivar_string_interpolation(self) -> None:
        self.assertTrue(
            assistant_taint._variable_referenced_on_sink_line(
                "@name", 'puts "hi #{@name}"'
            )
        )

    def test_ruby_ivar_predicate_suffix(self) -> None:
        self.assertTrue(
            assistant_taint._variable_referenced_on_sink_line(
                "@ok", "render if @ok?"
            )
        )

    def test_ruby_ivar_bang_suffix(self) -> None:
        self.assertTrue(
            assistant_taint._variable_referenced_on_sink_line(
                "@done", "notify @done!"
            )
        )

    def test_negative_php_prefix_of_longer_var(self) -> None:
        self.assertFalse(
            assistant_taint._variable_referenced_on_sink_line("$x", "$xyz = 1")
        )

    def test_negative_ruby_ivar_prefix(self) -> None:
        self.assertFalse(
            assistant_taint._variable_referenced_on_sink_line("@foo", "@foo_bar.nil?")
        )


if __name__ == "__main__":
    unittest.main()
