"""Tests for the assistant vulnerability-validation agent and helpers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Optional
from unittest import mock

from oasis.agent.assistant_invoke import (
    coerce_investigation_budget,
    invoke_assistant_validation,
)
from oasis.helpers.assistant.authz.authz import (
    authz_hits_in_root,
    evaluate_required_controls,
)
from oasis.helpers.assistant.batch import (
    annotate_rows_with_validation,
    summarize_validation_stats,
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
from oasis.helpers.assistant.web.result_presentation import (
    apply_presentation_filter_to_result,
)
from oasis.helpers.assistant.web.sink_resolution import (
    coerce_positive_int_line,
    resolve_sink_from_finding_indices,
)
from oasis.helpers.assistant.scan.scan_utils import (
    compile_groups,
    scan_patterns_best_effort,
)
from oasis.helpers.vuln.validation_patterns import (
    PATTERNS_VERSION,
    SINKS,
    all_pattern_groups,
)
from oasis.helpers.vuln.taxonomy import (
    ALL_VULN_NAMES,
    VulnFamily,
    get_descriptor,
)
from oasis.schemas.analysis import (
    AssistantInvestigationResult,
    AuthzCheckHit,
    CallHop,
    ChunkDeepAnalysis,
    Citation,
    ConfigFinding,
    ControlCheck,
    EntryPointHit,
    ExecutionPath,
    InvestigationScope,
    MitigationHit,
    TaintFlow,
    VulnerabilityFinding,
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


class TestCatalogLanguageCoverage(unittest.TestCase):
    def test_new_language_frameworks_registered(self) -> None:
        groups = all_pattern_groups()
        entry_points = groups["entry_points"]
        for framework in ("go", "rust", "kotlin", "scala"):
            self.assertIn(framework, entry_points)
            self.assertTrue(entry_points[framework])

    def test_patterns_version_bumped_with_language_support(self) -> None:
        self.assertGreaterEqual(PATTERNS_VERSION, 4)

    def test_refinement_patterns_registered(self) -> None:
        groups = all_pattern_groups()
        sources = groups["sources"]["http_params"]
        sinks = groups["sinks"]
        mitigations = groups["mitigations"]["sql_parameterized"]
        self.assertIn(r"\bcall\.parameters\s*\[", sources)
        self.assertIn(r"\bcall\.receive\s*[<(]", sources)
        self.assertIn(r"\brequest\.getQueryString\s*\(", sources)
        self.assertIn(r"\bvars\s*\[", sources)
        self.assertIn(r"\bchi\.URLParam\s*\(", sources)
        self.assertIn(
            r"\.(?:QueryRowx|Queryx|NamedExec|NamedQuery)\s*\(", sinks["sql_execute"]
        )
        self.assertIn(r"\.(?:get_results?|get_result)\b", sinks["sql_execute"])
        self.assertIn(r"\brender\s+inline:", sinks["html_render"])
        self.assertTrue(any(r"\$\d+" in p for p in mitigations))


class TestGoSupport(unittest.TestCase):
    def test_go_entry_points_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write(
                root,
                "main.go",
                "package main\n\n"
                "func setup() {\n"
                '    r.GET("/ping", pingHandler)\n'
                '    http.HandleFunc("/debug", debugHandler)\n'
                "}\n",
            )
            grouped = discover_entry_points(root)
            self.assertIn("go", grouped)

    def test_taint_flow_go_form_value_to_exec_command(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "handler.go",
                "func handler(w http.ResponseWriter, r *http.Request) {\n"
                '    cmd := r.FormValue("cmd")\n'
                '    exec.Command("sh", "-c", cmd).Run()\n'
                "}\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 3, ("os_exec",), ("http_params",)
            )
            self.assertTrue(flows)
            self.assertEqual(flows[0].source_kind, "http_params")
            self.assertEqual(flows[0].sink_kind, "os_exec")

    def test_go_gorm_placeholder_nullifying(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _write(
                Path(td),
                "gorm.go",
                "func q(name string) {\n"
                '    db.Where("name = ?", name).First(&u)\n'
                "}\n",
            )
            hits = find_mitigations_in_root(Path(td), ["sql_parameterized"])
            self.assertTrue(any(h.nullifies for h in hits))

    def test_go_query_row_sql_sink(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "store.go",
                "func load(id string) {\n"
                '    row := db.QueryRow("SELECT name FROM u WHERE id = " + id)\n'
                "}\n",
            )
            compiled = compile_groups({"sql_execute": SINKS["sql_execute"]})
            hits = scan_patterns_best_effort(p.parent, compiled)
            self.assertTrue(any(h.pattern_key == "sql_execute" for h in hits))

    def test_go_sqlx_gorm_sinks_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "store.go",
                "func load(id string) {\n"
                '    row := db.QueryRowx("SELECT name FROM u WHERE id = " + id)\n'
                "}\n",
            )
            compiled = compile_groups({"sql_execute": SINKS["sql_execute"]})
            hits = scan_patterns_best_effort(p.parent, compiled)
            self.assertTrue(any(h.pattern_key == "sql_execute" for h in hits))

    def test_go_ordinal_placeholder_nullifies(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _write(
                Path(td),
                "store.go",
                "func load(id string) {\n"
                '    row := db.QueryRow("SELECT * FROM u WHERE id = $1", id)\n'
                "}\n",
            )
            hits = find_mitigations_in_root(Path(td), ["sql_parameterized"])
            self.assertTrue(any(h.nullifies for h in hits))

    def test_currency_amount_not_treated_as_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _write(
                Path(td),
                "pricing.go",
                "func describe(total int) string {\n"
                '    return fmt.Sprintf("You earned $100 this month", total)\n'
                "}\n",
            )
            hits = find_mitigations_in_root(Path(td), ["sql_parameterized"])
            self.assertFalse(hits)

    def test_taint_flow_gorilla_vars_to_sql_sink(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "handler.go",
                "func userHandler(w http.ResponseWriter, r *http.Request) {\n"
                '    id := vars["id"]\n'
                '    db.QueryRow("SELECT name FROM u WHERE id = " + id)\n'
                "}\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 3, ("sql_execute",), ("http_params",)
            )
            self.assertTrue(flows)
            self.assertEqual(flows[0].source_kind, "http_params")
            self.assertEqual(flows[0].sink_kind, "sql_execute")


class TestJavaSupport(unittest.TestCase):
    def test_taint_flow_get_parameter_to_execute_query(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "List.java",
                "void list(HttpServletRequest request) throws Exception {\n"
                '    String name = request.getParameter("name");\n'
                '    st.executeQuery("SELECT * FROM u WHERE n=\'" + name + "\'");\n'
                "}\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 3, ("sql_execute",), ("http_params",)
            )
            self.assertTrue(flows)
            self.assertEqual(flows[0].source_kind, "http_params")
            self.assertEqual(flows[0].sink_kind, "sql_execute")

    def test_jdbc_setter_parameterized_nullifies(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _write(
                Path(td),
                "Dao.java",
                'PreparedStatement ps = conn.prepareStatement("SELECT * FROM u WHERE n = ?");\n'
                "ps.setString(1, name);\n",
            )
            hits = find_mitigations_in_root(Path(td), ["sql_parameterized"])
            self.assertTrue(any(h.nullifies for h in hits))

    def test_process_builder_sink_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "Run.java",
                'void run(String input) {\n'
                '    new ProcessBuilder("/bin/sh", "-c", input).start();\n'
                "}\n",
            )
            compiled = compile_groups({"os_exec": SINKS["os_exec"]})
            hits = scan_patterns_best_effort(p.parent, compiled)
            self.assertTrue(any(h.pattern_key == "os_exec" for h in hits))

    def test_spring_preauthorize_control_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _write(
                Path(td),
                "Api.java",
                "@PreAuthorize(\"hasRole('ADMIN')\")\n"
                "public Data get(Long id) { return repo.findById(id); }\n",
            )
            hits = authz_hits_in_root(Path(td), ["login_required"])
            self.assertTrue(any(h.kind == "login_required" for h in hits))


class TestRubySupport(unittest.TestCase):
    def test_taint_flow_params_to_find_by_sql(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "user.rb",
                "def show\n"
                "  id = params[:id]\n"
                '  User.find_by_sql("SELECT * FROM users WHERE id = #{id}")\n'
                "end\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 3, ("sql_execute",), ("http_params",)
            )
            self.assertTrue(flows)
            self.assertEqual(flows[0].source_kind, "http_params")
            self.assertEqual(flows[0].sink_kind, "sql_execute")

    def test_ruby_redirect_to_sink(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "session.rb",
                "def after_login\n"
                "  redirect_to params[:return_to]\n"
                "end\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 2, ("redirect_call",), ("http_params",)
            )
            self.assertTrue(flows)
            self.assertEqual(flows[0].sink_kind, "redirect_call")

    def test_ruby_strong_params_soft_mitigation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _write(
                Path(td),
                "ctrl.rb",
                "def create\n"
                "  User.create(params.require(:user).permit(:name))\n"
                "end\n",
            )
            hits = find_mitigations_in_root(Path(td), ["schema_validate"])
            self.assertTrue(hits)
            self.assertFalse(any(h.nullifies for h in hits))

    def test_rails_placeholder_nullifying(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _write(
                Path(td),
                "user.rb",
                "def q(name)\n"
                '  User.where("name = ?", name)\n'
                "end\n",
            )
            hits = find_mitigations_in_root(Path(td), ["sql_parameterized"])
            self.assertTrue(any(h.nullifies for h in hits))

    def test_rails_render_inline_sink_with_taint(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "comments.rb",
                "def render_comment\n"
                '  render inline: "Hello #{params[:name]}"\n'
                "end\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 2, ("html_render",), ("http_params",)
            )
            self.assertTrue(flows)
            self.assertEqual(flows[0].source_kind, "http_params")
            self.assertEqual(flows[0].sink_kind, "html_render")


class TestRustSupport(unittest.TestCase):
    def test_enclosing_symbol_rust_fn(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(Path(td), "main.rs", "fn run(cmd: String) {\n    let x = 1;\n}\n")
            self.assertEqual(enclosing_symbol(p, 2), "run")

    def test_taint_flow_axum_query_to_command(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "handler.rs",
                "async fn handle(Query(q): Query<HashMap<String, String>>) {\n"
                '    Command::new("sh").arg(q).output();\n'
                "}\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 2, ("os_exec",), ("http_params",)
            )
            self.assertTrue(flows)
            self.assertEqual(flows[0].source_kind, "http_params")
            self.assertEqual(flows[0].sink_kind, "os_exec")

    def test_rust_reqwest_sink_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "fetch.rs",
                "async fn go(u: &str) {\n"
                "    let resp = reqwest::get(u).await;\n"
                "}\n",
            )
            compiled = compile_groups({"url_fetch": SINKS["url_fetch"]})
            hits = scan_patterns_best_effort(p.parent, compiled)
            self.assertTrue(any(h.pattern_key == "url_fetch" for h in hits))

    def test_rust_axum_entry_point_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write(
                root,
                "app.rs",
                "let app = Router::new()\n"
                '    .route("/users", get(list_users));\n',
            )
            grouped = discover_entry_points(root)
            self.assertIn("rust", grouped)

    def test_rust_diesel_sql_sink_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "users.rs",
                "fn list_users(conn: &PgConnection) {\n"
                '    let rows = diesel::sql_query("SELECT * FROM users")\n'
                "        .get_results::<User>(conn);\n"
                "}\n",
            )
            compiled = compile_groups({"sql_execute": SINKS["sql_execute"]})
            hits = scan_patterns_best_effort(p.parent, compiled)
            self.assertTrue(any(h.pattern_key == "sql_execute" for h in hits))


class TestKotlinScalaEntryPoints(unittest.TestCase):
    def test_ktor_route_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write(
                root,
                "Server.kt",
                "fun Application.module() {\n"
                "    routing {\n"
                '        get("/users") { call.respond(users) }\n'
                "    }\n"
                "}\n",
            )
            grouped = discover_entry_points(root)
            self.assertIn("kotlin", grouped)

    def test_play_action_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write(
                root,
                "Home.scala",
                "class HomeController extends AbstractController(cc) {\n"
                "  def index = Action { Ok(views.html.index()) }\n"
                "}\n",
            )
            grouped = discover_entry_points(root)
            self.assertIn("scala", grouped)

    def test_taint_flow_ktor_parameters_to_execute_query(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "Users.kt",
                "fun handle(call: ApplicationCall, st: Statement) {\n"
                '    val id = call.parameters["id"]\n'
                '    st.executeQuery("SELECT * FROM u WHERE id = " + id)\n'
                "}\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 3, ("sql_execute",), ("http_params",)
            )
            self.assertTrue(flows)
            self.assertEqual(flows[0].source_kind, "http_params")
            self.assertEqual(flows[0].sink_kind, "sql_execute")

    def test_taint_flow_ktor_receive_to_execute_query(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "Search.kt",
                "suspend fun handle(call: ApplicationCall, st: Statement) {\n"
                "    val q = call.receive<String>()\n"
                '    st.executeQuery("SELECT * FROM u WHERE n = " + q)\n'
                "}\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 3, ("sql_execute",), ("http_params",)
            )
            self.assertTrue(flows)
            self.assertEqual(flows[0].source_kind, "http_params")
            self.assertEqual(flows[0].sink_kind, "sql_execute")

    def test_taint_flow_play_query_string_to_execute_query(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "Search.scala",
                "def search = Action { implicit request =>\n"
                '    val name = request.getQueryString("name")\n'
                '    stmt.executeQuery("SELECT * FROM u WHERE n = " + name)\n'
                "}\n",
            )
            flows = assistant_taint.detect_flows_for_descriptor(
                p, 3, ("sql_execute",), ("http_params",)
            )
            self.assertTrue(flows)
            self.assertEqual(flows[0].source_kind, "http_params")
            self.assertEqual(flows[0].sink_kind, "sql_execute")


class TestCrossLanguageSinks(unittest.TestCase):
    def test_csharp_http_client_and_redirect(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "Fetch.cs",
                "public async Task Go(string url) {\n"
                "    var client = new HttpClient();\n"
                "    var body = await client.GetStringAsync(url);\n"
                "    Response.Redirect(body);\n"
                "}\n",
            )
            compiled = compile_groups(
                {
                    "url_fetch": SINKS["url_fetch"],
                    "redirect_call": SINKS["redirect_call"],
                }
            )
            hits = scan_patterns_best_effort(p.parent, compiled)
            kinds = {h.pattern_key for h in hits}
            self.assertIn("url_fetch", kinds)
            self.assertIn("redirect_call", kinds)

    def test_js_template_render_sink(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = _write(
                Path(td),
                "app.js",
                "app.get('/profile', (req, res) => {\n"
                "  res.render('profile', { name: req.query.name });\n"
                "});\n",
            )
            compiled = compile_groups({"html_render": SINKS["html_render"]})
            hits = scan_patterns_best_effort(p.parent, compiled)
            self.assertTrue(
                any("res.render" in h.line_text for h in hits if h.pattern_key == "html_render")
            )


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

    def test_enrich_invalid_temperature_falls_back_and_warns(self) -> None:
        class _FakeOllama:
            def __init__(self) -> None:
                self.options = None

            def chat(self, model, messages, options=None, **kwargs):
                self.options = options
                return {"message": {"content": "ok"}}

        base = AssistantInvestigationResult(
            vulnerability_name="XSS",
            family="flow",
            status="likely_exploitable",
            confidence=0.5,
            summary="deterministic",
        )
        synth_logger_name = "oasis.helpers.assistant.think.investigation_synth"
        fake = _FakeOllama()
        with self.assertLogs(synth_logger_name, level="WARNING") as captured:
            out = enrich_investigation_with_llm_narrative(
                base,
                ollama_manager=fake,  # type: ignore[arg-type]
                chat_model="fake-model",
                temperature="not-a-float",  # type: ignore[arg-type]
            )
        self.assertEqual(fake.options, {"temperature": 0.2})
        self.assertIsInstance(fake.options["temperature"], float)
        self.assertTrue(
            any("invalid assistant synthesis temperature" in msg.lower() for msg in captured.output),
            f"Expected invalid temperature warning, got: {captured.output!r}",
        )
        self.assertEqual(out.synthesis_model, "fake-model")

    def test_enrich_clamps_out_of_range_temperature_and_warns(self) -> None:
        class _FakeOllama:
            def __init__(self) -> None:
                self.options = None

            def chat(self, model, messages, options=None, **kwargs):
                self.options = options
                return {"message": {"content": "ok"}}

        base = AssistantInvestigationResult(
            vulnerability_name="XSS",
            family="flow",
            status="likely_exploitable",
            confidence=0.5,
            summary="deterministic",
        )
        synth_logger_name = "oasis.helpers.assistant.think.investigation_synth"
        for raw_temp, expected in ((9, 1.0), (-0.5, 0.0)):
            with self.subTest(temperature=raw_temp):
                fake = _FakeOllama()
                with self.assertLogs(synth_logger_name, level="WARNING") as captured:
                    enrich_investigation_with_llm_narrative(
                        base,
                        ollama_manager=fake,  # type: ignore[arg-type]
                        chat_model="fake-model",
                        temperature=raw_temp,  # type: ignore[arg-type]
                    )
                self.assertEqual(fake.options, {"temperature": expected})
                self.assertTrue(
                    any("clamping" in msg.lower() for msg in captured.output),
                    f"Expected clamp warning, got: {captured.output!r}",
                )


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


class TestSinkResolution(unittest.TestCase):
    """Sink resolution from finding indices (executive aggregate + direct vuln)."""

    @staticmethod
    def _vuln_payload(file_path: str, snippet_line: int = 113) -> dict:
        return {
            "report_type": "vulnerability",
            "files": [
                {
                    "file_path": file_path,
                    "chunk_analyses": [
                        {
                            "start_line": 100,
                            "findings": [
                                {"snippet_start_line": snippet_line},
                            ],
                        }
                    ],
                }
            ],
        }

    def test_coerce_positive_int_line_accepts_int_and_integral_float(self) -> None:
        self.assertEqual(coerce_positive_int_line(113), 113)
        self.assertEqual(coerce_positive_int_line(113.0), 113)
        for invalid in (0, -3, 1.5, float("nan"), "113", True, None):
            with self.subTest(value=invalid):
                self.assertIsNone(coerce_positive_int_line(invalid))

    def test_resolve_from_primary_when_files_present(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = _write(root, "test_files/vulnerable.sh", "#!/bin/sh\necho hi\n")
            payload = self._vuln_payload("test_files/vulnerable.sh", snippet_line=107)
            sink_file, sink_line = resolve_sink_from_finding_indices(
                payload, None, fi=0, ci=0, gi=0, scan_root=root
            )
            self.assertEqual(sink_file, target.resolve())
            self.assertEqual(sink_line, 107)

    def test_resolve_prefers_scope_when_primary_has_no_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = _write(root, "src/Vulnerable.cs", "// stub\n")
            primary = {"report_type": "executive_summary"}
            scope = self._vuln_payload("src/Vulnerable.cs", snippet_line=42)
            sink_file, sink_line = resolve_sink_from_finding_indices(
                primary, scope, fi=0, ci=0, gi=0, scan_root=root
            )
            self.assertEqual(sink_file, target.resolve())
            self.assertEqual(sink_line, 42)

    def test_resolve_returns_none_when_neither_payload_has_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sink_file, sink_line = resolve_sink_from_finding_indices(
                {"report_type": "executive_summary"},
                {"report_type": "vulnerability"},
                fi=0,
                ci=0,
                gi=0,
                scan_root=root,
            )
            self.assertIsNone(sink_file)
            self.assertIsNone(sink_line)

    def test_resolve_accepts_float_integral_snippet_line(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write(root, "a.py", "x = 1\n")
            payload = self._vuln_payload("a.py", snippet_line=12)
            payload["files"][0]["chunk_analyses"][0]["findings"][0]["snippet_start_line"] = 12.0
            _, sink_line = resolve_sink_from_finding_indices(
                payload, None, fi=0, ci=0, gi=0, scan_root=root
            )
            self.assertEqual(sink_line, 12)

    def test_resolve_drops_non_integral_float(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write(root, "a.py", "x = 1\n")
            payload = self._vuln_payload("a.py", snippet_line=10)
            payload["files"][0]["chunk_analyses"][0]["findings"][0]["snippet_start_line"] = 10.5
            payload["files"][0]["chunk_analyses"][0]["start_line"] = 10.5
            _, sink_line = resolve_sink_from_finding_indices(
                payload, None, fi=0, ci=0, gi=0, scan_root=root
            )
            self.assertIsNone(sink_line)

    def test_resolve_rejects_path_outside_scan_root(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            payload = self._vuln_payload("../escape.txt", snippet_line=1)
            sink_file, _ = resolve_sink_from_finding_indices(
                payload, None, fi=0, ci=0, gi=0, scan_root=root
            )
            self.assertIsNone(sink_file)


class TestPresentationFilter(unittest.TestCase):
    """Post-verdict filtering of entry_points anchored on scope.sink_file."""

    @staticmethod
    def _make_result(
        family: str,
        entry_points: list,
        execution_paths: list,
        sink_rel: Optional[str] = None,
    ) -> AssistantInvestigationResult:
        scope = (
            InvestigationScope(
                scan_root="/tmp/proj",
                sink_file=sink_rel,
                sink_line=1 if sink_rel else None,
                vulnerability_name="vuln",
                family=family,  # type: ignore[arg-type]
            )
            if sink_rel
            else None
        )
        return AssistantInvestigationResult(
            vulnerability_name="vuln",
            family=family,  # type: ignore[arg-type]
            status="insufficient_signal",
            confidence=0.3,
            summary="x",
            scope=scope,
            entry_points=entry_points,
            execution_paths=execution_paths,
        )

    def test_flow_keeps_only_eps_linked_to_execution_paths(self) -> None:
        cit_a = Citation(file_path="vulnerable.py", start_line=113, end_line=113)
        cit_b = Citation(file_path="other.py", start_line=10, end_line=10)
        ep_a = EntryPointHit(framework="flask", label="flask_route", route="/transfer", citation=cit_a)
        ep_b = EntryPointHit(framework="flask", label="flask_route", route="/x", citation=cit_b)
        path = ExecutionPath(entry_point=ep_b, hops=[], reached_sink=True)
        result = self._make_result("flow", [ep_a, ep_b], [path], sink_rel="other.py")
        filtered = apply_presentation_filter_to_result(result)
        routes = [ep.route for ep in filtered.entry_points]
        self.assertEqual(routes, ["/x"])

    def test_flow_falls_back_to_sink_file_match_when_no_path_links(self) -> None:
        cit_a = Citation(file_path="vulnerable.py", start_line=113, end_line=113)
        cit_b = Citation(file_path="test_files/vulnerable.sh", start_line=107, end_line=107)
        ep_py = EntryPointHit(framework="flask", label="flask_route", route="/transfer", citation=cit_a)
        ep_sh = EntryPointHit(framework="shell", label="shell_handler", route="exec", citation=cit_b)
        result = self._make_result("flow", [ep_py, ep_sh], [], sink_rel="test_files/vulnerable.sh")
        filtered = apply_presentation_filter_to_result(result)
        self.assertEqual([ep.route for ep in filtered.entry_points], ["exec"])

    def test_flow_returns_empty_when_neither_path_nor_sink_file_match(self) -> None:
        cit = Citation(file_path="vulnerable.py", start_line=113, end_line=113)
        ep = EntryPointHit(framework="flask", label="flask_route", route="/transfer", citation=cit)
        result = self._make_result("flow", [ep], [], sink_rel="test_files/vulnerable.sh")
        filtered = apply_presentation_filter_to_result(result)
        self.assertEqual(filtered.entry_points, [])
        self.assertEqual(filtered.status, "insufficient_signal")
        self.assertAlmostEqual(filtered.confidence, 0.3, places=2)

    def test_access_keeps_only_eps_in_sink_file(self) -> None:
        cit_py = Citation(file_path="vulnerable.py", start_line=113, end_line=113)
        cit_cs = Citation(file_path="src/Vulnerable.cs", start_line=12, end_line=12)
        ep_py = EntryPointHit(framework="flask", label="flask_route", route="/transfer", citation=cit_py)
        ep_cs = EntryPointHit(framework="aspnet", label="aspnet_route", route="/api/x", citation=cit_cs)
        result = self._make_result("access", [ep_py, ep_cs], [], sink_rel="src/Vulnerable.cs")
        filtered = apply_presentation_filter_to_result(result)
        self.assertEqual([ep.route for ep in filtered.entry_points], ["/api/x"])

    def test_access_returns_empty_when_no_ep_in_sink_file(self) -> None:
        cit = Citation(file_path="vulnerable.py", start_line=113, end_line=113)
        ep = EntryPointHit(framework="flask", label="flask_route", route="/transfer", citation=cit)
        result = self._make_result("access", [ep], [], sink_rel="src/Vulnerable.cs")
        filtered = apply_presentation_filter_to_result(result)
        self.assertEqual(filtered.entry_points, [])

    def test_config_family_passes_through(self) -> None:
        cit = Citation(file_path="vulnerable.py", start_line=15, end_line=15)
        ep = EntryPointHit(framework="flask", label="flask_route", route="/x", citation=cit)
        result = self._make_result("config", [ep], [], sink_rel="src/Vulnerable.java")
        filtered = apply_presentation_filter_to_result(result)
        self.assertEqual(filtered.entry_points, result.entry_points)

    def test_no_scope_passes_through_unchanged(self) -> None:
        cit = Citation(file_path="vulnerable.py", start_line=113, end_line=113)
        ep = EntryPointHit(framework="flask", label="flask_route", route="/x", citation=cit)
        result = self._make_result("flow", [ep], [], sink_rel=None)
        filtered = apply_presentation_filter_to_result(result)
        self.assertIs(filtered, result)

    def test_filter_rebuilds_citations_to_match_filtered_eps(self) -> None:
        cit_noise = Citation(file_path="vulnerable.py", start_line=113, end_line=113)
        cit_real = Citation(file_path="src/Vulnerable.cs", start_line=12, end_line=12)
        ep_noise = EntryPointHit(framework="flask", label="r", route="/x", citation=cit_noise)
        ep_real = EntryPointHit(framework="aspnet", label="r", route="/y", citation=cit_real)
        result = AssistantInvestigationResult(
            vulnerability_name="vuln",
            family="access",
            status="confirmed_exploitable",
            confidence=0.85,
            summary="x",
            scope=InvestigationScope(
                scan_root="/tmp/proj",
                sink_file="src/Vulnerable.cs",
                sink_line=12,
                vulnerability_name="vuln",
                family="access",
            ),
            entry_points=[ep_noise, ep_real],
            citations=[cit_noise, cit_real],
        )
        filtered = apply_presentation_filter_to_result(result)
        cit_paths = {c.file_path for c in filtered.citations}
        self.assertNotIn("vulnerable.py", cit_paths)
        self.assertIn("src/Vulnerable.cs", cit_paths)

    def test_flow_filter_tolerates_missing_or_partial_citations(self) -> None:
        class _FakeScope:
            sink_file = "src/Vulnerable.cs"

        class _FakeResult:
            def __init__(self) -> None:
                self.scope = _FakeScope()
                self.family = "flow"
                self.entry_points = [
                    mock.Mock(framework="flask", label="r", route="/a", citation=None),
                    mock.Mock(
                        framework="aspnet",
                        label="r",
                        route="/b",
                        citation=mock.Mock(file_path="src/Vulnerable.cs"),
                    ),
                ]
                self.execution_paths = [
                    mock.Mock(entry_point=mock.Mock(framework="f", label="x", route="/x", citation=None), hops=[])
                ]
                self.taint_flows = [mock.Mock(source_citation=None, sink_citation=None)]
                self.mitigations = [mock.Mock(citation=None)]
                self.authz_checks = [mock.Mock(citation=None)]
                self.control_checks = [mock.Mock(citations=[None])]
                self.config_findings = [mock.Mock(citation=None)]
                self.citations = []

            def model_copy(self, update):
                for key, value in update.items():
                    setattr(self, key, value)
                return self

        result = _FakeResult()
        filtered = apply_presentation_filter_to_result(result)  # type: ignore[arg-type]
        self.assertIs(filtered, result)
        self.assertEqual([ep.route for ep in filtered.entry_points], ["/b"])
        self.assertEqual(len(filtered.citations), 1)
        self.assertEqual(getattr(filtered.citations[0], "file_path", None), "src/Vulnerable.cs")

    def test_flow_matches_entry_points_by_content_key(self) -> None:
        citation = Citation(file_path="src/Vulnerable.cs", start_line=12, end_line=12)
        result = AssistantInvestigationResult(
            vulnerability_name="Broken Access Control",
            family="flow",
            status="insufficient_signal",
            confidence=0.5,
            summary="x",
            scope=InvestigationScope(
                scan_root="/tmp/proj",
                sink_file="src/Vulnerable.cs",
                sink_line=12,
                vulnerability_name="Broken Access Control",
                family="flow",
            ),
            entry_points=[
                EntryPointHit(framework="flask", label="x", route="/x", citation=citation),
                EntryPointHit(framework="flask", label="other", route="/x", citation=citation),
            ],
            execution_paths=[
                ExecutionPath(
                    entry_point=EntryPointHit(
                        framework="flask",
                        label="x",
                        route="/x",
                        citation=citation,
                    ),
                    hops=[],
                )
            ],
        )
        filtered = apply_presentation_filter_to_result(result)
        self.assertEqual(len(filtered.entry_points), 1)
        self.assertEqual(filtered.entry_points[0].label, "x")


class TestScopeFocusInLLMPayload(unittest.TestCase):
    """``compact_investigation_for_llm`` exposes scope_focus first."""

    def test_scope_focus_present_when_scope_set(self) -> None:
        scope = InvestigationScope(
            scan_root="/tmp/proj",
            sink_file="src/Vulnerable.cs",
            sink_line=42,
            vulnerability_name="Authentication Issues",
            family="access",
        )
        result = AssistantInvestigationResult(
            vulnerability_name="Authentication Issues",
            family="access",
            status="confirmed_exploitable",
            confidence=0.85,
            summary="x",
            scope=scope,
        )
        payload = compact_investigation_for_llm(result)
        keys = list(payload.keys())
        self.assertEqual(keys[0], "scope_focus")
        focus = payload["scope_focus"]
        self.assertEqual(focus["sink_file"], "src/Vulnerable.cs")
        self.assertEqual(focus["sink_line"], 42)
        self.assertEqual(focus["family"], "access")
        self.assertEqual(focus["verdict_status"], "confirmed_exploitable")

    def test_scope_focus_minimal_when_scope_missing(self) -> None:
        result = AssistantInvestigationResult(
            vulnerability_name="XSS",
            family="flow",
            status="insufficient_signal",
            confidence=0.3,
            summary="x",
        )
        payload = compact_investigation_for_llm(result)
        focus = payload["scope_focus"]
        self.assertNotIn("sink_file", focus)
        self.assertEqual(focus["vulnerability_name"], "XSS")

    def test_scope_focus_computed_value_wins_over_model_dump_collision(self) -> None:
        scope = InvestigationScope(
            scan_root="/tmp/proj",
            sink_file="src/real.py",
            sink_line=42,
            vulnerability_name="XSS",
            family="flow",
        )
        result = AssistantInvestigationResult(
            vulnerability_name="XSS",
            family="flow",
            status="likely_exploitable",
            confidence=0.7,
            summary="x",
            scope=scope,
        )
        with mock.patch.object(
            AssistantInvestigationResult,
            "model_dump",
            autospec=True,
            return_value={
                "scope_focus": {"sink_file": "src/fake.py", "sink_line": 999},
                "entry_points": [],
            },
        ):
            payload = compact_investigation_for_llm(result)
        focus = payload["scope_focus"]
        self.assertEqual(focus["sink_file"], "src/real.py")
        self.assertEqual(focus["sink_line"], 42)
        self.assertEqual(focus["verdict_status"], "likely_exploitable")

    def test_scope_focus_collision_emits_warning_and_local_value_wins(self) -> None:
        """Schema drift on the dumped 'scope_focus' key must surface a WARNING
        log message; the locally computed value must still win in the payload."""
        scope = InvestigationScope(
            scan_root="/tmp/proj",
            sink_file="src/real.py",
            sink_line=42,
            vulnerability_name="XSS",
            family="flow",
        )
        result = AssistantInvestigationResult(
            vulnerability_name="XSS",
            family="flow",
            status="likely_exploitable",
            confidence=0.7,
            summary="x",
            scope=scope,
        )
        synth_logger_name = "oasis.helpers.assistant.think.investigation_synth"
        with mock.patch.object(
            AssistantInvestigationResult,
            "model_dump",
            autospec=True,
            return_value={
                "scope_focus": {"sink_file": "src/fake.py", "sink_line": 999},
                "entry_points": [],
            },
        ):
            with self.assertLogs(synth_logger_name, level="WARNING") as captured:
                payload = compact_investigation_for_llm(result)
        self.assertTrue(
            any("schema drift" in msg.lower() for msg in captured.output),
            f"Expected a schema drift warning, got: {captured.output!r}",
        )
        focus = payload["scope_focus"]
        self.assertEqual(focus["sink_file"], "src/real.py")
        self.assertEqual(focus["sink_line"], 42)


class TestBatchFindingValidation(unittest.TestCase):
    """Scan-time batch validation (oasis.helpers.assistant.batch)."""

    @staticmethod
    def _sqli_fixture(root: Path) -> Path:
        return _write(
            root,
            "app.py",
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n"
            "@app.route('/q')\n"
            "def handler():\n"
            "    q = request.args.get('q')\n"
            "    cursor.execute('SELECT * FROM t WHERE x = ' + q)\n"
            "    return 'ok'\n",
        )

    @staticmethod
    def _model_row(app_path: Path, line: int) -> dict:
        return {
            "file_path": str(app_path),
            "similarity_score": 0.9,
            "structured_chunks": [
                ChunkDeepAnalysis(
                    findings=[VulnerabilityFinding(title="SQLi", snippet_start_line=line)],
                    start_line=max(1, line - 1),
                    end_line=line + 1,
                )
            ],
        }

    def test_annotate_rows_embeds_verdicts_on_model_rows(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app = self._sqli_fixture(root)
            rows = [self._model_row(app, 6)]
            stats = annotate_rows_with_validation(
                rows,
                vulnerability_name="SQL Injection",
                scan_root=root,
                total_budget_seconds=60.0,
            )
            self.assertEqual(stats["validated"], 1)
            self.assertEqual(stats["statuses"], {"confirmed_exploitable": 1})
            self.assertFalse(stats["budget_exhausted"])
            finding = rows[0]["structured_chunks"][0].findings[0]
            self.assertIsNotNone(finding.validation)
            self.assertEqual(finding.validation.status, "confirmed_exploitable")
            self.assertEqual(finding.validation.family, "flow")

    def test_annotate_rows_returns_full_results_by_key(self) -> None:
        """Sidecar payloads: full results keyed by the stable session storage key."""
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app = self._sqli_fixture(root)
            rows = [self._model_row(app, 6)]
            stats = annotate_rows_with_validation(
                rows,
                vulnerability_name="SQL Injection",
                scan_root=root,
                total_budget_seconds=60.0,
            )
            by_key = stats["results_by_key"]
            fk = '{"ci":0,"fi":0,"gi":0,"s":""}'
            self.assertIn(fk, by_key)
            result = by_key[fk]
            self.assertEqual(result["status"], "confirmed_exploitable")
            self.assertEqual(result["scope"]["sink_file"], "app.py")
            self.assertEqual(result["scope"]["sink_line"], 6)
            self.assertEqual(result["scope"]["vulnerability_name"], "SQL Injection")
            self.assertTrue(result["entry_points"])

    def test_annotate_rows_dict_shape_and_dedupe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._sqli_fixture(root)
            row = {
                "file_path": "app.py",
                "structured_chunks": [
                    {
                        "findings": [
                            {"title": "A", "snippet_start_line": 6},
                            {"title": "B", "snippet_start_line": 6},
                        ],
                        "start_line": 4,
                    }
                ],
            }
            stats = annotate_rows_with_validation(
                [row],
                vulnerability_name="SQL Injection",
                scan_root=root,
                total_budget_seconds=60.0,
            )
            self.assertEqual(stats["validated"], 2)
            self.assertEqual(stats["cached"], 1)
            findings = row["structured_chunks"][0]["findings"]
            self.assertEqual(findings[0]["validation"]["status"], "confirmed_exploitable")
            self.assertEqual(
                findings[1]["validation"]["confidence"],
                findings[0]["validation"]["confidence"],
            )
            # Both findings share the same anchor verdict but carry distinct fk keys.
            by_key = stats["results_by_key"]
            self.assertIn('{"ci":0,"fi":0,"gi":0,"s":""}', by_key)
            self.assertIn('{"ci":0,"fi":0,"gi":1,"s":""}', by_key)
            self.assertEqual(
                by_key['{"ci":0,"fi":0,"gi":0,"s":""}']["status"],
                by_key['{"ci":0,"fi":0,"gi":1,"s":""}']["status"],
            )

    def test_annotate_rows_skips_unresolvable_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            row = {
                "file_path": "missing/app.py",
                "structured_chunks": [{"findings": [{"title": "X"}], "start_line": 1}],
            }
            stats = annotate_rows_with_validation(
                [row],
                vulnerability_name="SQL Injection",
                scan_root=Path(td),
                total_budget_seconds=60.0,
            )
            self.assertEqual(stats["skipped_no_anchor"], 1)
            self.assertEqual(stats["validated"], 0)
            self.assertIsNone(row["structured_chunks"][0]["findings"][0].get("validation"))

    def test_annotate_rows_budget_exhaustion_leaves_findings_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app = self._sqli_fixture(root)
            rows = [self._model_row(app, 6)]
            stats = annotate_rows_with_validation(
                rows,
                vulnerability_name="SQL Injection",
                scan_root=root,
                total_budget_seconds=0.0,
            )
            self.assertEqual(stats["validated"], 0)
            self.assertTrue(stats["budget_exhausted"])
            finding = rows[0]["structured_chunks"][0].findings[0]
            self.assertIsNone(finding.validation)

    def test_summarize_validation_stats(self) -> None:
        stats = {
            "validated": 2,
            "cached": 1,
            "skipped_no_anchor": 0,
            "statuses": {"confirmed_exploitable": 2},
            "budget_exhausted": False,
        }
        text = summarize_validation_stats("XSS", stats)
        self.assertIn("validated=2", text)
        self.assertIn("cached=1", text)
        self.assertIn("confirmed_exploitable=2", text)


if __name__ == "__main__":
    unittest.main()
