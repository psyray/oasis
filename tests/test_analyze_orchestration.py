"""Unit tests for SecurityAnalyzer orchestration (LangGraph pipeline)."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    import importlib

    importlib.import_module("oasis.agent.invoke")  # submodule for patch("oasis.agent.invoke...")
    from oasis.analyze import SecurityAnalyzer
    from oasis.enums import AnalysisType
    from oasis.helpers.progress import EXEC_SUMMARY_PROGRESS_EVENT_VERSION
except ModuleNotFoundError:
    SecurityAnalyzer = None
    AnalysisType = None
    EXEC_SUMMARY_PROGRESS_EVENT_VERSION = None

try:
    from langgraph.graph import END

    from oasis.agent.graph_labels import GRAPH_NODE_POC
    from oasis.agent.tools import route_after_report
except ModuleNotFoundError:
    END = None  # type: ignore[assignment]
    GRAPH_NODE_POC = None  # type: ignore[assignment]
    route_after_report = None  # type: ignore[assignment]


@unittest.skipIf(SecurityAnalyzer is None, "oasis.analyze dependencies are unavailable")
class TestAnalyzeOrchestration(unittest.TestCase):
    @patch("oasis.analyze.progress_timestamp_iso", return_value="2026-01-01T00:00:00+00:00")
    @patch("oasis.helpers.progress.safe_code_base_file_count", return_value=3)
    @patch("oasis.agent.invoke.invoke_oasis_langgraph")
    @patch("oasis.analyze.publish_incremental_summary")
    def test_process_analysis_with_model_calls_langgraph_and_graph_final_progress(
        self, mock_publish, mock_invoke, _mock_file_count, _mock_ts
    ):
        mock_invoke.return_value = {"XSS": {"results": []}}
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        analyzer.llm_model = "main-model"

        vulns = [{"name": "XSS"}]
        args = SimpleNamespace(
            silent=True,
            langgraph_max_expand_iterations=2,
            poc_hints=False,
            poc_assist=False,
        )
        report = SimpleNamespace(generate_executive_summary=lambda *a, **k: None)

        out = analyzer.process_analysis_with_model(vulns, args, report)

        mock_invoke.assert_called_once_with(analyzer, vulns, args, report)
        self.assertEqual(out, {"XSS": {"results": []}})
        mock_publish.assert_called()
        final_kw = mock_publish.call_args.kwargs
        self.assertEqual(final_kw.get("completed_vulnerabilities"), 1)
        self.assertEqual(final_kw.get("total_vulnerabilities"), 1)
        self.assertEqual(final_kw.get("event_version"), EXEC_SUMMARY_PROGRESS_EVENT_VERSION)
        self.assertEqual(final_kw.get("scan_mode"), AnalysisType.GRAPH.value)
        self.assertIn("phases", final_kw)
        self.assertTrue(any(r.get("id") == "graph_discover" for r in final_kw["phases"]))

    @patch("oasis.agent.invoke.invoke_oasis_langgraph")
    @patch("oasis.analyze.publish_incremental_summary")
    def test_process_analysis_with_model_returns_invoke_results(self, _mock_publish, mock_invoke):
        mock_invoke.return_value = {"k": "v"}
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        analyzer.llm_model = "m"
        args = SimpleNamespace(
            silent=True,
            langgraph_max_expand_iterations=2,
            poc_hints=False,
            poc_assist=False,
        )
        report = SimpleNamespace(generate_executive_summary=lambda *a, **k: None)

        self.assertEqual(
            analyzer.process_analysis_with_model([], args, report),
            {"k": "v"},
        )

    def test_get_vulnerabilities_to_check_all_returns_full_mapping(self):
        args = SimpleNamespace(vulns="all")
        mapping = {"sql": {"name": "SQL"}, "xss": {"name": "XSS"}}
        vulns, invalid = SecurityAnalyzer.get_vulnerabilities_to_check(args, mapping)
        self.assertIsNone(invalid)
        self.assertEqual({v["name"] for v in vulns}, {"SQL", "XSS"})

    def test_get_vulnerabilities_to_check_invalid_tag_returns_error(self):
        args = SimpleNamespace(vulns="sql,not_a_tag")
        mapping = {"sql": {"name": "SQL"}}
        vulns, invalid = SecurityAnalyzer.get_vulnerabilities_to_check(args, mapping)
        self.assertIsNone(vulns)
        self.assertEqual(invalid, ["not_a_tag"])

    def test_get_vulnerabilities_to_check_respects_tag_order(self):
        args = SimpleNamespace(vulns="sql, xss")
        mapping = {
            "sql": {"name": "SQL"},
            "xss": {"name": "XSS"},
        }
        vulns, invalid = SecurityAnalyzer.get_vulnerabilities_to_check(args, mapping)
        self.assertIsNone(invalid)
        self.assertEqual([v["name"] for v in vulns], ["SQL", "XSS"])

    def test_langgraph_poc_assist_empty_when_disabled(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        args = SimpleNamespace(poc_hints=False, poc_assist=False)
        self.assertEqual(analyzer.langgraph_poc_assist(args, {})["poc_hints_markdown"], "")

    def test_langgraph_poc_assist_hints_from_findings(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        args = SimpleNamespace(poc_hints=True, poc_assist=False, debug=False)
        all_results = {
            "XSS": [
                {
                    "file_path": "/app/x.py",
                    "structured_chunks": [
                        {
                            "findings": [
                                {
                                    "title": "Reflected XSS",
                                    "exploitation_steps": ["Send crafted query"],
                                    "example_payloads": ["<svg onload=alert(1)>"],
                                }
                            ]
                        }
                    ],
                }
            ]
        }
        md = analyzer.langgraph_poc_assist(args, all_results)["poc_hints_markdown"]
        self.assertIn("PoC hints", md)
        self.assertIn("Reflected XSS", md)

    def test_langgraph_poc_assist_llm_section_invokes_chat(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        analyzer.llm_model = "deep-m"
        analyzer.ollama_manager = MagicMock()
        analyzer.ollama_manager.get_model_display_name.return_value = "Deep M"
        analyzer.ollama_manager.chat.return_value = {"message": {"content": "```\necho ok\n```"}}
        args = SimpleNamespace(poc_hints=False, poc_assist=True, debug=False)
        all_results = {
            "SQ": [
                {
                    "file_path": "/q.sql",
                    "structured_chunks": [
                        {"findings": [{"title": "Injection", "vulnerable_code": "SELECT"}]}
                    ],
                }
            ]
        }
        md = analyzer.langgraph_poc_assist(args, all_results)["poc_hints_markdown"]
        analyzer.ollama_manager.chat.assert_called_once()
        self.assertIn("LLM-assisted executable PoC", md)
        self.assertIn("echo ok", md)

    def test_langgraph_poc_assist_custom_instructions_in_prompt(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        analyzer.llm_model = "deep-m"
        analyzer.ollama_manager = MagicMock()
        analyzer.ollama_manager.get_model_display_name.return_value = "Deep M"
        analyzer.ollama_manager.chat.return_value = {"message": {"content": "ok"}}
        args = SimpleNamespace(
            poc_hints=False,
            poc_assist=True,
            debug=False,
            custom_instructions="Prefer curl examples.",
            custom_instructions_file=None,
        )
        all_results = {
            "SQ": [
                {
                    "file_path": "/q.sql",
                    "structured_chunks": [
                        {"findings": [{"title": "Injection", "vulnerable_code": "SELECT"}]}
                    ],
                }
            ]
        }
        analyzer.langgraph_poc_assist(args, all_results)
        kwargs = analyzer.ollama_manager.chat.call_args.kwargs
        prompt = kwargs["messages"][0]["content"]
        self.assertIn("USER_ADDITIONAL_INSTRUCTIONS", prompt)
        self.assertIn("curl", prompt)

    @patch("oasis.analyze.CacheManager")
    def test_init_ensures_scan_and_deep_models_when_distinct(self, _mock_cache):
        ollama = MagicMock()
        ollama.get_client.return_value = object()
        ollama.ensure_model_available.return_value = True
        ollama.get_model_display_name.side_effect = lambda m: m

        em = MagicMock()
        em.embedding_model = "embed-m"
        em.code_base = {}
        em.analyze_by_function = False
        em.threshold = 0.5
        em.input_path = "/tmp/oasis-test-project"

        args = SimpleNamespace(
            clear_cache_scan=False,
            cache_days=7,
            project_name=None,
            language="en",
        )

        SecurityAnalyzer(
            args,
            llm_model="deep-model",
            embedding_manager=em,
            ollama_manager=ollama,
            scan_model="scan-model",
        )

        ollama.ensure_model_available.assert_has_calls(
            [call("scan-model"), call("deep-model")]
        )

    @patch("oasis.analyze.CacheManager")
    def test_init_ensures_model_once_when_scan_matches_deep(self, _mock_cache):
        ollama = MagicMock()
        ollama.get_client.return_value = object()
        ollama.ensure_model_available.return_value = True
        ollama.get_model_display_name.side_effect = lambda m: m

        em = MagicMock()
        em.embedding_model = "embed-m"
        em.code_base = {}
        em.analyze_by_function = False
        em.threshold = 0.5
        em.input_path = "/tmp/oasis-test-project"

        args = SimpleNamespace(
            clear_cache_scan=False,
            cache_days=7,
            project_name=None,
            language="en",
        )

        SecurityAnalyzer(
            args,
            llm_model="shared-model",
            embedding_manager=em,
            ollama_manager=ollama,
            scan_model=None,
        )

        ollama.ensure_model_available.assert_called_once_with("shared-model")

    @patch("oasis.analyze.CacheManager")
    def test_init_dedupes_normalized_model_aliases(self, _mock_cache):
        ollama = MagicMock()
        ollama.get_client.return_value = object()
        ollama.ensure_model_available.return_value = True
        ollama.get_model_display_name.side_effect = lambda m: m

        em = MagicMock()
        em.embedding_model = "embed-m"
        em.code_base = {}
        em.analyze_by_function = False
        em.threshold = 0.5
        em.input_path = "/tmp/oasis-test-project"

        args = SimpleNamespace(
            clear_cache_scan=False,
            cache_days=7,
            project_name=None,
            language="en",
        )

        SecurityAnalyzer(
            args,
            llm_model="llama3:latest",
            embedding_manager=em,
            ollama_manager=ollama,
            scan_model="llama3",
        )

        ollama.ensure_model_available.assert_called_once_with("llama3")

    @patch("oasis.analyze.CacheManager")
    def test_init_raises_when_model_cannot_be_made_available(self, _mock_cache):
        ollama = MagicMock()
        ollama.get_client.return_value = object()
        ollama.ensure_model_available.side_effect = [True, False]
        ollama.get_model_display_name.side_effect = lambda m: m

        em = MagicMock()
        em.embedding_model = "embed-m"
        em.code_base = {}
        em.analyze_by_function = False
        em.threshold = 0.5
        em.input_path = "/tmp/oasis-test-project"

        args = SimpleNamespace(
            clear_cache_scan=False,
            cache_days=7,
            project_name=None,
            language="en",
        )

        with self.assertRaises(RuntimeError) as ctx:
            SecurityAnalyzer(
                args,
                llm_model="deep-model",
                embedding_manager=em,
                ollama_manager=ollama,
                scan_model="scan-model",
            )

        self.assertIn("deep-model", str(ctx.exception))

@unittest.skipIf(route_after_report is None, "agent routing dependencies unavailable")
class TestAgentRouting(unittest.TestCase):
    def test_route_after_report_goes_to_poc_when_hints_enabled(self):
        state = {"args": SimpleNamespace(poc_hints=True, poc_assist=False)}
        self.assertEqual(route_after_report(state), GRAPH_NODE_POC)

    def test_route_after_report_goes_to_poc_when_assist_enabled(self):
        state = {"args": SimpleNamespace(poc_hints=False, poc_assist=True)}
        self.assertEqual(route_after_report(state), GRAPH_NODE_POC)

    def test_route_after_report_ends_when_poc_disabled(self):
        state = {"args": SimpleNamespace(poc_hints=False, poc_assist=False)}
        self.assertEqual(route_after_report(state), END)


if __name__ == "__main__":
    unittest.main()
