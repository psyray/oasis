"""Unit tests for SecurityAnalyzer orchestration (standard vs adaptive, phase ordering)."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from oasis.analyze import SecurityAnalyzer
except ModuleNotFoundError:
    SecurityAnalyzer = None


@unittest.skipIf(SecurityAnalyzer is None, "oasis.analyze dependencies are unavailable")
class TestAnalyzeOrchestration(unittest.TestCase):
    def test_perform_standard_analysis_runs_initial_scan_then_deep(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        order = []

        def stub_initial(vulnerabilities, args, main_pbar, report, *, n_vuln_types):
            order.append("initial")
            self.assertEqual(n_vuln_types, 1)
            return {"stub": "suspicious_payload"}

        def stub_deep(suspicious_data, args, report, main_pbar=None, *, n_vuln_types):
            order.append("deep")
            self.assertEqual(suspicious_data["stub"], "suspicious_payload")
            self.assertEqual(n_vuln_types, 1)
            return {"_inj": [{"chunk": 1}]}

        analyzer._perform_initial_scanning = stub_initial
        analyzer._perform_deep_analysis = stub_deep

        vulns = [{"name": "SQL Injection"}]
        args = SimpleNamespace(silent=True)
        report = SimpleNamespace()

        out = analyzer._perform_standard_analysis(vulns, args, report)

        self.assertEqual(order, ["initial", "deep"])
        self.assertEqual(out, {"_inj": [{"chunk": 1}]})

    @patch("oasis.analyze.publish_incremental_summary")
    @patch("oasis.analyze.safe_code_base_file_count", return_value=7)
    def test_process_analysis_with_model_standard_final_uses_standard_progress_extras(
        self, _mock_count, mock_publish
    ):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        analyzer.llm_model = "main-model"
        analyzer.analysis_pipeline = SimpleNamespace()

        captured = {}

        def fake_standard(vulnerabilities, args, report):
            captured["called"] = True
            self.assertEqual(len(vulnerabilities), 1)
            return {"inj": []}

        analyzer._perform_standard_analysis = fake_standard

        vulns = [{"name": "XSS"}]
        args = SimpleNamespace(silent=True, adaptive=False)
        report = SimpleNamespace(generate_executive_summary=lambda *a, **k: None)

        analyzer.process_analysis_with_model(vulns, args, report)

        self.assertTrue(captured.get("called"))
        mock_publish.assert_called()
        final_kw = mock_publish.call_args.kwargs
        self.assertEqual(final_kw.get("completed_vulnerabilities"), 1)
        self.assertEqual(final_kw.get("total_vulnerabilities"), 1)
        self.assertEqual(final_kw.get("vulnerability_types_total"), 1)
        self.assertIn("phases", final_kw)

    @patch("oasis.analyze.publish_incremental_summary")
    @patch("oasis.analyze.safe_code_base_file_count", return_value=3)
    def test_process_analysis_with_model_adaptive_final_uses_adaptive_progress_extras(
        self, _mock_count, mock_publish
    ):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        analyzer.llm_model = "main-model"
        pipeline = SimpleNamespace()

        def fake_adaptive(vulnerabilities, args, report):
            return {"a": [], "b": []}

        pipeline.perform_adaptive_analysis = fake_adaptive
        analyzer.analysis_pipeline = pipeline

        vulns = [{"name": "A"}, {"name": "B"}]
        args = SimpleNamespace(silent=True, adaptive=True)
        report = SimpleNamespace(generate_executive_summary=lambda *a, **k: None)

        out = analyzer.process_analysis_with_model(vulns, args, report)

        self.assertEqual(out, {"a": [], "b": []})
        mock_publish.assert_called()
        final_kw = mock_publish.call_args.kwargs
        self.assertEqual(final_kw.get("completed_vulnerabilities"), 2)
        self.assertEqual(final_kw.get("total_vulnerabilities"), 2)
        self.assertIn("adaptive_subphases", final_kw)

    @patch("oasis.analyze.publish_incremental_summary")
    @patch("oasis.analyze.safe_code_base_file_count", return_value=1)
    def test_process_analysis_with_model_returns_pipeline_results(self, _mock_count, _mock_pub):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        analyzer.llm_model = "m"
        analyzer.analysis_pipeline = SimpleNamespace(
            perform_adaptive_analysis=lambda v, a, r: {"k": "v"}
        )

        args = SimpleNamespace(silent=True, adaptive=True)
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


if __name__ == "__main__":
    unittest.main()
