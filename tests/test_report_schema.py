"""Tests for structured report schemas and stats aggregation."""

import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from oasis.schemas.analysis import (
        ChunkDeepAnalysis,
        DashboardStats,
        FileReportEntry,
        MediumRiskAnalysis,
        ScanVerdict,
        VulnerabilityFinding,
        VulnerabilityReportDocument,
        build_dashboard_stats,
        chunk_analysis_to_markdown,
    )
except ModuleNotFoundError:
    # Fallback for minimal test environments where package-level optional deps
    # (imported by oasis.__init__) are not installed.
    _spec = importlib.util.spec_from_file_location(
        "oasis_schemas_analysis",
        ROOT / "oasis" / "schemas" / "analysis.py",
    )
    _analysis = importlib.util.module_from_spec(_spec)
    assert _spec and _spec.loader is not None
    _spec.loader.exec_module(_analysis)
    ChunkDeepAnalysis = _analysis.ChunkDeepAnalysis
    DashboardStats = _analysis.DashboardStats
    FileReportEntry = _analysis.FileReportEntry
    MediumRiskAnalysis = _analysis.MediumRiskAnalysis
    ScanVerdict = _analysis.ScanVerdict
    VulnerabilityFinding = _analysis.VulnerabilityFinding
    VulnerabilityReportDocument = _analysis.VulnerabilityReportDocument
    build_dashboard_stats = _analysis.build_dashboard_stats
    chunk_analysis_to_markdown = _analysis.chunk_analysis_to_markdown

try:
    from oasis.analyze import AdaptiveAnalysisPipeline, SecurityAnalyzer
except ModuleNotFoundError:
    AdaptiveAnalysisPipeline = None
    SecurityAnalyzer = None


class TestReportSchema(unittest.TestCase):
    @unittest.skipIf(SecurityAnalyzer is None, "oasis.analyze dependencies are unavailable")
    def test_deep_analysis_updates_main_progress_by_one_per_vulnerability(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        analyzer.llm_model = "test-model"
        analyzer.ollama_manager = SimpleNamespace(get_model_display_name=lambda _model: "test-model")
        vulnerabilities = [{"name": "SQL Injection"}, {"name": "XSS"}]
        suspicious_files_by_vuln = {
            "sql": {"vuln_data": vulnerabilities[0], "files": [("app.py", 0.9)]},
            "xss": {"vuln_data": vulnerabilities[1], "files": [("app.py", 0.8)]},
        }
        suspicious_data = {"suspicious_data": {}, "files_by_vuln": suspicious_files_by_vuln}

        analyzer._analyze_vulnerability_deep = lambda *args, **kwargs: []

        updates = []
        main_pbar = SimpleNamespace(
            set_postfix_str=lambda _text: None,
            update=lambda value: updates.append(value),
        )
        report = SimpleNamespace(generate_vulnerability_report=lambda **kwargs: None)
        args = SimpleNamespace(silent=True)

        analyzer._perform_deep_analysis(suspicious_data, args, report, main_pbar)

        self.assertEqual(updates, [1, 1])

    def test_build_dashboard_stats_counts_severities(self):
        files = [
            FileReportEntry(
                file_path="a.py",
                similarity_score=0.9,
                chunk_analyses=[
                    ChunkDeepAnalysis(
                        findings=[
                            VulnerabilityFinding(
                                vulnerable_code="z",
                                explanation="e0",
                                severity="Critical",
                            ),
                            VulnerabilityFinding(
                                vulnerable_code="x",
                                explanation="e",
                                severity="High",
                            ),
                            VulnerabilityFinding(
                                vulnerable_code="y",
                                explanation="e2",
                                severity="Low",
                            ),
                        ]
                    )
                ],
            )
        ]
        stats = build_dashboard_stats(files)
        self.assertEqual(stats.total_findings, 3)
        self.assertEqual(stats.critical_risk, 1)
        self.assertEqual(stats.high_risk, 1)
        self.assertEqual(stats.low_risk, 1)
        self.assertEqual(stats.medium_risk, 0)
        self.assertEqual(stats.files_analyzed, 1)

    def test_build_dashboard_stats_excludes_errored_files_from_analyzed_count(self):
        files = [
            FileReportEntry(
                file_path="ok.py",
                similarity_score=0.9,
                chunk_analyses=[ChunkDeepAnalysis(findings=[])],
            ),
            FileReportEntry(
                file_path="failed.py",
                similarity_score=0.1,
                chunk_analyses=[],
                error="analysis failed",
            ),
        ]
        stats = build_dashboard_stats(files)
        self.assertEqual(stats.files_analyzed, 1)

    def test_vulnerability_report_document_roundtrip(self):
        doc = VulnerabilityReportDocument(
            title="SQL Injection Security Analysis",
            generated_at="2026-01-01 12:00:00",
            model_name="test-model",
            vulnerability_name="SQL Injection",
            vulnerability={"name": "SQL Injection"},
            files=[
                FileReportEntry(
                    file_path="app.py",
                    similarity_score=0.85,
                    chunk_analyses=[ChunkDeepAnalysis(findings=[])],
                )
            ],
            stats=DashboardStats(files_analyzed=1),
        )
        raw = doc.model_dump_json()
        restored = VulnerabilityReportDocument.model_validate_json(raw)
        self.assertEqual(restored.title, doc.title)
        self.assertEqual(len(restored.files), 1)
        self.assertEqual(restored.schema_version, doc.schema_version)
        self.assertEqual(restored.stats.files_analyzed, doc.stats.files_analyzed)

    def test_scan_verdict_accepts_error_value(self):
        verdict = ScanVerdict.model_validate({"verdict": "ERROR"})
        self.assertEqual(verdict.verdict, "ERROR")

    def test_analysis_models_expose_validation_error_flag(self):
        medium = MediumRiskAnalysis(risk_score=50, analysis="Invalid structured response", validation_error=True)
        deep = ChunkDeepAnalysis(findings=[], notes="validation failure", validation_error=True)
        self.assertTrue(medium.validation_error)
        self.assertTrue(deep.validation_error)

    def test_chunk_analysis_to_markdown_renders_multiple_findings(self):
        chunk = ChunkDeepAnalysis(
            findings=[
                VulnerabilityFinding(
                    title="User input flows to query",
                    vulnerable_code="user_input = request.GET['q']",
                    explanation="Unsanitized input reaches query builder.",
                    severity="High",
                    execution_path_diagram="handle -> do_query",
                    http_methods=["GET"],
                    manipulable_parameters=["q"],
                    example_payloads=['{"q":"test"}'],
                ),
                VulnerabilityFinding(
                    title="Eval usage",
                    vulnerable_code="eval(user_input)",
                    explanation="Dynamic execution of attacker-controlled input.",
                    severity="Critical",
                    execution_path_diagram="handler -> eval",
                    http_methods=["POST"],
                    manipulable_parameters=["user_input"],
                    example_payloads=['{"user_input":"__import__(\\"os\\")"}'],
                ),
            ]
        )

        markdown = chunk_analysis_to_markdown(chunk, 0)
        self.assertIn("#### Finding 1 (chunk 1): User input flows to query", markdown)
        self.assertIn("#### Finding 2 (chunk 1): Eval usage", markdown)
        self.assertIn("- **Severity**: High", markdown)
        self.assertIn("- **Severity**: Critical", markdown)
        self.assertIn("user_input = request.GET['q']", markdown)
        self.assertIn("## Execution Path", markdown)
        self.assertIn("**HTTP methods**: GET", markdown)
        self.assertIn("**Parameters**: q", markdown)
        self.assertIn("**Example payloads**:", markdown)
        self.assertIn('<div class="page-break"></div>', markdown)

    def test_chunk_analysis_to_markdown_includes_source_line_hint(self):
        chunk = ChunkDeepAnalysis(
            findings=[
                VulnerabilityFinding(
                    title="Issue",
                    vulnerable_code="x",
                    explanation="y",
                    severity="Medium",
                )
            ],
            start_line=2,
            end_line=9,
        )
        markdown = chunk_analysis_to_markdown(chunk, 0)
        self.assertIn("source lines 2-9", markdown)

    def test_chunk_analysis_to_markdown_no_findings_uses_notes(self):
        chunk = ChunkDeepAnalysis(
            findings=[],
            notes="Static analysis only: no problematic patterns discovered.",
        )
        markdown = chunk_analysis_to_markdown(chunk, 2)
        self.assertIn("No vulnerabilities identified in structured output.", markdown)
        self.assertIn("**Notes**: Static analysis only: no problematic patterns discovered.", markdown)
        self.assertNotIn("## Execution Path", markdown)

    def test_chunk_analysis_to_markdown_inserts_page_breaks_between_findings(self):
        chunk = ChunkDeepAnalysis(
            findings=[
                VulnerabilityFinding(
                    title="First",
                    vulnerable_code="a = 1",
                    explanation="first",
                    severity="Low",
                ),
                VulnerabilityFinding(
                    title="Second",
                    vulnerable_code="b = 2",
                    explanation="second",
                    severity="Medium",
                ),
            ]
        )
        markdown = chunk_analysis_to_markdown(chunk, 0)
        self.assertGreaterEqual(markdown.count('<div class="page-break"></div>'), 2)

    @unittest.skipIf(SecurityAnalyzer is None, "oasis.analyze dependencies are unavailable")
    def test_structured_output_failure_flags_are_set_in_fallbacks(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        analyzer.structured_output_failure_handler = None

        medium_json = analyzer._resolve_structured_output_failure(
            response_model=MediumRiskAnalysis,
            raw='{"bad":"json"}',
            error=ValueError("boom"),
            model_display="test-model",
        )
        deep_json = analyzer._resolve_structured_output_failure(
            response_model=ChunkDeepAnalysis,
            raw='{"bad":"json"}',
            error=ValueError("boom"),
            model_display="test-model",
        )

        medium = MediumRiskAnalysis.model_validate_json(medium_json)
        deep = ChunkDeepAnalysis.model_validate_json(deep_json)
        self.assertTrue(medium.validation_error)
        self.assertTrue(deep.validation_error)

    @unittest.skipIf(AdaptiveAnalysisPipeline is None, "oasis.analyze dependencies are unavailable")
    def test_identify_high_risk_chunks_skips_validation_errors(self):
        pipeline = AdaptiveAnalysisPipeline.__new__(AdaptiveAnalysisPipeline)
        suspicious_chunks = [(0, "chunk-a"), (1, "chunk-b"), (2, "chunk-c")]
        medium_results = [
            {"chunk_idx": 0, "risk_score": 90, "validation_error": False},
            {"chunk_idx": 1, "risk_score": 99, "validation_error": True},
            {"chunk_idx": 2, "risk_score": 40, "validation_error": False},
        ]
        selected = pipeline._identify_high_risk_chunks(
            suspicious_chunks=suspicious_chunks,
            medium_results=medium_results,
            risk_threshold=70,
        )
        self.assertEqual(selected, [(0, "chunk-a")])

    @unittest.skipIf(AdaptiveAnalysisPipeline is None, "oasis.analyze dependencies are unavailable")
    def test_combine_adaptive_results_escapes_backticks_and_truncates_unparseable_notes(self):
        pipeline = AdaptiveAnalysisPipeline.__new__(AdaptiveAnalysisPipeline)
        pipeline.analyzer = SimpleNamespace(
            _log_structured_output_error=lambda **kwargs: None,
            ollama_manager=SimpleNamespace(get_model_display_name=lambda _model: "test-model"),
            llm_model="test-model",
        )
        raw = "```" + ("A" * 450)
        combined = pipeline._combine_adaptive_results(
            file_path="demo.py",
            code_chunks=["chunk"],
            suspicious_chunks=[],
            medium_results=[],
            deep_results=[{"chunk_idx": 0, "analysis": raw, "content": "x"}],
        )
        markdown = combined["markdown"]
        self.assertIn("Unparseable deep analyses", markdown)
        self.assertIn("``\\`", markdown)
        self.assertIn("[truncated]", markdown)


if __name__ == "__main__":
    unittest.main()
