"""Tests for structured report schemas and stats aggregation."""

import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from flask import Flask

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.enums import PhaseRowStatus
from oasis.helpers import adaptive_subphases_payload, standard_scan_phases, standard_scan_phases_vuln_types
from oasis.helpers.pipeline_phase_md import parse_phase_counts_from_progress_cell
from oasis.helpers.progress_constants import (
    EXEC_SUMMARY_PROGRESS_EVENT_VERSION,
    SCAN_PROGRESS_EXTENDED_KEYS,
)

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

try:
    from oasis.report import Report, publish_incremental_summary
except ModuleNotFoundError:
    Report = None
    publish_incremental_summary = None

try:
    from oasis.web import WebServer
except ModuleNotFoundError:
    WebServer = None

try:
    from oasis.embedding import EmbeddingProgressThrottle
except ModuleNotFoundError:
    EmbeddingProgressThrottle = None


class TestReportSchema(unittest.TestCase):
    @unittest.skipIf(SecurityAnalyzer is None, "oasis.analyze dependencies are unavailable")
    def test_deep_analysis_generates_incremental_summary_for_each_completed_vulnerability(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        analyzer.llm_model = "test-model"
        analyzer.ollama_manager = SimpleNamespace(get_model_display_name=lambda _model: "test-model")
        vulnerabilities = [{"name": "SQL Injection"}, {"name": "XSS"}]
        suspicious_files_by_vuln = {
            "sql": {"vuln_data": vulnerabilities[0], "files": [("app.py", 0.9)]},
            "xss": {"vuln_data": vulnerabilities[1], "files": [("app.py", 0.8)]},
        }
        suspicious_data = {"suspicious_data": {}, "files_by_vuln": suspicious_files_by_vuln}

        deep_results = [
            [{"file_path": "a.py", "similarity_score": 0.9, "structured_chunks": []}],
            [],
        ]
        analyzer._analyze_vulnerability_deep = lambda *args, **kwargs: deep_results.pop(0)

        summary_calls = []
        report = SimpleNamespace(
            generate_vulnerability_report=lambda **kwargs: None,
            generate_executive_summary=lambda all_results, model_name, progress=None: summary_calls.append(
                {"keys": list(all_results.keys()), "model": model_name, "progress": progress}
            ),
        )
        args = SimpleNamespace(silent=True)

        analyzer._perform_deep_analysis(suspicious_data, args, report)

        progresses = [c["progress"] for c in summary_calls]
        self.assertTrue(
            any(
                p["completed_vulnerabilities"] == 0
                and p.get("active_phase") == "deep_analysis"
                and p.get("event_version") == EXEC_SUMMARY_PROGRESS_EVENT_VERSION
                for p in progresses
            ),
            "expected an initial deep_analysis snapshot with canonical event_version",
        )
        self.assertTrue(
            all(
                p.get("event_version") == EXEC_SUMMARY_PROGRESS_EVENT_VERSION for p in progresses
            ),
        )
        self.assertTrue(
            any(
                p["completed_vulnerabilities"] == 0
                and p["current_vulnerability"] == "sql"
                and p["tested_vulnerabilities"] == []
                for p in progresses
            )
        )
        self.assertTrue(
            any(
                p["completed_vulnerabilities"] == 1
                and p["current_vulnerability"] is None
                and p["tested_vulnerabilities"] == ["sql"]
                for p in progresses
            )
        )
        self.assertTrue(
            any(
                p["completed_vulnerabilities"] == 1
                and p["current_vulnerability"] == "xss"
                and p["tested_vulnerabilities"] == ["sql"]
                for p in progresses
            )
        )
        finals = [p for p in progresses if p["completed_vulnerabilities"] == 2]
        self.assertTrue(finals)
        self.assertEqual(finals[-1]["total_vulnerabilities"], 2)
        self.assertFalse(finals[-1]["is_partial"])
        self.assertIsNone(finals[-1]["current_vulnerability"])
        self.assertEqual(finals[-1]["tested_vulnerabilities"], ["sql", "xss"])

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
            reset=lambda **_kw: None,
            set_description=lambda *_a, **_kw: None,
        )
        report = SimpleNamespace(
            generate_vulnerability_report=lambda **kwargs: None,
            generate_executive_summary=lambda *args, **kwargs: None,
        )
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
    def test_adaptive_analysis_generates_incremental_summary_for_each_completed_vulnerability(self):
        pipeline = AdaptiveAnalysisPipeline.__new__(AdaptiveAnalysisPipeline)
        pipeline.llm_model = "test-model"
        pipeline.ollama_manager = SimpleNamespace(get_model_display_name=lambda _model: "test-model")
        pipeline.analyzer = SimpleNamespace(
            search_vulnerabilities=lambda vuln, threshold: [("app.py", 0.9)],
        )
        pipeline._batch_processor = SimpleNamespace(
            process_all_tasks_in_batches=lambda tasks: None,
        )
        pipeline._collect_vulnerability_results = lambda filtered_results, vuln: [{"file_path": "app.py", "similarity_score": 0.9}]

        vulnerabilities = [{"name": "SQL Injection"}, {"name": "XSS"}]
        args = SimpleNamespace(silent=True, threshold=0.5)
        summary_calls = []
        report = SimpleNamespace(
            generate_vulnerability_report=lambda **kwargs: None,
            generate_executive_summary=lambda all_results, model_name, progress=None: summary_calls.append(progress),
        )

        pipeline.perform_adaptive_analysis(vulnerabilities, args, report)

        nv = len(vulnerabilities)
        self.assertTrue(
            all(
                p.get("event_version") == EXEC_SUMMARY_PROGRESS_EVENT_VERSION
                for p in summary_calls
            )
        )

        identifying = [
            p
            for p in summary_calls
            if p.get("total_vulnerabilities") == nv
            and (p.get("adaptive_subphases") or {}).get("identify_files", {}).get("total") == nv
        ]
        self.assertTrue(identifying, "expected identification payloads with denominator nv")

        progress_total_while_collecting = 2
        collecting = [
            p
            for p in summary_calls
            if p.get("total_vulnerabilities") == progress_total_while_collecting
            and (p.get("adaptive_subphases") or {}).get("collect_results", {}).get("total")
            == progress_total_while_collecting
            and (p.get("adaptive_subphases") or {}).get("collect_results", {}).get("status")
            == PhaseRowStatus.IN_PROGRESS.value
        ]
        self.assertTrue(collecting, "expected collection payloads with collection denominator")

        batch_in_progress = [
            p
            for p in summary_calls
            if (p.get("adaptive_subphases") or {}).get("batch_process", {}).get("status")
            == PhaseRowStatus.IN_PROGRESS.value
        ]
        self.assertTrue(batch_in_progress)

        self.assertGreaterEqual(len(summary_calls), 2)
        collect_before_sql = [
            p
            for p in summary_calls
            if p.get("current_vulnerability") == "SQL Injection"
            and p.get("completed_vulnerabilities") == 0
            and (p.get("adaptive_subphases") or {}).get("batch_process", {}).get("status")
            == PhaseRowStatus.COMPLETE.value
            and (p.get("adaptive_subphases") or {}).get("collect_results", {}).get("status")
            == PhaseRowStatus.IN_PROGRESS.value
        ]
        self.assertTrue(collect_before_sql)

        final_updates = [
            p
            for p in summary_calls
            if p.get("completed_vulnerabilities") == 2
            and not p.get("current_vulnerability")
            and p.get("tested_vulnerabilities") == ["SQL Injection", "XSS"]
        ]
        self.assertTrue(final_updates)
        self.assertFalse(final_updates[-1].get("is_partial"))

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_executive_summary_includes_partial_progress_block(self):
        report = Report.__new__(Report)
        report.output_format = ["md"]
        report.current_model = "test-model"
        report.report_dirs = {"test_model": {"md": Path("/tmp")}}
        report.create_header = lambda title, model_name: [f"# {title}", f"Model: {model_name}"]
        report.filter_output_files = lambda safe_name: {"md": Path("/tmp") / f"{safe_name}.md"}
        captured = {}
        report._generate_and_save_report = lambda output_files, report_content, report_type=None: captured.update(
            {"output_files": output_files, "report_content": report_content, "report_type": report_type}
        )

        all_results = {"SQL Injection": [{"file_path": "app.py", "similarity_score": 0.9}]}
        report.generate_executive_summary(
            all_results,
            "test-model",
            progress={"completed_vulnerabilities": 1, "total_vulnerabilities": 3, "is_partial": True},
        )

        content = "\n".join(captured["report_content"])
        self.assertIn("Scan Progress", content)
        self.assertIn("1/3", content)
        self.assertIn("partial", content.lower())

    @unittest.skipIf(publish_incremental_summary is None, "oasis.report dependencies are unavailable")
    def test_publish_incremental_summary_strips_unknown_progress_extras(self):
        progresses: list = []

        report = SimpleNamespace(
            generate_executive_summary=lambda all_results, llm_model, progress=None: progresses.append(
                progress
            )
        )

        publish_incremental_summary(
            report,
            "model-x",
            {},
            completed_vulnerabilities=0,
            total_vulnerabilities=2,
            current_vulnerability=None,
            tested_vulnerabilities=[],
            scan_mode="standard",
            unwanted_blob={"nested": "unsanitized"},
            leaked_secret="token",
        )

        payload = progresses[-1]
        self.assertEqual(payload["scan_mode"], "standard")
        self.assertNotIn("unwanted_blob", payload)
        self.assertNotIn("leaked_secret", payload)

    @unittest.skipIf(publish_incremental_summary is None, "oasis.report dependencies are unavailable")
    def test_publish_incremental_summary_respects_explicit_status_override(self):
        progresses: list = []

        report = SimpleNamespace(
            generate_executive_summary=lambda all_results, llm_model, progress=None: progresses.append(
                progress
            )
        )

        publish_incremental_summary(
            report,
            "model-x",
            {},
            completed_vulnerabilities=1,
            total_vulnerabilities=5,
            current_vulnerability=None,
            tested_vulnerabilities=[],
            status="aborted",
        )

        payload = progresses[-1]
        self.assertEqual(payload["status"], "aborted")
        self.assertTrue(payload["is_partial"])

        publish_incremental_summary(
            report,
            "model-x",
            {},
            completed_vulnerabilities=1,
            total_vulnerabilities=5,
            current_vulnerability=None,
            tested_vulnerabilities=[],
            status="succeeded",
        )
        self.assertEqual(progresses[-1]["status"], "succeeded")
        self.assertFalse(progresses[-1]["is_partial"])

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_executive_summary_notifier_receives_progress_payload(self):
        report = Report.__new__(Report)
        report.output_format = ["md"]
        report.current_model = "test-model"
        report.report_dirs = {"test_model": {"md": Path("/tmp")}}
        report.create_header = lambda title, model_name: [f"# {title}", f"Model: {model_name}"]
        report.filter_output_files = lambda safe_name: {"md": Path("/tmp") / f"{safe_name}.md"}
        report._generate_and_save_report = lambda output_files, report_content, report_type=None: None
        captured = {}
        report.set_progress_notifier(lambda payload: captured.update(payload))
        all_results = {"SQL Injection": [{"file_path": "app.py", "similarity_score": 0.9}]}

        report.generate_executive_summary(
            all_results,
            "test-model",
            progress={
                "completed_vulnerabilities": 2,
                "total_vulnerabilities": 5,
                "is_partial": True,
                "current_vulnerability": "SQL Injection",
                "tested_vulnerabilities": ["Secrets Exposure", "SQL Injection"],
            },
        )

        self.assertEqual(captured["completed_vulnerabilities"], 2)
        self.assertEqual(captured["total_vulnerabilities"], 5)
        self.assertTrue(captured["is_partial"])
        self.assertEqual(captured["model"], "test-model")
        self.assertEqual(captured["status"], "in_progress")
        self.assertEqual(captured["current_vulnerability"], "SQL Injection")
        self.assertEqual(
            captured["tested_vulnerabilities"],
            ["Secrets Exposure", "SQL Injection"],
        )

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_report_mark_progress_aborted_republishes_summary_with_aborted_status(self):
        report = Report.__new__(Report)
        report.current_model = "test-model"
        report._last_summary_results = {"SQL Injection": []}
        report._last_summary_model_name = "test-model"
        report._last_progress_payload = {
            "completed_vulnerabilities": 1,
            "total_vulnerabilities": 5,
            "is_partial": True,
            "status": "in_progress",
            "current_vulnerability": "SQL Injection",
            "tested_vulnerabilities": ["SQL Injection"],
            "phases": [
                {
                    "id": "embeddings",
                    "label": "Embeddings",
                    "status": "complete",
                    "completed": 2,
                    "total": 2,
                }
            ],
            "active_phase": "deep_analysis",
        }
        captured = {}
        report.generate_executive_summary = lambda all_results, model_name, progress=None: captured.update(
            {"all_results": all_results, "model_name": model_name, "progress": progress}
        )

        report.mark_progress_aborted()

        self.assertEqual(captured["model_name"], "test-model")
        self.assertEqual(captured["progress"]["status"], "aborted")
        self.assertTrue(captured["progress"]["is_partial"])
        aborted_ts = captured["progress"].get("updated_at")
        self.assertIsInstance(aborted_ts, str)
        self.assertTrue(aborted_ts.endswith("Z"), "aborted progress should carry a fresh UTC updated_at for the dashboard")
        self.assertEqual(captured["progress"]["active_phase"], "deep_analysis")
        self.assertIsInstance(captured["progress"].get("phases"), list)
        self.assertEqual(captured["progress"]["phases"][0]["id"], "embeddings")

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_stats_reader_returns_empty_dict_on_partial_json(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = Path(tmp_dir) / "incomplete.json"
            report_file.write_text('{"stats":', encoding="utf-8")
            stats = WebServer._stats_from_json_report_file(report_file)
        self.assertEqual(stats, {})

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_summary_progress_reader_extracts_partial_status(self):
        payload = {
            "report_type": "executive_summary",
            "progress": {
                "completed_vulnerabilities": 2,
                "total_vulnerabilities": 5,
                "is_partial": True,
                "current_vulnerability": "XSS",
                "tested_vulnerabilities": ["SQL Injection", "XSS"],
            },
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = Path(tmp_dir) / "summary.json"
            report_file.write_text(json.dumps(payload), encoding="utf-8")
            progress = WebServer._summary_progress_from_json_report_file(report_file)
        self.assertEqual(progress["completed_vulnerabilities"], 2)
        self.assertEqual(progress["total_vulnerabilities"], 5)
        self.assertTrue(progress["is_partial"])
        self.assertEqual(progress["status"], "in_progress")
        self.assertEqual(progress["current_vulnerability"], "XSS")
        self.assertEqual(progress["tested_vulnerabilities"], ["SQL Injection", "XSS"])

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_json_progress_reader_preserves_phases_and_active_phase(self):
        payload = {
            "report_type": "executive_summary",
            "progress": {
                "completed_vulnerabilities": 0,
                "total_vulnerabilities": 2,
                "is_partial": True,
                "active_phase": "initial_scan",
                "vulnerability_types_total": 7,
                "phases": [
                    {
                        "id": "a",
                        "label": "A",
                        "status": PhaseRowStatus.IN_PROGRESS.value,
                        "completed": 0,
                        "total": 1,
                    }
                ],
            },
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "ex.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            progress = WebServer._summary_progress_from_json_report_file(path)
        self.assertEqual(progress["active_phase"], "initial_scan")
        self.assertEqual(progress["vulnerability_types_total"], 7)
        self.assertEqual(len(progress["phases"]), 1)
        self.assertEqual(progress["phases"][0]["id"], "a")

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_json_progress_reader_prefers_progress_sidecar(self):
        from oasis.report import executive_summary_progress_sidecar_path

        with tempfile.TemporaryDirectory() as tmp_dir:
            main = Path(tmp_dir) / "_executive_summary.json"
            sidecar = executive_summary_progress_sidecar_path(main)
            main.write_text(
                json.dumps(
                    {
                        "report_type": "executive_summary",
                        "progress": {
                            "completed_vulnerabilities": 1,
                            "total_vulnerabilities": 10,
                            "is_partial": True,
                        },
                    }
                ),
                encoding="utf-8",
            )
            sidecar.write_text(
                json.dumps(
                    {
                        "report_type": "executive_summary",
                        "progress": {
                            "completed_vulnerabilities": 9,
                            "total_vulnerabilities": 10,
                            "is_partial": True,
                            "adaptive_subphases": {
                                "embeddings": {"status": "running"},
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            progress = WebServer._summary_progress_from_json_report_file(main)
        self.assertEqual(progress["completed_vulnerabilities"], 9)
        adaptive_subphases = progress.get("adaptive_subphases")
        self.assertIsInstance(adaptive_subphases, dict)
        self.assertIn("embeddings", adaptive_subphases)

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_json_progress_reader_prefers_embedded_when_sidecar_older(self):
        from oasis.report import executive_summary_progress_sidecar_path

        with tempfile.TemporaryDirectory() as tmp_dir:
            main = Path(tmp_dir) / "_executive_summary.json"
            sidecar = executive_summary_progress_sidecar_path(main)
            main.write_text(
                json.dumps(
                    {
                        "report_type": "executive_summary",
                        "progress": {
                            "completed_vulnerabilities": 7,
                            "total_vulnerabilities": 10,
                            "is_partial": True,
                            "updated_at": "2026-04-18T12:00:00Z",
                        },
                    }
                ),
                encoding="utf-8",
            )
            sidecar.write_text(
                json.dumps(
                    {
                        "report_type": "executive_summary",
                        "progress": {
                            "completed_vulnerabilities": 1,
                            "total_vulnerabilities": 10,
                            "is_partial": True,
                            "updated_at": "2020-01-01T00:00:00Z",
                        },
                    }
                ),
                encoding="utf-8",
            )
            progress = WebServer._summary_progress_from_json_report_file(main)
        self.assertEqual(progress["completed_vulnerabilities"], 7)
        self.assertEqual(progress["updated_at"], "2026-04-18T12:00:00Z")

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_summary_markdown_progress_reader_extracts_vulnerability_details(self):
        markdown = """# Executive Summary

## Scan Progress
| Status | Completed vulnerabilities |
|--------|----------------------------|
| Partial (scan in progress) | 2/5 |
- Current vulnerability: XSS
- Tested vulnerabilities: SQL Injection, XSS
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = Path(tmp_dir) / "summary.md"
            report_file.write_text(markdown, encoding="utf-8")
            progress = WebServer._summary_progress_from_markdown_report_file(report_file)
        self.assertEqual(progress["completed_vulnerabilities"], 2)
        self.assertEqual(progress["total_vulnerabilities"], 5)
        self.assertTrue(progress["is_partial"])
        self.assertEqual(progress["status"], "in_progress")
        self.assertEqual(progress["current_vulnerability"], "XSS")
        self.assertEqual(progress["tested_vulnerabilities"], ["SQL Injection", "XSS"])

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_summary_markdown_progress_reader_extracts_pipeline_phases_table(self):
        markdown = """# Executive Summary

## Scan Progress
| Status | Completed vulnerabilities |
|--------|----------------------------|
| Partial (scan in progress) | 1/3 |

### Pipeline phases
| Phase | Status | Progress |
|-------|--------|----------|
| Embeddings | complete | 10/10 |
| Initial scanning | in_progress | 2/5 |
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = Path(tmp_dir) / "summary.md"
            report_file.write_text(markdown, encoding="utf-8")
            progress = WebServer._summary_progress_from_markdown_report_file(report_file)
        phases = progress.get("phases") or []
        self.assertEqual(len(phases), 2)
        self.assertEqual(phases[0]["label"], "Embeddings")
        self.assertEqual(phases[0]["completed"], 10)
        self.assertEqual(phases[1]["label"], "Initial scanning")

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_pipeline_phases_parse_tolerates_progress_suffix_text(self):
        markdown = """# Executive Summary

## Scan Progress
| Status | Completed vulnerabilities |
|--------|----------------------------|
| Partial (scan in progress) | 1/3 |

### Pipeline phases
| Phase | Status | Progress |
|-------|--------|----------|
| Embeddings | complete | 10/10 (100%) |
| Initial scanning | in_progress | 2 / 5 extra text |
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = Path(tmp_dir) / "summary.md"
            report_file.write_text(markdown, encoding="utf-8")
            progress = WebServer._summary_progress_from_markdown_report_file(report_file)
        phases = progress.get("phases") or []
        self.assertEqual(len(phases), 2)
        self.assertEqual(phases[0]["completed"], 10)
        self.assertEqual(phases[0]["total"], 10)
        self.assertEqual(phases[1]["completed"], 2)
        self.assertEqual(phases[1]["total"], 5)

    @unittest.skipIf(EmbeddingProgressThrottle is None, "oasis.embedding unavailable")
    def test_embedding_progress_hook_throttled_between_intermediates(self):
        calls = []
        hook = lambda c, t: calls.append((c, t))
        throttle = EmbeddingProgressThrottle()
        throttle.maybe_emit(hook, 1, 5, min_interval_sec=3600.0, force=True)
        throttle.maybe_emit(hook, 2, 5, min_interval_sec=3600.0, force=False)
        self.assertEqual(len(calls), 1)
        throttle.maybe_emit(hook, 5, 5, min_interval_sec=3600.0, force=True)
        self.assertEqual(calls[-1], (5, 5))

    @unittest.skipIf(EmbeddingProgressThrottle is None, "oasis.embedding unavailable")
    def test_embedding_progress_force_emit_with_zero_total_calls_hook(self):
        calls = []
        hook = lambda c, t: calls.append((c, t))
        throttle = EmbeddingProgressThrottle()
        throttle.maybe_emit(hook, 0, 0, min_interval_sec=3600.0, force=True)
        self.assertEqual(calls, [(0, 0)])

    def test_scan_progress_extended_keys_contract_matches_expected_set(self):
        """Guardrail: extend this set when adding wire keys; keeps report/web filtering aligned."""
        expected = frozenset(
            {
                "updated_at",
                "active_phase",
                "phases",
                "adaptive_subphases",
                "overall",
                "scan_mode",
                "event_version",
                "vulnerability_types_total",
                "status",
            }
        )
        self.assertEqual(SCAN_PROGRESS_EXTENDED_KEYS, expected)

    def test_exec_summary_progress_event_version_contract(self):
        self.assertEqual(EXEC_SUMMARY_PROGRESS_EVENT_VERSION, 2)

    def test_progress_timestamp_iso_utc_z_with_millisecond_precision(self):
        from oasis.report import progress_timestamp_iso

        ts = progress_timestamp_iso()
        self.assertTrue(ts.endswith("Z"), ts)
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$", msg=ts)

    def test_pipeline_phase_counts_parses_progress_cells(self):
        self.assertEqual(parse_phase_counts_from_progress_cell("10/10"), (10, 10))
        self.assertEqual(parse_phase_counts_from_progress_cell("2 / 5 extra"), (2, 5))
        self.assertEqual(parse_phase_counts_from_progress_cell("7/10 (100%)"), (7, 10))
        self.assertEqual(parse_phase_counts_from_progress_cell("3"), (3, 3))
        self.assertIsNone(parse_phase_counts_from_progress_cell("no digits"))
        self.assertIsNone(parse_phase_counts_from_progress_cell(""))

    @unittest.skipIf(EmbeddingProgressThrottle is None, "oasis.embedding unavailable")
    def test_embedding_progress_throttle_force_emit_normalizes_invalid_total(self):
        calls = []
        hook = lambda c, t: calls.append((c, t))
        throttle = EmbeddingProgressThrottle()
        throttle.maybe_emit(hook, 1, -5, min_interval_sec=0.0, force=True)
        throttle.maybe_emit(hook, 1, 0, min_interval_sec=0.0, force=True)
        throttle.maybe_emit(hook, 1, "bad", min_interval_sec=0.0, force=True)
        self.assertEqual(calls, [(0, 0), (0, 0), (0, 0)])
        throttle.maybe_emit(hook, 2, 5, min_interval_sec=0.0, force=True)
        self.assertEqual(calls, [(0, 0), (0, 0), (0, 0), (2, 5)])
        throttle.maybe_emit(hook, 1, 5.9, min_interval_sec=0.0, force=True)
        self.assertEqual(calls[-1], (1, 5))

    def test_scan_progress_helpers_build_consistent_labels(self):
        phases = standard_scan_phases(
            2,
            initial=(PhaseRowStatus.IN_PROGRESS.value, 0, 3),
            deep=(PhaseRowStatus.PENDING.value, 0, 3),
        )
        uniform = standard_scan_phases_vuln_types(
            2,
            3,
            initial_status=PhaseRowStatus.IN_PROGRESS,
            initial_completed=1,
            deep_status=PhaseRowStatus.PENDING,
            deep_completed=0,
        )
        self.assertEqual(uniform[1]["total"], uniform[2]["total"])
        self.assertEqual([p["id"] for p in phases], ["embeddings", "initial_scan", "deep_analysis"])
        self.assertEqual(phases[0]["label"], "Embeddings")
        sub = adaptive_subphases_payload(
            identify_files=(PhaseRowStatus.IN_PROGRESS.value, 0, 3),
            batch_process=(PhaseRowStatus.PENDING.value, 0, 1),
            collect_results=(PhaseRowStatus.PENDING.value, 0, 3),
        )
        self.assertEqual(sub["identify_files"]["label"], "Identify vulnerable files")
        self.assertEqual(sub["batch_process"]["label"], "Batch processing")
        self.assertEqual(sub["collect_results"]["label"], "Collect results")

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_get_scan_progress_returns_latest_summary_progress(self):
        server = WebServer.__new__(WebServer)
        server.report_data = [
            {
                "format": "json",
                "vulnerability_type": "Executive Summary",
                "progress": {
                    "completed_vulnerabilities": 1,
                    "total_vulnerabilities": 4,
                    "is_partial": True,
                },
                "model": "Model A",
                "date": "2026-04-17 10:00:00",
                "path": "run_a/model_a/json/_executive_summary.json",
            },
            {
                "format": "json",
                "vulnerability_type": "Executive Summary",
                "progress": {
                    "completed_vulnerabilities": 4,
                    "total_vulnerabilities": 4,
                    "is_partial": False,
                },
                "model": "Model B",
                "date": "2026-04-17 11:00:00",
                "path": "run_b/model_b/json/_executive_summary.json",
            },
        ]
        server.collect_report_data = lambda: None

        with Flask(__name__).test_request_context("/api/progress"):
            progress = server.get_scan_progress()

        self.assertTrue(progress["has_progress"])
        self.assertEqual(progress["completed_vulnerabilities"], 4)
        self.assertEqual(progress["total_vulnerabilities"], 4)
        self.assertFalse(progress["is_partial"])
        self.assertEqual(progress["model"], "Model B")
        self.assertEqual(progress["current_vulnerability"], "")
        self.assertEqual(progress["tested_vulnerabilities"], [])

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_get_scan_progress_accepts_markdown_summary_progress(self):
        server = WebServer.__new__(WebServer)
        server.report_data = []
        filtered_reports = [
            {
                "format": "md",
                "vulnerability_type": "Executive Summary",
                "progress": {
                    "completed_vulnerabilities": 3,
                    "total_vulnerabilities": 7,
                    "is_partial": True,
                },
                "model": "Model MD",
                "date": "2026-04-17 12:00:00",
                "path": "run_md/model_md/md/_executive_summary.md",
            }
        ]
        server.collect_report_data = lambda: None

        with Flask(__name__).test_request_context("/api/progress"):
            progress = server.get_scan_progress(filtered_reports=filtered_reports)

        self.assertTrue(progress["has_progress"])
        self.assertEqual(progress["completed_vulnerabilities"], 3)
        self.assertEqual(progress["total_vulnerabilities"], 7)
        self.assertTrue(progress["is_partial"])
        self.assertEqual(progress["model"], "Model MD")
        self.assertEqual(progress["current_vulnerability"], "")
        self.assertEqual(progress["tested_vulnerabilities"], [])

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_emit_scan_progress_emits_socketio_event(self):
        server = WebServer.__new__(WebServer)
        emitted = {}
        server.socketio = SimpleNamespace(emit=lambda event, payload: emitted.update({"event": event, "payload": payload}))
        server.emit_scan_progress(
            {
                "completed_vulnerabilities": 1,
                "total_vulnerabilities": 3,
                "is_partial": True,
                "model": "Model A",
            }
        )
        self.assertEqual(emitted["event"], "scan_progress")
        self.assertEqual(emitted["payload"]["event_version"], 1)
        self.assertEqual(emitted["payload"]["completed_vulnerabilities"], 1)
        self.assertEqual(emitted["payload"]["total_vulnerabilities"], 3)
        self.assertTrue(emitted["payload"]["is_partial"])
        self.assertEqual(emitted["payload"]["status"], "in_progress")
        self.assertEqual(emitted["payload"]["current_vulnerability"], "")
        self.assertEqual(emitted["payload"]["tested_vulnerabilities"], [])

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_emit_scan_progress_coerces_event_version_to_int(self):
        from oasis.web import _coerce_scan_progress_event_version

        self.assertEqual(_coerce_scan_progress_event_version("2"), 2)
        self.assertEqual(_coerce_scan_progress_event_version("v2"), 1)
        self.assertEqual(_coerce_scan_progress_event_version(None), 1)
        self.assertEqual(_coerce_scan_progress_event_version(True), 1)
        self.assertEqual(_coerce_scan_progress_event_version(False), 1)

        server = WebServer.__new__(WebServer)
        emitted = {}
        server.socketio = SimpleNamespace(emit=lambda event, payload: emitted.update({"event": event, "payload": payload}))
        server.emit_scan_progress(
            {
                "completed_vulnerabilities": 0,
                "total_vulnerabilities": 1,
                "is_partial": True,
                "event_version": "2",
            }
        )
        self.assertEqual(emitted["payload"]["event_version"], 2)

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_filter_reports_keeps_executive_summary_visible_with_vulnerability_filter(self):
        server = WebServer.__new__(WebServer)
        server.report_data = [
            {"vulnerability_type": "SQL Injection", "model": "M1", "format": "json", "date": "2026-04-17 10:00:00", "language": "en"},
            {"vulnerability_type": "Executive Summary", "model": "M1", "format": "json", "date": "2026-04-17 10:00:00", "language": "en"},
            {"vulnerability_type": "XSS", "model": "M2", "format": "json", "date": "2026-04-17 10:00:00", "language": "fr"},
        ]
        server.collect_report_data = lambda: None

        filtered = server.filter_reports(vuln_filter="xss")
        vuln_types = {row["vulnerability_type"] for row in filtered}
        self.assertIn("Executive Summary", vuln_types)
        self.assertIn("XSS", vuln_types)
        self.assertNotIn("SQL Injection", vuln_types)

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_filter_reports_supports_language_filter(self):
        server = WebServer.__new__(WebServer)
        server.report_data = [
            {"vulnerability_type": "SQL Injection", "model": "M1", "format": "json", "date": "2026-04-17 10:00:00", "language": "en"},
            {"vulnerability_type": "Executive Summary", "model": "M1", "format": "json", "date": "2026-04-17 10:00:00", "language": "fr"},
            {"vulnerability_type": "XSS", "model": "M2", "format": "json", "date": "2026-04-17 10:00:00", "language": "fr"},
        ]
        server.collect_report_data = lambda: None

        filtered = server.filter_reports(language_filter="fr")
        self.assertEqual(len(filtered), 2)
        self.assertTrue(all((row.get("language") or "").lower() == "fr" for row in filtered))

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_socketio_cors_origins_match_web_port_and_config(self):
        from oasis import config

        server = WebServer.__new__(WebServer)
        server.web_port = 5001
        server.web_expose = "local"
        prev = config.REPORT.get("DASHBOARD_SOCKETIO_CORS_ALLOWED_ORIGINS")
        try:
            config.REPORT["DASHBOARD_SOCKETIO_CORS_ALLOWED_ORIGINS"] = []
            origins = server._socketio_cors_allowed_origins()
            self.assertIn("http://127.0.0.1:5001", origins)
            self.assertIn("http://localhost:5001", origins)

            config.REPORT["DASHBOARD_SOCKETIO_CORS_ALLOWED_ORIGINS"] = ["https://reports.example:{port}"]
            origins_extra = server._socketio_cors_allowed_origins()
            self.assertIn("https://reports.example:5001", origins_extra)
        finally:
            config.REPORT["DASHBOARD_SOCKETIO_CORS_ALLOWED_ORIGINS"] = prev

    def test_dashboard_socket_prefers_polling_transport_first(self):
        api_js = (
            Path(__file__).resolve().parents[1]
            / "oasis"
            / "static"
            / "js"
            / "dashboard"
            / "api.js"
        )
        content = api_js.read_text(encoding="utf-8")
        match = re.search(r"transports\s*:\s*\[([^\]]+)\]", content)
        self.assertIsNotNone(match, "Socket.IO transports option not found in api.js")
        inner = match[1]
        polling_m = re.search(r"\bpolling\b", inner)
        websocket_m = re.search(r"\bwebsocket\b", inner)
        self.assertIsNotNone(polling_m, "Expected 'polling' in transports array")
        self.assertIsNotNone(websocket_m, "Expected 'websocket' in transports array")
        self.assertLess(
            polling_m.start(),
            websocket_m.start(),
            "polling transport should be listed before websocket",
        )

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
