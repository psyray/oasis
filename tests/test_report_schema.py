"""Tests for structured report schemas and stats aggregation."""

import importlib.util
import json
import math
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
from oasis.helpers.dashboard import (
    EXEC_SUMMARY_EMBEDDING_TIER_ORDER,
    audit_metrics_from_audit_payload,
    audit_metrics_from_markdown_content,
    executive_summary_similarity_tier_id,
    iter_audit_metrics_table_rows,
    parse_phase_counts_from_progress_cell,
)
from oasis.helpers.progress import (
    EXEC_SUMMARY_PROGRESS_EVENT_VERSION,
    SCAN_PROGRESS_EXTENDED_KEYS,
    scan_progress_tested_and_current,
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
    from oasis.schemas.audit_report import (
        AuditMatchResult,
        AuditMetrics,
        AuditPerVulnStatistics,
        AuditReportDocument,
        AuditThresholdRow,
        AuditVulnerabilitySection,
    )
except ModuleNotFoundError:
    _spec_ar = importlib.util.spec_from_file_location(
        "oasis_schemas_audit_report",
        ROOT / "oasis" / "schemas" / "audit_report.py",
    )
    _audit_m = importlib.util.module_from_spec(_spec_ar)
    assert _spec_ar and _spec_ar.loader is not None
    _spec_ar.loader.exec_module(_audit_m)
    AuditMatchResult = _audit_m.AuditMatchResult
    AuditMetrics = _audit_m.AuditMetrics
    AuditPerVulnStatistics = _audit_m.AuditPerVulnStatistics
    AuditReportDocument = _audit_m.AuditReportDocument
    AuditThresholdRow = _audit_m.AuditThresholdRow
    AuditVulnerabilitySection = _audit_m.AuditVulnerabilitySection

try:
    from oasis.analyze import SecurityAnalyzer
except ModuleNotFoundError:
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
    from oasis.helpers.embedding import EmbeddingProgressThrottle
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

    def test_exec_summary_similarity_tiers_use_shared_single_source(self):
        self.assertEqual(executive_summary_similarity_tier_id(0.95), "strong")
        self.assertEqual(executive_summary_similarity_tier_id(0.8), "strong")
        self.assertEqual(executive_summary_similarity_tier_id(0.79), "moderate")
        self.assertEqual(executive_summary_similarity_tier_id(0.6), "moderate")
        self.assertEqual(executive_summary_similarity_tier_id(0.59), "weak")
        self.assertEqual(executive_summary_similarity_tier_id(1.5), "strong")
        self.assertEqual(executive_summary_similarity_tier_id(-0.2), "weak")
        self.assertEqual(executive_summary_similarity_tier_id(math.nan), "weak")
        self.assertEqual([tier_id for tier_id, _ in EXEC_SUMMARY_EMBEDDING_TIER_ORDER], ["strong", "moderate", "weak"])

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_exec_summary_similarity_groups_follow_tier_order_contract(self):
        report = Report.__new__(Report)
        groups = report._executive_summary_similarity_groups(
            {
                "SQL Injection": [
                    {"file_path": "a.py", "similarity_score": 0.95},
                    {"file_path": "b.py", "similarity_score": 0.75},
                    {"file_path": "c.py", "similarity_score": 0.20},
                ]
            }
        )
        self.assertEqual(list(groups.keys()), [tier_id for tier_id, _ in EXEC_SUMMARY_EMBEDDING_TIER_ORDER])
        self.assertEqual(len(groups["strong"]), 1)
        self.assertEqual(len(groups["moderate"]), 1)
        self.assertEqual(len(groups["weak"]), 1)

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

    def test_audit_report_document_roundtrip(self):
        doc = AuditReportDocument(
            generated_at="2026-01-01 12:00:00",
            oasis_version="0.5.0",
            embedding_model="test-embed",
            total_files_analyzed=2,
            explain_analysis="\n## About\nSample explain.\n",
            audit_metrics=AuditMetrics(
                count=2,
                has_scores=True,
                total_items=2,
                scored_items=2,
                avg_score=0.77,
                median_score=0.76,
                max_score=0.79,
                min_score=0.75,
                high=1,
                medium=1,
                low=0,
            ),
            vulnerability_statistics=[
                {
                    "name": "Total",
                    "total": 2,
                    "high": 1,
                    "medium": 1,
                    "low": 0,
                    "is_total": True,
                }
            ],
            analyses={
                "SQL Injection": AuditVulnerabilitySection(
                    threshold_analysis=[
                        AuditThresholdRow(threshold=0.5, matching_items=2, percentage=100.0)
                    ],
                    results=[
                        AuditMatchResult(similarity_score=0.79, item_id="a.py"),
                        AuditMatchResult(similarity_score=0.75, item_id="b.py"),
                    ],
                    statistics=AuditPerVulnStatistics(
                        avg_score=0.77,
                        median_score=0.77,
                        max_score=0.79,
                        min_score=0.75,
                    ),
                )
            },
        )
        raw = doc.model_dump_json()
        restored = AuditReportDocument.model_validate_json(raw)
        self.assertEqual(restored.report_type, "audit")
        self.assertEqual(restored.analyses["SQL Injection"].statistics.max_score, 0.79)

    def test_audit_metrics_from_audit_payload_maps_dashboard_keys(self):
        payload = {
            "report_type": "audit",
            "audit_metrics": {
                "count": 4,
                "avg_score": 0.8125,
                "median_score": 0.8,
                "high": 2,
                "medium": 1,
                "low": 1,
                "total_items": 10,
                "scored_items": 4,
                "has_scores": True,
            },
        }
        metrics = audit_metrics_from_audit_payload(payload)
        self.assertEqual(metrics["count"], 4)
        self.assertAlmostEqual(metrics["avg_score"], 0.8125)
        self.assertEqual(metrics["total_items"], 10)
        self.assertNotIn("has_scores", metrics)

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_audit_metrics_markdown_matches_json_metrics_overlapping_keys(self):
        """Markdown table parsing and canonical JSON expose the same numeric dashboard keys."""

        class _FakeEmbeddingManager:
            embedding_model = "emb-test"

            def get_embeddings_info(self):
                return {"total_files": 4}

        analyzer_results = {
            "vulnerability_statistics": [
                {
                    "name": "Total",
                    "total": 10,
                    "high": 3,
                    "medium": 4,
                    "low": 3,
                    "is_total": True,
                },
            ],
            "SQL Injection": {
                "threshold_analysis": [
                    {"threshold": 0.5, "matching_items": 2, "percentage": 40.0}
                ],
                "results": [
                    {"similarity_score": 0.91, "item_id": "x.py"},
                    {"similarity_score": 0.72, "item_id": "y.py"},
                ],
                "statistics": {
                    "avg_score": 0.815,
                    "median_score": 0.815,
                    "max_score": 0.91,
                    "min_score": 0.72,
                },
            },
        }

        report = Report(input_path=".", output_format=["md", "json"])
        doc = report._build_audit_document(analyzer_results, _FakeEmbeddingManager())
        md_text = "\n".join(report._audit_report_markdown_lines_from_document(doc))
        from_md = audit_metrics_from_markdown_content(md_text)
        from_json = audit_metrics_from_audit_payload(doc.model_dump(mode="json"))
        overlap = sorted(set(from_md.keys()) & set(from_json.keys()))
        self.assertTrue(overlap)
        for key in overlap:
            self.assertAlmostEqual(float(from_md[key]), float(from_json[key]), places=5)

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_render_report_html_from_json_payload_supports_audit(self):
        report = Report(input_path=".", output_format=["md"])
        payload = {
            "report_type": "audit",
            "schema_version": 1,
            "title": "Embeddings Distribution Analysis Report",
            "generated_at": "2026-04-28 12:00:00",
            "language": "en",
            "project": None,
            "oasis_version": "0.5.0",
            "embedding_model": "nomic",
            "total_files_analyzed": 1,
            "explain_analysis": "## About\nTest.",
            "audit_metrics": {"count": 1, "avg_score": 0.5, "high": 0, "medium": 1, "low": 0},
            "vulnerability_statistics": [],
            "analyses": {},
        }
        html = report.render_report_html_from_json_payload(payload)
        self.assertIn("Embeddings Distribution Analysis Report", html)
        self.assertIn("nomic", html)

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_render_report_html_from_json_payload_supports_executive_summary(self):
        report = Report(input_path=".", output_format=["md"])
        payload = {
            "report_type": "executive_summary",
            "title": "Executive Summary",
            "generated_at": "2026-01-01T00:00:00Z",
            "model_name": "deep-model",
            "deep_model": "deep-model",
            "small_model": "scan-model",
            "embedding_model": "embed-model",
            "vulnerability_summary": {"SQL Injection": 2, "XSS": 1},
            "similarity_tier_counts": {"strong": 2, "moderate": 1, "weak": 0},
        }

        html = report.render_report_html_from_json_payload(payload)

        self.assertIn("Executive Summary", html)
        self.assertIn("deep-model", html)
        self.assertIn("SQL Injection", html)
        self.assertIn("strong", html)
        self.assertIn('class="executive-preview"', html)
        self.assertIn('class="report-toc executive-preview-toc"', html)
        self.assertIn('id="table-of-contents"', html)
        self.assertIn('id="exec-models"', html)
        self.assertIn('href="#exec-vuln-summary"', html)
        self.assertIn('href="#assistant"', html)
        self.assertIn('id="exec-situation"', html)
        self.assertIn("Security posture at a glance", html)
        self.assertIn("How to read this executive summary", html)
        self.assertIn("Priority embedding matches", html)
        self.assertIn('data-oasis-exec-before-overview="1"', html)
        self.assertLess(
            html.find('id="table-of-contents"'),
            html.find('id="exec-situation"'),
        )

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_render_executive_summary_html_without_output_base_dir_does_not_crash(self):
        report = Report(input_path=".", output_format=["md"])
        payload = {
            "report_type": "executive_summary",
            "title": "Executive Summary",
            "generated_at": "2026-01-01T00:00:00Z",
            "model_name": "deep-model",
            "deep_model": "deep-model",
            "small_model": "scan-model",
            "embedding_model": "embed-model",
            "vulnerability_summary": {"SQL Injection": 1},
            "similarity_tier_counts": {"strong": 1, "moderate": 0, "weak": 0},
            "similarity_highlights": [
                {
                    "tier_id": "strong",
                    "vuln_type": "SQL Injection",
                    "file_path": "app.py",
                    "similarity_score": 0.95,
                }
            ],
        }

        html = report.render_report_html_from_json_payload(payload)
        self.assertIn("Executive Summary", html)

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_render_executive_summary_html_builds_detail_link_from_preview_context(self):
        report = Report(input_path=".", output_format=["md"])
        with tempfile.TemporaryDirectory() as td:
            sec = Path(td) / "security_reports"
            model_dir = sec / "proj" / "20260101_120000" / "embed_model"
            json_dir = model_dir / "json"
            json_dir.mkdir(parents=True)
            (json_dir / "_executive_summary.json").write_text("{}", encoding="utf-8")
            (json_dir / "sql_injection.json").write_text("{}", encoding="utf-8")
            current = json_dir / "_executive_summary.json"

            payload = {
                "report_type": "executive_summary",
                "title": "Executive Summary",
                "generated_at": "2026-01-01T00:00:00Z",
                "model_name": "embed_model",
                "deep_model": "embed_model",
                "small_model": "scan-model",
                "embedding_model": "embed-model",
                "vulnerability_summary": {"SQL Injection": 1},
                "similarity_tier_counts": {"strong": 1, "moderate": 0, "weak": 0},
                "similarity_highlights": [
                    {
                        "tier_id": "strong",
                        "vuln_type": "SQL Injection",
                        "file_path": "app.py",
                        "similarity_score": 0.95,
                    }
                ],
            }
            html = report._render_executive_summary_inner_html(
                payload,
                preview_context={
                    "_security_root": sec.resolve(),
                    "_current_report_path": current.resolve(),
                },
            )
            self.assertIn("/reports/proj/20260101_120000/embed_model/json/sql_injection.json", html)

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_render_report_html_from_json_payload_autoescapes_all_modal_templates(self):
        report = Report(input_path=".", output_format=["md"])

        exec_payload = {
            "report_type": "executive_summary",
            "title": "Executive Summary",
            "generated_at": "2026-01-01T00:00:00Z",
            "model_name": "deep-model",
            "deep_model": "deep-model",
            "small_model": "scan-model",
            "embedding_model": "embed-model",
            "project": '<img src=x onerror=alert("xss")>',
            "vulnerability_summary": {},
            "similarity_tier_counts": {},
        }
        exec_html = report.render_report_html_from_json_payload(exec_payload)
        self.assertIn("&lt;img src=x onerror=alert", exec_html)
        self.assertNotIn('<img src=x onerror=alert("xss")>', exec_html)

        audit_payload = {
            "report_type": "audit",
            "schema_version": 1,
            "title": '<script>alert("xss")</script>',
            "generated_at": "2026-04-28 12:00:00",
            "language": "en",
            "project": None,
            "oasis_version": "0.5.0",
            "embedding_model": "nomic",
            "total_files_analyzed": 1,
            "explain_analysis": "## About\nSafe content.",
            "audit_metrics": {"count": 1, "avg_score": 0.5, "high": 0, "medium": 1, "low": 0},
            "vulnerability_statistics": [],
            "analyses": {},
        }
        audit_html = report.render_report_html_from_json_payload(audit_payload)
        self.assertIn("&lt;script&gt;alert", audit_html)
        self.assertNotIn('<script>alert("xss")</script>', audit_html)

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_executive_summary_html_rejects_noncanonical_guidance_markdown(self):
        """HTML rendering must not convert attacker-controlled Markdown from JSON to HTML."""
        from oasis.config import REPORT

        report = Report(input_path=".", output_format=["md"])
        malicious = '<script>alert("x")</script>\n\n## Evil'
        payload = {
            "report_type": "executive_summary",
            "title": "Executive Summary",
            "generated_at": "2026-01-01T00:00:00Z",
            "model_name": "m",
            "guidance_markdown": malicious,
            "vulnerability_summary": {},
            "similarity_tier_counts": {},
        }
        html = report.render_report_html_from_json_payload(payload)
        self.assertNotIn("<script>", html)
        self.assertNotIn("Evil", html)
        self.assertIn("embedding similarity", html.lower())

        trusted = REPORT["EXPLAIN_EXECUTIVE_SUMMARY"].strip()
        payload["guidance_markdown"] = trusted
        html_ok = report.render_report_html_from_json_payload(payload)
        self.assertIn("embedding similarity", html_ok.lower())

        payload["guidance_id"] = "default.v1"
        payload["guidance_markdown"] = trusted + "\n\n<script>tampered()</script>"
        html_tampered = report.render_report_html_from_json_payload(payload)
        self.assertNotIn("<script>", html_tampered)
        self.assertNotIn("tampered()", html_tampered)
        self.assertIn("embedding similarity", html_tampered.lower())

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_build_executive_summary_json_document_handles_none_deep_model_name(self):
        report = Report.__new__(Report)

        payload = report._build_executive_summary_json_document(
            all_results={},
            model_name="fallback-model",
            deep_model_name=None,
            scan_model_name="scan-model",
            embedding_model_name="embed-model",
            similarity_groups={},
        )

        self.assertEqual(payload["model_name"], "fallback-model")
        self.assertEqual(payload["deep_model"], "")
        self.assertEqual(payload.get("schema_version"), 2)
        self.assertEqual(payload["overview"]["vulnerability_types_count"], 0)
        self.assertEqual(payload["overview"]["embedding_comparisons_total"], 0)
        self.assertEqual(payload["overview"]["unique_source_files"], 0)
        self.assertIn("guidance_markdown", payload)
        self.assertEqual(len(payload["tier_definitions"]), 3)
        self.assertEqual(payload["similarity_highlights"], [])

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_render_report_html_from_json_payload_rejects_unknown_report_type(self):
        report = Report(input_path=".", output_format=["md"])
        with self.assertRaises(ValueError):
            report.render_report_html_from_json_payload({"report_type": "unknown"})

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_render_report_html_from_json_payload_escapes_finding_fields(self):
        report = Report(input_path=".", output_format=["md"])
        payload = {
            "report_type": "vulnerability",
            "schema_version": 5,
            "title": "Escaping Regression",
            "generated_at": "2026-01-01",
            "model_name": "m1",
            "vulnerability_name": "Injection",
            "vulnerability": {"name": "Injection"},
            "files": [
                {
                    "file_path": "test_files/vulnerable.php",
                    "similarity_score": 0.9,
                    "chunk_analyses": [
                        {
                            "start_line": 1,
                            "end_line": 10,
                            "findings": [
                                {
                                    "title": "Broken payload rendering",
                                    "severity": "High",
                                    "vulnerable_code": "return eval($code);",
                                    "explanation": "payload closes code tag",
                                    "example_payloads": [
                                        "</code></li></ul><code>",
                                    ],
                                }
                            ],
                        }
                    ],
                },
                {
                    "file_path": "test_files/safe.java",
                    "similarity_score": 0.8,
                    "chunk_analyses": [],
                },
            ],
            "stats": {
                "critical_risk": 0,
                "high_risk": 1,
                "medium_risk": 0,
                "low_risk": 0,
                "total_findings": 1,
                "files_analyzed": 2,
            },
        }

        html = report.render_report_html_from_json_payload(payload)
        self.assertIn("File 2: test_files/safe.java", html)
        self.assertIn("&lt;/code&gt;&lt;/li&gt;&lt;/ul&gt;&lt;code&gt;", html)
        self.assertNotIn("</code></li></ul><code>", html)

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_render_report_html_from_json_payload_whitelists_severity_css_suffix(self):
        report = Report(input_path=".", output_format=["md"])
        template = report.template_env.get_template("reports/vulnerability_from_json.html.j2")
        html = template.render(
            document={
                "title": "Severity Suffix Safety",
                "generated_at": "2026-01-01",
                "model_name": "m1",
                "vulnerability_name": "Injection",
                "files": [
                    {
                        "file_path": "test_files/vulnerable.php",
                        "similarity_score": 0.9,
                        "chunk_analyses": [
                            {
                                "findings": [
                                    {
                                        "title": "Unexpected severity format",
                                        "severity": 'high" onclick="alert(1)',
                                        "vulnerable_code": "return eval($code);",
                                        "explanation": "test",
                                    }
                                ]
                            }
                        ],
                    }
                ],
                "stats": {"files_analyzed": 1, "total_findings": 1},
            },
            preview={},
        )
        self.assertIn("report-severity-pill--unknown", html)
        self.assertNotIn('report-severity-pill--high" onclick=', html)

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

    def test_chunk_analysis_to_markdown_includes_http_raw_requests(self):
        chunk = ChunkDeepAnalysis(
            findings=[
                VulnerabilityFinding(
                    title="API issue",
                    vulnerable_code="x",
                    explanation="y",
                    severity="Medium",
                    http_raw_requests=["GET /api?q=1 HTTP/1.1\nHost: example.test"],
                )
            ]
        )
        markdown = chunk_analysis_to_markdown(chunk, 0)
        self.assertIn("HTTP raw requests", markdown)
        self.assertIn("GET /api?q=1 HTTP/1.1", markdown)

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

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_executive_summary_includes_partial_progress_block(self):
        report = Report.__new__(Report)
        report.output_format = ["md"]
        report.output_base_dir = Path("/tmp")
        report.current_model = "test-model"
        report.executive_summary_scan_model = "small-model"
        report.executive_summary_embedding_model = "embed-model"
        report._executive_summary_sidecar_write_failed = False
        report.report_dirs = {"test_model": {"md": Path("/tmp")}}
        report.create_header = lambda title, model_name: [f"# {title}", f"Model: {model_name}"]
        with tempfile.TemporaryDirectory() as td:
            run_md = Path(td) / "embed_model" / "md" / "_executive_summary.md"
            run_md.parent.mkdir(parents=True)
            report.filter_output_files = lambda safe_name: {"md": run_md}
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

            canon = Path(td) / "embed_model" / "json" / "_executive_summary.json"
            self.assertTrue(canon.is_file())
            parsed = json.loads(canon.read_text(encoding="utf-8"))
            self.assertEqual(parsed.get("report_type"), "executive_summary")
            self.assertEqual(parsed.get("schema_version"), 2)
            self.assertEqual(parsed.get("model_name"), "test-model")
            self.assertEqual(parsed.get("vulnerability_summary"), {"SQL Injection": 1})
            self.assertEqual(parsed["overview"]["vulnerability_types_count"], 1)
            self.assertEqual(parsed["overview"]["embedding_comparisons_total"], 1)
            self.assertEqual(parsed["overview"]["unique_source_files"], 1)
            self.assertEqual(len(parsed.get("similarity_highlights") or []), 1)
            hl0 = parsed["similarity_highlights"][0]
            self.assertEqual(hl0.get("tier_id"), "strong")
            self.assertIn("tier_description", hl0)
            self.assertIn("Strong", hl0["tier_description"])

            content = "\n".join(captured["report_content"])
            self.assertIn("Scan Progress", content)
            self.assertIn("1/3", content)
            self.assertIn("partial", content.lower())
            self.assertIn("Strong embedding match", content)
            self.assertIn("| Similarity |", content)
            self.assertIn("Deep model: test-model", content)
            self.assertIn("Small model: small-model", content)
            self.assertIn("Embedding model: embed-model", content)
            self.assertNotIn("Risk Findings", content)

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

    @unittest.skipIf(publish_incremental_summary is None, "oasis.report dependencies are unavailable")
    def test_publish_incremental_summary_passes_allowed_extended_progress_fields(self):
        progresses: list = []

        report = SimpleNamespace(
            generate_executive_summary=lambda all_results, llm_model, progress=None: progresses.append(
                progress
            )
        )

        publish_incremental_summary(
            report,
            "model-z",
            {"SQL Injection": []},
            completed_vulnerabilities=1,
            total_vulnerabilities=2,
            current_vulnerability="sqli",
            tested_vulnerabilities=["sqli"],
            event_version=2,
            vulnerability_types_total=7,
            active_phase="deep_analysis",
        )

        payload = progresses[-1]
        self.assertEqual(payload["event_version"], 2)
        self.assertEqual(payload["vulnerability_types_total"], 7)
        self.assertEqual(payload["active_phase"], "deep_analysis")

    def test_sanitize_name_strips_path_suffix_and_special_characters(self):
        from oasis.tools import sanitize_name

        self.assertEqual(sanitize_name("group/sub/Vuln Name!.md"), "Vuln_Name__md")

    @unittest.skipIf(
        WebServer is None or Report is None,
        "oasis.web or oasis.report dependencies are unavailable",
    )
    def test_web_get_report_statistics_empty_filtered_list(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            inp = base / "scan_root"
            inp.mkdir()
            (inp / "module.py").write_text("#", encoding="utf-8")
            report = Report(str(inp), ["json"])
            server = WebServer(report)
            server.report_data = []
            server.collect_report_data = lambda: None
            app = Flask(__name__)
            with app.test_request_context("/api/stats"):
                stats = server.get_report_statistics(filtered_reports=[])

        self.assertEqual(stats.get("formats"), {})
        self.assertEqual(stats["risk_summary"]["total_findings"], 0)
        self.assertEqual(stats["risk_summary"]["critical"], 0)
        self.assertEqual(stats.get("severity_finding_totals", {}).get("critical"), 0)

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_executive_summary_notifier_receives_progress_payload(self):
        report = Report.__new__(Report)
        report.output_format = ["md"]
        report.output_base_dir = Path("/tmp")
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
    def test_normalize_dashboard_relative_report_path_handles_separators_and_dot_segments(self):
        normalize = WebServer._normalize_dashboard_relative_report_path
        self.assertEqual(
            normalize(r"./20260101_120000\m1\json\.\auth.json"),
            "20260101_120000/m1/json/auth.json",
        )
        self.assertEqual(
            normalize("20260101_120000/m1/json/../json/auth.json"),
            "20260101_120000/m1/json/auth.json",
        )
        self.assertEqual(normalize(r"\windows\rooted.json"), "")
        self.assertEqual(normalize("/unix/rooted.json"), "")
        self.assertEqual(normalize("../outside.json"), "")

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_filter_vulnerability_payload_by_severity_tiers_counts_non_canonical_total_findings(self):
        payload = {
            "report_type": "vulnerability",
            "files": [
                {
                    "file_path": "x.py",
                    "chunk_analyses": [
                        {
                            "findings": [
                                {"severity": "High"},
                                {"severity": "Info"},
                            ]
                        }
                    ],
                }
            ],
            "stats": {"total_findings": 2},
        }
        filtered = WebServer._filter_vulnerability_payload_by_severity_tiers(payload, ("high", "info"))
        self.assertEqual(filtered["stats"]["high_risk"], 1)
        self.assertEqual(filtered["stats"]["total_findings"], 2)
        self.assertEqual(filtered["stats_unfiltered"]["total_findings"], 2)

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_allowed_paths_for_filtered_reports_collects_primary_and_alternatives(self):
        reports = [
            {
                "path": "run_a/model_a/json/a.json",
                "alternative_formats": {
                    "md": r".\run_a\model_a\md\a.md",
                    "html": "/absolute/should_be_rejected.html",
                },
            },
            {
                "path": "run_a/model_a/json/b.json",
                "alternative_formats": {},
            },
        ]
        allowed = WebServer._allowed_paths_for_filtered_reports(reports)
        self.assertEqual(
            allowed,
            {
                "run_a/model_a/json/a.json",
                "run_a/model_a/md/a.md",
                "run_a/model_a/json/b.json",
            },
        )

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_update_stats_for_report_aggregates_model_vuln_language_date_and_risk(self):
        server = WebServer.__new__(WebServer)
        stats = {
            "total_reports": 0,
            "models": {},
            "vulnerabilities": {},
            "languages": {},
            "dates": {},
            "risk_summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
        }
        server._update_stats_for_report(
            stats,
            {
                "format": "json",
                "model": "ModelA",
                "vulnerability_type": "SQL Injection",
                "language": "FR",
                "date": "2026-04-19 10:00:00",
                "stats": {
                    "total_findings": 6,
                    "critical_risk": 1,
                    "high_risk": 2,
                    "medium_risk": 2,
                    "low_risk": 1,
                },
            },
        )
        self.assertEqual(stats["total_reports"], 1)
        self.assertEqual(stats["models"]["ModelA"], 1)
        self.assertEqual(stats["vulnerabilities"]["SQL Injection"], 1)
        self.assertEqual(stats["languages"]["fr"], 1)
        self.assertEqual(stats["dates"]["2026-04-19"], 1)
        self.assertEqual(stats["risk_summary"]["total_findings"], 6)
        self.assertEqual(stats["risk_summary"]["critical"], 1)
        self.assertEqual(stats["risk_summary"]["high"], 2)
        self.assertEqual(stats["risk_summary"]["medium"], 2)
        self.assertEqual(stats["risk_summary"]["low"], 1)

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
    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_audit_json_metrics_reader_extracts_summary_metrics(self):
        import tempfile

        payload = {"report_type": "audit", "audit_metrics": {"count": 7, "avg_score": 0.551}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tmp:
            json.dump(payload, tmp)
            path = Path(tmp.name)
        try:
            metrics = WebServer._audit_metrics_from_audit_json_report_file(path)
            self.assertEqual(metrics["count"], 7)
            self.assertAlmostEqual(metrics["avg_score"], 0.551)
        finally:
            path.unlink(missing_ok=True)

    def test_web_audit_markdown_metrics_reader_extracts_summary_metrics(self):
        markdown = """# Embeddings Distribution Analysis Report

## Audit Metrics Summary

| Metric | Value |
|--------|-------|
| Count | 10 |
| Average similarity | 0.450 |
| Median similarity | 0.430 |
| Maximum similarity | 0.910 |
| Minimum similarity | 0.120 |
| High matches (>= 0.8) | 2 |
| Medium matches (>= 0.6 and < 0.8) | 3 |
| Low matches (>= 0.4 and < 0.6) | 5 |
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = Path(tmp_dir) / "audit_report.md"
            report_file.write_text(markdown, encoding="utf-8")
            metrics = WebServer._audit_metrics_from_markdown_report_file(report_file)
        self.assertEqual(metrics["count"], 10)
        self.assertAlmostEqual(metrics["avg_score"], 0.45)
        self.assertAlmostEqual(metrics["median_score"], 0.43)
        self.assertAlmostEqual(metrics["max_score"], 0.91)
        self.assertAlmostEqual(metrics["min_score"], 0.12)
        self.assertEqual(metrics["high"], 2)
        self.assertEqual(metrics["medium"], 3)
        self.assertEqual(metrics["low"], 5)

    def test_report_audit_metrics_summary_tolerates_missing_score_fields(self):
        report_lines = []
        summary_metrics = {
            "count": 4,
            "total_items": 12,
            "scored_items": 4,
            "has_scores": True,
            "high": 2,
            "medium": 1,
            "low": 1,
        }

        Report._extend_audit_metrics_summary(report_lines, summary_metrics)

        rendered = "\n".join(report_lines)
        self.assertIn("| Count | 4 |", rendered)
        self.assertIn("| High matches (>= 0.8) | 2 |", rendered)
        self.assertNotIn("Average similarity", rendered)
        self.assertNotIn("Median similarity", rendered)
        self.assertNotIn("Maximum similarity", rendered)
        self.assertNotIn("Minimum similarity", rendered)

    def test_report_audit_metrics_summary_skips_invalid_score_values(self):
        report_lines = []
        summary_metrics = {
            "count": 4,
            "total_items": 12,
            "scored_items": 4,
            "has_scores": True,
            "avg_score": "N/A",
            "median_score": "0.456",
            "max_score": "inf",
            "min_score": object(),
            "high": 2,
            "medium": 1,
            "low": 1,
        }

        Report._extend_audit_metrics_summary(report_lines, summary_metrics)

        rendered = "\n".join(report_lines)
        self.assertNotIn("Average similarity", rendered)
        self.assertIn("| Median similarity | 0.456 |", rendered)
        self.assertNotIn("Maximum similarity", rendered)
        self.assertNotIn("Minimum similarity", rendered)

    def test_audit_metrics_markdown_helper_extracts_metrics(self):
        markdown = """# Embeddings Distribution Analysis Report

## Audit Metrics Summary

| Metric | Value |
|--------|-------|
| Count | 10 |
| Average similarity | 0.450 |
| High matches (>= 0.8) | 2 |
"""
        metrics = audit_metrics_from_markdown_content(markdown)
        self.assertEqual(metrics.get("count"), 10)
        self.assertAlmostEqual(metrics.get("avg_score"), 0.45)
        self.assertEqual(metrics.get("high"), 2)

    def test_audit_metrics_markdown_helper_stops_after_first_non_table_line(self):
        section = """
| Metric | Value |
|--------|-------|
| Count | 10 |

Not a table line anymore.
| Average similarity | 0.450 |
"""
        rows = list(iter_audit_metrics_table_rows(section))
        labels = [label for label, _ in rows]
        self.assertIn("count", labels)
        self.assertNotIn("average similarity", labels)

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_audit_markdown_metrics_reader_tolerates_heading_and_label_variations(self):
        markdown = """# Embeddings Distribution Analysis Report

## Similarity Metrics

| METRIC | VALUE |
|--------|-------|
| Count | 10 rows |
| Mean Similarity | 0.450 score |
| Median Similarity | 0.430 |
| Max Similarity | 0.910 |
| Min Similarity | 0.120 |
| High Tier Matches | 2 matches |
| Medium Tier Matches | 3 matches |
| Low Tier Matches | 5 matches |
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = Path(tmp_dir) / "audit_report.md"
            report_file.write_text(markdown, encoding="utf-8")
            metrics = WebServer._audit_metrics_from_markdown_report_file(report_file)
        self.assertEqual(metrics["count"], 10)
        self.assertAlmostEqual(metrics["avg_score"], 0.45)
        self.assertAlmostEqual(metrics["median_score"], 0.43)
        self.assertAlmostEqual(metrics["max_score"], 0.91)
        self.assertAlmostEqual(metrics["min_score"], 0.12)
        self.assertEqual(metrics["high"], 2)
        self.assertEqual(metrics["medium"], 3)
        self.assertEqual(metrics["low"], 5)

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_audit_markdown_metrics_reader_accepts_heading_with_inline_annotation(self):
        markdown = """# Embeddings Distribution Analysis Report

## Audit Metrics Summary (latest run)

| Metric | Value |
|--------|-------|
| Count | 11 |
| Average similarity | 0.510 |
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = Path(tmp_dir) / "audit_report.md"
            report_file.write_text(markdown, encoding="utf-8")
            metrics = WebServer._audit_metrics_from_markdown_report_file(report_file)
        self.assertEqual(metrics.get("count"), 11)
        self.assertAlmostEqual(metrics.get("avg_score"), 0.51)

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_audit_markdown_metrics_reader_keeps_partial_metrics(self):
        markdown = """# Embeddings Distribution Analysis Report

## Audit Metrics Summary

| Metric | Value |
|--------|-------|
| Count | 10 |
| Average similarity | 0.450 |
| High matches (>= 0.8) | 2 |
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = Path(tmp_dir) / "audit_report.md"
            report_file.write_text(markdown, encoding="utf-8")
            metrics = WebServer._audit_metrics_from_markdown_report_file(report_file)
        self.assertEqual(metrics.get("count"), 10)
        self.assertAlmostEqual(metrics.get("avg_score"), 0.45)
        self.assertEqual(metrics.get("high"), 2)
        self.assertNotEqual(metrics, {})

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_audit_markdown_metrics_reader_ignores_tables_outside_metrics_section(self):
        markdown = """# Embeddings Distribution Analysis Report

## Audit Metrics Summary

| Metric | Value |
|--------|-------|
| Count | 10 |
| Average similarity | 0.450 |
| High matches (>= 0.8) | 2 |

## Vulnerability Statistics

| Metric | Value |
|--------|-------|
| Count | 999 |
| Average similarity | 0.999 |
| High matches (>= 0.8) | 999 |
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = Path(tmp_dir) / "audit_report.md"
            report_file.write_text(markdown, encoding="utf-8")
            metrics = WebServer._audit_metrics_from_markdown_report_file(report_file)
        self.assertEqual(metrics.get("count"), 10)
        self.assertAlmostEqual(metrics.get("avg_score"), 0.45)
        self.assertEqual(metrics.get("high"), 2)

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_audit_markdown_metrics_reader_requires_metric_value_table_header(self):
        markdown = """# Embeddings Distribution Analysis Report

## Audit Metrics Summary

| Foo | Bar |
|-----|-----|
| Count | 999 |
| Average similarity | 0.999 |

| Metric | Value |
|--------|-------|
| Count | 7 |
| Average similarity | 0.321 |
"""
        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = Path(tmp_dir) / "audit_report.md"
            report_file.write_text(markdown, encoding="utf-8")
            metrics = WebServer._audit_metrics_from_markdown_report_file(report_file)
        self.assertEqual(metrics.get("count"), 7)
        self.assertAlmostEqual(metrics.get("avg_score"), 0.321)

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
        self.assertEqual(EXEC_SUMMARY_PROGRESS_EVENT_VERSION, 3)

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

    def test_scan_progress_tested_and_current_skips_non_sequence_tested_payloads(self):
        pairs = [
            ({"tested_vulnerabilities": ["sqli", " xss "]}, (["sqli", "xss"], "")),
            (
                {"tested_vulnerabilities": "sqli"},
                ([], ""),
            ),  # bare strings must not iterate character-by-character
            (
                {"current_vulnerability": None},
                ([], ""),
            ),
            (
                {"current_vulnerability": "  deep  ", "tested_vulnerabilities": ["a"]},
                (["a"], "deep"),
            ),
        ]
        for progress, expected in pairs:
            with self.subTest(progress=progress):
                self.assertEqual(scan_progress_tested_and_current(progress), expected)

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
                "adaptive_subphases": {
                    "sqli_file_a": {"label": "SQL Injection · test_files/Vulnerable.java", "completed": 0, "total": 51}
                },
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
        self.assertNotIn("adaptive_subphases", emitted["payload"])

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_emit_scan_progress_keeps_only_summary_phase_rows(self):
        server = WebServer.__new__(WebServer)
        emitted = {}
        server.socketio = SimpleNamespace(emit=lambda event, payload: emitted.update({"event": event, "payload": payload}))
        server.emit_scan_progress(
            {
                "completed_vulnerabilities": 1,
                "total_vulnerabilities": 3,
                "is_partial": True,
                "phases": [
                    {"id": "embeddings", "label": "Embeddings", "status": "complete", "completed": 5, "total": 5},
                    {
                        "id": "graph_deep",
                        "label": "Deep analysis",
                        "status": "in_progress",
                        "completed": 1,
                        "total": 3,
                    },
                    {
                        "id": "detail_sql_cs",
                        "label": "SQL Injection · test_files/Vulnerable.cs",
                        "status": "pending",
                        "completed": 0,
                        "total": 65,
                    },
                ],
            }
        )
        labels = [str(row.get("label")) for row in emitted["payload"].get("phases", [])]
        self.assertIn("Embeddings", labels)
        self.assertIn("Deep analysis", labels)
        self.assertNotIn("SQL Injection · test_files/Vulnerable.cs", labels)

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_web_emit_scan_progress_coerces_event_version_to_int(self):
        from oasis.helpers.progress import coerce_scan_progress_event_version

        self.assertEqual(coerce_scan_progress_event_version("2"), 2)
        self.assertEqual(coerce_scan_progress_event_version("v2"), 1)
        self.assertEqual(coerce_scan_progress_event_version(None), 1)
        self.assertEqual(coerce_scan_progress_event_version(True), 1)
        self.assertEqual(coerce_scan_progress_event_version(False), 1)

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
    def test_filter_reports_supports_model_filter_as_list(self):
        server = WebServer.__new__(WebServer)
        server.report_data = [
            {"vulnerability_type": "SQL Injection", "model": "Model A", "format": "json", "date": "2026-04-17 10:00:00", "language": "en"},
            {"vulnerability_type": "Executive Summary", "model": "Model B", "format": "json", "date": "2026-04-17 10:00:00", "language": "en"},
            {"vulnerability_type": "XSS", "model": "Model C", "format": "json", "date": "2026-04-17 10:00:00", "language": "en"},
        ]
        server.collect_report_data = lambda: None

        filtered = server.filter_reports(model_filter=["model a", "model b"])
        models = {row["model"] for row in filtered}
        self.assertEqual(models, {"Model A", "Model B"})

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_filter_reports_supports_severity_filter(self):
        server = WebServer.__new__(WebServer)
        server.report_data = [
            {
                "vulnerability_type": "SQL Injection",
                "model": "M1",
                "format": "json",
                "date": "2026-04-17 10:00:00",
                "language": "en",
                "stats": {"high_risk": 1, "critical_risk": 0, "medium_risk": 0, "low_risk": 0},
            },
            {
                "vulnerability_type": "XSS",
                "model": "M1",
                "format": "json",
                "date": "2026-04-17 10:00:00",
                "language": "en",
                "stats": {"high_risk": 0, "critical_risk": 0, "medium_risk": 2, "low_risk": 0},
            },
            {
                "vulnerability_type": "Executive Summary",
                "model": "M1",
                "format": "json",
                "date": "2026-04-17 10:00:00",
                "language": "en",
                "stats": {},
            },
        ]
        server.collect_report_data = lambda: None

        filtered = server.filter_reports(severity_filter="high")
        types = {row["vulnerability_type"] for row in filtered}
        self.assertEqual(types, {"SQL Injection", "Executive Summary"})

        filtered_med = server.filter_reports(severity_filter="medium")
        self.assertEqual({row["vulnerability_type"] for row in filtered_med}, {"XSS", "Executive Summary"})

    @unittest.skipIf(WebServer is None, "oasis.web dependencies are unavailable")
    def test_filter_reports_project_is_exact_match_not_substring(self):
        server = WebServer.__new__(WebServer)
        server.report_data = [
            {
                "vulnerability_type": "SQL Injection",
                "model": "M",
                "format": "json",
                "date": "2026-04-17 10:00:00",
                "language": "en",
                "project": "test",
            },
            {
                "vulnerability_type": "SQL Injection",
                "model": "M",
                "format": "json",
                "date": "2026-04-17 10:00:00",
                "language": "en",
                "project": "test_project",
            },
        ]
        server.collect_report_data = lambda: None

        filtered = server.filter_reports(project_filter="test")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["project"], "test")

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

    def test_dashboard_url_with_active_filters_preserves_hash_fragment(self):
        api_js = (
            Path(__file__).resolve().parents[1]
            / "oasis"
            / "static"
            / "js"
            / "dashboard"
            / "api.js"
        )
        content = api_js.read_text(encoding="utf-8")
        self.assertIn("const hashIndex = rawUrl.indexOf('#')", content)
        self.assertIn("const hashFragment = hashIndex >= 0 ? rawUrl.slice(hashIndex) : ''", content)
        self.assertIn("return `${pathPart}${mergedQuery ? `?${mergedQuery}` : ''}${hashFragment}`;", content)

    def test_dashboard_url_with_active_filters_merges_existing_query_with_urlsearchparams(self):
        api_js = (
            Path(__file__).resolve().parents[1]
            / "oasis"
            / "static"
            / "js"
            / "dashboard"
            / "api.js"
        )
        content = api_js.read_text(encoding="utf-8")
        self.assertIn("const mergedParams = new URLSearchParams(existingQuery)", content)
        self.assertIn("mergedParams.append(key, value)", content)

    def test_dashboard_views_include_audit_comparison_table_markup(self):
        views_js = (
            Path(__file__).resolve().parents[1]
            / "oasis"
            / "static"
            / "js"
            / "dashboard"
            / "views.js"
        )
        content = views_js.read_text(encoding="utf-8")
        self.assertIn("DashboardApp.buildDateTagInnerHtml", content)
        self.assertIn("datesSelectionBadgeHTML", content)
        self.assertIn("buildAuditComparisonTableHtml", content)
        self.assertIn("DashboardApp.auditComparison.buildTableHtml", content)
        self.assertIn("DashboardApp.modelSelectionBadgeHtml(0)", content)
        self.assertIn("critical_risk", content)
        self.assertIn(".replace('${criticalRisk}'", content)
        self.assertIn("data-model", content)

    def test_dashboard_utils_define_audit_comparison_builder(self):
        utils_js = (
            Path(__file__).resolve().parents[1]
            / "oasis"
            / "static"
            / "js"
            / "dashboard"
            / "utils.js"
        )
        content = utils_js.read_text(encoding="utf-8")
        self.assertIn("DashboardApp.auditComparison", content)
        self.assertIn("DashboardApp.buildDateTagInnerHtml", content)
        self.assertIn("model-emoji", content)
        self.assertIn("buildTableHtml", content)
        self.assertIn("Embedding models comparison (latest available audit scores)", content)
        self.assertIn("audit-comparison-table", content)
        self.assertIn("No comparable metrics available.", content)
        self.assertIn("formatAuditNumber", content)
        self.assertIn("getAuditRunWindowKey", content)
        self.assertIn("Object.keys(m).length > 0", content)

    def test_dashboard_card_template_supports_dynamic_card_class(self):
        template_html = (
            Path(__file__).resolve().parents[1]
            / "oasis"
            / "static"
            / "templates"
            / "dashboard_card.html"
        )
        content = template_html.read_text(encoding="utf-8")
        self.assertIn("${cardClass}", content)
        self.assertIn("${criticalRisk}", content)
        self.assertIn("Critical", content)

    def test_report_jinja_autoescape_is_scoped_to_html_like_templates(self):
        report_py = (
            Path(__file__).resolve().parents[1]
            / "oasis"
            / "report.py"
        )
        content = report_py.read_text(encoding="utf-8")
        self.assertIn('template_name.endswith(".html.j2")', content)
        self.assertNotIn("select_autoescape(", content)

    def test_dashboard_report_grouping_keeps_audit_metrics_payload_fields(self):
        utils_js = (
            Path(__file__).resolve().parents[1]
            / "oasis"
            / "static"
            / "js"
            / "dashboard"
            / "utils.js"
        )
        content = utils_js.read_text(encoding="utf-8")
        self.assertIn("audit_metrics", content)
        self.assertIn("timestamp_dir", content)

    def test_dashboard_model_date_filter_uses_local_report_data_before_api_fallback(self):
        interactions_js = (
            Path(__file__).resolve().parents[1]
            / "oasis"
            / "static"
            / "js"
            / "dashboard"
            / "interactions.js"
        )
        content = interactions_js.read_text(encoding="utf-8")
        self.assertIn("DashboardApp.reportData", content)
        self.assertIn("report.vulnerability_type !== vulnType", content)
        self.assertIn("selectedModelSet.has(normalizeModelKey(report.model))", content)
        self.assertIn("DashboardApp._normalizeDateEntries", content)
        self.assertIn("Date.parse", content)
        self.assertIn("DashboardApp._buildDateEntriesFromApiPayload", content)
        self.assertIn("params.append('model', modelName)", content)
        self.assertIn("DashboardApp.buildDateTagInnerHtml", content)
        self.assertIn("readSelectedModelsFromCard(card)", content)
        self.assertIn("writeSelectedModelsToCard(card, selectedList)", content)
        self.assertIn("isModelSelected(selectedModels, tag.dataset.model)", content)
        self.assertIn("normalizedSelectedKeys.has(modelKey)", content)
        self.assertIn("selectedModels.delete(entry)", content)
        self.assertIn("DashboardApp.updateDatesForModels", content)
        self.assertIn("DashboardApp.updateModelSelectionBadge", content)
        self.assertIn("DashboardApp.updateAuditComparisonTableForModels", content)

    def test_dashboard_model_selection_state_uses_helpers(self):
        interactions_js = (
            Path(__file__).resolve().parents[1]
            / "oasis"
            / "static"
            / "js"
            / "dashboard"
            / "interactions.js"
        )
        content = interactions_js.read_text(encoding="utf-8")
        self.assertIn("readSelectedModelsFromCard(card)", content)
        self.assertIn("writeSelectedModelsToCard(card, selectedList)", content)
        self.assertIn("isModelSelected(selectedModels, tag.dataset.model)", content)
        self.assertIn("DashboardApp.modelSelectionBadgeHtml", content)
        self.assertIn("const {normalizeModelKey", content)

    def test_dashboard_utils_vulnerability_sort_is_case_insensitive_for_priority_labels(self):
        utils_js = (
            Path(__file__).resolve().parents[1]
            / "oasis"
            / "static"
            / "js"
            / "dashboard"
            / "utils.js"
        )
        content = utils_js.read_text(encoding="utf-8")
        self.assertIn("'audit report': 0", content)
        self.assertIn("'executive summary': 1", content)
        self.assertIn(".toLowerCase()", content)

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_report_audit_metrics_summary_uses_scored_count_and_tracks_total_items(self):
        analyzer_results = {
            "SQL Injection": {
                "results": [
                    {"similarity_score": 0.9},
                    {"similarity_score": 0.7},
                    {"similarity_score": "n/a"},
                ]
            },
            "vulnerability_statistics": [
                {"name": "TOTAL", "total": 3, "high": 1, "medium": 1, "low": 1, "is_total": True}
            ],
        }
        summary = Report._audit_metrics_summary(analyzer_results)
        self.assertEqual(summary["count"], 2)
        self.assertTrue(summary["has_scores"])
        self.assertEqual(summary["scored_items"], 2)
        self.assertEqual(summary["total_items"], 3)

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_report_audit_metrics_summary_accepts_numeric_like_string_scores(self):
        analyzer_results = {
            "SQL Injection": {
                "results": [
                    {"similarity_score": "0.9"},
                    {"similarity_score": "0.7"},
                    {"similarity_score": "n/a"},
                ]
            },
            "vulnerability_statistics": [
                {"name": "TOTAL", "total": 3, "high": 1, "medium": 1, "low": 1, "is_total": True}
            ],
        }
        summary = Report._audit_metrics_summary(analyzer_results)
        self.assertEqual(summary["count"], 2)
        self.assertTrue(summary["has_scores"])
        self.assertEqual(summary["scored_items"], 2)

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_report_audit_metrics_summary_marks_no_scores(self):
        analyzer_results = {
            "SQL Injection": {
                "results": [
                    {"similarity_score": "n/a"},
                ]
            },
            "vulnerability_statistics": [
                {"name": "TOTAL", "total": 1, "high": 0, "medium": 0, "low": 0, "is_total": True}
            ],
        }
        summary = Report._audit_metrics_summary(analyzer_results)
        self.assertEqual(summary["count"], 0)
        self.assertFalse(summary["has_scores"])

    @unittest.skipIf(Report is None, "oasis.report dependencies are unavailable")
    def test_report_audit_metrics_summary_ignores_non_dict_vulnerability_entries(self):
        analyzer_results = {
            "SQL Injection": {
                "results": [
                    {"similarity_score": 0.9},
                ]
            },
            "Malformed Entry": ["unexpected", "list"],
            "vulnerability_statistics": [
                {"name": "TOTAL", "total": 1, "high": 1, "medium": 0, "low": 0, "is_total": True}
            ],
        }
        summary = Report._audit_metrics_summary(analyzer_results)
        self.assertEqual(summary["count"], 1)
        self.assertTrue(summary["has_scores"])

    def test_graph_final_progress_extras_use_graph_scan_mode(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        from oasis.enums import AnalysisType
        from oasis.helpers.progress import graph_final_phases

        with patch("oasis.helpers.progress.safe_code_base_file_count", return_value=2):
            out = graph_final_phases(
                SimpleNamespace(), 1, updated_at="2026-01-01T00:00:00+00:00"
            )
        self.assertEqual(out.get("scan_mode"), AnalysisType.GRAPH.value)
        phases = out.get("phases") or []
        ids = [r.get("id") for r in phases]
        self.assertIn("graph_discover", ids)
        self.assertIn("graph_verify", ids)


if __name__ == "__main__":
    unittest.main()
