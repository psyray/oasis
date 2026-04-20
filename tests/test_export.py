"""Tests for export helpers and SARIF generation."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.export.filenames import artifact_filename, report_dir_glob_for_format
from oasis.export.writers import write_utf8_text
from oasis.export.sarif import vulnerability_document_to_sarif
from oasis.schemas.analysis import (
    ChunkDeepAnalysis,
    FileReportEntry,
    VulnerabilityFinding,
    VulnerabilityReportDocument,
)


class TestArtifactFilename(unittest.TestCase):
    def test_json_suffix(self):
        self.assertEqual(artifact_filename("sql_injection", "json"), "sql_injection.json")

    def test_sarif_suffix(self):
        self.assertEqual(artifact_filename("sql_injection", "sarif"), "sql_injection.sarif")


class TestReportDirGlob(unittest.TestCase):
    def test_globs_match_artifact_extensions(self):
        self.assertEqual(report_dir_glob_for_format("json"), "*.json")
        self.assertEqual(report_dir_glob_for_format("sarif"), "*.sarif")
        self.assertEqual(report_dir_glob_for_format("md"), "*.md")
        self.assertEqual(report_dir_glob_for_format("html"), "*.html")
        self.assertEqual(report_dir_glob_for_format("pdf"), "*.pdf")

    def test_glob_normalizes_mixed_case(self):
        self.assertEqual(report_dir_glob_for_format("JSON"), "*.json")
        self.assertEqual(report_dir_glob_for_format(" PDF "), "*.pdf")


class TestSarifExport(unittest.TestCase):
    def test_minimal_document_produces_run_and_result(self):
        doc = VulnerabilityReportDocument(
            title="SQL Injection Security Analysis",
            generated_at="2026-01-01T00:00:00",
            model_name="test-model",
            vulnerability_name="SQL Injection",
            vulnerability={"name": "SQL Injection", "description": "SQLi desc"},
            files=[
                FileReportEntry(
                    file_path="app/routes.py",
                    similarity_score=0.91,
                    chunk_analyses=[
                        ChunkDeepAnalysis(
                            findings=[
                                VulnerabilityFinding(
                                    title="Unsafe query",
                                    vulnerable_code="cursor.execute(q)",
                                    explanation="User input reaches SQL.",
                                    severity="High",
                                )
                            ]
                        )
                    ],
                )
            ],
        )
        payload = vulnerability_document_to_sarif(doc, tool_version="0.5.0-test")
        self.assertEqual(payload.get("version"), "2.1.0")
        runs = payload.get("runs") or []
        self.assertEqual(len(runs), 1)
        results = runs[0].get("results") or []
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].get("ruleId"), "sql-injection")
        locs = results[0].get("locations") or []
        self.assertTrue(locs)
        self.assertEqual(locs[0]["physicalLocation"]["artifactLocation"]["uri"], "app/routes.py")

    def test_sarif_region_includes_chunk_line_span(self):
        doc = VulnerabilityReportDocument(
            title="Test",
            generated_at="2026-01-01T00:00:00",
            model_name="m",
            vulnerability_name="XSS",
            vulnerability={"name": "XSS", "description": "d"},
            files=[
                FileReportEntry(
                    file_path="src/x.js",
                    similarity_score=1.0,
                    chunk_analyses=[
                        ChunkDeepAnalysis(
                            findings=[
                                VulnerabilityFinding(
                                    title="Reflected",
                                    vulnerable_code="innerHTML = x",
                                    explanation="DOM XSS.",
                                    severity="High",
                                )
                            ],
                            start_line=40,
                            end_line=55,
                        )
                    ],
                )
            ],
        )
        payload = vulnerability_document_to_sarif(doc, tool_version="0.5.0-test")
        region = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region.get("startLine"), 40)
        self.assertEqual(region.get("endLine"), 55)
        self.assertIn("snippet", region)

    def test_sarif_region_prefers_finding_snippet_span(self):
        doc = VulnerabilityReportDocument(
            title="Test",
            generated_at="2026-01-01T00:00:00",
            model_name="m",
            vulnerability_name="SQL Injection",
            vulnerability={"name": "SQL Injection"},
            files=[
                FileReportEntry(
                    file_path="app.php",
                    similarity_score=1.0,
                    chunk_analyses=[
                        ChunkDeepAnalysis(
                            findings=[
                                VulnerabilityFinding(
                                    title="Unsafe",
                                    vulnerable_code="cursor.execute(q)",
                                    explanation="SQLi",
                                    severity="High",
                                    snippet_start_line=12,
                                    snippet_end_line=14,
                                )
                            ],
                            start_line=50,
                            end_line=300,
                        )
                    ],
                )
            ],
        )
        payload = vulnerability_document_to_sarif(doc, tool_version="0.5.0-test")
        region = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region.get("startLine"), 12)
        self.assertEqual(region.get("endLine"), 14)


class TestWriterAtomicity(unittest.TestCase):
    def test_write_utf8_text_uses_atomic_replace(self):
        target = Path("/tmp/oasis_atomic_writer_test.txt")
        with patch("oasis.export.writers.os.replace") as replace_mock:
            write_utf8_text(target, "hello")
        self.assertTrue(replace_mock.called)

    def test_write_utf8_text_cleans_tmp_file_when_replace_fails(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            target = Path(tmp_dir) / "report.json"
            with self.assertRaises(OSError):
                with patch("oasis.export.writers.os.replace", side_effect=OSError("replace failed")):
                    write_utf8_text(target, "hello")
            leftovers = [p for p in Path(tmp_dir).iterdir() if p.name != target.name]
            self.assertEqual(leftovers, [])
