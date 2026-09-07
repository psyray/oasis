"""Tests for the CI fail-on severity gate helpers."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.helpers.ci_gate import (
    EXIT_FINDINGS_ABOVE_THRESHOLD,
    SEVERITY_ORDER,
    evaluate_fail_on_gate,
    is_severity_at_or_above,
    iter_vulnerability_document_paths,
    normalize_severity,
)


def _vulnerability_doc(findings_by_severity):
    """Build a canonical vulnerability document payload with given severities."""
    findings = [
        {"title": f"F{i}", "severity": severity}
        for i, severity in enumerate(findings_by_severity)
    ]
    return {
        "schema_version": 2,
        "report_type": "vulnerability",
        "title": "Test",
        "generated_at": "2026-01-01T00:00:00",
        "model_name": "m",
        "vulnerability_name": "SQL Injection",
        "files": [
            {
                "file_path": "app.py",
                "similarity_score": 0.9,
                "chunk_analyses": [{"findings": findings}],
            }
        ],
    }


class TestNormalizeSeverity(unittest.TestCase):
    def test_accepts_known_severities_case_insensitive(self):
        self.assertEqual(normalize_severity("HIGH"), "high")
        self.assertEqual(normalize_severity(" Critical "), "critical")
        self.assertEqual(normalize_severity("Medium"), "medium")
        self.assertEqual(normalize_severity("low"), "low")

    def test_rejects_unknown_values(self):
        self.assertIsNone(normalize_severity("urgent"))
        self.assertIsNone(normalize_severity(""))
        self.assertIsNone(normalize_severity(None))
        self.assertIsNone(normalize_severity(42))


class TestSeverityThreshold(unittest.TestCase):
    def test_ordering(self):
        self.assertLess(SEVERITY_ORDER["low"], SEVERITY_ORDER["medium"])
        self.assertLess(SEVERITY_ORDER["medium"], SEVERITY_ORDER["high"])
        self.assertLess(SEVERITY_ORDER["high"], SEVERITY_ORDER["critical"])

    def test_is_severity_at_or_above(self):
        self.assertTrue(is_severity_at_or_above("Critical", "high"))
        self.assertTrue(is_severity_at_or_above("high", "high"))
        self.assertFalse(is_severity_at_or_above("medium", "high"))
        self.assertFalse(is_severity_at_or_above("unknown", "low"))

    def test_invalid_threshold_never_trips(self):
        self.assertFalse(is_severity_at_or_above("critical", "urgent"))


class TestIterVulnerabilityDocumentPaths(unittest.TestCase):
    def test_lists_json_documents_under_model_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "run" / "embed-model" / "json").mkdir(parents=True)
            (root / "run" / "embed-model" / "md").mkdir(parents=True)
            (root / "run" / "embed-model" / "json" / "sql_injection.json").write_text("{}", encoding="utf-8")
            paths = iter_vulnerability_document_paths(root / "run")
            self.assertEqual([p.name for p in paths], ["sql_injection.json"])
            self.assertEqual([p.name for p in iter_vulnerability_document_paths(root / "run" / "embed-model")], ["sql_injection.json"])

    def test_skips_progress_sidecars_and_missing_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            jdir = root / "json"
            jdir.mkdir()
            (jdir / "_executive_summary_progress.json").write_text("{}", encoding="utf-8")
            (jdir / "report.json").write_text("{}", encoding="utf-8")
            names = [p.name for p in iter_vulnerability_document_paths(root)]
            self.assertEqual(names, ["report.json"])
            self.assertEqual(iter_vulnerability_document_paths(root / "missing"), [])


class TestEvaluateFailOnGate(unittest.TestCase):
    def _write_run(self, root, docs_by_name):
        root = Path(root)
        jdir = root / "run" / "embed-model" / "json"
        jdir.mkdir(parents=True)
        for name, payload in docs_by_name.items():
            (jdir / name).write_text(json.dumps(payload), encoding="utf-8")
        return root / "run"

    def test_trips_when_findings_meet_threshold(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = self._write_run(td, {
                "sql_injection.json": _vulnerability_doc(["High", "Low"]),
                "xss.json": _vulnerability_doc(["Critical"]),
            })
            gate = evaluate_fail_on_gate(run_dir, "high")
            self.assertTrue(gate["tripped"])
            self.assertEqual(gate["findings_at_or_above"], 2)
            self.assertEqual(gate["counts_by_severity"]["critical"], 1)
            self.assertEqual(gate["counts_by_severity"]["high"], 1)
            self.assertEqual(gate["counts_by_severity"]["low"], 1)
            self.assertEqual(gate["documents_scanned"], 2)

    def test_does_not_trip_below_threshold(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = self._write_run(td, {
                "sql_injection.json": _vulnerability_doc(["Medium", "Low"]),
            })
            gate = evaluate_fail_on_gate(run_dir, "high")
            self.assertFalse(gate["tripped"])
            self.assertEqual(gate["findings_at_or_above"], 0)

    def test_threshold_none_never_trips(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = self._write_run(td, {
                "sql_injection.json": _vulnerability_doc(["Critical"]),
            })
            gate = evaluate_fail_on_gate(run_dir, "urgent")
            self.assertFalse(gate["tripped"])
            self.assertIsNone(gate["fail_on"])

    def test_non_vulnerability_documents_are_ignored(self):
        exec_doc = {
            "schema_version": 2,
            "report_type": "executive_summary",
            "title": "Executive Summary",
            "stats": {"critical_risk": 99},
            "files": [
                {
                    "file_path": "app.py",
                    "similarity_score": 0.9,
                    "chunk_analyses": [{"findings": [{"title": "ghost", "severity": "Critical"}]}],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as td:
            run_dir = self._write_run(td, {
                "_executive_summary.json": exec_doc,
                "audit_report.json": {"report_type": "audit"},
                "sql_injection.json": _vulnerability_doc(["Low"]),
            })
            gate = evaluate_fail_on_gate(run_dir, "critical")
            self.assertFalse(gate["tripped"])
            self.assertEqual(gate["documents_scanned"], 1)

    def test_unreadable_documents_are_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            run_dir = self._write_run(td, {
                "broken.json": _vulnerability_doc(["Critical"]),
            })
            (run_dir / "embed-model" / "json" / "broken.json").write_text("{not json", encoding="utf-8")
            gate = evaluate_fail_on_gate(run_dir, "critical")
            self.assertFalse(gate["tripped"])
            self.assertEqual(gate["documents_scanned"], 0)

    def test_error_file_entries_do_not_count(self):
        doc = _vulnerability_doc(["Critical"])
        doc["files"][0]["error"] = "analysis failed"
        with tempfile.TemporaryDirectory() as td:
            run_dir = self._write_run(td, {"sql_injection.json": doc})
            gate = evaluate_fail_on_gate(run_dir, "low")
            self.assertFalse(gate["tripped"])


class TestExitCodeContract(unittest.TestCase):
    def test_gate_exit_code_is_dedicated(self):
        self.assertEqual(EXIT_FINDINGS_ABOVE_THRESHOLD, 3)


if __name__ == "__main__":
    unittest.main()