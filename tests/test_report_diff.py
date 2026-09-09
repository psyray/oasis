"""Tests for the baseline scan-diff helpers (fingerprints, buckets, artifacts)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.helpers.report_diff import (
    collect_finding_refs,
    diff_finding_refs,
    finding_fingerprint,
    iter_findings_from_document,
    normalize_snippet_text,
    write_diff_artifacts,
)
from oasis.schemas.analysis import DiffReportDocument


def _vulnerability_doc(vulnerability_name, files_findings):
    """files_findings: list of (file_path, [(title, severity, snippet), ...])."""
    files = [
        {
            "file_path": file_path,
            "similarity_score": 0.9,
            "chunk_analyses": [
                {
                    "findings": [
                        {"title": title, "severity": severity, "vulnerable_code": snippet}
                        for title, severity, snippet in findings
                    ]
                }
            ],
        }
        for file_path, findings in files_findings
    ]
    return {
        "schema_version": 5,
        "report_type": "vulnerability",
        "title": "Test",
        "generated_at": "2026-01-01T00:00:00",
        "model_name": "m",
        "vulnerability_name": vulnerability_name,
        "files": files,
    }


class TestSnippetNormalization(unittest.TestCase):
    def test_normalizes_line_endings_and_edges(self):
        self.assertEqual(normalize_snippet_text("a = 1\r\nb = 2\r\n"), "a = 1\nb = 2")
        self.assertEqual(normalize_snippet_text("\n\n  x = 1  \n\n\n"), "  x = 1")
        self.assertEqual(normalize_snippet_text(""), "")

    def test_non_string_input_is_empty(self):
        self.assertEqual(normalize_snippet_text(None), "")
        self.assertEqual(normalize_snippet_text(42), "")


class TestFindingFingerprint(unittest.TestCase):
    def test_stable_across_whitespace_and_line_endings(self):
        a = finding_fingerprint("app/routes.py", "SQL Injection", "cursor.execute(q)\r\n")
        b = finding_fingerprint("app/routes.py", "SQL Injection", "\ncursor.execute(q)\n")
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("sha256:"))

    def test_differs_for_other_file_or_vuln_type(self):
        base = finding_fingerprint("app/routes.py", "SQL Injection", "cursor.execute(q)")
        self.assertNotEqual(base, finding_fingerprint("app/other.py", "SQL Injection", "cursor.execute(q)"))
        self.assertNotEqual(base, finding_fingerprint("app/routes.py", "XSS", "cursor.execute(q)"))

    def test_windows_path_separators_match_posix(self):
        self.assertEqual(
            finding_fingerprint("app\\routes.py", "XSS", "s"),
            finding_fingerprint("app/routes.py", "XSS", "s"),
        )


class TestIterFindingsFromDocument(unittest.TestCase):
    def test_flattens_findings_with_fingerprints(self):
        doc = _vulnerability_doc("SQL Injection", [("app.py", [("Unsafe", "High", "q = f'{x}'")])])
        refs = iter_findings_from_document(doc)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["file_path"], "app.py")
        self.assertEqual(refs[0]["vulnerability_name"], "SQL Injection")
        self.assertEqual(refs[0]["severity"], "High")
        self.assertTrue(refs[0]["fingerprint"].startswith("sha256:"))

    def test_ignores_non_vulnerability_documents_and_errors(self):
        self.assertEqual(iter_findings_from_document({"report_type": "audit"}), [])
        doc = _vulnerability_doc("XSS", [("app.py", [("Unsafe", "High", "s")])])
        doc["files"][0]["error"] = "failed"
        self.assertEqual(iter_findings_from_document(doc), [])


class TestDiffFindingRefs(unittest.TestCase):
    def _refs(self, entries):
        return [
            {
                "file_path": file_path,
                "vulnerability_name": vuln,
                "title": title,
                "severity": severity,
                "snippet": snippet,
                "fingerprint": finding_fingerprint(file_path, vuln, snippet),
            }
            for file_path, vuln, title, severity, snippet in entries
        ]

    def test_buckets_new_fixed_persistent(self):
        baseline = self._refs([
            ("a.py", "SQLi", "old query", "High", "cursor.execute(q)"),
            ("b.py", "XSS", "old dom", "Medium", "innerHTML = x"),
        ])
        current = self._refs([
            ("a.py", "SQLi", "old query", "High", "cursor.execute(q)"),
            ("c.py", "SSRF", "new fetch", "Critical", "requests.get(url)"),
        ])
        result = diff_finding_refs(baseline, current)
        self.assertEqual(result["counts"].new, 1)
        self.assertEqual(result["counts"].fixed, 1)
        self.assertEqual(result["counts"].persistent, 1)
        self.assertEqual(result["new"][0].file_path, "c.py")
        self.assertEqual(result["fixed"][0].file_path, "b.py")

    def test_severity_change_is_tracked_and_finding_stays_persistent(self):
        baseline = self._refs([("a.py", "SQLi", "q", "High", "cursor.execute(q)")])
        current = self._refs([("a.py", "SQLi", "q", "Critical", "cursor.execute(q)")])
        result = diff_finding_refs(baseline, current)
        self.assertEqual(result["counts"].persistent, 1)
        self.assertEqual(result["counts"].severity_changes, 1)
        change = result["severity_changes"][0]
        self.assertEqual(change.baseline_severity, "High")
        self.assertEqual(change.current_severity, "Critical")

    def test_severity_case_difference_is_not_a_change(self):
        baseline = self._refs([("a.py", "SQLi", "q", "High", "cursor.execute(q)")])
        current = self._refs([("a.py", "SQLi", "q", "HIGH", "cursor.execute(q)")])
        result = diff_finding_refs(baseline, current)
        self.assertEqual(result["counts"].severity_changes, 0)


class TestCollectFindingRefs(unittest.TestCase):
    def test_single_file_baseline(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "sql.json"
            source.write_text(json.dumps(_vulnerability_doc("SQLi", [("a.py", [("t", "Low", "s")])])), encoding="utf-8")
            refs, documents = collect_finding_refs(source)
            self.assertEqual(documents, 1)
            self.assertEqual(len(refs), 1)

    def test_run_root_rglob_and_report_type_filter(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            jdir = root / "run" / "model" / "json"
            jdir.mkdir(parents=True)
            (jdir / "sql.json").write_text(json.dumps(_vulnerability_doc("SQLi", [("a.py", [("t", "Low", "s")])])), encoding="utf-8")
            (jdir / "_executive_summary.json").write_text("{}", encoding="utf-8")
            (jdir / "audit_report.json").write_text(json.dumps({"report_type": "audit"}), encoding="utf-8")
            refs, documents = collect_finding_refs(root / "run")
            self.assertEqual(documents, 1)
            self.assertEqual(len(refs), 1)

    def test_missing_source_returns_empty(self):
        refs, documents = collect_finding_refs(Path("/nonexistent/oasis-diff-source"))
        self.assertEqual((refs, documents), ([], 0))


class TestWriteDiffArtifacts(unittest.TestCase):
    def test_writes_json_and_md_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            baseline = Path(td) / "baseline"
            bjdir = baseline / "model" / "json"
            bjdir.mkdir(parents=True)
            (bjdir / "sql.json").write_text(
                json.dumps(_vulnerability_doc("SQLi", [("a.py", [("old", "High", "q = 1")])])), encoding="utf-8"
            )

            current = Path(td) / "current"
            cjdir = current / "model" / "json"
            cjdir.mkdir(parents=True)
            (cjdir / "sql.json").write_text(
                json.dumps(_vulnerability_doc("SQLi", [
                    ("a.py", [("old", "Critical", "q = 1")]),
                    ("b.py", [("fresh", "Low", "rm -rf $x")]),
                ])), encoding="utf-8"
            )

            doc = write_diff_artifacts(current, baseline)
            self.assertIsNotNone(doc)
            self.assertEqual(doc["counts"]["new"], 1)
            self.assertEqual(doc["counts"]["persistent"], 1)
            self.assertEqual(doc["counts"]["severity_changes"], 1)

            json_path = current / "diff" / "diff_report.json"
            md_path = current / "diff" / "diff_report.md"
            self.assertTrue(json_path.is_file())
            self.assertTrue(md_path.is_file())
            parsed = DiffReportDocument.model_validate(json.loads(json_path.read_text(encoding="utf-8")))
            self.assertEqual(parsed.report_type, "diff")
            self.assertEqual(parsed.counts.fixed, 0)
            self.assertIn("Severity changes", md_path.read_text(encoding="utf-8"))

    def test_missing_current_dir_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(write_diff_artifacts(Path(td) / "missing", Path(td)))


if __name__ == "__main__":
    unittest.main()