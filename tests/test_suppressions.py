"""Tests for the suppression registry helpers (fingerprints, registry, candidates)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.helpers.suppressions import (
    DEFAULT_SUPPRESSIONS_FILENAME,
    count_suppressed_findings,
    finding_fingerprint,
    iter_findings_from_documents,
    iter_vulnerability_documents,
    load_suppressions,
    normalize_snippet_text,
    write_suppression_candidates,
)


def _vulnerability_doc(vulnerability_name, files_findings):
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


class TestFingerprint(unittest.TestCase):
    def test_stable_across_whitespace_and_line_endings(self):
        a = finding_fingerprint("app.py", "SQL Injection", "cursor.execute(q)\r\n")
        b = finding_fingerprint("app.py", "SQL Injection", "\ncursor.execute(q)\n")
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("sha256:"))

    def test_differs_for_other_file_or_vuln_type(self):
        base = finding_fingerprint("app.py", "SQL Injection", "cursor.execute(q)")
        self.assertNotEqual(base, finding_fingerprint("other.py", "SQL Injection", "cursor.execute(q)"))
        self.assertNotEqual(base, finding_fingerprint("app.py", "XSS", "cursor.execute(q)"))

    def test_normalize_snippet(self):
        self.assertEqual(normalize_snippet_text(None), "")
        self.assertEqual(normalize_snippet_text("\r\na=1\r\n"), "a=1")


class TestLoadSuppressions(unittest.TestCase):
    def test_loads_nested_registry_format(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / DEFAULT_SUPPRESSIONS_FILENAME
            path.write_text(json.dumps({
                "version": 1,
                "suppressions": {
                    "sha256:abc": {"note": "intentional for tests"},
                    "sha256:def": "flat note",
                },
            }), encoding="utf-8")
            registry = load_suppressions(path)
            self.assertEqual(registry["sha256:abc"]["note"], "intentional for tests")
            self.assertEqual(registry["sha256:def"]["note"], "flat note")

    def test_loads_flat_registry_format(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / DEFAULT_SUPPRESSIONS_FILENAME
            path.write_text(json.dumps({"sha256:abc": {"note": "n"}}), encoding="utf-8")
            self.assertEqual(load_suppressions(path)["sha256:abc"]["note"], "n")

    def test_missing_file_returns_empty(self):
        self.assertEqual(load_suppressions(Path("/nonexistent/registry.json")), {})

    def test_invalid_content_fails_open(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / DEFAULT_SUPPRESSIONS_FILENAME
            path.write_text("{not json", encoding="utf-8")
            self.assertEqual(load_suppressions(path), {})
            path.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
            self.assertEqual(load_suppressions(path), {})

    def test_invalid_entries_are_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / DEFAULT_SUPPRESSIONS_FILENAME
            path.write_text(json.dumps({
                "suppressions": {
                    "sha256:ok": {"note": "keep"},
                    "sha256:bad": {"note": 123},
                    "sha256:worsetype": 42,
                    "": "empty key",
                },
            }), encoding="utf-8")
            registry = load_suppressions(path)
            self.assertEqual(list(registry.keys()), ["sha256:ok"])


class TestSuppressionCandidates(unittest.TestCase):
    def test_write_candidates_lists_all_findings(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            jdir = root / "run" / "model" / "json"
            jdir.mkdir(parents=True)
            (jdir / "sql.json").write_text(json.dumps(_vulnerability_doc(
                "SQL Injection", [("a.py", [("t", "High", "q = 1")])]
            )), encoding="utf-8")
            count = write_suppression_candidates(root / "run")
            self.assertEqual(count, 1)
            payload = json.loads((root / "run" / "suppression_candidates.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(len(payload["candidates"]), 1)
            candidate = payload["candidates"][0]
            self.assertEqual(candidate["file_path"], "a.py")
            self.assertEqual(candidate["vulnerability_name"], "SQL Injection")
            self.assertTrue(candidate["fingerprint"].startswith("sha256:"))

    def test_ignores_non_vulnerability_documents(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            jdir = root / "json"
            jdir.mkdir()
            (jdir / "audit_report.json").write_text(json.dumps({"report_type": "audit"}), encoding="utf-8")
            self.assertEqual(write_suppression_candidates(root), 0)

    def test_iter_vulnerability_documents_skips_sidecars_and_missing_dirs(self):
        self.assertEqual(iter_vulnerability_documents(Path("/nonexistent/run")), [])
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            jdir = root / "json"
            jdir.mkdir()
            (jdir / "_progress.json").write_text("{}", encoding="utf-8")
            self.assertEqual(iter_vulnerability_documents(root), [])


class TestCountSuppressedFindings(unittest.TestCase):
    def test_counts_only_registered_fingerprints(self):
        doc = _vulnerability_doc("SQL Injection", [
            ("a.py", [("t1", "High", "q = 1")]),
            ("b.py", [("t2", "Low", "x = 2")]),
        ])
        fingerprint = finding_fingerprint("a.py", "SQL Injection", "q = 1")
        self.assertEqual(count_suppressed_findings(Path("/nonexistent"), {}), 0)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            jdir = root / "json"
            jdir.mkdir()
            (jdir / "sql.json").write_text(json.dumps(doc), encoding="utf-8")
            self.assertEqual(count_suppressed_findings(root, {fingerprint: {"note": "n"}}), 1)
            self.assertEqual(count_suppressed_findings(root, {"sha256:other": {"note": "n"}}), 0)


if __name__ == "__main__":
    unittest.main()