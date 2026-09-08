"""Tests for transverse finding deduplication (oasis.helpers.findings_dedupe)."""

from __future__ import annotations

import unittest

from oasis.helpers.findings_dedupe import deduplicate_rows_findings
from oasis.schemas.analysis import VulnerabilityFinding


class _Chunk:
    """Model-like chunk (attribute access, settable findings list)."""

    def __init__(self, findings):
        self.findings = findings


def _finding(
    title: str = "Finding",
    severity: str = "High",
    snippet: str = "cur.execute(sql)",
    start: int | None = None,
    end: int | None = None,
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        title=title,
        severity=severity,
        vulnerable_code=snippet,
        snippet_start_line=start,
        snippet_end_line=end,
    )


def _dict_rows(findings_per_chunk, file_path: str = "app.py"):
    return [
        {"file_path": file_path, "structured_chunks": [{"findings": list(chunk)} for chunk in findings_per_chunk]}
    ]


class TestFindingsDeduplication(unittest.TestCase):
    def test_identical_snippet_same_file_merges(self):
        rows = _dict_rows([[_finding("A", "High", "cur.execute(sql)"), _finding("B", "Medium", "cur.execute(sql)")]])
        stats = deduplicate_rows_findings(rows, "SQL Injection")
        self.assertEqual(stats["duplicates_removed"], 1)
        self.assertEqual(len(rows[0]["structured_chunks"][0]["findings"]), 1)
        self.assertEqual(rows[0]["structured_chunks"][0]["findings"][0].title, "A")

    def test_best_severity_wins_and_positions_preserved(self):
        rows = _dict_rows([[_finding("low first", "Low", "dup"), _finding("critical twin", "Critical", "dup")]])
        deduplicate_rows_findings(rows, "SQL Injection")
        kept = rows[0]["structured_chunks"][0]["findings"]
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].title, "critical twin")
        self.assertEqual(kept[0].severity, "Critical")

    def test_overlapping_resolved_lines_merge(self):
        rows = _dict_rows(
            [
                [
                    _finding("A", "High", "snippet one", start=10, end=20),
                    _finding("B", "Medium", "snippet two", start=15, end=25),
                ]
            ]
        )
        stats = deduplicate_rows_findings(rows, "SQL Injection")
        self.assertEqual(stats["duplicates_removed"], 1)
        self.assertEqual(len(rows[0]["structured_chunks"][0]["findings"]), 1)

    def test_disjoint_ranges_and_snippets_kept(self):
        rows = _dict_rows(
            [
                [
                    _finding("A", "High", "snippet one", start=10, end=20),
                    _finding("B", "Medium", "snippet two", start=30, end=40),
                ]
            ]
        )
        stats = deduplicate_rows_findings(rows, "SQL Injection")
        self.assertEqual(stats["duplicates_removed"], 0)
        self.assertEqual(len(rows[0]["structured_chunks"][0]["findings"]), 2)

    def test_empty_snippets_never_snippet_merged(self):
        rows = _dict_rows([[_finding("A", "High", ""), _finding("B", "Medium", "")]])
        stats = deduplicate_rows_findings(rows, "SQL Injection")
        self.assertEqual(stats["duplicates_removed"], 0)
        self.assertEqual(len(rows[0]["structured_chunks"][0]["findings"]), 2)

    def test_same_snippet_different_files_kept(self):
        rows = [
            {"file_path": "a.py", "structured_chunks": [{"findings": [_finding("A", "High", "dup")]}]},
            {"file_path": "b.py", "structured_chunks": [{"findings": [_finding("B", "High", "dup")]}]},
        ]
        stats = deduplicate_rows_findings(rows, "SQL Injection")
        self.assertEqual(stats["duplicates_removed"], 0)
        self.assertEqual(stats["clusters"], 2)

    def test_model_rows_supported(self):
        chunk = _Chunk([_finding("A", "High", "dup"), _finding("B", "Medium", "dup")])
        rows = [{"file_path": "app.py", "structured_chunks": [chunk]}]
        stats = deduplicate_rows_findings(rows, "SQL Injection")
        self.assertEqual(stats["duplicates_removed"], 1)
        self.assertEqual(len(chunk.findings), 1)
        self.assertEqual(chunk.findings[0].title, "A")

    def test_dedup_runs_across_chunks(self):
        rows = _dict_rows(
            [
                [_finding("chunk one", "High", "dup")],
                [_finding("chunk two", "Medium", "dup")],
            ]
        )
        stats = deduplicate_rows_findings(rows, "SQL Injection")
        self.assertEqual(stats["duplicates_removed"], 1)
        self.assertEqual(len(rows[0]["structured_chunks"][0]["findings"]), 1)
        self.assertEqual(len(rows[0]["structured_chunks"][1]["findings"]), 0)

    def test_empty_rows_are_noop(self):
        self.assertEqual(deduplicate_rows_findings([], "SQL Injection"), {"clusters": 0, "duplicates_removed": 0})
        self.assertEqual(
            deduplicate_rows_findings(None, "SQL Injection"),  # type: ignore[arg-type]
            {"clusters": 0, "duplicates_removed": 0},
        )


if __name__ == "__main__":
    unittest.main()