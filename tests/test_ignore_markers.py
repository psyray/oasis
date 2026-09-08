"""Tests for inline ignore markers (oasis.helpers.ignore_markers)."""

from __future__ import annotations

import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.helpers.ignore_markers import (
    DEFAULT_INLINE_IGNORE_TOKENS,
    _compile_marker_pattern,
    drop_inline_ignored_findings,
    finding_has_inline_ignore_marker,
    normalize_inline_ignore_tokens,
)


class _Chunk:
    """Model-like chunk (attribute access, settable findings list)."""

    def __init__(self, findings, notes: str | None = None):
        self.findings = findings
        self.notes = notes


class _Row:
    """Model-like row with structured chunks."""

    def __init__(self, file_path, chunks):
        self.file_path = file_path
        self.structured_chunks = chunks


def _finding(
    title: str = "Finding",
    severity: str = "High",
    snippet: str = "cur.execute(sql)",
    start: int | None = None,
    end: int | None = None,
):
    return {
        "title": title,
        "severity": severity,
        "vulnerable_code": snippet,
        "snippet_start_line": start,
        "snippet_end_line": end,
    }


def _dict_rows(findings_per_chunk, file_path: str = "app.py"):
    return [
        {"file_path": file_path, "structured_chunks": [{"findings": list(chunk)} for chunk in findings_per_chunk]}
    ]


def _model_rows(findings_per_chunk, file_path: str = "app.py"):
    return [_Row(file_path, [_Chunk(list(chunk)) for chunk in findings_per_chunk])]


@contextmanager
def _scan_root(lines: list[str]):
    """Temp scan root containing one ``app.py`` written from *lines* (1-based)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
        yield root


class TestNormalizeInlineIgnoreTokens(unittest.TestCase):
    def test_none_falls_back_to_defaults(self):
        self.assertEqual(normalize_inline_ignore_tokens(None), DEFAULT_INLINE_IGNORE_TOKENS)

    def test_csv_is_lowercased_trimmed_and_deduplicated(self):
        self.assertEqual(
            normalize_inline_ignore_tokens("NoQA, oasisignore ,noqa"),
            ("noqa", "oasisignore"),
        )

    def test_iterable_input_accepted(self):
        self.assertEqual(
            normalize_inline_ignore_tokens([" Nosemgrep ", "nosec", "nosec"]),
            ("nosemgrep", "nosec"),
        )

    def test_blank_or_invalid_input_falls_back_to_defaults(self):
        self.assertEqual(normalize_inline_ignore_tokens("   "), DEFAULT_INLINE_IGNORE_TOKENS)
        self.assertEqual(normalize_inline_ignore_tokens(123), DEFAULT_INLINE_IGNORE_TOKENS)

    def test_explicit_empty_iterable_disables(self):
        self.assertEqual(normalize_inline_ignore_tokens([]), ())
        self.assertEqual(normalize_inline_ignore_tokens(("", "  ")), ())

    def test_default_tokens_cover_expected_markers(self):
        self.assertEqual(
            DEFAULT_INLINE_IGNORE_TOKENS,
            ("oasisignore", "nosec", "noqa", "nosemgrep"),
        )


class TestDropInlineIgnoredFindings(unittest.TestCase):
    def test_snippet_marker_drops_finding(self):
        rows = _dict_rows(
            [[_finding("clean"), _finding("marked", snippet='password = "x"  # noqa')]]
        )
        stats = drop_inline_ignored_findings(rows, scan_root=Path("/nonexistent"))
        self.assertEqual(stats["dropped"], 1)
        kept = rows[0]["structured_chunks"][0]["findings"]
        self.assertEqual([f["title"] for f in kept], ["clean"])

    def test_trailing_line_marker_drops_finding(self):
        lines = [
            "import os",
            "",
            "def f():",
            '    password = "hunter2"',
            "    # noqa",
            "    return password",
        ]
        with _scan_root(lines) as root:
            rows = _dict_rows([[_finding("hardcoded", start=4, end=4)]])
            stats = drop_inline_ignored_findings(rows, scan_root=root)
            self.assertEqual(stats["dropped"], 1)
            self.assertEqual(rows[0]["structured_chunks"][0]["findings"], [])

    def test_marker_inside_span_drops_finding(self):
        lines = [
            "import os",
            "def f():",
            '    password = "hunter2"  # nosec',
            "    return password",
        ]
        with _scan_root(lines) as root:
            rows = _dict_rows([[_finding("sink", start=3, end=3)]])
            stats = drop_inline_ignored_findings(rows, scan_root=root)
            self.assertEqual(stats["dropped"], 1)

    def test_marker_on_line_above_is_not_honored(self):
        lines = ["def f():", "    # noqa", '    password = "hunter2"']
        with _scan_root(lines) as root:
            rows = _dict_rows([[_finding("sink", start=3, end=3)]])
            stats = drop_inline_ignored_findings(rows, scan_root=root)
            self.assertEqual(stats["dropped"], 0)
            self.assertEqual(len(rows[0]["structured_chunks"][0]["findings"]), 1)

    def test_clean_file_keeps_finding(self):
        lines = ["def f():", '    password = "hunter2"']
        with _scan_root(lines) as root:
            rows = _dict_rows([[_finding("sink", start=2, end=2)]])
            stats = drop_inline_ignored_findings(rows, scan_root=root)
            self.assertEqual(stats["dropped"], 0)

    def test_case_insensitive_marker(self):
        rows = _dict_rows([[_finding("marked", snippet='password = "x"  # NOQA')]])
        stats = drop_inline_ignored_findings(rows, scan_root=Path("/nonexistent"))
        self.assertEqual(stats["dropped"], 1)

    def test_custom_tokens_csv_restricts_marker_set(self):
        rows = _dict_rows(
            [
                [
                    _finding("noqa-marked", snippet='password = "x"  # noqa'),
                    _finding("oasis-marked", snippet='password = "y"  # oasisignore'),
                ]
            ]
        )
        stats = drop_inline_ignored_findings(rows, scan_root=Path("/nonexistent"), tokens="oasisignore")
        self.assertEqual(stats["dropped"], 1)
        kept = rows[0]["structured_chunks"][0]["findings"]
        self.assertEqual([f["title"] for f in kept], ["noqa-marked"])

    def test_empty_token_list_disables_pass(self):
        rows = _dict_rows([[_finding("marked", snippet='password = "x"  # noqa')]])
        stats = drop_inline_ignored_findings(rows, scan_root=Path("/nonexistent"), tokens=[])
        self.assertEqual(stats["dropped"], 0)
        self.assertEqual(len(rows[0]["structured_chunks"][0]["findings"]), 1)

    def test_unresolved_lines_without_snippet_marker_kept(self):
        rows = _dict_rows([[_finding("clean", start=None, end=None)]])
        stats = drop_inline_ignored_findings(rows, scan_root=Path("/nonexistent"))
        self.assertEqual(stats["dropped"], 0)

    def test_unresolvable_file_path_fail_open(self):
        rows = _dict_rows([[_finding("sink", start=4, end=4)]], file_path="../outside/secret.py")
        stats = drop_inline_ignored_findings(rows, scan_root=Path("/nonexistent"))
        self.assertEqual(stats["dropped"], 0)
        self.assertEqual(len(rows[0]["structured_chunks"][0]["findings"]), 1)

    def test_model_style_rows_and_chunks_mutated_in_place(self):
        rows = _model_rows(
            [[_finding("marked", snippet='password = "x"  # noqa'), _finding("clean")]]
        )
        stats = drop_inline_ignored_findings(rows, scan_root=Path("/nonexistent"))
        self.assertEqual(stats["dropped"], 1)
        chunk = rows[0].structured_chunks[0]
        self.assertEqual([f["title"] for f in chunk.findings], ["clean"])

    def test_all_dropped_chunk_notes_rewritten_with_original_preserved(self):
        rows = _dict_rows([[_finding("marked", snippet='password = "x"  # noqa')]])
        rows[0]["structured_chunks"][0]["notes"] = "One RCE vulnerability found via shell injection."
        drop_inline_ignored_findings(rows, scan_root=Path("/nonexistent"))
        notes = rows[0]["structured_chunks"][0]["notes"]
        self.assertTrue(notes.startswith("1 finding skipped via inline ignore marker."))
        self.assertIn("Original notes: One RCE vulnerability found via shell injection.", notes)

    def test_all_dropped_plural_notes(self):
        rows = _dict_rows(
            [
                [
                    _finding("marked-a", snippet='password = "x"  # noqa'),
                    _finding("marked-b", snippet='password = "y"  # nosec'),
                ]
            ]
        )
        drop_inline_ignored_findings(rows, scan_root=Path("/nonexistent"))
        notes = rows[0]["structured_chunks"][0]["notes"]
        self.assertTrue(notes.startswith("2 findings skipped via inline ignore marker."))

    def test_partial_drop_appends_skip_note(self):
        rows = _dict_rows(
            [[_finding("clean"), _finding("marked", snippet='password = "x"  # noqa')]]
        )
        rows[0]["structured_chunks"][0]["notes"] = "Two suspicious constructs found."
        drop_inline_ignored_findings(rows, scan_root=Path("/nonexistent"))
        notes = rows[0]["structured_chunks"][0]["notes"]
        self.assertIn("Two suspicious constructs found.", notes)
        self.assertTrue(notes.endswith("1 finding skipped via inline ignore marker."))

    def test_model_style_chunk_notes_updated(self):
        rows = [_Row("app.py", [_Chunk([_finding("marked", snippet='password = "x"  # noqa')], notes="Suspicious sink found.")])]
        drop_inline_ignored_findings(rows, scan_root=Path("/nonexistent"))
        chunk_notes = rows[0].structured_chunks[0].notes
        self.assertEqual(
            chunk_notes,
            "1 finding skipped via inline ignore marker. Original notes: Suspicious sink found.",
        )

    def test_drop_without_notes_still_annotated(self):
        rows = _dict_rows([[_finding("marked", snippet='password = "x"  # noqa')]])
        drop_inline_ignored_findings(rows, scan_root=Path("/nonexistent"))
        notes = rows[0]["structured_chunks"][0]["notes"]
        self.assertEqual(notes, "1 finding skipped via inline ignore marker.")

    def test_malformed_rows_never_raise(self):
        rows = [
            None,
            {"file_path": None},
            {"file_path": "app.py", "structured_chunks": "not-a-list"},
            {
                "file_path": "app.py",
                "structured_chunks": [
                    {"findings": None},
                    {},
                    None,
                    {"findings": [_finding("kept")]},
                ],
            },
        ]
        stats = drop_inline_ignored_findings(rows, scan_root=Path("/nonexistent"))
        self.assertEqual(stats["dropped"], 0)

    def test_finding_object_shape_supported(self):
        from oasis.schemas.analysis import VulnerabilityFinding

        finding = VulnerabilityFinding(
            title="marked",
            vulnerable_code='password = "x"  # noqa',
        )
        rows = _dict_rows([[finding]])
        stats = drop_inline_ignored_findings(rows, scan_root=Path("/nonexistent"))
        self.assertEqual(stats["dropped"], 1)


class TestCompileMarkerPattern(unittest.TestCase):
    def test_empty_tokens_rejected(self):
        with self.assertRaises(ValueError):
            _compile_marker_pattern(())

    def test_regex_special_tokens_escaped(self):
        pattern = _compile_marker_pattern(("oasis-ignore",))
        self.assertTrue(pattern.search('password = "x"  # oasis-ignore'))
        self.assertFalse(pattern.search('password = "x"  # oasisXignore'))


class TestFindingHasInlineIgnoreMarker(unittest.TestCase):
    def _pattern(self):
        return _compile_marker_pattern(DEFAULT_INLINE_IGNORE_TOKENS)

    def test_snippet_match_reported_without_file(self):
        finding = _finding("marked", snippet="eval(user_input)  # nosemgrep: rule-id")
        self.assertTrue(
            finding_has_inline_ignore_marker(
                finding,
                "",
                scan_root=Path("/nonexistent"),
                pattern=self._pattern(),
                line_cache={},
            )
        )


if __name__ == "__main__":
    unittest.main()