"""Unit tests for line-aware chunk splitting (``chunk_content_with_spans``)."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from oasis.tools import chunk_content, chunk_content_with_spans
except ModuleNotFoundError:  # e.g. weasyprint not installed in minimal CI
    chunk_content = None  # type: ignore[assignment]
    chunk_content_with_spans = None  # type: ignore[assignment]


@unittest.skipUnless(
    chunk_content_with_spans is not None,
    "oasis.tools import requires optional dependencies (e.g. weasyprint)",
)
class TestChunkContentWithSpans(unittest.TestCase):
    def test_empty_content_yields_no_chunks(self):
        self.assertEqual(chunk_content_with_spans("", 80), [])

    def test_short_single_line(self):
        self.assertEqual(chunk_content_with_spans("a", 10), [("a", 1, 1)])

    def test_short_multiline_one_chunk(self):
        text = "line1\nline2\nline3"
        self.assertEqual(chunk_content_with_spans(text, 100), [(text, 1, 3)])

    def test_matches_chunk_content_texts(self):
        text = "alpha\nbeta\ngamma\ndelta"
        max_len = 12
        texts = [t[0] for t in chunk_content_with_spans(text, max_len)]
        self.assertEqual(texts, chunk_content(text, max_len))

    def test_shortcut_removed_join_budget_can_split_under_total_char_cap(self):
        # Total len(content) == max_length, but per-line join budget forces two chunks.
        text = "aaaaa\nbbbb"
        self.assertEqual(len(text), 10)
        spans = chunk_content_with_spans(text, 10)
        self.assertEqual(len(spans), 2)
        self.assertEqual(spans[0][0], "aaaaa")
        self.assertEqual(spans[0][1:], (1, 1))
        self.assertEqual(spans[1][0], "bbbb")
        self.assertEqual(spans[1][1:], (2, 2))

    def test_split_preserves_inclusive_line_ranges(self):
        # Each line is 4 chars; implementation counts +1 per line as for a joining newline => 5 units/line.
        # max_length 12 fits two lines per chunk; five lines => three chunks with ranges 1-2, 3-4, 5-5.
        lines = ["AAAA", "BBBB", "CCCC", "DDDD", "EEEE"]
        text = "\n".join(lines)
        spans = chunk_content_with_spans(text, 12)
        self.assertEqual(len(spans), 3)
        self.assertEqual(spans[0][1:], (1, 2))
        self.assertEqual(spans[1][1:], (3, 4))
        self.assertEqual(spans[2][1:], (5, 5))

    def test_oversized_single_line_is_split_by_max_length(self):
        long_line = "x" * 50
        spans = chunk_content_with_spans(long_line, 10)
        self.assertEqual(len(spans), 5)
        self.assertEqual("".join(t[0] for t in spans), long_line)
        for text, start, end in spans:
            self.assertEqual((start, end), (1, 1))
            self.assertLessEqual(len(text), 10)


class TestChunkDeepLineEnrichment(unittest.TestCase):
    def test_model_copy_overwrites_line_fields(self):
        from oasis.schemas.analysis import ChunkDeepAnalysis, VulnerabilityFinding

        base = ChunkDeepAnalysis(
            findings=[
                VulnerabilityFinding(
                    title="t",
                    vulnerable_code="c",
                    explanation="e",
                    severity="Low",
                )
            ],
            start_line=99,
            end_line=100,
        )
        merged = base.model_copy(update={"start_line": 10, "end_line": 20})
        self.assertEqual(merged.start_line, 10)
        self.assertEqual(merged.end_line, 20)
        self.assertEqual(len(merged.findings), 1)
