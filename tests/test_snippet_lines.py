"""Tests for snippet-to-line resolution (no heavy oasis.tools dependency)."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.helpers.misc import absolute_snippet_lines_in_file, substring_line_span_1based


class TestSubstringLineSpan(unittest.TestCase):
    def test_single_line_snippet(self):
        haystack = "a\nb\nc\nd"
        self.assertEqual(substring_line_span_1based(haystack, "c"), (3, 3))

    def test_multiline_snippet(self):
        haystack = "L1\nL2\nL3\nL4"
        self.assertEqual(substring_line_span_1based(haystack, "L2\nL3"), (2, 3))

    def test_php_chunk_sql_injection_lines(self):
        php = Path(ROOT / "test_files" / "vulnerable.php").read_text(encoding="utf-8")
        needle = (
            '$query = "SELECT * FROM users WHERE username = \'$username\'";\n'
            "    return $conn->query($query);"
        )
        rel = substring_line_span_1based(php, needle)
        self.assertIsNotNone(rel)
        assert rel is not None
        self.assertEqual(rel, (6, 7))

    def test_absolute_lines_single_chunk_file(self):
        php = Path(ROOT / "test_files" / "vulnerable.php").read_text(encoding="utf-8")
        needle = '$query = "SELECT * FROM users WHERE username = \'$username\'";'
        abs_lines = absolute_snippet_lines_in_file(php, 1, needle)
        self.assertEqual(abs_lines, (6, 6))
