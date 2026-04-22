"""Tests for oasis.helpers.context.expand."""

import unittest

from oasis.helpers.context.expand import expand_line_window


class TestExpandLineWindow(unittest.TestCase):
    def test_untrimmed_when_under_budget(self):
        lines = [f"line{i}" for i in range(1, 21)]
        text, wl, wh = expand_line_window(
            lines,
            start_line=10,
            end_line=12,
            padding_before=2,
            padding_after=2,
            max_chars=10000,
        )
        self.assertEqual(wl, 8)
        self.assertEqual(wh, 14)
        self.assertEqual(text.splitlines()[0], "line8")
        self.assertEqual(text.splitlines()[-1], "line14")

    def test_trim_keeps_suspicious_span_lines(self):
        # Padded window would be huge; budget forces trimming. Suspicious lines 5–7
        # must remain fully present (not dropped from the bottom).
        lines = [f"L{i:03d}" * 15 for i in range(1, 51)]  # long lines (~48 chars each)
        text, wl, wh = expand_line_window(
            lines,
            start_line=10,
            end_line=12,
            padding_before=30,
            padding_after=30,
            max_chars=250,
        )
        self.assertLessEqual(len(text), 250)
        self.assertLessEqual(wl, 10)
        self.assertGreaterEqual(wh, 12)
        joined = "\n".join(lines[wl - 1 : wh])
        self.assertEqual(text, joined)
        for ln in (10, 11, 12):
            self.assertIn(lines[ln - 1], text)

    def test_suspicious_span_alone_exceeds_budget_prefix_from_start(self):
        # Single very long suspicious line: hard prefix cut; window starts at start_line.
        long_line = "X" * 500
        lines = ["short", long_line, "tail"]
        text, wl, wh = expand_line_window(
            lines,
            start_line=2,
            end_line=2,
            padding_before=1,
            padding_after=1,
            max_chars=80,
        )
        self.assertEqual(wl, 2)
        self.assertEqual(text, long_line[:80])
        self.assertEqual(wh, 2)


if __name__ == "__main__":
    unittest.main()
