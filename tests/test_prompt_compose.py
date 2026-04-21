"""Tests for user-instruction prompt composition."""

import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.helpers.prompt_compose import (
    append_user_instructions,
    read_custom_instructions_file,
    resolved_custom_instructions,
)


class TestPromptCompose(unittest.TestCase):
    def test_append_empty_returns_base(self):
        self.assertEqual(append_user_instructions("base", ""), "base")
        self.assertEqual(append_user_instructions("base", "   "), "base")

    def test_append_adds_block(self):
        out = append_user_instructions("base", "x")
        self.assertIn("base", out)
        self.assertIn("USER_ADDITIONAL_INSTRUCTIONS", out)
        self.assertIn("x", out)

    def test_resolved_merges_file_and_inline(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "i.txt"
            p.write_text("from file", encoding="utf-8")
            args = SimpleNamespace(
                custom_instructions="from cli",
                custom_instructions_file=str(p),
            )
            r = resolved_custom_instructions(args)
            self.assertIn("from file", r)
            self.assertIn("from cli", r)

    def test_read_file_missing_returns_empty(self):
        self.assertEqual(read_custom_instructions_file(None), "")
        self.assertEqual(read_custom_instructions_file("/nonexistent/nope.txt"), "")
