"""Tests for canonical path containment helpers."""

import tempfile
import unittest
from pathlib import Path

from oasis.helpers.path_containment import is_path_within_root


class TestPathContainment(unittest.TestCase):
    def test_inside_same_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            inner = root / "a" / "b.txt"
            inner.parent.mkdir(parents=True)
            inner.write_text("x", encoding="utf-8")
            self.assertTrue(is_path_within_root(inner, root))

    def test_outside_traversal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            escape = root.parent / "outside.txt"
            self.assertFalse(is_path_within_root(escape, root))


if __name__ == "__main__":
    unittest.main()
