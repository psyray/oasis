"""Tests for tools.parse_input and related path helpers."""

import logging
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.tools import EmojiFormatter, calculate_similarity, extract_clean_path, parse_input


class TestCalculateSimilarity(unittest.TestCase):
    def test_zero_norm_returns_zero(self):
        self.assertEqual(calculate_similarity([0.0, 0.0], [1.0, 0.0]), 0.0)
        self.assertEqual(calculate_similarity([1.0, 0.0], [0.0, 0.0]), 0.0)

    def test_identical_vectors_cosine_one(self):
        self.assertAlmostEqual(calculate_similarity([1.0, 2.0], [1.0, 2.0]), 1.0, places=5)


class TestParseInput(unittest.TestCase):
    def test_single_file_returns_one_path(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "sample.py"
            p.write_text("print(1)", encoding="utf-8")
            files = parse_input(str(p))
            self.assertEqual(files, [p.resolve()])

    def test_directory_collects_files_recursively(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sub = root / "pkg"
            sub.mkdir()
            a = root / "a.py"
            b = sub / "b.js"
            a.write_text("#", encoding="utf-8")
            b.write_text("//", encoding="utf-8")
            files = parse_input(str(root))
            resolved = {f.resolve() for f in files}
            self.assertEqual(resolved, {a.resolve(), b.resolve()})

    def test_txt_manifest_lists_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "listed.py"
            target.write_text("x", encoding="utf-8")
            manifest = root / "paths.txt"
            manifest.write_text(str(target) + "\n", encoding="utf-8")
            files = parse_input(str(manifest))
            self.assertEqual(files, [target.resolve()])


class TestExtractCleanPath(unittest.TestCase):
    def test_strips_inline_comment_after_space(self):
        raw = "/tmp/project/app.py extra-args"
        clean = extract_clean_path(raw)
        self.assertEqual(Path(clean), Path("/tmp/project/app.py"))


class TestEmojiFormatter(unittest.TestCase):
    def test_includes_exception_text_from_parent_formatter(self):
        formatter = EmojiFormatter()
        try:
            raise RuntimeError("boom")
        except RuntimeError:
            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname=__file__,
                lineno=1,
                msg="handler failed",
                args=(),
                exc_info=sys.exc_info(),
            )
        out = formatter.format(record)
        self.assertIn("handler failed", out)
        self.assertIn("RuntimeError", out)
        self.assertIn("boom", out)


if __name__ == "__main__":
    unittest.main()
