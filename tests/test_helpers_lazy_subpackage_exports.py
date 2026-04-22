"""Validate lazy _LAZY_IMPORTS maps on assistant.scan, assistant.web, and executive."""

from __future__ import annotations

import unittest

import oasis.helpers.assistant.scan as assistant_scan
import oasis.helpers.assistant.web as assistant_web
import oasis.helpers.executive as executive
from oasis.helpers.lazy_export_validation import validate_lazy_import_map


class TestHelpersLazySubpackageExports(unittest.TestCase):
    def test_assistant_scan_lazy_map(self) -> None:
        errs = validate_lazy_import_map(assistant_scan)
        self.assertEqual(errs, [], "\n".join(errs))

    def test_assistant_web_lazy_map(self) -> None:
        errs = validate_lazy_import_map(assistant_web)
        self.assertEqual(errs, [], "\n".join(errs))

    def test_executive_lazy_map(self) -> None:
        errs = validate_lazy_import_map(executive)
        self.assertEqual(errs, [], "\n".join(errs))


if __name__ == "__main__":
    unittest.main()
