"""Regression tests for OasisScanner web-only mode behavior."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.oasis import OasisScanner


class TestOasisWebMode(unittest.TestCase):
    def test_web_mode_serves_ui_without_starting_scan_pipeline(self):
        scanner = OasisScanner()
        scanner.args = SimpleNamespace(
            web=True,
            debug=False,
            web_expose="local",
            web_password="secret",
            web_port=5000,
            input_path="test_files",
            output_format=["json"],
            language="en",
            ollama_url="http://localhost:11434",
        )

        scanner._init_arguments = MagicMock(return_value=True)
        scanner._init_ollama = MagicMock(return_value=True)
        scanner._init_processing = MagicMock(return_value=True)
        scanner._execute_requested_mode = MagicMock(return_value=0)

        with patch("oasis.oasis.Report") as report_cls, patch("oasis.oasis.WebServer") as web_cls:
            report_instance = MagicMock()
            report_cls.return_value = report_instance
            web_instance = MagicMock()
            web_cls.return_value = web_instance

            exit_code = scanner._init_oasis(args=scanner.args)

        self.assertEqual(exit_code, 0)
        scanner._init_ollama.assert_not_called()
        scanner._init_processing.assert_not_called()
        scanner._execute_requested_mode.assert_not_called()
        web_instance.run.assert_called_once()

    def test_keyboard_interrupt_marks_progress_aborted_before_exit(self):
        scanner = OasisScanner()
        scanner.report = MagicMock()
        scanner._init_oasis = MagicMock(side_effect=KeyboardInterrupt)
        scanner._save_cache_on_exit = MagicMock()

        exit_code = scanner.run(args=SimpleNamespace())

        self.assertEqual(exit_code, 1)
        scanner.report.mark_progress_aborted.assert_called_once()
        scanner._save_cache_on_exit.assert_called_once()


if __name__ == "__main__":
    unittest.main()
