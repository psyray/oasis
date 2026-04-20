"""CLI validation tests for OasisScanner (argparse helpers, argument rules)."""

import argparse
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.config import REPORT
from oasis.oasis import OasisScanner


class TestRemovedLegacyCliFlags(unittest.TestCase):
    def test_removed_legacy_flags_return_error_message(self):
        self.assertIsNotNone(OasisScanner.removed_cli_flag_error(["--adaptive"]))
        self.assertIsNotNone(OasisScanner.removed_cli_flag_error(["-ad"]))
        self.assertIsNotNone(OasisScanner.removed_cli_flag_error(["--analyze-type", "deep"]))
        self.assertIsNotNone(OasisScanner.removed_cli_flag_error(["-at"]))
        self.assertIsNotNone(OasisScanner.removed_cli_flag_error(["--analyze-type=standard"]))
        self.assertIsNotNone(OasisScanner.removed_cli_flag_error(["-at=deep"]))

    def test_removed_legacy_flags_absent_returns_none(self):
        td = tempfile.mkdtemp()
        try:
            self.assertIsNone(
                OasisScanner.removed_cli_flag_error(
                    ["-i", td, "--langgraph-max-expand", "3", "--embeddings-analyze-type", "file"]
                )
            )
        finally:
            shutil.rmtree(td)


class TestOasisCliParsing(unittest.TestCase):
    def test_parse_yes_no_accepts_yes_no(self):
        self.assertTrue(OasisScanner._parse_yes_no_flag("yes"))
        self.assertFalse(OasisScanner._parse_yes_no_flag("no"))
        self.assertFalse(OasisScanner._parse_yes_no_flag(" NO "))
        self.assertTrue(OasisScanner._parse_yes_no_flag("Yes"))

    def test_parse_yes_no_rejects_invalid(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            OasisScanner._parse_yes_no_flag("maybe")

    def test_output_format_cli_all_expands_to_canonical_list(self):
        out = OasisScanner._output_format_cli_type("all")
        self.assertEqual(out, list(REPORT["OUTPUT_FORMATS"]))

    def test_output_format_cli_rejects_non_string(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            OasisScanner._output_format_cli_type(123)  # type: ignore[arg-type]

    def test_parse_output_formats_list_rejects_unknown_token(self):
        with self.assertRaises(ValueError) as ctx:
            OasisScanner._parse_output_formats_list("json,not_a_real_format")
        self.assertIn("Unknown output format", str(ctx.exception))

    def test_langgraph_cli_flags_defaults_and_values(self):
        scanner = OasisScanner()
        parser = scanner.setup_argument_parser()
        td = tempfile.mkdtemp()
        try:
            ns = parser.parse_args(
                ["-i", td, "--langgraph-max-expand", "4", "--poc-hints", "--poc-assist"]
            )
            self.assertEqual(ns.langgraph_max_expand_iterations, 4)
            self.assertTrue(ns.poc_hints)
            self.assertTrue(ns.poc_assist)
            ns2 = parser.parse_args(["-i", td])
            self.assertEqual(ns2.langgraph_max_expand_iterations, 2)
            self.assertFalse(ns2.poc_hints)
            self.assertFalse(ns2.poc_assist)
        finally:
            shutil.rmtree(td)


class TestOasisCliInitArguments(unittest.TestCase):
    def test_init_arguments_requires_input_path(self):
        scanner = OasisScanner()
        parser = scanner.setup_argument_parser()
        namespace = parser.parse_args(["--output-format", "json"])
        namespace.input_path = ""
        with patch.object(scanner, "_handle_argument_errors", return_value=False) as err:
            result = scanner._init_arguments(namespace)
        self.assertFalse(result)
        err.assert_called_once()
        self.assertIn("--input", err.call_args[0][0])

    def test_init_arguments_rejects_silent_without_models_or_audit(self):
        scanner = OasisScanner()
        parser = scanner.setup_argument_parser()
        td = tempfile.mkdtemp()
        try:
            namespace = parser.parse_args(["-i", td, "-s"])
            with patch.object(scanner, "_handle_argument_errors", return_value=False) as err:
                result = scanner._init_arguments(namespace)
            self.assertFalse(result)
            err.assert_called_once()
            self.assertIn("silent", err.call_args[0][0].lower())
        finally:
            shutil.rmtree(td)

    def test_init_arguments_accepts_silent_with_models(self):
        scanner = OasisScanner()
        parser = scanner.setup_argument_parser()
        td = tempfile.mkdtemp()
        try:
            namespace = parser.parse_args(["-i", td, "-s", "-m", "mistral"])
            with patch.object(scanner, "_setup_logging"), patch(
                "oasis.oasis.validate_report_dashboard_formats"
            ), patch("oasis.oasis.display_logo"):
                result = scanner._init_arguments(namespace)
            self.assertTrue(result)
        finally:
            shutil.rmtree(td)

    def test_init_arguments_version_returns_none(self):
        scanner = OasisScanner()
        parser = scanner.setup_argument_parser()
        namespace = parser.parse_args(["--version"])
        with patch("builtins.print") as mock_print:
            result = scanner._init_arguments(namespace)
        self.assertIsNone(result)
        mock_print.assert_called_once()

    def test_init_arguments_invalid_output_format_string_returns_false(self):
        scanner = OasisScanner()
        td = tempfile.mkdtemp()
        try:
            namespace = MagicMock()
            namespace.version = False
            namespace.list_models = False
            namespace.silent = False
            namespace.models = None
            namespace.audit = False
            namespace.input_path = td
            namespace.output_format = "%%%invalid%%%"
            namespace.debug = False
            with patch.object(scanner, "_handle_argument_errors", return_value=False) as err:
                result = scanner._init_arguments(namespace)
            self.assertFalse(result)
            err.assert_called_once()
        finally:
            shutil.rmtree(td)


class TestOllamaInitOrdering(unittest.TestCase):
    def test_init_ollama_detects_chunk_after_model_is_available(self):
        scanner = OasisScanner()
        scanner.args = SimpleNamespace(
            ollama_url="http://127.0.0.1:11434",
            chunk_size=None,
            embed_model="qwen3-embedding:4b",
        )

        fake_manager = MagicMock()
        fake_manager.get_client.return_value = object()
        fake_manager.check_connection.return_value = True
        fake_manager.ensure_model_available.return_value = True
        fake_manager.detect_optimal_chunk_size.return_value = 36864

        with patch("oasis.oasis.OllamaManager", return_value=fake_manager):
            result = scanner._init_ollama()

        self.assertTrue(result)
        self.assertEqual(scanner.args.chunk_size, 36864)
        check_idx = fake_manager.method_calls.index(("check_connection", (), {}))
        ensure_idx = fake_manager.method_calls.index(
            ("ensure_model_available", ("qwen3-embedding:4b",), {})
        )
        detect_idx = fake_manager.method_calls.index(
            ("detect_optimal_chunk_size", ("qwen3-embedding:4b",), {})
        )
        self.assertLess(check_idx, ensure_idx)
        self.assertLess(ensure_idx, detect_idx)

    def test_init_ollama_skips_chunk_detection_when_model_unavailable(self):
        scanner = OasisScanner()
        scanner.args = SimpleNamespace(
            ollama_url="http://127.0.0.1:11434",
            chunk_size=None,
            embed_model="qwen3-embedding:4b",
        )

        fake_manager = MagicMock()
        fake_manager.get_client.return_value = object()
        fake_manager.check_connection.return_value = True
        fake_manager.ensure_model_available.return_value = False

        with patch("oasis.oasis.OllamaManager", return_value=fake_manager):
            result = scanner._init_ollama()

        self.assertFalse(result)
        fake_manager.detect_optimal_chunk_size.assert_not_called()


if __name__ == "__main__":
    unittest.main()
