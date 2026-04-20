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

from oasis.config import MAX_CHUNK_SIZE, REPORT
from oasis.helpers.embedding import (
    EmbedModelValueError,
    normalize_embed_models,
    primary_embed_model,
    resolve_embed_models,
)
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
    @staticmethod
    def _parse_cli_args(parser: argparse.ArgumentParser, input_path: str, *extra: str):
        return parser.parse_args(["-i", input_path, *extra])

    def _assert_langgraph_flags(
        self,
        namespace: argparse.Namespace,
        max_expand: int,
        poc_hints: bool,
        poc_assist: bool,
    ):
        self.assertEqual(namespace.langgraph_max_expand_iterations, max_expand)
        self.assertEqual(namespace.poc_hints, poc_hints)
        self.assertEqual(namespace.poc_assist, poc_assist)

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
            ns = self._parse_cli_args(
                parser, td, "--langgraph-max-expand", "4", "--poc-hints", "--poc-assist"
            )
            self._assert_langgraph_flags(ns, max_expand=4, poc_hints=True, poc_assist=True)
            ns2 = self._parse_cli_args(parser, td)
            self._assert_langgraph_flags(ns2, max_expand=2, poc_hints=False, poc_assist=False)
        finally:
            shutil.rmtree(td)

    def test_parse_embed_models_csv_returns_unique_trimmed_ordered_values(self):
        models = OasisScanner._parse_embed_models_csv(
            " qwen3-embedding:4b, bge-m3 ,qwen3-embedding:4b "
        )
        self.assertEqual(models, ["qwen3-embedding:4b", "bge-m3"])

    def test_parse_embed_models_csv_rejects_empty_values(self):
        with self.assertRaises(EmbedModelValueError):
            OasisScanner._parse_embed_models_csv(" , , ")

    def test_embed_model_cli_type_accepts_csv_in_audit_mode(self):
        scanner = OasisScanner()
        parser = scanner.setup_argument_parser()
        td = tempfile.mkdtemp()
        try:
            ns = self._parse_cli_args(parser, td, "--audit", "-em", "m1,m2,m1")
            self.assertEqual(ns.embed_model, ["m1", "m2"])
        finally:
            shutil.rmtree(td)

    def test_normalize_embed_models_keeps_order_and_uniqueness_for_iterables(self):
        models = normalize_embed_models([" m1,m2 ", "m2", "m3"])
        self.assertEqual(models, ["m1", "m2", "m3"])

    def test_primary_embed_model_uses_first_normalized_value(self):
        model = primary_embed_model("  qwen3-embedding:4b , bge-m3 ")
        self.assertEqual(model, "qwen3-embedding:4b")

    def test_resolve_embed_models_returns_list_and_primary(self):
        models, primary = resolve_embed_models([" m1,m2 ", "m2"])
        self.assertEqual(models, ["m1", "m2"])
        self.assertEqual(primary, "m1")

    def test_normalize_embed_models_rejects_non_string_iterable_items(self):
        with self.assertRaises(EmbedModelValueError):
            normalize_embed_models(["m1", object()])  # type: ignore[list-item]

    def test_normalize_embed_models_rejects_empty_iterable_values(self):
        with self.assertRaises(EmbedModelValueError):
            normalize_embed_models([])


class TestOasisCliInitArguments(unittest.TestCase):
    @staticmethod
    def _build_init_namespace(input_path: str, output_format: str = "%%%invalid%%%"):
        namespace = MagicMock()
        namespace.version = False
        namespace.list_models = False
        namespace.silent = False
        namespace.models = None
        namespace.audit = False
        namespace.input_path = input_path
        namespace.output_format = output_format
        namespace.debug = False
        return namespace

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
            namespace = self._build_init_namespace(td)
            with patch.object(scanner, "_handle_argument_errors", return_value=False) as err:
                result = scanner._init_arguments(namespace)
            self.assertFalse(result)
            err.assert_called_once()
        finally:
            shutil.rmtree(td)


class TestOasisAuditMode(unittest.TestCase):
    @staticmethod
    def _build_embedding_analyzer_mock():
        analyzer = MagicMock()
        analyzer.analyze_all_vulnerabilities.return_value = {"XSS": {"results": []}}
        analyzer.generate_vulnerability_statistics.return_value = [{"name": "TOTAL"}]
        return analyzer

    def test_handle_audit_mode_runs_once_per_embedding_model(self):
        scanner = OasisScanner()
        scanner.embed_models = ["embed-a", "embed-b"]
        scanner.args = SimpleNamespace(
            embed_model=["embed-a", "embed-b"],
            input_path="/tmp/project",
        )
        scanner.ollama_manager = MagicMock()
        scanner.report = MagicMock()
        vuln_mapping = {"xss": {"name": "XSS"}}

        with patch(
            "oasis.oasis.SecurityAnalyzer.get_vulnerabilities_to_check",
            return_value=([{"name": "XSS"}], []),
        ), patch("oasis.oasis.EmbeddingManager") as manager_cls, patch(
            "oasis.oasis.EmbeddingAnalyzer"
        ) as analyzer_cls:
            base_manager = MagicMock()
            base_manager.prepare_input_files.return_value = [Path("a.py"), Path("b.py")]
            manager_a = MagicMock()
            manager_b = MagicMock()
            manager_cls.side_effect = [base_manager, manager_a, manager_b]
            analyzer_a = self._build_embedding_analyzer_mock()
            analyzer_b = self._build_embedding_analyzer_mock()
            analyzer_cls.side_effect = [analyzer_a, analyzer_b]

            result = scanner.handle_audit_mode(vuln_mapping)

        self.assertTrue(result)
        scanner.report.create_report_directories.assert_called_once_with(
            "/tmp/project", models=["embed-a", "embed-b"]
        )
        base_manager.prepare_input_files.assert_called_once()
        manager_a.process_input_files.assert_called_once_with(
            unittest.mock.ANY,
            files_to_analyze=[Path("a.py"), Path("b.py")],
            pre_parsed=True,
        )
        manager_b.process_input_files.assert_called_once_with(
            unittest.mock.ANY,
            files_to_analyze=[Path("a.py"), Path("b.py")],
            pre_parsed=True,
        )
        self.assertEqual(scanner.report.generate_audit_report.call_count, 2)

    def test_handle_audit_mode_reuses_single_detected_chunk_size_for_all_models(self):
        scanner = OasisScanner()
        scanner.embed_models = ["embed-a", "embed-b"]
        scanner.args = SimpleNamespace(
            embed_model=["embed-a", "embed-b"],
            input_path="/tmp/project",
            chunk_size=None,
        )
        scanner.ollama_manager = MagicMock()
        scanner.ollama_manager.detect_optimal_chunk_size.return_value = 1024
        scanner.report = MagicMock()
        vuln_mapping = {"xss": {"name": "XSS"}}

        with patch(
            "oasis.oasis.SecurityAnalyzer.get_vulnerabilities_to_check",
            return_value=([{"name": "XSS"}], []),
        ), patch("oasis.oasis.EmbeddingManager") as manager_cls, patch(
            "oasis.oasis.EmbeddingAnalyzer"
        ) as analyzer_cls:
            base_manager = MagicMock()
            base_manager.prepare_input_files.return_value = [Path("a.py"), Path("b.py")]
            manager_a = MagicMock()
            manager_b = MagicMock()
            manager_cls.side_effect = [base_manager, manager_a, manager_b]
            analyzer_a = self._build_embedding_analyzer_mock()
            analyzer_b = self._build_embedding_analyzer_mock()
            analyzer_cls.side_effect = [analyzer_a, analyzer_b]

            result = scanner.handle_audit_mode(vuln_mapping)

        self.assertTrue(result)
        self.assertEqual(
            scanner.ollama_manager.detect_optimal_chunk_size.call_args_list,
            [unittest.mock.call("embed-a")],
        )
        first_model_args = manager_cls.call_args_list[1].args[0]
        second_model_args = manager_cls.call_args_list[2].args[0]
        self.assertEqual(first_model_args.chunk_size, 1024)
        self.assertEqual(second_model_args.chunk_size, 1024)

    def test_handle_audit_mode_reuses_single_detected_chunk_size_even_with_existing_auto_chunk_size(self):
        scanner = OasisScanner()
        scanner.embed_models = ["embed-a", "embed-b"]
        scanner.chunk_size_is_manual = False
        scanner.args = SimpleNamespace(
            embed_model=["embed-a", "embed-b"],
            input_path="/tmp/project",
            chunk_size=7372,
        )
        scanner.ollama_manager = MagicMock()
        scanner.ollama_manager.detect_optimal_chunk_size.return_value = 1536
        scanner.report = MagicMock()
        vuln_mapping = {"xss": {"name": "XSS"}}

        with patch(
            "oasis.oasis.SecurityAnalyzer.get_vulnerabilities_to_check",
            return_value=([{"name": "XSS"}], []),
        ), patch("oasis.oasis.EmbeddingManager") as manager_cls, patch(
            "oasis.oasis.EmbeddingAnalyzer"
        ) as analyzer_cls:
            base_manager = MagicMock()
            base_manager.prepare_input_files.return_value = [Path("a.py"), Path("b.py")]
            manager_a = MagicMock()
            manager_b = MagicMock()
            manager_cls.side_effect = [base_manager, manager_a, manager_b]
            analyzer_a = self._build_embedding_analyzer_mock()
            analyzer_b = self._build_embedding_analyzer_mock()
            analyzer_cls.side_effect = [analyzer_a, analyzer_b]

            result = scanner.handle_audit_mode(vuln_mapping)

        self.assertTrue(result)
        self.assertEqual(
            scanner.ollama_manager.detect_optimal_chunk_size.call_args_list,
            [unittest.mock.call("embed-a")],
        )

    def test_handle_audit_mode_uses_safe_fallback_when_detection_returns_invalid(self):
        scanner = OasisScanner()
        scanner.embed_models = ["embed-a", "embed-b"]
        scanner.args = SimpleNamespace(
            embed_model=["embed-a", "embed-b"],
            input_path="/tmp/project",
            chunk_size=None,
        )
        scanner.ollama_manager = MagicMock()
        scanner.ollama_manager.detect_optimal_chunk_size.return_value = None
        scanner.report = MagicMock()
        vuln_mapping = {"xss": {"name": "XSS"}}

        with patch(
            "oasis.oasis.SecurityAnalyzer.get_vulnerabilities_to_check",
            return_value=([{"name": "XSS"}], []),
        ), patch("oasis.oasis.EmbeddingManager") as manager_cls, patch(
            "oasis.oasis.EmbeddingAnalyzer"
        ) as analyzer_cls:
            base_manager = MagicMock()
            base_manager.prepare_input_files.return_value = [Path("a.py"), Path("b.py")]
            manager_a = MagicMock()
            manager_b = MagicMock()
            manager_cls.side_effect = [base_manager, manager_a, manager_b]
            analyzer_a = self._build_embedding_analyzer_mock()
            analyzer_b = self._build_embedding_analyzer_mock()
            analyzer_cls.side_effect = [analyzer_a, analyzer_b]

            result = scanner.handle_audit_mode(vuln_mapping)

        self.assertTrue(result)
        first_model_args = manager_cls.call_args_list[1].args[0]
        second_model_args = manager_cls.call_args_list[2].args[0]
        self.assertEqual(first_model_args.chunk_size, MAX_CHUNK_SIZE)
        self.assertEqual(second_model_args.chunk_size, MAX_CHUNK_SIZE)

    def test_handle_audit_mode_uses_safe_fallback_when_detection_raises(self):
        scanner = OasisScanner()
        scanner.embed_models = ["embed-a"]
        scanner.args = SimpleNamespace(
            embed_model=["embed-a"],
            input_path="/tmp/project",
            chunk_size=None,
        )
        scanner.ollama_manager = MagicMock()
        scanner.ollama_manager.detect_optimal_chunk_size.side_effect = RuntimeError("boom")
        scanner.report = MagicMock()
        vuln_mapping = {"xss": {"name": "XSS"}}

        with patch(
            "oasis.oasis.SecurityAnalyzer.get_vulnerabilities_to_check",
            return_value=([{"name": "XSS"}], []),
        ), patch("oasis.oasis.EmbeddingManager") as manager_cls, patch(
            "oasis.oasis.EmbeddingAnalyzer"
        ) as analyzer_cls:
            base_manager = MagicMock()
            base_manager.prepare_input_files.return_value = [Path("a.py")]
            manager_a = MagicMock()
            manager_cls.side_effect = [base_manager, manager_a]
            analyzer_a = self._build_embedding_analyzer_mock()
            analyzer_cls.side_effect = [analyzer_a]

            result = scanner.handle_audit_mode(vuln_mapping)

        self.assertTrue(result)
        first_model_args = manager_cls.call_args_list[1].args[0]
        self.assertEqual(first_model_args.chunk_size, MAX_CHUNK_SIZE)

    def test_handle_audit_mode_warns_when_manual_chunk_size_invalid(self):
        """Manual --chunk-size that does not resolve to a positive int falls back to MAX_CHUNK_SIZE."""
        scanner = OasisScanner()
        scanner.embed_models = ["embed-a"]
        scanner.chunk_size_is_manual = True
        scanner.args = SimpleNamespace(
            embed_model=["embed-a"],
            input_path="/tmp/project",
            chunk_size=0,
        )
        scanner.ollama_manager = MagicMock()
        scanner.report = MagicMock()
        vuln_mapping = {"xss": {"name": "XSS"}}

        with patch(
            "oasis.oasis.SecurityAnalyzer.get_vulnerabilities_to_check",
            return_value=([{"name": "XSS"}], []),
        ), patch("oasis.oasis.EmbeddingManager") as manager_cls, patch(
            "oasis.oasis.EmbeddingAnalyzer"
        ) as analyzer_cls:
            base_manager = MagicMock()
            base_manager.prepare_input_files.return_value = [Path("a.py")]
            manager_a = MagicMock()
            manager_cls.side_effect = [base_manager, manager_a]
            analyzer_a = self._build_embedding_analyzer_mock()
            analyzer_cls.side_effect = [analyzer_a]

            with self.assertLogs("oasis", level="WARNING") as cm:
                result = scanner.handle_audit_mode(vuln_mapping)

        self.assertTrue(result)
        messages = [rec.getMessage() for rec in cm.records]
        self.assertTrue(
            any("Invalid manual --chunk-size" in m for m in messages),
            f"Expected invalid chunk-size warning in {messages!r}",
        )
        scanner.ollama_manager.detect_optimal_chunk_size.assert_not_called()
        first_model_args = manager_cls.call_args_list[1].args[0]
        self.assertEqual(first_model_args.chunk_size, MAX_CHUNK_SIZE)

    def test_handle_audit_mode_logs_and_exits_when_no_vulnerabilities(self):
        scanner = OasisScanner()
        scanner.embed_models = ["embed-a"]
        scanner.args = SimpleNamespace(
            embed_model=["embed-a"],
            input_path="/tmp/project",
        )
        scanner.ollama_manager = MagicMock()
        scanner.report = MagicMock()
        vuln_mapping = {"xss": {"name": "XSS"}}

        with patch(
            "oasis.oasis.SecurityAnalyzer.get_vulnerabilities_to_check",
            return_value=([], []),
        ), patch("oasis.oasis.logger") as logger_mock:
            result = scanner.handle_audit_mode(vuln_mapping)

        self.assertTrue(result)
        logger_mock.warning.assert_called_once()
        scanner.report.create_report_directories.assert_not_called()


class TestOllamaInitOrdering(unittest.TestCase):
    def test_init_ollama_detects_chunk_after_model_is_available(self):
        scanner = OasisScanner()
        scanner.embed_models = ["qwen3-embedding:4b"]
        scanner.primary_embed_model = "qwen3-embedding:4b"
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
        self.assertEqual(scanner.args.chunk_size, 2048)
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
        scanner.embed_models = ["qwen3-embedding:4b"]
        scanner.primary_embed_model = "qwen3-embedding:4b"
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


class TestOasisInitFlow(unittest.TestCase):
    def test_init_oasis_skips_preprocessing_for_audit_mode(self):
        scanner = OasisScanner()
        scanner.args = SimpleNamespace(
            input_path="/tmp/project",
            output_format=["json"],
            language="en",
            web=False,
            debug=False,
            web_expose="local",
            web_password=None,
            web_port=5000,
            ollama_url="http://127.0.0.1:11434",
            audit=True,
        )

        with patch.object(scanner, "_init_arguments", return_value=True), patch(
            "oasis.oasis.Report"
        ) as report_cls, patch.object(scanner, "_init_ollama", return_value=True), patch.object(
            scanner, "_init_processing", return_value=True
        ) as init_processing_mock, patch.object(
            scanner, "_execute_requested_mode", return_value=0
        ) as execute_mock:
            result = scanner._init_oasis(scanner.args)

        self.assertEqual(result, 0)
        report_cls.assert_called_once()
        init_processing_mock.assert_not_called()
        execute_mock.assert_called_once()

    def test_init_oasis_keeps_preprocessing_for_non_audit_mode(self):
        scanner = OasisScanner()
        scanner.args = SimpleNamespace(
            input_path="/tmp/project",
            output_format=["json"],
            language="en",
            web=False,
            debug=False,
            web_expose="local",
            web_password=None,
            web_port=5000,
            ollama_url="http://127.0.0.1:11434",
            audit=False,
        )

        with patch.object(scanner, "_init_arguments", return_value=True), patch(
            "oasis.oasis.Report"
        ), patch.object(scanner, "_init_ollama", return_value=True), patch.object(
            scanner, "_init_processing", return_value=True
        ) as init_processing_mock, patch.object(
            scanner, "_execute_requested_mode", return_value=0
        ) as execute_mock:
            result = scanner._init_oasis(scanner.args)

        self.assertEqual(result, 0)
        init_processing_mock.assert_called_once()
        execute_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
