"""Resilience-oriented tests for OllamaManager (connection handling, client compatibility)."""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.ollama_manager import OllamaManager


class TestOllamaManagerResilience(unittest.TestCase):
    def test_get_client_raises_connection_error_when_probe_list_fails(self):
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        fake_client = MagicMock()
        fake_client.list.side_effect = RuntimeError("simulated transport failure")

        with patch("oasis.ollama_manager.ollama.Client", return_value=fake_client):
            mgr.client = None
            with self.assertRaises(ConnectionError) as ctx:
                mgr.get_client()
            self.assertIn("Cannot connect to Ollama server", str(ctx.exception))

    def test_check_connection_returns_false_when_probe_fails(self):
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        fake_client = MagicMock()
        fake_client.list.side_effect = ConnectionError("connection refused")

        with patch("oasis.ollama_manager.ollama.Client", return_value=fake_client):
            mgr.client = None
            self.assertFalse(mgr.check_connection())

    def test_chat_retries_without_think_when_client_rejects_think_kwarg(self):
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        mgr.client = MagicMock()
        mgr.client.chat.side_effect = [
            TypeError("unexpected keyword argument 'think'"),
            {"message": {"content": "ok"}},
        ]
        mgr.set_model_thinking("mistral", True)

        out = mgr.chat("mistral", [{"role": "user", "content": "ping"}])

        self.assertEqual(out, {"message": {"content": "ok"}})
        self.assertEqual(mgr.client.chat.call_count, 2)
        second_kw = mgr.client.chat.call_args_list[1].kwargs
        self.assertNotIn("think", second_kw)

    def test_generate_retries_without_think_when_client_rejects_think_kwarg(self):
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        mgr.client = MagicMock()
        mgr.client.generate.side_effect = [
            TypeError("unexpected keyword argument 'think'"),
            {"response": "done"},
        ]
        mgr.set_model_thinking("llama", True)

        out = mgr.generate("llama", "prompt text")

        self.assertEqual(out, {"response": "done"})
        self.assertEqual(mgr.client.generate.call_count, 2)
        self.assertNotIn("think", mgr.client.generate.call_args_list[1].kwargs)


class TestOllamaManagerThinkingOverrides(unittest.TestCase):
    """State-only thinking configuration (no network)."""

    def test_resolve_model_thinking_returns_override(self):
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        mgr.set_model_thinking("scan-model", False)
        mgr.set_model_thinking("deep-model", True)
        self.assertIs(mgr._resolve_model_thinking("deep-model"), True)
        self.assertIs(mgr._resolve_model_thinking("scan-model"), False)
        self.assertIsNone(mgr._resolve_model_thinking("unknown"))

    def test_configure_analysis_model_thinking_maps_scan_and_main_models(self):
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        mgr.configure_analysis_model_thinking(
            "scanner",
            ["deep-a", "deep-b"],
            scan_model_thinking=False,
            main_model_thinking=True,
        )
        self.assertIs(mgr._resolve_model_thinking("scanner"), False)
        self.assertIs(mgr._resolve_model_thinking("deep-a"), True)
        self.assertIs(mgr._resolve_model_thinking("deep-b"), True)


class TestNormalizeClientResponse(unittest.TestCase):
    """ollama-python may return Pydantic ChatResponse instead of dict — normalize to dict."""

    def test_passes_through_dict_and_none(self):
        self.assertIsNone(OllamaManager._normalize_client_response(None))
        d = {"message": {"content": "x"}}
        self.assertEqual(OllamaManager._normalize_client_response(d), d)

    def test_model_dump_converts_sdk_like_object(self):
        class ChatResp:
            def model_dump(self):
                return {
                    "model": "qwen",
                    "message": {"role": "assistant", "content": '{"verdict":"CLEAN"}'},
                }

        out = OllamaManager._normalize_client_response(ChatResp())
        self.assertEqual(out["message"]["content"], '{"verdict":"CLEAN"}')

    def test_chat_returns_dict_when_client_returns_sdk_object(self):
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        mgr.client = MagicMock()

        class ChatResp:
            def model_dump(self):
                return {"model": "m", "message": {"role": "assistant", "content": "hi"}}

        mgr.client.chat.return_value = ChatResp()
        out = mgr.chat("m", [{"role": "user", "content": "x"}])
        self.assertEqual(out, {"model": "m", "message": {"role": "assistant", "content": "hi"}})


class TestModelInfoNumCtx(unittest.TestCase):
    """num_ctx extraction for chunk sizing and UI (embedding models may omit parameters)."""

    def test_none_parameters_returns_none(self):
        class MI:
            parameters = None

        self.assertIsNone(OllamaManager._model_info_num_ctx(MI()))

    def test_dict_with_num_ctx(self):
        self.assertEqual(
            OllamaManager._model_info_num_ctx({"parameters": {"num_ctx": 8192}}),
            8192,
        )

    def test_detect_optimal_chunk_size_uses_num_ctx(self):
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        mgr._get_model_info = MagicMock(
            return_value={"parameters": {"num_ctx": 1000}}
        )
        self.assertEqual(mgr._detect_optimal_chunk_size("embed"), int(1000 * 0.9))


class TestParameterCountNumeric(unittest.TestCase):
    """Pure helpers used by lightweight filtering and formatted parameter display."""

    def test_dict_details_parameter_size_b(self):
        info = {"details": {"parameter_size": "8.0B"}}
        self.assertEqual(OllamaManager._parameter_count_numeric(info), 8e9)

    def test_dict_modelinfo_parameter_count_fallback(self):
        info = {"modelinfo": {"general.parameter_count": 500_000_000}}
        self.assertEqual(OllamaManager._parameter_count_numeric(info), 500_000_000.0)

    def test_unknown_returns_zero(self):
        self.assertEqual(OllamaManager._parameter_count_numeric({}), 0.0)


if __name__ == "__main__":
    unittest.main()
