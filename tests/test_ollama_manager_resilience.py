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


if __name__ == "__main__":
    unittest.main()
