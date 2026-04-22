"""Resilience-oriented tests for OllamaManager (connection handling, client compatibility)."""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
from ollama import RequestError

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

    def test_chat_stream_yields_error_chunk_when_iterator_raises(self):
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        mgr.client = MagicMock()

        def _chunks():
            yield {"message": {"content": "partial"}}
            raise RuntimeError("stream dropped")

        mgr.client.chat.return_value = _chunks()

        out = list(mgr.chat_stream("m", [{"role": "user", "content": "x"}]))
        self.assertGreaterEqual(len(out), 2)
        self.assertEqual(out[0].get("message", {}).get("content"), "partial")
        self.assertEqual(out[-1].get("type"), "error")
        self.assertIn("stream dropped", str(out[-1].get("error", "")))


class TestModelInfoNumCtx(unittest.TestCase):
    """Chunk sizing: Modelfile ``num_ctx`` first, else GGUF ``*.context_length``."""

    def test_num_ctx_from_dict_parameters(self):
        self.assertEqual(
            OllamaManager._model_info_num_ctx({"parameters": {"num_ctx": 8192}}),
            8192,
        )

    def test_num_ctx_from_string_parameters_modelfile(self):
        self.assertEqual(
            OllamaManager._model_info_num_ctx(
                {"parameters": "num_ctx 8192\nstop [INST]"}
            ),
            8192,
        )

    def test_num_ctx_from_string_with_extra_whitespace(self):
        self.assertEqual(
            OllamaManager._model_info_num_ctx(
                {"parameters": "  num_ctx    4096  "}
            ),
            4096,
        )

    def test_num_ctx_returns_none_when_missing(self):
        self.assertIsNone(OllamaManager._model_info_num_ctx({"parameters": {}}))
        self.assertIsNone(OllamaManager._model_info_num_ctx({}))

    def test_none_parameters_returns_none_for_num_ctx_only(self):
        class MI:
            parameters = None

        self.assertIsNone(OllamaManager._model_info_num_ctx(MI()))

    def test_modelinfo_context_length_reads_gguf_keys(self):
        mi = {"nomic-bert.context_length": 2048, "other.context_length": 4096}
        self.assertEqual(OllamaManager._modelinfo_context_length_tokens(mi), 4096)

    def test_effective_prefers_parameters_over_modelinfo(self):
        info = {
            "parameters": {"num_ctx": 8192},
            "modelinfo": {"x.context_length": 2048},
        }
        n, src = OllamaManager._model_info_effective_context_tokens(info)
        self.assertEqual(n, 8192)
        self.assertEqual(src, "parameters")

    def test_effective_falls_back_to_modelinfo(self):
        info = {"modelinfo": {"qwen3.context_length": 40960}}
        n, src = OllamaManager._model_info_effective_context_tokens(info)
        self.assertEqual(n, 40960)
        self.assertEqual(src, "modelinfo")

    def test_effective_accepts_model_info_alias_key(self):
        info = {"model_info": {"foo.context_length": 8000}}
        n, src = OllamaManager._model_info_effective_context_tokens(info)
        self.assertEqual(n, 8000)
        self.assertEqual(src, "modelinfo")

    def test_detect_optimal_chunk_size_uses_num_ctx(self):
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        mgr._get_model_info = MagicMock(
            return_value={"parameters": {"num_ctx": 1000}}
        )
        self.assertEqual(mgr._detect_optimal_chunk_size("embed"), int(1000 * 0.9))

    def test_detect_optimal_chunk_size_uses_modelinfo_without_parameters(self):
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        mgr._get_model_info = MagicMock(
            return_value={"modelinfo": {"embed.context_length": 10000}}
        )
        self.assertEqual(mgr._detect_optimal_chunk_size("embed"), int(10000 * 0.9))


class TestModelAvailabilityNormalization(unittest.TestCase):
    def test_is_model_present_locally_matches_latest_alias(self):
        self.assertTrue(
            OllamaManager._is_model_present_locally(
                "nomic-embed-text",
                ["nomic-embed-text:latest", "qwen3:8b"],
            )
        )

    def test_is_model_present_locally_matches_reverse_latest_alias(self):
        self.assertTrue(
            OllamaManager._is_model_present_locally(
                "nomic-embed-text:latest",
                ["nomic-embed-text"],
            )
        )

    def test_is_model_present_locally_keeps_non_latest_tags_distinct(self):
        self.assertFalse(
            OllamaManager._is_model_present_locally(
                "qwen3-embedding:4b",
                ["qwen3-embedding:8b", "qwen3-embedding:latest"],
            )
        )

    def test_ensure_model_available_does_not_pull_when_alias_matches(self):
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        mgr.get_client = MagicMock(return_value=MagicMock())
        mgr._get_models = MagicMock(return_value=["nomic-embed-text:latest"])

        result = mgr.ensure_model_available("nomic-embed-text")

        self.assertTrue(result)
        mgr.get_client.return_value.pull.assert_not_called()


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


class TestEffectiveContextSource(unittest.TestCase):
    """``ps()`` must win over Modelfile and GGUF sources for runtime num_ctx."""

    def _manager_with_fake_client(self, ps_response):
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        fake_client = MagicMock()
        fake_client.ps.return_value = ps_response
        mgr.get_client = MagicMock(return_value=fake_client)
        return mgr

    def test_ps_response_takes_priority_over_modelinfo(self):
        ps_response = {
            "models": [
                {"name": "other-model:latest", "context_length": 4096},
                {
                    "name": "bugtraceai-apex-q4:latest",
                    "model": "bugtraceai-apex-q4:latest",
                    "context_length": 64000,
                },
            ]
        }
        mgr = self._manager_with_fake_client(ps_response)
        mgr._get_model_info = MagicMock(
            return_value={"modelinfo": {"gemma4.context_length": 262144}}
        )
        tokens, source = mgr.get_effective_context_token_count_with_source(
            "bugtraceai-apex-q4:latest"
        )
        self.assertEqual(tokens, 64000)
        self.assertEqual(source, "ps")

    def test_ps_matches_tagless_model_alias(self):
        ps_response = {
            "models": [
                {"name": "bugtraceai-apex-q4:latest", "context_length": 64000}
            ]
        }
        mgr = self._manager_with_fake_client(ps_response)
        tokens = mgr.get_running_num_ctx("bugtraceai-apex-q4")
        self.assertEqual(tokens, 64000)

    def test_falls_back_to_modelinfo_when_model_not_loaded(self):
        mgr = self._manager_with_fake_client({"models": []})
        mgr._get_model_info = MagicMock(
            return_value={"modelinfo": {"gemma4.context_length": 262144}}
        )
        tokens, source = mgr.get_effective_context_token_count_with_source("cold-model")
        self.assertEqual(tokens, 262144)
        self.assertEqual(source, "modelinfo")

    def test_ps_cache_avoids_second_client_call(self):
        ps_response = {
            "models": [{"name": "a:latest", "context_length": 32000}]
        }
        mgr = self._manager_with_fake_client(ps_response)
        mgr.get_running_num_ctx("a:latest")
        mgr.get_running_num_ctx("a:latest")
        fake_client = mgr.get_client.return_value
        self.assertEqual(fake_client.ps.call_count, 1)

    def test_model_field_preferred_over_name_alias(self):
        """When ``name`` and ``model`` differ (alias to a distinct canonical tag),
        a lookup by the canonical ``model`` must win over any aliased ``name``
        mapping to a different ctx value."""
        ps_response = {
            "models": [
                {"name": "myalias", "model": "llama3:70b", "context_length": 64000},
                {"name": "sibling:latest", "model": "sibling:latest", "context_length": 8000},
            ]
        }
        mgr = self._manager_with_fake_client(ps_response)
        self.assertEqual(mgr.get_running_num_ctx("llama3:70b"), 64000)
        self.assertEqual(mgr.get_running_num_ctx("myalias"), 64000)
        self.assertEqual(mgr.get_running_num_ctx("sibling"), 8000)

    def test_ps_lookup_miss_emits_debug_log(self):
        """Lookup that misses both the tag and the :latest alias is logged so
        operators can investigate context-window resolution issues."""
        ps_response = {"models": [{"name": "a:latest", "context_length": 32000}]}
        mgr = self._manager_with_fake_client(ps_response)
        with self.assertLogs("oasis", level="DEBUG") as captured:
            result = mgr.get_running_num_ctx("unknown-model")
        self.assertIsNone(result)
        self.assertTrue(
            any("cache miss for 'unknown-model'" in line for line in captured.output),
            captured.output,
        )

    def test_invalidate_ps_cache_forces_refresh(self):
        """Calling ``invalidate_ps_cache()`` must force the next lookup to
        re-query ``client.ps()`` instead of waiting for the TTL."""
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        fake_client = MagicMock()
        fake_client.ps.side_effect = [
            {"models": [{"name": "a:latest", "context_length": 32000}]},
            {"models": [{"name": "a:latest", "context_length": 65000}]},
        ]
        mgr.get_client = MagicMock(return_value=fake_client)
        self.assertEqual(mgr.get_running_num_ctx("a:latest"), 32000)
        mgr.invalidate_ps_cache()
        self.assertEqual(mgr.get_running_num_ctx("a:latest"), 65000)
        self.assertEqual(fake_client.ps.call_count, 2)

    def test_invalidate_ps_cache_targets_single_model(self):
        """Per-model invalidation drops the targeted entry *and* resets the
        TTL so the next lookup refreshes the whole snapshot — the event that
        triggered the invalidation (pull/unload) likely affected neighbours
        too, so unrelated cached entries should not be trusted until a
        re-query confirms them."""
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        fake_client = MagicMock()
        fake_client.ps.side_effect = [
            {
                "models": [
                    {"name": "a:latest", "context_length": 32000},
                    {"name": "b:latest", "context_length": 8000},
                ]
            },
            {
                "models": [
                    {"name": "b:latest", "context_length": 16000},
                ]
            },
        ]
        mgr.get_client = MagicMock(return_value=fake_client)
        mgr.get_running_num_ctx("a:latest")
        self.assertEqual(mgr.get_running_num_ctx("b:latest"), 8000)
        mgr.invalidate_ps_cache("a")
        with mgr._ps_cache_lock:
            self.assertNotIn("a:latest", mgr._ps_cache_by_name)
            # Targeted entry gone; the TTL reset forces a full re-query next.
            self.assertEqual(mgr._ps_cache_expires_at, 0.0)
        self.assertEqual(mgr.get_running_num_ctx("b:latest"), 16000)
        self.assertEqual(fake_client.ps.call_count, 2)

    def test_invalidate_ps_cache_uses_same_tag_normalization_as_lookups(self):
        """Invalidation by short name or case must still drop ``name:latest`` cache rows."""
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        fake_client = MagicMock()
        fake_client.ps.return_value = {
            "models": [
                {"name": "a:latest", "context_length": 32000},
                {"name": "b:latest", "context_length": 8000},
            ]
        }
        mgr.get_client = MagicMock(return_value=fake_client)
        mgr.get_running_num_ctx("a:latest")
        mgr.get_running_num_ctx("b:latest")
        mgr.invalidate_ps_cache("A")
        with mgr._ps_cache_lock:
            self.assertNotIn("a:latest", mgr._ps_cache_by_name)
            self.assertIn("b:latest", mgr._ps_cache_by_name)
            self.assertEqual(mgr._ps_cache_expires_at, 0.0)

    def test_clear_model_cache_also_invalidates_ps_cache(self):
        """The model-info cache purge must cascade to the ps() cache so a
        post-pull lookup observes the freshly loaded context length."""
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        fake_client = MagicMock()
        fake_client.ps.return_value = {
            "models": [{"name": "a:latest", "context_length": 32000}]
        }
        mgr.get_client = MagicMock(return_value=fake_client)
        mgr.get_running_num_ctx("a:latest")
        mgr.clear_model_cache()
        with mgr._ps_cache_lock:
            self.assertEqual(mgr._ps_cache_by_model, {})
            self.assertEqual(mgr._ps_cache_by_name, {})
            self.assertEqual(mgr._ps_cache_expires_at, 0.0)

    def test_ps_failure_does_not_break_fallback(self):
        """Transport-style failures (SDK / httpx) are treated as a cold ps() cache."""
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        fake_client = MagicMock()
        # Must be a recognised transient (not bare Exception); see _refresh_ps_cache.
        fake_client.ps.side_effect = RequestError("transport")
        mgr.get_client = MagicMock(return_value=fake_client)
        mgr._get_model_info = MagicMock(
            return_value={"parameters": {"num_ctx": 8192}}
        )
        with self.assertLogs("oasis", level="WARNING") as captured:
            tokens, source = mgr.get_effective_context_token_count_with_source("any")
        self.assertEqual(tokens, 8192)
        self.assertEqual(source, "parameters")
        self.assertTrue(
            any(
                "Failed to refresh Ollama ps() cache" in line
                for line in captured.output
            ),
            captured.output,
        )

    def test_ps_httpx_connect_error_treated_as_transient(self):
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        fake_client = MagicMock()
        fake_client.ps.side_effect = httpx.ConnectError("refused", request=MagicMock())
        mgr.get_client = MagicMock(return_value=fake_client)
        mgr._get_model_info = MagicMock(
            return_value={"parameters": {"num_ctx": 4096}}
        )
        with self.assertLogs("oasis", level="WARNING"):
            tokens, source = mgr.get_effective_context_token_count_with_source("m")
        self.assertEqual(tokens, 4096)
        self.assertEqual(source, "parameters")

    def test_ps_unexpected_error_from_client_ps_propagates(self):
        """Non-transient errors from ``ps()`` are logged and re-raised (not hidden)."""
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        fake_client = MagicMock()
        fake_client.ps.side_effect = TypeError("programmer bug")
        mgr.get_client = MagicMock(return_value=fake_client)
        with self.assertLogs("oasis", level="ERROR") as captured:
            with self.assertRaisesRegex(TypeError, "programmer bug"):
                mgr.get_running_num_ctx("m")
        self.assertTrue(
            any(
                "Unexpected exception from Ollama client.ps()" in line
                for line in captured.output
            ),
            captured.output,
        )

    def test_unexpected_ps_path_error_is_not_silently_masked(self):
        """Programming regressions in ps() resolution must propagate."""
        mgr = OllamaManager(api_url="http://127.0.0.1:11434")
        mgr.get_running_num_ctx = MagicMock(side_effect=ValueError("bad-state"))
        with self.assertRaisesRegex(ValueError, "bad-state"):
            mgr.get_effective_context_token_count_with_source("any")


if __name__ == "__main__":
    unittest.main()
