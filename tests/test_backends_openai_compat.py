"""Tests for the OpenAI-compatible backend and the model-backend factory."""

import json
import os
import unittest
from unittest.mock import MagicMock, patch

import httpx

from oasis import config
from oasis.backends import create_model_manager, resolve_provider_choice
from oasis.backends.ollama_backend import OllamaManager
from oasis.backends.openai_compat import OpenAICompatClient, OpenAICompatManager


def _json_route(handler):
    """Build an httpx.MockTransport from a (request) -> (status, payload) handler."""
    def transport_handler(request: httpx.Request) -> httpx.Response:
        status, payload = handler(request)
        return httpx.Response(status, json=payload, request=request)

    return httpx.MockTransport(transport_handler)


def _resp(status: int, payload, request: httpx.Request) -> httpx.Response:
    return httpx.Response(status, json=payload, request=request)


def _client_with_routes(chat_handler=None, models_payload=None, embeddings_handler=None):
    models_payload = models_payload if models_payload is not None else {
        "data": [
            {"id": "Qwen/Qwen2.5-Coder-32B-Instruct"},
            {"id": "nomic-embed-text"},
        ]
    }

    def default_chat_handler(request):
        body = json.loads(request.content.decode("utf-8"))
        return 200, {"choices": [{"message": {"content": "ok:" + body["model"]}}]}

    def default_embeddings_handler(request):
        return 200, {"data": [{"embedding": [0.1, 0.2, 0.3]}]}

    def route(request: httpx.Request):
        path = request.url.path
        if path.endswith("/models"):
            return _resp(200, models_payload, request)
        if path.endswith("/chat/completions"):
            status, payload = chat_handler(request) if chat_handler else default_chat_handler(request)
            return _resp(status, payload, request)
        if path.endswith("/embeddings"):
            status, payload = (
                embeddings_handler(request) if embeddings_handler
                else default_embeddings_handler(request)
            )
            return _resp(status, payload, request)
        raise AssertionError(f"Unexpected path {path}")

    return OpenAICompatClient("http://llm.test/v1", transport=httpx.MockTransport(route))


class TestProviderResolution(unittest.TestCase):
    def test_resolve_provider_choice_aliases(self):
        self.assertIsNone(resolve_provider_choice(None))
        self.assertIsNone(resolve_provider_choice(""))
        self.assertEqual(resolve_provider_choice("ollama"), "ollama")
        self.assertEqual(resolve_provider_choice("OpenAI"), "openai")
        self.assertEqual(resolve_provider_choice("vllm"), "openai")
        with self.assertRaises(ValueError):
            resolve_provider_choice("together-ai")

    def test_factory_defaults_to_ollama(self):
        manager = create_model_manager()
        self.assertIsInstance(manager, OllamaManager)

    def test_factory_provider_from_args(self):
        args = type("Args", (), {"provider": "openai", "api_base": "https://llm.example.com/v1"})()
        manager = create_model_manager(args)
        self.assertIsInstance(manager, OpenAICompatManager)
        self.assertEqual(manager.api_base, "https://llm.example.com/v1")

    def test_factory_api_base_implies_openai(self):
        args = type("Args", (), {"api_base": "http://localhost:1234/v1"})()
        manager = create_model_manager(args)
        self.assertIsInstance(manager, OpenAICompatManager)

    def test_factory_env_provider(self):
        with patch.object(config, "LLM_PROVIDER_ENV", "openai"):
            manager = create_model_manager()
        self.assertIsInstance(manager, OpenAICompatManager)

    def test_factory_ollama_url_fallback(self):
        args = type("Args", (), {"ollama_url": "http://127.0.0.1:11434"})()
        manager = create_model_manager(args)
        self.assertIsInstance(manager, OllamaManager)
        self.assertEqual(manager.api_url, "http://127.0.0.1:11434")

    def test_openai_manager_exposes_api_url_alias(self):
        manager = OpenAICompatManager(api_base="https://llm.example.com/v1")
        self.assertEqual(manager.api_url, "https://llm.example.com/v1")
        self.assertEqual(manager.provider, "openai")


class TestOpenAICompatChat(unittest.TestCase):
    def test_chat_normalizes_response_and_translates_options(self):
        captured = {}

        def chat_handler(request):
            captured["payload"] = json.loads(request.content.decode("utf-8"))
            return 200, {"choices": [{"message": {"content": "pong"}}]}

        client = _client_with_routes(chat_handler=chat_handler)
        response = client.chat(
            "qwen2.5-coder",
            [{"role": "user", "content": "ping"}],
            options={"timeout": 2500, "num_predict": 8192, "temperature": 0, "num_ctx": 8192},
        )

        self.assertEqual(response, {"message": {"content": "pong"}})
        self.assertEqual(captured["payload"]["max_tokens"], 8192)
        self.assertEqual(captured["payload"]["temperature"], 0)
        self.assertNotIn("num_ctx", captured["payload"])
        self.assertNotIn("options", captured["payload"])

    def test_chat_sends_response_format_for_json_schema(self):
        captured = {}

        def chat_handler(request):
            captured["payload"] = json.loads(request.content.decode("utf-8"))
            return 200, {"choices": [{"message": {"content": '{"verdict": "SAFE"}'}}]}

        client = _client_with_routes(chat_handler=chat_handler)
        schema = {"type": "object", "properties": {"verdict": {"type": "string"}}}
        client.chat("m", [{"role": "user", "content": "x"}], format=schema)

        response_format = captured["payload"]["response_format"]
        self.assertEqual(response_format["type"], "json_schema")
        self.assertEqual(response_format["json_schema"]["schema"], schema)

    def test_chat_falls_back_to_schema_in_prompt_on_400(self):
        calls = []

        def chat_handler(request):
            body = json.loads(request.content.decode("utf-8"))
            calls.append(body)
            if "response_format" in body:
                return 400, {"error": {"message": "response_format not supported"}}
            return 200, {"choices": [{"message": {"content": '{"verdict": "SAFE"}'}}]}

        client = _client_with_routes(chat_handler=chat_handler)
        schema = {"type": "object", "properties": {"verdict": {"type": "string"}}}
        response = client.chat("m", [{"role": "user", "content": "x"}], format=schema)

        self.assertEqual(len(calls), 2)
        self.assertNotIn("response_format", calls[1])
        self.assertIn("verdict", calls[1]["messages"][-1]["content"])
        self.assertEqual(response["message"]["content"], '{"verdict": "SAFE"}')

    def test_chat_translates_think_to_chat_template_kwargs(self):
        captured = {}

        def chat_handler(request):
            captured["payload"] = json.loads(request.content.decode("utf-8"))
            return 200, {"choices": [{"message": {"content": "pong"}}]}

        client = _client_with_routes(chat_handler=chat_handler)
        client.chat("m", [{"role": "user", "content": "x"}], think=False)
        self.assertEqual(captured["payload"]["chat_template_kwargs"], {"enable_thinking": False})

        client.chat("m", [{"role": "user", "content": "x"}], think=True)
        self.assertEqual(captured["payload"]["chat_template_kwargs"], {"enable_thinking": True})

    def test_chat_maps_reasoning_content_to_thinking_channel(self):
        def chat_handler(request):
            return 200, {
                "choices": [
                    {
                        "message": {
                            "content": "Final answer",
                            "reasoning_content": "thinking hard",
                        }
                    }
                ]
            }

        client = _client_with_routes(chat_handler=chat_handler)
        response = client.chat("m", [{"role": "user", "content": "x"}])
        self.assertEqual(
            response,
            {"message": {"content": "Final answer", "thinking": "thinking hard"}},
        )

    def test_chat_without_reasoning_content_has_no_thinking_key(self):
        def chat_handler(request):
            return 200, {
                "choices": [{"message": {"content": "pong", "reasoning_content": None}}]
            }

        client = _client_with_routes(chat_handler=chat_handler)
        response = client.chat("m", [{"role": "user", "content": "x"}])
        self.assertEqual(response, {"message": {"content": "pong"}})

    def test_chat_without_think_omits_chat_template_kwargs(self):
        captured = {}

        def chat_handler(request):
            captured["payload"] = json.loads(request.content.decode("utf-8"))
            return 200, {"choices": [{"message": {"content": "pong"}}]}

        client = _client_with_routes(chat_handler=chat_handler)
        client.chat("m", [{"role": "user", "content": "x"}])
        self.assertNotIn("chat_template_kwargs", captured["payload"])

    def test_chat_thinking_off_ignores_think(self):
        captured = {}

        def chat_handler(request):
            captured["payload"] = json.loads(request.content.decode("utf-8"))
            return 200, {"choices": [{"message": {"content": "pong"}}]}

        client = _client_with_routes(chat_handler=chat_handler)
        with patch.object(config, "OPENAI_THINKING_KWARGS", "off"):
            client.chat("m", [{"role": "user", "content": "x"}], think=False)

        self.assertNotIn("chat_template_kwargs", captured["payload"])

    def test_chat_strips_chat_template_kwargs_on_400(self):
        calls = []

        def chat_handler(request):
            body = json.loads(request.content.decode("utf-8"))
            calls.append(body)
            if "chat_template_kwargs" in body:
                return 400, {"error": {"message": "unknown field chat_template_kwargs"}}
            return 200, {"choices": [{"message": {"content": "pong"}}]}

        client = _client_with_routes(chat_handler=chat_handler)
        response = client.chat(
            "m", [{"role": "user", "content": "x"}], think=False, format={"type": "object"}
        )

        self.assertEqual(len(calls), 2)
        self.assertNotIn("chat_template_kwargs", calls[1])
        self.assertIn("response_format", calls[1])
        self.assertEqual(response["message"]["content"], "pong")

    def test_chat_compat_retries_strip_fields_in_order(self):
        calls = []

        def chat_handler(request):
            body = json.loads(request.content.decode("utf-8"))
            calls.append(body)
            if "chat_template_kwargs" in body:
                return 400, {"error": {"message": "unknown field chat_template_kwargs"}}
            if "response_format" in body:
                return 400, {"error": {"message": "response_format not supported"}}
            return 200, {"choices": [{"message": {"content": '{"verdict": "SAFE"}'}}]}

        client = _client_with_routes(chat_handler=chat_handler)
        schema = {"type": "object", "properties": {"verdict": {"type": "string"}}}
        response = client.chat(
            "m", [{"role": "user", "content": "x"}], think=False, format=schema
        )

        self.assertEqual(len(calls), 3)
        self.assertNotIn("chat_template_kwargs", calls[1])
        self.assertIn("response_format", calls[1])
        self.assertNotIn("response_format", calls[2])
        self.assertIn("verdict", calls[2]["messages"][-1]["content"])
        self.assertEqual(response["message"]["content"], '{"verdict": "SAFE"}')

    def test_chat_thinking_on_surfaces_server_errors(self):
        calls = []

        def chat_handler(request):
            body = json.loads(request.content.decode("utf-8"))
            calls.append(body)
            return 400, {"error": {"message": "unknown field chat_template_kwargs"}}

        client = _client_with_routes(chat_handler=chat_handler)
        with patch.object(config, "OPENAI_THINKING_KWARGS", "on"), self.assertRaises(RuntimeError):
            client.chat("m", [{"role": "user", "content": "x"}], think=False)

        self.assertEqual(len(calls), 1)

    def test_chat_structured_off_never_sends_response_format(self):
        captured = {}

        def chat_handler(request):
            captured["payload"] = json.loads(request.content.decode("utf-8"))
            return 200, {"choices": [{"message": {"content": "{}"}}]}

        client = _client_with_routes(chat_handler=chat_handler)
        with patch.object(config, "OPENAI_STRUCTURED_OUTPUT", "off"):
            client.chat("m", [{"role": "user", "content": "x"}], format={"type": "object"})

        self.assertNotIn("response_format", captured["payload"])

    def test_generate_returns_ollama_shape(self):
        client = _client_with_routes()
        response = client.generate("m", "prompt text")
        self.assertEqual(response, {"response": "ok:m"})

    def test_stream_yields_normalized_chunks(self):
        sse_lines = [
            b'data: {"choices": [{"delta": {"content": "hel"}}]}',
            b'',
            b'data: {"choices": [{"delta": {"content": "lo"}}]}',
            b'data: [DONE]',
            b'',
        ]

        def stream_handler(request: httpx.Request) -> httpx.Response:
            # Emulate real server behavior: SSE body only when the request asks
            # for streaming; a JSON completion otherwise.
            body = json.loads(request.content.decode("utf-8"))
            if not body.get("stream"):
                return httpx.Response(
                    200, json={"choices": [{"message": {"content": "ok"}}]}, request=request
                )
            return httpx.Response(200, content=b"\n".join(sse_lines), request=request)

        client = OpenAICompatClient(
            "http://llm.test/v1", transport=httpx.MockTransport(stream_handler)
        )
        chunks = list(client.chat("m", [{"role": "user", "content": "x"}], stream=True))
        self.assertEqual(
            chunks,
            [{"message": {"content": "hel"}}, {"message": {"content": "lo"}}],
        )

    def test_stream_maps_reasoning_deltas_to_thinking_channel(self):
        sse_lines = [
            b'data: {"choices": [{"delta": {"reasoning_content": "think"}}]}',
            b'data: {"choices": [{"delta": {"reasoning_content": "ing"}}]}',
            b'data: {"choices": [{"delta": {"content": "answer"}}]}',
            b'data: {"choices": [{"finish_reason": "stop", "delta": {}}]}',
            b'data: [DONE]',
            b'',
        ]

        def stream_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"\n".join(sse_lines), request=request)

        client = OpenAICompatClient(
            "http://llm.test/v1", transport=httpx.MockTransport(stream_handler)
        )
        chunks = list(client.chat("m", [{"role": "user", "content": "x"}], stream=True))
        self.assertEqual(
            chunks,
            [
                {"message": {"thinking": "think"}},
                {"message": {"thinking": "ing"}},
                {"message": {"content": "answer"}},
            ],
        )

    def test_backend_chat_stream_yields_error_chunk_on_http_error(self):
        def error_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={"error": "boom"}, request=request)

        client = OpenAICompatClient("http://llm.test/v1", transport=httpx.MockTransport(error_handler))
        manager = OpenAICompatManager(api_base="http://llm.test/v1")
        manager.client = client
        chunks = list(
            manager.chat_stream("m", [{"role": "user", "content": "x"}])
        )
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].get("type"), "error")


class TestOpenAICompatModels(unittest.TestCase):
    def test_list_returns_ollama_shape(self):
        client = _client_with_routes()
        listing = client.list()
        self.assertEqual(
            [m["model"] for m in listing["models"]],
            ["Qwen/Qwen2.5-Coder-32B-Instruct", "nomic-embed-text"],
        )

    def test_get_available_models_filters_excluded_patterns(self):
        manager = OpenAICompatManager(api_base="http://llm.test/v1")
        manager.client = _client_with_routes()
        models = manager.get_available_models()
        # 'embed' is in the default excluded patterns
        self.assertEqual(models, ["Qwen/Qwen2.5-Coder-32B-Instruct"])

    def test_list_chat_model_names_empty_on_transport_error(self):
        def broken(request):
            raise httpx.ConnectError("down", request=request)

        manager = OpenAICompatManager(api_base="http://llm.test/v1")
        manager.client = OpenAICompatClient(
            "http://llm.test/v1", transport=httpx.MockTransport(broken)
        )
        self.assertEqual(manager.list_chat_model_names(), [])

    def test_ensure_model_available_matches_case_insensitively(self):
        manager = OpenAICompatManager(api_base="http://llm.test/v1")
        manager.client = _client_with_routes()
        self.assertTrue(manager.ensure_model_available("qwen/qwen2.5-coder-32b-instruct"))
        self.assertFalse(manager.ensure_model_available("missing-model"))

    def test_embeddings_returns_ollama_shape(self):
        client = _client_with_routes()
        response = client.embeddings(model="nomic-embed-text", prompt="hello")
        self.assertEqual(response, {"embedding": [0.1, 0.2, 0.3]})

    def test_embeddings_error_includes_server_body_for_context_detection(self):
        def embeddings_handler(request):
            return 400, {"error": {"message": "This model's maximum context length is 512 tokens"}}

        client = _client_with_routes(embeddings_handler=embeddings_handler)
        with self.assertRaises(RuntimeError) as ctx:
            client.embeddings(model="nomic-embed-text", prompt="hello")
        self.assertIn("maximum context length", str(ctx.exception))

    def test_get_client_raises_connection_error_on_unreachable_server(self):
        def broken(request):
            raise httpx.ConnectError("refused", request=request)

        manager = OpenAICompatManager(api_base="http://llm.test/v1")
        manager._transport = httpx.MockTransport(broken)
        with self.assertRaises(ConnectionError):
            manager.get_client()


class TestOpenAICompatContext(unittest.TestCase):
    def test_context_tokens_from_config_env(self):
        manager = OpenAICompatManager(api_base="http://llm.test/v1")
        with patch.object(config, "OPENAI_CTX_TOKENS", 32768):
            tokens, source = manager.get_effective_context_token_count_with_source("m")
        self.assertEqual(tokens, 32768)
        self.assertEqual(source, "env")

    def test_context_tokens_unset_returns_none(self):
        manager = OpenAICompatManager(api_base="http://llm.test/v1")
        tokens, source = manager.get_effective_context_token_count_with_source("m")
        self.assertIsNone(tokens)
        self.assertEqual(source, "")

    def test_detect_optimal_chunk_size_uses_env_context(self):
        manager = OpenAICompatManager(api_base="http://llm.test/v1")
        with patch.object(config, "OPENAI_CTX_TOKENS", 8192):
            self.assertEqual(manager.detect_optimal_chunk_size("m"), int(8192 * 0.9))

    def test_detect_optimal_chunk_size_falls_back_to_max_chunk(self):
        from oasis.config import MAX_CHUNK_SIZE

        manager = OpenAICompatManager(api_base="http://llm.test/v1")
        self.assertEqual(manager.detect_optimal_chunk_size("m"), MAX_CHUNK_SIZE)

    def test_thinking_overrides_are_stored_without_transport_effect(self):
        manager = OpenAICompatManager(api_base="http://llm.test/v1")
        manager.set_model_thinking("m", True)
        self.assertTrue(manager._resolve_model_thinking("m"))

    def test_explicit_think_kwarg_wins_over_model_override(self):
        """A caller forcing thinking for one call must beat the global override."""
        from oasis.backends.base import ModelBackend

        class _StubClient:
            def __init__(self):
                self.calls = []

            def chat(self, **kwargs):
                self.calls.append(kwargs)
                return {"message": {"content": "pong"}}

        class _Backend(ModelBackend):
            def __init__(self, stub):
                super().__init__()
                self._stub = stub

            def get_client(self):
                return self._stub

        stub = _StubClient()
        backend = _Backend(stub)
        backend.set_model_thinking("m", False)
        backend.chat("m", [{"role": "user", "content": "x"}], think=True)
        self.assertIs(stub.calls[0]["think"], True)

        # Without an explicit think kwarg the per-model override still applies.
        backend.chat("m", [{"role": "user", "content": "x"}])
        self.assertIs(stub.calls[1]["think"], False)

    def test_cache_invalidation_hooks_are_safe_noops(self):
        manager = OpenAICompatManager(api_base="http://llm.test/v1")
        manager.clear_model_cache("m")
        manager.invalidate_ps_cache("m")


if __name__ == "__main__":
    unittest.main()