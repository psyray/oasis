"""OpenAI-compatible backend for OASIS (vLLM, LM Studio, llama.cpp, LocalAI, ...).

Implements the :class:`oasis.backends.base.ModelBackend` contract against any
server exposing the OpenAI REST surface (``/v1/models``, ``/v1/chat/completions``,
``/v1/embeddings``):

- :class:`OpenAICompatClient` is an httpx adapter that mirrors the ollama client
  shapes OASIS relies on (``chat`` / ``chat_stream`` / ``generate`` /
  ``embeddings(model=, prompt=)`` / ``list()``), so shared call sites keep
  working unchanged.
- :class:`OpenAICompatManager` adds OASIS-level behavior: model availability
  checks (no pull — the server owns its models), context-token resolution from
  ``OASIS_OPENAI_CTX_TOKENS``, and structured-output negotiation
  (``response_format`` JSON schema with a schema-in-prompt fallback for servers
  that reject it).

Options translation (Ollama-style ``options`` dict → OpenAI payload):
``num_predict`` → ``max_tokens``, ``temperature``/``top_p``/``top_k``/``stop``/
``seed``/``presence_penalty``/``frequency_penalty`` are forwarded verbatim,
``timeout`` (ms) becomes the per-request httpx timeout (seconds), and unsupported
keys (``num_ctx``, ``repeat_penalty``, ...) are dropped with a debug log.
The Ollama ``think`` flag maps to vLLM-style ``chat_template_kwargs
.enable_thinking`` (reasoning models), gated by ``OASIS_OPENAI_THINKING_KWARGS``
with the same auto/on/off negotiation as structured outputs.
"""

import json
import threading
from typing import Any, Dict, Iterator, List, Optional, Tuple

import httpx

from .base import ModelBackend
from .. import config
from ..config import (
    OPENAI_COMPAT_API_KEY,
    OPENAI_COMPAT_BASE_URL,
    OPENAI_HTTP_CLIENT_TIMEOUT_SEC,
)
from ..tools import logger


# Ollama-style option names forwarded to OpenAI-compatible payloads (identity map).
_OPENAI_IDENTITY_OPTIONS = (
    "temperature",
    "top_p",
    "top_k",
    "stop",
    "seed",
    "presence_penalty",
    "frequency_penalty",
)

# HTTP status codes treated as "structured output not supported here" in auto mode.
_STRUCTURED_UNSUPPORTED_STATUS = (400, 404, 422)

_SCHEMA_PROMPT_HINT = (
    "\n\nRespond with a single JSON object matching this JSON Schema "
    "(no markdown code fences around the JSON):\n{schema}"
)


class OpenAICompatClient:
    """
    httpx adapter exposing Ollama-shaped methods against an OpenAI-compatible server.

    The class intentionally mirrors the small ollama client surface used by
    OASIS so duck-typed call sites (embedding helpers, RAG, parallel workers)
    work with either backend without branching.
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: Optional[float] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        self.base_url: str = str(base_url or OPENAI_COMPAT_BASE_URL).strip().rstrip("/")
        # Local servers commonly ignore auth; a dummy bearer keeps strict ones happy.
        self.api_key: str = str(api_key or OPENAI_COMPAT_API_KEY)
        self._default_timeout: Optional[float] = float(timeout) if timeout else None
        self._transport: Optional[httpx.BaseTransport] = transport
        self._http_client: Optional[httpx.Client] = None
        self._http_lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Low-level HTTP helpers
    # ------------------------------------------------------------------

    def _http(self) -> httpx.Client:
        with self._http_lock:
            if self._http_client is None:
                headers = {"Authorization": f"Bearer {self.api_key}"}
                self._http_client = httpx.Client(
                    base_url=self.base_url,
                    headers=headers,
                    timeout=self._default_timeout,
                    transport=self._transport,
                )
        return self._http_client

    def _get_json(self, path: str) -> Any:
        try:
            response = self._http().get(path)
        except httpx.HTTPError as error:
            raise RuntimeError(
                f"OpenAI-compatible request failed for {path}: {type(error).__name__}: {error}"
            ) from error
        if response.status_code >= 400:
            raise RuntimeError(
                f"OpenAI-compatible server returned {response.status_code} for {path}: "
                + response.text[:500]
            )
        return response.json()

    def _post_json(self, path: str, payload: Dict[str, Any], timeout: Optional[float] = None) -> Any:
        try:
            response = self._http().post(path, json=payload, timeout=timeout)
        except httpx.HTTPError as error:
            raise RuntimeError(
                f"OpenAI-compatible request failed for {path}: {type(error).__name__}: {error}"
            ) from error
        if response.status_code >= 400:
            raise RuntimeError(
                f"OpenAI-compatible server returned {response.status_code} for {path}: "
                + response.text[:500]
            )
        return response.json()

    # ------------------------------------------------------------------
    # Ollama-shaped surface
    # ------------------------------------------------------------------

    def list(self) -> Dict[str, Any]:
        """``GET /models`` normalized to the ollama ``list()`` shape (``{"models": [...]}``)."""
        data = self._get_json("/models")
        entries: List[Dict[str, str]] = []
        rows = data.get("data", []) if isinstance(data, dict) else []
        for row in rows:
            model_id = row.get("id") if isinstance(row, dict) else None
            if isinstance(model_id, str) and model_id.strip():
                entries.append({"model": model_id.strip(), "name": model_id.strip()})
        return {"models": entries}

    def embeddings(self, model: str, prompt: str) -> Dict[str, Any]:
        """``POST /embeddings`` normalized to the ollama shape (``{"embedding": [...]}``)."""
        data = self._post_json("/embeddings", {"model": model, "input": [prompt]})
        rows = data.get("data") if isinstance(data, dict) else None
        if not rows or not isinstance(rows[0], dict):
            raise RuntimeError("OpenAI-compatible embeddings response missing data[0]")
        embedding = rows[0].get("embedding")
        if not isinstance(embedding, list):
            raise RuntimeError("OpenAI-compatible embeddings response missing 'embedding' vector")
        return {"embedding": embedding}

    def chat(self, model: str, messages: List[dict], options: Optional[dict] = None, **kwargs: Any):
        """
        ``POST /chat/completions`` returning the ollama shape ``{"message": {"content": ...}}``.

        Accepts Ollama-style kwargs for drop-in compatibility: ``format`` (JSON
        schema for structured outputs), ``stream`` (SSE generator), ``think``
        (translated to vLLM-style ``chat_template_kwargs.enable_thinking`` when
        ``OASIS_OPENAI_THINKING_KWARGS`` allows it).
        """
        stream = bool(kwargs.pop("stream", False))
        schema = kwargs.pop("format", None)
        think = kwargs.pop("think", None)
        if kwargs:
            logger.debug(
                "Ignoring unsupported chat kwargs for OpenAI-compatible backend: %s",
                ", ".join(sorted(kwargs)),
            )

        payload, timeout = self._build_chat_payload(model, messages, options)
        if think is not None and config.OPENAI_THINKING_KWARGS != "off":
            # vLLM-style thinking control for reasoning models: the chat-template
            # variable is simply unused by templates that don't declare it.
            payload["chat_template_kwargs"] = {"enable_thinking": bool(think)}
        elif think is not None:
            logger.debug(
                "Ignoring 'think' option for OpenAI-compatible backend (OASIS_OPENAI_THINKING_KWARGS=off)"
            )
        structured_enabled = isinstance(schema, dict) and bool(schema) and config.OPENAI_STRUCTURED_OUTPUT != "off"
        if structured_enabled:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "oasis_structured_output",
                    "schema": schema,
                },
            }

        if stream:
            return self._stream_chat(payload, timeout)

        try:
            data = self._post_json("/chat/completions", payload, timeout=timeout)
        except RuntimeError as error:
            # Compat retries after HTTP 4xx, least destructive first: strip the
            # vendor-only thinking kwargs (keeps response_format), then fall back
            # to schema-in-prompt for servers that reject structured outputs.
            data = None
            last_error: Optional[Exception] = error
            for retry_payload in self._compat_retry_payloads(payload, schema, error):
                try:
                    data = self._post_json("/chat/completions", retry_payload, timeout=timeout)
                    break
                except RuntimeError as retry_error:
                    last_error = retry_error
            if data is None:
                raise last_error
        return self._normalize_chat_response(data)

    def generate(self, model: str, prompt: str, options: Optional[dict] = None, **kwargs: Any):
        """Convenience wrapper: one-shot generation via chat, ollama-shaped ``{"response": ...}``."""
        response = self.chat(model, [{"role": "user", "content": prompt}], options=options, **kwargs)
        content = ""
        message = response.get("message") if isinstance(response, dict) else None
        if isinstance(message, dict):
            content = message.get("content") or ""
        return {"response": content}

    # ------------------------------------------------------------------
    # Payload building / response normalization
    # ------------------------------------------------------------------

    def _thinking_kwargs_fallback_payload(
        self,
        payload: Dict[str, Any],
        error: Exception,
    ) -> Optional[Dict[str, Any]]:
        """Build a retry payload without ``chat_template_kwargs`` when the server rejects it (auto mode + HTTP 4xx only).

        Returns ``None`` when the fallback does not apply so other retries (or the
        original error) take over.
        """
        if "chat_template_kwargs" not in payload or config.OPENAI_THINKING_KWARGS != "auto":
            return None
        message = str(error)
        if not any(f"returned {status}" in message for status in _STRUCTURED_UNSUPPORTED_STATUS):
            return None
        logger.warning(
            "OpenAI-compatible server rejected chat_template_kwargs; retrying once "
            "without thinking control"
        )
        retry_payload = dict(payload)
        retry_payload.pop("chat_template_kwargs", None)
        return retry_payload

    def _compat_retry_payloads(
        self,
        payload: Dict[str, Any],
        schema: Any,
        error: Exception,
    ) -> List[Dict[str, Any]]:
        """Compat retry payloads after an HTTP 4xx, least destructive first.

        1. ``chat_template_kwargs`` stripped (vendor-only field) — servers that
           reject unknown body fields but support ``response_format`` still work.
        2. Structured output replaced by a schema-in-prompt hint (existing
           structured-output negotiation).
        """
        candidates = (
            self._thinking_kwargs_fallback_payload(payload, error),
            self._schema_in_prompt_fallback_payload(payload, schema, error),
        )
        return [candidate for candidate in candidates if candidate is not None]

    def _schema_in_prompt_fallback_payload(
        self,
        payload: Dict[str, Any],
        schema: Any,
        error: Exception,
    ) -> Optional[Dict[str, Any]]:
        """Build a retry payload without structured enforcement when the server rejects ``response_format`` (auto mode + HTTP 4xx only).

        Returns ``None`` when the fallback does not apply so the original error propagates.
        When thinking kwargs negotiation is in auto mode, the vendor-only
        ``chat_template_kwargs`` field is stripped too, so this retry is the
        maximally-compatible payload (no extension fields at all).
        """
        if "response_format" not in payload or schema is None:
            return None
        if config.OPENAI_STRUCTURED_OUTPUT != "auto":
            return None
        message = str(error)
        if not any(f"returned {status}" in message for status in _STRUCTURED_UNSUPPORTED_STATUS):
            return None
        logger.warning(
            "OpenAI-compatible server rejected response_format; retrying once with "
            "the JSON schema appended to the prompt"
        )
        retry_payload = dict(payload)
        retry_payload.pop("response_format", None)
        if config.OPENAI_THINKING_KWARGS == "auto":
            retry_payload.pop("chat_template_kwargs", None)
        messages = [dict(m) if isinstance(m, dict) else m for m in payload.get("messages", [])]
        if messages and isinstance(messages[-1], dict):
            hint = _SCHEMA_PROMPT_HINT.format(schema=json.dumps(schema, indent=2))
            messages[-1] = {**messages[-1], "content": f"{messages[-1].get('content', '')}{hint}"}
        retry_payload["messages"] = messages
        return retry_payload

    def _build_chat_payload(
        self,
        model: str,
        messages: List[dict],
        options: Optional[dict],
    ) -> tuple:
        payload: Dict[str, Any] = {"model": model, "messages": messages}
        timeout: Optional[float] = None
        dropped: List[str] = []
        if isinstance(options, dict):
            for key, value in options.items():
                if key == "timeout":
                    with_timeout = self._timeout_seconds(value)
                    if with_timeout is not None:
                        timeout = with_timeout
                elif key in _OPENAI_IDENTITY_OPTIONS and value is not None:
                    payload[key] = value
                elif key == "num_predict":
                    payload["max_tokens"] = value
                else:
                    dropped.append(key)
        if dropped:
            logger.debug(
                "Dropping Ollama-style chat options unsupported by OpenAI-compatible servers: %s",
                ", ".join(sorted(dropped)),
            )
        return payload, timeout

    @staticmethod
    def _timeout_seconds(raw: Any) -> Optional[float]:
        """Ollama ``timeout`` option is milliseconds; httpx wants seconds."""
        try:
            seconds = float(raw) / 1000.0
        except (TypeError, ValueError):
            return None
        return max(seconds, 1.0)

    @staticmethod
    def _normalize_chat_response(data: Any) -> Dict[str, Any]:
        choices = data.get("choices") if isinstance(data, dict) else None
        content = ""
        thinking = ""
        if choices and isinstance(choices[0], dict):
            message = choices[0].get("message")
            if isinstance(message, dict):
                raw = message.get("content")
                if isinstance(raw, str):
                    content = raw
                # Reasoning models (vLLM reasoning parsers) return thinking in a
                # separate ``reasoning_content`` field even for non-streaming
                # calls; map it to the ollama native ``thinking`` channel so
                # callers can capture reasoning the same way as streaming.
                reasoning = message.get("reasoning_content")
                if isinstance(reasoning, str) and reasoning:
                    thinking = reasoning
        if thinking:
            return {"message": {"content": content, "thinking": thinking}}
        return {"message": {"content": content}}

    @staticmethod
    def _normalize_stream_chunk(data: Any) -> Optional[Dict[str, Any]]:
        choices = data.get("choices") if isinstance(data, dict) else None
        if not choices or not isinstance(choices[0], dict):
            return None
        delta = choices[0].get("delta")
        if not isinstance(delta, dict):
            return None
        content = delta.get("content")
        if isinstance(content, str) and content:
            return {"message": {"content": content}}
        # Reasoning models (vLLM reasoning parsers) stream thinking in a
        # separate ``reasoning_content`` field; map it to the ollama native
        # ``thinking`` channel so callers can render it separately.
        thinking = delta.get("reasoning_content")
        if isinstance(thinking, str) and thinking:
            return {"message": {"thinking": thinking}}
        return None

    # ------------------------------------------------------------------
    # Streaming (SSE)
    # ------------------------------------------------------------------

    def _stream_chat(self, payload: Dict[str, Any], timeout: Optional[float] = None) -> Iterator[Dict[str, Any]]:
        """
        Yield ollama-shaped chunks ``{"message": {"content": ...}}`` from an SSE stream.

        ``stream: true`` is set here (not by the caller) so the server actually
        answers with an SSE body; reasoning deltas (``reasoning_content``) are
        normalized to the ollama ``thinking`` channel so callers can surface them.
        Transport and HTTP errors propagate; :meth:`ModelBackend.chat_stream`
        converts them into ``{"type": "error", ...}`` chunks for callers.
        """
        http = self._http()
        stream_payload = {**payload, "stream": True}
        with http.stream("POST", "/chat/completions", json=stream_payload, timeout=timeout) as response:
            if response.status_code >= 400:
                body = response.read().decode(errors="replace")[:500]
                raise RuntimeError(
                    f"OpenAI-compatible server returned {response.status_code} for /chat/completions: {body}"
                )
            for line in response.iter_lines():
                if not line.startswith("data:"):
                    continue
                data = line[len("data:"):].strip()
                if data == "[DONE]":
                    break
                try:
                    obj = json.loads(data)
                except json.JSONDecodeError:
                    logger.debug("Skipping non-JSON SSE line from OpenAI-compatible stream")
                    continue
                chunk = self._normalize_stream_chunk(obj)
                if chunk is not None:
                    yield chunk


class OpenAICompatManager(ModelBackend):
    """
    Model backend for OpenAI-compatible local servers (vLLM, LM Studio,
    llama.cpp server, LocalAI, LiteLLM, ...).

    Args:
        api_base: Base URL including the OpenAI prefix path
            (e.g. ``https://llm.example.com/v1``).
        api_key: Bearer token; most local servers accept any value.
        transport: Optional httpx transport (tests).
    """

    provider: str = "openai"

    def __init__(
        self,
        api_base: Optional[str] = None,
        api_key: Optional[str] = None,
        excluded_models: Optional[List[str]] = None,
        default_models: Optional[List[str]] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        super().__init__(excluded_models=excluded_models, default_models=default_models)
        self.api_base: str = str(api_base or OPENAI_COMPAT_BASE_URL).strip().rstrip("/")
        # ``api_url`` alias keeps worker-namespace builders generic across backends.
        self.api_url: str = self.api_base
        self.api_key: str = str(api_key or OPENAI_COMPAT_API_KEY)
        self._transport: Optional[httpx.BaseTransport] = transport

    def get_client(self) -> OpenAICompatClient:
        """
        Get the OpenAI-compatible client instance, checking connection first.

        Returns:
            OpenAICompatClient: Connected client

        Raises:
            ConnectionError: If the server is not accessible
        """
        with self._client_lock:
            if not self.client:
                client = OpenAICompatClient(
                    self.api_base,
                    api_key=self.api_key,
                    timeout=float(OPENAI_HTTP_CLIENT_TIMEOUT_SEC),
                    transport=self._transport,
                )
                try:
                    client.list()
                except Exception as e:
                    logger.error(
                        "Cannot connect to OpenAI-compatible server at %s: %s: %s",
                        self.api_base,
                        type(e).__name__,
                        str(e)[:300],
                    )
                    raise ConnectionError(
                        f"Cannot connect to OpenAI-compatible server at {self.api_base}: {e}"
                    ) from e
                self.client = client
        return self.client

    def ensure_model_available(self, model: str) -> bool:
        """
        Ensure a model is served by the OpenAI-compatible server.

        These servers own their model registry (no pull possible): the check is
        an exact/case-insensitive id match against ``/v1/models``, and failures
        list the available ids to ease configuration fixes.

        Args:
            model: Model id to check
        Returns:
            True if the model is served, False otherwise
        """
        try:
            available_models = self._get_models([])
            if self._is_model_present_locally(model, available_models):
                logger.debug(f"Model {model} is already served")
                return True
            logger.error(
                "Model %r is not served by the OpenAI-compatible server at %s. "
                "Available models: %s",
                model,
                self.api_base,
                ", ".join(sorted(available_models)) or "<none>",
            )
            return False
        except Exception as e:
            logger.exception(f"Error checking model availability: {str(e)}")
            return False

    def get_effective_context_token_count_with_source(
        self, model: str
    ) -> Tuple[Optional[int], str]:
        """
        Context length in tokens from ``OASIS_OPENAI_CTX_TOKENS`` (source ``"env"``).

        The OpenAI protocol does not expose per-model context windows, so the
        value is deployment configuration; unset means "unknown". Read at call
        time so runtime configuration changes are honored.
        """
        tokens = int(getattr(config, "OPENAI_CTX_TOKENS", 0) or 0)
        if tokens > 0:
            return tokens, "env"
        return None, ""


__all__ = ["OpenAICompatClient", "OpenAICompatManager"]