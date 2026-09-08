"""Provider-agnostic model backend contract shared by OASIS LLM backends.

A **backend** wraps one local LLM server family and normalizes it to the
interface OASIS call sites already use:

- :meth:`ModelBackend.chat` / :meth:`chat_stream` / :meth:`generate` return
  Ollama-shaped payloads (``{"message": {"content": ...}}``) so analysis and
  assistant code stay backend-agnostic.
- :meth:`ModelBackend.get_client` returns a raw, duck-typed client exposing
  Ollama-style helpers (``embeddings(model=, prompt=)``, ``list()``, ...).
  The OpenAI-compatible backend ships a small httpx adapter
  (:class:`oasis.backends.openai_compat.OpenAICompatClient`) that mirrors those
  method shapes against ``/v1/chat/completions`` / ``/v1/embeddings``.
- Model listing, interactive selection, thinking overrides, and chunk-size
  detection live here because they only depend on the duck-typed client.

Backends must keep logging free of secrets (API keys are never logged).
"""

import contextlib
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from ..config import (
    DEFAULT_MODELS,
    EXCLUDED_MODELS,
    MAX_CHUNK_SIZE,
    MODEL_EMOJIS,
    OLLAMA_SLOW_CALL_WARNING_SEC,
)
from ..helpers.ollama_timing import (
    estimate_ollama_payload_chars,
    options_timeout_ms,
)
from ..tools import logger


class ModelBackend:
    """
    Base class for OASIS model backends.

    Subclasses provide :meth:`get_client` (duck-typed Ollama-style client) and
    override the hooks that depend on server-specific metadata
    (``show()``/``ps()`` for Ollama, model ids + environment for
    OpenAI-compatible servers).
    """

    #: Short provider identifier (``"ollama"`` / ``"openai"``).
    provider: str = "base"

    def __init__(self, excluded_models: Optional[List[str]] = None, default_models: Optional[List[str]] = None):
        self.client = None
        self.excluded_models = list(EXCLUDED_MODELS if excluded_models is None else excluded_models)
        self.default_models = list(DEFAULT_MODELS if default_models is None else default_models)
        self._client_lock = threading.Lock()
        self._cache_lock = threading.Lock()
        self.formatted_models: List[Any] = []
        self._model_thinking_overrides: Dict[str, bool] = {}

    # ------------------------------------------------------------------
    # Connection / raw client
    # ------------------------------------------------------------------

    def get_client(self) -> Any:
        """
        Return the raw backend client, checking connection first.

        Raises:
            ConnectionError: If the backend server is not accessible.
        """
        raise NotImplementedError("ModelBackend subclasses must implement get_client()")

    def check_connection(self) -> bool:
        """
        Check if the backend server is running and accessible.

        Returns:
            bool: True if connection is successful, False otherwise
        """
        try:
            self.get_client()
            return True
        except ConnectionError:
            return False

    # ------------------------------------------------------------------
    # Per-model thinking overrides (generic state; transport is backend-specific)
    # ------------------------------------------------------------------

    def set_model_thinking(self, model: str, thinking: bool) -> None:
        """
        Set thinking behavior override for a given model.

        Args:
            model: Model name
            thinking: Whether thinking is enabled for this model
        """
        self._model_thinking_overrides[model] = thinking

    def configure_analysis_model_thinking(
        self,
        scan_model: str,
        main_models: List[str],
        scan_model_thinking: bool,
        main_model_thinking: bool
    ) -> None:
        """
        Configure thinking behavior for selected scan and deep analysis models.

        Args:
            scan_model: Model used for quick scanning
            main_models: Models used for deep analysis
            scan_model_thinking: Thinking flag for scan model
            main_model_thinking: Thinking flag for deep models
        """
        if scan_model:
            self.set_model_thinking(scan_model, scan_model_thinking)
        for model in main_models or []:
            self.set_model_thinking(model, main_model_thinking)

    def _resolve_model_thinking(self, model: str) -> Optional[bool]:
        """
        Resolve whether thinking should be sent for a model.

        Args:
            model: Model name

        Returns:
            Thinking override, or None if no override is configured
        """
        return self._model_thinking_overrides.get(model)

    # ------------------------------------------------------------------
    # Chat / generate transport (generic over the duck-typed client)
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_client_response(result: Any) -> Any:
        """
        Convert SDK response objects (e.g. ollama ChatResponse) into plain dicts
        expected by callers. Older SDK versions returned dicts directly.
        """
        if result is None or isinstance(result, dict):
            return result
        model_dump = getattr(result, "model_dump", None)
        if callable(model_dump):
            with contextlib.suppress(Exception):
                return model_dump()
        legacy_dict = getattr(result, "dict", None)
        if callable(legacy_dict):
            with contextlib.suppress(Exception):
                return legacy_dict()
        return result

    def _call_with_thinking(
        self,
        method_name: str,
        model: str,
        payload_key: str,
        payload_value: Any,
        options: Optional[dict] = None,
        **kwargs: Any
    ):
        """
        Execute a backend client call with optional per-model thinking behavior.
        """
        client = self.get_client()
        request_kwargs = {
            "model": model,
            payload_key: payload_value
        }
        if options is not None:
            request_kwargs["options"] = options
        request_kwargs |= kwargs

        # Explicit call-site ``think`` wins; per-model overrides fill the rest
        # (a caller forcing thinking for one call — e.g. validation narratives —
        # must not be silently overridden by the global -mt/-smt config).
        if "think" not in request_kwargs:
            thinking = self._resolve_model_thinking(model)
            if thinking is not None:
                request_kwargs["think"] = thinking

        method = getattr(client, method_name)
        payload_chars = estimate_ollama_payload_chars(payload_key, payload_value)
        timeout_ms_opt = options_timeout_ms(options)
        has_structured_format = bool(kwargs.get("format"))
        t_round = time.monotonic()
        err_type: Optional[str] = None
        try:
            try:
                result = method(**request_kwargs)
            except TypeError as error:
                # Backward compatibility with ollama clients not supporting think=
                error_message = error.args[0] if error.args else ""
                if (
                    "think" not in request_kwargs
                    or "unexpected keyword argument 'think'"
                    not in str(error_message)
                ):
                    raise
                request_kwargs.pop("think", None)
                result = method(**request_kwargs)
            return self._normalize_client_response(result)
        except Exception as exc:
            err_type = type(exc).__name__
            raise
        finally:
            elapsed = time.monotonic() - t_round
            if err_type is None and elapsed >= OLLAMA_SLOW_CALL_WARNING_SEC:
                logger.warning(
                    "Slow LLM backend call %s provider=%s model=%s elapsed=%.1fs payload_chars=%s timeout_ms=%s structured=%s",
                    method_name,
                    self.provider,
                    model,
                    elapsed,
                    payload_chars,
                    timeout_ms_opt,
                    has_structured_format,
                )

    def chat(self, model: str, messages: List[dict], options: Optional[dict] = None, **kwargs):
        """
        Chat completion wrapper with per-model thinking support.
        """
        return self._call_with_thinking(
            method_name="chat",
            model=model,
            payload_key="messages",
            payload_value=messages,
            options=options,
            **kwargs
        )

    def chat_stream(
        self,
        model: str,
        messages: List[dict],
        options: Optional[dict] = None,
        **kwargs: Any,
    ):
        """
        Streaming chat wrapper yielding normalized dict chunks.

        Uses ``client.chat(stream=True, ...)`` under the hood and mirrors
        :meth:`chat` for thinking support. Falls back gracefully on older
        ollama-python clients that do not accept ``think``.
        """
        client = self.get_client()
        request_kwargs: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": True,
        }
        if options is not None:
            request_kwargs["options"] = options
        request_kwargs |= kwargs

        if "think" not in request_kwargs:
            thinking = self._resolve_model_thinking(model)
            if thinking is not None:
                request_kwargs["think"] = thinking

        try:
            iterator = client.chat(**request_kwargs)
        except TypeError as error:
            error_message = error.args[0] if error.args else ""
            if (
                "think" not in request_kwargs
                or "unexpected keyword argument 'think'" not in str(error_message)
            ):
                raise
            request_kwargs.pop("think", None)
            iterator = client.chat(**request_kwargs)

        try:
            for chunk in iterator:
                yield self._normalize_client_response(chunk)
        except Exception as error:
            logger.exception("Error while streaming response from LLM backend")
            yield self._normalize_client_response(
                {
                    "type": "error",
                    "error": (
                        f"Error while streaming response from model: {type(error).__name__}: {error}"
                    ),
                }
            )

    def generate(self, model: str, prompt: str, options: Optional[dict] = None, **kwargs):
        """
        Text generation wrapper with per-model thinking support.
        """
        return self._call_with_thinking(
            method_name="generate",
            model=model,
            payload_key="prompt",
            payload_value=prompt,
            options=options,
            **kwargs
        )

    # ------------------------------------------------------------------
    # Model listing / selection
    # ------------------------------------------------------------------

    def get_available_models(self, show_formatted: bool = False) -> List[str]:
        """
        Get list of available models from the backend server

        Args:
            show_formatted: If True, show formatted model list with progress
        Returns:
            List of model names
        """
        try:
            model_names = self._get_models(self.excluded_models)

            # If requested, display formatted list
            if self.formatted_models:
                return self.formatted_models

            if show_formatted and model_names:
                self.formatted_models = self.format_model_display_batch(model_names)
                logger.info("\nAvailable models:")
                for i, (model_name, formatted_model) in enumerate(zip(model_names, self.formatted_models), 1):
                    # Align model numbers with proper spacing
                    prefix = " " if i < 10 else ""
                    logger.info(f"{prefix}{i}. {formatted_model}")
                    logger.info(f"       Use with --models: '{model_name}' or '{i}'")
            return model_names
        except Exception as e:
            logger.exception(f"Error fetching models: {str(e)}")
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Full error:", exc_info=True)

            logger.warning(f"Using default model list: {', '.join(self.default_models)}")
            return self.default_models

    def _get_models(self, excluded_models: List[str]) -> List[str]:
        """
        Get filtered list of models from the backend client (ollama-shaped ``list()``)

        Args:
            excluded_models: List of patterns to exclude from model names

        Returns:
            List of available model names
        """
        try:
            client = self.get_client()
            models = client.list()
            # Filter out embedding models and sort in natural order
            model_names = [
                model.get('model')
                for model in models.get('models', [])
                if all(
                    pattern not in model.get('model', '').lower()
                    for pattern in excluded_models
                )
            ]
            model_names.sort(reverse=False)
            logger.debug(", ".join(model_names))
            return model_names
        except ConnectionError as e:
            logger.exception(f"Connection error while getting models: {str(e)}")
            raise

    def list_chat_model_names(self) -> List[str]:
        """Return sorted model tags available from the backend (respecting excluded patterns)."""
        try:
            return list(self._get_models(self.excluded_models))
        except Exception:
            return []

    def select_models(self, available_models: List[str], show_formatted: bool = True, max_models: Optional[int] = None, msg: str = "", recommend_lightweight: bool = False) -> List[str]:
        """
        Let user select models interactively

        Args:
            available_models: List of available model names
            show_formatted: Whether to show formatted model names
            max_models: Maximum number of models to select
        Returns:
            List of selected model names
        """
        if not available_models:
            logger.error("No models available for selection")
            return []

        # Filter models to display only lightweight models if requested
        if recommend_lightweight and (lightweight_models := self._filter_lightweight_models(available_models)):
            logger.info(f"Filtering models to display only lightweight models (< 10B parameters): {len(lightweight_models)} models found.")
            if not lightweight_models:
                logger.warning("No lightweight models found, displaying all available models.")
            else:
                available_models = lightweight_models

        # Format models if requested
        if show_formatted:
            formatted_models = self.format_model_display_batch(available_models)
        else:
            formatted_models = available_models

        # Display available models
        logger.info("\nAvailable models:")
        for i, (model_name, formatted_name) in enumerate(zip(available_models, formatted_models), 1):
            logger.info(f"{i}. {formatted_name}")

        limit_text = f" (max {max_models})" if max_models else ""

        # Get user input for model selection
        try:
            selected_models = []
            while len(selected_models) < (max_models or len(available_models)):
                logger.info(f"{msg}")
                selection = input(f"\nEnter model numbers separated by comma (e.g., 1,3,5), or 'all'{limit_text}: ")

                # Handle 'all' case
                if selection.strip().lower() == 'all':
                    if max_models:
                        logger.error(f"You can only select up to {max_models} models")
                        continue
                    logger.info(f"Selected all {len(available_models)} models")
                    return available_models

                # Parse selected indices
                try:
                    selected_indices = [int(idx.strip()) for idx in selection.split(',') if idx.strip()]
                    # Convert to 0-based indices
                    selected_indices = [idx - 1 for idx in selected_indices]

                    # Check if all indices are valid
                    if not all(0 <= idx < len(available_models) for idx in selected_indices):
                        logger.error(f"Invalid selection. Numbers must be between 1 and {len(available_models)}")
                        continue

                    # Check max_models limit
                    if max_models and len(selected_indices) > max_models:
                        logger.error(f"You can only select up to {max_models} models")
                        continue

                    # Get corresponding model names
                    selected_models = [available_models[idx] for idx in selected_indices]

                    if not selected_models:
                        logger.error("No models selected")
                        continue

                    logger.debug(f"Selected models: {', '.join(selected_models)}")
                    return selected_models

                except ValueError:
                    logger.error("Invalid input. Please enter numbers separated by commas")

        except KeyboardInterrupt:
            logger.info("\nModel selection interrupted")
            return []

    def select_analysis_models(self, args, available_models):
        """
        Select models for security analysis

        Args:
            args: Command line arguments
            available_models: List of available models

        Returns:
            Dictionary with selected models, containing 'scan_model' and 'main_models' keys
        """
        # Initialize variables
        main_models = []
        scan_model = None

        # If models are provided as a comma-separated list, return them
        if hasattr(args, 'models') and args.models:
            # Handle 'all' case
            if args.models.strip().lower() == 'all':
                logger.info(f"Selected all {len(available_models)} models")
                main_models = available_models
            else:
                main_models = [model.strip() for model in args.models.split(',')]

        # If a scan model is provided, return it
        if hasattr(args, 'scan_model') and args.scan_model:
            scan_model = [args.scan_model]

        if scan_model and main_models:
            return {'scan_model': scan_model, 'main_models': main_models}

        # If no models are provided, select the scan model
        # First, select the scan model - only show lightweight models
        if not hasattr(args, 'scan_model') or not scan_model:
            msg = "First, choose your quick scan model (lightweight model for initial scanning):"
            if not (scan_model := self.select_models(
                available_models,
                show_formatted=True,
                msg=msg,
                max_models=1,
                recommend_lightweight=True
            )):
                scan_model = None

        if not hasattr(args, 'models') or not main_models:
            # Then, select the main analysis model - show all models
            msg = "\nThen, choose your main model for deep vulnerability analysis:"
            if not (main_models := self.select_models(
                available_models, show_formatted=True, msg=msg
            )):
                main_models = None

        if scan_model and main_models:
            return {'scan_model': scan_model, 'main_models': main_models}

        return None

    # ------------------------------------------------------------------
    # Model display (base = emoji + raw name; Ollama overrides with show() metadata)
    # ------------------------------------------------------------------

    def get_model_display_name(self, model_name: str) -> str:
        """
        Get a display name for a model with appropriate emoji

        Args:
            model_name: Raw model name

        Returns:
            Formatted model name with emoji
        """
        emoji = self._get_model_emoji(model_name)
        return f"{emoji}{model_name}"

    @staticmethod
    def _get_model_emoji(model_name: str, default_emoji: str = "🤖 ") -> str:
        """
        Select an appropriate emoji for a model based on its name

        Args:
            model_name: Name of the model
            default_emoji: Default emoji to use if no match

        Returns:
            Emoji string with trailing space
        """
        model_lower = model_name.lower()

        # Extract the base name without version and family name if possible
        model_parts = model_lower.split('/')
        model_basename = model_parts[-1].split(':')[0]  # base name without version
        model_family = model_parts[0] if len(model_parts) > 1 else None  # potential family
        model_families = model_parts[:-1]  # all potential family parts

        # Default emoji
        model_emoji = default_emoji

        # Try matching with full priority order - this time checking specifically
        # for matches in the basename to give higher priority
        best_match_length = 0
        for model_id, emoji in MODEL_EMOJIS.items():
            if model_id in model_basename and len(model_id) > best_match_length:
                model_emoji = emoji
                best_match_length = len(model_id)

        # If no basename match, try other matches
        if best_match_length == 0:
            for model_id, emoji in MODEL_EMOJIS.items():
                # Check in full name, family and families
                if (model_id in model_lower or
                    (model_family and model_id in model_family) or
                    any(model_id in family for family in model_families)):
                    model_emoji = emoji
                    # Don't break - continue to find the most specific match

        return model_emoji

    def format_model_display(self, model_name: str) -> str:
        """
        Format a model name for display. Backends with rich metadata (Ollama
        ``show()``) override this to append parameter / quant info.
        """
        return self.get_model_display_name(model_name)

    def format_model_display_batch(self, model_names: List[str]) -> List[str]:
        """
        Format multiple model names

        Args:
            model_names: List of model names to format

        Returns:
            List of formatted model strings
        """
        return [self.format_model_display(model) for model in model_names]

    def _preload_model_info(self, model_names: List[str]) -> None:
        """Hook for backends that need to prefetch model metadata (Ollama ``show()``)."""

    def _filter_lightweight_models(self, models: List[str]) -> List[str]:
        """
        Filter models to only include lightweight models (less than 10B parameters).

        Base implementation has no parameter metadata; keep every model.
        """
        return list(models or [])

    # ------------------------------------------------------------------
    # Model availability
    # ------------------------------------------------------------------

    def ensure_model_available(self, model: str) -> bool:
        """
        Ensure a model is usable by the backend (pull it if the server supports it).

        Args:
            model: Model name to check/pull
        Returns:
            True if model is available, False if error
        """
        raise NotImplementedError("ModelBackend subclasses must implement ensure_model_available()")

    @classmethod
    def _normalize_model_reference(cls, model: str) -> str:
        """
        Normalize model name for local-availability checks.

        Examples:
            "nomic-embed-text:latest" -> "nomic-embed-text"
            "qwen3-embedding:4b" -> "qwen3-embedding:4b"
        """
        if text := (model or "").strip().lower():
            return text[: -len(":latest")] if text.endswith(":latest") else text
        else:
            return ""

    @classmethod
    def _is_model_present_locally(cls, requested_model: str, available_models: List[str]) -> bool:
        """Return True when requested model exists, accounting for server-side :latest alias."""
        requested = cls._normalize_model_reference(requested_model)
        available = {cls._normalize_model_reference(name) for name in available_models or []}
        return bool(requested) and requested in available

    # ------------------------------------------------------------------
    # Context window / chunk size
    # ------------------------------------------------------------------

    def get_running_num_ctx(self, model: str) -> Optional[int]:
        """
        Runtime context length in tokens allocated by the server for ``model``,
        when the backend can observe it (Ollama ``ps()``). ``None`` otherwise.
        """
        return None

    def get_effective_context_token_count_with_source(
        self, model: str
    ) -> Tuple[Optional[int], str]:
        """
        Resolve context length in tokens along with its source.

        Base implementation resolves nothing; Ollama reads ``ps()`` / ``show()``
        metadata and OpenAI-compatible backends honor the configured env value.
        """
        return None, ""

    def get_effective_context_token_count(self, model: str) -> Optional[int]:
        """Return merged context window size in tokens, preferring runtime probes."""
        tokens, source = self.get_effective_context_token_count_with_source(model)
        if tokens is None:
            return None
        if source:
            logger.debug(
                "Resolved effective context tokens for %s: %s (source=%s)",
                model,
                tokens,
                source,
            )
        return tokens

    _CHUNK_SIZE_SOURCE_LABELS: Dict[str, str] = {
        "ps": "runtime ps (loaded context)",
        "parameters": "Modelfile num_ctx",
        "modelinfo": "GGUF context_length",
        "env": "configured environment",
    }

    def _detect_optimal_chunk_size(self, model: str):
        tokens, source = self.get_effective_context_token_count_with_source(model)
        logger.debug(f"Resolved effective context tokens: {tokens} (source={source or 'none'})")
        if tokens is not None and tokens > 0:
            chunk_size = int(tokens * 0.9)
            label = self._CHUNK_SIZE_SOURCE_LABELS.get(source, source or "unknown source")
            logger.info(f"Model {model} context ({label}, tokens): {tokens}")
            logger.info(f"🔄 Using chunk size: {chunk_size}")
            return chunk_size

        logger.warning(f"Could not detect context length for {model}, using default size: {MAX_CHUNK_SIZE}")
        return MAX_CHUNK_SIZE

    def detect_optimal_chunk_size(self, model: str) -> int:
        """
        Detect optimal chunk size by querying backend model parameters

        Args:
            model: Name of the embedding model
        Returns:
            Optimal chunk size in characters
        """
        try:
            return self._detect_optimal_chunk_size(model)
        except Exception as e:
            logger.exception(f"Error detecting chunk size: {str(e)}")
            logger.debug("Using default chunk size", exc_info=True)
            return MAX_CHUNK_SIZE

    # ------------------------------------------------------------------
    # Cache invalidation hooks (no-op by default; Ollama overrides)
    # ------------------------------------------------------------------

    def clear_model_cache(self, model: Optional[str] = None):
        """Clear cached model metadata. Backends without metadata caches ignore this."""
        logger.debug(f"clear_model_cache has no effect for provider {self.provider!r}")

    def invalidate_ps_cache(self, model: Optional[str] = None) -> None:
        """Drop cached runtime state entries. Backends without runtime state ignore this."""
        logger.debug(f"invalidate_ps_cache has no effect for provider {self.provider!r}")


__all__ = ["ModelBackend"]