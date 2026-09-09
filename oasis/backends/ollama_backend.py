"""Native Ollama backend for OASIS.

Thin subclass of :class:`oasis.backends.base.ModelBackend`: everything generic
(chat transport, listing, selection, display hooks) lives in the base class.
This module keeps the Ollama-specific machinery:

- ``ollama.Client`` creation and connection probing;
- ``show()`` model metadata (parameters, quant, parent model) for display;
- runtime ``ps()`` cache (``num_ctx``) and context resolution;
- automatic ``pull`` of missing model weights in ``ensure_model_available``.
"""

import contextlib
import re
import threading
import time
import httpx
import ollama
from ollama import RequestError, ResponseError
from typing import List, Optional, Any, Dict, Tuple
from tqdm import tqdm

# Import from configuration
from .base import ModelBackend
from ..config import (
    MODEL_EMOJIS,
    OLLAMA_URL,
    OLLAMA_HTTP_CLIENT_TIMEOUT_SEC,
)

# Import from other modules
from ..tools import logger


def _is_ps_client_transient_error(exc: BaseException) -> bool:
    """True for transport/HTTP issues from ``ps()``; false for likely programmer bugs.

    ollama-python surfaces failures as :class:`RequestError` / :class:`ResponseError`;
    the client uses httpx, which raises :class:`httpx.HTTPError` for low-level
    request failures. We also allow common stdlib I/O so misconfigured networks
    do not get masked. Unexpected exceptions re-raise from :meth:`OllamaManager._refresh_ps_cache`.
    """
    return isinstance(
        exc,
        (
            RequestError,
            ResponseError,
            httpx.HTTPError,
            ConnectionError,
            TimeoutError,
            OSError,
        ),
    )


def _is_ollama_client_transient_error(exc: BaseException) -> bool:
    """Same policy as :func:`_is_ps_client_transient_error` for ``show()`` / other SDK calls."""
    return _is_ps_client_transient_error(exc)


class _PsCacheLog:
    """Format strings for :meth:`OllamaManager._refresh_ps_cache` and related paths.

    Centralizes *what* is emitted (warning vs debug, throttled vs every failure)
    so normal operation vs degraded ``ps()`` behaviour is easier to reason about.
    """

    REFRESH_FAIL_WARNING = (
        "Failed to refresh Ollama ps() cache; treating as no running models. "
        "This may indicate a misconfigured or unavailable Ollama instance."
    )
    REFRESH_FAIL_DEBUG = "Ollama ps() failed when refreshing cache: %s: %s"
    FULLY_INVALIDATED = "Ollama ps() cache fully invalidated"
    ENTRIES_INVALIDATED = "Ollama ps() cache entries invalidated for %r; TTL reset"
    CTX_CONFLICT_MODEL = (
        "Ollama ps(): conflicting ctx for model %r (%s vs %s); keeping latest"
    )
    CTX_CONFLICT_ALIAS = (
        "Ollama ps(): conflicting ctx for alias %r (%s vs %s); keeping latest"
    )
    CACHE_MISS = "Ollama ps() cache miss for %r (tried tag and :latest); known=%s"
    UNEXPECTED_PS = (
        "Unexpected exception from Ollama client.ps(); re-raising instead of "
        "treating as a transient network/config issue: %s: %s"
    )


class OllamaManager(ModelBackend):
    """
    Class for managing Ollama interactions and model operations.

    **Runtime ``ps()`` cache (``num_ctx``) — high level**

    Instance state: ``_ps_cache_by_model``, ``_ps_cache_by_name`` (two maps so
    canonical ``model`` vs alias ``name`` stay unambiguous), ``_ps_cache_expires_at``,
    ``_ps_cache_lock``, and ``_ps_cache_last_ps_error_warn_mono`` (throttle for
    failure logs). Class constants: :data:`_PS_CACHE_TTL_SEC`,
    :data:`_PS_CACHE_ERROR_RETRY_SEC`.

    Lifecycle: (1) cold or expired → :meth:`get_running_num_ctx` calls
    :meth:`_refresh_ps_cache` which hits ``client.ps()`` and repopulates the maps;
    (2) hot → snapshots are read under the lock, resolution uses
    :meth:`_ps_lookup_in_snapshot` without calling ``ps()``; (3) errors → empty
    maps, short retry TTL, throttled warning; (4) :meth:`invalidate_ps_cache` or
    :meth:`clear_model_cache` forces expiry to ``0`` so the next lookup refreshes.

    All TTL and expiry **comparisons** use :func:`time.monotonic` only; wall-clock
    :func:`time.time` is not used for cache behavior (avoids skew if the system
    clock jumps).

    Args:
        api_url: URL for Ollama API
    """

    provider = "ollama"

    def __init__(self, api_url: str = OLLAMA_URL):
        """
        Initialize the Ollama manager

        Args:
            api_url: URL for Ollama API
        """
        super().__init__()
        self.api_url = api_url
        # Cache for storing model information (from ``show()``) to avoid repeated API calls
        self._model_info_cache = {}
        # Short-lived cache for Ollama ``ps()`` runtime num_ctx lookups.
        # Two maps keep alias resolution unambiguous: ``model`` is the canonical
        # Ollama identifier (preferred on lookup); ``name`` is the alias the user
        # may have typed. See :meth:`get_running_num_ctx`.
        self._ps_cache_lock = threading.Lock()
        self._ps_cache_expires_at: float = 0.0
        self._ps_cache_by_model: Dict[str, int] = {}
        self._ps_cache_by_name: Dict[str, int] = {}
        # Throttle for :meth:`_refresh_ps_cache` warning when ``client.ps()`` fails.
        self._ps_cache_last_ps_error_warn_mono: float = 0.0

    def get_client(self) -> ollama.Client:
        """
        Get the Ollama client instance, checking connection first
        
        Returns:
            ollama.Client: Connected Ollama client
            
        Raises:
            ConnectionError: If Ollama server is not accessible
        """
        with self._client_lock:
            if not self.client:
                try:
                    self.client = ollama.Client(
                        self.api_url,
                        timeout=float(OLLAMA_HTTP_CLIENT_TIMEOUT_SEC),
                    )
                    # Try to list models to verify connection
                    self.client.list()
                except Exception as e:
                    self._log_connection_error(e)
                    raise ConnectionError(f"Cannot connect to Ollama server: {str(e)}") from e
        return self.client

    @staticmethod
    def _ps_cache_storage_key(tag: str) -> str:
        """Stable key for the ``ps()`` num_ctx maps: trim + case-fold to match read/write paths."""
        return tag.strip().lower() if isinstance(tag, str) and tag.strip() else ""

    @classmethod
    def _is_model_present_locally(cls, requested_model: str, available_models: List[str]) -> bool:
        """Return True when requested model exists, accounting for Ollama's :latest alias."""
        requested = cls._normalize_model_reference(requested_model)
        available = {cls._normalize_model_reference(name) for name in available_models or []}
        return bool(requested) and requested in available

    @staticmethod
    def _parse_parameter_size_value(param_size: Any) -> float:
        """Approximate parameter count from Ollama ``parameter_size`` (e.g. ``8.0B``, ``7M``)."""
        if param_size is None:
            return 0.0
        with contextlib.suppress(ValueError, TypeError):
            if isinstance(param_size, str):
                if "B" in param_size:
                    return float(param_size.replace("B", "")) * 1_000_000_000
                if "M" in param_size:
                    return float(param_size.replace("M", "")) * 1_000_000
            return float(param_size)
        return 0.0

    @staticmethod
    def _parameter_count_from_modelinfo_dict(modelinfo: Any) -> float:
        if not isinstance(modelinfo, dict):
            return 0.0
        raw = modelinfo.get("general.parameter_count")
        if raw is None:
            return 0.0
        with contextlib.suppress(ValueError, TypeError):
            return float(raw)
        return 0.0

    @staticmethod
    def _parameter_count_numeric(model_info: Any) -> float:
        """Raw parameter count for display and lightweight filtering (0 if unknown)."""
        if model_info is None:
            return 0.0
        parameters = 0.0
        try:
            if isinstance(model_info, dict):
                details = model_info.get("details")
                if isinstance(details, dict) and "parameter_size" in details:
                    parameters = OllamaManager._parse_parameter_size_value(details["parameter_size"])
                if parameters == 0.0 and (mi := model_info.get("modelinfo")):
                    parameters = OllamaManager._parameter_count_from_modelinfo_dict(mi)
            elif hasattr(model_info, "details") and model_info.details:
                details = model_info.details
                if hasattr(details, "parameter_size") and details.parameter_size:
                    parameters = OllamaManager._parse_parameter_size_value(details.parameter_size)
            if parameters == 0.0 and hasattr(model_info, "modelinfo") and (
                mi_attr := model_info.modelinfo
            ):
                parameters = OllamaManager._parameter_count_from_modelinfo_dict(mi_attr)
        except Exception:
            return 0.0
        return parameters

    def _get_model_info(self, model: str):
        """
        Get detailed information about a model from Ollama API
        Uses a cache to avoid repeated API calls for the same model

        Args:
            model: Name of the model
            
        Returns:
            Model information from Ollama API or cache
        """
        # Check if the model info is already in the cache
        with self._cache_lock:
            if model in self._model_info_cache:
                logger.debug(f"Using cached model information for {model}")
                return self._model_info_cache[model]
            
        # Not in cache, query the API
        client = self.get_client()
        logger.debug(f"Querying model information for {model} from Ollama API...")
        
        try:
            model_info = client.show(model)
            # Store in cache for future use
            with self._cache_lock:
                self._model_info_cache[model] = model_info
            return model_info
        except Exception as e:
            logger.warning(f"Error fetching model info for {model}: {str(e)}")
            # Return empty dict to avoid further errors
            return {}
            
    def clear_model_cache(self, model: str = None):
        """
        Clear the model information cache

        Also invalidates the runtime ``ps()`` cache (``num_ctx`` lookups) so a
        subsequent chat turn re-reads the up-to-date state of loaded models —
        e.g. after a pull, unload, or manual Modelfile edit.

        Args:
            model: Optional specific model to clear from cache.
                  If None, clears the entire cache.
        """
        with self._cache_lock:
            if model:
                if model in self._model_info_cache:
                    logger.debug(f"Clearing cache for model: {model}")
                    del self._model_info_cache[model]
            else:
                logger.debug("Clearing entire model information cache")
                self._model_info_cache = {}
        self.invalidate_ps_cache(model)

    def invalidate_ps_cache(self, model: Optional[str] = None) -> None:
        """
        Drop cached ``ps()`` runtime ``num_ctx`` entries.

        The ``ps()`` cache is TTL-bounded (:data:`_PS_CACHE_TTL_SEC`) but some
        operations — pulling a new model, unloading an existing one, restarting
        ``ollama serve`` — must be reflected immediately instead of waiting for
        natural expiry. Call this helper from those code paths (and from tests)
        to force a refresh on the next :meth:`get_running_num_ctx`.

        Args:
            model: Model tag or alias. If provided, entries in either ``by_model``
                or ``by_name`` whose :meth:`_normalize_model_reference` matches
                the reference for ``model`` are removed (case-insensitive; ``a``,
                ``A``, ``a:latest`` are equivalent, matching how lookups resolve).
                Any successful removal also **resets the overall TTL**
                (``_ps_cache_expires_at = 0``) so the next
                :meth:`get_running_num_ctx` refreshes the full snapshot — a
                pull/unload that changes one model's state often has ripple
                effects on others (eviction, memory pressure), and keeping stale
                neighbours would defeat the invalidation. If ``None``, both maps
                are emptied and the TTL reset unconditionally.
        """
        with self._ps_cache_lock:
            if model is None or not str(model).strip():
                self._ps_cache_by_model = {}
                self._ps_cache_by_name = {}
                self._ps_cache_expires_at = 0.0
                logger.debug(_PsCacheLog.FULLY_INVALIDATED)
                return
            ref = str(model).strip()
            target = self._normalize_model_reference(ref)
            if not target:
                return
            removed = False
            for store in (self._ps_cache_by_model, self._ps_cache_by_name):
                for k in list(store.keys()):
                    if self._normalize_model_reference(str(k)) != target:
                        continue
                    if store.pop(k, None) is not None:
                        removed = True
            if removed:
                # Force a full snapshot refresh on the next lookup: the event
                # that triggered this invalidation (pull/unload/restart) is
                # likely to have shifted neighbouring models too, so returning
                # other cached entries until natural expiry would be stale.
                self._ps_cache_expires_at = 0.0
                logger.debug(_PsCacheLog.ENTRIES_INVALIDATED, ref)
        
    _PS_CACHE_TTL_SEC = 30.0
    #: When ``ps()`` errors, cache empty maps with this shorter TTL so we retry
    #: soon without hammering a dead server every request.
    _PS_CACHE_ERROR_RETRY_SEC = 5.0

    def _ps_cache_expires_after(self, now: float, had_error: bool) -> float:
        """``now +`` short retry TTL after ``ps()`` failure, else full cache TTL."""
        if had_error:
            return now + self._PS_CACHE_ERROR_RETRY_SEC
        return now + self._PS_CACHE_TTL_SEC

    @staticmethod
    def _extract_ps_context_length(entry: Any) -> Optional[int]:
        """Pull runtime ``context_length`` from a single ``ps()`` model entry."""
        candidates: List[Any] = []
        if isinstance(entry, dict):
            candidates.extend((entry.get("context_length"), entry.get("num_ctx")))
        else:
            candidates.extend(
                (
                    getattr(entry, "context_length", None),
                    getattr(entry, "num_ctx", None),
                )
            )
        for raw in candidates:
            if raw is None:
                continue
            try:
                n = int(raw)
            except (TypeError, ValueError):
                continue
            if n > 0:
                return n
        return None

    @staticmethod
    def _iter_ps_models(ps_response: Any):
        """Yield model entries from an Ollama ``ps()`` response (dict or SDK object)."""
        if ps_response is None:
            return
        yield from (
            ps_response.get("models") or []
            if isinstance(ps_response, dict)
            else getattr(ps_response, "models", None) or []
        )

    @staticmethod
    def _ps_entry_names(entry: Any) -> Tuple[Optional[str], Optional[str]]:
        """Return ``(name, model)`` strings from a ``ps()`` model entry."""
        if isinstance(entry, dict):
            return entry.get("name"), entry.get("model")
        return getattr(entry, "name", None), getattr(entry, "model", None)

    def _refresh_ps_cache(self) -> Tuple[Dict[str, int], Dict[str, int], bool]:
        """Populate the ``ps()`` runtime context caches and return fresh maps.

        Internal TTL / throttle times use :func:`time.monotonic` exclusively;
        :func:`time.time` is reserved for human-facing timestamps elsewhere, so
        clock adjustments never affect cache behaviour.

        Returns:
            ``(by_model, by_name, had_error)`` where ``by_model`` is keyed by the
            canonical Ollama identifier (``model`` field) and ``by_name`` by the
            alias the user may have typed (``name`` field). When both entry
            fields differ they must route to the same ``num_ctx`` — otherwise a
            debug log is emitted so operators can notice conflicting aliases.

            ``had_error`` is ``True`` when ``client.ps()`` raised. Then both maps
            are empty, which is *not* equivalent to a healthy response with no
            loaded models: see :meth:`get_running_num_ctx` for how TTL is
            shortened on error. Warnings are throttled to at most once per
            :data:`_PS_CACHE_TTL_SEC` to avoid log spam while Ollama is down.
        """
        client = self.get_client()
        now_mono = time.monotonic()
        try:
            ps_response = client.ps()
        except Exception as exc:
            if not _is_ollama_client_transient_error(exc):
                logger.error(
                    _PsCacheLog.UNEXPECTED_PS,
                    type(exc).__name__,
                    exc,
                    exc_info=True,
                )
                raise
            if now_mono - self._ps_cache_last_ps_error_warn_mono >= self._PS_CACHE_TTL_SEC:
                logger.warning(_PsCacheLog.REFRESH_FAIL_WARNING, exc_info=True)
                self._ps_cache_last_ps_error_warn_mono = now_mono
            else:
                logger.debug(
                    _PsCacheLog.REFRESH_FAIL_DEBUG,
                    type(exc).__name__,
                    exc,
                    exc_info=True,
                )
            return {}, {}, True
        by_model: Dict[str, int] = {}
        by_name: Dict[str, int] = {}
        for entry in self._iter_ps_models(ps_response):
            ctx = self._extract_ps_context_length(entry)
            if ctx is None:
                continue
            name, model = self._ps_entry_names(entry)
            mkey = OllamaManager._ps_cache_storage_key(model) if isinstance(model, str) else ""
            nkey = OllamaManager._ps_cache_storage_key(name) if isinstance(name, str) else ""
            if mkey:
                if mkey in by_model and by_model[mkey] != ctx:
                    logger.debug(
                        _PsCacheLog.CTX_CONFLICT_MODEL,
                        model,
                        by_model[mkey],
                        ctx,
                    )
                by_model[mkey] = ctx
            if nkey and nkey != mkey:
                if nkey in by_name and by_name[nkey] != ctx:
                    logger.debug(
                        _PsCacheLog.CTX_CONFLICT_ALIAS,
                        name,
                        by_name[nkey],
                        ctx,
                    )
                by_name[nkey] = ctx
        return by_model, by_name, False

    @staticmethod
    def _ps_lookup_in_snapshot(
        key: str,
        by_model: Dict[str, int],
        by_name: Dict[str, int],
    ) -> Optional[int]:
        """Pure resolver: look up ``key`` against pre-snapshotted ps() maps.

        Does **not** touch ``self._ps_cache_lock`` — it operates only on its
        arguments. Keeping this function lock-free makes the surrounding
        concurrency pattern non-re-entrant by construction: any future caller
        that already holds the lock can pass a snapshot without risking a
        deadlock, and callers that do not hold the lock snapshot first.

        Lookup order: exact ``model`` → exact ``name`` → ``"<key>:latest"``
        on ``model`` → ``"<key>:latest"`` on ``name``. Uses explicit
        ``is None`` fallbacks; ps() entries carry only strictly positive ctx
        values (enforced by :meth:`_extract_ps_context_length`), but
        truthiness-based fallbacks would silently drop a hypothetical ``0``.
        """
        tokens = by_model.get(key)
        if tokens is None:
            tokens = by_name.get(key)
        if tokens is None and ":" not in key:
            alias = f"{key}:latest"
            tokens = by_model.get(alias)
            if tokens is None:
                tokens = by_name.get(alias)
        if tokens is None and (by_model or by_name):
            logger.debug(
                _PsCacheLog.CACHE_MISS,
                key,
                sorted(set(by_model.keys()) | set(by_name.keys())),
            )
        return int(tokens) if tokens is not None else None

    def _ps_snapshot(self) -> Tuple[Dict[str, int], Dict[str, int], float]:
        """Return a lock-free copy of the ps() caches plus the expiry timestamp.

        **Lifecycle (mental model for staleness and concurrency):**

        1. *Cold / expired:* :meth:`get_running_num_ctx` calls
           :meth:`_refresh_ps_cache`, which issues ``client.ps()``, then stores
           the two maps and sets ``_ps_cache_expires_at = now + TTL`` (or a
           shorter retry interval when ``ps()`` errored — empty maps are not
           trusted for the full TTL).

        2. *Hot:* While ``time.monotonic() < _ps_cache_expires_at``, lookups
           read only from snapshots of the maps (via :meth:`_ps_lookup_in_snapshot`)
           and never re-enter the client for ``ps()``.

        3. *Targeted invalidation:* :meth:`invalidate_ps_cache` drops entries (or
           clears all maps) and resets the expiry to ``0.0`` so the next
           read-path refresh rebuilds a consistent view after pull/unload/restart
           without waiting for natural TTL.

        The lock is held only while copying the dicts and reading the float;
        resolution runs on the snapshot outside the lock.
        """
        with self._ps_cache_lock:
            return (
                dict(self._ps_cache_by_model),
                dict(self._ps_cache_by_name),
                self._ps_cache_expires_at,
            )

    def get_running_num_ctx(self, model: str) -> Optional[int]:
        """
        Return the runtime ``num_ctx`` (context length in tokens) actually allocated
        by Ollama for the given model, from ``client.ps()``.

        Returns ``None`` when the model is not currently loaded or ``ps()`` fails.
        Results are cached for :data:`_PS_CACHE_TTL_SEC` to avoid an API call on
        every chat turn. Resolution prefers the canonical ``model`` field over
        ``name`` to avoid ambiguity when aliases map to a different canonical tag.

        Concurrency: the ps() cache is snapshotted once under
        ``self._ps_cache_lock`` and resolution runs lock-free via
        :meth:`_ps_lookup_in_snapshot`, so this method is safe to call from
        inside higher-level locked sections without risking a deadlock.
        """
        if not isinstance(model, str) or not model.strip():
            return None
        key = OllamaManager._ps_cache_storage_key(model)
        if not key:
            return None
        now = time.monotonic()
        by_model, by_name, expires_at = self._ps_snapshot()
        if now < expires_at and (by_model or by_name):
            cached = self._ps_lookup_in_snapshot(key, by_model, by_name)
            if cached is not None:
                return cached
        by_model, by_name, ps_had_error = self._refresh_ps_cache()
        with self._ps_cache_lock:
            self._ps_cache_by_model = by_model
            self._ps_cache_by_name = by_name
            # Do not cache "empty" for the full TTL on error — that would conflate
            # transport failure with a legitimately empty ps() for 30s.
            self._ps_cache_expires_at = self._ps_cache_expires_after(now, ps_had_error)
        return self._ps_lookup_in_snapshot(key, by_model, by_name)

    def get_effective_context_token_count_with_source(
        self, model: str
    ) -> Tuple[Optional[int], str]:
        """
        Resolve context length in tokens along with its source.

        Sources (in priority order):
          - ``"ps"``: runtime ``num_ctx`` from ``ps()`` (source of truth when loaded)
          - ``"parameters"``: Modelfile ``num_ctx`` from ``show()``
          - ``"modelinfo"``: GGUF ``*.context_length`` from ``show()``
          - ``""``: nothing could be resolved

        A failing ``ps()`` call is distinct from *no running models*:
        :meth:`_refresh_ps_cache` returns ``had_error=True``, logs a throttled
        warning, and :meth:`get_running_num_ctx` applies a shorter cache TTL so
        the next request retries soon. That yields ``running=None`` and falls
        back to ``show()``-based context. Unexpected programmer errors are
        not swallowed from :meth:`get_running_num_ctx`. On the ``show()`` path,
        :meth:`_get_model_info` / token extraction raises after logging unless the
        failure is a known transient client/transport error (see
        :func:`_is_ollama_client_transient_error`).
        """
        running = self.get_running_num_ctx(model)
        if running is not None and running > 0:
            return int(running), "ps"
        try:
            model_info = self._get_model_info(model)
            tokens, src = self._model_info_effective_context_tokens(model_info)
        except Exception as exc:
            if not _is_ollama_client_transient_error(exc):
                logger.error(
                    "Unexpected error while resolving context from Ollama show() "
                    "for model %r: %s: %s",
                    model,
                    type(exc).__name__,
                    exc,
                    exc_info=True,
                )
                raise
            return None, ""
        if tokens is None or tokens <= 0:
            return None, src or ""
        return int(tokens), src or ""

    _NUM_CTX_IN_PARAMETERS = re.compile(r"num_ctx\s+(\d+)", re.IGNORECASE)

    @staticmethod
    def _num_ctx_from_parameters_value(params: Any) -> Optional[int]:
        """Resolve num_ctx from Ollama ``parameters`` (dict or Modelfile-style string)."""
        if params is None:
            return None
        with contextlib.suppress(TypeError, ValueError):
            if isinstance(params, dict) and "num_ctx" in params:
                return int(params["num_ctx"])
            if isinstance(params, str):
                if match := OllamaManager._NUM_CTX_IN_PARAMETERS.search(params):
                    return int(match.group(1))
        return None

    @staticmethod
    def _model_info_num_ctx(model_info: Any) -> Optional[int]:
        """Parse num_ctx from Ollama client.show() payload (dict or SDK object)."""
        with contextlib.suppress(TypeError, ValueError):
            if isinstance(model_info, dict):
                params = model_info.get("parameters")
            elif hasattr(model_info, "parameters"):
                params = getattr(model_info, "parameters", None)
            else:
                params = None
            return OllamaManager._num_ctx_from_parameters_value(params)
        return None

    @staticmethod
    def _raw_modelinfo_kv(model_info: Any) -> Any:
        """GGUF KV map from ``client.show()`` (``modelinfo`` / ``model_info``)."""
        if isinstance(model_info, dict):
            return model_info.get("modelinfo") or model_info.get("model_info")
        if getattr(model_info, "modelinfo", None) is not None:
            return getattr(model_info, "modelinfo")
        if getattr(model_info, "model_info", None) is not None:
            return getattr(model_info, "model_info")
        return None

    @staticmethod
    def _modelinfo_context_length_tokens(modelinfo: Any) -> Optional[int]:
        """
        Largest ``*.context_length`` value from GGUF metadata (Model card context length).

        Used when Modelfile ``parameters`` omit ``num_ctx`` (e.g. some embedding builds).
        """
        if not isinstance(modelinfo, dict):
            return None
        best: Optional[int] = None
        for key, raw in modelinfo.items():
            if not isinstance(key, str) or not key.endswith(".context_length"):
                continue
            try:
                n = int(float(raw))
            except (TypeError, ValueError):
                continue
            if n > 0:
                best = n if best is None else max(best, n)
        return best

    @staticmethod
    def _model_info_effective_context_tokens(model_info: Any) -> tuple[Optional[int], str]:
        """
        Effective context size in tokens for chunk sizing.

        Prefer Modelfile ``num_ctx`` (runtime allocation); else GGUF ``*.context_length``.

        Returns:
            (token_count or None, source: "parameters" | "modelinfo" | "")
        """
        from_params = OllamaManager._model_info_num_ctx(model_info)
        if from_params is not None and from_params > 0:
            return from_params, "parameters"
        mi = OllamaManager._raw_modelinfo_kv(model_info)
        from_gguf = OllamaManager._modelinfo_context_length_tokens(mi)
        if from_gguf is not None and from_gguf > 0:
            return from_gguf, "modelinfo"
        return None, ""

    def format_model_display(self, model_name: str) -> str:
        """
        Format a model name with emoji and technical info
        
        Args:
            model_name: Name of the model
            
        Returns:
            Formatted string with emoji and technical info
        """
        try:
            # Get model information using Ollama API
            model_info = self._get_model_info(model_name)
            
            # Extract emoji, parameters, context, and parent model info
            model_emoji = self._get_model_emoji(model_name)
            param_str = self._extract_model_parameters(model_info) or ""
            ctx_str = self._extract_token_context(model_info) or ""
            parent_info = self._extract_parent_model_info(model_info)
            
            # Build final formatted string
            return self._build_formatted_string(model_name, model_emoji, param_str, ctx_str, parent_info)
            
        except Exception as e:
            # Fallback to simple formatting if API fails
            logger.exception(f"Error fetching model details: {str(e)}")
            model_emoji = self._get_model_emoji(model_name)
            return f"{model_emoji}{model_name}"
    
    def _preload_model_info(self, model_names: List[str]) -> None:
        """
        Preload information for multiple models at once to reduce API calls
        
        Args:
            model_names: List of model names to preload information for
        """
        # Check first which models are not in cache
        with self._cache_lock:
            models_to_load = [m for m in model_names if m not in self._model_info_cache]
        
        if not models_to_load:
            logger.debug("All models already cached, no need to preload")
            return
            
        logger.debug(f"Preloading information for {len(models_to_load)} models")
        client = self.get_client()
        
        for model in tqdm(models_to_load, desc="Preloading model info", unit="model"):
            try:
                model_info = client.show(model)
                with self._cache_lock:
                    if model not in self._model_info_cache:
                        self._model_info_cache[model] = model_info
            except Exception as e:
                logger.warning(f"Error preloading model info for {model}: {str(e)}")
                # Use empty dict to avoid repeated attempts
                with self._cache_lock:
                    self._model_info_cache[model] = {}

    def _filter_lightweight_models(self, models: List[str]) -> List[str]:
        """
        Filter models to only include lightweight models (less than 10B parameters)
        
        Args:
            models: List of model names to filter
            
        Returns:
            List of lightweight model names
        """
        if not models:
            return []

        self._preload_model_info(models)

        lightweight_models: List[str] = []
        max_lightweight = 10_000_000_000

        for model in models:
            try:
                parameters = self._parameter_count_numeric(self._get_model_info(model))
                if parameters == 0 or parameters <= max_lightweight:
                    lightweight_models.append(model)
            except Exception as e:
                logger.debug(f"Could not get parameter info for {model}: {str(e)}")
                lightweight_models.append(model)

        return lightweight_models

    def ensure_model_available(self, model: str) -> bool:
        """
        Ensure a model is available, pull if needed

        Args:
            model: Model name to check/pull
        Returns:
            True if model is available, False if error
        """
        try:
            client = self.get_client()
            available_models = self._get_models([])
            
            # Check if model is already available (:latest alias handled)
            if self._is_model_present_locally(model, available_models):
                logger.debug(f"Model {model} is already available")
                return True
                
            # Model not available, try to pull it
            logger.info(f"🤖 Model {model} not found locally, pulling from Ollama library...")

            try:
                with tqdm(desc=f"Downloading {model}", unit='B', unit_scale=True, unit_divisor=1024) as pbar:
                    for response in client.pull(model, stream=True):
                        if 'status' in response:
                            status = response['status']
                            if 'completed' in status:
                                if 'completed' in response:
                                    completed = int(response['completed'])
                                    delta = completed - pbar.n
                                    if delta > 0:
                                        pbar.update(delta)
                                else:
                                    pbar.update(pbar.total - pbar.n)  # Fallback update if no detailed progress available
                            elif 'pulling' in status:
                                if 'total' in response and 'completed' in response:
                                    total = int(response['total'])
                                    completed = int(response['completed'])
                                    if pbar.total != total:
                                        pbar.total = total
                                    pbar.n = completed
                                    pbar.refresh()

                logger.info(f"Successfully pulled model {model}")
                
                # Clear the model cache entry if it exists to force a refresh
                self.clear_model_cache(model)
                
                return True
                
            except Exception as pull_error:
                logger.exception(f"Failed to pull model {model}: {str(pull_error)}")
                logger.error("Please check that the model name is correct and available from Ollama")
                return False
                
        except Exception as e:
            logger.exception(f"Error checking model availability: {str(e)}")
            return False

    def _log_connection_error(self, error):
        """
        Log detailed Ollama connection error messages

        Args:
            error: Exception
        """
        logger.error("\nError: Could not connect to Ollama server")
        logger.info("Please ensure that:")
        logger.info("1. Ollama is installed (https://ollama.ai)")
        logger.info("2. Ollama server is running (usually with 'ollama serve')")
        logger.info(f"3. Ollama is accessible ({self.api_url})")
        logger.debug(f"Connection error: {str(error)}")

    def _extract_model_parameters(self, model_info: Any) -> Optional[str]:
        """
        Extract and format parameter information from model info

        Args:
            model_info: Model information
        Returns:
            Formatted parameter information
        """
        parameters = self._parameter_count_numeric(model_info)
        if parameters <= 0:
            return ""

        # Format parameter count in billions or millions
        if parameters >= 1_000_000_000:
            param_str = f"{parameters/1_000_000_000:.1f}B params"
            # Add turtle emoji for models larger than 26B
            if parameters > 26_000_000_000:
                param_str = f"🐢 {param_str}"
            # Add fast emoji for models with parameters <= 10B
            if parameters <= 10_000_000_000:
                param_str = f"⚡ {param_str}"
            return param_str
        elif parameters > 0:
            # Small models are considered fast
            return f"⚡ {parameters:,} params"
        return ""
    
    def _extract_token_context(self, model_info: Any) -> Optional[str]:
        """
        Extract token context window size from model info

        Args:
            model_info: Model information
        Returns:
            Formatted token context window size
        """
        try:
            ctx_size, _src = self._model_info_effective_context_tokens(model_info)
            if ctx_size is not None and ctx_size > 0:
                if ctx_size >= 1000:
                    return f"{ctx_size // 1000}k context"
                return f"{ctx_size} context"
        except Exception as e:
            logger.debug(f"Error extracting context window: {str(e)}")

        return None
    
    def _extract_parent_model_info(self, model_info: Any, default_emoji: str = "🤖 ") -> str:
        """
        Extract and format parent model information

        Args:
            model_info: Model information
            default_emoji: Default emoji to use if no match
        """
        try:
            # Check for dictionary format (newer API)
            if isinstance(model_info, dict):
                if ('details' in model_info and model_info['details'] and 
                    isinstance(model_info['details'], dict) and 
                    'parent_model' in model_info['details'] and 
                    model_info['details']['parent_model']):
                    
                    parent_model = model_info['details']['parent_model']
                    return self._format_parent_model_display(
                        parent_model, default_emoji
                    )
            elif (hasattr(model_info, 'details') and model_info.details and 
                  hasattr(model_info.details, 'parent_model') and 
                  model_info.details.parent_model):
                
                parent_model = model_info.details.parent_model
                return self._format_parent_model_display(
                    parent_model, default_emoji
                )
        except Exception as e:
            logger.debug(f"Error extracting parent model info: {str(e)}")

        return ""

    def _format_parent_model_display(self, parent_model, default_emoji):
        parent_lower = parent_model.lower()
   
        # Extract base name without version
        parent_basename = parent_lower.split('/')[-1].split(':')[0]

        # Get emoji for parent model
        parent_emoji = next(
            (
                emoji
                for model_id, emoji in MODEL_EMOJIS.items()
                if model_id in parent_basename or model_id in parent_lower
            ),
            default_emoji,
        )

        # Return formatted parent model info
        return f"{parent_emoji}{parent_model.split(':')[0]}"
    
    def _build_formatted_string(self, model_name: str, model_emoji: str, param_str: str, ctx_str: str, parent_info: str = "") -> str:
        """
        Build the final formatted string with all available information

        Args:
            model_name: Name of the model
            model_emoji: Emoji for the model
            param_str: Formatted parameter information
        """
        # Keep the full Ollama name (including the version tag) so variants of the
        # same base model stay distinguishable in the selection list (issue #61).
        formatted_parts = [f"{model_emoji}{model_name}"]
        
        # Format technical info parts
        tech_info_parts = []
        if param_str:
            tech_info_parts.append(param_str)
        if ctx_str:
            tech_info_parts.append(ctx_str)
        if parent_info:
            tech_info_parts.append(f"based on {parent_info}")
        
        # Add technical info if available
        if tech_info_parts:
            formatted_parts.append(f"({', '.join(tech_info_parts)})")

        return " ".join(formatted_parts)
