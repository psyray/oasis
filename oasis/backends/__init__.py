"""Model backend package: Ollama or OpenAI-compatible local servers.

Public entry points:

- :func:`create_model_manager` — build the chat backend matching CLI args / env;
- :func:`create_embed_model_manager` — build the embedding backend, resolved
  independently from the chat backend (``--embed-*`` overrides win, otherwise
  the chat configuration is inherited) so chat and embedding workloads can be
  routed to separate servers (e.g. a dedicated RAG server);
- :class:`ModelBackend` — the backend contract;
- :class:`OllamaManager` / :class:`OpenAICompatManager` — concrete backends.
"""

from typing import Any, Optional

from .base import ModelBackend
from .ollama_backend import OllamaManager
from .openai_compat import OpenAICompatManager
from .. import config
from ..config import (
    LLM_PROVIDER_CHOICES,
    LLM_PROVIDER_OPENAI,
    LLM_PROVIDER_OLLAMA,
    OLLAMA_URL,
)


def resolve_provider_choice(raw: Any) -> Optional[str]:
    """
    Normalize a provider value to ``"ollama"`` / ``"openai"``.

    Accepts None (→ None, caller decides the default) and case-insensitive
    aliases (``openai-compatible``, ``openai_compat``, ``vllm``...). Raises
    ``ValueError`` for unknown explicit choices.
    """
    if raw is None:
        return None
    value = str(raw).strip().lower()
    if not value:
        return None
    if value in ("ollama",):
        return LLM_PROVIDER_OLLAMA
    if value in ("openai", "openai-compatible", "openai_compat", "openaicompat", "vllm"):
        return LLM_PROVIDER_OPENAI
    raise ValueError(
        f"Unknown model provider {raw!r}; expected one of: {', '.join(LLM_PROVIDER_CHOICES)}"
    )


def _resolve_chat_provider(
    args: Optional[Any],
    provider: Optional[str],
    api_base: Optional[str],
) -> str:
    """Shared chat-provider resolution used by both backend factories.

    Order: explicit ``provider`` argument → ``args.provider`` (``--provider``) →
    ``OASIS_LLM_PROVIDER`` environment variable → ``"openai"`` when an
    OpenAI-compatible base URL is provided, else ``"ollama"``.
    """
    resolved = resolve_provider_choice(provider)
    if resolved is None and args is not None:
        resolved = resolve_provider_choice(getattr(args, "provider", None))
    if resolved is None:
        # Read at call time so runtime patches / late env changes are honored.
        resolved = resolve_provider_choice(config.LLM_PROVIDER_ENV)
    if resolved is None:
        arg_api_base = api_base or getattr(args, "api_base", None)
        resolved = LLM_PROVIDER_OPENAI if arg_api_base else LLM_PROVIDER_OLLAMA
    return resolved


def create_model_manager(
    args: Optional[Any] = None,
    *,
    provider: Optional[str] = None,
    ollama_url: Optional[str] = None,
    api_base: Optional[str] = None,
    api_key: Optional[str] = None,
) -> ModelBackend:
    """
    Build the model backend matching CLI args / environment.

    Resolution order for the provider:

    1. explicit ``provider`` argument;
    2. ``args.provider`` (``--provider``);
    3. ``OASIS_LLM_PROVIDER`` environment variable;
    4. ``"openai"`` when an OpenAI-compatible base URL is provided
       (``api_base`` argument or ``args.api_base``), else ``"ollama"``.

    Args:
        args: Namespace-like CLI arguments (reads ``provider``, ``ollama_url``,
            ``api_base``, ``api_key`` when present).
        provider: Explicit provider override.
        ollama_url: Explicit Ollama URL override (used when provider = ollama).
        api_base: Explicit OpenAI-compatible base URL override.
        api_key: Explicit OpenAI-compatible API key override.

    Returns:
        ModelBackend: the configured backend instance.
    """
    resolved = _resolve_chat_provider(args, provider, api_base)

    if resolved == LLM_PROVIDER_OPENAI:
        base = api_base or getattr(args, "api_base", None) or getattr(args, "api_url", None)
        key = api_key or getattr(args, "api_key", None)
        return OpenAICompatManager(api_base=base, api_key=key)

    url = ollama_url or getattr(args, "ollama_url", None) or OLLAMA_URL
    return OllamaManager(url)


def create_embed_model_manager(
    args: Optional[Any] = None,
    *,
    provider: Optional[str] = None,
    ollama_url: Optional[str] = None,
    api_base: Optional[str] = None,
    api_key: Optional[str] = None,
) -> ModelBackend:
    """
    Build the embedding backend, resolved independently from the chat backend.

    Embedding-specific configuration (``--embed-provider`` / ``--embed-api-base`` /
    ``--embed-api-key`` or their env equivalents) always wins; when none is set,
    the embedding backend **inherits the chat backend configuration** (provider,
    base URL and API key) instead of defaulting to local Ollama — so chat and
    embedding workloads still can be routed to separate servers explicitly.

    Resolution order for the provider:

    1. explicit ``provider`` argument;
    2. ``args.embed_provider`` (``--embed-provider``);
    3. ``OASIS_EMBED_PROVIDER`` environment variable;
    4. ``"openai"`` when an embedding base URL is provided (``api_base`` argument,
       ``args.embed_api_base`` or ``OASIS_EMBED_OPENAI_BASE_URL``);
    5. the chat backend configuration (``args.provider`` / ``OASIS_LLM_PROVIDER`` /
       ``args.api_base``);
    6. ``"ollama"`` — the local default.

    Args:
        args: Namespace-like CLI arguments (reads ``embed_provider``,
            ``embed_api_base``, ``embed_api_key`` and, as inheritance fallback,
            ``provider`` / ``api_base`` / ``api_key`` / ``ollama_url``).
        provider: Explicit provider override.
        ollama_url: Explicit Ollama URL override (used when provider = ollama).
        api_base: Explicit OpenAI-compatible embedding base URL override.
        api_key: Explicit OpenAI-compatible embedding API key override.

    Returns:
        ModelBackend: the configured embedding backend instance.
    """
    resolved = resolve_provider_choice(provider)
    if resolved is None and args is not None:
        resolved = resolve_provider_choice(getattr(args, "embed_provider", None))
    if resolved is None:
        # Read at call time so runtime patches / late env changes are honored.
        resolved = resolve_provider_choice(config.EMBED_PROVIDER_ENV)
    if resolved is None:
        arg_api_base = api_base or getattr(args, "embed_api_base", None) or config.EMBED_OPENAI_BASE_URL
        resolved = LLM_PROVIDER_OPENAI if arg_api_base else _resolve_chat_provider(args, None, None)

    if resolved == LLM_PROVIDER_OPENAI:
        base = (
            api_base
            or getattr(args, "embed_api_base", None)
            or config.EMBED_OPENAI_BASE_URL
            or getattr(args, "api_base", None)
            or config.OPENAI_COMPAT_BASE_URL
        )
        key = (
            api_key
            or getattr(args, "embed_api_key", None)
            or config.EMBED_OPENAI_API_KEY
            or getattr(args, "api_key", None)
            or config.OPENAI_COMPAT_API_KEY
        )
        return OpenAICompatManager(api_base=base, api_key=key)

    url = ollama_url or getattr(args, "ollama_url", None) or OLLAMA_URL
    return OllamaManager(url)


__all__ = [
    "ModelBackend",
    "OllamaManager",
    "OpenAICompatManager",
    "create_embed_model_manager",
    "create_model_manager",
    "resolve_provider_choice",
]