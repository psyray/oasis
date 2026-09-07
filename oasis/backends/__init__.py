"""Model backend package: Ollama or OpenAI-compatible local servers.

Public entry points:

- :func:`create_model_manager` — build the backend matching CLI args / env;
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
    resolved = resolve_provider_choice(provider)
    if resolved is None and args is not None:
        resolved = resolve_provider_choice(getattr(args, "provider", None))
    if resolved is None:
        # Read at call time so runtime patches / late env changes are honored.
        resolved = resolve_provider_choice(config.LLM_PROVIDER_ENV)
    if resolved is None:
        arg_api_base = api_base or getattr(args, "api_base", None)
        resolved = LLM_PROVIDER_OPENAI if arg_api_base else LLM_PROVIDER_OLLAMA

    if resolved == LLM_PROVIDER_OPENAI:
        base = api_base or getattr(args, "api_base", None) or getattr(args, "api_url", None)
        key = api_key or getattr(args, "api_key", None)
        return OpenAICompatManager(api_base=base, api_key=key)

    url = ollama_url or getattr(args, "ollama_url", None) or OLLAMA_URL
    return OllamaManager(url)


__all__ = [
    "ModelBackend",
    "OllamaManager",
    "OpenAICompatManager",
    "create_model_manager",
    "resolve_provider_choice",
]