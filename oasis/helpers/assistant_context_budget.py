"""Compute assistant system-prompt character budget using Ollama model context hints."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

if TYPE_CHECKING:
    from oasis.ollama_manager import OllamaManager

# Rough chars per token for conservative English-heavy security report text (heuristic).
_ASSISTANT_CHARS_PER_TOKEN_DEFAULT = 3
_ASSISTANT_SYSTEM_RESERVE_MESSAGES_AND_OUTPUT = 4096

# Clamp dynamic budget between these so misdetected contexts do not explode RAM or cripple UX.
_ASSISTANT_DYNAMIC_BUDGET_MIN = 32000
_ASSISTANT_DYNAMIC_BUDGET_MAX = 512000


def assistant_total_system_budget_chars(
    *,
    fallback_total: int,
    ollama_manager: Optional["OllamaManager"],
    chat_model: str,
    approx_message_chars_in_request: int,
    chars_per_token_guess: int = _ASSISTANT_CHARS_PER_TOKEN_DEFAULT,
    reserve_tail: int = _ASSISTANT_SYSTEM_RESERVE_MESSAGES_AND_OUTPUT,
) -> Tuple[int, Dict[str, Any]]:
    """
    Return a total character budget for the assistant system prompt + extras.

    Falls back to ``fallback_total`` when model context cannot be resolved.
    ``meta`` describes source and intermediate values for logging/diagnostics.
    """
    meta: Dict[str, Any] = {
        "source": "fallback",
        "fallback_total": int(fallback_total),
        "approx_message_chars": int(approx_message_chars_in_request),
    }

    if not ollama_manager or not chat_model or not str(chat_model).strip():
        return int(fallback_total), meta

    tokens: Optional[int] = None
    try:
        tokens = ollama_manager.get_effective_context_token_count(str(chat_model).strip())
    except Exception:
        tokens = None

    if tokens is None or tokens <= 0:
        return int(fallback_total), meta

    char_cap = int(tokens) * max(1, int(chars_per_token_guess))
    char_cap -= max(0, int(reserve_tail))
    char_cap -= max(0, int(approx_message_chars_in_request))
    char_cap = max(_ASSISTANT_DYNAMIC_BUDGET_MIN, min(_ASSISTANT_DYNAMIC_BUDGET_MAX, char_cap))

    meta.update(
        {
            "source": "ollama_context",
            "context_tokens": int(tokens),
            "chars_per_token_guess": int(chars_per_token_guess),
            "computed_before_clamp": char_cap,
            "budget_total": char_cap,
        }
    )
    return char_cap, meta
