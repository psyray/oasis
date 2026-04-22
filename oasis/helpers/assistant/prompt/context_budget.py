"""Compute assistant system-prompt character budget using Ollama model context hints.

Tuning index: :mod:`oasis.helpers.assistant.prompt.prompt_tuning`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

if TYPE_CHECKING:
    from oasis.ollama_manager import OllamaManager

from .prompt_tuning import (
    resolve_assistant_chars_per_token_guess,
)

_ASSISTANT_SYSTEM_RESERVE_MESSAGES_AND_OUTPUT = 4096

# Clamp dynamic budget between these so misdetected contexts do not explode RAM or cripple UX.
_ASSISTANT_DYNAMIC_BUDGET_MIN = 32000
_ASSISTANT_DYNAMIC_BUDGET_MAX = 256000


@dataclass
class AssistantBudgetMeta:
    """Stable contract for :func:`assistant_total_system_budget_chars` diagnostics (logs / warnings)."""

    source: str = "fallback"
    fallback_total: int = 0
    approx_message_chars: int = 0
    context_tokens: Optional[int] = None
    context_source: str = ""
    chars_per_token_guess: Optional[int] = None
    computed_before_clamp: Optional[int] = None
    budget_total: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Log / JSON shape (keys kept stable for downstream parsers)."""
        d: Dict[str, Any] = {
            "source": self.source,
            "fallback_total": self.fallback_total,
            "approx_message_chars": self.approx_message_chars,
            "context_source": self.context_source,
            "context_tokens": self.context_tokens,
            "chars_per_token_guess": self.chars_per_token_guess,
            "computed_before_clamp": self.computed_before_clamp,
            "budget_total": self.budget_total,
        }
        return d

    def __getitem__(self, key: str) -> Any:
        if key not in {
            "source",
            "fallback_total",
            "approx_message_chars",
            "context_source",
            "context_tokens",
            "chars_per_token_guess",
            "computed_before_clamp",
            "budget_total",
        }:
            raise KeyError(key)
        return getattr(self, key)

    def ollama_runtime_num_ctx(self) -> Optional[int]:
        """Runtime token count when the budget was derived from Ollama, else None."""
        if self.source != "ollama_context":
            return None
        t = self.context_tokens
        return t if isinstance(t, int) and t > 0 else None

    def effective_chars_per_token(self) -> Optional[int]:
        """Integer chars/token heuristic for over-budget comparison (tolerate legacy str)."""
        c = self.chars_per_token_guess
        if isinstance(c, int) and c > 0:
            return c
        if isinstance(c, str):
            stripped = c.strip()
            if stripped.isdigit():
                n = int(stripped)
                if n > 0:
                    return n
        return None


def assistant_total_system_budget_chars(
    *,
    fallback_total: int,
    ollama_manager: Optional["OllamaManager"],
    chat_model: str,
    approx_message_chars_in_request: int,
    chars_per_token_guess: Optional[int] = None,
    reserve_tail: int = _ASSISTANT_SYSTEM_RESERVE_MESSAGES_AND_OUTPUT,
) -> Tuple[int, AssistantBudgetMeta]:
    """
    Return a total character budget for the assistant system prompt + extras.

    Falls back to ``fallback_total`` when model context cannot be resolved.
    The second return value is a typed :class:`AssistantBudgetMeta` (use
    :meth:`AssistantBudgetMeta.to_dict` for the legacy log dict shape).

    ``chars_per_token_guess``: if omitted or non-positive, uses
    :func:`oasis.helpers.assistant.prompt.prompt_tuning.resolve_assistant_chars_per_token_guess`
    (default + :data:`oasis.helpers.assistant.prompt.prompt_tuning.ASSISTANT_CHARS_PER_TOKEN_BY_MODEL_PREFIX`).
    """
    base = AssistantBudgetMeta(
        source="fallback",
        fallback_total=fallback_total,
        approx_message_chars=approx_message_chars_in_request,
    )

    if not ollama_manager or not chat_model or not chat_model.strip():
        return fallback_total, base

    cm = chat_model.strip()
    cpt: int
    if chars_per_token_guess is not None and int(chars_per_token_guess) > 0:
        cpt = int(chars_per_token_guess)
    else:
        cpt = resolve_assistant_chars_per_token_guess(cm)

    tokens: Optional[int] = None
    context_source: str = ""
    tokens, context_source = ollama_manager.get_effective_context_token_count_with_source(
        cm
    )

    if tokens is None or tokens <= 0:
        base.context_source = context_source or ""
        return fallback_total, base

    raw_char_cap = int(tokens) * max(1, cpt)
    raw_char_cap -= max(0, reserve_tail)
    raw_char_cap -= max(0, approx_message_chars_in_request)
    char_cap = max(
        _ASSISTANT_DYNAMIC_BUDGET_MIN,
        min(_ASSISTANT_DYNAMIC_BUDGET_MAX, raw_char_cap),
    )

    ollama_meta = AssistantBudgetMeta(
        source="ollama_context",
        fallback_total=fallback_total,
        approx_message_chars=approx_message_chars_in_request,
        context_tokens=int(tokens),
        context_source=context_source or "",
        chars_per_token_guess=cpt,
        computed_before_clamp=raw_char_cap,
        budget_total=char_cap,
    )
    return char_cap, ollama_meta


__all__ = [
    "AssistantBudgetMeta",
    "assistant_total_system_budget_chars",
]
