"""
Single source of truth for **assistant chat prompt contracts** that span
``oasis.web`` and the helper modules: section labels, truncation markers, soft
subbudget ratios, and compact-report sizing.

Import these symbols from here when adding a new call-site; do not duplicate
string literals. :mod:`oasis.helpers.assistant.prompt.chat_context` re-exports
assembly APIs from :mod:`oasis.helpers.assistant.verdict.verdict_assembly` and
validation from :mod:`oasis.helpers.assistant.verdict.verdict_validation` for
backward-compatible imports. :mod:`oasis.helpers.assistant.prompt.report_excerpt`
consumes compact sizing from here.

**Also documented elsewhere (not duplicated here):**
  - :mod:`oasis.helpers.assistant.prompt.context_budget` — dynamic char clamp,
    :class:`~oasis.helpers.assistant.prompt.context_budget.AssistantBudgetMeta`
  - :mod:`oasis.helpers.assistant.prompt.prompt_shrink` — label-boundary hard cap config
  - :class:`oasis.ollama_manager.OllamaManager` — ``ps()`` / context token resolution
"""

from __future__ import annotations

from typing import Dict, Final, Optional, Tuple

# ---------------------------------------------------------------------------
# Verdict-first system prompt — section labels (exact strings, LLM-visible)
# ---------------------------------------------------------------------------
FINDING_VALIDATION_LABEL: Final = "FINDING_VALIDATION_JSON:"
SELECTED_FINDING_LABEL: Final = "SELECTED_FINDING_JSON:"
RETRIEVAL_CONTEXT_LABEL: Final = "RETRIEVAL_CONTEXT:"
REPORT_SUMMARY_LABEL: Final = "REPORT_SUMMARY:"
USER_NOTES_LABEL: Final = "USER_LOCAL_TRIAGE_NOTES:"

# Order emitted by assembly (for documentation / hard-cap label scan).
VERDICT_SECTION_LABEL_ORDER: Final[Tuple[str, ...]] = (
    FINDING_VALIDATION_LABEL,
    SELECTED_FINDING_LABEL,
    RETRIEVAL_CONTEXT_LABEL,
    REPORT_SUMMARY_LABEL,
    USER_NOTES_LABEL,
)

# ---------------------------------------------------------------------------
# Truncation markers (chat sections vs report excerpt may share the same text)
# ---------------------------------------------------------------------------
CHAT_SECTION_TRUNC_SUFFIX: Final = "\n…(truncated)…"
CHAT_RAG_TRUNC_SUFFIX: Final = "\n…(RAG truncated)…"
CHAT_EXCERPT_TRUNC_SUFFIX: Final = "\n…(summary truncated)…"
# Kept in sync with chat suffix for a consistent UX in compact Markdown.
REPORT_COMPACT_TRUNCATION_SUFFIX: Final = "\n…(truncated)…"

# ---------------------------------------------------------------------------
# Soft subbudget ratios (must sum to <= 1.0 - VALIDATION_MAX_RATIO)
# ---------------------------------------------------------------------------
VALIDATION_MAX_RATIO: Final = 0.50

SUBBUDGET_SELECTED_FINDING_RATIO: Final = 0.30
SUBBUDGET_RAG_RATIO: Final = 0.25
SUBBUDGET_REPORT_SUMMARY_RATIO: Final = 0.15
SUBBUDGET_USER_LABELS_RATIO: Final = 0.05
# Cap on report summary soft budget (chars) even when total_budget is huge.
SUBBUDGET_REPORT_SUMMARY_MAX: Final = 15_000

# ---------------------------------------------------------------------------
# Validation JSON compaction (chat-sized clip + evidence prefix under pressure)
# ---------------------------------------------------------------------------
VALIDATION_EVIDENCE_PREFIX_KEEP: Final = 3

VALIDATION_EVIDENCE_PRIORITY: Final[Tuple[str, ...]] = (
    "errors",
    "citations",
    "warnings",
    "notes",
)

# Per-list caps for :func:`compact_validation_for_chat` (evidence lists).
CHAT_VALIDATION_LIST_CAPS: Final[Dict[str, int]] = {
    "entry_points": 8,
    "execution_paths": 6,
    "taint_flows": 6,
    "mitigations": 6,
    "authz_checks": 8,
    "control_checks": 12,
    "config_findings": 10,
    "citations": 10,
    "errors": 4,
}

# ---------------------------------------------------------------------------
# Report summary compaction (:func:`compact_report_excerpt` sizing before max_chars)
# ---------------------------------------------------------------------------
COMPACT_MAX_FILES_LISTED: Final = 25
COMPACT_MAX_TOP_FINDINGS: Final = 10

COMPACT_SEVERITY_RANK: Final[Dict[str, int]] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# Chars per token for converting Ollama ``num_ctx`` (tokens) to a *character*
# budget. **Conservative (high) values shrink the char cap** and reduce
# token-overflow risk; lower values (e.g. 3) reserve more space for a given
# reported context, which can help on small ``num_ctx`` models but may
# overshoot real tokenizer usage. Override per deployment or model family
# via :data:`ASSISTANT_CHARS_PER_TOKEN_BY_MODEL_PREFIX` (longest matching
# lowercase prefix wins) or by passing an explicit
# ``chars_per_token_guess`` to :func:`oasis.helpers.assistant.prompt.context_budget.assistant_total_system_budget_chars`.
ASSISTANT_CHARS_PER_TOKEN_DEFAULT: Final = 4
# Example: ``{"qwen2.5": 3, "llama3:": 3}`` — empty by default; edit in fork/config if needed.
ASSISTANT_CHARS_PER_TOKEN_BY_MODEL_PREFIX: Final[Dict[str, int]] = {}

# Aggregate merge in :func:`oasis.helpers.assistant.web.web_prepare.build_report_summary_payload`
# needs a **temporary** per-merge char budget. This factor × the final report-summary
# subbudget gives merge headroom; :func:`oasis.helpers.assistant.prompt.report_excerpt.compact_report_excerpt`
# enforces the real subbudget (single cap for the system prompt). Without slack,
# multi-file merge would pre-truncate more aggressively than the final Markdown pass.
REPORT_SUMMARY_AGGREGATE_MERGE_BUDGET_FACTOR: Final = 2


def resolve_assistant_chars_per_token_guess(chat_model: str) -> int:
    """Default chars/token for ``chat_model``, with optional longest-prefix override."""
    m = (chat_model or "").strip().lower()
    if not m:
        return int(ASSISTANT_CHARS_PER_TOKEN_DEFAULT)
    best_value: Optional[int] = None
    best_plen: int = -1
    for raw_prefix, val in ASSISTANT_CHARS_PER_TOKEN_BY_MODEL_PREFIX.items():
        prefix = (raw_prefix or "").strip().lower()
        if not prefix or not isinstance(val, int) or val <= 0:
            continue
        if m.startswith(prefix) and len(prefix) > best_plen:
            best_plen = len(prefix)
            best_value = val
    if best_value is not None:
        return best_value
    return int(ASSISTANT_CHARS_PER_TOKEN_DEFAULT)


def verdict_subbudget_ratios() -> Dict[str, float]:
    """Return the ratio map used by :func:`compute_verdict_first_subbudgets` (exposed for tests)."""
    return {
        "selected_finding": SUBBUDGET_SELECTED_FINDING_RATIO,
        "rag": SUBBUDGET_RAG_RATIO,
        "report_summary": SUBBUDGET_REPORT_SUMMARY_RATIO,
        "user_labels": SUBBUDGET_USER_LABELS_RATIO,
    }


__all__ = [
    "ASSISTANT_CHARS_PER_TOKEN_BY_MODEL_PREFIX",
    "ASSISTANT_CHARS_PER_TOKEN_DEFAULT",
    "CHAT_EXCERPT_TRUNC_SUFFIX",
    "CHAT_RAG_TRUNC_SUFFIX",
    "CHAT_SECTION_TRUNC_SUFFIX",
    "CHAT_VALIDATION_LIST_CAPS",
    "COMPACT_MAX_FILES_LISTED",
    "COMPACT_MAX_TOP_FINDINGS",
    "COMPACT_SEVERITY_RANK",
    "FINDING_VALIDATION_LABEL",
    "REPORT_COMPACT_TRUNCATION_SUFFIX",
    "REPORT_SUMMARY_AGGREGATE_MERGE_BUDGET_FACTOR",
    "REPORT_SUMMARY_LABEL",
    "RETRIEVAL_CONTEXT_LABEL",
    "SELECTED_FINDING_LABEL",
    "SUBBUDGET_RAG_RATIO",
    "SUBBUDGET_REPORT_SUMMARY_MAX",
    "SUBBUDGET_REPORT_SUMMARY_RATIO",
    "SUBBUDGET_SELECTED_FINDING_RATIO",
    "SUBBUDGET_USER_LABELS_RATIO",
    "USER_NOTES_LABEL",
    "VALIDATION_EVIDENCE_PREFIX_KEEP",
    "VALIDATION_EVIDENCE_PRIORITY",
    "VALIDATION_MAX_RATIO",
    "VERDICT_SECTION_LABEL_ORDER",
    "resolve_assistant_chars_per_token_guess",
    "verdict_subbudget_ratios",
]
