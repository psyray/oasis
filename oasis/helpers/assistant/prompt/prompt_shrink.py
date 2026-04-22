"""Last-resort prompt trimming for the verdict-first assistant system prompt.

The main assembly lives in
:mod:`oasis.helpers.assistant.verdict.verdict_assembly` (re-exported from
:mod:`oasis.helpers.assistant.prompt.chat_context`); this module holds the
label-boundary--aware hard cap so the control flow in the main file stays
easier to follow and this logic can be tested in isolation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Tuple

__all__ = (
    "VerdictPromptHardCapConfig",
    "find_safe_cut_boundary",
    "hard_cap_verdict_prompt_if_needed",
)


@dataclass(frozen=True)
class VerdictPromptHardCapConfig:
    """Configuration for the final hard cap (suffix + section label order)."""

    trunc_suffix: str
    section_label_prefixes: Tuple[str, ...]


def find_safe_cut_boundary(
    body: str, raw_limit: int, section_label_prefixes: Tuple[str, ...]
) -> int:
    """Return the largest index ``<= raw_limit`` that is a safe cut boundary.

    "Safe" means the remaining prefix ends at a section boundary — we never
    want to chop a label or the opening of a JSON block mid-token. Probe
    order:

      1. Immediately before a section label marker (``"\\n\\n" + label``).
      2. Last paragraph break (``"\\n\\n"``) before ``raw_limit``.
      3. Last line break (``"\\n"``) before ``raw_limit``.

    Returns ``-1`` when none of the above exist (caller must fall back to a
    raw slice).
    """
    if raw_limit <= 0:
        return -1
    best = -1
    for label in section_label_prefixes:
        idx = body.rfind("\n\n" + label, 0, raw_limit)
        if idx > best:
            best = idx
    if best >= 0:
        return best
    paragraph = body.rfind("\n\n", 0, raw_limit)
    return paragraph if paragraph >= 0 else body.rfind("\n", 0, raw_limit)


def hard_cap_verdict_prompt_if_needed(
    body: str,
    total_budget: int,
    validation_len: int,
    *,
    config: VerdictPromptHardCapConfig,
    logger: logging.Logger,
) -> str:
    """Trim ``body`` to ``total_budget`` at a safe boundary, then append suffix.

    This is the absolute last pass after all section-aware compactions. A raw
    character slice would break section labels and JSON; see
    :func:`find_safe_cut_boundary`.
    """
    trunc_suffix = config.trunc_suffix
    if len(body) <= total_budget:
        return body
    if total_budget <= len(trunc_suffix):
        logger.warning(
            "Assistant system prompt budget is smaller than the truncation "
            "suffix (budget=%s body=%s validation_len=%s); returning suffix only.",
            total_budget,
            len(body),
            validation_len,
        )
        return trunc_suffix[: max(0, total_budget)]
    raw_limit = total_budget - len(trunc_suffix)
    cut_at = find_safe_cut_boundary(
        body, raw_limit, config.section_label_prefixes
    )
    cut_kind = "label-boundary"
    if cut_at < 0:
        cut_at = raw_limit
        cut_kind = "raw-slice"
    logger.warning(
        "Assistant system prompt still over budget after all compaction passes "
        "(budget=%s body=%s validation_len=%s); hard-capping tail at %s=%s.",
        total_budget,
        len(body),
        validation_len,
        cut_kind,
        cut_at,
    )
    prefix = body[:cut_at]
    return prefix.rstrip() + trunc_suffix
