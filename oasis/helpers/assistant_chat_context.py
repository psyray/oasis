"""Utilities for assistant chat system prompt (finding validation JSON sizing)."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

FINDING_VALIDATION_LABEL = "FINDING_VALIDATION_JSON:"


def serialize_finding_validation(validation: Dict[str, Any]) -> str:
    """Compact JSON for system prompts."""
    return json.dumps(validation, ensure_ascii=False, separators=(",", ":"))


def trim_finding_validation_json(text: str, max_chars: int) -> str:
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    suffix = "\n…(truncated)…"
    return text[: max(0, max_chars - len(suffix))] + suffix


def shrink_rag_block(rag_block: str, target_max_len: int) -> str:
    if target_max_len <= 0:
        return ""
    if len(rag_block) <= target_max_len:
        return rag_block
    suffix = "\n…(RAG truncated)…"
    return rag_block[: max(0, target_max_len - len(suffix))] + suffix


def _trim_validation_for_budget(
    *,
    prompt_core: str,
    val_raw: str,
    rag_section: str,
    total_budget: int,
) -> tuple[str, str]:
    """Rebuild validation section and body when trimming JSON to fit *total_budget*."""
    prefix = prompt_core + "\n\n" + FINDING_VALIDATION_LABEL + "\n"
    room_for_val = total_budget - len(prefix) - len(rag_section)
    trimmed = trim_finding_validation_json(val_raw, max(0, room_for_val))
    if len(trimmed) < len(val_raw):
        logger.warning(
            "FINDING_VALIDATION_JSON truncated to fit system budget (len=%s)",
            len(trimmed),
        )
    val_section = "\n\n" + FINDING_VALIDATION_LABEL + "\n" + trimmed
    return val_section, prompt_core + val_section + rag_section


def append_validation_then_balance_rag(
    *,
    prompt_core: str,
    finding_validation: Optional[Dict[str, Any]],
    rag_block: str,
    total_budget: int,
) -> str:
    """Append validation JSON and RAG; trim RAG first, then validation. Logs when validation is truncated."""
    val_section = ""
    val_raw = ""
    if finding_validation:
        val_raw = serialize_finding_validation(finding_validation)
        val_section = "\n\n" + FINDING_VALIDATION_LABEL + "\n" + val_raw

    rag_section = ""
    if rag_block:
        rag_section = "\n\nRETRIEVAL_CONTEXT:\n" + rag_block

    body = prompt_core + val_section + rag_section
    if len(body) <= total_budget:
        return body

    if rag_block:
        overhead = len(body) - total_budget
        rag_shrunk = shrink_rag_block(rag_block, max(0, len(rag_block) - overhead))
        rag_section = "\n\nRETRIEVAL_CONTEXT:\n" + rag_shrunk
        body = prompt_core + val_section + rag_section

    if len(body) > total_budget and finding_validation and val_raw:
        val_section, body = _trim_validation_for_budget(
            prompt_core=prompt_core,
            val_raw=val_raw,
            rag_section=rag_section,
            total_budget=total_budget,
        )

    if len(body) > total_budget:
        body = body[:total_budget] + "\n…(truncated)…"
    return body
