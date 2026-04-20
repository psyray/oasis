"""Format LLM request/response lines for CLI debug (-d/--debug only)."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from ..config import LLM_DEBUG_CONTENT_MAX_CHARS
from .debug_cli_separators import separator_chunk_llm_turn

# Default cap when not in full debug transcript mode (avoid huge INFO logs accidentally).
MAX_DEBUG_CONTENT_CHARS = LLM_DEBUG_CONTENT_MAX_CHARS


def truncate_debug_content(
    text: str,
    max_chars: Optional[int] = MAX_DEBUG_CONTENT_CHARS,
) -> str:
    if max_chars is None:
        return text or ""
    if not text:
        return ""
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return f"{text[:max_chars]}\n... [truncated {omitted} chars]"


def llm_debug_log_request(
    logger: logging.Logger,
    *,
    mode: str,
    model: str,
    file_path: Optional[str],
    vuln_name: Optional[str],
    structured: bool,
    attempt: int,
    prompt: str,
    full_content: bool = False,
) -> None:
    cap: Optional[int] = None if full_content else MAX_DEBUG_CONTENT_CHARS
    logger.debug(
        "%s[LLM request] mode=%s model=%s file=%s vuln=%s structured=%s attempt=%s prompt_chars=%s%s%s",
        separator_chunk_llm_turn(),
        mode,
        model,
        file_path or "?",
        vuln_name or "?",
        structured,
        attempt,
        len(prompt),
        separator_chunk_llm_turn(),
        truncate_debug_content(prompt, cap),
    )


def llm_debug_log_response(
    logger: logging.Logger,
    *,
    model: str,
    file_path: Optional[str],
    vuln_name: Optional[str],
    raw_content: str,
    message: Optional[Dict[str, Any]] = None,
    full_content: bool = False,
) -> None:
    extra = ""
    cap: Optional[int] = None if full_content else MAX_DEBUG_CONTENT_CHARS
    if message and isinstance(message, dict):
        if thinking := message.get("thinking"):
            extra = f"{separator_chunk_llm_turn()}[LLM thinking trace]{separator_chunk_llm_turn()}{truncate_debug_content(str(thinking), cap)}"
    logger.debug(
        "%s[LLM response] model=%s file=%s vuln=%s content_chars=%s%s%s%s",
        separator_chunk_llm_turn(),
        model,
        file_path or "?",
        vuln_name or "?",
        len(raw_content or ""),
        separator_chunk_llm_turn(),
        extra,
        truncate_debug_content(raw_content or "", cap),
    )
