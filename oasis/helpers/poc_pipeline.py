"""
PoC assist pipeline: budgets, markdown generation, and stage logging.

Runtime limits are defined once in ``oasis.config`` and re-exported here so PoC-related
policy (digest / hints / logs) lives behind a single module surface.

Tuning: see ``oasis/config.py`` module docstring — **Reference — OASIS_* env vars** table
(PoC vs structured-output degeneracy); keep env names aligned with README and tests.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from ..config import (
    CHUNK_ANALYZE_TIMEOUT,
    CHUNK_DEEP_NUM_PREDICT,
    POC_DIGEST_JSON_MAX_CHARS,
    POC_HINTS_MAX_CHARS,
    POC_STAGE_LOG_MAX_CHARS,
)
from .llm_debug_log import truncate_debug_content

__all__ = [
    "POC_DIGEST_JSON_MAX_CHARS",
    "POC_HINTS_MAX_CHARS",
    "POC_STAGE_LOG_MAX_CHARS",
    "build_poc_hints_markdown",
    "maybe_debug_log_poc_stage_output",
    "poc_assist_chat_options",
    "truncate_poc_stage_log_for_log",
]


def poc_assist_chat_options() -> Dict[str, Any]:
    """Ollama options aligned with structured chunk analysis (timeout ms, generation budget)."""
    return {"timeout": CHUNK_ANALYZE_TIMEOUT * 1000, "num_predict": CHUNK_DEEP_NUM_PREDICT}


def truncate_poc_stage_log_for_log(text: str) -> str:
    """Truncate PoC markdown for DEBUG logs (not the stored report payload)."""
    return truncate_debug_content(text, POC_STAGE_LOG_MAX_CHARS)


def maybe_debug_log_poc_stage_output(logger: logging.Logger, args: Any, text: str) -> None:
    """Emit PoC markdown to DEBUG when ``--debug`` and not ``--silent`` (size-capped)."""
    if not text.strip():
        return
    log_text = truncate_poc_stage_log_for_log(text) if len(text) > POC_STAGE_LOG_MAX_CHARS else text
    if getattr(args, "debug", False) and not getattr(args, "silent", False):
        logger.debug("PoC stage output:\n%s", log_text)


def build_poc_hints_markdown(
    all_results: Dict[str, Any],
    *,
    max_chars: Optional[int] = None,
) -> str:
    """Non-executable bullet hints from structured findings (global character budget)."""
    budget = POC_HINTS_MAX_CHARS if max_chars is None else max_chars
    lines = [
        "## PoC hints (from findings only)",
        "",
        "_Non-executable guidance synthesized from structured findings; OASIS does not execute code in this mode._",
        "",
    ]
    total_chars = len("\n".join(lines))

    def _append_line(text: str) -> bool:
        nonlocal total_chars
        add = (1 if lines else 0) + len(text)
        if total_chars + add > budget:
            return False
        lines.append(text)
        total_chars += add
        return True

    for vn, rows in (all_results or {}).items():
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            fp = row.get("file_path") or ""
            for ch in row.get("structured_chunks") or []:
                if not isinstance(ch, dict):
                    continue
                for fn in ch.get("findings") or []:
                    if not isinstance(fn, dict):
                        continue
                    title = (fn.get("title") or "Finding").strip()
                    if not _append_line(f"- **{vn}** (`{fp}`): {title}"):
                        return "\n".join(lines)
                    for step in (fn.get("exploitation_steps") or [])[:5]:
                        if isinstance(step, str) and step.strip() and not _append_line(f"  - Step: {step.strip()[:500]}"):
                            return "\n".join(lines)
                    for pl in (fn.get("example_payloads") or [])[:3]:
                        if isinstance(pl, str) and pl.strip() and not _append_line(f"  - Example payload: `{pl.strip()[:300]}`"):
                            return "\n".join(lines)
    if len(lines) <= 4:
        lines.append("- Review structured findings per vulnerability and craft a minimal repro in an isolated sandbox.")
    return "\n".join(lines)
