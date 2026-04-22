"""PoC assist: JSON digests, hints markdown, stage logging, and chat options."""

from __future__ import annotations

import copy
import json
import logging
from typing import Any, Dict, List, Optional

from ...config import (
    CHUNK_ANALYZE_TIMEOUT,
    CHUNK_DEEP_NUM_PREDICT,
    POC_DIGEST_JSON_MAX_CHARS,
    POC_HINTS_MAX_CHARS,
    POC_STAGE_LOG_MAX_CHARS,
)
from ..langgraph_cli import truncate_debug_content

__all__ = [
    "POC_DIGEST_JSON_MAX_CHARS",
    "POC_HINTS_MAX_CHARS",
    "POC_STAGE_LOG_MAX_CHARS",
    "build_compact_findings_digest",
    "build_poc_hints_markdown",
    "finalize_poc_digest_json",
    "maybe_debug_log_poc_stage_output",
    "poc_assist_chat_options",
    "pop_last_digest_leaf_for_vuln",
    "pop_last_findings_digest_leaf",
    "truncate_poc_stage_log_for_log",
]


# --- PoC digest JSON (size-limited, valid JSON) -------------------------------------

def build_compact_findings_digest(all_results: Dict[str, Any]) -> Dict[str, Any]:
    """Structured summary of ``all_results`` for PoC prompts (nested dicts/lists only)."""
    compact: Dict[str, Any] = {}
    for vuln_name, rows in (all_results or {}).items():
        if not isinstance(rows, list):
            continue
        per_vuln: List[Dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            fp = row.get("file_path") or ""
            chunks = row.get("structured_chunks") or []
            chunk_summaries: List[Dict[str, Any]] = []
            for ch in chunks:
                if not isinstance(ch, dict):
                    continue
                findings = ch.get("findings") or []
                slim_findings: List[Dict[str, Any]] = [
                    {
                        "title": (fn.get("title") or "")[:400],
                        "vulnerable_code": (fn.get("vulnerable_code") or "")[
                            :1200
                        ],
                        "explanation": (fn.get("explanation") or "")[:800],
                        "example_payloads": (fn.get("example_payloads") or [])[
                            :5
                        ],
                        "exploitation_steps": (
                            fn.get("exploitation_steps") or []
                        )[:8],
                        "entry_point": (fn.get("entry_point") or "")[:400],
                    }
                    for fn in findings
                    if isinstance(fn, dict)
                ]
                chunk_summaries.append(
                    {
                        "chunk_lines": [ch.get("start_line"), ch.get("end_line")],
                        "findings": slim_findings,
                    }
                )
            per_vuln.append({"file_path": fp, "chunks": chunk_summaries})
        compact[vuln_name] = per_vuln
    return compact


def pop_last_findings_digest_leaf(compact: Dict[str, Any]) -> bool:
    """
    Remove one leaf finding (or empty container) from the digest tree.

    Returns False when nothing remains to remove.
    """
    if not compact:
        return False
    for vn in sorted(compact.keys(), reverse=True):
        return pop_last_digest_leaf_for_vuln(compact, vn)
    return False


def pop_last_digest_leaf_for_vuln(compact, vn):
    rows = compact.get(vn)
    if not isinstance(rows, list) or not rows:
        del compact[vn]
        return True
    row = rows[-1]
    if not isinstance(row, dict):
        rows.pop()
        return True
    chunks = row.get("chunks") if isinstance(row.get("chunks"), list) else []
    if chunks:
        ch = chunks[-1]
        if isinstance(ch, dict):
            findings = ch.get("findings")
            if isinstance(findings, list) and findings:
                findings.pop()
                return True
        chunks.pop()
        return True
    rows.pop()
    return True


def finalize_poc_digest_json(compact: Dict[str, Any], max_chars: int) -> str:
    """
    Return a JSON string <= ``max_chars`` that is always valid JSON.

    Wraps digest metadata so the LLM knows when rows were dropped for budget reasons.
    """
    trimmed = copy.deepcopy(compact)
    orig_len = len(json.dumps(trimmed, ensure_ascii=False))
    truncated = False

    while len(json.dumps(trimmed, ensure_ascii=False)) > max_chars:
        truncated = True
        if not pop_last_findings_digest_leaf(trimmed):
            trimmed = {}
            break

    envelope: Dict[str, Any] = {
        "truncated_for_llm_prompt_budget": truncated,
        "original_approx_json_chars": orig_len,
        "budget_chars": max_chars,
        "findings_digest": trimmed,
    }
    raw = json.dumps(envelope, ensure_ascii=False)
    if len(raw) <= max_chars:
        return raw

    envelope = {
        "truncated_for_llm_prompt_budget": True,
        "original_approx_json_chars": orig_len,
        "budget_chars": max_chars,
        "note": (
            "Digest still exceeded the JSON character budget after dropping leaf findings; "
            "increase OASIS_POC_DIGEST_JSON_MAX_CHARS if you need more context."
        ),
        "findings_digest": {},
    }
    raw = json.dumps(envelope, ensure_ascii=False)
    if len(raw) <= max_chars:
        return raw
    return json.dumps({"truncated_for_llm_prompt_budget": True, "findings_digest": {}}, ensure_ascii=False)


# --- PoC pipeline (hints, logging, options) ----------------------------------------

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
    """Non-executable bullet hints from structured findings (global character budget).

    Example::

        md = build_poc_hints_markdown(
            {"sqli": [{"file_path": "app.py", "structured_chunks": [...]}]},
            max_chars=8000,
        )
    """
    budget = POC_HINTS_MAX_CHARS if max_chars is None else max_chars
    if not all_results:
        return "\n".join(
            [
                "## PoC hints (from findings only)",
                "",
                "_Non-executable guidance synthesized from structured findings; OASIS does not execute code in this mode._",
                "",
                "- Review structured findings per vulnerability and craft a minimal repro in an isolated sandbox.",
            ]
        )

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
