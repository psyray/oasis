"""LangGraph CLI: debug separators, LLM debug logging, pipeline banners, tqdm-safe emits, vuln counts."""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, List, Optional

from ...config import LLM_DEBUG_CONTENT_MAX_CHARS

# Default extra when logging blocks that already include emoji in the message text.
EXTRA_NO_EMOJI: Dict[str, Any] = {"emoji": False}

logger = logging.getLogger(__name__)

# --- Debug CLI separators -----------------------------------------------------------

_REPEAT = 18


def separator_graph_step(step_name: str, detail: str = "") -> str:
    """LangGraph pipeline step — uses '='."""
    suf = f" ({detail})" if detail else ""
    mid = f" GRAPH STEP · {step_name}{suf} "
    return "\n" + "=" * _REPEAT + mid + "=" * _REPEAT + "\n"


def separator_vulnerability(vuln_title: str) -> str:
    """One vulnerability type during deep analysis — uses '-'."""
    mid = f" DEEP · VULNERABILITY · {vuln_title} "
    return "\n" + "-" * _REPEAT + mid + "-" * _REPEAT + "\n"


def separator_file_scope(path_label: str, extra: str = "") -> str:
    """One file (scan task or deep file) — uses '~'."""
    suf = f" · {extra}" if extra else ""
    mid = f" FILE · {path_label}{suf} "
    return "\n" + "~" * _REPEAT + mid + "~" * _REPEAT + "\n"


def separator_chunk_llm_turn() -> str:
    """Between LLM debug headers and full prompt/response body."""
    return "\n" + "*" * 72 + "\n"


# --- LLM debug formatting (-d/--debug) ---------------------------------------------

MAX_DEBUG_CONTENT_CHARS = LLM_DEBUG_CONTENT_MAX_CHARS


def truncate_debug_content(
    text: str,
    max_chars: Optional[int] = MAX_DEBUG_CONTENT_CHARS,
) -> str:
    """Truncate for DEBUG logs; ``None`` means no limit.

    Non-positive ``max_chars`` returns no body (empty string), avoiding a useless one-character
    slice plus a truncation footer. Negative values log a warning (misconfigured cap).
    """
    if max_chars is None:
        return text or ""
    if max_chars <= 0:
        if max_chars < 0 and logger.isEnabledFor(logging.WARNING):
            logger.warning(
                "truncate_debug_content: max_chars=%r is not positive; returning empty content",
                max_chars,
            )
        return ""
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


# --- LangGraph CLI banners and emits ----------------------------------------------

def cli_bold(text: str) -> str:
    """ANSI bold for TTY; disabled when ``NO_COLOR`` is set or streams are not interactive."""
    if not text:
        return text
    if os.environ.get("NO_COLOR", "").strip():
        return text
    stderr_tty = getattr(sys.stderr, "isatty", lambda: False)()
    stdout_tty = getattr(sys.stdout, "isatty", lambda: False)()
    return text if not stderr_tty and not stdout_tty else f"\033[1m{text}\033[0m"


PHASE_COUNT = 6

LG_PIPELINE_INFO = (
    "📄 Using LangGraph pipeline — "
    f"① 🔎 {cli_bold('Discover')} → ② 📋 {cli_bold('Scan')} → ③ 🔄 {cli_bold('Expand')} → "
    f"④ 🔬 {cli_bold('Deep')} → ⑤ ✅ {cli_bold('Verify')} → ⑥ 📄 {cli_bold('Report')}"
)

LG_SCAN_TASK_COMPLETE = "🏁 Task done · file=%s · vuln=%s · %.1fs"
LG_NODE_DEEP_QUEUE = "🪲 queue node_deep · expand_iterations=%s (deep block follows)"
LG_LLM_SELECTED = "🤖 LLM for deep pass: %s"
LG_DEEP_VULN_FINISHED = "🏁 Deep done · %s · %.1fs"
LG_VERIFY = "🔎 Verify result · retry_pending=%s · expand_it=%s/%s"
LG_POC = "🔧 PoC assist (optional)"
LG_AFTER_VERIFY = "🚀 Route after verify · next=%s"
LG_DEBUG_SEPARATOR = "🪲 %s"

_RULE = "━" * 72


def cli_emit_section_banner(
    logger: logging.Logger,
    emoji: str,
    title: str,
    detail: str = "",
    *,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Heavy rule + one title line (optional trailing detail after em dash)."""
    tail = f" — {detail}" if detail else ""
    block = f"\n{_RULE}\n{emoji}  {cli_bold(title)}{tail}\n"
    langgraph_emit(logger, logging.INFO, block, extra=extra)


def langgraph_emit(
    logger: logging.Logger,
    level: int,
    msg: str,
    *args: Any,
    pbar: Optional[Any] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Emit one line or block; template already includes any emoji prefix.

    When ``extra`` is passed, keys are preserved; ``emoji`` defaults to False only if absent
    (so callers can override).
    """
    line = msg % args if args else msg
    if pbar is not None and not getattr(pbar, "disable", True):
        pbar.write(line)
    else:
        # Only default ``emoji`` when the caller did not supply it—preserves unrelated
        # structured-logging keys without overwriting their values.
        if extra:
            merged_extra = dict(extra)
            merged_extra.setdefault("emoji", False)
        else:
            merged_extra = dict(EXTRA_NO_EMOJI)
        logger.log(level, line, extra=merged_extra)


def langgraph_emit_phase(
    logger: logging.Logger,
    level: int,
    phase: int,
    emoji: str,
    title: str,
    detail: str,
    pbar: Optional[Any] = None,
    *,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Clear boundary before a LangGraph phase: rule line + ``Phase n/6 · title — detail``.

    Example::

        langgraph_emit_phase(
            logger, logging.INFO, 3, "🔄", "Expand", "context windows", pbar=pbar
        )
    """
    if not 1 <= phase <= PHASE_COUNT:
        raise ValueError(f"phase must be 1..{PHASE_COUNT}, got {phase}")
    body = f"{emoji}  Phase {phase}/{PHASE_COUNT} · {cli_bold(title)} — {detail}"
    block = f"\n{_RULE}\n{body}\n"
    langgraph_emit(logger, level, block, pbar=pbar, extra=extra)


def langgraph_emit_post_pipeline(logger: logging.Logger, *, extra: Optional[Dict[str, Any]] = None) -> None:
    """
    After LangGraph returns: separate file export / dashboard work from the 6 graph phases.
    Placed before ``GENERATING FINAL REPORT`` in the orchestrator.
    """
    block = f"\n{_RULE}\n📦 {cli_bold('Post-pipeline')} — generating reports & publishing artifacts\n"
    langgraph_emit(logger, logging.INFO, block, extra=extra)


def langgraph_emit_report_delivery(
    logger: logging.Logger,
    report_type: Optional[str],
    output_dir: str,
    *,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Success block when report files are written (replaces ad-hoc ``----`` lines)."""
    label = (report_type or "Security").strip() or "Security"
    block = (
        f"\n{_RULE}\n"
        f"✅ {cli_bold(label)} report generated successfully\n"
        f"📄 {label} reports have been generated in: {cli_bold(output_dir)}\n"
    )
    langgraph_emit(logger, logging.INFO, block, extra=extra)


# --- LangGraph vulnerability-type counts --------------------------------------------

def embedding_tasks_vuln_types_total(task_list: List[Dict[str, Any]]) -> int:
    """
    Distinct vuln labels from embedding tasks for executive-summary totals.

    Malformed tasks are skipped. When tasks exist but no label is readable, returns 1.
    """
    unique: set[str] = set()
    for t in task_list:
        v_obj = t.get("vuln")
        if isinstance(v_obj, dict):
            vn = v_obj.get("name") or v_obj.get("tag")
            if isinstance(vn, str) and vn.strip():
                unique.add(vn.strip())
    if unique:
        return max(len(unique), 1)
    # No readable labels in any task: still return at least 1 so downstream totals stay sane.
    return 1


def deep_payload_vuln_types_total(files_by_vuln: Any) -> int:
    """Number of vulnerability buckets in the deep-analysis payload (at least 1)."""
    return max(len(files_by_vuln), 1) if isinstance(files_by_vuln, dict) else 1
