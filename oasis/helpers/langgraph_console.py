"""LangGraph CLI: pipeline banner, numbered phase boundaries, tqdm-safe lines (no ``[LangGraph]`` tag)."""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Optional


def cli_bold(text: str) -> str:
    """ANSI bold for TTY; disabled when ``NO_COLOR`` is set or streams are not interactive."""
    if not text:
        return text
    if os.environ.get("NO_COLOR", "").strip():
        return text
    stderr_tty = getattr(sys.stderr, "isatty", lambda: False)()
    stdout_tty = getattr(sys.stdout, "isatty", lambda: False)()
    return text if not stderr_tty and not stdout_tty else f"\033[1m{text}\033[0m"

# Six canonical LangGraph nodes (PoC is optional auxiliary, not numbered here).
PHASE_COUNT = 6

# Startup banner: circled numbers + emoji per step (matches graph order).
LG_PIPELINE_INFO = (
    "📄 Using LangGraph pipeline — "
    f"① 🔎 {cli_bold('Discover')} → ② 📋 {cli_bold('Scan')} → ③ 🔄 {cli_bold('Expand')} → "
    f"④ 🔬 {cli_bold('Deep')} → ⑤ ✅ {cli_bold('Verify')} → ⑥ 📄 {cli_bold('Report')}"
)

# --- Sub-line templates (printf where needed) ---
LG_SCAN_TASK_COMPLETE = "🏁 Task done · file=%s · vuln=%s · %.1fs"
LG_NODE_DEEP_QUEUE = "🪲 queue node_deep · expand_iterations=%s (deep block follows)"
LG_LLM_SELECTED = "🤖 LLM for deep pass: %s"
LG_DEEP_VULN_FINISHED = "🏁 Deep done · %s · %.1fs"
LG_VERIFY = "🔎 Verify result · retry_pending=%s · expand_it=%s/%s"
LG_POC = "🔧 PoC assist (optional)"
LG_AFTER_VERIFY = "🚀 Route after verify · next=%s"
# Debug: prefix multi-line separator blocks from debug_cli_separators
LG_DEBUG_SEPARATOR = "🪲 %s"

_RULE = "━" * 72


def cli_emit_section_banner(
    logger: logging.Logger,
    emoji: str,
    title: str,
    detail: str = "",
) -> None:
    """Heavy rule + one title line (optional trailing detail after em dash)."""
    tail = f" — {detail}" if detail else ""
    block = f"\n{_RULE}\n{emoji}  {cli_bold(title)}{tail}\n"
    langgraph_emit(logger, logging.INFO, block)


def langgraph_emit(
    logger: logging.Logger,
    level: int,
    msg: str,
    *args: Any,
    pbar: Optional[Any] = None,
) -> None:
    """Emit one line or block; template already includes any emoji prefix."""
    line = msg % args if args else msg
    if pbar is not None and not getattr(pbar, "disable", True):
        pbar.write(line)
    else:
        logger.log(level, line, extra={"emoji": False})


def langgraph_emit_phase(
    logger: logging.Logger,
    level: int,
    phase: int,
    emoji: str,
    title: str,
    detail: str,
    pbar: Optional[Any] = None,
) -> None:
    """
    Clear boundary before a LangGraph phase: rule line + ``Phase n/6 · title — detail``.
    """
    if not 1 <= phase <= PHASE_COUNT:
        raise ValueError(f"phase must be 1..{PHASE_COUNT}, got {phase}")
    body = f"{emoji}  Phase {phase}/{PHASE_COUNT} · {cli_bold(title)} — {detail}"
    block = f"\n{_RULE}\n{body}\n"
    langgraph_emit(logger, level, block, pbar=pbar)


def langgraph_emit_post_pipeline(logger: logging.Logger) -> None:
    """
    After LangGraph returns: separate file export / dashboard work from the 6 graph phases.
    Placed before ``GENERATING FINAL REPORT`` in the orchestrator.
    """
    block = f"\n{_RULE}\n📦 {cli_bold('Post-pipeline')} — generating reports & publishing artifacts\n"
    langgraph_emit(logger, logging.INFO, block)


def langgraph_emit_report_delivery(
    logger: logging.Logger,
    report_type: Optional[str],
    output_dir: str,
) -> None:
    """Success block when report files are written (replaces ad-hoc ``----`` lines)."""
    label = (report_type or "Security").strip() or "Security"
    block = (
        f"\n{_RULE}\n"
        f"✅ {cli_bold(label)} report generated successfully\n"
        f"📄 {label} reports have been generated in: {cli_bold(output_dir)}\n"
    )
    langgraph_emit(logger, logging.INFO, block)
