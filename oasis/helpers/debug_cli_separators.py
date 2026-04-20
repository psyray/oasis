"""Distinct visual separators for ``-d`` / ``--debug`` CLI output."""

from __future__ import annotations

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
