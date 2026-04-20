"""Executive-summary scan progress: normalize JSON payloads and markdown sections."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .progress_constants import (
    SCAN_PROGRESS_STATUS_EXPLICIT,
    SCAN_PROGRESS_STATUS_MARKDOWN_LABELS,
)


def scan_progress_nonneg_int(raw: Any, *, default: int = 0) -> int:
    """Parse a counter from JSON progress payloads; clamp to non-negative ints."""
    try:
        return max(int(raw), 0)
    except (TypeError, ValueError):
        return max(default, 0)


def scan_progress_vulnerability_counts(progress: Dict[str, Any]) -> Tuple[int, int]:
    """Return (completed, total) with total >= completed."""
    completed = scan_progress_nonneg_int(progress.get("completed_vulnerabilities"), default=0)
    total = scan_progress_nonneg_int(progress.get("total_vulnerabilities"), default=0)
    return completed, max(total, completed)


def notifier_vulnerability_counts(
    progress: Dict[str, Any],
    *,
    fallback_total: Optional[Any],
) -> Tuple[int, int]:
    """Normalize completed/total for realtime notifier (supports fallback when total omitted)."""
    completed = scan_progress_nonneg_int(progress.get("completed_vulnerabilities"), default=0)
    total_raw = progress.get("total_vulnerabilities")
    try:
        candidate = total_raw if total_raw is not None else fallback_total
        total = int(candidate) if candidate is not None else completed
    except (TypeError, ValueError):
        total = completed
    total = max(total, 0)
    total = max(total, completed)
    return completed, total


def phase_row_counts(row: Dict[str, Any]) -> Tuple[int, int]:
    """Normalize completed/total for a pipeline phase row."""
    c = scan_progress_nonneg_int(row.get("completed", 0))
    t = scan_progress_nonneg_int(row.get("total", 0))
    return c, max(t, c)


def scan_progress_status_meta(progress: Dict[str, Any]) -> Tuple[bool, str, str]:
    """Derive ``is_partial``, canonical ``status_key``, and human ``status_label`` for markdown."""
    is_partial = bool(progress.get("is_partial", False))
    status_key = str(progress.get("status") or "").strip().lower()
    if status_key not in SCAN_PROGRESS_STATUS_EXPLICIT:
        status_key = "in_progress" if is_partial else "complete"
    label = SCAN_PROGRESS_STATUS_MARKDOWN_LABELS.get(status_key, "Complete")
    return is_partial, status_key, label


def scan_progress_tested_and_current(progress: Dict[str, Any]) -> Tuple[List[str], str]:
    tested = [
        str(item).strip()
        for item in (progress.get("tested_vulnerabilities") or [])
        if str(item).strip()
    ]
    current_v = str(progress.get("current_vulnerability") or "").strip()
    return tested, current_v


def append_pipeline_phases_markdown(report: List[str], phases: Any) -> None:
    if not isinstance(phases, list) or not phases:
        return
    report.append("\n### Pipeline phases")
    report.extend(
        [
            "| Phase | Status | Progress |",
            "|-------|--------|----------|",
        ]
    )
    for row in phases:
        if not isinstance(row, dict):
            continue
        label = str(row.get("label") or row.get("id") or "").strip() or "—"
        st = str(row.get("status") or "").strip() or "—"
        c, t = phase_row_counts(row)
        report.append(f"| {label} | {st} | {c}/{t} |")


def append_adaptive_subphases_markdown(report: List[str], adaptive_subphases: Any) -> None:
    """Render legacy adaptive-shaped ``adaptive_subphases`` block when present in payloads."""
    if not isinstance(adaptive_subphases, dict) or not adaptive_subphases:
        return
    report.append("\n#### Adaptive sub-phases")
    for sub_id, sub in adaptive_subphases.items():
        if not isinstance(sub, dict):
            continue
        slabel = str(sub.get("label") or sub_id)
        sc = scan_progress_nonneg_int(sub.get("completed", 0))
        stot = scan_progress_nonneg_int(sub.get("total", 0))
        sst = str(sub.get("status") or "")
        report.append(f"- {slabel}: {sst} ({sc}/{stot})")
