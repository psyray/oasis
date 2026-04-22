"""Progress helpers: constants, tqdm, coercion, extras, markdown normalization, LangGraph pipeline rows."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from ...enums import AnalysisType, PhaseRowStatus, ProgressActivePhase, ProgressPhaseRowId
from .numbers import (
    phase_row_completed_total,
    vuln_completed_total_pair,
    wire_nonneg_int,
)
from ..phases.scan import (
    adaptive_phases_identifying,
    adaptive_scan_phases,
    adaptive_subphases_during_identification,
    adaptive_subphases_payload,
    embedding_phase_row,
    phase_progress_row,
    phase_triple,
    safe_code_base_file_count,
    standard_scan_phases_vuln_types,
)

# Wire contract constants (sync with publish_incremental_summary, Report, web dashboard readers).
EXEC_SUMMARY_PROGRESS_EVENT_VERSION = 3

SCAN_PROGRESS_STATUS_EXPLICIT = frozenset(
    {
        "in_progress",
        "complete",
        "aborted",
        "failed",
        "succeeded",
        "finished",
    }
)

SCAN_PROGRESS_NON_PARTIAL_STATUSES = frozenset({"complete", "succeeded", "finished"})

SCAN_PROGRESS_STATUS_MARKDOWN_LABELS: dict[str, str] = {
    "in_progress": "Partial (scan in progress)",
    "complete": "Complete",
    "aborted": "Aborted",
    "failed": "Failed",
    "succeeded": "Succeeded",
    "finished": "Finished",
}

SCAN_PROGRESS_EXTENDED_KEYS = frozenset(
    {
        "updated_at",
        "active_phase",
        "phases",
        "adaptive_subphases",
        "overall",
        "scan_mode",
        "event_version",
        "vulnerability_types_total",
        "status",
    }
)


def tqdm_safe_log(
    logger: logging.Logger,
    pbar: Any,
    level: int,
    msg: str,
    *args: Any,
) -> None:
    """Log without corrupting tqdm: use ``pbar.write`` while the bar is shown (``disable`` False)."""
    text = msg % args if args else msg
    if getattr(pbar, "disable", True):
        logger.log(level, msg, *args)
    else:
        pbar.write(text)


def reset_tqdm_phase_bar(
    pbar: Any,
    *,
    total: int,
    description: Optional[str] = None,
) -> None:
    """Reset tqdm to n=0 with a new total when starting a new high-level scan phase (tqdm>=4.67)."""
    if pbar is None:
        return
    reset_fn = getattr(pbar, "reset", None)
    if callable(reset_fn):
        reset_fn(total=total)
    set_desc = getattr(pbar, "set_description", None)
    if description is not None and callable(set_desc):
        set_desc(description, refresh=False)


def coerce_scan_progress_event_version(raw: Any) -> int:
    """Normalize ``event_version`` to int for Socket.IO / REST consumers (matches dashboard coercion).

    Integer-like values (non-boolean ints or integer strings) are returned as ints; all other
    values (including booleans and empty/invalid strings) fall back to ``1``.
    """
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    if raw is None:
        return 1
    try:
        text = str(raw).strip()
        return int(text, 10) if text else 1
    except (TypeError, ValueError):
        return 1


def standard_progress_extras(
    *,
    active_phase: ProgressActivePhase,
    phases: List[Dict[str, Any]],
    vulnerability_types_total: Optional[int] = None,
    adaptive_subphases: Optional[Dict[str, Dict[str, Any]]] = None,
    updated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Shared progress extras for phased scan rows (tests and markdown fixtures)."""
    extras: Dict[str, Any] = {
        "active_phase": active_phase.value,
        "scan_mode": AnalysisType.GRAPH.value,
        "phases": phases,
    }
    if vulnerability_types_total is not None:
        extras["vulnerability_types_total"] = vulnerability_types_total
    if adaptive_subphases is not None:
        extras["adaptive_subphases"] = adaptive_subphases
    if updated_at is not None:
        extras["updated_at"] = updated_at
    return extras


def adaptive_progress_extras(
    *,
    phases: List[Dict[str, Any]],
    adaptive_subphases: Dict[str, Dict[str, Any]],
    nv: int,
    updated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Progress extras with adaptive-shaped phase rows (wire compatibility for fixtures)."""
    extras: Dict[str, Any] = {
        "active_phase": ProgressActivePhase.ADAPTIVE_SCAN.value,
        "scan_mode": AnalysisType.GRAPH.value,
        "vulnerability_types_total": nv,
        "phases": phases,
        "adaptive_subphases": adaptive_subphases,
    }
    if updated_at is not None:
        extras["updated_at"] = updated_at
    return extras


def standard_initial_sweep_extras(n_files: int, vuln_types_total: int) -> Dict[str, Any]:
    """Standard scan kickoff: initial phase in progress, deep pending."""
    return standard_progress_extras(
        active_phase=ProgressActivePhase.INITIAL_SCAN,
        phases=standard_scan_phases_vuln_types(
            n_files,
            vuln_types_total,
            initial_status=PhaseRowStatus.IN_PROGRESS,
            initial_completed=0,
            deep_status=PhaseRowStatus.PENDING,
            deep_completed=0,
        ),
        vulnerability_types_total=vuln_types_total,
    )


def standard_initial_iteration_extras(
    n_files: int,
    vuln_types_total: int,
    initial_completed: int,
    *,
    scanning_item: Optional[str] = None,
) -> Dict[str, Any]:
    """Standard phase 1 progress while iterating vulnerability types."""
    return standard_progress_extras(
        active_phase=ProgressActivePhase.INITIAL_SCAN,
        phases=standard_scan_phases_vuln_types(
            n_files,
            vuln_types_total,
            initial_status=PhaseRowStatus.IN_PROGRESS,
            initial_completed=initial_completed,
            deep_status=PhaseRowStatus.PENDING,
            deep_completed=0,
            initial_current_item=scanning_item,
        ),
        vulnerability_types_total=vuln_types_total,
    )


def standard_deep_phase_extras(
    n_files: int,
    vuln_types_total: int,
    *,
    deep_completed: int,
    deep_current_item: Optional[str] = None,
) -> Dict[str, Any]:
    """Standard phase 2 (deep) with initial row complete and deep in progress."""
    return standard_progress_extras(
        active_phase=ProgressActivePhase.DEEP_ANALYSIS,
        phases=standard_scan_phases_vuln_types(
            n_files,
            vuln_types_total,
            initial_status=PhaseRowStatus.COMPLETE,
            initial_completed=vuln_types_total,
            deep_status=PhaseRowStatus.IN_PROGRESS,
            deep_completed=deep_completed,
            deep_current_item=deep_current_item,
        ),
        vulnerability_types_total=vuln_types_total,
    )


def standard_final_complete_extras(
    n_files: int,
    nv_final: int,
    *,
    updated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Final standard-mode snapshot: both pipeline rows complete."""
    return standard_progress_extras(
        active_phase=ProgressActivePhase.DEEP_ANALYSIS,
        phases=standard_scan_phases_vuln_types(
            n_files,
            nv_final,
            initial_status=PhaseRowStatus.COMPLETE,
            initial_completed=nv_final,
            deep_status=PhaseRowStatus.COMPLETE,
            deep_completed=nv_final,
        ),
        vulnerability_types_total=nv_final,
        updated_at=updated_at,
    )


def adaptive_identification_start_extras(
    *,
    n_files: int,
    nv: int,
    n_batch_tasks: int,
    collect_results_total: int,
) -> Dict[str, Any]:
    """Adaptive: start of vuln-type identification (batch/collect still pending)."""
    return adaptive_progress_extras(
        phases=adaptive_phases_identifying(n_files, nv=nv, adaptive_completed=0),
        adaptive_subphases=adaptive_subphases_payload(
            identify_files=phase_triple(PhaseRowStatus.IN_PROGRESS, 0, nv),
            batch_process=phase_triple(
                PhaseRowStatus.PENDING, 0, max(n_batch_tasks, 1)
            ),
            collect_results=phase_triple(
                PhaseRowStatus.PENDING, 0, collect_results_total
            ),
        ),
        nv=nv,
    )


def adaptive_identifying_loop_extras(
    *,
    n_files: int,
    nv: int,
    vuln_pbar_n: int,
    n_batch_tasks: int,
    n_vulns_with_files: int,
    phase_current_item: Optional[str] = None,
) -> Dict[str, Any]:
    """Adaptive: identification sweep updates (within-vuln and post-step publishes)."""
    return adaptive_progress_extras(
        phases=adaptive_phases_identifying(
            n_files,
            nv=nv,
            adaptive_completed=vuln_pbar_n,
            current_item=phase_current_item,
        ),
        adaptive_subphases=adaptive_subphases_during_identification(
            nv=nv,
            identify_completed=vuln_pbar_n,
            n_batch_tasks=n_batch_tasks,
            n_vulns_with_files=n_vulns_with_files,
        ),
        nv=nv,
    )


def adaptive_after_identification_extras(
    *,
    n_files: int,
    nv: int,
    n_batch_tasks: int,
    progress_total_while_collecting: int,
) -> Dict[str, Any]:
    """Adaptive: identification finished; batch running; collect pending."""
    return adaptive_progress_extras(
        phases=adaptive_phases_identifying(n_files, nv=nv, adaptive_completed=0),
        adaptive_subphases=adaptive_subphases_payload(
            identify_files=phase_triple(PhaseRowStatus.COMPLETE, nv, nv),
            batch_process=phase_triple(
                PhaseRowStatus.IN_PROGRESS, 0, max(n_batch_tasks, 1)
            ),
            collect_results=phase_triple(
                PhaseRowStatus.PENDING, 0, progress_total_while_collecting
            ),
        ),
        nv=nv,
    )


def adaptive_after_batch_extras(
    *,
    n_files: int,
    nv: int,
    n_batch_tasks: int,
    progress_total_while_collecting: int,
) -> Dict[str, Any]:
    """Adaptive: batch complete; collecting results."""
    return adaptive_progress_extras(
        phases=adaptive_phases_identifying(n_files, nv=nv, adaptive_completed=0),
        adaptive_subphases=adaptive_subphases_payload(
            identify_files=phase_triple(PhaseRowStatus.COMPLETE, nv, nv),
            batch_process=phase_triple(
                PhaseRowStatus.COMPLETE,
                max(n_batch_tasks, 1),
                max(n_batch_tasks, 1),
            ),
            collect_results=phase_triple(
                PhaseRowStatus.IN_PROGRESS,
                0,
                progress_total_while_collecting,
            ),
        ),
        nv=nv,
    )


def adaptive_collect_step_extras(
    *,
    n_files: int,
    nv: int,
    n_batch_tasks: int,
    progress_total_while_collecting: int,
    collect_completed: int,
    adaptive_row_completed: int,
    phase_current_item: Optional[str] = None,
) -> Dict[str, Any]:
    """Adaptive: collection loop (``total_vulnerabilities`` uses collection denominator)."""
    return adaptive_progress_extras(
        phases=adaptive_scan_phases(
            n_files,
            adaptive=phase_triple(
                PhaseRowStatus.IN_PROGRESS,
                adaptive_row_completed,
                progress_total_while_collecting,
            ),
            current_item=phase_current_item,
        ),
        adaptive_subphases=adaptive_subphases_payload(
            identify_files=phase_triple(PhaseRowStatus.COMPLETE, nv, nv),
            batch_process=phase_triple(
                PhaseRowStatus.COMPLETE,
                max(n_batch_tasks, 1),
                max(n_batch_tasks, 1),
            ),
            collect_results=phase_triple(
                PhaseRowStatus.IN_PROGRESS,
                collect_completed,
                progress_total_while_collecting,
            ),
        ),
        nv=nv,
    )


def adaptive_final_summary_extras(
    *,
    n_files: int,
    nv_final: int,
    n_collect_completed: int,
    updated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Legacy adaptive-shaped run finished: sub-phases and top-level adaptive row complete."""
    return adaptive_progress_extras(
        phases=adaptive_scan_phases(
            n_files,
            adaptive=phase_triple(PhaseRowStatus.COMPLETE, nv_final, nv_final),
        ),
        adaptive_subphases=adaptive_subphases_payload(
            identify_files=phase_triple(PhaseRowStatus.COMPLETE, nv_final, nv_final),
            batch_process=phase_triple(PhaseRowStatus.COMPLETE, 1, 1),
            collect_results=phase_triple(
                PhaseRowStatus.COMPLETE,
                n_collect_completed,
                max(n_collect_completed, 1),
            ),
        ),
        nv=nv_final,
        updated_at=updated_at,
    )


# --- Scan progress JSON / markdown (executive summary) --------------------------------

def scan_progress_nonneg_int(raw: Any, *, default: int = 0) -> int:
    """Parse a counter from JSON progress payloads; clamp to non-negative ints."""
    return wire_nonneg_int(raw, default=default)


def scan_progress_vulnerability_counts(progress: Dict[str, Any]) -> Tuple[int, int]:
    """Return (completed, total) with total >= completed."""
    return vuln_completed_total_pair(
        progress.get("completed_vulnerabilities"),
        progress.get("total_vulnerabilities"),
    )


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
    return phase_row_completed_total(row.get("completed", 0), row.get("total", 0))


def scan_progress_status_meta(progress: Dict[str, Any]) -> Tuple[bool, str, str]:
    """Derive ``is_partial``, canonical ``status_key``, and human ``status_label`` for markdown."""
    is_partial = bool(progress.get("is_partial", False))
    status_key = str(progress.get("status") or "").strip().lower()
    if status_key not in SCAN_PROGRESS_STATUS_EXPLICIT:
        status_key = "in_progress" if is_partial else "complete"
    label = SCAN_PROGRESS_STATUS_MARKDOWN_LABELS.get(status_key, "Complete")
    return is_partial, status_key, label


def scan_progress_tested_and_current(progress: Dict[str, Any]) -> Tuple[List[str], str]:
    """Extract tested vulnerability ids and the current vulnerability label from progress payloads.

    **Input contract (permissive)**

    - ``progress`` is the incremental executive-summary progress mapping (JSON-shaped).
    - ``tested_vulnerabilities``: if missing or ``None``, treated as empty. If a list, tuple,
      or set, each element is coerced with ``str()`` and stripped (empty strings omitted).
      Other types (including bare strings) are treated as empty to avoid corrupting IDs.
    - ``current_vulnerability``: missing, ``None``, or non-string values become ``""``.
    """
    raw_tested = progress.get("tested_vulnerabilities")
    if isinstance(raw_tested, (list, tuple, set)):
        iterable = raw_tested
    else:
        iterable = []

    tested = [
        str(item).strip()
        for item in iterable
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
        sc, stot = phase_row_counts(sub)
        sst = str(sub.get("status") or "")
        report.append(f"- {slabel}: {sst} ({sc}/{stot})")


# --- LangGraph pipeline progress extras ----------------------------------------------

def graph_pipeline_phases(
    n_files: int,
    nv: int,
    *,
    discover_status: str,
    discover_completed: int,
    scan_status: str,
    scan_completed: int,
    scan_total: int,
    expand_status: str,
    expand_completed: int,
    expand_total: int,
    deep_status: str,
    deep_completed: int,
    deep_total: int,
    verify_status: str,
    verify_completed: int,
    verify_total: int,
) -> List[Dict[str, Any]]:
    """Phase rows aligned with LangGraph nodes (Discover → Scan → Expand → Deep → Verify)."""
    scan_total = max(scan_total, 1)
    expand_total = max(expand_total, 1)
    deep_total = max(deep_total, 1)
    verify_total = max(verify_total, 1)
    return [
        embedding_phase_row(n_files),
        phase_progress_row(
            ProgressPhaseRowId.GRAPH_DISCOVER.value,
            "Discover candidates",
            status=discover_status,
            completed=discover_completed,
            total=max(nv, 1),
        ),
        phase_progress_row(
            ProgressPhaseRowId.GRAPH_CHUNK_SCAN.value,
            "Structured chunk scan",
            status=scan_status,
            completed=scan_completed,
            total=scan_total,
        ),
        phase_progress_row(
            ProgressPhaseRowId.GRAPH_CONTEXT_EXPAND.value,
            "Context expansion",
            status=expand_status,
            completed=expand_completed,
            total=expand_total,
        ),
        phase_progress_row(
            ProgressPhaseRowId.GRAPH_DEEP.value,
            "Deep analysis",
            status=deep_status,
            completed=deep_completed,
            total=deep_total,
        ),
        phase_progress_row(
            ProgressPhaseRowId.GRAPH_VERIFY.value,
            "Verify structured output",
            status=verify_status,
            completed=verify_completed,
            total=verify_total,
        ),
    ]


def graph_progress_extras(
    *,
    analyzer: Any,
    nv: int,
    phases: List[Dict[str, Any]],
    updated_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Wire extras for ``publish_incremental_summary`` (scan_mode=graph)."""
    n_files = safe_code_base_file_count(analyzer)
    extras: Dict[str, Any] = {
        "active_phase": ProgressActivePhase.GRAPH_PIPELINE.value,
        "scan_mode": AnalysisType.GRAPH.value,
        "vulnerability_types_total": nv,
        "phases": phases,
    }
    if updated_at is not None:
        extras["updated_at"] = updated_at
    return extras


def graph_initial_phases(analyzer: Any, nv: int) -> Dict[str, Any]:
    """Kickoff snapshot: embeddings complete, discover running."""
    n_files = safe_code_base_file_count(analyzer)
    phases = graph_pipeline_phases(
        n_files,
        nv,
        discover_status=PhaseRowStatus.IN_PROGRESS.value,
        discover_completed=0,
        scan_status=PhaseRowStatus.PENDING.value,
        scan_completed=0,
        scan_total=1,
        expand_status=PhaseRowStatus.PENDING.value,
        expand_completed=0,
        expand_total=1,
        deep_status=PhaseRowStatus.PENDING.value,
        deep_completed=0,
        deep_total=1,
        verify_status=PhaseRowStatus.PENDING.value,
        verify_completed=0,
        verify_total=1,
    )
    return graph_progress_extras(analyzer=analyzer, nv=nv, phases=phases)


def graph_phases_discover_done_scan_pending(n_files: int, nv: int) -> List[Dict[str, Any]]:
    """After embedding discover: scan row not started (matches LangGraph ``node_discover`` completion)."""
    return graph_pipeline_phases(
        n_files,
        nv,
        discover_status=PhaseRowStatus.COMPLETE.value,
        discover_completed=nv,
        scan_status=PhaseRowStatus.PENDING.value,
        scan_completed=0,
        scan_total=1,
        expand_status=PhaseRowStatus.PENDING.value,
        expand_completed=0,
        expand_total=1,
        deep_status=PhaseRowStatus.PENDING.value,
        deep_completed=0,
        deep_total=1,
        verify_status=PhaseRowStatus.PENDING.value,
        verify_completed=0,
        verify_total=1,
    )


def graph_phases_scan_done_expand_pending(n_files: int, nv: int) -> List[Dict[str, Any]]:
    """Scan finished; expand/deep/verify rows still pending."""
    return graph_pipeline_phases(
        n_files,
        nv,
        discover_status=PhaseRowStatus.COMPLETE.value,
        discover_completed=nv,
        scan_status=PhaseRowStatus.COMPLETE.value,
        scan_completed=1,
        scan_total=1,
        expand_status=PhaseRowStatus.PENDING.value,
        expand_completed=0,
        expand_total=1,
        deep_status=PhaseRowStatus.PENDING.value,
        deep_completed=0,
        deep_total=1,
        verify_status=PhaseRowStatus.PENDING.value,
        verify_completed=0,
        verify_total=1,
    )


def graph_phases_deep_in_progress(
    n_files: int,
    vuln_types_total: int,
    *,
    deep_completed: int,
) -> List[Dict[str, Any]]:
    """Deep analysis row in progress (used during ``_perform_deep_analysis`` graph progress)."""
    nv = vuln_types_total
    deep_total = max(vuln_types_total, 1)
    return graph_pipeline_phases(
        n_files,
        nv,
        discover_status=PhaseRowStatus.COMPLETE.value,
        discover_completed=nv,
        scan_status=PhaseRowStatus.COMPLETE.value,
        scan_completed=1,
        scan_total=1,
        expand_status=PhaseRowStatus.COMPLETE.value,
        expand_completed=1,
        expand_total=1,
        deep_status=PhaseRowStatus.IN_PROGRESS.value,
        deep_completed=deep_completed,
        deep_total=deep_total,
        verify_status=PhaseRowStatus.PENDING.value,
        verify_completed=0,
        verify_total=1,
    )


def graph_final_phases(analyzer: Any, nv: int, *, updated_at: str) -> Dict[str, Any]:
    """All graph rows complete."""
    n_files = safe_code_base_file_count(analyzer)
    phases = graph_pipeline_phases(
        n_files,
        nv,
        discover_status=PhaseRowStatus.COMPLETE.value,
        discover_completed=nv,
        scan_status=PhaseRowStatus.COMPLETE.value,
        scan_completed=1,
        scan_total=1,
        expand_status=PhaseRowStatus.COMPLETE.value,
        expand_completed=1,
        expand_total=1,
        deep_status=PhaseRowStatus.COMPLETE.value,
        deep_completed=1,
        deep_total=1,
        verify_status=PhaseRowStatus.COMPLETE.value,
        verify_completed=1,
        verify_total=1,
    )
    return graph_progress_extras(analyzer=analyzer, nv=nv, phases=phases, updated_at=updated_at)
