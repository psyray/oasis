"""Progress helpers: wire constants, tqdm, REST/Socket.IO coercion, executive-summary extras."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..enums import AnalysisType, PhaseRowStatus, ProgressActivePhase
from .scan import (
    adaptive_phases_identifying,
    adaptive_scan_phases,
    adaptive_subphases_during_identification,
    adaptive_subphases_payload,
    phase_triple,
    standard_scan_phases_vuln_types,
)

# Canonical keys for executive-summary progress payload extensions (wire JSON / Markdown).
# Keep in sync across publish_incremental_summary, Report, and oasis.web dashboard readers.

EXEC_SUMMARY_PROGRESS_EVENT_VERSION = 2

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
    """Shared progress fields for ``AnalysisType.STANDARD`` runs."""
    extras: Dict[str, Any] = {
        "active_phase": active_phase.value,
        "scan_mode": AnalysisType.STANDARD.value,
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
    """Shared progress fields for ``AnalysisType.ADAPTIVE`` runs (``nv`` = vuln-type count)."""
    extras: Dict[str, Any] = {
        "active_phase": ProgressActivePhase.ADAPTIVE_SCAN.value,
        "scan_mode": AnalysisType.ADAPTIVE.value,
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
    """Adaptive run finished: all sub-phases and top-level adaptive row complete."""
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
