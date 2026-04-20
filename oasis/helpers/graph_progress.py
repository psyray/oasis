"""Executive-summary progress extras for LangGraph-orchestrated analysis runs."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..enums import AnalysisType, PhaseRowStatus, ProgressActivePhase, ProgressPhaseRowId
from .scan import embedding_phase_row, phase_progress_row, safe_code_base_file_count


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
