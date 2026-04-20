"""Scan helpers: phase rows, wire typing, and executive-summary phase structures.

Includes TypedDict shapes for dashboard/JSON and builders for phased progress rows used in tests
and markdown fixtures; the orchestrated product pipeline is LangGraph (``graph_progress.py``).
"""

from __future__ import annotations

from typing import Tuple, TypedDict, Any, Dict, List, Optional, Union

try:
    from typing import NotRequired  # py3.11+
except ImportError:
    from typing_extensions import NotRequired  # py3.9–3.10


class AdaptiveSubphaseSnapshot(TypedDict):
    label: str
    status: str
    completed: int
    total: int


AdaptiveSubphasesWire = Dict[str, AdaptiveSubphaseSnapshot]


class PhaseRowPayload(TypedDict):
    id: str
    label: str
    status: str
    completed: int
    total: int
    current_item: NotRequired[str]


PhaseRowsWire = List[PhaseRowPayload]






from ..enums import PhaseRowStatus, ProgressPhaseRowId, ProgressPhaseRowKind

PhaseTriple = Tuple[str, int, int]
StatusArg = Union[PhaseRowStatus, str]


def phase_triple(status: StatusArg, completed: int, total: int) -> PhaseTriple:
    """Build a ``(status, completed, total)`` triple using canonical status strings."""
    st = status.value if isinstance(status, PhaseRowStatus) else status
    return (st, completed, total)


def safe_code_base_file_count(analyzer: Any) -> int:
    """Count indexed files when ``code_base`` is available (defensive for tests / partial init).

    Accepts any collection-like object that exposes ``__len__``, not only ``dict``.
    """
    cb = getattr(analyzer, "code_base", None)
    if cb is None:
        return 0
    if hasattr(cb, "__len__"):
        try:
            return len(cb)  # type: ignore[arg-type]
        except TypeError:
            return 0
    return 0


def phase_progress_row(
    phase_id: str,
    label: str,
    *,
    status: str,
    completed: int,
    total: int,
    current_item: Optional[str] = None,
    row_kind: str = ProgressPhaseRowKind.SUMMARY.value,
) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "id": phase_id,
        "label": label,
        "row_kind": row_kind,
        "status": status,
        "completed": max(0, completed),
        "total": max(0, total),
    }
    if current_item:
        row["current_item"] = current_item
    return row


def embedding_phase_row(n_files: int) -> Dict[str, Any]:
    """Embeddings phase row (always id ``embeddings``)."""
    return phase_progress_row(
        ProgressPhaseRowId.EMBEDDINGS.value,
        "Embeddings",
        status=PhaseRowStatus.COMPLETE.value,
        completed=n_files,
        total=max(n_files, 1),
    )


def standard_scan_phases(
    n_files: int,
    *,
    initial: PhaseTriple,
    deep: PhaseTriple,
    initial_current_item: Optional[str] = None,
    deep_current_item: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Three rows: embeddings, initial scan, deep analysis (fixture / non-graph layouts)."""
    return [
        embedding_phase_row(n_files),
        phase_progress_row(
            ProgressPhaseRowId.INITIAL_SCAN.value,
            "Initial scanning",
            status=initial[0],
            completed=initial[1],
            total=initial[2],
            current_item=initial_current_item,
        ),
        phase_progress_row(
            ProgressPhaseRowId.DEEP_ANALYSIS.value,
            "Deep analysis",
            status=deep[0],
            completed=deep[1],
            total=deep[2],
            current_item=deep_current_item,
        ),
    ]


def standard_scan_phases_vuln_types(
    n_files: int,
    vuln_types_total: int,
    *,
    initial_status: StatusArg,
    initial_completed: int,
    deep_status: StatusArg,
    deep_completed: int,
    initial_current_item: Optional[str] = None,
    deep_current_item: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Standard scan rows where initial and deep phases share one vulnerability-type denominator.

    Keeps dashboard phase totals aligned with the configured vulnerability type count so
    progress does not appear to move backwards when phase bookkeeping uses a different
    notion of \"how many types\" than iteration order.
    """
    vt = max(0, vuln_types_total)
    i0 = initial_status.value if isinstance(initial_status, PhaseRowStatus) else initial_status
    d0 = deep_status.value if isinstance(deep_status, PhaseRowStatus) else deep_status
    return standard_scan_phases(
        n_files,
        initial=(i0, initial_completed, vt),
        deep=(d0, deep_completed, vt),
        initial_current_item=initial_current_item,
        deep_current_item=deep_current_item,
    )


def adaptive_phases_identifying(
    n_files: int,
    *,
    nv: int,
    adaptive_completed: int,
    current_item: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Adaptive mode while sweeping vulnerability types (denominator ``nv``)."""
    return adaptive_scan_phases(
        n_files,
        adaptive=phase_triple(PhaseRowStatus.IN_PROGRESS, adaptive_completed, nv),
        current_item=current_item,
    )


def adaptive_subphases_during_identification(
    *,
    nv: int,
    identify_completed: int,
    n_batch_tasks: int,
    n_vulns_with_files: int,
) -> Dict[str, Dict[str, Any]]:
    """Sub-phase snapshot during file identification (batch/collect still pending)."""
    return adaptive_subphases_payload(
        identify_files=phase_triple(PhaseRowStatus.IN_PROGRESS, identify_completed, nv),
        batch_process=phase_triple(PhaseRowStatus.PENDING, 0, max(n_batch_tasks, 1)),
        collect_results=phase_triple(PhaseRowStatus.PENDING, 0, max(n_vulns_with_files, 1)),
    )


def adaptive_scan_phases(
    n_files: int,
    *,
    adaptive: PhaseTriple,
    current_item: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Two rows: embeddings, adaptive-style row (wire compatibility in tests / old payloads)."""
    return [
        embedding_phase_row(n_files),
        phase_progress_row(
            ProgressPhaseRowId.ADAPTIVE_SCAN.value,
            "Adaptive analysis",
            status=adaptive[0],
            completed=adaptive[1],
            total=adaptive[2],
            current_item=current_item,
        ),
    ]


def adaptive_subphases_payload(
    *,
    identify_files: PhaseTriple,
    batch_process: PhaseTriple,
    collect_results: PhaseTriple,
) -> Dict[str, Dict[str, Any]]:
    """Nested sub-phase dict for legacy adaptive-shaped progress; triple is ``(status, completed, total)``."""
    return {
        "identify_files": {
            "label": "Identify vulnerable files",
            "status": identify_files[0],
            "completed": identify_files[1],
            "total": identify_files[2],
        },
        "batch_process": {
            "label": "Batch processing",
            "status": batch_process[0],
            "completed": batch_process[1],
            "total": batch_process[2],
        },
        "collect_results": {
            "label": "Collect results",
            "status": collect_results[0],
            "completed": collect_results[1],
            "total": collect_results[2],
        },
    }
