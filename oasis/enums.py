from enum import Enum


# Define analysis modes and types
class AnalysisMode(Enum):
    SCAN = "scan"  # Lightweight scanning mode
    DEEP = "deep"  # Deep analysis mode


class AnalysisType(Enum):
    """Scan/deep orchestration mode (LangGraph only).

    Older releases exposed a separate adaptive mode; orchestration is unified under ``GRAPH``.
    """

    GRAPH = "graph"


# Progress payloads (executive summary / dashboard wire format)
class PhaseRowStatus(str, Enum):
    """Status string for pipeline phase rows (LangGraph and legacy wire shapes)."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"


class ProgressActivePhase(str, Enum):
    """``active_phase`` field in incremental executive-summary progress payloads."""

    INITIAL_SCAN = "initial_scan"
    DEEP_ANALYSIS = "deep_analysis"
    # Retained for dashboard / fixture compatibility with older runs that emitted adaptive-shaped payloads.
    ADAPTIVE_SCAN = "adaptive_scan"
    GRAPH_PIPELINE = "graph_pipeline"


class ProgressPhaseRowId(str, Enum):
    """Stable ``id`` values for rows in ``phases`` arrays."""

    EMBEDDINGS = "embeddings"
    INITIAL_SCAN = "initial_scan"
    DEEP_ANALYSIS = "deep_analysis"
    # Legacy adaptive pipeline row id; still parsed by the dashboard when reading old JSON sidecars.
    ADAPTIVE_SCAN = "adaptive_scan"
    GRAPH_DISCOVER = "graph_discover"
    GRAPH_CHUNK_SCAN = "graph_chunk_scan"
    GRAPH_CONTEXT_EXPAND = "graph_context_expand"
    GRAPH_DEEP = "graph_deep"
    GRAPH_VERIFY = "graph_verify"