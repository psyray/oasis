from enum import Enum


# Define analysis modes and types
class AnalysisMode(Enum):
    SCAN = "scan"  # Lightweight scanning mode
    DEEP = "deep"  # Deep analysis mode


class AnalysisType(Enum):
    STANDARD = "standard"  # Standard two-phase analysis
    ADAPTIVE = "adaptive"  # Multi-level adaptive analysis


# Progress payloads (executive summary / dashboard wire format)
class PhaseRowStatus(str, Enum):
    """Status string for pipeline phase rows and adaptive sub-phase rows."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"


class ProgressActivePhase(str, Enum):
    """``active_phase`` field in incremental executive-summary progress payloads."""

    INITIAL_SCAN = "initial_scan"
    DEEP_ANALYSIS = "deep_analysis"
    ADAPTIVE_SCAN = "adaptive_scan"


class ProgressPhaseRowId(str, Enum):
    """Stable ``id`` values for rows in ``phases`` arrays."""

    EMBEDDINGS = "embeddings"
    INITIAL_SCAN = "initial_scan"
    DEEP_ANALYSIS = "deep_analysis"
    ADAPTIVE_SCAN = "adaptive_scan"