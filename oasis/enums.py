from enum import Enum

# Define analysis modes and types
class AnalysisMode(Enum):
    SCAN = "scan"  # Lightweight scanning mode
    DEEP = "deep"  # Deep analysis mode

class AnalysisType(Enum):
    STANDARD = "standard"  # Standard two-phase analysis
    ADAPTIVE = "adaptive"  # Multi-level adaptive analysis 