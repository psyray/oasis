"""
Enumeration types for OASIS analysis modes and types.

This module defines the various analysis modes and types used throughout
the OASIS scanner for configuring scanning behavior and analysis depth.
"""

from enum import Enum


class AnalysisMode(Enum):
    """
    Analysis mode enumeration.

    Defines the operational mode for the analysis process:
    - SCAN: Lightweight scanning mode using smaller models for initial detection
    - DEEP: Deep analysis mode using powerful models for comprehensive analysis

    Attributes:
        SCAN (str): Lightweight scanning mode for quick initial detection
        DEEP (str): Deep analysis mode for comprehensive vulnerability analysis
    """
    SCAN = "scan"
    DEEP = "deep"


class AnalysisType(Enum):
    """
    Analysis type enumeration.

    Defines the analysis strategy and workflow:
    - STANDARD: Standard two-phase analysis (scan then deep analysis)
    - ADAPTIVE: Multi-level adaptive analysis with risk-based depth adjustment

    Attributes:
        STANDARD (str): Standard two-phase analysis workflow
        ADAPTIVE (str): Adaptive multi-level analysis with progressive depth

    Examples:
        >>> mode = AnalysisType.STANDARD
        >>> print(mode.value)
        'standard'

        >>> adaptive = AnalysisType.ADAPTIVE
        >>> print(adaptive.value)
        'adaptive'
    """
    STANDARD = "standard"
    ADAPTIVE = "adaptive" 