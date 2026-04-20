"""Structured analysis and report schemas for OASIS."""

from .analysis import (
    ANALYSIS_SCHEMA_VERSION,
    ChunkDeepAnalysis,
    DashboardStats,
    FileReportEntry,
    MediumRiskAnalysis,
    ScanVerdict,
    VulnerabilityFinding,
    VulnerabilityReportDocument,
)

__all__ = [
    "ANALYSIS_SCHEMA_VERSION",
    "ChunkDeepAnalysis",
    "DashboardStats",
    "FileReportEntry",
    "MediumRiskAnalysis",
    "ScanVerdict",
    "VulnerabilityFinding",
    "VulnerabilityReportDocument",
]
