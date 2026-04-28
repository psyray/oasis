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
from .audit_report import (
    AUDIT_REPORT_DOCUMENT_VERSION,
    AuditMatchResult,
    AuditMetrics,
    AuditPerVulnStatistics,
    AuditReportDocument,
    AuditThresholdRow,
    AuditVulnerabilitySection,
)

__all__ = [
    "ANALYSIS_SCHEMA_VERSION",
    "AUDIT_REPORT_DOCUMENT_VERSION",
    "AuditMatchResult",
    "AuditMetrics",
    "AuditPerVulnStatistics",
    "AuditReportDocument",
    "AuditThresholdRow",
    "AuditVulnerabilitySection",
    "ChunkDeepAnalysis",
    "DashboardStats",
    "FileReportEntry",
    "MediumRiskAnalysis",
    "ScanVerdict",
    "VulnerabilityFinding",
    "VulnerabilityReportDocument",
]
