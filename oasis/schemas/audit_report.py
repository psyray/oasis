"""Pydantic models for canonical audit (embedding distribution) reports."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

AUDIT_REPORT_DOCUMENT_VERSION = 1


class AuditThresholdRow(BaseModel):
    threshold: float
    matching_items: int
    percentage: float


class AuditMatchResult(BaseModel):
    similarity_score: float
    item_id: str


class AuditPerVulnStatistics(BaseModel):
    avg_score: float
    median_score: float
    max_score: float
    min_score: float


class AuditVulnerabilitySection(BaseModel):
    threshold_analysis: List[AuditThresholdRow] = Field(default_factory=list)
    results: List[AuditMatchResult] = Field(default_factory=list)
    statistics: AuditPerVulnStatistics


class AuditMetrics(BaseModel):
    """Structured audit summary metrics (dashboard keys)."""

    count: int = 0
    avg_score: Optional[float] = None
    median_score: Optional[float] = None
    max_score: Optional[float] = None
    min_score: Optional[float] = None
    high: int = 0
    medium: int = 0
    low: int = 0
    total_items: int = 0
    scored_items: int = 0
    has_scores: bool = False


class AuditReportDocument(BaseModel):
    """Canonical on-disk JSON for embedding audit reports."""

    schema_version: int = Field(default=AUDIT_REPORT_DOCUMENT_VERSION)
    report_type: Literal["audit"] = "audit"
    title: str = "Embeddings Distribution Analysis Report"
    generated_at: str
    language: str = "en"
    project: Optional[str] = None
    analysis_root: Optional[str] = Field(
        default=None,
        description=(
            "Scanned project root path: relative to the security_reports directory for new reports; "
            "legacy reports may omit this field."
        ),
    )
    oasis_version: str = ""
    embedding_model: str
    total_files_analyzed: int = 0
    explain_analysis: str = Field(
        default="",
        description="Markdown body copied from REPORT['EXPLAIN_ANALYSIS'] when generating reports.",
    )
    audit_metrics: Optional[AuditMetrics] = None
    vulnerability_statistics: List[Dict[str, Any]] = Field(default_factory=list)
    analyses: Dict[str, AuditVulnerabilitySection] = Field(
        default_factory=dict,
        description="Per vulnerability-type sections (excludes vulnerability_statistics aggregate).",
    )


__all__ = [
    "AUDIT_REPORT_DOCUMENT_VERSION",
    "AuditMatchResult",
    "AuditMetrics",
    "AuditPerVulnStatistics",
    "AuditReportDocument",
    "AuditThresholdRow",
    "AuditVulnerabilitySection",
]
