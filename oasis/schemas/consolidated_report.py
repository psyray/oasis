"""Pydantic models for the consolidated multi-model report (issue #60).

Deterministic buckets merge the findings of every deep model of one run by
stable fingerprint (file + vulnerability type + normalized snippet); the
consolidation model only synthesizes the narrative (overview / priorities /
guidance) from a compact digest — it narrates, it never re-detects findings.
"""

from __future__ import annotations

from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field

from .analysis import ANALYSIS_SCHEMA_VERSION


class ConsolidatedNarrative(BaseModel):
    """LLM-synthesized narrative over the deterministic finding groups."""

    overview: str = Field(default="", description="Executive overview of the consolidated results")
    priorities_markdown: str = Field(default="", description="Prioritized action list (Markdown)")
    guidance_markdown: str = Field(default="", description="Remediation guidance (Markdown)")


class ConsolidatedFindingGroup(BaseModel):
    """One finding identity observed across the deep models of the run."""

    fingerprint: str = Field(description="Stable content hash (file + vulnerability type + snippet)")
    file_path: str
    vulnerability_name: str
    title: str = ""
    snippet: str = ""
    severity_by_model: Dict[str, str] = Field(default_factory=dict)
    confirming_models: List[str] = Field(default_factory=list)


class ConsolidatedCounts(BaseModel):
    """Bucket sizes across the merged finding groups."""

    total_groups: int = 0
    confirmed_by_all: int = 0
    confirmed_by_several: int = 0
    single_model: int = 0


class ConsolidatedReportDocument(BaseModel):
    """Canonical consolidated report merging the deep models of one run.

    Finding groups are deterministic (fingerprint identity + per-model
    severities); ``narrative`` comes from the consolidation model when
    configured and stays ``None`` on LLM failure — the report is still written.
    """

    schema_version: int = Field(default=ANALYSIS_SCHEMA_VERSION)
    report_type: Literal["consolidated"] = "consolidated"
    title: str = "Consolidated multi-model report"
    generated_at: str
    project: Optional[str] = Field(default=None, description="Project label (dashboard grouping)")
    analysis_root: Optional[str] = Field(
        default=None,
        description=(
            "Scanned codebase root stored relative to security_reports "
            "(same encoding as canonical vulnerability documents)"
        ),
    )
    source_models: List[str] = Field(default_factory=list)
    counts: ConsolidatedCounts = Field(default_factory=ConsolidatedCounts)
    groups: List[ConsolidatedFindingGroup] = Field(default_factory=list)
    narrative: Optional[ConsolidatedNarrative] = None