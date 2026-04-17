"""
Pydantic models for Ollama structured outputs and canonical vulnerability reports.

All user-facing strings in instances should follow English prompts from the analyzer.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

# Bump when changing chunk or report shapes (cache invalidation).
ANALYSIS_SCHEMA_VERSION = 3


class ScanVerdict(BaseModel):
    """Structured response for lightweight scan (one chunk)."""

    verdict: Literal["SUSPICIOUS", "CLEAN", "ERROR"]


class MediumRiskAnalysis(BaseModel):
    """Adaptive pipeline medium-depth structured response."""

    risk_score: int = Field(ge=0, le=100, description="Risk score 0-100")
    analysis: str = Field(default="", description="Brief analysis text")
    validation_error: bool = Field(default=False, description="True when structured validation failed")


class VulnerabilityFinding(BaseModel):
    """Single finding aligned with deep analysis prompt intent."""

    title: str = Field(default="Vulnerability found", description="Short section title")
    vulnerable_code: str = Field(default="", description="Quoted vulnerable snippet")
    explanation: str = Field(default="", description="Why this is vulnerable")
    severity: Literal["Critical", "High", "Medium", "Low"] = Field(
        default="Medium", description="Severity for this finding"
    )
    impact: str = Field(default="", description="Potential impact")
    entry_point: str = Field(default="", description="Route, endpoint, or function entry")
    execution_path_diagram: str = Field(
        default="",
        description="ASCII flowchart for execution path (markdown-friendly text allowed)",
    )
    http_methods: List[str] = Field(default_factory=list)
    manipulable_parameters: List[str] = Field(default_factory=list)
    exploitation_steps: List[str] = Field(default_factory=list)
    example_payloads: List[str] = Field(default_factory=list)
    exploitation_conditions: str = Field(default="", description="Dependencies for exploitation")
    remediation: str = Field(default="", description="Remediation guidance")
    secure_code_example: str = Field(default="", description="Secure code example if any")
    snippet_start_line: Optional[int] = Field(
        default=None,
        description="1-based first line of vulnerable_code in the file when resolved in the chunk (tooling)",
    )
    snippet_end_line: Optional[int] = Field(
        default=None,
        description="1-based last line of vulnerable_code in the file when resolved in the chunk (tooling)",
    )


class ChunkDeepAnalysis(BaseModel):
    """Structured deep analysis for one code chunk."""

    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    start_line: Optional[int] = Field(
        default=None,
        description="1-based first line of this chunk in the source file (tooling; not from LLM)",
    )
    end_line: Optional[int] = Field(
        default=None,
        description="1-based last line of this chunk in the source file (tooling; not from LLM)",
    )
    notes: Optional[str] = Field(default=None, description="Optional analyst notes")
    validation_error: bool = Field(default=False, description="True when structured validation failed")
    potential_vulnerabilities: bool = Field(
        default=False,
        description="True when findings are unknown due to parse/validation failures",
    )
    truncated: bool = Field(default=False, description="True when notes were truncated for size limits")


class FileReportEntry(BaseModel):
    """One file row inside a vulnerability report document."""

    file_path: str
    similarity_score: float
    chunk_analyses: List[ChunkDeepAnalysis] = Field(default_factory=list)
    error: Optional[str] = None


class DashboardStats(BaseModel):
    """Precomputed stats for the web dashboard (no markdown parsing)."""

    files_analyzed: int = 0
    high_risk: int = 0
    medium_risk: int = 0
    low_risk: int = 0
    critical_risk: int = 0
    total_findings: int = 0
    potential_findings: int = 0


class VulnerabilityReportDocument(BaseModel):
    """Canonical on-disk JSON for one vulnerability-type report."""

    schema_version: int = Field(default=ANALYSIS_SCHEMA_VERSION)
    report_type: Literal["vulnerability"] = "vulnerability"
    title: str
    generated_at: str
    model_name: str
    language: str = "en"
    vulnerability_name: str
    vulnerability: Dict[str, Any] = Field(default_factory=dict)
    files: List[FileReportEntry] = Field(default_factory=list)
    stats: DashboardStats = Field(default_factory=DashboardStats)


ScanVerdict.model_rebuild()
VulnerabilityFinding.model_rebuild()
ChunkDeepAnalysis.model_rebuild()
FileReportEntry.model_rebuild()
VulnerabilityReportDocument.model_rebuild()


def build_dashboard_stats(files: List[FileReportEntry]) -> DashboardStats:
    """Aggregate severities from structured chunk analyses."""
    stats = DashboardStats()
    for entry in files:
        if entry.error:
            continue
        stats.files_analyzed += 1
        for chunk in entry.chunk_analyses:
            if chunk.potential_vulnerabilities:
                stats.potential_findings += 1
            for f in chunk.findings:
                stats.total_findings += 1
                sev = f.severity
                if sev == "Critical":
                    stats.critical_risk += 1
                elif sev == "High":
                    stats.high_risk += 1
                elif sev == "Medium":
                    stats.medium_risk += 1
                elif sev == "Low":
                    stats.low_risk += 1
    return stats


def chunk_analysis_to_markdown(chunk: ChunkDeepAnalysis, chunk_index: int) -> str:
    """Render chunk structured analysis as markdown for adaptive combined reports."""
    parts: List[str] = []
    line_hint = ""
    if chunk.start_line is not None and chunk.end_line is not None:
        line_hint = f" _(source lines {chunk.start_line}-{chunk.end_line})_"
    if not chunk.findings:
        parts.append(
            f"#### Chunk {chunk_index + 1}{line_hint}\n\nNo vulnerabilities identified in structured output.\n"
        )
        if chunk.notes:
            parts.append(f"\n**Notes**: {chunk.notes}\n")
        return "\n".join(parts)
    for i, finding in enumerate(chunk.findings):
        parts.extend(
            (
                f"#### Finding {i + 1} (chunk {chunk_index + 1}){line_hint}: {finding.title}\n",
                f"- **Severity**: {finding.severity}\n",
            )
        )
        if finding.vulnerable_code:
            parts.append("```\n" + finding.vulnerable_code.strip() + "\n```\n")
        parts.append(f"\n{finding.explanation}\n")
        if finding.impact:
            parts.append(f"\n**Impact**: {finding.impact}\n")
        if finding.entry_point:
            parts.append(f"\n**Entry point**: {finding.entry_point}\n")
        if finding.execution_path_diagram:
            parts.append("\n## Execution Path\n\n```\n" + finding.execution_path_diagram.strip() + "\n```\n")
        if finding.http_methods:
            parts.append("\n**HTTP methods**: " + ", ".join(finding.http_methods) + "\n")
        if finding.manipulable_parameters:
            parts.append("\n**Parameters**: " + ", ".join(finding.manipulable_parameters) + "\n")
        if finding.exploitation_steps:
            parts.append("\n**Exploitation steps**:\n" + "\n".join(f"- {s}" for s in finding.exploitation_steps) + "\n")
        if finding.example_payloads:
            parts.append("\n**Example payloads**:\n" + "\n".join(f"- `{p}`" for p in finding.example_payloads) + "\n")
        if finding.exploitation_conditions:
            parts.append(f"\n**Conditions**: {finding.exploitation_conditions}\n")
        if finding.remediation:
            parts.append(f"\n**Remediation**: {finding.remediation}\n")
        if finding.secure_code_example:
            parts.append("\n**Secure example**:\n```\n" + finding.secure_code_example.strip() + "\n```\n")
        parts.append('\n<div class="page-break"></div>\n')
    return "\n".join(parts)
