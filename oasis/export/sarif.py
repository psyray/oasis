"""Build SARIF 2.1.0 logs from canonical vulnerability report documents."""

from __future__ import annotations

import re
from typing import Any, Dict, List

from ..schemas.analysis import VulnerabilityFinding, VulnerabilityReportDocument

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
OASIS_INFORMATION_URI = "https://github.com/psyray/oasis"


def _slug_rule_id(vulnerability_name: str) -> str:
    slug = vulnerability_name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-") or "oasis-finding"


def _severity_to_level(severity: str) -> str:
    """Map a severity string to a SARIF ``result.level`` value (case-insensitive)."""
    normalized = (severity or "").strip().lower()
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }
    return mapping.get(normalized, "warning")


def _artifact_uri(file_path: str) -> str:
    """Use path as stored in the report (portable relative paths when the scanner used them)."""
    return file_path.replace("\\", "/")


def _finding_message(finding: VulnerabilityFinding) -> str:
    parts: List[str] = []
    if finding.title:
        parts.append(finding.title.strip())
    if finding.explanation:
        parts.append(finding.explanation.strip())
    if finding.impact:
        parts.append(f"Impact: {finding.impact.strip()}")
    if finding.remediation:
        parts.append(f"Remediation: {finding.remediation.strip()}")
    return "\n\n".join(p for p in parts if p)


def vulnerability_document_to_sarif(
    doc: VulnerabilityReportDocument,
    *,
    tool_version: str,
) -> Dict[str, Any]:
    """
    Map a ``VulnerabilityReportDocument`` to a SARIF 2.1.0 ``sarifLog`` object.

    Fills ``region.startLine`` / ``region.endLine`` from finding-level
    ``snippet_start_line`` / ``snippet_end_line`` when present (resolved from
    ``vulnerable_code`` inside the analyzed chunk); otherwise falls back to the
    chunk span. ``region.snippet`` carries ``vulnerable_code`` when present.
    """
    rule_id = _slug_rule_id(doc.vulnerability_name)
    vuln_meta: Dict[str, Any] = doc.vulnerability if isinstance(doc.vulnerability, dict) else {}

    short_desc = str(vuln_meta.get("description") or doc.vulnerability_name)[:512]
    full_parts: List[str] = [f"**{doc.vulnerability_name}**", "", short_desc]
    if vuln_meta.get("impact"):
        full_parts.extend(["", f"**Impact (type metadata)**\n{vuln_meta['impact']}"])
    if vuln_meta.get("mitigation"):
        full_parts.extend(["", f"**Mitigation (type metadata)**\n{vuln_meta['mitigation']}"])
    full_description = "\n".join(full_parts)

    rule = {
        "id": rule_id,
        "name": doc.vulnerability_name,
        "shortDescription": {"text": short_desc},
        "fullDescription": {"text": full_description},
        "helpUri": OASIS_INFORMATION_URI,
    }

    results: List[Dict[str, Any]] = []
    for file_entry in doc.files:
        if file_entry.error:
            continue
        uri = _artifact_uri(file_entry.file_path)
        for chunk_index, chunk in enumerate(file_entry.chunk_analyses):
            for finding_index, finding in enumerate(chunk.findings):
                physical: Dict[str, Any] = {
                    "artifactLocation": {"uri": uri},
                }
                region: Dict[str, Any] = {}
                if snippet_text := (finding.vulnerable_code or "").strip():
                    region["snippet"] = {"text": snippet_text}
                if finding.snippet_start_line is not None and finding.snippet_end_line is not None:
                    region["startLine"] = finding.snippet_start_line
                    region["endLine"] = finding.snippet_end_line
                elif chunk.start_line is not None and chunk.end_line is not None:
                    region["startLine"] = chunk.start_line
                    region["endLine"] = chunk.end_line
                if region:
                    physical["region"] = region

                result: Dict[str, Any] = {
                    "ruleId": rule_id,
                    "level": _severity_to_level(finding.severity),
                    "message": {"text": _finding_message(finding)},
                    "locations": [{"physicalLocation": physical}],
                    "properties": {
                        "oasisModel": doc.model_name,
                        "oasisFileSimilarity": file_entry.similarity_score,
                        "oasisChunkIndex": chunk_index,
                        "oasisFindingIndex": finding_index,
                    },
                }
                results.append(result)

    run: Dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "OASIS",
                "version": tool_version,
                "informationUri": OASIS_INFORMATION_URI,
                "rules": [rule],
            }
        },
        "results": results,
        "properties": {
            "oasisReportTitle": doc.title,
            "oasisGeneratedAt": doc.generated_at,
            "oasisVulnerabilityName": doc.vulnerability_name,
        },
    }

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }
