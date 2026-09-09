"""Consolidated multi-model report: merge findings across the deep models of one run.

Findings of every per-model canonical vulnerability document are fingerprinted
(reusing the shared ``finding_fingerprint`` identity) and merged into groups
tagged with the confirming models and per-model severities. When a
consolidation model is configured, an LLM narrative (overview / priorities /
guidance) is synthesized from a compact digest of the groups via structured
output — the model narrates, it never re-detects findings. Artifacts mirror
the scan diff: ``consolidated/consolidated_report.json``
(``ConsolidatedReportDocument``) plus a Markdown sibling.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import ValidationError

from ..backends.base import ModelBackend
from ..config import REPORT_CONSOLIDATION_DIGEST_MAX_CHARS
from ..export.filenames import CONSOLIDATED_REPORT_ARTIFACT_STEM
from ..export.writers import write_utf8_text
from ..schemas.consolidated_report import (
    ConsolidatedCounts,
    ConsolidatedFindingGroup,
    ConsolidatedNarrative,
    ConsolidatedReportDocument,
)
from ..tools import generate_timestamp
from .misc import load_json_document
from .report_diff import iter_findings_from_document, iter_json_document_paths

logger = logging.getLogger(__name__)

_SEVERITY_RANK: Dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1}

_SYSTEM_PROMPT = (
    "You are a security-audit report editor. You receive a consolidated digest of "
    "vulnerability findings detected by several independent models on the same codebase. "
    "Write an executive overview, a prioritized action list and remediation guidance "
    "based strictly on the digest. Never invent findings, files, lines or severities "
    "that are not listed. Reply with one JSON object matching the provided schema."
)


def _first_source_document_meta(run_dir: Path) -> tuple[Optional[str], Optional[str]]:
    """First ``(project, analysis_root)`` among the run's canonical source documents.

    Every per-model document of a run shares the same scanned root, so the first
    readable one provides the context the dashboard needs (codebase reachability).
    """
    for path in iter_json_document_paths(run_dir):
        doc = load_json_document(path)
        if doc is None or str(doc.get("report_type") or "") != "vulnerability":
            continue
        project = doc.get("project")
        analysis_root = doc.get("analysis_root")
        return (
            project.strip() if isinstance(project, str) and project.strip() else None,
            analysis_root.strip() if isinstance(analysis_root, str) and analysis_root.strip() else None,
        )
    return None, None


def collect_model_findings(output_dir: Path) -> Dict[str, List[Dict[str, str]]]:
    """Fingerprinted finding refs grouped by the ``model_name`` of each document."""
    refs_by_model: Dict[str, List[Dict[str, str]]] = {}
    for path in iter_json_document_paths(output_dir):
        doc = load_json_document(path)
        if doc is None or str(doc.get("report_type") or "") != "vulnerability":
            continue
        model = str(doc.get("model_name") or "").strip()
        if not model:
            continue
        refs_by_model.setdefault(model, []).extend(iter_findings_from_document(doc))
    return refs_by_model


def _collapsed_snippet(snippet: Any) -> str:
    """Whitespace-collapsed snippet text for containment matching."""
    return " ".join(str(snippet or "").split())


def _snippets_overlap(first: Any, second: Any) -> bool:
    """True when either snippet contains the other (same finding, different quoted context)."""
    left, right = _collapsed_snippet(first), _collapsed_snippet(second)
    if not left or not right:
        return False
    return left in right or right in left


def _merge_overlapping_groups(groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Second consolidation pass: merge same-location groups whose snippets overlap.

    Models quote different amounts of context around the same vulnerable line, so
    exact snippet fingerprints can split one finding into several groups
    (e.g. one line vs. the same line plus its assignment). Containment in either
    direction on whitespace-collapsed snippets re-joins them deterministically;
    the presentation of the group confirming on more models wins on merge.
    """
    merged: List[Dict[str, Any]] = []
    for group in groups:
        target = next(
            (
                existing for existing in merged
                if existing["file_path"] == group["file_path"]
                and existing["vulnerability_name"] == group["vulnerability_name"]
                and _snippets_overlap(existing["snippet"], group["snippet"])
            ),
            None,
        )
        if target is None:
            merged.append(group)
            continue
        if len(group["confirming_models"]) > len(target["confirming_models"]):
            for key in ("fingerprint", "title", "snippet"):
                target[key] = group[key]
        for model, severity in group["severity_by_model"].items():
            if model not in target["confirming_models"]:
                target["confirming_models"].append(model)
            target["severity_by_model"][model] = str(severity)
    return merged


def group_findings(refs_by_model: Dict[str, List[Dict[str, str]]]) -> List[ConsolidatedFindingGroup]:
    """Merge per-model refs into fingerprint groups, best-confirmation first."""
    merged: Dict[str, Dict[str, Any]] = {}
    for model, refs in refs_by_model.items():
        for ref in refs:
            fingerprint = ref.get("fingerprint") or ""
            if not fingerprint:
                continue
            group = merged.setdefault(
                fingerprint,
                {
                    "fingerprint": fingerprint,
                    "file_path": ref.get("file_path") or "",
                    "vulnerability_name": ref.get("vulnerability_name") or "",
                    "title": ref.get("title") or "",
                    "snippet": ref.get("snippet") or "",
                    "severity_by_model": {},
                    "confirming_models": [],
                },
            )
            if model not in group["confirming_models"]:
                group["confirming_models"].append(model)
            group["severity_by_model"][model] = str(ref.get("severity") or "")

    def _order_key(group: Dict[str, Any]) -> tuple:
        best_severity = max(
            (_SEVERITY_RANK.get(str(s).strip().lower(), 0) for s in group["severity_by_model"].values()),
            default=0,
        )
        return (-len(group["confirming_models"]), -best_severity, group["file_path"], group["vulnerability_name"])

    return [
        ConsolidatedFindingGroup(**group)
        for group in sorted(_merge_overlapping_groups(list(merged.values())), key=_order_key)
    ]


def _consolidated_counts(groups: List[ConsolidatedFindingGroup], model_count: int) -> ConsolidatedCounts:
    confirmed_by_all = sum(1 for group in groups if len(group.confirming_models) >= model_count)
    confirmed_by_several = sum(1 for group in groups if 1 < len(group.confirming_models) < model_count)
    single_model = sum(1 for group in groups if len(group.confirming_models) == 1)
    return ConsolidatedCounts(
        total_groups=len(groups),
        confirmed_by_all=confirmed_by_all,
        confirmed_by_several=confirmed_by_several,
        single_model=single_model,
    )


def build_consolidated_digest(groups: List[ConsolidatedFindingGroup], *, max_chars: int) -> str:
    """Compact JSON digest of the merged groups, capped to ``max_chars`` (best groups kept)."""
    rows = [
        {
            "vulnerability": group.vulnerability_name,
            "file": group.file_path,
            "title": group.title,
            "severity_by_model": group.severity_by_model,
            "models": group.confirming_models,
        }
        for group in groups
    ]
    payload = json.dumps({"groups": rows, "truncated": False}, ensure_ascii=False)
    kept = rows
    while len(payload) > max_chars and len(kept) > 1:
        kept = kept[: max(1, len(kept) // 2)]
        payload = json.dumps({"groups": kept, "truncated": True}, ensure_ascii=False)
    return payload


def synthesize_narrative(
    backend: ModelBackend,
    *,
    report_model: str,
    digest: str,
    source_models: List[str],
) -> Optional[ConsolidatedNarrative]:
    """Structured-output narrative over the digest; ``None`` on any LLM failure."""
    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {
            "role": "user",
            "content": f"Models compared: {', '.join(source_models)}\nConsolidated digest:\n{digest}",
        },
    ]
    try:
        response = backend.chat(
            model=report_model,
            messages=messages,
            format=ConsolidatedNarrative.model_json_schema(),
            options={"temperature": 0.2},
        )
    except Exception as exc:  # best-effort enrichment: LLM failure must never abort the run
        logger.warning(
            "Consolidated narrative LLM call failed model=%s err=%s", report_model, type(exc).__name__, exc_info=True
        )
        return None

    raw = response.get("message", {}).get("content") if isinstance(response, dict) else None
    try:
        return ConsolidatedNarrative.model_validate(json.loads(raw or ""))
    except (json.JSONDecodeError, TypeError, ValidationError) as exc:
        logger.warning(
            "Consolidated narrative returned invalid JSON model=%s err=%s", report_model, type(exc).__name__
        )
        return None


def _consolidated_markdown_lines(doc: ConsolidatedReportDocument) -> List[str]:
    model_count = len(doc.source_models)
    lines = [
        f"# {doc.title}",
        "",
        f"- **Models**: {', '.join(doc.source_models)}",
        f"- **Generated**: {doc.generated_at}",
        "",
        "## Summary",
        "",
        f"- **Finding groups**: {doc.counts.total_groups}",
        f"- **Confirmed by all models**: {doc.counts.confirmed_by_all}",
        f"- **Confirmed by several models**: {doc.counts.confirmed_by_several}",
        f"- **Single-model findings**: {doc.counts.single_model}",
        "",
    ]
    lines.extend(["## Narrative", ""])
    if doc.narrative:
        if doc.narrative.overview:
            lines.extend(["### Overview", "", doc.narrative.overview, ""])
        if doc.narrative.priorities_markdown:
            lines.extend(["### Priorities", "", doc.narrative.priorities_markdown, ""])
        if doc.narrative.guidance_markdown:
            lines.extend(["### Remediation guidance", "", doc.narrative.guidance_markdown, ""])
    else:
        lines.extend(["_(unavailable — the deterministic grouping below stands on its own)_", ""])

    def _group_table(rows: List[ConsolidatedFindingGroup]) -> List[str]:
        if not rows:
            return ["_(none)_", ""]
        table = ["| Severity | Vulnerability | File | Title | Models |", "|---|---|---|---|---|"]
        for group in rows:
            severity = max(
                (group.severity_by_model.get(model, "") for model in group.confirming_models),
                key=lambda s: _SEVERITY_RANK.get(str(s).strip().lower(), 0),
            )
            title = (group.title or "-").replace("|", "\\|")
            table.append(
                f"| {severity or '-'} | {group.vulnerability_name} | {group.file_path} "
                f"| {title} | {', '.join(group.confirming_models)} |"
            )
        table.append("")
        return table

    lines.extend(["## Confirmed by all models", ""])
    lines.extend(_group_table([g for g in doc.groups if len(g.confirming_models) >= model_count]))
    lines.extend(["## Confirmed by several models", ""])
    lines.extend(_group_table([g for g in doc.groups if 1 < len(g.confirming_models) < model_count]))
    lines.extend(["## Single-model findings", ""])
    lines.extend(_group_table([g for g in doc.groups if len(g.confirming_models) == 1]))
    return lines


def write_consolidated_report(
    output_dir: Path,
    *,
    source_models: Optional[List[str]] = None,
    backend: Optional[ModelBackend] = None,
    report_model: Optional[str] = None,
    digest_max_chars: Optional[int] = None,
) -> Optional[Dict[str, Any]]:
    """
    Merge per-model canonical vulnerability documents under ``output_dir`` into
    ``consolidated/consolidated_report.json`` plus a Markdown sibling.

    The deterministic merge always runs when at least two models produced
    findings; the LLM narrative only when ``backend`` + ``report_model`` are
    provided (failure degrades to a narrative-less document, never an abort).

    Returns the document (dict form) for logging, or ``None`` when the run has
    a single model or no readable findings.
    """
    run_dir = Path(output_dir)
    if not run_dir.is_dir():
        logger.warning("Consolidated report skipped: run directory not found: %s", run_dir)
        return None

    refs_by_model = collect_model_findings(run_dir)
    if source_models:
        allowed = {str(model) for model in source_models}
        refs_by_model = {model: refs for model, refs in refs_by_model.items() if model in allowed}
    if len(refs_by_model) < 2:
        logger.info(
            "Consolidated report skipped: fewer than two models produced findings (%s)",
            ", ".join(sorted(refs_by_model)) or "none",
        )
        return None

    groups = group_findings(refs_by_model)
    if not groups:
        logger.info("Consolidated report skipped: no findings across the models")
        return None

    model_names = sorted(refs_by_model)
    max_chars = digest_max_chars or REPORT_CONSOLIDATION_DIGEST_MAX_CHARS
    narrative: Optional[ConsolidatedNarrative] = None
    if backend is not None and report_model:
        digest = build_consolidated_digest(groups, max_chars=max_chars)
        narrative = synthesize_narrative(
            backend, report_model=report_model, digest=digest, source_models=model_names
        )

    project, analysis_root = _first_source_document_meta(run_dir)
    doc = ConsolidatedReportDocument(
        generated_at=generate_timestamp(),
        source_models=model_names,
        project=project,
        analysis_root=analysis_root,
        counts=_consolidated_counts(groups, len(model_names)),
        groups=groups,
        narrative=narrative,
    )

    consolidated_dir = run_dir / "consolidated"
    consolidated_dir.mkdir(parents=True, exist_ok=True)
    write_utf8_text(consolidated_dir / f"{CONSOLIDATED_REPORT_ARTIFACT_STEM}.json", doc.model_dump_json(indent=2))
    write_utf8_text(
        consolidated_dir / f"{CONSOLIDATED_REPORT_ARTIFACT_STEM}.md", "\n".join(_consolidated_markdown_lines(doc))
    )
    logger.info("Consolidated report written to %s", consolidated_dir / f"{CONSOLIDATED_REPORT_ARTIFACT_STEM}.json")
    return doc.model_dump(mode="json")


__all__ = [
    "build_consolidated_digest",
    "collect_model_findings",
    "group_findings",
    "synthesize_narrative",
    "write_consolidated_report",
]