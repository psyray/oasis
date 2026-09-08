"""Scan-time batch finding validation.

Runs the deterministic assistant validator over every finding produced by a
deep-analysis pass and annotates findings in place with a compact verdict
(``finding.validation``, :class:`FindingValidationSummary`). Verdicts are
computed once per distinct anchor ``(file, line)`` and reused for duplicate
findings sharing the same anchor.

The batch also returns ``results_by_key``: the full
:class:`AssistantInvestigationResult` payloads keyed with the same stable
``finding_validation_storage_key`` used by chat sessions (``s`` empty), so the
scan can persist a ``finding_validations.json`` sidecar next to the report and
the dashboard can surface the full evidence (entry points, taint flows, call
chains, mitigations) without re-running an investigation.

Anchoring reuses the dashboard sink resolution rules: the finding's
``snippet_start_line`` first, the chunk ``start_line`` fallback, and report
``file_path`` values resolved against the scan root (launcher-relative paths
supported) via the shared ``resolve_report_file_path`` helper.

Rows may hold either Pydantic models (the LangGraph deep pass yields
``ChunkDeepAnalysis``) or plain dicts (legacy/defensive path); both shapes are
annotated in place so the canonical report builder picks the verdicts up.
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from oasis.agent.assistant_invoke import invoke_assistant_validation
from oasis.helpers.assistant.web.persistence import finding_validation_storage_key
from oasis.helpers.assistant.web.result_presentation import (
    apply_presentation_filter_to_result,
)
from oasis.helpers.assistant.web.sink_resolution import (
    coerce_positive_int_line,
    resolve_report_file_path,
)
from oasis.schemas.analysis import (
    AssistantInvestigationResult,
    FindingValidationSummary,
    InvestigationScope,
)

logger = logging.getLogger(__name__)

_PER_FINDING_BUDGET_SECONDS = 20.0
_DEFAULT_TOTAL_BUDGET_SECONDS = 120.0

_ValidationCache = Dict[Tuple[str, Optional[int]], AssistantInvestigationResult]
_FindingAnchor = Tuple[
    int,  # chunk index (0-based, matches dashboard chunk_index)
    int,  # finding index (0-based, matches dashboard finding_index)
    Any,  # finding container (model or dict)
    Tuple[Optional[Path], Optional[int]],
]


def _row_chunks(row: Any) -> List[Any]:
    """Return the structured chunks of one result row (model or dict)."""
    chunks = row.get("structured_chunks") if isinstance(row, dict) else getattr(row, "structured_chunks", None)
    return list(chunks) if isinstance(chunks, list) else []


def _chunk_findings(chunk: Any) -> List[Any]:
    findings = chunk.get("findings") if isinstance(chunk, dict) else getattr(chunk, "findings", None)
    return list(findings) if isinstance(findings, list) else []


def _chunk_start_line(chunk: Any) -> Optional[int]:
    value = chunk.get("start_line") if isinstance(chunk, dict) else getattr(chunk, "start_line", None)
    return coerce_positive_int_line(value)


def _finding_snippet_start_line(finding: Any) -> Optional[int]:
    value = (
        finding.get("snippet_start_line")
        if isinstance(finding, dict)
        else getattr(finding, "snippet_start_line", None)
    )
    return coerce_positive_int_line(value)


def _finding_set_validation(finding: Any, summary: Dict[str, Any]) -> None:
    if isinstance(finding, dict):
        finding["validation"] = dict(summary)
    else:
        finding.validation = FindingValidationSummary.model_validate(summary)


def _iter_finding_anchors(
    row: Any, scan_root: Path
) -> Iterator[_FindingAnchor]:
    """Yield ``(chunk_index, finding_index, finding, (sink_file, sink_line))`` for one row."""
    raw_fp = row.get("file_path") if isinstance(row, dict) else getattr(row, "file_path", None)
    sink_file = resolve_report_file_path(raw_fp, scan_root)
    for chunk_index, chunk in enumerate(_row_chunks(row)):
        chunk_start = _chunk_start_line(chunk)
        for finding_index, finding in enumerate(_chunk_findings(chunk)):
            yield chunk_index, finding_index, finding, (
                sink_file,
                _finding_snippet_start_line(finding) or chunk_start,
            )


def _safe_iter_finding_anchors(
    row: Any, scan_root: Path
) -> Iterator[_FindingAnchor]:
    try:
        yield from _iter_finding_anchors(row, scan_root)
    except Exception:
        logger.warning("Scan-time validation: unable to iterate row findings", exc_info=True)


def _relative_sink_file(sink_file: Path, scan_root: Path) -> str:
    try:
        return str(sink_file.relative_to(scan_root))
    except ValueError:
        return str(sink_file)


def _persisted_result_dict(
    result: AssistantInvestigationResult,
    *,
    vulnerability_name: str,
    scan_root: Path,
    sink_file: Optional[Path],
    sink_line: Optional[int],
) -> Dict[str, Any]:
    """Scope-attach + presentation-filter + serialize one investigation result."""
    try:
        scoped = result.model_copy(
            update={
                "scope": InvestigationScope(
                    scan_root=str(scan_root),
                    sink_file=_relative_sink_file(sink_file, scan_root)
                    if sink_file is not None
                    else None,
                    sink_line=sink_line,
                    vulnerability_name=vulnerability_name,
                    family=result.family,
                )
            }
        )
        return apply_presentation_filter_to_result(scoped).model_dump(mode="json")
    except Exception:
        logger.warning("Scan-time validation: unable to persist result payload", exc_info=True)
        return result.model_dump(mode="json")


def _run_single_validation(
    *,
    vulnerability_name: str,
    scan_root: Path,
    sink_file: Optional[Path],
    sink_line: Optional[int],
) -> Optional[AssistantInvestigationResult]:
    """Run one deterministic investigation and return the full result."""
    try:
        return invoke_assistant_validation(
            vulnerability_name=vulnerability_name,
            scan_root=scan_root,
            sink_file=sink_file,
            sink_line=sink_line,
            budget_seconds=_PER_FINDING_BUDGET_SECONDS,
        )
    except Exception:
        logger.warning(
            "Scan-time validation failed for %s (%s:%s)",
            vulnerability_name,
            sink_file,
            sink_line,
            exc_info=True,
        )
        return None


def annotate_rows_with_validation(
    rows: List[Any],
    *,
    vulnerability_name: str,
    scan_root: Path,
    total_budget_seconds: float = _DEFAULT_TOTAL_BUDGET_SECONDS,
) -> Dict[str, Any]:
    """Validate every finding in *rows* in place and return aggregate stats.

    Duplicate anchors within the batch reuse the first verdict; findings with
    no resolvable anchor and findings past the wall-clock budget are left
    untouched (the dashboard can still run a live investigation for them).

    Returns ``results_by_key``: full ``AssistantInvestigationResult`` payloads
    (scope-attached, presentation-filtered) keyed by the stable
    ``finding_validation_storage_key`` the dashboard sessions use, so the caller
    can persist a ``finding_validations.json`` sidecar beside the report.
    """
    deadline = time.monotonic() + max(0.0, float(total_budget_seconds))
    cache: _ValidationCache = {}
    persisted_by_anchor: Dict[Tuple[str, Optional[int]], Dict[str, Any]] = {}
    results_by_key: Dict[str, Dict[str, Any]] = {}
    statuses: Counter[str] = Counter()
    validated = 0
    cached_hits = 0
    skipped_no_anchor = 0
    budget_exhausted = False

    for row_index, row in enumerate(rows or []):
        for chunk_index, finding_index, finding, (sink_file, sink_line) in _safe_iter_finding_anchors(
            row, scan_root
        ):
            if sink_file is None or sink_line is None:
                skipped_no_anchor += 1
                continue
            anchor = (str(sink_file), sink_line)
            result = cache.get(anchor)
            if anchor not in cache:
                if time.monotonic() >= deadline:
                    budget_exhausted = True
                    break
                result = _run_single_validation(
                    vulnerability_name=vulnerability_name,
                    scan_root=scan_root,
                    sink_file=sink_file,
                    sink_line=sink_line,
                )
                cache[anchor] = result
                if result is not None:
                    persisted_by_anchor[anchor] = _persisted_result_dict(
                        result,
                        vulnerability_name=vulnerability_name,
                        scan_root=scan_root,
                        sink_file=sink_file,
                        sink_line=sink_line,
                    )
            else:
                cached_hits += 1
            if result is None:
                continue
            statuses[result.status] += 1
            validated += 1
            persisted = persisted_by_anchor.get(anchor)
            if persisted is None:
                continue
            _finding_set_validation(
                finding,
                {
                    "status": result.status,
                    "confidence": result.confidence,
                    "summary": result.summary,
                    "family": result.family,
                    "validation_backend": result.validation_backend,
                },
            )
            fk = finding_validation_storage_key("", row_index, chunk_index, finding_index)
            if fk:
                results_by_key[fk] = persisted

    return {
        "validated": validated,
        "cached": cached_hits,
        "skipped_no_anchor": skipped_no_anchor,
        "statuses": dict(statuses),
        "budget_exhausted": budget_exhausted,
        "results_by_key": results_by_key,
    }


def summarize_validation_stats(vuln_name: str, stats: Dict[str, Any]) -> str:
    """Human-readable detail line (paired with the ``LG_FINDING_VALIDATION`` banner)."""
    parts = [f"validated={stats.get('validated', 0)}"]
    if stats.get("cached"):
        parts.append(f"cached={stats['cached']}")
    if stats.get("skipped_no_anchor"):
        parts.append(f"no_anchor={stats['skipped_no_anchor']}")
    if stats.get("budget_exhausted"):
        parts.append("budget_exhausted=true")
    status_bits = " ".join(f"{k}={v}" for k, v in sorted((stats.get("statuses") or {}).items()))
    if status_bits:
        parts.append(status_bits)
    return ", ".join(parts)


__all__ = [
    "annotate_rows_with_validation",
    "summarize_validation_stats",
]