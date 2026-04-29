"""Presentation-time filtering of assistant validation results.

Goal: keep deterministic verdict honest (computed on full evidence by
:func:`oasis.helpers.assistant.verdict.verdict.compute_verdict`) while
suppressing noisy ``entry_points`` and citations that are unrelated to
the user's selected sink. This avoids LLM narratives that "explain"
Flask routes when the actual finding lives in another file (e.g.,
``Vulnerable.cs``) — without changing the verdict label or confidence.

Filtering rules (locked in plan §5 step 3):

- ``family == "flow"``: keep ``entry_points`` cited by at least one
  ``execution_paths.entry_point``; otherwise keep only EPs whose citation
  file matches ``scope.sink_file``; otherwise the empty list.
- ``family == "access"``: keep EPs whose citation file matches
  ``scope.sink_file``; otherwise empty (``control_checks`` /
  ``authz_checks`` carry the evidence).
- ``family == "config"``: untouched (pipeline does not produce EPs).

The verdict (``status``, ``confidence``, ``summary``) is never altered:
this filter operates on a copy of the result *after* aggregation, used
both as the API response and as the input to LLM synthesis.
"""

from __future__ import annotations

import logging
from pathlib import PurePosixPath
from typing import Iterable, List, Optional, Set

from oasis.schemas.analysis import (
    AssistantInvestigationResult,
    Citation,
    EntryPointHit,
    ExecutionPath,
)

logger = logging.getLogger(__name__)


def _normalize_path(value: Optional[str]) -> Optional[str]:
    """Normalize a path string for cross-OS comparison (POSIX, no leading slash)."""
    if not isinstance(value, str):
        return None
    text = value.strip().replace("\\", "/")
    if not text:
        return None
    parts = [seg for seg in text.split("/") if seg and seg != "."]
    return str(PurePosixPath(*parts)) if parts else None


def _file_matches_sink(citation_path: Optional[str], sink_norm: Optional[str]) -> bool:
    """Return True when *citation_path* refers to the same file as *sink_norm*.

    Handles the common dashboard case where ``scope.sink_file`` is relative to
    ``scan_root`` and citations are stored as relative paths too. We accept a
    suffix match either way to tolerate one side being absolute.
    """
    if not sink_norm:
        return False
    if cit_norm := _normalize_path(citation_path):
        return (
            cit_norm == sink_norm
            or cit_norm.endswith(f"/{sink_norm}")
            or sink_norm.endswith(f"/{cit_norm}")
        )
    return False


def _execution_path_entry_keys(paths: Iterable[ExecutionPath]) -> Set[tuple]:
    """Stable identifiers for entry points referenced by execution paths."""
    keys: Set[tuple] = set()
    for path in paths:
        ep = path.entry_point
        if ep is None:
            continue
        keys.add(_entry_point_key(ep))
    return keys


def _entry_point_key(ep: EntryPointHit) -> tuple:
    """Identifier comparing entry points by framework + label + citation."""
    cit = ep.citation
    return (
        ep.framework,
        ep.label,
        ep.route,
        cit.file_path,
        cit.start_line,
        cit.end_line,
    )


def _filter_entry_points_for_flow(
    result: AssistantInvestigationResult,
    sink_norm: Optional[str],
) -> List[EntryPointHit]:
    """Apply the flow-family filter rule on ``result.entry_points``."""
    eps = list(result.entry_points)
    if not eps:
        return eps
    if path_keys := _execution_path_entry_keys(result.execution_paths):
        if linked := [ep for ep in eps if _entry_point_key(ep) in path_keys]:
            return linked
    if sink_norm and (
        same_file := [ep for ep in eps if _file_matches_sink(ep.citation.file_path, sink_norm)]
    ):
        return same_file
    return []


def _filter_entry_points_for_access(
    result: AssistantInvestigationResult,
    sink_norm: Optional[str],
) -> List[EntryPointHit]:
    """Apply the access-family filter rule on ``result.entry_points``."""
    eps = list(result.entry_points)
    if not eps or not sink_norm:
        return []
    return [ep for ep in eps if _file_matches_sink(ep.citation.file_path, sink_norm)]


def _rebuild_citations(
    entry_points: Iterable[EntryPointHit],
    result: AssistantInvestigationResult,
) -> List[Citation]:
    """Rebuild ``citations`` after EP filtering, mirroring the verdict aggregator order."""
    seen: Set[tuple] = set()
    out: List[Citation] = []

    def add(cit: Citation) -> None:
        key = (cit.file_path, cit.start_line, cit.end_line)
        if key in seen:
            return
        seen.add(key)
        out.append(cit)

    for ep in entry_points:
        add(ep.citation)
    for path in result.execution_paths:
        if path.entry_point is not None:
            add(path.entry_point.citation)
        for hop in path.hops:
            add(hop.citation)
    for flow in result.taint_flows:
        add(flow.source_citation)
        add(flow.sink_citation)
    for mit in result.mitigations:
        add(mit.citation)
    for hit in result.authz_checks:
        add(hit.citation)
    for check in result.control_checks:
        for cit in check.citations:
            add(cit)
    for cf in result.config_findings:
        add(cf.citation)
    return out


def apply_presentation_filter_to_result(
    result: AssistantInvestigationResult,
) -> AssistantInvestigationResult:
    """Return a presentation-friendly copy of *result* with EPs filtered to the sink.

    The verdict (``status``, ``confidence``, ``summary``) is never modified.
    When ``result.scope`` is missing or ``family == "config"``, *result* is
    returned unchanged (no EPs are emitted by the config pipeline).
    """
    scope = result.scope
    if scope is None:
        return result
    family = result.family
    if family == "config":
        return result

    sink_norm = _normalize_path(scope.sink_file)
    if family == "flow":
        filtered = _filter_entry_points_for_flow(result, sink_norm)
    elif family == "access":
        filtered = _filter_entry_points_for_access(result, sink_norm)
    else:
        return result

    if len(filtered) == len(result.entry_points):
        return result

    omitted = len(result.entry_points) - len(filtered)
    if omitted > 0:
        logger.debug(
            "Assistant validation: filtered %d/%d entry_points for presentation "
            "(family=%s sink=%s)",
            omitted,
            len(result.entry_points),
            family,
            sink_norm or "<unset>",
        )

    new_citations = _rebuild_citations(filtered, result)
    return result.model_copy(
        update={
            "entry_points": filtered,
            "citations": new_citations,
        }
    )


__all__ = [
    "apply_presentation_filter_to_result",
]
