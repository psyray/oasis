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
from typing import Iterable, List, Optional, Protocol, Set

from oasis.schemas.analysis import (
    AssistantInvestigationResult,
    Citation,
    EntryPointHit,
    ExecutionPath,
)

logger = logging.getLogger(__name__)
_MISSING = object()


class CitationLike(Protocol):
    """Structural citation view used by defensive helper code."""

    file_path: Optional[str]
    start_line: Optional[int]
    end_line: Optional[int]


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
        ep = getattr(path, "entry_point", None)
        if ep is None:
            continue
        keys.add(_entry_point_key(ep))
    return keys


def _read_attr(obj: Optional[object], name: str) -> tuple[Optional[object], bool]:
    """Read an attribute and track whether it exists on the runtime object."""
    if obj is None:
        return (None, False)
    value = getattr(obj, name, _MISSING)
    return ((None, False) if value is _MISSING else (value, True))


def _citation_fields(
    citation: Optional[CitationLike],
) -> tuple[Optional[str], Optional[int], Optional[int], tuple[bool, bool, bool]]:
    """Return defensive citation fields, tolerating partial/missing objects."""
    path_raw, has_path = _read_attr(citation, "file_path")
    start_raw, has_start = _read_attr(citation, "start_line")
    end_raw, has_end = _read_attr(citation, "end_line")
    file_path = path_raw if isinstance(path_raw, str) else None
    start_line = start_raw if isinstance(start_raw, int) else None
    end_line = end_raw if isinstance(end_raw, int) else None
    return (
        file_path,
        start_line,
        end_line,
        (has_path, has_start, has_end),
    )


def _entry_point_key(ep: EntryPointHit) -> tuple:
    """Identifier comparing entry points by framework + label + citation.

    For fully-populated objects, we use a stable value key so execution path
    links continue to match equivalent pydantic instances by content.
    For partial objects (missing attributes), we use an instance discriminator to
    avoid harmful collisions where absent fields would otherwise collapse
    unrelated entry points into the same key.
    """
    framework, has_framework = _read_attr(ep, "framework")
    label, has_label = _read_attr(ep, "label")
    route, has_route = _read_attr(ep, "route")
    cit_path, cit_start, cit_end, citation_presence = _citation_fields(
        getattr(ep, "citation", None)
    )
    if not all((has_framework, has_label, has_route, *citation_presence)):
        return ("partial", id(ep))
    return ("full", framework, label, route, cit_path, cit_start, cit_end)


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
        same_file := [
            ep
            for ep in eps
            if _file_matches_sink(
                _citation_fields(getattr(ep, "citation", None))[0], sink_norm
            )
        ]
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
    return [
        ep
        for ep in eps
        if _file_matches_sink(
            _citation_fields(getattr(ep, "citation", None))[0], sink_norm
        )
    ]


def _rebuild_citations(
    entry_points: Iterable[EntryPointHit],
    result: AssistantInvestigationResult,
) -> List[Citation]:
    """Rebuild ``citations`` after EP filtering, mirroring the verdict aggregator order."""
    seen: Set[tuple] = set()
    out: List[Citation] = []

    def add(cit: Optional[Citation]) -> None:
        if cit is None:
            return
        file_path = getattr(cit, "file_path", None)
        if not isinstance(file_path, str) or not file_path.strip():
            return
        key = (cit.file_path, cit.start_line, cit.end_line)
        if key in seen:
            return
        seen.add(key)
        out.append(cit)

    for ep in entry_points:
        add(getattr(ep, "citation", None))
    for path in result.execution_paths:
        entry_point = getattr(path, "entry_point", None)
        if entry_point is not None:
            add(getattr(entry_point, "citation", None))
        for hop in getattr(path, "hops", []):
            add(getattr(hop, "citation", None))
    for flow in result.taint_flows:
        add(getattr(flow, "source_citation", None))
        add(getattr(flow, "sink_citation", None))
    for mit in result.mitigations:
        add(getattr(mit, "citation", None))
    for hit in result.authz_checks:
        add(getattr(hit, "citation", None))
    for check in result.control_checks:
        for cit in getattr(check, "citations", []):
            add(cit)
    for cf in result.config_findings:
        add(getattr(cf, "citation", None))
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
