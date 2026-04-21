"""Lightweight taint-flow detector: tie user-controlled sources to sinks.

This helper complements :mod:`oasis.helpers.assistant_trace`. While the trace
helper reconstructs *call* chains, this one reconstructs *data* chains inside
the same function body by looking for simple variable flow patterns:

    value = request.args.get("q")   # source
    ...
    cursor.execute(value)           # sink

The detection is intentionally shallow (no SSA, no alias analysis): it is good
enough to flag obvious flows, it scales to any language, and the verdict node
uses its output as one signal among others.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set

from oasis.helpers.assistant_scan_utils import read_text_safely
from oasis.helpers.validation_patterns import SINKS, SOURCES
from oasis.schemas.analysis import Citation, TaintFlow


_ASSIGNMENT_PATTERN = re.compile(
    r"""^\s*(?:var\s+|let\s+|const\s+)?(?P<name>[A-Za-z_][\w]*)\s*=\s*(?P<rhs>.+)$"""
)


def _compiled(patterns: Sequence[str]) -> List[re.Pattern[str]]:
    return [re.compile(p) for p in patterns]


def _line_matches_any(line: str, compiled: List[re.Pattern[str]]) -> bool:
    return any(p.search(line) for p in compiled)


def _collect_source_variables(
    lines: List[str],
    start: int,
    end: int,
    compiled_sources: Dict[str, List[re.Pattern[str]]],
) -> Dict[str, str]:
    """Return a map ``variable -> source_kind`` within ``lines[start:end]``."""
    tainted: Dict[str, str] = {}
    for idx in range(start, end):
        line = lines[idx]
        assign = _ASSIGNMENT_PATTERN.match(line)
        rhs = assign.group("rhs") if assign else line
        for source_kind, compiled in compiled_sources.items():
            if not _line_matches_any(rhs, compiled):
                continue
            if assign is not None:
                tainted[assign.group("name")] = source_kind
            else:
                tainted.setdefault(f"__line_{idx + 1}", source_kind)
            break
    return tainted


def _window_bounds(total: int, line_number: int, radius: int) -> tuple[int, int]:
    start = max(0, line_number - 1 - radius)
    end = min(total, line_number - 1 + radius + 1)
    return start, end


def detect_flows_for_sink(
    sink_file: Path,
    sink_line: int,
    sink_kinds: Sequence[str],
    *,
    source_kinds: Sequence[str] = ("http_params", "http_headers", "http_body", "http_file_upload"),
    radius: int = 60,
) -> List[TaintFlow]:
    """Find plausible taint flows feeding *sink_line* in *sink_file*.

    Strategy: look ``radius`` lines above the sink (typical function body size
    after which the data provenance becomes speculative anyway), collect any
    variable that is assigned from a user-controlled source, then emit a flow
    whenever one of those variables is referenced on (or just around) the
    sink line.
    """
    text = read_text_safely(sink_file)
    if text is None:
        return []
    lines = text.splitlines()
    if not lines:
        return []

    compiled_sources = {kind: _compiled(SOURCES.get(kind, [])) for kind in source_kinds}
    compiled_sinks = {kind: _compiled(SINKS.get(kind, [])) for kind in sink_kinds}

    start, end = _window_bounds(len(lines), sink_line, radius)
    tainted = _collect_source_variables(lines, start, end, compiled_sources)
    if not tainted:
        return []

    # Build an index of first source occurrence per kind for citations.
    source_citations: Dict[str, Citation] = {}
    for idx in range(start, end):
        line = lines[idx]
        for kind, compiled in compiled_sources.items():
            if kind in source_citations:
                continue
            if _line_matches_any(line, compiled):
                source_citations[kind] = Citation(
                    file_path=str(sink_file),
                    start_line=idx + 1,
                    end_line=idx + 1,
                    snippet=line.rstrip(),
                )

    flows: List[TaintFlow] = []
    sink_snippet = lines[min(max(sink_line - 1, 0), len(lines) - 1)]
    sink_citation_base = Citation(
        file_path=str(sink_file),
        start_line=sink_line,
        end_line=sink_line,
        snippet=sink_snippet.rstrip(),
    )

    already_emitted: Set[tuple[str, str]] = set()
    for sink_kind, compiled in compiled_sinks.items():
        if not _line_matches_any(sink_snippet, compiled):
            continue
        for variable, source_kind in tainted.items():
            if variable.startswith("__line_") or re.search(rf"\b{re.escape(variable)}\b", sink_snippet):
                pair = (source_kind, sink_kind)
                if pair in already_emitted:
                    continue
                already_emitted.add(pair)
                flows.append(
                    TaintFlow(
                        source_kind=source_kind,
                        sink_kind=sink_kind,
                        source_citation=source_citations.get(source_kind, sink_citation_base),
                        sink_citation=sink_citation_base,
                    )
                )
    return flows


def detect_flows_for_descriptor(
    sink_file: Path,
    sink_line: int,
    descriptor_sink_kinds: Sequence[str],
    descriptor_source_kinds: Sequence[str],
) -> List[TaintFlow]:
    """Convenience wrapper that plugs a :class:`VulnDescriptor` directly in."""
    if not descriptor_sink_kinds:
        return []
    return detect_flows_for_sink(
        sink_file,
        sink_line,
        descriptor_sink_kinds,
        source_kinds=descriptor_source_kinds or (),
    )
