"""Lightweight taint-flow detector: tie user-controlled sources to sinks.

This helper complements :mod:`oasis.helpers.assistant_trace`. While the trace
helper reconstructs *call* chains, this one reconstructs *data* chains inside
the same function body by looking for simple variable flow patterns:

    value = request.args.get("q")   # source
    ...
    cursor.execute(value)           # sink

Assignment parsing is heuristic and covers common shapes across typical OASIS
targets (e.g. ``x =``, Go ``:=``, PHP ``$x =``, Ruby ``@x =``, Kotlin ``val``,
and typed LHS such as ``String s =`` / ``final T v =``) by taking the last
identifier token before a lone ``=``. It is still shallow (no SSA, no alias
analysis, no tuple-unpacking): good enough to flag obvious flows; the verdict
node uses its output as one signal among others. The generic ``=`` fallback
ignores LHS with ``.``, ``[]``, or comma-separated targets so member writes,
subscripts, and destructuring are not mistaken for simple bindings.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set

from oasis.helpers.assistant_scan_utils import read_text_safely
from oasis.helpers.validation_patterns import SINKS, SOURCES
from oasis.schemas.analysis import Citation, TaintFlow

# Lone "=" not part of ==, !=, <=, >=, or =>.
_ASSIGN_OP = re.compile(r"(?<![=!<>])=(?!=|>)")

_GO_ASSIGN = re.compile(
    r"""^\s*(?P<name>[A-Za-z_][\w]*)\s*:=\s*(?P<rhs>.+)$"""
)
_PHP_ASSIGN = re.compile(
    r"""^\s*\$(?P<name>[A-Za-z_][\w]*)\s*=\s*(?P<rhs>.+)$"""
)
_RUBY_IVAR_ASSIGN = re.compile(
    r"""^\s*(?P<name>@@?[A-Za-z_][\w]*)\s*=\s*(?P<rhs>.+)$"""
)
_JS_LIKE_ASSIGN = re.compile(
    r"""^\s*(?:var\s+|let\s+|const\s+|val\s+)?(?P<name>[A-Za-z_][\w]*)\s*=\s*(?P<rhs>.+)$"""
)

_IDENTIFIER_TOKEN = re.compile(r"[A-Za-z_][\w]*")


def _reject_generic_assign_fallback(line: str, assign_match: re.Match[str]) -> bool:
    """Reject *_ASSIGN_OP* matches that are unlikely to be simple assignments."""
    lhs = line[: assign_match.start()].strip()
    if not lhs:
        return True
    if "&&" in lhs or "||" in lhs:
        return True
    if "==" in lhs or "!=" in lhs or "<=" in lhs or ">=" in lhs:
        return True
    # Ternary parsed as LHS (not valid assignment); allow RHS like ``x = a ? b : c``.
    return "?" in lhs and ":" in lhs


def _generic_assign_lhs_too_complex(lhs: str) -> bool:
    """True if *lhs* is not a simple assignee (member, subscript, multi-target)."""
    return any(ch in lhs for ch in (".", "[", "]", ","))


def _compiled(patterns: Sequence[str]) -> List[re.Pattern[str]]:
    return [re.compile(p) for p in patterns]


def _line_matches_any(line: str, compiled: List[re.Pattern[str]]) -> bool:
    return any(p.search(line) for p in compiled)


def _is_identifier_boundary(ch: Optional[str]) -> bool:
    """True if *ch* ends / starts an identifier token for cross-language matching."""
    return True if ch is None else not (ch.isalnum() or ch == "_")


def _sigil_variable_referenced_on_sink_line(variable: str, sink_snippet: str) -> bool:
    """Match PHP/Ruby ``$x`` / ``@x`` (including ``${x}``, ``#{@x}``, ``?``/``!`` suffixes)."""
    escaped = re.escape(variable)
    sigil_pat = rf"{escaped}[!?]?"
    for match in re.finditer(sigil_pat, sink_snippet):
        start, end = match.span()
        before = sink_snippet[start - 1] if start > 0 else None
        after = sink_snippet[end] if end < len(sink_snippet) else None
        if _is_identifier_boundary(before) and _is_identifier_boundary(after):
            return True

    name_no_sigils = re.escape(variable.lstrip("$@"))
    if re.search(rf"\$\{{{name_no_sigils}[!?]?\}}", sink_snippet):
        return True
    return re.search(rf"#\{{\s*{escaped}[!?]?\s*\}}", sink_snippet) is not None


def _variable_referenced_on_sink_line(variable: str, sink_snippet: str) -> bool:
    """Return True if *variable* appears as a use on the sink line.

    Handles plain identifiers, PHP ``$x`` / ``${x}``, Ruby ``@x`` / ``@x?``,
    and similar without matching a shorter name inside a longer one (e.g. ``$x``
    inside ``$xyz``).
    """
    if not variable:
        return False

    if variable.startswith(("$", "@")):
        return _sigil_variable_referenced_on_sink_line(variable, sink_snippet)

    return re.search(rf"\b{re.escape(variable)}\b", sink_snippet) is not None


def _parse_assignment(line: str) -> Optional[tuple[str, str]]:
    """Return (variable_name, rhs) if *line* looks like a simple assignment."""
    if "=" not in line:
        return None
    for pattern in (_GO_ASSIGN, _PHP_ASSIGN, _RUBY_IVAR_ASSIGN, _JS_LIKE_ASSIGN):
        m = pattern.match(line)
        if m is not None:
            return m.group("name"), m.group("rhs")
    m = _ASSIGN_OP.search(line)
    if m is None:
        return None
    if _reject_generic_assign_fallback(line, m):
        return None
    lhs = line[: m.start()].strip()
    rhs = line[m.end() :].strip()
    if not lhs or not rhs:
        return None
    if _generic_assign_lhs_too_complex(lhs):
        return None
    tokens = _IDENTIFIER_TOKEN.findall(lhs)
    return (tokens[-1], rhs) if tokens else None


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
        parsed = _parse_assignment(line)
        rhs = parsed[1] if parsed else line
        for source_kind, compiled in compiled_sources.items():
            if not _line_matches_any(rhs, compiled):
                continue
            if parsed is not None:
                tainted[parsed[0]] = source_kind
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
            if variable.startswith("__line_") or _variable_referenced_on_sink_line(
                variable, sink_snippet
            ):
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
