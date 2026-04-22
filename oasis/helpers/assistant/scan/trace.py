"""Callers trace from a vulnerable sink up to plausible entry points.

This helper powers the flow-based validator: starting from a finding's
sink file/line, it reconstructs up to ``max_depth`` of caller hops by
(a) identifying the enclosing function/method symbol and (b) searching
the codebase for references to that symbol. Caller search is intentionally
regex-based and language-agnostic so OASIS can reason about Python, JS,
Go, Ruby, PHP and JVM code with a single implementation.

Deterministic + KISS: we don't build a full call graph, we only surface
evidence rows the LLM can cite or the verdict aggregator can weigh.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .scan_utils import (
    PatternMatch,
    compile_groups,
    iter_source_files,
    read_text_safely,
    scan_patterns_best_effort,
)
from oasis.helpers.context.path_containment import is_path_within_root
from oasis.schemas.analysis import CallHop, Citation, EntryPointHit, ExecutionPath


DEFAULT_MAX_DEPTH = 5
DEFAULT_MAX_FANOUT = 6


_FUNCTION_DEF_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("python_def", re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\(")),
    ("python_class_method", re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\(")),
    ("js_function", re.compile(r"^\s*(?:async\s+)?function\s+(\w+)\s*\(")),
    ("js_method", re.compile(r"^\s*(\w+)\s*\([^)]*\)\s*\{")),
    ("js_arrow", re.compile(r"^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(")),
    ("go_func", re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?(\w+)\s*\(")),
    ("ruby_def", re.compile(r"^\s*def\s+(?:self\.)?(\w+)")),
    ("php_function", re.compile(r"^\s*(?:public|private|protected)?\s*function\s+(\w+)\s*\(")),
    ("java_method", re.compile(r"^\s*(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*\{")),
)


def enclosing_symbol(file_path: Path, line_number: int) -> Optional[str]:
    """Find the function/method name whose body contains *line_number*.

    Walks the file backwards from *line_number* and returns the name on the
    first function/method declaration it encounters. Returns ``None`` when the
    file cannot be read or no definition is found above the line.
    """
    info = enclosing_symbol_with_line(file_path, line_number)
    return info[0] if info else None


def enclosing_symbol_with_line(
    file_path: Path,
    line_number: int,
) -> Optional[Tuple[str, int]]:
    """Like :func:`enclosing_symbol` but also returns the def line (1-based)."""
    text = read_text_safely(file_path)
    if text is None:
        return None
    lines = text.splitlines()
    idx = min(max(line_number, 1), len(lines)) - 1
    while idx >= 0:
        line = lines[idx]
        for _name, pattern in _FUNCTION_DEF_PATTERNS:
            match = pattern.match(line)
            if match:
                return match.group(1), idx + 1
        idx -= 1
    return None


def _build_caller_patterns(symbol: str) -> Dict[str, List[str]]:
    """Regex group for references to *symbol* (dotted access, decorator, bare)."""
    escaped = re.escape(symbol)
    return {
        "caller": [
            rf"(?<![\w.]){escaped}\s*\(",
            rf"\.\s*{escaped}\s*\(",
        ]
    }


def find_callers(
    root: Path,
    symbol: str,
    *,
    exclude_file: Optional[Path] = None,
    max_hits: int = 20,
) -> List[PatternMatch]:
    """Return code locations that call *symbol* inside *root*."""
    if not symbol:
        return []
    compiled = compile_groups(_build_caller_patterns(symbol))
    hits = scan_patterns_best_effort(root, compiled, max_hits=max_hits)
    if exclude_file is not None:
        excluded = exclude_file.resolve(strict=False)
        hits = [
            hit
            for hit in hits
            if hit.file_path.resolve(strict=False) != excluded
        ]
    return hits


def _hit_citation(hit: PatternMatch) -> Citation:
    return Citation(
        file_path=str(hit.file_path),
        start_line=hit.line_number,
        end_line=hit.line_number,
        snippet=hit.line_text,
    )


def _is_entry_point_hit(hit: PatternMatch, entry_points: Dict[str, List[EntryPointHit]]) -> Optional[EntryPointHit]:
    """If *hit* is near an entry point declaration, return it."""
    resolved = hit.file_path.resolve(strict=False)
    for entries in entry_points.values():
        for entry in entries:
            if Path(entry.citation.file_path).resolve(strict=False) != resolved:
                continue
            # Accept match when entry decorator sits on the line or within 3 lines above.
            if entry.citation.start_line - 3 <= hit.line_number <= entry.citation.end_line + 5:
                return entry
    return None


def _entry_point_attached_to_def(
    file_path: Path,
    def_line: int,
    entry_points: Dict[str, List[EntryPointHit]],
) -> Optional[EntryPointHit]:
    """Return the entry point whose decorator is directly above the def, if any."""
    resolved = file_path.resolve(strict=False)
    for entries in entry_points.values():
        for entry in entries:
            if Path(entry.citation.file_path).resolve(strict=False) != resolved:
                continue
            # Decorator is usually 1-4 lines above the ``def``/``function`` line.
            if 0 <= def_line - entry.citation.start_line <= 4:
                return entry
    return None


def trace_to_entry_points(
    root: Path,
    sink_file: Path,
    sink_line: int,
    entry_points: Dict[str, List[EntryPointHit]],
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_fanout: int = DEFAULT_MAX_FANOUT,
) -> List[ExecutionPath]:
    """Walk callers of the sink's enclosing function and stop when we hit an entry point.

    Returns at most ``max_fanout`` :class:`ExecutionPath` entries; each path is
    ordered from the entry point (closest to the user) toward the sink.
    """
    if not is_path_within_root(sink_file, root):
        return []

    symbol_info = enclosing_symbol_with_line(sink_file, sink_line)
    if not symbol_info:
        return []
    symbol, symbol_def_line = symbol_info

    sink_hop = CallHop(
        symbol=symbol,
        citation=Citation(
            file_path=str(sink_file),
            start_line=sink_line,
            end_line=sink_line,
            snippet="",
        ),
    )

    # Fast path: if the enclosing function itself is an entry point (Flask
    # ``@app.route`` decorator, FastAPI verb, ...), emit that path directly
    # rather than searching callers in the framework internals.
    direct_entry = _entry_point_attached_to_def(
        sink_file, symbol_def_line, entry_points
    )
    paths: List[ExecutionPath] = []
    if direct_entry is not None:
        paths.append(
            ExecutionPath(entry_point=direct_entry, hops=[sink_hop], reached_sink=True)
        )

    seen_symbols: Set[str] = {symbol}
    frontier: List[Tuple[str, List[CallHop]]] = [(symbol, [sink_hop])]
    depth = 0
    while frontier and depth < max_depth and len(paths) < max_fanout:
        next_frontier: List[Tuple[str, List[CallHop]]] = []
        for cur_symbol, hops in frontier:
            callers = find_callers(root, cur_symbol, exclude_file=None)
            for hit in callers:
                entry = _is_entry_point_hit(hit, entry_points)
                new_hop = CallHop(symbol=cur_symbol, citation=_hit_citation(hit))
                new_hops = [new_hop, *hops]
                if entry is not None:
                    paths.append(
                        ExecutionPath(entry_point=entry, hops=new_hops, reached_sink=True)
                    )
                    if len(paths) >= max_fanout:
                        return paths
                    continue
                caller_symbol = enclosing_symbol(hit.file_path, hit.line_number)
                if not caller_symbol or caller_symbol in seen_symbols:
                    continue
                seen_symbols.add(caller_symbol)
                next_frontier.append((caller_symbol, new_hops))
        frontier = next_frontier
        depth += 1

    # When no entry point was reached, surface the best partial chain so the LLM
    # can still reason about it rather than losing the evidence entirely.
    if not paths and seen_symbols:
        paths.append(ExecutionPath(entry_point=None, hops=[sink_hop], reached_sink=True))
    return paths


def sample_files_for_scan(
    root: Path,
    *,
    max_files: int = 200,
) -> List[Path]:
    """Return up to *max_files* source files under *root* (debug/testing helper)."""
    return list(iter_source_files(root, max_files=max_files))
