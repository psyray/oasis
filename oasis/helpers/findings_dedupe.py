"""Transverse finding deduplication for canonical scan results.

The LLM deep pass can emit the same finding twice (overlapping chunks,
re-formulated snippets, ...). This helper merges duplicates **in place**
inside the ``detailed_results`` rows structure right after the deep pass and
before scan-time validation and report generation, so every downstream
consumer (canonical JSON, stats, exports, sidecar, diff baseline) sees the
deduplicated list.

Two findings of the same vulnerability type are duplicates when they point at
the same file and either:

- their ``vulnerable_code`` snippets normalize to the same fingerprint
  (reusing :func:`oasis.helpers.suppressions.finding_fingerprint`), or
- both have resolved ``snippet_start_line``/``snippet_end_line`` ranges and
  those ranges overlap.

Per duplicate cluster the best finding is kept — highest severity, then the
longest snippet — and the others are removed. Document order is preserved:
kept findings stay at their original positions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

from oasis.helpers.suppressions import finding_fingerprint, normalize_snippet_text

_SEVERITY_RANK: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

_MemberKey = Tuple[int, int, int]  # (row_index, chunk_index, finding_index)


@dataclass
class _Cluster:
    """One duplicate group: same file, same snippet fingerprint or overlap."""

    file_path: str
    fingerprint: str
    start: Optional[int]
    end: Optional[int]
    members: List[_MemberKey] = field(default_factory=list)
    best: Optional[_MemberKey] = None
    best_rank: int = -1
    best_snippet_len: int = -1


def finding_field(obj: Any, name: str) -> Any:
    """Read *name* from a dict-like or model-like finding/row/chunk (shared accessor)."""
    return obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)


def _normalize_file_path(value: Any) -> str:
    return str(value or "").strip().replace("\\", "/")


def _coerce_line(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    return None


def _resolved_range(finding: Any) -> Optional[Tuple[int, int]]:
    start = _coerce_line(finding_field(finding, "snippet_start_line"))
    end = _coerce_line(finding_field(finding, "snippet_end_line"))
    if start is None or end is None or end < start:
        return None
    return start, end


def _severity_rank(finding: Any) -> int:
    severity = finding_field(finding, "severity")
    return _SEVERITY_RANK.get(str(severity or "").strip().lower(), 0)


def _ranges_overlap(
    first: Tuple[int, int], second: Tuple[int, int]
) -> bool:
    return first[0] <= second[1] and second[0] <= first[1]


def iter_structured_chunks(
    rows: Any,
) -> Iterator[Tuple[int, int, Any, List[Any], str]]:
    """Yield ``(row_index, chunk_index, chunk, findings, file_path)`` for every
    structured chunk holding a findings list.

    Shared traversal for the in-place findings passes (dedup, inline ignore
    markers). Callers may replace ``chunk.findings`` while iterating: the
    yielded list is the snapshot they enumerate.
    """
    for row_index, row in enumerate(rows or []):
        file_path = _normalize_file_path(finding_field(row, "file_path"))
        chunks = finding_field(row, "structured_chunks")
        if not isinstance(chunks, list):
            continue
        for chunk_index, chunk in enumerate(chunks):
            findings = finding_field(chunk, "findings")
            if not isinstance(findings, list):
                continue
            yield row_index, chunk_index, chunk, findings, file_path


def set_chunk_field(chunk: Any, name: str, value: Any) -> None:
    """Assign one field back to a dict-like or model-like chunk."""
    if isinstance(chunk, dict):
        chunk[name] = value
    else:
        setattr(chunk, name, value)


def set_chunk_findings(chunk: Any, kept: List[Any]) -> None:
    """Assign a filtered findings list back to a dict-like or model-like chunk."""
    set_chunk_field(chunk, "findings", kept)


def deduplicate_rows_findings(
    rows: Any,
    vulnerability_name: str,
) -> Dict[str, int]:
    """Deduplicate findings across *rows* in place for one vulnerability type.

    Returns ``{"clusters": <group count>, "duplicates_removed": <count>}``.
    Malformed rows/chunks/findings are skipped silently: dedup must never
    abort the deep pass.
    """
    clusters: List[_Cluster] = []

    for row_index, chunk_index, _chunk, findings, file_path in iter_structured_chunks(rows):
        for finding_index, finding in enumerate(findings):
            snippet = finding_field(finding, "vulnerable_code")
            snippet_text = snippet if isinstance(snippet, str) else ""
            fingerprint = (
                finding_fingerprint(file_path, vulnerability_name, snippet_text)
                if file_path and normalize_snippet_text(snippet_text)
                else ""
            )
            line_range = _resolved_range(finding)
            rank = _severity_rank(finding)
            snippet_len = len(normalize_snippet_text(snippet_text))

            target: Optional[_Cluster] = None
            for cluster in clusters:
                if cluster.file_path != file_path:
                    continue
                if fingerprint and cluster.fingerprint == fingerprint:
                    target = cluster
                    break
                if (
                    line_range is not None
                    and cluster.start is not None
                    and cluster.end is not None
                    and _ranges_overlap((cluster.start, cluster.end), line_range)
                ):
                    target = cluster
                    break
            member = (row_index, chunk_index, finding_index)
            if target is None:
                clusters.append(
                    _Cluster(
                        file_path=file_path,
                        fingerprint=fingerprint,
                        start=line_range[0] if line_range else None,
                        end=line_range[1] if line_range else None,
                        members=[member],
                        best=member,
                        best_rank=rank,
                        best_snippet_len=snippet_len,
                    )
                )
                continue

            target.members.append(member)
            better = rank > target.best_rank or (
                rank == target.best_rank and snippet_len > target.best_snippet_len
            )
            if better:
                target.best = member
                target.best_rank = rank
                target.best_snippet_len = snippet_len

    removed: set[_MemberKey] = set()
    for cluster in clusters:
        if cluster.best is None:
            continue
        for member in cluster.members:
            if member != cluster.best:
                removed.add(member)

    if removed:
        for row_index, chunk_index, chunk, findings, _file_path in iter_structured_chunks(rows):
            kept = [
                finding
                for finding_index, finding in enumerate(findings)
                if (row_index, chunk_index, finding_index) not in removed
            ]
            if len(kept) != len(findings):
                set_chunk_findings(chunk, kept)

    return {
        "clusters": len(clusters),
        "duplicates_removed": len(removed),
    }


__all__ = [
    "deduplicate_rows_findings",
    "finding_field",
    "iter_structured_chunks",
    "set_chunk_field",
    "set_chunk_findings",
]