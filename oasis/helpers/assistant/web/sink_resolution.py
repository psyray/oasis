"""Resolve assistant validation sink (file + line) from finding indices.

The dashboard sends ``(file_index, chunk_index, finding_index)`` for the
selected finding plus optional ``finding_scope_report_path``. This module
turns those wire fields into a concrete ``(sink_file, sink_line)`` pair so
``/api/assistant/investigate`` can run the LangGraph validator on the
correct anchor — even when the primary report is the executive summary
(no ``files`` array of its own).

Pure helpers: only filesystem ``is_file()`` checks (no network), so the
logic is cheap to unit-test with temporary directories.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from oasis.helpers.context.path_containment import is_path_within_root


def coerce_positive_int_line(value: Any) -> Optional[int]:
    """Return *value* as a positive ``int`` line number, else ``None``.

    Accepts ``int`` and ``float`` integers (e.g. ``113.0`` from JSON parsers
    that always yield floats); rejects negatives, zero, ``bool``, strings,
    ``NaN`` and non-integral floats. Centralized so ``web.py`` and the
    helper share the same coercion rule.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, float):
        if value != value or value <= 0 or not value.is_integer():
            return None
        return int(value)
    return None


def _sink_from_payload_indices(
    payload: Dict[str, Any],
    *,
    fi: Optional[int],
    ci: Optional[int],
    gi: Optional[int],
    scan_root: Path,
) -> Tuple[Optional[Path], Optional[int]]:
    """Lookup ``(sink_file, sink_line)`` inside one canonical vuln payload."""
    if fi is None or fi < 0:
        return None, None
    files = payload.get("files")
    if not isinstance(files, list) or fi >= len(files):
        return None, None
    file_entry = files[fi]
    if not isinstance(file_entry, dict):
        return None, None

    sink_file: Optional[Path] = None
    fp = file_entry.get("file_path")
    if isinstance(fp, str) and fp.strip():
        candidate = (scan_root / fp).resolve(strict=False)
        if is_path_within_root(candidate, scan_root) and candidate.is_file():
            sink_file = candidate

    sink_line: Optional[int] = None
    chunks = file_entry.get("chunk_analyses") or []
    if isinstance(chunks, list) and ci is not None and 0 <= ci < len(chunks):
        chunk = chunks[ci]
        if isinstance(chunk, dict):
            findings = chunk.get("findings") or []
            chosen_line: Any = None
            if (
                isinstance(findings, list)
                and gi is not None
                and 0 <= gi < len(findings)
                and isinstance(findings[gi], dict)
            ):
                finding = findings[gi]
                chosen_line = finding.get("snippet_start_line") or chunk.get("start_line")
            else:
                chosen_line = chunk.get("start_line")
            sink_line = coerce_positive_int_line(chosen_line)

    return sink_file, sink_line


def resolve_sink_from_finding_indices(
    primary_payload: Dict[str, Any],
    scope_payload: Optional[Dict[str, Any]],
    *,
    fi: Optional[int],
    ci: Optional[int],
    gi: Optional[int],
    scan_root: Path,
) -> Tuple[Optional[Path], Optional[int]]:
    """Resolve ``(sink_file, sink_line)`` from finding indices.

    Resolution order:

    1. ``scope_payload`` (the vulnerability JSON pointed to by
       ``finding_scope_report_path``) — used when the primary report is the
       executive summary, which has no ``files`` array.
    2. ``primary_payload`` (a direct vulnerability report).
    3. ``(None, None)`` if neither yields a usable anchor.

    Both payloads must look like ``VulnerabilityReportDocument`` (top-level
    ``files`` list with ``chunk_analyses`` per file). The function never
    raises on malformed inputs; it returns ``(None, None)`` instead so the
    caller can fall back to client-supplied hints.
    """
    if isinstance(scope_payload, dict):
        sink_file, sink_line = _sink_from_payload_indices(
            scope_payload, fi=fi, ci=ci, gi=gi, scan_root=scan_root
        )
        if sink_file is not None or sink_line is not None:
            return sink_file, sink_line

    if isinstance(primary_payload, dict):
        return _sink_from_payload_indices(
            primary_payload, fi=fi, ci=ci, gi=gi, scan_root=scan_root
        )

    return None, None


__all__ = [
    "coerce_positive_int_line",
    "resolve_sink_from_finding_indices",
]
