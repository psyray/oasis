"""Compact report summary for the assistant chat system prompt.

Replaces the previous ``json.dumps(report_payload)`` dump with a structured,
size-bounded Markdown summary. The goal is to keep essential context (scan
identity, per-file stats, top findings) while drastically reducing noise so
the model can focus on ``FINDING_VALIDATION_JSON`` and ``SELECTED_FINDING_JSON``.

This module is deliberately framework-free so it can be unit-tested in
isolation from :mod:`oasis.web`. Cross-module tuning index:
:mod:`oasis.helpers.assistant.prompt.prompt_tuning`.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from .prompt_tuning import (
    COMPACT_MAX_FILES_LISTED,
    COMPACT_MAX_TOP_FINDINGS,
    COMPACT_SEVERITY_RANK,
    REPORT_COMPACT_TRUNCATION_SUFFIX,
)


def _severity_rank(value: Any) -> int:
    if not isinstance(value, str):
        return -1
    return COMPACT_SEVERITY_RANK.get(value.strip().lower(), -1)


def _max_severity_of_file(file_entry: Dict[str, Any]) -> str:
    best = ""
    best_rank = -1
    chunks = file_entry.get("chunk_analyses") or []
    if not isinstance(chunks, list):
        return ""
    for chunk in chunks:
        if not isinstance(chunk, dict):
            continue
        findings = chunk.get("findings") or []
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            r = _severity_rank(finding.get("severity"))
            if r > best_rank:
                best_rank = r
                best = str(finding.get("severity") or "").strip()
    return best


def _count_findings_in_file(file_entry: Dict[str, Any]) -> int:
    total = 0
    chunks = file_entry.get("chunk_analyses") or []
    if not isinstance(chunks, list):
        return 0
    for chunk in chunks:
        if not isinstance(chunk, dict):
            continue
        findings = chunk.get("findings") or []
        if isinstance(findings, list):
            total += sum(isinstance(f, dict) for f in findings)
    return total


def _iter_findings_with_location(report_payload: Dict[str, Any]):
    """Yield ``(severity_rank, severity, file_path, start_line, title)`` tuples."""
    files = report_payload.get("files") or []
    if not isinstance(files, list):
        return
    for file_entry in files:
        if not isinstance(file_entry, dict):
            continue
        file_path = str(file_entry.get("file_path") or "").strip()
        chunks = file_entry.get("chunk_analyses") or []
        if not isinstance(chunks, list):
            continue
        for chunk in chunks:
            if not isinstance(chunk, dict):
                continue
            chunk_start = chunk.get("start_line")
            findings = chunk.get("findings") or []
            if not isinstance(findings, list):
                continue
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                severity = str(finding.get("severity") or "").strip()
                rank = _severity_rank(severity)
                start_line = (
                    finding.get("snippet_start_line")
                    or chunk_start
                    or 0
                )
                try:
                    start_line = int(start_line or 0)
                except (TypeError, ValueError):
                    start_line = 0
                title = str(finding.get("title") or "").strip()
                yield rank, severity, file_path, start_line, title


def _format_files_summary_lines(report_payload: Dict[str, Any]) -> List[str]:
    files = report_payload.get("files") or []
    if not isinstance(files, list) or not files:
        return []
    rows: List[Tuple[int, int, str, str]] = []
    for entry in files:
        if not isinstance(entry, dict):
            continue
        fp = str(entry.get("file_path") or "").strip()
        if not fp:
            continue
        count = _count_findings_in_file(entry)
        max_sev = _max_severity_of_file(entry)
        rows.append((_severity_rank(max_sev), count, max_sev, fp))
    rows.sort(key=lambda r: (-r[0], -r[1], r[3]))
    lines: List[str] = []
    shown = rows[:COMPACT_MAX_FILES_LISTED]
    for _rank, count, max_sev, fp in shown:
        sev_label = max_sev or "n/a"
        lines.append(f"- {fp}: {count} finding(s), max severity {sev_label}")
    omitted = len(rows) - len(shown)
    if omitted > 0:
        lines.append(f"- …({omitted} more file(s) omitted)…")
    return lines


def _format_top_findings_lines(report_payload: Dict[str, Any]) -> List[str]:
    triples = list(_iter_findings_with_location(report_payload))
    if not triples:
        return []
    triples.sort(key=lambda t: (-t[0], t[2], t[3]))
    lines: List[str] = []
    for _rank, severity, file_path, start_line, title in triples[:COMPACT_MAX_TOP_FINDINGS]:
        loc = file_path
        if start_line:
            loc = f"{file_path}:{start_line}"
        sev_label = severity or "n/a"
        title_label = title or "(untitled finding)"
        lines.append(f"- [{sev_label}] {loc} — {title_label}")
    omitted = len(triples) - min(len(triples), COMPACT_MAX_TOP_FINDINGS)
    if omitted > 0:
        lines.append(f"- …({omitted} more finding(s) omitted)…")
    return lines


def _format_stats_line(report_payload: Dict[str, Any]) -> str:
    """One-line roll-up of known ``stats`` keys.

    Every listed key is emitted when the value is numeric, **including zero**,
    so "explicitly zero" is distinct from a missing/unknown key.
    """
    stats = report_payload.get("stats") or {}
    if not isinstance(stats, dict):
        return ""
    parts: List[str] = []
    for key, label in (
        ("total_findings", "total"),
        ("critical_risk", "critical"),
        ("high_risk", "high"),
        ("medium_risk", "medium"),
        ("low_risk", "low"),
        ("potential_findings", "potential"),
        ("files_analyzed", "files"),
    ):
        value = stats.get(key)
        if isinstance(value, (int, float)):
            parts.append(f"{label}={int(value)}")
    return ", ".join(parts)


def _compact_aggregate_summary(report_payload: Dict[str, Any]) -> List[str]:
    """Compact summary for executive aggregate documents (``assistant_aggregate=True``)."""
    lines: List[str] = ["# AGGREGATE REPORT SUMMARY"]
    included = report_payload.get("included_relative_paths") or []
    if isinstance(included, list) and included:
        lines.extend(
            (
                "",
                f"Aggregated {len(included)} canonical vulnerability report(s):",
            )
        )
        lines.extend(
            f"- {rel}"
            for rel in included[:COMPACT_MAX_FILES_LISTED]
            if isinstance(rel, str) and rel
        )
        omitted = len(included) - min(len(included), COMPACT_MAX_FILES_LISTED)
        if omitted > 0:
            lines.append(f"- …({omitted} more report(s) omitted)…")
    truncated = bool(report_payload.get("truncated"))
    if truncated:
        lines.extend(
            (
                "",
                "Note: underlying per-file payloads were truncated when merged.",
            )
        )
    return lines


def _truncate_markdown(text: str, max_chars: int) -> str:
    """Truncate ``text`` to ``max_chars`` while preserving line boundaries.

    The compact summary is Markdown (bulleted lists, headings), so a raw
    character slice can split a heading or a list item mid-line and leave
    the downstream consumer (LLM prompt) with a syntactically broken chunk.
    This helper therefore prefers to cut at the last ``"\\n"`` before the
    hard slicing limit and only falls back to a hard slice when the first
    line alone already exceeds the budget.
    """
    if len(text) <= max_chars:
        return text
    hard_limit = max(0, max_chars - len(REPORT_COMPACT_TRUNCATION_SUFFIX))
    if hard_limit <= 0:
        return REPORT_COMPACT_TRUNCATION_SUFFIX
    slice_candidate = text[:hard_limit]
    last_newline = slice_candidate.rfind("\n")
    if last_newline > 0:
        slice_candidate = slice_candidate[:last_newline]
    return slice_candidate + REPORT_COMPACT_TRUNCATION_SUFFIX


def compact_report_excerpt(report_payload: Dict[str, Any], max_chars: int) -> str:
    """
    Build a compact Markdown summary for the chat system prompt.

    The output is capped at ``max_chars`` characters (hard cap). Empty string
    is returned when the budget is non-positive. A single-line suffix marks
    truncation so the model can acknowledge missing context. Truncation is
    line-boundary aware (see :func:`_truncate_markdown`) to keep the Markdown
    structure intact for the consuming LLM.

    Tuning knobs driving the structural (pre-``max_chars``) size (canonical
    definitions: :mod:`oasis.helpers.assistant.prompt.prompt_tuning`):
      - :data:`oasis.helpers.assistant.prompt.prompt_tuning.COMPACT_MAX_FILES_LISTED` —
        cap of the ``## Files`` section.
      - :data:`oasis.helpers.assistant.prompt.prompt_tuning.COMPACT_MAX_TOP_FINDINGS` —
        cap of the ``## Top findings`` section.
      - :data:`oasis.helpers.assistant.prompt.prompt_tuning.COMPACT_SEVERITY_RANK` —
        severity ordering used to keep the worst offenders when trimming.
      - :data:`oasis.helpers.assistant.prompt.prompt_tuning.REPORT_COMPACT_TRUNCATION_SUFFIX` —
        marker appended on char-level cut.
    """
    if max_chars <= 0 or not isinstance(report_payload, dict):
        return ""

    if report_payload.get("assistant_aggregate"):
        lines = _compact_aggregate_summary(report_payload)
        text = "\n".join(lines).strip()
        return _truncate_markdown(text, max_chars)

    header_fields = [
        ("report_type", "Report type"),
        ("title", "Title"),
        ("vulnerability_name", "Vulnerability name"),
        ("model_name", "Scan model"),
        ("generated_at", "Generated at"),
        ("language", "Language"),
        ("analysis_root", "Analysis root"),
    ]
    lines: List[str] = ["# REPORT SUMMARY"]
    for key, label in header_fields:
        val = report_payload.get(key)
        if isinstance(val, str) and val.strip():
            lines.append(f"- {label}: {val.strip()}")

    if stats_line := _format_stats_line(report_payload):
        lines.append(f"- Stats: {stats_line}")

    if file_lines := _format_files_summary_lines(report_payload):
        lines.extend(("", "## Files"))
        lines.extend(file_lines)

    if finding_lines := _format_top_findings_lines(report_payload):
        lines.extend(("", "## Top findings (severity-ranked)"))
        lines.extend(finding_lines)

    text = "\n".join(lines).strip()
    return _truncate_markdown(text, max_chars)


__all__ = [
    "compact_report_excerpt",
]
