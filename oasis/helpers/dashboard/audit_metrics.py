"""Parse audit metrics tables from markdown security reports (dashboard / web aggregation)."""

from __future__ import annotations

import re
from typing import Iterator


AUDIT_METRICS_SECTION_HEADING_PATTERN = re.compile(
    r"^##+\s*(audit\s+metrics?\s+summary|metrics?\s+summary|similarity\s+metrics?)\b.*$",
    re.IGNORECASE | re.MULTILINE,
)
AUDIT_METRIC_LABELS: dict[str, tuple[str, str]] = {
    "count": ("int", "count"),
    "average similarity": ("float", "avg_score"),
    "avg similarity": ("float", "avg_score"),
    "mean similarity": ("float", "avg_score"),
    "median similarity": ("float", "median_score"),
    "maximum similarity": ("float", "max_score"),
    "max similarity": ("float", "max_score"),
    "minimum similarity": ("float", "min_score"),
    "min similarity": ("float", "min_score"),
}
AUDIT_METRICS_TABLE_HEADER_LABELS = frozenset({"metric", "value"})
AUDIT_METRIC_TABLE_ROW_PATTERN = re.compile(r"^\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*$")


def normalize_audit_metric_label(raw_label: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", " ", str(raw_label or "").strip().lower())
    return re.sub(r"\s+", " ", normalized).strip()


def parse_first_int_metric(raw_value: str) -> int | None:
    if match := re.search(r"-?\d+", str(raw_value or "")):
        try:
            return int(match[0])
        except ValueError:
            return None
    return None


def parse_first_float_metric(raw_value: str) -> float | None:
    if match := re.search(r"-?\d+(?:\.\d+)?", str(raw_value or "")):
        try:
            return float(match[0])
        except ValueError:
            return None
    return None


def audit_metric_key_from_label(normalized_label: str) -> tuple[str, str]:
    """
    Return metric kind/key tuple where kind is ``int`` or ``float``.
    """
    if normalized_label in AUDIT_METRIC_LABELS:
        return AUDIT_METRIC_LABELS[normalized_label]
    if "average" in normalized_label and "similarity" in normalized_label:
        return ("float", "avg_score")
    if "median" in normalized_label and "similarity" in normalized_label:
        return ("float", "median_score")
    if ("maximum" in normalized_label or normalized_label.startswith("max")) and "similarity" in normalized_label:
        return ("float", "max_score")
    if ("minimum" in normalized_label or normalized_label.startswith("min")) and "similarity" in normalized_label:
        return ("float", "min_score")
    if normalized_label.startswith("high") and ("match" in normalized_label or "tier" in normalized_label or "risk" in normalized_label):
        return ("int", "high")
    if normalized_label.startswith("medium") and ("match" in normalized_label or "tier" in normalized_label or "risk" in normalized_label):
        return ("int", "medium")
    if normalized_label.startswith("low") and ("match" in normalized_label or "tier" in normalized_label or "risk" in normalized_label):
        return ("int", "low")
    return ("", "")


def slice_markdown_section_after_heading(content: str, heading_match: re.Match[str]) -> str:
    """Return markdown slice between heading and the next heading of same level."""
    section_start = heading_match.end()
    next_heading_match = re.search(r"^##+\s+", content[section_start:], re.MULTILINE)
    section_end = section_start + next_heading_match.start() if next_heading_match else len(content)
    return content[section_start:section_end]


def parse_audit_metric_table_row(line: str) -> tuple[str, str] | None:
    """Parse a markdown ``| label | value |`` row."""
    if match := AUDIT_METRIC_TABLE_ROW_PATTERN.match(line):
        return match.group(1), match.group(2)
    return None


def is_audit_metrics_table_header_row(label: str, value: str) -> bool:
    """True when the row is the ``| Metric | Value |`` header."""
    return (
        label in AUDIT_METRICS_TABLE_HEADER_LABELS
        and normalize_audit_metric_label(value) in AUDIT_METRICS_TABLE_HEADER_LABELS
    )


def iter_audit_metrics_table_rows(metrics_section: str) -> Iterator[tuple[str, str]]:
    """Yield normalized ``(label, value)`` rows from the first audit metrics table."""
    in_metrics_table = False
    for raw in metrics_section.splitlines():
        line = raw.strip()
        row = parse_audit_metric_table_row(line)
        if not row:
            if in_metrics_table and line:
                break
            continue
        label, raw_value = row
        normalized_label = normalize_audit_metric_label(label)
        value = raw_value.strip()
        if is_audit_metrics_table_header_row(normalized_label, value):
            in_metrics_table = True
            continue
        if not in_metrics_table:
            continue
        if set(normalized_label) == {"-"}:
            continue
        yield normalized_label, value


def audit_metrics_from_markdown_content(content: str) -> dict[str, int | float]:
    """
    Parse comparable audit metrics from markdown audit report content.

    **Input contract (permissive)**

    - ``content`` is full markdown text. The function searches for a section whose heading
      matches :data:`AUDIT_METRICS_SECTION_HEADING_PATTERN` (flexible wording).
    - Inside that section, it scans for the first GitHub-style pipe table (``| col | col |``).
      Rows before the ``Metric`` / ``Value`` header are ignored; parsing stops at the first
      non-table line after the table started.
    - Label text is normalized (case/spacing); values are parsed by taking the first integer
      or float substring—extra prose around numbers is tolerated.

    **Output**

    - Flat dict mapping canonical keys (e.g. ``avg_score``, ``count``) to numeric values.
      Unknown or non-numeric labels are skipped. Missing section or table yields ``{}``.
    """
    heading_match = AUDIT_METRICS_SECTION_HEADING_PATTERN.search(content)
    if not heading_match:
        return {}
    metrics_section = slice_markdown_section_after_heading(content, heading_match)

    metrics: dict[str, int | float] = {}
    for label, value in iter_audit_metrics_table_rows(metrics_section):
        kind, key = audit_metric_key_from_label(label)
        if not key:
            continue
        parsed = parse_first_int_metric(value) if kind == "int" else parse_first_float_metric(value)
        if parsed is not None:
            metrics[key] = parsed
    return metrics
