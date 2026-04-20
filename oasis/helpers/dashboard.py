"""Dashboard helpers: formats, Socket.IO CORS, markdown phase parsing; re-exports focused submodules."""

from __future__ import annotations

import contextlib
import re
import socket
from typing import Optional, Tuple

from .audit_metrics import (
    AUDIT_METRIC_LABELS,
    AUDIT_METRIC_TABLE_ROW_PATTERN,
    AUDIT_METRICS_SECTION_HEADING_PATTERN,
    AUDIT_METRICS_TABLE_HEADER_LABELS,
    audit_metric_key_from_label,
    audit_metrics_from_markdown_content,
    iter_audit_metrics_table_rows,
    normalize_audit_metric_label,
    parse_audit_metric_table_row,
    parse_first_float_metric,
    parse_first_int_metric,
    slice_markdown_section_after_heading,
)
from .dashboard_links import dashboard_reports_href, preferred_detail_relative_path_and_format
from .exec_summary_tiers import (
    EXEC_SUMMARY_EMBEDDING_TIER_ORDER,
    EXEC_SUMMARY_EMBEDDING_TIERS,
    ExecSummaryTier,
    executive_summary_similarity_tier_id,
    executive_summary_tier_heading,
    executive_summary_tiers_inline_text,
    executive_summary_tiers_markdown_bullets,
)
from .report_preview_html import rewrite_report_preview_anchor_hrefs

# --- Output formats / Socket.IO / phase cell parsing ---------------------------------

_PHASE_CELL_DIGITS = re.compile(r"\d+")


def dashboard_format_display_order() -> list[str]:
    """Ordered formats for dashboard chips, date-picker open preference, and /api/dates.

    Matching between DASHBOARD_FORMAT_DISPLAY_ORDER and OUTPUT_FORMATS is
    case-insensitive, but the returned list preserves the original casing
    from OUTPUT_FORMATS.
    """
    from ..config import REPORT

    preferred = REPORT.get("DASHBOARD_FORMAT_DISPLAY_ORDER") or []
    allowed = list(REPORT.get("OUTPUT_FORMATS") or [])

    normalized_to_original: dict[str, str] = {}
    for fmt in allowed:
        key = fmt.lower()
        if key not in normalized_to_original:
            normalized_to_original[key] = fmt

    seen_normalized: set[str] = set()
    out: list[str] = []

    for fmt in preferred:
        key = fmt.lower()
        original = normalized_to_original.get(key)
        if original is not None and key not in seen_normalized:
            out.append(original)
            seen_normalized.add(key)

    for fmt in allowed:
        key = fmt.lower()
        if key not in seen_normalized:
            out.append(fmt)
            seen_normalized.add(key)

    return out


def socketio_lan_http_origins(port: int) -> list[str]:
    """Best-effort LAN URLs for Socket.IO CORS when the server binds to all interfaces.

    Browsers send ``Origin`` with the host the user typed (e.g. ``http://192.168.1.10:5001``).
    We discover likely interface addresses without requiring extra dependencies.
    """
    out: list[str] = []
    seen: set[str] = set()

    def add_origin(url: str) -> None:
        if url not in seen:
            seen.add(url)
            out.append(url)

    with contextlib.suppress(OSError):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.connect(("192.0.2.1", 80))
            ip = udp.getsockname()[0]
            if ip and not ip.startswith("127."):
                add_origin(f"http://{ip}:{port}")
    with contextlib.suppress(OSError):
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                add_origin(f"http://{ip}:{port}")
    return out


def expand_socketio_cors_config_entries(entries: list[str] | tuple[str, ...], port: int) -> list[str]:
    """Replace ``{port}`` in configured origin strings."""
    expanded: list[str] = []
    for raw in entries:
        if not raw or not isinstance(raw, str):
            continue
        s = raw.strip()
        if not s:
            continue
        if "{port}" in s:
            s = s.format(port=port)
        expanded.append(s)
    return expanded


def parse_phase_counts_from_progress_cell(prog_cell: str) -> Optional[Tuple[int, int]]:
    """Extract ``(completed, total)`` integers from a markdown progress column.

    Accepts cells with extra text (percent suffixes, spacing). Returns ``None`` when
    no usable counts are found or integers cannot be parsed.
    """
    nums = _PHASE_CELL_DIGITS.findall(prog_cell)
    if len(nums) >= 2:
        try:
            c, t = int(nums[0]), int(nums[1])
        except ValueError:
            return None
        return (max(c, 0), max(t, 0))
    if len(nums) == 1:
        try:
            c = int(nums[0])
        except ValueError:
            return None
        t = max(c, 1)
        return (max(c, 0), max(t, 0))
    return None
