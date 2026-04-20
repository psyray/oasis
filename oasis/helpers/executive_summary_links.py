"""Executive Summary markdown links for dashboard-relative report paths."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Tuple

from oasis.export.filenames import artifact_filename

if TYPE_CHECKING:
    from oasis.report import Report


def _model_dir_key(name: str | None) -> str:
    """Match :func:`oasis.tools.sanitize_name` without importing ``oasis.tools`` (heavy deps)."""
    if not name:
        return ""
    base_name = str(name).split("/")[-1]
    return re.sub(r"[^a-zA-Z0-9]", "_", base_name)

# Align with dashboard modal preview preference (canonical JSON first).
_DETAIL_FORMAT_PRIORITY: tuple[str, ...] = ("json", "html", "md", "pdf", "sarif")


def preferred_detail_relative_path_and_format(report: "Report", vuln_stem: str) -> Tuple[str, str]:
    """
    Return ``(path_under_security_reports, format_key)`` for a vulnerability stem.

    Chooses the first existing artifact directory entry in priority order; if none exist,
    returns the preferred json path so new scans stay consistent once artifacts land.
    """
    model_key = _model_dir_key(report.current_model or "")
    dirs = report.report_dirs.get(model_key)
    base: Path = report.output_base_dir

    def rel_str(p: Path) -> str:
        return p.relative_to(base).as_posix()

    if dirs:
        for fmt in _DETAIL_FORMAT_PRIORITY:
            fmt_dir = dirs.get(fmt)
            if fmt_dir is None:
                continue
            candidate = fmt_dir / artifact_filename(vuln_stem, fmt)
            if candidate.is_file():
                return rel_str(candidate), fmt

        # Pipeline ordering: JSON is usually written before the summary step.
        if "json" in dirs:
            candidate = dirs["json"] / artifact_filename(vuln_stem, "json")
            return rel_str(candidate), "json"

    stem_clean = vuln_stem.strip() or "unknown"
    fallback = base / model_key / "pdf" / artifact_filename(stem_clean, "pdf")
    return rel_str(fallback), "pdf"


def dashboard_reports_href(relative_under_security: str) -> str:
    """Build ``/reports/<relative>`` href for incremental links (leading slash, posix)."""
    rel = relative_under_security.strip().replace("\\", "/").lstrip("/")
    return f"/reports/{rel}"
