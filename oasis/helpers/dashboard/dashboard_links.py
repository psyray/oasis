"""Executive summary markdown links for dashboard-relative report paths."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Tuple

from oasis.export.filenames import artifact_filename

if TYPE_CHECKING:
    from oasis.report import Report


def _model_dir_key(name: str | None) -> str:
    """Match :func:`oasis.tools.sanitize_name` without importing ``oasis.tools`` (heavy deps)."""
    if not name:
        return ""
    base_name = str(name).split("/")[-1]
    return re.sub(r"[^a-zA-Z0-9]", "_", base_name)


_DETAIL_FORMAT_PRIORITY: tuple[str, ...] = ("json", "html", "md", "pdf", "sarif")


def _fallback_detail_relative_path_from_current_report(
    vuln_stem: str,
    *,
    security_root: Optional[Path],
    current_report_path: Optional[Path],
) -> Optional[Tuple[str, str]]:
    """Resolve detail artifact path from the current report run under ``security_reports``."""
    if not isinstance(security_root, Path) or not isinstance(current_report_path, Path):
        return None
    try:
        resolved_root = security_root.resolve()
        resolved_current = current_report_path.resolve()
        rel_current = resolved_current.relative_to(resolved_root)
    except (OSError, ValueError):
        return None
    # Expected layout: .../<model>/<format>/<report_file>
    if len(rel_current.parts) < 3:
        return None
    model_dir = resolved_current.parent.parent
    for fmt in _DETAIL_FORMAT_PRIORITY:
        candidate = model_dir / fmt / artifact_filename(vuln_stem, fmt)
        if candidate.is_file():
            return candidate.relative_to(resolved_root).as_posix(), fmt
    fallback = model_dir / "json" / artifact_filename(vuln_stem.strip() or "unknown", "json")
    try:
        return fallback.relative_to(resolved_root).as_posix(), "json"
    except ValueError:
        return None


def preferred_detail_relative_path_and_format(
    report: "Report",
    vuln_stem: str,
    *,
    security_root: Optional[Path] = None,
    current_report_path: Optional[Path] = None,
) -> Tuple[str, str]:
    """
    Return ``(path_under_security_reports, format_key)`` for a vulnerability stem.

    Chooses the first existing artifact directory entry in priority order; if none exist,
    returns the preferred json path so new scans stay consistent once artifacts land.
    """
    model_key = _model_dir_key(report.current_model or "")
    dirs = report.report_dirs.get(model_key)
    base_raw = getattr(report, "output_base_dir", None)
    if not isinstance(base_raw, Path):
        fallback = _fallback_detail_relative_path_from_current_report(
            vuln_stem,
            security_root=security_root,
            current_report_path=current_report_path,
        )
        if fallback:
            return fallback
        raise ValueError("report.output_base_dir is unavailable")
    base: Path = base_raw

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
