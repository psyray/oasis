"""Project label and safe directory segment for `security_reports` output layout."""

from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Final

from oasis.tools import sanitize_name

# Filesystem run folder: %Y%m%d_%H%M%S
_RUN_TIMESTAMP_PATTERN: Final[re.Pattern[str]] = re.compile(r"^\d{8}_\d{6}$")

# Suffix in legacy run roots, e.g. myapp_20260101_120000
_LEGACY_RUN_SUFFIX: Final[re.Pattern[str]] = re.compile(r"_(?P<ts>\d{8}_\d{6})$")


def _is_usable_segment_name(name: str) -> bool:
    return bool(name and name not in (".", ".."))


def _resolved_is_likely_file(clean_path: Path, resolved: Path) -> bool:
    if resolved.exists():
        return resolved.is_file()
    s = str(clean_path)
    if s.endswith(("/", "\\")):
        return False
    suf = clean_path.suffix
    if suf and len(suf) <= 6 and "/" not in suf and "\\" not in suf:
        return True
    return False


def project_label_for_report_storage(clean_path: Path) -> str:
    """
    Human-readable project name for JSON ``project`` and directory slugging.

    - **Directory** ``--input``: basename of the scanned directory (e.g. ``a/b`` → ``b``).
    - **File** ``--input``: name of the folder that contains the file.
    """
    try:
        resolved = clean_path.expanduser().resolve()
    except OSError:
        resolved = clean_path
    is_file = _resolved_is_likely_file(clean_path, resolved)
    if is_file:
        candidate = resolved.parent.name
    else:
        candidate = resolved.name
    if not _is_usable_segment_name(candidate):
        return "project"
    return candidate


def _raw_path_token_for_warnings(path: Path) -> str:
    s = str(path)
    s = s.split()[0] if s else s
    return s.strip().strip('"').strip("'")


def log_input_path_project_naming_warnings(logger: logging.Logger, input_path: Path) -> None:
    """
    Warn when ``--input`` is ill-suited for a stable, meaningful project / filter name.
    """
    raw = _raw_path_token_for_warnings(input_path)
    try:
        resolved = input_path.expanduser().resolve()
    except OSError:
        resolved = input_path
    is_file = _resolved_is_likely_file(input_path, resolved)
    if is_file:
        parent_name = resolved.parent.name or "(unnamed)"
        logger.warning(
            "Reports and the dashboard use a 'project' label derived from --input. "
            "You passed a file: the project name will be the containing folder name (%r). "
            "For predictable grouping and filters, set --input to the project directory "
            "(the folder to analyze), not a single file path.",
            parent_name,
        )
    if raw in (".", "..", "/", "\\") or (len(raw) == 1 and raw in ("/", "\\")):
        logger.warning(
            "The project name for this run (reports path + UI filters) is derived from --input. "
            "A generic path like %r gives a non-specific label; use an explicit project directory "
            "so you can find runs easily (e.g. app/subproject instead of only %r).",
            raw,
            raw,
        )
    if not is_file and resolved.is_dir() and not (resolved.name or "").strip():
        logger.warning(
            "Cannot derive a project folder name from filesystem root. "
            "Point --input to a normal project directory (a named folder to scan)."
        )


def project_slug_for_report_storage(label: str) -> str:
    """Single path segment under ``security_reports``; safe, non-empty."""
    raw = sanitize_name(label)
    slug = re.sub(r"_+", "_", raw).strip("_")
    if not slug or re.sub(r"[^a-zA-Z0-9]", "", slug) == "":
        return "project"
    return slug


def is_run_timestamp_dirname(name: str) -> bool:
    """True when *name* is only ``YYYYMMDD_HHMMSS`` (new layout run folder)."""
    return bool(_RUN_TIMESTAMP_PATTERN.match(name or ""))


def is_legacy_run_dirname(name: str) -> bool:
    """True when *name* matches legacy ``<stem>_<YYYYMMDD>_<HHMMSS>`` run roots."""
    return bool(_LEGACY_RUN_SUFFIX.search(name or ""))


def run_timestamp_from_path_or_key(path_or_key: str) -> str | None:
    """
    Return ``YYYYMMDD_HHMMSS`` from a run directory name or POSIX run key
    (e.g. ``myproject/20260101_120000`` or ``oldname_20260101_120000``).
    """
    s = (path_or_key or "").replace("\\", "/").rstrip("/")
    if not s:
        return None
    last = s.split("/")[-1]
    if is_run_timestamp_dirname(last):
        return last
    m = _LEGACY_RUN_SUFFIX.search(last)
    if m:
        return m.group("ts")
    return None


def report_date_display_from_run_key(path_or_key: str) -> str:
    """
    Human-readable date string for dashboard ``date`` field (matches former dirname parsing).
    """
    ts = run_timestamp_from_path_or_key(path_or_key)
    if not ts:
        return ""
    try:
        date_obj = datetime.strptime(ts, "%Y%m%d_%H%M%S")
    except ValueError:
        return ""
    return date_obj.strftime("%Y-%m-%d %H:%M:%S")
