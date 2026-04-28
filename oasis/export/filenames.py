"""Filename helpers for report artifacts (single place for format-specific naming)."""

# Stem for embedding audit reports (``audit_report.md``, ``audit_report.json``, …).
# Keep aligned with ``Report.filter_output_files(\"audit_report\")`` and dashboard JS.
AUDIT_REPORT_ARTIFACT_STEM = "audit_report"


def artifact_filename(stem: str, fmt: str) -> str:
    """
    Build the on-disk basename for a report format directory.

    Most formats use ``{stem}.{fmt}``. SARIF uses the ``.sarif`` extension while
    living under a ``sarif/`` directory (same pattern as ``fmt == "sarif"``).
    """
    return f"{stem}.sarif" if fmt == "sarif" else f"{stem}.{fmt}"


def report_dir_glob_for_format(fmt: str) -> str:
    """
    Glob pattern for listing report files under a per-format subdirectory.

    ``fmt`` is normalized to lower case so patterns match files from :func:`artifact_filename`
    regardless of config casing. Matches basenames produced by ``artifact_filename`` (no ``*.*``).
    """
    key = str(fmt or "").strip().lower()
    if key == "json":
        return "*.json"
    return "*.sarif" if key == "sarif" else f"*.{key}"
