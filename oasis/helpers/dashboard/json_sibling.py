"""Resolve canonical JSON next to a format artifact (md/html/pdf) under a model directory.

Audit reports use stem ``audit_report`` (see ``oasis.export.filenames.AUDIT_REPORT_ARTIFACT_STEM``);
dashboard JS resolves the same sibling via ``audit-report-paths.js``.
"""

from __future__ import annotations

from pathlib import Path

_FORMAT_DIRS = frozenset({"md", "html", "pdf", "sarif", "json"})


def json_sibling_for_format_artifact(artifact_path: Path) -> Path:
    """
    Return ``.../<model_dir>/json/<stem>.json`` for an artifact under ``.../<model_dir>/<format>/``.

    If *artifact_path* is already a JSON under ``json/``, returns it as-is.
    """
    if artifact_path.suffix.lower() == ".json" and artifact_path.parent.name.lower() == "json":
        return artifact_path
    if artifact_path.parent.name.lower() not in _FORMAT_DIRS:
        return artifact_path
    return artifact_path.parent.parent / "json" / f"{artifact_path.stem}.json"
