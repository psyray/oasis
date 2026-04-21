"""Executive modal: vulnerability report list and aggregate finding-scope validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from oasis.helpers.assistant_scan_aggregate import (
    first_vulnerability_payload_from_paths,
    iter_json_report_paths_in_model_dir,
    model_directory_from_security_report_file,
    security_relative_posix,
)
from oasis.helpers.path_containment import is_path_within_root


def synthetic_executive_primary_payload(model_dir: Path) -> Dict[str, Any]:
    """Minimal executive JSON when only ``md/_executive_summary.md`` exists (no sibling JSON file)."""
    paths = iter_json_report_paths_in_model_dir(model_dir)
    vp = first_vulnerability_payload_from_paths(paths)
    mn = ""
    if isinstance(vp, dict):
        raw = vp.get("model_name")
        mn = raw.strip() if isinstance(raw, str) and raw.strip() else ""
    return {
        "report_type": "executive_summary",
        "schema_version": 1,
        "model_name": mn,
        "title": "Executive Summary",
    }


def vulnerability_reports_for_executive_assistant(model_dir: Path, security_root: Path) -> List[Dict[str, str]]:
    """
    List canonical vulnerability JSON files under ``model_dir`` for assistant UI.

    Each entry: ``relative_path`` (posix under security root), ``label`` (vulnerability name or stem).
    """
    out: List[Dict[str, str]] = []
    root = security_root.resolve()
    for p in iter_json_report_paths_in_model_dir(model_dir):
        if p.stem.lower().startswith("_executive_summary"):
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        if str(data.get("report_type") or "") != "vulnerability":
            continue
        rel = security_relative_posix(p, root)
        vn = data.get("vulnerability_name")
        label = vn.strip() if isinstance(vn, str) and vn.strip() else p.stem
        out.append({"relative_path": rel, "label": label})
    out.sort(key=lambda x: x.get("relative_path") or "")
    return out


def resolve_aggregate_finding_scope_payload(
    scope_rel_raw: str,
    *,
    security_root: Path,
    executive_report_path: Path,
    model_dir: Path,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Resolve and validate ``finding_scope_report_path`` for executive aggregate chat.

    Returns ``(payload, None)`` or ``(None, error_message)``.
    """
    s = scope_rel_raw.strip()
    if not s or ".." in Path(s).parts or s.startswith("/"):
        return None, "invalid finding_scope_report_path"
    scope_path = (security_root / s).resolve(strict=False)
    try:
        root = security_root.resolve()
        if not is_path_within_root(scope_path, root):
            return None, "invalid finding_scope_report_path"
    except OSError:
        return None, "invalid finding_scope_report_path"
    if not scope_path.is_file() or scope_path.suffix.lower() != ".json":
        return None, "finding scope report not found"

    md_dir = model_directory_from_security_report_file(root, executive_report_path)
    if md_dir is None:
        return None, "could not resolve model directory"
    scope_model = model_directory_from_security_report_file(root, scope_path)
    if scope_model is None or scope_model.resolve() != md_dir.resolve():
        return None, "finding scope report is not in the same scan directory"

    try:
        data = json.loads(scope_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None, "could not read finding scope report"
    if not isinstance(data, dict):
        return None, "invalid finding scope report"
    if str(data.get("report_type") or "") != "vulnerability":
        return None, "finding scope report is not a vulnerability JSON"
    return data, None
