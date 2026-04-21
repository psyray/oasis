"""Aggregate dashboard chart metadata for executive modal preview."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from oasis.helpers.assistant_scan_aggregate import iter_json_report_paths_in_model_dir


def rollup_severity_counts_from_model_dir(model_dir: Path) -> Dict[str, Any]:
    """Sum severity counters from canonical vulnerability JSON files under ``model_dir/json``."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    vuln_reports = 0
    paths = iter_json_report_paths_in_model_dir(model_dir)
    for p in paths:
        if p.stem.lower().startswith("_executive_summary"):
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        if str(data.get("report_type") or "") != "vulnerability":
            continue
        vuln_reports += 1
        st = data.get("stats") or {}
        if not isinstance(st, dict):
            continue
        try:
            counts["critical"] += int(st.get("critical_risk", 0))
            counts["high"] += int(st.get("high_risk", 0))
            counts["medium"] += int(st.get("medium_risk", 0))
            counts["low"] += int(st.get("low_risk", 0))
        except (TypeError, ValueError):
            continue

    total = sum(counts.values())
    return {
        "severity_counts": counts,
        "total_findings_rollups": total,
        "vulnerability_report_files": vuln_reports,
        "has_executive_json": any(p.stem.lower().startswith("_executive_summary") for p in paths),
    }
