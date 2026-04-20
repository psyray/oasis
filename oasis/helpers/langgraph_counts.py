"""Canonical vulnerability-type counts for LangGraph progress (avoid drift vs scan payloads)."""

from __future__ import annotations

from typing import Any, Dict, List


def embedding_tasks_vuln_types_total(task_list: List[Dict[str, Any]]) -> int:
    """
    Distinct vuln labels from embedding tasks for executive-summary totals.

    Malformed tasks are skipped. When tasks exist but no label is readable, returns 1.
    """
    unique: set[str] = set()
    for t in task_list:
        v_obj = t.get("vuln")
        if isinstance(v_obj, dict):
            vn = v_obj.get("name") or v_obj.get("tag")
            if isinstance(vn, str) and vn.strip():
                unique.add(vn.strip())
    return max(len(unique), 1) if unique else max(1, 1 if task_list else 1)


def deep_payload_vuln_types_total(files_by_vuln: Any) -> int:
    """Number of vulnerability buckets in the deep-analysis payload (at least 1)."""
    return max(len(files_by_vuln), 1) if isinstance(files_by_vuln, dict) else 1
