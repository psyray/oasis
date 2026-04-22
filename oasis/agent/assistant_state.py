"""LangGraph state schema for the assistant validation agent.

Keeps shared, mutable state small and explicit so each node has a single
source of truth. Not a Pydantic model: LangGraph prefers plain TypedDicts
to minimise copy overhead between nodes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Optional, TypedDict

from oasis.helpers.vuln.taxonomy import VulnDescriptor


class AssistantGraphState(TypedDict, total=False):
    """State container for the investigation LangGraph."""

    vulnerability_name: str
    descriptor: VulnDescriptor
    scan_root: Path
    sink_file: Optional[Path]
    sink_line: Optional[int]
    budget_seconds: float

    entry_points: List[Any]
    execution_paths: List[Any]
    taint_flows: List[Any]
    mitigations: List[Any]
    authz_hits: List[Any]
    control_checks: List[Any]
    config_findings: List[Any]

    errors: List[str]
    budget_exhausted: bool
    backend: str
    result: Any
