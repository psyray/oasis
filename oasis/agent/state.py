"""LangGraph state schema for OASIS analysis orchestration."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict


class OasisGraphState(TypedDict, total=False):
    """Mutable analysis state passed between LangGraph nodes."""

    analyzer: Any
    args: Any
    report: Any
    vulnerabilities: List[Dict[str, Any]]
    embedding_tasks: List[Dict[str, Any]]
    suspicious_payload: Dict[str, Any]
    all_results: Dict[str, Any]
    expand_iterations: int
    max_expand_iterations: int
    verify_retry_pending: bool
    validation_error_count: int
    poc_hints_markdown: str
    silent: bool
