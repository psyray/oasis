"""Public entry: invoke the LangGraph analysis pipeline."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List

from .graph import build_oasis_analysis_graph
from .state import OasisGraphState

if TYPE_CHECKING:
    from ..analyze import SecurityAnalyzer
    from ..report import Report


def invoke_oasis_langgraph(
    analyzer: SecurityAnalyzer,
    vulnerabilities: List[Dict[str, Any]],
    args: Any,
    report: Report,
) -> Dict[str, Any]:
    """
    Run the canonical OASIS vulnerability analysis via LangGraph.

    Returns the aggregated vulnerability-type results dict (same shape as legacy runners).
    """
    graph = build_oasis_analysis_graph()
    initial: OasisGraphState = {
        "analyzer": analyzer,
        "args": args,
        "report": report,
        "vulnerabilities": vulnerabilities,
        "embedding_tasks": [],
        "suspicious_payload": {},
        "all_results": {},
        "expand_iterations": 0,
        "max_expand_iterations": getattr(args, "langgraph_max_expand_iterations", 2),
        "verify_retry_pending": False,
        "validation_error_count": 0,
        "poc_hints_markdown": "",
        "silent": bool(getattr(args, "silent", False)),
    }
    final = graph.invoke(initial)
    return final.get("all_results") or {}
