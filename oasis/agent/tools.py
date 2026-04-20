"""LangGraph step implementations: delegate to SecurityAnalyzer hooks (single dispatch layer).

Orchestration logic and prompts remain in ``oasis/analyze.py``; this module only wires
state dicts into analyzer methods so ``nodes.py`` stays a thin surface for graph registration.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from langgraph.graph import END

from ..helpers.debug_cli_separators import separator_graph_step
from ..helpers.langgraph_console import (
    LG_AFTER_VERIFY,
    LG_NODE_DEEP_QUEUE,
    LG_POC,
    LG_VERIFY,
    langgraph_emit,
    langgraph_emit_phase,
)
from ..tools import logger
from .graph_labels import GRAPH_NODE_POC, GRAPH_ROUTE_EXPAND, GRAPH_ROUTE_REPORT
from .state import OasisGraphState


def _emit_graph_step_debug(state: OasisGraphState, step: str, detail: str = "") -> None:
    args = state.get("args")
    if args is not None and getattr(args, "debug", False):
        logger.debug(separator_graph_step(step, detail))


def node_discover(state: OasisGraphState) -> Dict[str, Any]:
    nv = len(state.get("vulnerabilities") or [])
    langgraph_emit_phase(
        logger,
        logging.INFO,
        1,
        "🔎",
        "Discover",
        f"embedding candidates ({nv} vuln type(s))",
    )
    _emit_graph_step_debug(state, "discover", f"{nv} vuln type(s)")
    analyzer = state["analyzer"]
    args = state["args"]
    vulns = state["vulnerabilities"]
    report = state.get("report")
    return analyzer.langgraph_discover_and_publish(vulns, args, report)


def node_scan(state: OasisGraphState) -> Dict[str, Any]:
    tasks = state.get("embedding_tasks") or []
    langgraph_emit_phase(
        logger,
        logging.INFO,
        2,
        "📋",
        "Structured chunk scan",
        f"{len(tasks)} candidate task(s)",
    )
    _emit_graph_step_debug(state, "scan", f"{len(tasks)} tasks")
    analyzer = state["analyzer"]
    args = state["args"]
    report = state.get("report")
    return analyzer.langgraph_scan_and_publish(tasks, args, report)


def node_expand(state: OasisGraphState) -> Dict[str, Any]:
    expand_it = int(state.get("expand_iterations") or 0)
    pending = bool(state.get("verify_retry_pending"))
    langgraph_emit_phase(
        logger,
        logging.INFO,
        3,
        "🔄",
        "Context expansion",
        f"iteration={expand_it}, retry_after_verify={pending}",
    )
    _emit_graph_step_debug(state, "expand", f"iter={expand_it} retry_verify={pending}")
    analyzer = state["analyzer"]
    args = state["args"]
    payload = state.get("suspicious_payload") or {}
    return analyzer.langgraph_expand_and_publish(payload, args, expand_it, pending)


def node_deep(state: OasisGraphState) -> Dict[str, Any]:
    expand_it = int(state.get("expand_iterations") or 0)
    langgraph_emit_phase(
        logger,
        logging.INFO,
        4,
        "🔬",
        "Deep analysis",
        f"expand_iterations={expand_it}",
    )
    langgraph_emit(logger, logging.DEBUG, LG_NODE_DEEP_QUEUE, expand_it)
    _emit_graph_step_debug(state, "deep", f"expand_pass={expand_it}")
    analyzer = state["analyzer"]
    args = state["args"]
    report = state["report"]
    payload = state.get("suspicious_payload") or {}
    return analyzer.langgraph_deep_and_publish(
        payload, args, report, graph_deep_pass=expand_it
    )


def node_verify(state: OasisGraphState) -> Dict[str, Any]:
    expand_it = int(state.get("expand_iterations") or 0)
    max_it = int(state.get("max_expand_iterations") or 2)
    results = state.get("all_results") or {}
    langgraph_emit_phase(
        logger,
        logging.INFO,
        5,
        "✅",
        "Verify",
        "structured output validation",
    )
    _emit_graph_step_debug(state, "verify", f"expand_it={expand_it}/{max_it}")
    analyzer = state["analyzer"]
    args = state["args"]
    out = analyzer.langgraph_verify(results, args, expand_it, max_it)
    rp = out.get("verify_retry_pending")
    langgraph_emit(
        logger,
        logging.INFO,
        LG_VERIFY,
        rp,
        expand_it,
        max_it,
    )
    return out


def node_report(state: OasisGraphState) -> Dict[str, Any]:
    langgraph_emit_phase(
        logger,
        logging.INFO,
        6,
        "📄",
        "Report",
        "finalize & executive summary",
    )
    _emit_graph_step_debug(state, "report")
    analyzer = state["analyzer"]
    args = state["args"]
    report = state["report"]
    vulns = state["vulnerabilities"]
    results = state.get("all_results") or {}
    return analyzer.langgraph_finalize_reports(vulns, args, report, results)


def node_poc(state: OasisGraphState) -> Dict[str, Any]:
    langgraph_emit(logger, logging.INFO, LG_POC)
    _emit_graph_step_debug(state, "poc")
    analyzer = state["analyzer"]
    args = state["args"]
    results = state.get("all_results") or {}
    return analyzer.langgraph_poc_assist(args, results)


def route_after_verify(state: OasisGraphState) -> str:
    expand_it = int(state.get("expand_iterations") or 0)
    max_it = int(state.get("max_expand_iterations") or 2)
    retry = bool(state.get("verify_retry_pending"))
    if retry and expand_it < max_it:
        nxt = GRAPH_ROUTE_EXPAND
    else:
        nxt = GRAPH_ROUTE_REPORT
    langgraph_emit(logger, logging.INFO, LG_AFTER_VERIFY, nxt)
    return nxt


def route_after_report(state: OasisGraphState) -> str:
    """Skip the PoC node when neither hints nor LLM-assisted PoC is requested."""
    args = state.get("args")
    if args is not None and (
        getattr(args, "poc_hints", False) or getattr(args, "poc_assist", False)
    ):
        return GRAPH_NODE_POC
    return END
