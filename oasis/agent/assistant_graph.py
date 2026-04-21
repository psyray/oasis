"""Compile the assistant validation LangGraph.

The graph branches on the vulnerability family:

                           ┌── flow ──> entry_points -> trace -> taint -> mitigations -> verdict
  classify_family ─(route)─┼── access ─> entry_points -> authz -> verdict
                           └── config ─> config_audit -> verdict

LangGraph is imported lazily so ``oasis.agent.assistant_graph`` stays cheap
for environments that only consume the helpers without running the graph.
"""

from __future__ import annotations

from typing import Any

from oasis.agent.assistant_labels import (
    ASSISTANT_NODE_AUTHZ,
    ASSISTANT_NODE_CLASSIFY,
    ASSISTANT_NODE_CONFIG_AUDIT,
    ASSISTANT_NODE_ENTRY_POINTS,
    ASSISTANT_NODE_MITIGATIONS,
    ASSISTANT_NODE_TAINT,
    ASSISTANT_NODE_TRACE,
    ASSISTANT_NODE_VERDICT,
    ASSISTANT_ROUTE_ACCESS,
    ASSISTANT_ROUTE_CONFIG,
    ASSISTANT_ROUTE_FLOW,
)
from oasis.agent.assistant_nodes import (
    node_aggregate_verdict,
    node_classify_family,
    node_collect_entry_points,
    node_config_audit,
    node_detect_authz,
    node_detect_mitigations,
    node_taint_flow,
    node_trace_execution,
    route_after_classify,
)
from oasis.agent.assistant_state import AssistantGraphState


def build_assistant_validation_graph() -> Any:
    """Return a compiled LangGraph for the assistant validation agent."""
    from langgraph.graph import END, START, StateGraph

    graph: Any = StateGraph(AssistantGraphState)
    graph.add_node(ASSISTANT_NODE_CLASSIFY, node_classify_family)
    graph.add_node(ASSISTANT_NODE_ENTRY_POINTS, node_collect_entry_points)
    graph.add_node(ASSISTANT_NODE_TRACE, node_trace_execution)
    graph.add_node(ASSISTANT_NODE_TAINT, node_taint_flow)
    graph.add_node(ASSISTANT_NODE_MITIGATIONS, node_detect_mitigations)
    graph.add_node(ASSISTANT_NODE_AUTHZ, node_detect_authz)
    graph.add_node(ASSISTANT_NODE_CONFIG_AUDIT, node_config_audit)
    graph.add_node(ASSISTANT_NODE_VERDICT, node_aggregate_verdict)

    graph.add_edge(START, ASSISTANT_NODE_CLASSIFY)

    # Each family first resolves entry points (flow, access) OR jumps to config audit.
    graph.add_conditional_edges(
        ASSISTANT_NODE_CLASSIFY,
        route_after_classify,
        {
            ASSISTANT_ROUTE_FLOW: ASSISTANT_NODE_ENTRY_POINTS,
            ASSISTANT_ROUTE_ACCESS: ASSISTANT_NODE_ENTRY_POINTS,
            ASSISTANT_ROUTE_CONFIG: ASSISTANT_NODE_CONFIG_AUDIT,
        },
    )

    # Flow family: entry points -> trace -> taint -> mitigations -> verdict.
    # Access family reuses entry points but skips trace/taint and jumps to authz.
    def _route_after_entry_points(state: AssistantGraphState) -> str:
        # route_after_classify already used; re-derive the family.
        return route_after_classify(state)

    graph.add_conditional_edges(
        ASSISTANT_NODE_ENTRY_POINTS,
        _route_after_entry_points,
        {
            ASSISTANT_ROUTE_FLOW: ASSISTANT_NODE_TRACE,
            ASSISTANT_ROUTE_ACCESS: ASSISTANT_NODE_AUTHZ,
            ASSISTANT_ROUTE_CONFIG: ASSISTANT_NODE_CONFIG_AUDIT,
        },
    )

    graph.add_edge(ASSISTANT_NODE_TRACE, ASSISTANT_NODE_TAINT)
    graph.add_edge(ASSISTANT_NODE_TAINT, ASSISTANT_NODE_MITIGATIONS)
    graph.add_edge(ASSISTANT_NODE_MITIGATIONS, ASSISTANT_NODE_VERDICT)
    graph.add_edge(ASSISTANT_NODE_AUTHZ, ASSISTANT_NODE_VERDICT)
    graph.add_edge(ASSISTANT_NODE_CONFIG_AUDIT, ASSISTANT_NODE_VERDICT)
    graph.add_edge(ASSISTANT_NODE_VERDICT, END)

    return graph.compile()
