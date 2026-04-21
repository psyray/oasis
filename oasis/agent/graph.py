"""Compile the LangGraph analysis DAG.

Linear segment order matches ``GRAPH_PIPELINE_NODE_AND_PHASE_ID`` in ``graph_labels.py``
(dashboard phase rows + CLI banners). Report/PoC follow conditional routing after verify.
"""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from .graph_labels import (
    GRAPH_NODE_DEEP,
    GRAPH_NODE_DISCOVER,
    GRAPH_NODE_EXPAND,
    GRAPH_NODE_POC,
    GRAPH_NODE_REPORT,
    GRAPH_NODE_SCAN,
    GRAPH_NODE_VERIFY,
    GRAPH_ROUTE_EXPAND,
    GRAPH_ROUTE_REPORT,
)
from .nodes import (
    node_deep,
    node_discover,
    node_expand,
    node_poc,
    node_report,
    node_scan,
    node_verify,
    route_after_report,
    route_after_verify,
)
from .state import OasisGraphState


def build_oasis_analysis_graph():
    graph = StateGraph(OasisGraphState)
    graph.add_node(GRAPH_NODE_DISCOVER, node_discover)
    graph.add_node(GRAPH_NODE_SCAN, node_scan)
    graph.add_node(GRAPH_NODE_EXPAND, node_expand)
    graph.add_node(GRAPH_NODE_DEEP, node_deep)
    graph.add_node(GRAPH_NODE_VERIFY, node_verify)
    graph.add_node(GRAPH_NODE_REPORT, node_report)
    graph.add_node(GRAPH_NODE_POC, node_poc)

    graph.add_edge(START, GRAPH_NODE_DISCOVER)
    graph.add_edge(GRAPH_NODE_DISCOVER, GRAPH_NODE_SCAN)
    graph.add_edge(GRAPH_NODE_SCAN, GRAPH_NODE_EXPAND)
    graph.add_edge(GRAPH_NODE_EXPAND, GRAPH_NODE_DEEP)
    graph.add_edge(GRAPH_NODE_DEEP, GRAPH_NODE_VERIFY)
    graph.add_conditional_edges(
        GRAPH_NODE_VERIFY,
        route_after_verify,
        {GRAPH_ROUTE_EXPAND: GRAPH_NODE_EXPAND, GRAPH_ROUTE_REPORT: GRAPH_NODE_REPORT},
    )
    graph.add_conditional_edges(
        GRAPH_NODE_REPORT,
        route_after_report,
        {GRAPH_NODE_POC: GRAPH_NODE_POC, END: END},
    )
    graph.add_edge(GRAPH_NODE_POC, END)

    return graph.compile()
