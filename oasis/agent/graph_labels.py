"""Stable LangGraph node identifiers and conditional routing targets.

Single source for ``StateGraph.add_node``, ``add_edge``, and routing returns so refactors
do not drift from string literals scattered across modules.

``GRAPH_PIPELINE_NODE_AND_PHASE_ID`` pairs each linear-segment graph node with the
corresponding ``ProgressPhaseRowId`` used in ``oasis/helpers/progress.py`` (graph pipeline rows).
Nodes ``report`` / ``poc`` are not phase rows (report is CLI phase 6; PoC is optional after routing).
"""

from __future__ import annotations

from ..enums import ProgressPhaseRowId

GRAPH_NODE_DISCOVER = "discover"
GRAPH_NODE_SCAN = "scan"
GRAPH_NODE_EXPAND = "expand"
GRAPH_NODE_DEEP = "deep"
GRAPH_NODE_VERIFY = "verify"
GRAPH_NODE_REPORT = "report"
GRAPH_NODE_POC = "poc"

GRAPH_ROUTE_EXPAND = GRAPH_NODE_EXPAND
GRAPH_ROUTE_REPORT = GRAPH_NODE_REPORT

# Order must match the main chain in ``oasis/agent/graph.py`` (START → discover → … → verify)
# and the graph phase rows emitted by ``graph_pipeline_phases`` (after the embeddings row).
GRAPH_PIPELINE_NODE_AND_PHASE_ID: tuple[tuple[str, str], ...] = (
    (GRAPH_NODE_DISCOVER, ProgressPhaseRowId.GRAPH_DISCOVER.value),
    (GRAPH_NODE_SCAN, ProgressPhaseRowId.GRAPH_CHUNK_SCAN.value),
    (GRAPH_NODE_EXPAND, ProgressPhaseRowId.GRAPH_CONTEXT_EXPAND.value),
    (GRAPH_NODE_DEEP, ProgressPhaseRowId.GRAPH_DEEP.value),
    (GRAPH_NODE_VERIFY, ProgressPhaseRowId.GRAPH_VERIFY.value),
)
