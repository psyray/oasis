"""Stable node/route identifiers for the assistant validation LangGraph."""

from __future__ import annotations


ASSISTANT_NODE_CLASSIFY = "classify_family"
ASSISTANT_NODE_ENTRY_POINTS = "collect_entry_points"
ASSISTANT_NODE_TRACE = "trace_execution"
ASSISTANT_NODE_TAINT = "taint_flow"
ASSISTANT_NODE_MITIGATIONS = "detect_mitigations"
ASSISTANT_NODE_AUTHZ = "detect_authz"
ASSISTANT_NODE_CONFIG_AUDIT = "config_audit"
ASSISTANT_NODE_VERDICT = "aggregate_verdict"

ASSISTANT_ROUTE_FLOW = "flow"
ASSISTANT_ROUTE_ACCESS = "access"
ASSISTANT_ROUTE_CONFIG = "config"
