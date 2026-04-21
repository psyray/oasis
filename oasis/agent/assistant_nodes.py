"""Nodes for the assistant validation LangGraph.

Each node is pure (takes ``AssistantGraphState`` → returns a dict patch) so
nodes can be unit-tested without compiling the graph.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List

from oasis.agent.assistant_labels import (
    ASSISTANT_ROUTE_ACCESS,
    ASSISTANT_ROUTE_CONFIG,
    ASSISTANT_ROUTE_FLOW,
)
from oasis.agent.assistant_state import AssistantGraphState
from oasis.helpers.assistant_authz import (
    authz_hits_in_root,
    evaluate_required_controls,
)
from oasis.helpers.assistant_config_audit import run_config_audit
from oasis.helpers.assistant_crypto_scan import run_crypto_scan
from oasis.helpers.assistant_entrypoints import discover_entry_points
from oasis.helpers.assistant_log_filter import run_log_filter_scan
from oasis.helpers.assistant_mitigations import find_mitigations_in_root
from oasis.helpers.assistant_secret_scan import run_secret_scan
from oasis.helpers.assistant_taint import detect_flows_for_descriptor
from oasis.helpers.assistant_trace import trace_to_entry_points
from oasis.helpers.assistant_verdict import VerdictInputs, compute_verdict
from oasis.helpers.vuln_taxonomy import VulnDescriptor, VulnFamily, get_descriptor


def _ensure_descriptor(state: AssistantGraphState) -> VulnDescriptor:
    descriptor = state.get("descriptor")
    if isinstance(descriptor, VulnDescriptor):
        return descriptor
    resolved = get_descriptor(state.get("vulnerability_name", ""))
    if resolved is None:
        raise ValueError(
            f"Unknown vulnerability: {state.get('vulnerability_name')!r}"
        )
    return resolved


def _deadline(state: AssistantGraphState) -> float:
    started = state.setdefault("_started_at", time.monotonic())  # type: ignore[arg-type]
    budget = float(state.get("budget_seconds", 20.0))
    return started + budget


def _budget_ok(state: AssistantGraphState) -> bool:
    return time.monotonic() < _deadline(state)


def node_classify_family(state: AssistantGraphState) -> Dict[str, Any]:
    """Resolve the descriptor and prime the timer."""
    descriptor = _ensure_descriptor(state)
    state.setdefault("_started_at", time.monotonic())  # type: ignore[arg-type]
    return {
        "descriptor": descriptor,
        "entry_points": state.get("entry_points", []),
        "execution_paths": state.get("execution_paths", []),
        "taint_flows": state.get("taint_flows", []),
        "mitigations": state.get("mitigations", []),
        "authz_hits": state.get("authz_hits", []),
        "control_checks": state.get("control_checks", []),
        "config_findings": state.get("config_findings", []),
        "errors": state.get("errors", []),
        "budget_exhausted": False,
    }


def node_collect_entry_points(state: AssistantGraphState) -> Dict[str, Any]:
    """Discover framework entry points across the scan root."""
    if not _budget_ok(state):
        return {"budget_exhausted": True}
    try:
        grouped = discover_entry_points(Path(state["scan_root"]))
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "errors": [*state.get("errors", []), f"entry_points: {exc}"],
            "entry_points": [],
        }
    flat = [ep for entries in grouped.values() for ep in entries]
    state["_entry_points_grouped"] = grouped  # type: ignore[index]
    return {"entry_points": flat}


def node_trace_execution(state: AssistantGraphState) -> Dict[str, Any]:
    """Walk callers of the sink up toward the detected entry points."""
    if not _budget_ok(state):
        return {"budget_exhausted": True}
    sink_file = state.get("sink_file")
    sink_line = state.get("sink_line")
    grouped = state.get("_entry_points_grouped") or {}  # type: ignore[assignment]
    if not sink_file or not sink_line:
        return {"execution_paths": []}
    try:
        paths = trace_to_entry_points(
            Path(state["scan_root"]),
            Path(sink_file),
            int(sink_line),
            grouped,
        )
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "errors": [*state.get("errors", []), f"trace: {exc}"],
            "execution_paths": [],
        }
    return {"execution_paths": paths}


def node_taint_flow(state: AssistantGraphState) -> Dict[str, Any]:
    """Attempt to connect a user-controlled source to the sink line."""
    if not _budget_ok(state):
        return {"budget_exhausted": True}
    descriptor = _ensure_descriptor(state)
    sink_file = state.get("sink_file")
    sink_line = state.get("sink_line")
    if not sink_file or not sink_line:
        return {"taint_flows": []}
    try:
        flows = detect_flows_for_descriptor(
            Path(sink_file),
            int(sink_line),
            descriptor.sink_kinds,
            descriptor.source_kinds,
        )
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "errors": [*state.get("errors", []), f"taint: {exc}"],
            "taint_flows": [],
        }
    return {"taint_flows": flows}


def node_detect_mitigations(state: AssistantGraphState) -> Dict[str, Any]:
    """Scan for sanitizers/validators relevant to this vulnerability."""
    if not _budget_ok(state):
        return {"budget_exhausted": True}
    descriptor = _ensure_descriptor(state)
    if not descriptor.mitigation_kinds:
        return {"mitigations": []}
    try:
        hits = find_mitigations_in_root(
            Path(state["scan_root"]), descriptor.mitigation_kinds
        )
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "errors": [*state.get("errors", []), f"mitigations: {exc}"],
            "mitigations": [],
        }
    return {"mitigations": hits}


def node_detect_authz(state: AssistantGraphState) -> Dict[str, Any]:
    """Scan for access controls and evaluate the required ones."""
    if not _budget_ok(state):
        return {"budget_exhausted": True}
    descriptor = _ensure_descriptor(state)
    required = descriptor.required_controls
    if not required:
        return {"authz_hits": [], "control_checks": []}
    try:
        hits = authz_hits_in_root(Path(state["scan_root"]), required)
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "errors": [*state.get("errors", []), f"authz: {exc}"],
            "authz_hits": [],
            "control_checks": [],
        }
    checks = evaluate_required_controls(hits, required)
    return {"authz_hits": hits, "control_checks": checks}


def node_config_audit(state: AssistantGraphState) -> Dict[str, Any]:
    """Run the config/secrets/crypto/logs family scans for config vulns."""
    if not _budget_ok(state):
        return {"budget_exhausted": True}
    descriptor = _ensure_descriptor(state)
    if descriptor.family is not VulnFamily.CONFIG:
        return {"config_findings": []}

    scan_root = Path(state["scan_root"])
    findings: List[Any] = []
    name = state.get("vulnerability_name", "")
    try:
        if name == "Hardcoded Secrets":
            findings.extend(run_secret_scan(scan_root))
        if name == "Insecure Cryptographic Usage":
            findings.extend(run_crypto_scan(scan_root))
        if name == "Sensitive Data Logging":
            findings.extend(run_log_filter_scan(scan_root))
        # Config-level vulns share the general config audit; always run it to
        # surface DEBUG-on and wildcard CORS even for secondary checks.
        findings.extend(run_config_audit(scan_root))
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "errors": [*state.get("errors", []), f"config_audit: {exc}"],
            "config_findings": findings,
        }
    return {"config_findings": findings}


def node_aggregate_verdict(state: AssistantGraphState) -> Dict[str, Any]:
    """Combine evidence deterministically into the final verdict."""
    descriptor = _ensure_descriptor(state)
    inputs = VerdictInputs(
        vulnerability_name=state.get("vulnerability_name", ""),
        descriptor=descriptor,
        entry_points=state.get("entry_points", []),
        execution_paths=state.get("execution_paths", []),
        taint_flows=state.get("taint_flows", []),
        mitigations=state.get("mitigations", []),
        authz_hits=state.get("authz_hits", []),
        control_checks=state.get("control_checks", []),
        config_findings=state.get("config_findings", []),
        errors=state.get("errors", []),
        budget_exhausted=bool(state.get("budget_exhausted")),
    )
    result = compute_verdict(inputs)
    return {"result": result}


def route_after_classify(state: AssistantGraphState) -> str:
    """Pick the right validator branch based on the descriptor family."""
    descriptor = _ensure_descriptor(state)
    if descriptor.family is VulnFamily.FLOW:
        return ASSISTANT_ROUTE_FLOW
    if descriptor.family is VulnFamily.ACCESS:
        return ASSISTANT_ROUTE_ACCESS
    return ASSISTANT_ROUTE_CONFIG
