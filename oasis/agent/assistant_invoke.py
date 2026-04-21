"""High-level entry point to run the assistant validation LangGraph.

Wraps the compile/build cost behind a lazy singleton so callers (HTTP
endpoint, tests, CLI) just call :func:`invoke_assistant_validation` with a
findings-like payload and receive a validated
:class:`AssistantInvestigationResult`.

When LangGraph is unavailable (optional dependency), a pure-Python fallback
executes the same nodes sequentially so unit tests and CI without LangGraph
installed still exercise the logic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from oasis.agent.assistant_nodes import (
    _ensure_descriptor,
    node_aggregate_verdict,
    node_classify_family,
    node_collect_entry_points,
    node_config_audit,
    node_detect_authz,
    node_detect_mitigations,
    node_taint_flow,
    node_trace_execution,
)
from oasis.agent.assistant_state import AssistantGraphState
from oasis.helpers.vuln_taxonomy import VulnFamily
from oasis.schemas.analysis import AssistantInvestigationResult


_DEFAULT_BUDGET_SECONDS = 20.0
_BUDGET_MIN_SECONDS = 2.0
_BUDGET_MAX_SECONDS = 120.0


def coerce_investigation_budget(raw: Any) -> float:
    """Clamp a raw client-supplied budget to a safe range."""
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return _DEFAULT_BUDGET_SECONDS
    return max(_BUDGET_MIN_SECONDS, min(_BUDGET_MAX_SECONDS, value))


def _apply_patch(state: AssistantGraphState, patch: dict) -> None:
    for key, value in patch.items():
        state[key] = value  # type: ignore[literal-required]


def _run_fallback(state: AssistantGraphState) -> AssistantGraphState:
    """Execute nodes sequentially when LangGraph is not importable."""
    _apply_patch(state, node_classify_family(state))
    descriptor = _ensure_descriptor(state)
    if descriptor.family is VulnFamily.CONFIG:
        _apply_patch(state, node_config_audit(state))
    else:
        _apply_patch(state, node_collect_entry_points(state))
        if descriptor.family is VulnFamily.FLOW:
            _apply_patch(state, node_trace_execution(state))
            _apply_patch(state, node_taint_flow(state))
            _apply_patch(state, node_detect_mitigations(state))
        else:  # ACCESS
            _apply_patch(state, node_detect_authz(state))
    _apply_patch(state, node_aggregate_verdict(state))
    return state


def _compile_graph() -> Optional[Any]:
    try:
        from oasis.agent.assistant_graph import build_assistant_validation_graph

        return build_assistant_validation_graph()
    except Exception:
        return None


_COMPILED_GRAPH: Optional[Any] = None
_GRAPH_COMPILE_ATTEMPTED = False


def _get_compiled_graph() -> Optional[Any]:
    global _COMPILED_GRAPH, _GRAPH_COMPILE_ATTEMPTED
    if not _GRAPH_COMPILE_ATTEMPTED:
        _GRAPH_COMPILE_ATTEMPTED = True
        _COMPILED_GRAPH = _compile_graph()
    return _COMPILED_GRAPH


def invoke_assistant_validation(
    *,
    vulnerability_name: str,
    scan_root: Path,
    sink_file: Optional[Path] = None,
    sink_line: Optional[int] = None,
    budget_seconds: Optional[float] = None,
) -> AssistantInvestigationResult:
    """Run the validation agent and return the aggregated verdict."""
    state: AssistantGraphState = {
        "vulnerability_name": vulnerability_name,
        "scan_root": Path(scan_root),
        "sink_file": Path(sink_file) if sink_file else None,
        "sink_line": int(sink_line) if sink_line else None,
        "budget_seconds": coerce_investigation_budget(budget_seconds)
        if budget_seconds is not None
        else _DEFAULT_BUDGET_SECONDS,
        "entry_points": [],
        "execution_paths": [],
        "taint_flows": [],
        "mitigations": [],
        "authz_hits": [],
        "control_checks": [],
        "config_findings": [],
        "errors": [],
        "budget_exhausted": False,
    }

    graph = _get_compiled_graph()
    if graph is not None:
        try:
            final_state = graph.invoke(state)
            if isinstance(final_state, dict) and "result" in final_state:
                result = final_state["result"]
                if isinstance(result, AssistantInvestigationResult):
                    return result
        except Exception:
            # Fall back to sequential execution on LangGraph runtime errors.
            pass
    final_state = _run_fallback(state)
    result = final_state.get("result")
    if isinstance(result, AssistantInvestigationResult):
        return result
    # Defensive: produce a minimal schema-valid error result.
    return AssistantInvestigationResult(
        vulnerability_name=vulnerability_name,
        family="flow",
        status="error",
        summary="Validation agent returned no result.",
        errors=["no_result"],
    )
