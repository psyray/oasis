"""Deterministic aggregation of validation evidence into a verdict.

The LangGraph nodes gather raw evidence (entry points, taint flows, call
chains, mitigations, authz/control checks, config findings). This module
turns that evidence into one of the
:data:`AssistantInvestigationStatus` states plus a confidence score, without
calling the LLM. Keeping the aggregation in code makes results reproducible
and cheap to unit-test.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from oasis.helpers.vuln_taxonomy import VulnDescriptor, VulnFamily
from oasis.schemas.analysis import (
    AssistantInvestigationResult,
    AuthzCheckHit,
    ConfigFinding,
    ControlCheck,
    EntryPointHit,
    ExecutionPath,
    MitigationHit,
    TaintFlow,
)


@dataclass
class VerdictInputs:
    """Container for the evidence collected by the LangGraph helpers."""

    vulnerability_name: str
    descriptor: VulnDescriptor
    entry_points: Sequence[EntryPointHit] = ()
    execution_paths: Sequence[ExecutionPath] = ()
    taint_flows: Sequence[TaintFlow] = ()
    mitigations: Sequence[MitigationHit] = ()
    authz_hits: Sequence[AuthzCheckHit] = ()
    control_checks: Sequence[ControlCheck] = ()
    config_findings: Sequence[ConfigFinding] = ()
    errors: Sequence[str] = ()
    budget_exhausted: bool = False


def _verdict_flow(inputs: VerdictInputs) -> tuple[str, float, str]:
    paths_reaching_entry = [
        path for path in inputs.execution_paths if path.entry_point is not None and path.reached_sink
    ]
    any_taint = bool(inputs.taint_flows)
    nullifying = any(m.nullifies for m in inputs.mitigations)
    has_soft_mit = bool(inputs.mitigations) and not nullifying

    if nullifying:
        return "fully_mitigated", 0.85, (
            "A sanitizer or parameterization strong enough to neutralise the "
            "finding was detected on the exploitation path."
        )

    if paths_reaching_entry and any_taint and not has_soft_mit:
        return "confirmed_exploitable", 0.9, (
            "User input reaches the vulnerable sink through a reachable entry "
            "point and no mitigation was detected on the path."
        )

    if (paths_reaching_entry or any_taint) and has_soft_mit:
        return "partial_mitigation", 0.6, (
            "Exploitation path is plausible but some validators/sanitizers may "
            "reduce impact. Manual review recommended."
        )

    if paths_reaching_entry or any_taint:
        return "likely_exploitable", 0.65, (
            "Evidence of a taintable path to the sink was found, but the chain "
            "could not be fully reconstructed."
        )

    if not inputs.entry_points:
        return "unreachable", 0.55, (
            "No entry point reaching this sink was detected. The finding may be "
            "internal code with no external trigger."
        )

    return "insufficient_signal", 0.3, (
        "Not enough deterministic evidence to rule on this finding."
    )


def _verdict_access(inputs: VerdictInputs) -> tuple[str, float, str]:
    missing = [check for check in inputs.control_checks if not check.present]
    present = [check for check in inputs.control_checks if check.present]

    if inputs.control_checks and not missing:
        return "fully_mitigated", 0.85, (
            "All required access controls were observed in the codebase."
        )

    if missing and not present:
        return "confirmed_exploitable", 0.85, (
            "None of the required controls ("
            + ", ".join(check.kind for check in missing)
            + ") were detected."
        )

    if missing and present:
        return "partial_mitigation", 0.6, (
            "Some controls are present but others are missing: "
            + ", ".join(check.kind for check in missing)
        )

    if inputs.authz_hits:
        return "likely_exploitable", 0.55, (
            "Authorization hits were observed but required controls for this "
            "vulnerability were not explicitly verified."
        )

    return "insufficient_signal", 0.3, (
        "No access-control evidence could be correlated to this finding."
    )


def _verdict_config(inputs: VerdictInputs) -> tuple[str, float, str]:
    findings = list(inputs.config_findings)
    if not findings:
        return "fully_mitigated", 0.7, (
            "No misconfiguration or sensitive leak was detected by the "
            "configuration audit."
        )

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    top = max(findings, key=lambda f: severity_order.get(f.severity, 0))
    if severity_order.get(top.severity, 0) >= 3:
        return "confirmed_exploitable", 0.8, (
            f"Config finding '{top.kind}' was detected with severity {top.severity}."
        )
    return "partial_mitigation", 0.55, (
        f"Config finding '{top.kind}' detected with severity {top.severity}; review recommended."
    )


def compute_verdict(inputs: VerdictInputs) -> AssistantInvestigationResult:
    """Aggregate *inputs* deterministically and return a schema-validated result."""
    if inputs.errors and not any(
        (
            inputs.entry_points,
            inputs.execution_paths,
            inputs.taint_flows,
            inputs.mitigations,
            inputs.authz_hits,
            inputs.control_checks,
            inputs.config_findings,
        )
    ):
        return AssistantInvestigationResult(
            vulnerability_name=inputs.vulnerability_name,
            family=inputs.descriptor.family.value,
            status="error",
            confidence=0.0,
            summary="Validation failed before any evidence could be collected.",
            errors=list(inputs.errors),
            budget_exhausted=inputs.budget_exhausted,
        )

    if inputs.descriptor.family is VulnFamily.FLOW:
        status, confidence, summary = _verdict_flow(inputs)
    elif inputs.descriptor.family is VulnFamily.ACCESS:
        status, confidence, summary = _verdict_access(inputs)
    else:
        status, confidence, summary = _verdict_config(inputs)

    # Penalise confidence when the agent ran out of budget and evidence is mixed.
    if inputs.budget_exhausted:
        confidence = max(0.1, confidence - 0.15)

    citations = _flatten_citations(inputs)

    return AssistantInvestigationResult(
        vulnerability_name=inputs.vulnerability_name,
        family=inputs.descriptor.family.value,
        status=status,
        confidence=round(confidence, 2),
        summary=summary,
        entry_points=list(inputs.entry_points),
        execution_paths=list(inputs.execution_paths),
        taint_flows=list(inputs.taint_flows),
        mitigations=list(inputs.mitigations),
        authz_checks=list(inputs.authz_hits),
        control_checks=list(inputs.control_checks),
        config_findings=list(inputs.config_findings),
        citations=citations,
        budget_exhausted=inputs.budget_exhausted,
        errors=list(inputs.errors),
    )


def _flatten_citations(inputs: VerdictInputs) -> List:
    """Gather every citation from all evidence buckets (dedup by position)."""
    seen = set()
    out = []
    sources = []
    sources.extend(ep.citation for ep in inputs.entry_points)
    for path in inputs.execution_paths:
        if path.entry_point:
            sources.append(path.entry_point.citation)
        sources.extend(hop.citation for hop in path.hops)
    for flow in inputs.taint_flows:
        sources.extend((flow.source_citation, flow.sink_citation))
    sources.extend(m.citation for m in inputs.mitigations)
    sources.extend(h.citation for h in inputs.authz_hits)
    for check in inputs.control_checks:
        sources.extend(check.citations)
    sources.extend(f.citation for f in inputs.config_findings)
    for cit in sources:
        key = (cit.file_path, cit.start_line, cit.end_line)
        if key in seen:
            continue
        seen.add(key)
        out.append(cit)
    return out
