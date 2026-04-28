"""Dashboard severity tier filtering (canonical JSON stats keys)."""

from __future__ import annotations

from typing import Any, Dict, Mapping, MutableMapping, Sequence, Tuple

# Query / UI tokens (lowercase)
DASHBOARD_SEVERITY_TIERS: Tuple[str, ...] = ("critical", "high", "medium", "low")

_STATS_KEYS: Mapping[str, str] = {
    "critical": "critical_risk",
    "high": "high_risk",
    "medium": "medium_risk",
    "low": "low_risk",
}


def parse_severity_filter_param(raw: str) -> Tuple[str, ...]:
    """Parse comma-separated severity tiers; unknown tokens dropped; order preserved."""
    if not raw or not raw.strip():
        return ()
    allowed = frozenset(DASHBOARD_SEVERITY_TIERS)
    seen: set[str] = set()
    out: list[str] = []
    for token in raw.split(","):
        t = token.strip().lower()
        if t in allowed and t not in seen:
            seen.add(t)
            out.append(t)
    return tuple(out)


def json_report_matches_any_severity_tier(report: Mapping[str, Any], tiers: Sequence[str]) -> bool:
    """True if JSON report stats show at least one selected tier with count > 0."""
    if report.get("format") != "json":
        return False
    st = report.get("stats") or {}
    for tier in tiers:
        key = _STATS_KEYS.get(tier)
        if key and int(st.get(key, 0)) > 0:
            return True
    return False


def report_passes_dashboard_severity_filter(report: Mapping[str, Any], tiers: Sequence[str]) -> bool:
    """Apply dashboard severity rules (Executive Summary always passes when tiers are active)."""
    if not tiers:
        return True
    if report.get("vulnerability_type") == "Executive Summary":
        return True
    return json_report_matches_any_severity_tier(report, tiers)


def merge_severity_finding_totals_for_report(
    finding_totals_by_tier: MutableMapping[str, int], report: Mapping[str, Any]
) -> None:
    """
    Add per-tier **finding** counts from a JSON vulnerability report (excludes Executive Summary).

    ``finding_totals_by_tier`` accumulates sums of LLM severity counters (``critical_risk``, …),
    aligned with dashboard ``risk_summary`` and the "Findings by severity" chart — not the number
    of report files per tier.
    """
    if report.get("format") != "json":
        return
    if report.get("vulnerability_type") == "Executive Summary":
        return
    st = report.get("stats") or {}
    for tier in DASHBOARD_SEVERITY_TIERS:
        key = _STATS_KEYS[tier]
        finding_totals_by_tier[tier] = finding_totals_by_tier.get(tier, 0) + int(st.get(key, 0) or 0)


def empty_severity_finding_totals() -> Dict[str, int]:
    """Return zeroed finding totals per canonical severity tier (for ``/api/stats`` aggregation)."""
    return {tier: 0 for tier in DASHBOARD_SEVERITY_TIERS}
