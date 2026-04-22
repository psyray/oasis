"""Shared wire counters for progress payloads (non-negative ints, completed vs total guards)."""

from __future__ import annotations

from typing import Any, Tuple


def wire_nonneg_int(raw: Any, *, default: int = 0) -> int:
    """Parse a JSON wire counter; clamp to a non-negative int."""
    try:
        return max(int(raw), 0)
    except (TypeError, ValueError):
        return max(default, 0)


def phase_row_completed_total(completed_raw: Any, total_raw: Any) -> Tuple[int, int]:
    """Normalize completed/total for a pipeline phase row (total >= completed)."""
    c = wire_nonneg_int(completed_raw, default=0)
    t = wire_nonneg_int(total_raw, default=0)
    return c, max(t, c)


def vuln_completed_total_pair(completed_raw: Any, total_raw: Any) -> Tuple[int, int]:
    """Executive-summary vulnerability counters (total >= completed)."""
    completed = wire_nonneg_int(completed_raw, default=0)
    total = wire_nonneg_int(total_raw, default=0)
    return completed, max(total, completed)
