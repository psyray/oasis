"""
Lightweight typing for executive-summary progress payloads (wire JSON / dashboard).

These mirror structures built in ``scan_progress`` and ``exec_summary_progress``; they are
not enforced at runtime but help catch key/shape drift in static analysis.
"""

from __future__ import annotations

from typing import Dict, List, TypedDict

try:
    from typing import NotRequired  # py3.11+
except ImportError:
    from typing_extensions import NotRequired  # py3.9–3.10


class AdaptiveSubphaseSnapshot(TypedDict):
    label: str
    status: str
    completed: int
    total: int


AdaptiveSubphasesWire = Dict[str, AdaptiveSubphaseSnapshot]


class PhaseRowPayload(TypedDict):
    id: str
    label: str
    status: str
    completed: int
    total: int
    current_item: NotRequired[str]


PhaseRowsWire = List[PhaseRowPayload]
