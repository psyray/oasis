"""Pure helpers for parsing executive-summary pipeline phase markdown tables."""

from __future__ import annotations

import re
from typing import Optional, Tuple

_PHASE_CELL_DIGITS = re.compile(r"\d+")


def parse_phase_counts_from_progress_cell(prog_cell: str) -> Optional[Tuple[int, int]]:
    """Extract ``(completed, total)`` integers from a markdown progress column.

    Accepts cells with extra text (percent suffixes, spacing). Returns ``None`` when
    no usable counts are found or integers cannot be parsed.
    """
    nums = _PHASE_CELL_DIGITS.findall(prog_cell)
    if len(nums) >= 2:
        try:
            c, t = int(nums[0]), int(nums[1])
        except ValueError:
            return None
        return (max(c, 0), max(t, 0))
    if len(nums) == 1:
        try:
            c = int(nums[0])
        except ValueError:
            return None
        t = max(c, 1)
        return (max(c, 0), max(t, 0))
    return None
