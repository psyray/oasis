"""Helpers for resetting tqdm bars between high-level scan phases (CLI orchestration)."""

from __future__ import annotations

from typing import Any, Optional


def reset_tqdm_phase_bar(
    pbar: Optional[Any],
    *,
    total: int,
    description: Optional[str] = None,
) -> None:
    """Reset tqdm to n=0 with a new total when starting a new high-level scan phase (tqdm>=4.67)."""
    if pbar is None:
        return
    reset_fn = getattr(pbar, "reset", None)
    if callable(reset_fn):
        reset_fn(total=total)
    set_desc = getattr(pbar, "set_description", None)
    if description is not None and callable(set_desc):
        set_desc(description, refresh=False)
