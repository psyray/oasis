"""
Embedding helpers: throttling for optional embedding progress hooks (file-level embedding pass).

Used by ``EmbeddingManager``; complements ``oasis.helpers.scan`` for scan-level phases.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

EMBEDDING_PROGRESS_MIN_INTERVAL_SEC = 2.0

# Minimum spacing between throttle checks when ``min_interval_sec`` is very small or zero:
# avoids tight loops from hammering embedding hooks while still allowing frequent updates.
EMBEDDING_THROTTLE_MIN_INTERVAL_FLOOR_SEC = 0.05


def _coerce_nonneg_total(value: Any) -> int:
    """Parse ``total`` to a non-negative int; invalid or boolean values become ``0``."""
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(float(value)))
    except (TypeError, ValueError):
        return 0


def _coerce_completed(completed: Any, cap: int) -> int:
    if isinstance(completed, bool):
        n = 0
    else:
        try:
            n = int(float(completed))
        except (TypeError, ValueError):
            n = 0
    return max(0, min(n, cap))


class EmbeddingProgressThrottle:
    """Holds throttle state for optional embedding ``(completed, total)`` callbacks."""

    __slots__ = ("_last_emit_mono",)

    def __init__(self) -> None:
        self._last_emit_mono = 0.0

    def maybe_emit(
        self,
        hook: Optional[Callable[[int, int], None]],
        completed: int,
        total: int,
        *,
        min_interval_sec: float,
        force: bool = False,
    ) -> None:
        """Emit at most once per ``min_interval_sec`` while work is incomplete."""
        if hook is None:
            return

        safe_total = _coerce_nonneg_total(total)
        if safe_total <= 0:
            if not force:
                return
            self._last_emit_mono = time.monotonic()
            hook(0, 0)
            return

        safe_completed = _coerce_completed(completed, safe_total)
        now = time.monotonic()

        if force:
            self._last_emit_mono = now
            hook(safe_completed, safe_total)
            return

        if (
            safe_completed < safe_total
            and now - self._last_emit_mono
            < max(EMBEDDING_THROTTLE_MIN_INTERVAL_FLOOR_SEC, min_interval_sec)
        ):
            return
        self._last_emit_mono = now
        hook(safe_completed, safe_total)
