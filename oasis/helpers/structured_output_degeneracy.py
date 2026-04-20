"""Detect pathological structured LLM output before expensive JSON repair.

Tuning: see the "Heuristic tuning" section in ``oasis/config.py`` (``OASIS_STRUCTURED_DEGENERACY_*``).
"""

from __future__ import annotations

import logging
import re
import zlib

from ..config import (
    STRUCTURED_OUTPUT_DEGENERACY_COMPRESSION_RATIO_MAX,
    STRUCTURED_OUTPUT_DEGENERACY_MIN_RAW_CHARS,
    STRUCTURED_OUTPUT_DEGENERACY_REPEAT_MIN_RUNS,
    STRUCTURED_OUTPUT_DEGENERACY_REPEAT_UNIT_LEN,
    STRUCTURED_OUTPUT_DEGENERACY_ZLIB_LEVEL,
)

logger = logging.getLogger(__name__)


def structured_deep_raw_looks_degenerate(raw: str, *, debug_log: bool = False) -> bool:
    """
    True when ``raw`` likely contains token loops / extreme repetition.

    Uses zlib compression ratio (repetitive text compresses unusually well) plus a
    fallback regex for consecutive identical substring repeats. Thresholds live in
    ``oasis.config`` (override via ``OASIS_STRUCTURED_DEGENERACY_*`` env vars).

    When ``debug_log`` is True, logs compression metrics if the zlib ratio threshold
    fires (use under ``-d`` / DEBUG to tune heuristics from production traces).
    """
    if not raw:
        return False
    if len(raw) < STRUCTURED_OUTPUT_DEGENERACY_MIN_RAW_CHARS:
        return False

    blob = raw.encode("utf-8", errors="ignore")
    compressed = zlib.compress(blob, level=STRUCTURED_OUTPUT_DEGENERACY_ZLIB_LEVEL)
    ratio = len(compressed) / max(len(blob), 1)
    # Normal structured JSON (~2–15 KB) typically yields ratios ~0.22–0.55; repetitive
    # filler inside a broken string drops far below ~0.12.
    if ratio < STRUCTURED_OUTPUT_DEGENERACY_COMPRESSION_RATIO_MAX:
        if debug_log:
            logger.debug(
                "structured_deep_raw_looks_degenerate: zlib ratio below threshold",
                extra={
                    "payload_bytes": len(blob),
                    "compressed_bytes": len(compressed),
                    "compression_ratio": ratio,
                    "threshold": STRUCTURED_OUTPUT_DEGENERACY_COMPRESSION_RATIO_MAX,
                },
            )
        return True

    unit = STRUCTURED_OUTPUT_DEGENERACY_REPEAT_UNIT_LEN
    runs = STRUCTURED_OUTPUT_DEGENERACY_REPEAT_MIN_RUNS
    # Same short run repeated many times (stuck token loop inside a string).
    return bool(re.search(rf"(.{{{unit}}})(\1){{{runs},}}", raw, flags=re.DOTALL))
