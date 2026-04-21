"""Snippet line resolution (SARIF / JSON) and structured-output degeneracy guards."""

from __future__ import annotations

import logging
import re
import zlib
from typing import Optional, Tuple

from ..config import (
    STRUCTURED_OUTPUT_DEGENERACY_COMPRESSION_RATIO_MAX,
    STRUCTURED_OUTPUT_DEGENERACY_MIN_RAW_CHARS,
    STRUCTURED_OUTPUT_DEGENERACY_REPEAT_MIN_RUNS,
    STRUCTURED_OUTPUT_DEGENERACY_REPEAT_UNIT_LEN,
    STRUCTURED_OUTPUT_DEGENERACY_ZLIB_LEVEL,
)

logger = logging.getLogger(__name__)


def _normalized_zlib_compress_level() -> int:
    """Clamp ``STRUCTURED_OUTPUT_DEGENERACY_ZLIB_LEVEL`` to zlib-supported values (defensive)."""
    raw = STRUCTURED_OUTPUT_DEGENERACY_ZLIB_LEVEL
    try:
        configured_level = int(raw)
    except (TypeError, ValueError):
        if logger.isEnabledFor(logging.WARNING):
            logger.warning(
                "structured_deep_raw_looks_degenerate: non-integer zlib level %r; "
                "falling back to default level 6",
                raw,
            )
        return 6
    if configured_level < 0 or configured_level > 9:
        if logger.isEnabledFor(logging.WARNING):
            logger.warning(
                "structured_deep_raw_looks_degenerate: invalid zlib level %r; "
                "clamping into [0, 9]",
                raw,
            )
        configured_level = min(max(configured_level, 0), 9)
    return configured_level


def substring_line_span_1based(haystack: str, needle: str) -> Optional[Tuple[int, int]]:
    """
    Return 1-based inclusive (start_line, end_line) for the first occurrence of
    ``needle`` in ``haystack``. Lines follow newline boundaries in ``haystack``.
    """
    n = (needle or "").strip()
    if not n:
        return None

    def span_for_char_range(start_char: int, end_char_inclusive: int) -> Tuple[int, int]:
        start_ln = haystack.count("\n", 0, start_char) + 1
        end_ln = haystack.count("\n", 0, end_char_inclusive + 1) + 1
        return (start_ln, end_ln)

    idx = haystack.find(n)
    if idx >= 0:
        return span_for_char_range(idx, idx + len(n) - 1)

    first_line = n.split("\n", 1)[0].strip()
    if len(first_line) >= 8:
        k = haystack.find(first_line)
        if k >= 0:
            return span_for_char_range(k, k + len(first_line) - 1)

    return None


def absolute_snippet_lines_in_file(
    chunk_text: str,
    chunk_start_line: int,
    vulnerable_code: str,
) -> Optional[Tuple[int, int]]:
    """Map a snippet inside ``chunk_text`` to absolute 1-based file lines."""
    rel = substring_line_span_1based(chunk_text, vulnerable_code)
    if rel is None:
        return None
    rel_s, rel_e = rel
    return (chunk_start_line + rel_s - 1, chunk_start_line + rel_e - 1)


def structured_deep_raw_looks_degenerate(raw: str, *, debug_log: bool = False) -> bool:
    """
    True when ``raw`` likely contains token loops / extreme repetition.

    Uses zlib compression ratio (repetitive text compresses unusually well) plus a
    fallback regex for consecutive identical substring repeats. Thresholds live in
    ``oasis.config`` (override via ``OASIS_STRUCTURED_DEGENERACY_*`` env vars).

    When ``debug_log`` is True, logs compression metrics if the zlib ratio threshold
    fires (use under ``-d`` / DEBUG to tune heuristics from production traces).

    Zlib level and repeat-regex parameters are validated against invalid env tuning so bad
    values degrade to non-degenerate or skip the regex branch instead of crashing.
    """
    if not raw:
        return False
    if len(raw) < STRUCTURED_OUTPUT_DEGENERACY_MIN_RAW_CHARS:
        return False

    zlib_level = _normalized_zlib_compress_level()
    blob = raw.encode("utf-8", errors="ignore")
    try:
        compressed = zlib.compress(blob, level=zlib_level)
    except ValueError as exc:
        if logger.isEnabledFor(logging.WARNING):
            logger.warning(
                "structured_deep_raw_looks_degenerate: zlib.compress failed with "
                "normalized level %s (config was %r); treating payload as non-degenerate: %s",
                zlib_level,
                STRUCTURED_OUTPUT_DEGENERACY_ZLIB_LEVEL,
                exc,
            )
        return False
    ratio = len(compressed) / max(len(blob), 1)
    if ratio < STRUCTURED_OUTPUT_DEGENERACY_COMPRESSION_RATIO_MAX:
        if debug_log and logger.isEnabledFor(logging.DEBUG):
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

    try:
        unit = int(STRUCTURED_OUTPUT_DEGENERACY_REPEAT_UNIT_LEN)
        runs = int(STRUCTURED_OUTPUT_DEGENERACY_REPEAT_MIN_RUNS)
    except (TypeError, ValueError):
        return False
    if unit < 1 or runs < 1:
        return False
    try:
        pattern = rf"(.{{{unit}}})(\1){{{runs},}}"
        return bool(re.search(pattern, raw, flags=re.DOTALL))
    except re.error:
        if logger.isEnabledFor(logging.WARNING):
            logger.warning(
                "structured_deep_raw_looks_degenerate: invalid repeat regex params "
                "unit=%r runs=%r; skipping repeat probe",
                STRUCTURED_OUTPUT_DEGENERACY_REPEAT_UNIT_LEN,
                STRUCTURED_OUTPUT_DEGENERACY_REPEAT_MIN_RUNS,
            )
        return False
