"""Executive-summary embedding similarity tier definitions (no config import; safe for config/bootstrap)."""

from __future__ import annotations

import logging
import math
from typing import Optional, Tuple, TypedDict

logger = logging.getLogger(__name__)


class ExecSummaryTier(TypedDict):
    id: str
    name: str
    heading_prefix: str
    min_inclusive: float
    max_exclusive: Optional[float]


EXEC_SUMMARY_EMBEDDING_TIERS: Tuple[ExecSummaryTier, ...] = (
    {
        "id": "strong",
        "name": "Strong",
        "heading_prefix": "Strong embedding match",
        "min_inclusive": 0.80,
        "max_exclusive": None,
    },
    {
        "id": "moderate",
        "name": "Moderate",
        "heading_prefix": "Moderate embedding match",
        "min_inclusive": 0.60,
        "max_exclusive": 0.80,
    },
    {
        "id": "weak",
        "name": "Weak",
        "heading_prefix": "Weak embedding match",
        "min_inclusive": 0.00,
        "max_exclusive": 0.60,
    },
)


def _tier_range_text(min_inclusive: float, max_exclusive: float | None) -> str:
    if max_exclusive is None:
        return f"similarity ≥ {min_inclusive:.2f}"
    if min_inclusive <= 0.0:
        return f"similarity < {max_exclusive:.2f}"
    return f"{min_inclusive:.2f} ≤ similarity < {max_exclusive:.2f}"


def executive_summary_tier_heading(tier: ExecSummaryTier) -> str:
    """Human heading used by markdown report section titles."""
    min_inclusive = tier["min_inclusive"]
    max_exclusive = tier["max_exclusive"]
    return f"{tier['heading_prefix']} ({_tier_range_text(min_inclusive, max_exclusive)})"


EXEC_SUMMARY_EMBEDDING_TIER_ORDER: Tuple[Tuple[str, str], ...] = tuple(
    (tier["id"], executive_summary_tier_heading(tier))
    for tier in EXEC_SUMMARY_EMBEDDING_TIERS
)


def executive_summary_similarity_tier_id(score: float) -> str:
    """Map cosine similarity to a canonical executive-summary tier id."""
    weakest_tier_id = EXEC_SUMMARY_EMBEDDING_TIERS[-1]["id"]
    if not math.isfinite(score):
        logger.warning(
            "Non-finite executive-summary similarity score %r; using weakest tier",
            score,
        )
        return weakest_tier_id
    normalized_score = min(max(score, 0.0), 1.0)
    if normalized_score != score:
        logger.warning(
            "Out-of-range executive-summary similarity score %r; clamping to [0.0, 1.0]",
            score,
        )
    for tier in EXEC_SUMMARY_EMBEDDING_TIERS:
        min_inclusive = tier["min_inclusive"]
        max_exclusive = tier["max_exclusive"]
        if max_exclusive is None:
            if normalized_score >= min_inclusive:
                return tier["id"]
            continue
        if min_inclusive <= normalized_score < max_exclusive:
            return tier["id"]
    return weakest_tier_id


def executive_summary_tiers_markdown_bullets() -> str:
    """Markdown bullet list used in explanatory report prose."""
    lines = []
    for tier in EXEC_SUMMARY_EMBEDDING_TIERS:
        min_inclusive = tier["min_inclusive"]
        max_exclusive = tier["max_exclusive"]
        lines.append(
            f"- **{tier['name']}**: {_tier_range_text(min_inclusive, max_exclusive)}"
        )
    return "\n".join(lines)


def executive_summary_tiers_inline_text() -> str:
    """Compact prose form used in short explanatory blocks."""
    parts = []
    for tier in EXEC_SUMMARY_EMBEDDING_TIERS:
        min_inclusive = tier["min_inclusive"]
        max_exclusive = tier["max_exclusive"]
        parts.append(
            f"{tier['id'].lower()} ({_tier_range_text(min_inclusive, max_exclusive)})"
        )
    return ", ".join(parts)
