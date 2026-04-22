"""
Embedding helpers: progress throttling, model normalization, and valid input file resolution.

Used by ``EmbeddingManager``; complements ``oasis.helpers.phases.scan`` for scan-level phases.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence, Union

from oasis.config import DEFAULT_ARGS

from ...tools import parse_input

logger = logging.getLogger(__name__)


class EmbedModelValueError(ValueError):
    """Invalid embed-model string or iterable (for programmatic callers; not argparse-specific)."""


# --- Embed model normalization (CLI / runtime) --------------------------------------

def parse_embed_models_csv(value: str) -> list[str]:
    """
    Parse comma-separated embedding model values into a normalized list.

    Raises:
        EmbedModelValueError: empty or invalid input (callers may map to ``argparse.ArgumentTypeError`` for CLI).
    """
    if not isinstance(value, str):
        raise EmbedModelValueError("embed-model must be a string")
    models: list[str] = []
    seen: set[str] = set()
    for raw in value.split(","):
        item = raw.strip()
        if not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        models.append(item)
    if not models:
        raise EmbedModelValueError("embed-model must contain at least one model name")
    return models


def normalize_embed_models(raw: str | Iterable[str] | None) -> list[str]:
    """
    Normalize raw embed-model values to a non-empty ordered list.

    Raises:
        EmbedModelValueError: invalid types or empty result after normalization.
    """
    if raw is None:
        return [DEFAULT_ARGS["EMBED_MODEL"]]
    if isinstance(raw, str):
        return parse_embed_models_csv(raw)

    models: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, str):
            raise EmbedModelValueError("embed-model entries must be strings")
        for parsed in parse_embed_models_csv(item):
            if parsed in seen:
                continue
            seen.add(parsed)
            models.append(parsed)
    if not models:
        raise EmbedModelValueError("embed-model must contain at least one model name")
    return models


def primary_embed_model(raw: str | Iterable[str] | None) -> str:
    """
    Return the first embedding model from normalized values.
    """
    return normalize_embed_models(raw)[0]


def resolve_embed_models(raw: str | Iterable[str] | None) -> tuple[list[str], str]:
    """
    Resolve both normalized embed models and primary model in one call.
    """
    models = normalize_embed_models(raw)
    return models, models[0]


# --- Embedding input files -----------------------------------------------------------

def resolve_valid_embedding_input_files(
    input_path: str,
    is_valid_file: Callable[[Path], bool],
    *,
    files_to_analyze: Optional[Sequence[Union[Path, str]]] = None,
    pre_parsed: bool = False,
) -> tuple[list[Path], int, list[Path]]:
    """
    Resolve embedding input files and split them into valid/unsupported groups.

    When ``pre_parsed`` is True, ``files_to_analyze`` must already contain ``Path`` instances.
    Otherwise, any provided paths are wrapped with ``Path(...)``. When ``files_to_analyze`` is
    omitted and ``pre_parsed`` is False, paths come from ``parse_input(input_path)``.
    """
    if pre_parsed:
        parsed_input_files = list(files_to_analyze or [])
    elif files_to_analyze is not None:
        parsed_input_files = [Path(file_path) for file_path in files_to_analyze]
    else:
        parsed_input_files = parse_input(input_path)
    if not parsed_input_files:
        return [], 0, []

    valid_files: list[Path] = []
    unsupported_files: list[Path] = []
    for file_path in parsed_input_files:
        if is_valid_file(file_path):
            valid_files.append(file_path)
        else:
            unsupported_files.append(file_path)
    return valid_files, len(parsed_input_files), unsupported_files


# --- Embedding progress throttle -----------------------------------------------------

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
