"""Encode and resolve ``analysis_root`` paths relative to ``security_reports``.

New reports store a path relative to the ``security_reports`` directory (typically
the scan input's parent's ``security_reports`` folder). Older reports store an
absolute scanned project root.

When reports are relocated, embedding cache (``.oasis_cache``) and RAG rely on
reconstructing the project root from this field plus the dashboard's current
``security_reports`` directory.
"""

from __future__ import annotations

import logging
import os
from contextlib import suppress
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# User-facing strings (reuse in README, dashboard constants, templates).
CODEBASE_UNAVAILABLE_SHORT = (
    "Scanned codebase directory is not reachable from this dashboard."
)
CODEBASE_UNAVAILABLE_DETAIL = (
    "The scanned codebase directory could not be resolved or read at the expected "
    "location relative to security_reports. Move or restore ``security_reports`` "
    "and ``.oasis_cache`` alongside the scanned project folder (same parent layout "
    "as when the scan ran). Until then, assistant and RAG cannot reliably use "
    "source files and embeddings."
)


def encode_analysis_root_for_storage(
    scan_root: Path | str,
    security_reports_root: Path | str,
) -> str:
    """Relative path string from ``security_reports`` to the scanned project root.

    Uses POSIX ``/`` separators so stored JSON matches normalization elsewhere.
    On ``relpath`` failure (e.g. distinct drive roots on Windows), falls back to the
    resolved absolute scan root as a POSIX path.
    """
    root = Path(scan_root).resolve()
    base = Path(security_reports_root).resolve()
    try:
        rel = os.path.relpath(root, base)
    except ValueError:
        return root.resolve().as_posix()
    return rel.replace("\\", "/")


def _normalized_path_segments(path: Path) -> tuple[str, ...]:
    """Cross-platform normalized parts without resolving (for suffix matching)."""
    norm = os.path.normpath(os.path.expanduser(str(path))).replace("\\", "/").strip("/")
    return tuple(norm.split("/")) if norm else ()


def _resolved_path_under_or_equal(ancestor: Path, descendant: Path) -> bool:
    """Return True if ``descendant`` resolves under ``ancestor`` or equals it.

    Used to reject relative stored paths that traverse outside ``security_reports``
    (e.g. ``..`` segments after joining with ``sec_root``).
    """
    try:
        descendant.resolve(strict=False).relative_to(ancestor.resolve(strict=False))
        return True
    except ValueError:
        return False


def _resolve_stale_absolute_by_suffix(
    raw: str,
    security_reports_root: Path,
) -> Optional[Path]:
    """Relocate an absolute stored root when the old path no longer exists on disk.

    **Precedence** (invoked only when the primary resolved path is not an existing
    directory): walk under ``security_reports_root.parent`` (the layout parent;
    typically the folder that contains both the project and ``security_reports``)
    and try suffixes of the stored absolute path from longest to shortest segment
    tail until an existing directory is found. Example: stored
    ``/old/machine/myapp`` may match ``…/workspace/myapp`` after relocation.

    To reduce accidental mismatches when many folders share trailing segments:

    * only multi-segment suffixes (at least two path segments) are tried in the
      main scan; single-segment tails are handled via the direct child of the
      layout parent (``anchor / last_segment``);
    * among candidates, the **longest** matching suffix wins (most specific path);
    * if several distinct directories tie at that depth, a warning is logged and
      the first deterministic choice is kept.
    """
    stripped = raw.strip()
    if not stripped:
        return None
    pure = Path(stripped)
    if not pure.is_absolute():
        return None
    anchor = Path(security_reports_root).resolve().parent
    seg = _normalized_path_segments(pure)
    if not seg:
        return None

    MIN_SUFFIX_SEGMENTS = 2
    matches: list[tuple[int, Path]] = []

    for k in range(len(seg), MIN_SUFFIX_SEGMENTS - 1, -1):
        candidate = (anchor / Path(*seg[-k:])).resolve(strict=False)
        with suppress(OSError):
            if candidate.exists() and candidate.is_dir():
                matches.append((k, candidate))

    tail_direct = (anchor / seg[-1]).resolve(strict=False)
    with suppress(OSError):
        if tail_direct.exists() and tail_direct.is_dir():
            matches.append((1, tail_direct))

    if not matches:
        return None

    max_k = max(k for k, _ in matches)
    tier = [(k, p) for k, p in matches if k == max_k]
    seen_resolved: set[str] = set()
    uniq_at_max: list[Path] = []
    for _, p in tier:
        try:
            key = str(p.resolve(strict=False))
        except OSError:
            key = str(p)
        if key not in seen_resolved:
            seen_resolved.add(key)
            uniq_at_max.append(p)

    chosen = uniq_at_max[0]
    if len(uniq_at_max) > 1:
        logger.warning(
            "Ambiguous stale analysis_root relocation for %r under layout parent %r "
            "(suffix depth %s). Candidates: %s. Using %s.",
            stripped,
            anchor,
            max_k,
            ", ".join(sorted(str(p) for p in uniq_at_max)),
            chosen,
        )
    return chosen


def resolve_analysis_root_from_storage(
    raw: Optional[str],
    security_reports_root: Path | str,
) -> Optional[Path]:
    """Resolve stored ``analysis_root`` to an existing directory, or ``None``.

    **Precedence**: (1) absolute paths — resolve as stored, then fallback to
    suffix relocation if missing; (2) relative paths — join with
    ``security_reports_root``, then reject if the resolved path escapes the
    layout parent directory (parent of ``security_reports``); this keeps normal
    ``../project`` sibling layouts while blocking traversal to unrelated trees
    (e.g. ``/etc``). Then same directory / suffix fallback as for absolutes.
    """
    if raw is None or not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None

    sec_root = Path(security_reports_root).expanduser().resolve(strict=False)

    candidate = Path(text).expanduser()
    if candidate.is_absolute():
        resolved = candidate.resolve(strict=False)
        return _resolve_existing_dir_or_suffix_fallback(resolved, text, sec_root)
    combined = (sec_root / text).resolve(strict=False)
    # Relative values are stored with os.path.relpath(scan_root, security_reports), so they
    # may legitimately use ".." to reach a sibling folder (e.g. "../myapp"). Reject only
    # resolutions that escape the layout parent (folder that contains security_reports).
    layout_parent = sec_root.resolve(strict=False).parent
    if not _resolved_path_under_or_equal(layout_parent, combined):
        return None
    return _resolve_existing_dir_or_suffix_fallback(combined, text, sec_root)


def _resolve_existing_dir_or_suffix_fallback(
    primary_candidate: Path,
    stored_text: str,
    security_reports_root: Path,
) -> Optional[Path]:
    """Prefer ``primary_candidate`` when it exists as a directory.

    Otherwise call :func:`_resolve_stale_absolute_by_suffix` with ``stored_text``
    (preserving the original string for suffix matching on stale absolutes).
    """
    if primary_candidate.is_dir():
        return primary_candidate
    suffix_hit = _resolve_stale_absolute_by_suffix(stored_text, security_reports_root)
    return suffix_hit if suffix_hit is not None else None


def is_directory_usable_for_assistant(path: Optional[Path]) -> bool:
    """Return True if ``path`` is a readable directory (exists + R_OK)."""
    if path is None:
        return False
    try:
        p = path.resolve(strict=False)
    except OSError:
        return False
    if not p.exists() or not p.is_dir():
        return False
    try:
        return os.access(str(p), os.R_OK)
    except OSError:
        return False


def codebase_access_state(
    *,
    stored_raw: Optional[str],
    security_reports_root: Path | str,
) -> tuple[Optional[Path], bool]:
    """Return ``(resolved_path, accessible)`` for dashboard / assistant flags."""
    resolved = resolve_analysis_root_from_storage(stored_raw, security_reports_root)
    ok = is_directory_usable_for_assistant(resolved)
    return resolved, ok


def assistant_context_warning(not_accessible: bool) -> Optional[str]:
    """Long user-facing explanation when codebase is unreachable."""
    return CODEBASE_UNAVAILABLE_DETAIL if not_accessible else None


def resolve_assistant_cache_root(
    report_payload: Optional[Dict[str, Any]],
    security_reports_root: Path | str,
    fallback_root: Path | str,
) -> Path:
    """Pick a local project root for embedding cache lookup (assistant RAG).

    Delegates to :func:`resolve_analysis_root_from_storage` then accessibility;
    falls back to ``fallback_root`` when unresolved or unusable.
    """
    fallback = Path(fallback_root).resolve()
    if not isinstance(report_payload, dict):
        return fallback
    raw = report_payload.get("analysis_root")
    if not isinstance(raw, str) or not raw.strip():
        return fallback
    resolved = resolve_analysis_root_from_storage(raw.strip(), security_reports_root)
    if resolved is not None and is_directory_usable_for_assistant(resolved):
        return resolved
    return fallback


def resolve_first_existing_scan_root(
    candidate_raw_strings: Optional[list[str]],
    security_reports_root: Path | str,
) -> Optional[Path]:
    """Return the first usable scan root among candidates (order preserved).

    Each non-empty candidate is tried once (deduplicated). Resolution uses
    :func:`resolve_analysis_root_from_storage` first; if that yields nothing but
    the candidate is an existing absolute directory, that path is used. The first
    result that passes :func:`is_directory_usable_for_assistant` wins.
    """
    if not candidate_raw_strings:
        return None
    sec_root = Path(security_reports_root).expanduser().resolve(strict=False)
    seen: set[str] = set()
    for raw in candidate_raw_strings:
        if raw is None:
            continue
        text = str(raw).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        resolved = resolve_analysis_root_from_storage(text, sec_root)
        if resolved is None:
            cand = Path(text).expanduser().resolve(strict=False)
            if cand.exists() and cand.is_dir():
                resolved = cand
        if resolved is not None and is_directory_usable_for_assistant(resolved):
            return resolved
    return None


__all__ = [
    "CODEBASE_UNAVAILABLE_DETAIL",
    "CODEBASE_UNAVAILABLE_SHORT",
    "assistant_context_warning",
    "codebase_access_state",
    "encode_analysis_root_for_storage",
    "is_directory_usable_for_assistant",
    "resolve_analysis_root_from_storage",
    "resolve_assistant_cache_root",
    "resolve_first_existing_scan_root",
]
