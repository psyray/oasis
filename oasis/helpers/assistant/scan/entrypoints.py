"""Detect framework entry points (web routes, CLI commands, message handlers).

Produces :class:`oasis.schemas.analysis.EntryPointHit` records that the
assistant agent uses to:

1. Tell the user where a codebase can be reached from outside (high-value UX).
2. Root taint-flow traces when validating flow-based vulnerabilities.
3. Anchor access-control checks (is this endpoint protected by ``@login_required``?).

Results are cached on disk under ``<root>/.oasis_cache/assistant/entrypoints.v{N}.pkl``
keyed on the pattern catalog version, so repeated investigations during the
same dashboard session are fast.
"""

from __future__ import annotations

import hashlib
import pickle
from pathlib import Path
from typing import Dict, List, Optional

from .scan_utils import (
    PatternMatch,
    citation_from_match,
    compile_groups,
    scan_patterns_best_effort,
)
from oasis.helpers.context.path_containment import is_path_within_root
from oasis.helpers.vuln.validation_patterns import ENTRY_POINTS, PATTERNS_VERSION
from oasis.schemas.analysis import Citation, EntryPointHit


CACHE_VERSION = 1
_CACHE_DIR_NAME = ".oasis_cache/assistant"
_CACHE_FILE_TEMPLATE = "entrypoints.v{version}.pkl"


def _cache_path(root: Path) -> Path:
    filename = _CACHE_FILE_TEMPLATE.format(version=f"{CACHE_VERSION}-{PATTERNS_VERSION}")
    return root / _CACHE_DIR_NAME / filename


def _pattern_fingerprint() -> str:
    """Stable fingerprint of the entry-point catalog for cache invalidation."""
    parts: List[str] = [f"v{PATTERNS_VERSION}"]
    for framework in sorted(ENTRY_POINTS.keys()):
        parts.append(framework)
        parts.extend(f"{label}::{pattern}" for pattern, label in ENTRY_POINTS[framework])
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def _compiled_entry_patterns() -> Dict[str, List]:
    groups = {
        framework: [pat for pat, _label in patterns]
        for framework, patterns in ENTRY_POINTS.items()
    }
    return compile_groups(groups)


def _label_for(framework: str, line_text: str) -> str:
    """Pick the most precise label whose pattern still matches the hit line."""
    import re

    return next(
        (
            label
            for pattern, label in ENTRY_POINTS.get(framework, [])
            if re.search(pattern, line_text)
        ),
        framework,
    )


def _route_from_line(line_text: str) -> str:
    """Best-effort extraction of the route/path token from a hit line."""
    import re

    match = re.search(r"""['"]([^'"]+)['"]""", line_text)
    return match.group(1) if match else ""


def _match_to_entry_point(hit: PatternMatch, framework: str, root: Path) -> EntryPointHit:
    citation = Citation(**citation_from_match(hit))
    return EntryPointHit(
        framework=framework,
        label=_label_for(framework, hit.line_text),
        route=_route_from_line(hit.line_text),
        citation=citation,
    )


def _load_cache(root: Path) -> Optional[Dict[str, List[EntryPointHit]]]:
    cache_file = _cache_path(root)
    if not cache_file.is_file():
        return None
    try:
        with cache_file.open("rb") as handle:
            payload = pickle.load(handle)
    except (OSError, pickle.UnpicklingError, EOFError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("fingerprint") != _pattern_fingerprint():
        return None
    hits = payload.get("hits")
    if not isinstance(hits, list):
        return None
    results: Dict[str, List[EntryPointHit]] = {}
    for raw in hits:
        try:
            ep = EntryPointHit.model_validate(raw)
        except Exception:
            return None
        results.setdefault(ep.framework, []).append(ep)
    return results


def _save_cache(root: Path, grouped: Dict[str, List[EntryPointHit]]) -> None:
    cache_file = _cache_path(root)
    try:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        flat = [ep.model_dump() for hits in grouped.values() for ep in hits]
        payload = {"fingerprint": _pattern_fingerprint(), "hits": flat}
        with cache_file.open("wb") as handle:
            pickle.dump(payload, handle, protocol=pickle.HIGHEST_PROTOCOL)
    except OSError:
        # Cache is best-effort: ignore disk errors but do not crash the agent.
        return


def discover_entry_points(
    root: Path,
    *,
    use_cache: bool = True,
    max_hits: int = 2000,
) -> Dict[str, List[EntryPointHit]]:
    """Return detected entry points grouped by framework token."""
    if not root.exists() or not root.is_dir():
        return {}
    resolved = root.resolve()
    if use_cache:
        cached = _load_cache(resolved)
        if cached is not None:
            return cached

    compiled = _compiled_entry_patterns()
    hits = scan_patterns_best_effort(resolved, compiled, max_hits=max_hits)

    grouped: Dict[str, List[EntryPointHit]] = {}
    for hit in hits:
        if not is_path_within_root(hit.file_path, resolved):
            continue
        grouped.setdefault(hit.pattern_key, []).append(
            _match_to_entry_point(hit, hit.pattern_key, resolved)
        )

    if use_cache:
        _save_cache(resolved, grouped)
    return grouped


def entry_points_for_file(
    grouped: Dict[str, List[EntryPointHit]],
    file_path: Path,
) -> List[EntryPointHit]:
    """Filter *grouped* to entry points whose citation points at *file_path*."""
    resolved = file_path.resolve(strict=False)
    out: List[EntryPointHit] = []
    for entries in grouped.values():
        out.extend(
            ep
            for ep in entries
            if Path(ep.citation.file_path).resolve(strict=False) == resolved
        )
    return out


def invalidate_cache(root: Path) -> None:
    """Remove any persisted cache for *root* (used when users change patterns)."""
    cache_file = _cache_path(root.resolve())
    try:
        cache_file.unlink(missing_ok=True)
    except OSError:
        return
