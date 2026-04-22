"""Canonical filesystem containment checks under a security root."""

from __future__ import annotations

from pathlib import Path


def is_path_within_root(path: Path, root: Path) -> bool:
    """Return True if *path* resolves inside *root* (path traversal safe).

    Uses ``Path.is_relative_to`` when available (Python 3.9+); falls back to
    ``relative_to`` for older interpreters. Both arguments are normalized via
    ``resolve`` so callers may pass unresolved paths.
    """
    resolved_path = path.resolve(strict=False)
    resolved_root = root.resolve()
    is_relative_to = getattr(resolved_path, "is_relative_to", None)
    if callable(is_relative_to):
        return resolved_path.is_relative_to(resolved_root)
    try:
        resolved_path.relative_to(resolved_root)
        return True
    except ValueError:
        return False
