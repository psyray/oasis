"""Context expansion and safe path containment (reports, code windows)."""

from __future__ import annotations

from .expand import expand_line_window, expand_suspicious_chunk_records
from .path_containment import is_path_within_root

__all__ = [
    "expand_line_window",
    "expand_suspicious_chunk_records",
    "is_path_within_root",
]
