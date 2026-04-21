"""Request validation helpers for dashboard assistant HTTP routes."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from oasis.helpers.path_containment import is_path_within_root

JsonErr = Tuple[Dict[str, Any], int]


def validate_assistant_messages(
    messages: Any,
    *,
    max_messages: int,
    max_message_chars: int,
) -> Tuple[Optional[List[Dict[str, Any]]], Optional[JsonErr]]:
    """Validate ``messages`` for ``/api/assistant/chat``. Returns ``(None, err)`` on failure."""
    if not isinstance(messages, list) or not messages:
        return None, ({'error': 'messages required'}, 400)
    if len(messages) > max_messages:
        return None, ({'error': 'too many messages'}, 400)
    out: List[Dict[str, Any]] = []
    for msg in messages:
        if not isinstance(msg, dict):
            return None, ({'error': 'invalid message'}, 400)
        role = msg.get('role')
        if role not in ('user', 'assistant', 'system'):
            return None, ({'error': 'invalid role'}, 400)
        content = msg.get('content', '')
        if not isinstance(content, str):
            return None, ({'error': 'invalid content'}, 400)
        if len(content) > max_message_chars:
            return None, ({'error': 'message too long'}, 400)
        out.append(msg)
    return out, None


def resolve_assistant_report_json_path(
    report_rel_raw: Any,
    security_dir: Path,
) -> Tuple[Optional[Path], Optional[JsonErr]]:
    """Resolve and validate ``report_path`` for a JSON report under *security_dir*."""
    if not isinstance(report_rel_raw, str) or not report_rel_raw.strip():
        return None, ({'error': 'report_path required'}, 400)
    report_rel = report_rel_raw.strip()
    json_file = security_dir / report_rel
    security_root = security_dir.resolve()
    resolved_report = json_file.resolve(strict=False)

    if not is_path_within_root(resolved_report, security_root):
        return None, ({'error': 'Invalid path'}, 403)
    if not resolved_report.is_file() or resolved_report.suffix.lower() != '.json':
        return None, ({'error': 'Report not found'}, 404)
    return resolved_report, None


def coerce_optional_index(value: Any) -> Optional[int]:
    """Return a non-negative int or ``None`` for optional finding indices."""
    if value is None:
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


def coerce_finding_indices(data: Dict[str, Any]) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    """Extract optional file/chunk/finding indices from assistant POST JSON."""
    return (
        coerce_optional_index(data.get('file_index')),
        coerce_optional_index(data.get('chunk_index')),
        coerce_optional_index(data.get('finding_index')),
    )


def normalize_report_rel_query_arg(raw: Any) -> Optional[str]:
    """Strip ``report_path`` query/form value; return ``None`` if missing."""
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    return s or None
