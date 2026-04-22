"""Request validation helpers for dashboard assistant HTTP routes."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from oasis.helpers.assistant_scan_aggregate import model_directory_from_security_report_file
from oasis.helpers.executive_assistant_scope import synthetic_executive_primary_payload
from oasis.helpers.path_containment import is_path_within_root
from oasis.report import is_executive_summary_progress_sidecar

JsonErr = Tuple[Dict[str, Any], int]

AssistantPrimaryResult = Tuple[Optional[Path], Optional[Dict[str, Any]], Optional[JsonErr]]


def validate_assistant_messages(
    messages: Any,
    *,
    max_messages: int,
    max_message_chars: int,
    allow_empty: bool = False,
) -> Tuple[Optional[List[Dict[str, Any]]], Optional[JsonErr]]:
    """Validate ``messages`` for ``/api/assistant/chat`` (and session-branch when *allow_empty*).

    Returns ``(None, err)`` on failure.
    """
    if not isinstance(messages, list):
        return None, ({'error': 'messages required'}, 400)
    if not messages and not allow_empty:
        return None, ({'error': 'messages required'}, 400)
    if not messages:
        return [], None
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


def resolve_assistant_primary_payload(
    security_dir: Path,
    report_rel_raw: Any,
) -> AssistantPrimaryResult:
    """
    Resolve the report JSON path and optional on-disk payload for ``/api/assistant/chat``.

    Returns ``(resolved_path, synthetic_payload_or_none, err)``:
    - If the JSON file exists, ``(path, None, None)`` — load payload from disk.
    - For executive summary with only ``md/_executive_summary.md`` (missing sibling JSON),
      ``(json_path_anchor, synthetic_dict, None)`` — use the dict; anchor may not exist as a file.
    """
    if not isinstance(report_rel_raw, str) or not report_rel_raw.strip():
        return None, None, ({'error': 'report_path required'}, 400)
    rel = report_rel_raw.strip()
    if rel.startswith('/') or '..' in Path(rel).parts:
        return None, None, ({'error': 'Invalid path'}, 403)

    security_root = security_dir.resolve()
    candidate = (security_dir / rel).resolve(strict=False)

    if not is_path_within_root(candidate, security_root):
        return None, None, ({'error': 'Invalid path'}, 403)

    if candidate.is_file() and candidate.suffix.lower() == '.json':
        if is_executive_summary_progress_sidecar(candidate):
            return None, None, ({'error': 'Report not found'}, 404)
        return candidate, None, None

    if candidate.is_file() and candidate.suffix.lower() == '.md':
        json_sibling = candidate.parent.parent / 'json' / f'{candidate.stem}.json'
        if json_sibling.is_file():
            js_resolved = json_sibling.resolve(strict=False)
            if is_path_within_root(js_resolved, security_root):
                return js_resolved, None, None
        if candidate.stem.lower() == '_executive_summary':
            md_dir = model_directory_from_security_report_file(security_root, candidate)
            if md_dir is None:
                return None, None, ({'error': 'Could not resolve model directory'}, 400)
            anchor = json_sibling.resolve(strict=False)
            if not is_path_within_root(anchor, security_root):
                return None, None, ({'error': 'Invalid path'}, 403)
            return anchor, synthetic_executive_primary_payload(md_dir), None
        return None, None, ({'error': 'Report not found'}, 404)

    if (
        candidate.suffix.lower() == '.json'
        and candidate.stem.lower() == '_executive_summary'
        and not candidate.is_file()
    ):
        md_path = candidate.parent.parent / 'md' / '_executive_summary.md'
        if md_path.is_file():
            md_dir = model_directory_from_security_report_file(security_root, md_path)
            if md_dir is None:
                return None, None, ({'error': 'Could not resolve model directory'}, 400)
            if not is_path_within_root(candidate, security_root):
                return None, None, ({'error': 'Invalid path'}, 403)
            return candidate, synthetic_executive_primary_payload(md_dir), None

    return None, None, ({'error': 'Report not found'}, 404)


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
