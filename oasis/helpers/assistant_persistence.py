"""Persist dashboard assistant chat sessions beside canonical JSON reports."""

from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .path_containment import is_path_within_root

CHAT_SCHEMA_VERSION = 1

_SESSION_ID_RE = re.compile(r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$")


def new_session_id() -> str:
    return str(uuid.uuid4())


def utc_now_iso() -> str:
    """UTC ISO-8601 timestamp with ``Z`` suffix (second resolution)."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def chat_dir_for_report_json(resolved_report: Path) -> Path:
    """Per-report chat directory ``<parent>/<stem>/chat`` (isolated per JSON file)."""
    stem = resolved_report.stem
    return (resolved_report.parent / stem / "chat").resolve()


def validate_session_id(session_id: str) -> bool:
    return isinstance(session_id, str) and bool(_SESSION_ID_RE.match(session_id.strip()))


def resolve_report_json(security_root: Path, report_rel: str) -> Optional[Path]:
    """Return resolved absolute path to report JSON if it exists and lies under *security_root*."""
    if not isinstance(report_rel, str) or not report_rel.strip():
        return None
    rel = report_rel.strip()
    if rel.startswith("/") or ".." in Path(rel).parts:
        return None
    candidate = (security_root / rel).resolve(strict=False)
    root = security_root.resolve()
    if not is_path_within_root(candidate, root):
        return None
    if not candidate.is_file() or candidate.suffix.lower() != ".json":
        return None
    return candidate


def list_chat_sessions(
    security_root: Path,
    report_rel: str,
    *,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """Return lightweight metadata for sessions, newest ``updated_at`` first."""
    resolved = resolve_report_json(security_root, report_rel)
    if resolved is None:
        return []
    chat_dir = chat_dir_for_report_json(resolved)
    if not chat_dir.is_dir():
        return []
    root = security_root.resolve()
    if not is_path_within_root(chat_dir, root):
        return []

    rows: List[Dict[str, Any]] = []
    try:
        for entry in chat_dir.iterdir():
            if not entry.is_file() or entry.suffix.lower() != ".json":
                continue
            try:
                raw = entry.read_text(encoding="utf-8")
                data = json.loads(raw)
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            sid = data.get("session_id")
            if not isinstance(sid, str) or not validate_session_id(sid):
                continue
            rows.append(
                {
                    "session_id": sid,
                    "created_at": data.get("created_at") or "",
                    "updated_at": data.get("updated_at") or "",
                    "message_count": len(data.get("messages") or []) if isinstance(data.get("messages"), list) else 0,
                    "model": data.get("model") or "",
                }
            )
    except OSError:
        return []

    def sort_key(r: Dict[str, Any]) -> str:
        return str(r.get("updated_at") or "")

    rows.sort(key=sort_key, reverse=True)
    cap = max(1, min(int(limit), 100))
    return rows[:cap]


def load_chat_session(
    security_root: Path,
    report_rel: str,
    session_id: str,
) -> Optional[Dict[str, Any]]:
    """Load full session document if present and valid."""
    if not validate_session_id(session_id):
        return None
    resolved = resolve_report_json(security_root, report_rel)
    if resolved is None:
        return None
    chat_dir = chat_dir_for_report_json(resolved)
    root = security_root.resolve()
    if not is_path_within_root(chat_dir, root):
        return None
    path = chat_dir / f"{session_id.strip()}.json"
    path = path.resolve(strict=False)
    if not is_path_within_root(path, root) or not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def _atomic_write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    fd, tmp = tempfile.mkstemp(
        prefix=".oasis_chat_",
        suffix=".json",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def save_chat_session(
    security_root: Path,
    report_rel: str,
    session_id: str,
    messages: List[Dict[str, Any]],
    model_name: str,
    vulnerability_name: str,
) -> None:
    """Write or replace the session file (full message list including latest assistant reply)."""
    if not validate_session_id(session_id):
        raise ValueError("invalid session_id")
    resolved_report = resolve_report_json(security_root, report_rel)
    if resolved_report is None:
        raise ValueError("invalid report")
    root = security_root.resolve()

    chat_dir = chat_dir_for_report_json(resolved_report)
    if not is_path_within_root(chat_dir, root):
        raise ValueError("invalid chat directory")

    path = chat_dir / f"{session_id}.json"
    path = path.resolve(strict=False)
    if not is_path_within_root(path.parent, root):
        raise ValueError("invalid chat path")

    now = utc_now_iso()
    created_at = now
    if path.is_file():
        try:
            prev = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(prev, dict) and isinstance(prev.get("created_at"), str):
                created_at = prev["created_at"]
        except (OSError, json.JSONDecodeError):
            pass

    rel_store = resolved_report.relative_to(root).as_posix()
    payload: Dict[str, Any] = {
        "schema_version": CHAT_SCHEMA_VERSION,
        "report_relative_path": rel_store,
        "vulnerability_name": vulnerability_name if isinstance(vulnerability_name, str) else "",
        "session_id": session_id,
        "created_at": created_at,
        "updated_at": now,
        "model": model_name if isinstance(model_name, str) else "",
        "messages": messages,
    }
    _atomic_write_json(path, payload)


def delete_chat_session(security_root: Path, report_rel: str, session_id: str) -> bool:
    """Remove one session file. Returns True if a file was deleted."""
    if not validate_session_id(session_id):
        return False
    resolved = resolve_report_json(security_root, report_rel)
    if resolved is None:
        return False
    chat_dir = chat_dir_for_report_json(resolved)
    root = security_root.resolve()
    if not is_path_within_root(chat_dir, root):
        return False
    path = (chat_dir / f"{session_id}.json").resolve(strict=False)
    if not is_path_within_root(path, root) or not path.is_file():
        return False
    try:
        path.unlink()
        return True
    except OSError:
        return False


def delete_all_chat_sessions(security_root: Path, report_rel: str) -> int:
    """Remove every ``*.json`` session under the report's chat directory. Returns delete count."""
    resolved = resolve_report_json(security_root, report_rel)
    if resolved is None:
        return 0
    chat_dir = chat_dir_for_report_json(resolved)
    root = security_root.resolve()
    if not is_path_within_root(chat_dir, root) or not chat_dir.is_dir():
        return 0
    n = 0
    try:
        for entry in chat_dir.iterdir():
            if not entry.is_file() or entry.suffix.lower() != ".json":
                continue
            ep = entry.resolve(strict=False)
            if not is_path_within_root(ep, root):
                continue
            try:
                entry.unlink()
                n += 1
            except OSError:
                continue
    except OSError:
        return n
    return n
