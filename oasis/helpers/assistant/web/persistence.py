"""Persist dashboard assistant chat sessions beside canonical JSON reports."""


from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ...context.path_containment import is_path_within_root

CHAT_SCHEMA_VERSION = 3

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


def normalize_validated_messages_for_storage(
    messages: Sequence[Dict[str, Any]],
    *,
    default_at: str,
) -> List[Dict[str, Any]]:
    """Build the on-disk message list (roles, ``at``, assistant think fields).

    Call after :func:`oasis.helpers.assistant.web.api_validate.validate_assistant_messages`.
    Shapes match dashboard ``_assistantMessagesForApi`` / branch persistence.
    """
    out: List[Dict[str, Any]] = []
    for m in messages:
        if not isinstance(m, dict):
            continue
        mc: Dict[str, Any] = {
            "role": str(m.get("role", "")),
            "content": m["content"] if isinstance(m.get("content"), str) else "",
        }
        att = m.get("at")
        mc["at"] = att.strip() if isinstance(att, str) and att.strip() else default_at
        if m.get("role") == "assistant":
            if isinstance(m.get("visible_markdown"), str):
                mc["visible_markdown"] = m["visible_markdown"]
            if isinstance(m.get("thought_segments"), list):
                mc["thought_segments"] = m["thought_segments"]
        out.append(mc)
    return out


def branch_key(model: str) -> str:
    """Normalized dict key for ``model_branches`` (chat model name)."""
    return (model or "").strip()


def finding_validation_storage_key(
    finding_scope_report_path: str,
    file_index: Optional[int],
    chunk_index: Optional[int],
    finding_index: Optional[int],
) -> Optional[str]:
    """Stable JSON key for ``finding_validations`` (must match dashboard JS).

    Uses sorted object keys so the wire form matches ``JSON.stringify`` with
    keys ``ci``, ``fi``, ``gi``, ``s`` (alphabetical).
    """
    if file_index is None or chunk_index is None or finding_index is None:
        return None
    if file_index < 0 or chunk_index < 0 or finding_index < 0:
        return None
    s = (finding_scope_report_path or "").strip()
    payload = {"ci": chunk_index, "fi": file_index, "gi": finding_index, "s": s}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


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
    if candidate.is_file() and candidate.suffix.lower() == ".json":
        return candidate
    rel_path = Path(rel)
    # Executive assistant anchor: missing json/_executive_summary.json but md exists (same chat dir layout).
    if (
        candidate.suffix.lower() == ".json"
        and rel_path.stem.lower() == "_executive_summary"
        and not candidate.is_file()
    ):
        md_path = candidate.parent.parent / "md" / "_executive_summary.md"
        if md_path.is_file():
            return candidate
    if (
        candidate.is_file()
        and candidate.suffix.lower() == ".md"
        and rel_path.stem.lower() == "_executive_summary"
    ):
        anchor = candidate.parent.parent / "json" / "_executive_summary.json"
        if is_path_within_root(anchor.resolve(strict=False), root):
            return anchor.resolve(strict=False)
    return None


def _default_branch() -> Dict[str, Any]:
    return {"messages": [], "finding_validations": {}}


def _coerce_finding_validations_map(raw: Any) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    if not isinstance(raw, dict):
        return out
    for k, v in raw.items():
        ks = str(k).strip()
        if ks and isinstance(v, dict):
            out[ks] = dict(v)
    return out


def _created_at_prev_vuln_from_document(
    prev: Optional[Dict[str, Any]], *, now: str
) -> Tuple[str, str]:
    """Default ``created_at`` to *now* and vulnerability carry-over from *prev* when present."""
    if not prev:
        return now, ""
    created_at = prev["created_at"] if isinstance(prev.get("created_at"), str) else now
    pv = prev.get("vulnerability_name")
    prev_vuln = pv if isinstance(pv, str) else ""
    return created_at, prev_vuln


def _top_level_model_and_messages_for_branch_save(
    key: str,
    messages: List[Dict[str, Any]],
    *,
    set_as_active: bool,
    top_model_seed: str,
    model_branches: Dict[str, Any],
) -> Tuple[str, List[Dict[str, Any]]]:
    """Pick top-level ``model`` / ``messages`` after updating one branch."""
    if set_as_active:
        return key, list(messages)
    active = model_branches.get(branch_key(top_model_seed))
    if isinstance(active, dict) and isinstance(active.get("messages"), list):
        return top_model_seed, active["messages"]
    return top_model_seed, []


def _top_messages_reflecting_active_branch(
    model_branches: Dict[str, Any],
    top_model: str,
    *,
    fallback: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Prefer messages on the active branch when well-formed; otherwise *fallback*."""
    active = model_branches.get(branch_key(top_model))
    if isinstance(active, dict) and isinstance(active.get("messages"), list):
        return active["messages"]
    return fallback


def _branch_context_from_prev_for_validation_merge(
    prev: Optional[Dict[str, Any]], *, key: str
) -> Tuple[Dict[str, Any], str, List[Dict[str, Any]]]:
    """Return ``model_branches``, stored top ``model``, and top-level messages fallback."""
    if not prev:
        return {}, key, []
    model_branches = _coerce_model_branches(prev.get("model_branches"))
    pm = prev.get("model")
    top_model = pm.strip() if isinstance(pm, str) and pm.strip() else key
    pmessages = prev.get("messages")
    top_fb: List[Dict[str, Any]] = pmessages if isinstance(pmessages, list) else []
    return model_branches, top_model, top_fb


def _resolve_writable_chat_session_path(
    security_root: Path,
    report_rel: str,
    session_id: str,
) -> Tuple[Path, Path, Path]:
    """Return ``(root, resolved_report_json, session_json_path)`` for chat writes."""
    if not validate_session_id(session_id):
        raise ValueError("invalid session_id")
    resolved_report = resolve_report_json(security_root, report_rel)
    if resolved_report is None:
        raise ValueError("invalid report")
    root = security_root.resolve()
    chat_dir = chat_dir_for_report_json(resolved_report)
    if not is_path_within_root(chat_dir, root):
        raise ValueError("invalid chat directory")
    path = (chat_dir / f"{session_id}.json").resolve(strict=False)
    if not is_path_within_root(path.parent, root):
        raise ValueError("invalid chat path")
    return root, resolved_report, path


def _coerce_model_branches(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    out: Dict[str, Any] = {}
    for k, v in raw.items():
        key = branch_key(str(k))
        if not key:
            continue
        if not isinstance(v, dict):
            out[key] = _default_branch()
            continue
        msgs = v.get("messages")
        if not isinstance(msgs, list):
            msgs = []
        fvs = _coerce_finding_validations_map(v.get("finding_validations"))
        out[key] = {"messages": msgs, "finding_validations": fvs}
    return out


def _session_path(
    security_root: Path, report_rel: str, session_id: str
) -> Optional[Path]:
    if not validate_session_id(session_id):
        return None
    resolved_report = resolve_report_json(security_root, report_rel)
    if resolved_report is None:
        return None
    root = security_root.resolve()
    chat_dir = chat_dir_for_report_json(resolved_report)
    if not is_path_within_root(chat_dir, root):
        return None
    path = (chat_dir / f"{session_id.strip()}.json").resolve(strict=False)
    return path if is_path_within_root(path.parent, root) else None


def _load_session_document(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


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
            msgs = data.get("messages")
            msg_count = len(msgs) if isinstance(msgs, list) else 0
            rows.append(
                {
                    "session_id": sid,
                    "created_at": data.get("created_at") or "",
                    "updated_at": data.get("updated_at") or "",
                    "message_count": msg_count,
                    "model": data.get("model") or "",
                }
            )
    except OSError:
        return []

    def sort_key(r: Dict[str, Any]) -> str:
        return str(r.get("updated_at") or "")

    rows.sort(key=sort_key, reverse=True)
    cap = max(1, min(limit, 100))
    return rows[:cap]


def load_chat_session(
    security_root: Path,
    report_rel: str,
    session_id: str,
) -> Optional[Dict[str, Any]]:
    """Load full session document if present and valid."""
    path = _session_path(security_root, report_rel, session_id)
    return None if path is None else _load_session_document(path)


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
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def save_chat_session(
    security_root: Path,
    report_rel: str,
    session_id: str,
    messages: List[Dict[str, Any]],
    model_name: str,
    vulnerability_name: str,
) -> None:
    """Merge messages into ``model_branches`` for ``model_name`` (preserves ``finding_validations``)."""
    root, resolved_report, path = _resolve_writable_chat_session_path(
        security_root, report_rel, session_id
    )

    now = utc_now_iso()
    prev = _load_session_document(path)
    created_at, prev_vuln = _created_at_prev_vuln_from_document(prev, now=now)
    model_branches: Dict[str, Any] = {}
    if prev:
        model_branches = _coerce_model_branches(prev.get("model_branches"))

    key = branch_key(model_name)
    if not key:
        raise ValueError("model_name required")

    branch = dict(model_branches.get(key) or _default_branch())
    branch["messages"] = list(messages)
    model_branches[key] = branch

    rel_store = resolved_report.relative_to(root).as_posix()
    vn = vulnerability_name if isinstance(vulnerability_name, str) else ""
    if not vn and prev_vuln:
        vn = prev_vuln

    payload: Dict[str, Any] = {
        "schema_version": CHAT_SCHEMA_VERSION,
        "report_relative_path": rel_store,
        "vulnerability_name": vn,
        "session_id": session_id,
        "created_at": created_at,
        "updated_at": now,
        "model": key,
        "messages": list(messages),
        "model_branches": model_branches,
    }
    _atomic_write_json(path, payload)


def save_session_branch_messages(
    security_root: Path,
    report_rel: str,
    session_id: str,
    model_name: str,
    messages: List[Dict[str, Any]],
    vulnerability_name: str,
    *,
    set_as_active: bool = False,
) -> None:
    """Update only ``messages`` for one branch; preserve ``finding_validations`` and other branches.

    If ``set_as_active`` is True, top-level ``model`` / ``messages`` mirror this branch after the write.
    """
    root, resolved_report, path = _resolve_writable_chat_session_path(
        security_root, report_rel, session_id
    )

    key = branch_key(model_name)
    if not key:
        raise ValueError("model_name required")

    now = utc_now_iso()
    prev = _load_session_document(path)
    created_at, prev_vuln = _created_at_prev_vuln_from_document(prev, now=now)
    model_branches: Dict[str, Any] = {}
    top_model = key
    if prev:
        model_branches = _coerce_model_branches(prev.get("model_branches"))
        pm = prev.get("model")
        if isinstance(pm, str) and pm.strip():
            top_model = pm.strip()

    branch = dict(model_branches.get(key) or _default_branch())
    branch["messages"] = list(messages)
    model_branches[key] = branch

    top_model, top_messages = _top_level_model_and_messages_for_branch_save(
        key,
        messages,
        set_as_active=set_as_active,
        top_model_seed=top_model,
        model_branches=model_branches,
    )

    vn = vulnerability_name if isinstance(vulnerability_name, str) else ""
    if not vn and prev_vuln:
        vn = prev_vuln

    rel_store = resolved_report.relative_to(root).as_posix()
    payload: Dict[str, Any] = {
        "schema_version": CHAT_SCHEMA_VERSION,
        "report_relative_path": rel_store,
        "vulnerability_name": vn,
        "session_id": session_id,
        "created_at": created_at,
        "updated_at": now,
        "model": top_model,
        "messages": top_messages,
        "model_branches": model_branches,
    }
    _atomic_write_json(path, payload)


def get_finding_validation_for_branch(
    doc: Optional[Dict[str, Any]],
    model_name: str,
    finding_key: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return stored validation dict for ``model_name`` and ``finding_key`` if present."""
    if not doc or not isinstance(doc, dict):
        return None
    if not isinstance(finding_key, str) or not finding_key.strip():
        return None
    branches = _coerce_model_branches(doc.get("model_branches"))
    b = branches.get(branch_key(model_name))
    if not isinstance(b, dict):
        return None
    fvs = b.get("finding_validations")
    if not isinstance(fvs, dict):
        return None
    fv = fvs.get(finding_key.strip())
    return fv if isinstance(fv, dict) else None


def ensure_session_views(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy with ``model_branches`` coerced and top-level ``messages`` mirroring ``model``."""
    out = dict(doc)
    branches = _coerce_model_branches(out.get("model_branches"))
    out["model_branches"] = branches
    mid = branch_key(str(out.get("model") or ""))
    if mid and mid in branches:
        b = branches[mid]
        if isinstance(b, dict) and isinstance(b.get("messages"), list):
            out["messages"] = list(b["messages"])
    return out


def merge_finding_validation_into_session(
    security_root: Path,
    report_rel: str,
    session_id: str,
    model_name: str,
    validation: Dict[str, Any],
    vulnerability_name: str,
    *,
    finding_key: str,
) -> None:
    """Set ``finding_validations[finding_key]`` for ``model_name``; preserve messages and other keys."""
    if not isinstance(validation, dict):
        raise ValueError("validation must be a dict")
    fk = finding_key.strip() if isinstance(finding_key, str) else ""
    if not fk:
        raise ValueError("finding_key required")
    root, resolved_report, path = _resolve_writable_chat_session_path(
        security_root, report_rel, session_id
    )

    key = branch_key(model_name)
    if not key:
        raise ValueError("model_name required")

    now = utc_now_iso()
    prev = _load_session_document(path)
    created_at, prev_vuln = _created_at_prev_vuln_from_document(prev, now=now)
    model_branches, top_model, top_messages_fb = _branch_context_from_prev_for_validation_merge(
        prev, key=key
    )

    branch = dict(model_branches.get(key) or _default_branch())
    fvs = dict(_coerce_finding_validations_map(branch.get("finding_validations")))
    fvs[fk] = dict(validation)
    branch["finding_validations"] = fvs
    model_branches[key] = branch

    top_messages = _top_messages_reflecting_active_branch(
        model_branches, top_model, fallback=top_messages_fb
    )

    vn = vulnerability_name if isinstance(vulnerability_name, str) else ""
    if not vn and prev_vuln:
        vn = prev_vuln

    rel_store = resolved_report.relative_to(root).as_posix()
    payload: Dict[str, Any] = {
        "schema_version": CHAT_SCHEMA_VERSION,
        "report_relative_path": rel_store,
        "vulnerability_name": vn,
        "session_id": session_id,
        "created_at": created_at,
        "updated_at": now,
        "model": top_model,
        "messages": top_messages,
        "model_branches": model_branches,
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
