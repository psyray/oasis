"""Resolve model-directory paths and build scan-wide assistant aggregate JSON excerpts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from oasis.helpers.path_containment import is_path_within_root
from oasis.report import is_executive_summary_progress_sidecar

_REPORT_FORMAT_DIRS = frozenset({"md", "json", "html", "pdf", "sarif"})


def model_directory_from_security_report_file(security_root: Path, report_file: Path) -> Optional[Path]:
    """Return ``.../timestamp/embed_model`` given ``.../timestamp/embed_model/md/x.md`` or ``.../json/x.json``."""
    try:
        rf = report_file.resolve()
        sec = security_root.resolve()
        if not is_path_within_root(rf, sec):
            return None
    except OSError:
        return None
    parent = rf.parent
    key = parent.name.lower()
    if key not in _REPORT_FORMAT_DIRS:
        return None
    model_dir = parent.parent
    if model_dir == sec:
        return None
    return model_dir


def iter_json_report_paths_in_model_dir(model_dir: Path) -> List[Path]:
    """Sorted JSON canonical files under ``model_dir/json``, excluding progress sidecars."""
    jdir = model_dir / "json"
    if not jdir.is_dir():
        return []
    out: List[Path] = []
    for p in sorted(jdir.glob("*.json")):
        if not p.is_file():
            continue
        if is_executive_summary_progress_sidecar(p):
            continue
        out.append(p)
    return out


def union_file_paths_from_vulnerability_payloads(paths: Sequence[Path]) -> List[str]:
    """Collect unique ``file_path`` strings from canonical vulnerability JSON payloads."""
    seen: set[str] = set()
    ordered: List[str] = []
    for p in paths:
        try:
            text = p.read_text(encoding="utf-8")
            data = json.loads(text)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        if str(data.get("report_type") or "") != "vulnerability":
            continue
        files = data.get("files") or []
        if not isinstance(files, list):
            continue
        for entry in files:
            if not isinstance(entry, dict):
                continue
            fp = entry.get("file_path")
            if isinstance(fp, str) and fp.strip():
                key = fp.strip()
                if key not in seen:
                    seen.add(key)
                    ordered.append(key)
    return ordered


def security_relative_posix(path: Path, security_root: Path) -> str:
    try:
        return str(path.relative_to(security_root)).replace("\\", "/")
    except ValueError:
        return path.name


_TRUNCATION_SUFFIX = "\n…(truncated)…"


def _fit_payload_json_to_char_budget(raw_stripped: str, max_len: int) -> Tuple[str, bool]:
    """Return ``payload_json`` text of at most ``max_len`` characters; second value is whether raw was truncated."""
    if max_len <= 0:
        return "", True
    if len(raw_stripped) <= max_len:
        return raw_stripped, False
    suf = _TRUNCATION_SUFFIX
    if max_len <= len(suf):
        return raw_stripped[:max_len], True
    prefix_len = max_len - len(suf)
    return raw_stripped[:prefix_len] + suf, True


def build_aggregate_assistant_document(
    paths: Sequence[Path],
    security_root: Path,
    *,
    total_char_budget: int,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Merge multiple report JSON files into one assistant-facing document with per-file truncation.

    Returns ``(aggregate_dict, meta)`` where meta includes truncation flags and file list.
    """
    meta: Dict[str, Any] = {"files_included": [], "truncated": False, "per_file_truncated": []}
    paths_list = [p for p in paths if p.is_file()]
    if not paths_list:
        return (
            {
                "schema_version": 1,
                "assistant_aggregate": True,
                "segments": [],
                "included_relative_paths": [],
            },
            meta,
        )

    remaining = max(0, int(total_char_budget))
    wrapper_estimate = 256 + len(paths_list) * 64
    remaining = max(0, remaining - wrapper_estimate)

    segments: List[Dict[str, Any]] = []

    for idx, path in enumerate(paths_list):
        rel = security_relative_posix(path, security_root)
        n_rest = len(paths_list) - idx
        share = remaining // n_rest if n_rest > 0 else 0
        budget = min(share, remaining)
        if budget <= 0:
            meta["truncated"] = True
            continue
        try:
            raw_json = path.read_text(encoding="utf-8")
        except OSError:
            continue
        body, truncated_file = _fit_payload_json_to_char_budget(raw_json.strip(), budget)
        if truncated_file:
            meta["truncated"] = True
            meta["per_file_truncated"].append(rel)

        segments.append({"relative_path": rel, "payload_json": body})
        meta["files_included"].append(rel)
        remaining -= len(body)
        if remaining <= 0:
            meta["truncated"] = True

    aggregate: Dict[str, Any] = {
        "schema_version": 1,
        "assistant_aggregate": True,
        "segments": segments,
        "included_relative_paths": meta["files_included"],
    }
    return aggregate, meta


def resolve_canonical_json_for_markdown_report(md_path: Path) -> Optional[Path]:
    """Sibling ``json/<stem>.json`` for ``md/<stem>.md`` (canonical dashboard reports)."""
    if md_path.suffix.lower() != ".md":
        return None
    json_dir = md_path.parent.parent / "json"
    candidate = json_dir / f"{md_path.stem}.json"
    return candidate if candidate.is_file() else None


def first_vulnerability_payload_from_paths(paths: Sequence[Path]) -> Optional[Dict[str, Any]]:
    """Load the first canonical vulnerability JSON dict from paths (for RAG embed / analysis_root)."""
    for p in paths:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and str(data.get("report_type") or "") == "vulnerability":
            return data
    return None
