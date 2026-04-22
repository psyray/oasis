"""Pure helpers for building dashboard assistant chat context (web.py)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .assistant_rag import json_finding_slice
from .executive_assistant_scope import resolve_aggregate_finding_scope_payload


def resolve_assistant_chat_model(
    data: Dict[str, Any],
    primary_payload: Dict[str, Any],
    aggregate_mode: bool,
    json_paths_for_union: List[Path],
    rag_source_payload: Dict[str, Any],
) -> str:
    """Resolve chat model from request body and report payloads; empty if missing."""
    chat_model = data.get("model")
    if isinstance(chat_model, str) and chat_model.strip():
        return chat_model.strip()

    mn = primary_payload.get("model_name")
    chat_model = mn.strip() if isinstance(mn, str) and mn.strip() else ""
    if not chat_model and aggregate_mode:
        for jp in json_paths_for_union:
            try:
                jd = json.loads(jp.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(jd, dict):
                mnx = jd.get("model_name")
                if isinstance(mnx, str) and mnx.strip():
                    chat_model = mnx.strip()
                    break
    if not chat_model:
        mn2 = rag_source_payload.get("model_name")
        chat_model = mn2.strip() if isinstance(mn2, str) and mn2.strip() else ""
    return chat_model


def json_excerpt_for_assistant_prompt(
    report_payload: Dict[str, Any],
    excerpt_budget: int,
    excerpt_truncated: bool,
) -> Tuple[str, bool]:
    """Serialize report JSON for the system prompt and apply excerpt budget."""
    excerpt = json.dumps(report_payload, ensure_ascii=False)
    if excerpt_budget > 0 and len(excerpt) > excerpt_budget:
        return excerpt[:excerpt_budget] + "\n…(truncated)…", True
    if excerpt_budget <= 0:
        return "", True
    return excerpt, excerpt_truncated


def build_assistant_finding_json_prompt_block(
    *,
    aggregate_mode: bool,
    primary_payload: Dict[str, Any],
    data: Dict[str, Any],
    security_root: Path,
    resolved_report: Path,
    md_obj: Optional[Path],
    fi: int,
    ci: int,
    gi: int,
    finding_max: int,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Build the optional SELECTED_FINDING_JSON block.

    Returns:
        (finding_json, error_message). When error_message is set, the route should
        respond with 400 and that body key ``error``.
    """
    if not aggregate_mode:
        return (
            json_finding_slice(
                primary_payload,
                fi,
                ci,
                gi,
                max_chars=finding_max,
            ),
            None,
        )

    scope_raw = data.get("finding_scope_report_path")
    if isinstance(scope_raw, str) and scope_raw.strip():
        scope_payload, scope_err = resolve_aggregate_finding_scope_payload(
            scope_raw.strip(),
            security_root=security_root,
            executive_report_path=resolved_report,
            model_dir=md_obj,
        )
        if scope_err is not None:
            return None, scope_err
        if scope_payload is not None:
            return (
                json_finding_slice(
                    scope_payload,
                    fi,
                    ci,
                    gi,
                    max_chars=finding_max,
                ),
                None,
            )
    return "", None
