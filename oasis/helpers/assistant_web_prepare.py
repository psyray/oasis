"""Pure helpers for building dashboard assistant chat context (web.py).

These functions cover the steps that happen *before* the final system-prompt
assembly (see :func:`oasis.helpers.assistant_chat_context.assemble_verdict_first_prompt`):

- Resolving paths and payloads for single-report and executive-aggregate modes.
- Picking the chat model.
- Slicing the selected finding JSON.
- Building the payload that feeds the compact report summary.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .assistant_http_contract import (
    ERR_AGGREGATE_MODEL_DIR,
    ERR_NO_JSON_REPORTS_AGGREGATE,
    HTTP_BAD_REQUEST,
    HTTP_NOT_FOUND,
    JsonErr,
    assistant_http_error,
)
from .assistant_rag import json_finding_slice
from .assistant_scan_aggregate import (
    build_aggregate_assistant_document,
    first_vulnerability_payload_from_paths,
    iter_json_report_paths_in_model_dir,
    model_directory_from_security_report_file,
    union_file_paths_from_vulnerability_payloads,
)
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


def prepare_aggregate_branch_paths(
    security_root: Path,
    resolved_report: Path,
    primary_payload: Dict[str, Any],
) -> Tuple[Optional[Path], List[Path], Dict[str, Any], Optional[List[str]], Optional[JsonErr]]:
    """Resolve model dir and JSON paths for executive aggregate assistant mode."""
    md_obj = model_directory_from_security_report_file(security_root, resolved_report)
    if md_obj is None:
        return (
            None,
            [],
            primary_payload,
            None,
            assistant_http_error(ERR_AGGREGATE_MODEL_DIR, HTTP_BAD_REQUEST),
        )
    json_paths = iter_json_report_paths_in_model_dir(md_obj)
    if not json_paths:
        return (
            None,
            [],
            primary_payload,
            None,
            assistant_http_error(ERR_NO_JSON_REPORTS_AGGREGATE, HTTP_NOT_FOUND),
        )
    vp = first_vulnerability_payload_from_paths(json_paths)
    rag_source = vp if vp is not None else primary_payload
    extra = union_file_paths_from_vulnerability_payloads(json_paths)
    return md_obj, json_paths, rag_source, extra, None


def build_report_summary_payload(
    *,
    aggregate_mode: bool,
    json_paths_for_union: List[Path],
    security_root: Path,
    primary_payload: Dict[str, Any],
    aggregate_char_budget: int,
) -> Tuple[Dict[str, Any], bool]:
    """
    Return the dict to feed into :func:`compact_report_excerpt`.

    In aggregate mode, merges per-model canonical JSON reports into one
    assistant-facing document (``assistant_aggregate=True``). ``aggregate_char_budget``
    is the merge-phase cap (web passes ``report_summary subbudget`` ×
    :data:`oasis.helpers.assistant_prompt_tuning.REPORT_SUMMARY_AGGREGATE_MERGE_BUDGET_FACTOR`);
    the string shown in the system prompt is then capped separately by
    :func:`compact_report_excerpt` to the *actual* subbudget. Otherwise returns
    the primary report payload untouched. The boolean is ``True`` when the
    aggregate document had to truncate per-file payloads.
    """
    if aggregate_mode:
        report_payload, agg_meta = build_aggregate_assistant_document(
            json_paths_for_union,
            security_root,
            total_char_budget=max(0, int(aggregate_char_budget)),
        )
        return report_payload, bool(agg_meta.get("truncated"))
    return primary_payload, False


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


def full_messages_from_system_and_dialogue(
    system_content: str,
    messages: List[Dict[str, Any]],
) -> List[Dict[str, str]]:
    """Build Ollama ``messages`` list with a single system message plus dialogue turns."""
    full_messages: List[Dict[str, str]] = [{"role": "system", "content": system_content}]
    for m in messages:
        role = str(m.get("role", ""))
        content = m.get("content", "")
        if isinstance(content, str):
            full_messages.append({"role": role, "content": content})
    return full_messages


def extract_last_user_message_text(messages: List[Dict[str, Any]]) -> str:
    """Return the most recent user message content, or empty string."""
    for m in reversed(messages):
        if isinstance(m, dict) and m.get("role") == "user":
            c = m.get("content", "")
            return c if isinstance(c, str) else ""
    return ""
