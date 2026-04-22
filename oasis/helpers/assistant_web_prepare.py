"""Pure helpers for building dashboard assistant chat context (web.py)."""

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

# Finding JSON block sizing: must stay aligned with ``build_assistant_prompt_core`` layout
# (excerpt, then ``\\n\\nSELECTED_FINDING_JSON:\\n``, then the finding body).
ASSISTANT_FINDING_PROMPT_SECTION_HEADER = "\n\nSELECTED_FINDING_JSON:\n"
ASSISTANT_FINDING_JSON_BODY_MAX_CHARS = 12_000
ASSISTANT_FINDING_JSON_BUDGET_BUFFER_CHARS = 200


def compute_assistant_finding_json_max_chars(
    *,
    total_budget: int,
    system_intro_prefix_len: int,
    excerpt_len: int,
) -> int:
    """Char budget for ``json_finding_slice`` given total system prompt budget."""
    used_after_excerpt = system_intro_prefix_len + excerpt_len
    remaining_for_prompt = max(0, total_budget - used_after_excerpt)
    finding_header_len = len(ASSISTANT_FINDING_PROMPT_SECTION_HEADER)
    finding_budget = (
        remaining_for_prompt
        - finding_header_len
        - ASSISTANT_FINDING_JSON_BUDGET_BUFFER_CHARS
    )
    return max(0, min(ASSISTANT_FINDING_JSON_BODY_MAX_CHARS, finding_budget))


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


def build_report_excerpt_for_chat_context(
    *,
    aggregate_mode: bool,
    json_paths_for_union: List[Path],
    security_root: Path,
    primary_payload: Dict[str, Any],
    excerpt_budget: int,
    excerpt_truncated: bool,
) -> Tuple[str, bool]:
    """Build JSON excerpt string and truncation flag for the system prompt."""
    if aggregate_mode:
        report_payload, agg_meta = build_aggregate_assistant_document(
            json_paths_for_union,
            security_root,
            total_char_budget=excerpt_budget,
        )
        excerpt_truncated = excerpt_truncated or bool(agg_meta.get("truncated"))
    else:
        report_payload = primary_payload
    return json_excerpt_for_assistant_prompt(
        report_payload,
        excerpt_budget,
        excerpt_truncated,
    )


def build_assistant_prompt_core(
    system_intro_prefix: str,
    excerpt: str,
    finding_json: str,
) -> str:
    """Assemble prompt text up to (optional) finding JSON slice."""
    chunks: List[str] = [system_intro_prefix + excerpt]
    if finding_json:
        chunks.extend(["", "SELECTED_FINDING_JSON:", finding_json])
    return "\n".join(chunks)


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


def apply_user_finding_labels_to_system_content(
    core_so_far: str,
    labels_note: Any,
    total_budget: int,
) -> str:
    """Append capped user triage notes when present."""
    labels_header = "\n\nUSER_LOCAL_TRIAGE_NOTES:\n"
    labels_cap = max(0, total_budget - len(core_so_far) - len(labels_header))
    system_content = core_so_far
    if isinstance(labels_note, str) and labels_note.strip():
        note = labels_note.strip()
        if labels_cap > 0 and len(note) > labels_cap:
            note = note[:labels_cap] + "\n…(truncated)…"
        elif labels_cap <= 0:
            note = ""
        if note:
            system_content = core_so_far + "\n\nUSER_LOCAL_TRIAGE_NOTES:\n" + note
    return system_content


def truncate_system_prompt_to_char_budget(system_content: str, total_budget: int) -> str:
    """Hard-cap system prompt length."""
    if len(system_content) <= total_budget:
        return system_content
    return system_content[:total_budget] + "\n…(truncated)…"


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
