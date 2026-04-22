"""LLM narrative layer for assistant finding validation.

The deterministic LangGraph produces :class:`AssistantInvestigationResult`.
This module optionally asks a chat model to turn that structured verdict into
developer-facing Markdown. The model must **not** override ``status``,
``confidence``, ``family``, or ``summary`` — it only elaborates on the evidence.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from .think_parse import parse_assistant_think
from oasis.ollama_manager import OllamaManager
from oasis.schemas.analysis import AssistantInvestigationResult

logger = logging.getLogger(__name__)
_oasis_log = logging.getLogger("oasis")

_MAX_ENTRY_POINTS = 15
_MAX_PATHS = 8
_MAX_FLOWS = 8
_MAX_MITIGATIONS = 12
_MAX_AUTHZ = 12
_MAX_CONTROLS = 12
_MAX_CONFIG = 24
_MAX_CITATIONS = 28
_MAX_ERRORS = 8

_DEFAULT_CONTEXT_CAP = 16_000
_MAX_USER_MESSAGE_CHARS = 18_000

_SYSTEM_PROMPT = """You are a security analyst assisting OASIS dashboard users.

You receive JSON from a deterministic static-analysis validation run (entry points, paths, controls, config hits, verdict).

Rules (strict):
- Treat fields "status", "confidence", "family", "vulnerability_name", and "summary" as authoritative. Do NOT contradict them or propose a different verdict label.
- Output Markdown only (no JSON). Aim for 3–6 short paragraphs plus optional bullet lists.
- Explain what the evidence implies in plain language. When citing code, use only paths and line numbers that appear in the JSON (path:line format).
- If evidence is thin or the tool reported errors/budget exhaustion, say what is missing instead of inventing details.
- Do not fabricate file paths, line numbers, or frameworks not present in the JSON.
"""


def _trunc_marker(omitted: int) -> Dict[str, Any]:
    return {"_truncated": True, "_omitted_count": omitted}


def compact_investigation_for_llm(result: AssistantInvestigationResult) -> Dict[str, Any]:
    """Build a size-bounded dict suitable for the synthesis prompt."""
    raw = result.model_dump(mode="json")
    raw.pop("narrative_markdown", None)
    raw.pop("synthesis_model", None)
    raw.pop("synthesis_error", None)

    def clip_list(key: str, max_len: int) -> None:
        items = raw.get(key)
        if not isinstance(items, list) or len(items) <= max_len:
            return
        omitted = len(items) - max_len
        raw[key] = list(items[:max_len]) + [_trunc_marker(omitted)]

    clip_list("entry_points", _MAX_ENTRY_POINTS)
    clip_list("execution_paths", _MAX_PATHS)
    clip_list("taint_flows", _MAX_FLOWS)
    clip_list("mitigations", _MAX_MITIGATIONS)
    clip_list("authz_checks", _MAX_AUTHZ)
    clip_list("control_checks", _MAX_CONTROLS)
    clip_list("config_findings", _MAX_CONFIG)
    clip_list("citations", _MAX_CITATIONS)
    clip_list("errors", _MAX_ERRORS)
    return raw


def build_synthesis_messages(
    result: AssistantInvestigationResult,
    *,
    max_context_chars: int = _DEFAULT_CONTEXT_CAP,
) -> List[Dict[str, str]]:
    """Return Ollama ``messages`` for narrative synthesis."""
    payload = compact_investigation_for_llm(result)
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    if max_context_chars > 0 and len(body) > max_context_chars:
        body = body[:max_context_chars] + "\n…(truncated)…"
    user_text = (
        "VALIDATION_JSON (deterministic tool output — do not override verdict fields):\n\n" + body
    )
    if len(user_text) > _MAX_USER_MESSAGE_CHARS:
        user_text = user_text[:_MAX_USER_MESSAGE_CHARS] + "\n…(truncated)…"
    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_text},
    ]


def enrich_investigation_with_llm_narrative(
    result: AssistantInvestigationResult,
    *,
    ollama_manager: OllamaManager,
    chat_model: str,
    max_context_chars: int = _DEFAULT_CONTEXT_CAP,
    temperature: float = 0.2,
) -> AssistantInvestigationResult:
    """Return a copy of ``result`` with ``narrative_markdown`` filled when successful."""
    model = (chat_model or "").strip()
    if not model:
        return result

    messages = build_synthesis_messages(result, max_context_chars=max_context_chars)
    if _oasis_log.isEnabledFor(logging.DEBUG):
        _oasis_log.debug(
            "[assistant_llm] POST /api/assistant/investigate synthesize ollama_request\n%s",
            json.dumps(
                {
                    "model": model,
                    "options": {"temperature": float(temperature)},
                    "messages": messages,
                },
                ensure_ascii=False,
                indent=2,
            ),
        )
    try:
        resp = ollama_manager.chat(
            model,
            messages,
            options={"temperature": float(temperature)},
        )
    except Exception as exc:
        logger.warning(
            "Investigation narrative LLM call failed model=%s err=%s",
            model,
            type(exc).__name__,
            exc_info=True,
        )
        return result.model_copy(
            update={
                "synthesis_error": f"{type(exc).__name__}: {exc}",
            }
        )

    if _oasis_log.isEnabledFor(logging.DEBUG):
        _oasis_log.debug(
            "[assistant_llm] POST /api/assistant/investigate synthesize ollama_response\n%s",
            json.dumps({"raw": resp}, ensure_ascii=False, indent=2, default=str),
        )

    msg = resp.get("message") if isinstance(resp, dict) else None
    raw = ""
    if isinstance(msg, dict):
        raw = msg.get("content") or ""
    if not isinstance(raw, str):
        raw = ""
    split = parse_assistant_think(raw)
    narrative = (split.visible_markdown or raw).strip()
    return result.model_copy(
        update={
            "narrative_markdown": narrative,
            "synthesis_model": model,
            "synthesis_error": None,
        }
    )
