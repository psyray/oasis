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
- The user finding is anchored on `scope_focus.sink_file:scope_focus.sink_line` when present. Always state this anchor explicitly; do not silently shift the discussion to a different file.
- Explain what the evidence implies in plain language. When citing code, use only paths and line numbers that appear in the JSON (path:line format).
- If `entry_points` is empty or none cover `scope_focus.sink_file`, do NOT suggest exploitation chains the JSON does not support. Frame any unrelated entry points as ambient observations, not as the attack vector.
- For `family == "access"`, prioritize `control_checks` and `authz_checks`; do NOT introduce routes outside `scope_focus.sink_file` as the primary attack vector.
- If you cannot deterministically link the sink to a source/control using the provided JSON, declare the gap (insufficient signal) instead of speculating.
- If evidence is thin or the tool reported errors/budget exhaustion, say what is missing instead of inventing details.
- Do not fabricate file paths, line numbers, frameworks, route names, or call chains not present in the JSON.
"""


def _normalize_temperature(value: Any, *, fallback: float = 0.2) -> float:
    """Normalize synthesis temperature once with a defensive fallback."""
    try:
        normalized = float(value)
    except (TypeError, ValueError):
        logger.warning(
            "Invalid assistant synthesis temperature=%r; falling back to %s",
            value,
            fallback,
        )
        normalized = fallback

    clamped = max(0.0, min(1.0, normalized))
    if clamped != normalized:
        logger.warning(
            "Assistant synthesis temperature out of range (%s); clamping to %s",
            normalized,
            clamped,
        )
    return clamped


def _trunc_marker(omitted: int) -> Dict[str, Any]:
    return {"_truncated": True, "_omitted_count": omitted}


def _build_scope_focus(result: AssistantInvestigationResult) -> Dict[str, Any]:
    """Highlight the sink anchor + verdict so the LLM cannot drift to other files."""
    focus: Dict[str, Any] = {
        "vulnerability_name": result.vulnerability_name,
        "family": result.family,
        "verdict_status": result.status,
        "verdict_confidence": float(result.confidence),
    }
    if result.scope is not None:
        if result.scope.sink_file:
            focus["sink_file"] = result.scope.sink_file
        if result.scope.sink_line is not None:
            focus["sink_line"] = result.scope.sink_line
        if result.scope.scan_root:
            focus["scan_root"] = result.scope.scan_root
    return focus


def compact_investigation_for_llm(result: AssistantInvestigationResult) -> Dict[str, Any]:
    """Build a size-bounded dict suitable for the synthesis prompt."""
    raw = result.model_dump(mode="json")
    # Guard against collisions: ``scope_focus`` is computed by OASIS and must
    # never be overridden by a same-named key from ``model_dump``. If the
    # serialized payload ever exposes one (schema drift), surface it via a
    # WARNING log so the discrepancy is visible — but keep the assistant
    # resilient by always letting the locally computed value win below.
    if "scope_focus" in raw:
        logger.warning(
            "Assistant schema drift detected: AssistantInvestigationResult.model_dump() "
            "now exposes a 'scope_focus' key; the locally computed scope_focus from "
            "_build_scope_focus supersedes the dumped value to keep the LLM payload anchored."
        )
        raw.pop("scope_focus", None)
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

    # Place ``scope_focus`` first so the LLM hits it before walking the (possibly
    # noisy) evidence buckets — the system prompt above explicitly references it.
    return {"scope_focus": _build_scope_focus(result), **raw}


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

    normalized_temperature = _normalize_temperature(temperature, fallback=0.2)
    messages = build_synthesis_messages(result, max_context_chars=max_context_chars)
    if _oasis_log.isEnabledFor(logging.DEBUG):
        _oasis_log.debug(
            "[assistant_llm] POST /api/assistant/investigate synthesize ollama_request\n%s",
            json.dumps(
                {
                    "model": model,
                    "options": {"temperature": normalized_temperature},
                    "messages": messages,
                },
                ensure_ascii=False,
                indent=2,
            ),
        )
    try:
        resp = ollama_manager.chat(
            model, messages, options={"temperature": normalized_temperature}
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
    raw = msg.get("content") or "" if isinstance(msg, dict) else ""
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
