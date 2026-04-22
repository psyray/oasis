"""Compaction of ``FINDING_VALIDATION_JSON`` for chat (lists, ratio fit).

Hard-caps and verdict-first *assembly* live in
:mod:`oasis.helpers.assistant_verdict_assembly`; label-truncation hard cap in
:mod:`oasis.helpers.assistant_prompt_shrink`. Tuning: :mod:`oasis.helpers.assistant_prompt_tuning`.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from oasis.helpers.assistant_prompt_tuning import (
    CHAT_SECTION_TRUNC_SUFFIX,
    CHAT_VALIDATION_LIST_CAPS,
    VALIDATION_EVIDENCE_PREFIX_KEEP,
    VALIDATION_EVIDENCE_PRIORITY,
    VALIDATION_MAX_RATIO,
)

#: Authoritative fields that must always survive any compaction pass, in any
#: order. Used by :func:`_extract_authoritative_subset` and by the hard-cap
#: paths of :func:`_fit_validation_to_budget`.
_VALIDATION_AUTHORITATIVE_KEYS: Tuple[str, ...] = (
    "status",
    "confidence",
    "family",
    "vulnerability_name",
    "summary",
    "scope",
)


def _trunc_marker(omitted: int) -> Dict[str, Any]:
    return {"_truncated": True, "_omitted_count": omitted}


def _drop_empty_collections(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``payload`` without top-level empty list/dict values.

    Pure — does not mutate the input mapping. This matters because callers may
    hand us a shallow copy of validation data whose nested collections still
    alias the caller's dict.
    """
    return {
        key: value
        for key, value in payload.items()
        if not (isinstance(value, (list, dict)) and not value)
    }


def _clip_list(payload: Dict[str, Any], key: str, max_len: int) -> None:
    items = payload.get(key)
    if not isinstance(items, list) or len(items) <= max_len:
        return
    omitted = len(items) - max_len
    payload[key] = list(items[:max_len]) + [_trunc_marker(omitted)]


def compact_validation_for_chat(
    validation: Optional[Dict[str, Any]],
    *,
    list_caps: Optional[Dict[str, int]] = None,
) -> Optional[Dict[str, Any]]:
    """Return a chat-sized copy of ``validation`` with evidence lists clipped.

    This is the chat analogue of ``compact_investigation_for_llm``: it preserves
    the authoritative verdict fields and clips evidence lists to
    :data:`oasis.helpers.assistant_prompt_tuning.CHAT_VALIDATION_LIST_CAPS` (or a
    caller-supplied ``list_caps`` override).
    Empty lists/dicts, the redundant ``schema_version`` and
    ``validation_backend`` fields, and the ``budget_exhausted=False`` flag are
    dropped entirely. The input dict is never mutated.
    """
    if not isinstance(validation, dict):
        return None

    caps = dict(CHAT_VALIDATION_LIST_CAPS if list_caps is None else list_caps)
    payload = dict(validation)

    payload.pop("schema_version", None)
    payload.pop("validation_backend", None)
    payload.pop("narrative_markdown", None)
    payload.pop("synthesis_model", None)
    payload.pop("synthesis_error", None)

    if payload.get("budget_exhausted") is False:
        payload.pop("budget_exhausted", None)
    errors = payload.get("errors")
    if isinstance(errors, list) and not errors:
        payload.pop("errors", None)

    for key, cap in caps.items():
        _clip_list(payload, key, cap)

    return _drop_empty_collections(payload)


def _extract_authoritative_subset(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return only authoritative verdict fields (used for core-only / no-budget path)."""
    return {k: payload[k] for k in _VALIDATION_AUTHORITATIVE_KEYS if k in payload}


def _serialize(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _is_evidence_list_key(key: str) -> bool:
    """Best-effort classifier for evidence-like list keys."""
    if key in VALIDATION_EVIDENCE_PRIORITY:
        return True
    lowered = key.lower()
    return any(
        lowered.endswith(suffix)
        for suffix in (
            "_errors",
            "_error",
            "_citations",
            "_citation",
            "_warnings",
            "_warning",
            "_notes",
            "_note",
        )
    )


def _sort_non_authoritative_keys_for_compaction(
    keys: Iterable[str], payload: Dict[str, Any]
) -> List[str]:
    """Order keys so low-value/non-evidence lists are compacted first."""

    def _priority(key: str) -> Tuple[int, int, str]:
        items = payload.get(key)
        item_count = len(items) if isinstance(items, list) else 0
        return (1 if _is_evidence_list_key(key) else 0, item_count, key)

    return sorted(keys, key=_priority)


def _truncate_list_with_prefix(items: Sequence[Any], keep_prefix: int) -> List[Any]:
    """Keep the first ``keep_prefix`` items plus a truncation marker."""
    if keep_prefix <= 0 or len(items) <= keep_prefix:
        return list(items)
    omitted = max(0, len(items) - keep_prefix)
    return list(items[:keep_prefix]) + [_trunc_marker(omitted)]


def _fit_validation_to_budget(
    validation: Dict[str, Any],
    *,
    max_chars: int,
) -> Tuple[str, Dict[str, Any]]:
    """Shrink validation JSON to fit ``max_chars`` while preserving authoritative keys.

    The compaction preserves :data:`_VALIDATION_AUTHORITATIVE_KEYS` at every
    pass; only non-authoritative evidence lists are ever dropped or halved.
    ``max_chars`` itself is typically derived from
    ``total_budget * VALIDATION_MAX_RATIO`` (see
    :data:`oasis.helpers.assistant_prompt_tuning.VALIDATION_MAX_RATIO`) by
    :func:`oasis.helpers.assistant_verdict_assembly.assemble_verdict_first_prompt` in
    :mod:`oasis.helpers.assistant_verdict_assembly`.
    """
    stats: Dict[str, Any] = {
        "validation_fit_pass": "initial",
        "validation_lists_dropped": [],
    }

    serialized = _serialize(validation)
    if len(serialized) <= max_chars:
        stats["validation_fit_pass"] = "fits_initial"
        return serialized, stats

    payload = dict(validation)
    list_keys_by_size: List[str] = sorted(
        (k for k, v in payload.items() if isinstance(v, list) and len(v) > 1),
        key=lambda k: len(payload[k]),
        reverse=True,
    )
    for key in list_keys_by_size:
        items = payload.get(key)
        if not isinstance(items, list) or len(items) <= 1:
            continue
        halved = max(1, len(items) // 2)
        omitted = len(items) - halved
        payload[key] = list(items[:halved]) + [_trunc_marker(omitted)]
        serialized = _serialize(payload)
        if len(serialized) <= max_chars:
            stats["validation_fit_pass"] = "halved_lists"
            return serialized, stats

    non_authoritative_keys = [
        key for key in list_keys_by_size if key not in _VALIDATION_AUTHORITATIVE_KEYS
    ]
    for key in _sort_non_authoritative_keys_for_compaction(
        non_authoritative_keys, payload
    ):
        if key in _VALIDATION_AUTHORITATIVE_KEYS:
            continue
        if key in payload:
            original_items = payload.get(key)
            if not isinstance(original_items, list):
                continue
            if _is_evidence_list_key(key):
                payload[key] = _truncate_list_with_prefix(
                    original_items, VALIDATION_EVIDENCE_PREFIX_KEEP
                )
            else:
                payload[key] = [_trunc_marker(len(original_items))]
            stats["validation_lists_dropped"].append(key)
            serialized = _serialize(payload)
            if len(serialized) <= max_chars:
                stats["validation_fit_pass"] = "dropped_lists"
                return serialized, stats

    core = _extract_authoritative_subset(validation)
    serialized = _serialize(core)
    if len(serialized) <= max_chars:
        stats["validation_fit_pass"] = "core_only"
        return serialized, stats

    if max_chars <= len(CHAT_SECTION_TRUNC_SUFFIX):
        stats["validation_fit_pass"] = "hard_cap"
        return serialized[:max_chars], stats
    stats["validation_fit_pass"] = "hard_cap"
    return (
        serialized[: max(0, max_chars - len(CHAT_SECTION_TRUNC_SUFFIX))]
        + CHAT_SECTION_TRUNC_SUFFIX
    ), stats


def serialize_finding_validation(validation: Dict[str, Any]) -> str:
    """Compact JSON serialization used inside ``FINDING_VALIDATION_JSON``.

    Legacy helper kept for callers that do not know about the total budget; new code
    should prefer ``compact_validation_for_chat`` followed by ``_fit_validation_to_budget``
    (both invoked by :func:`oasis.helpers.assistant_verdict_assembly.assemble_verdict_first_prompt`).
    """
    return _serialize(validation)
