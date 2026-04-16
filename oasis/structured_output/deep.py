"""
Declarative helpers for ChunkDeepAnalysis structured LLM output.

Centralizes:
- Path-based field normalizers (list -> string, etc.)
- Retry heuristics tied to specific schema locations (e.g. findings.*.exploitation_conditions)
- Shared prompt / retry-suffix text so normalization, retry, and instructions stay aligned.

**Extending path normalizers**

Register at import time (e.g. plugin or ``analyze`` setup). Use ``*`` to map over one list
level. Normalizers should return an equivalent value when no change is needed so diffs
stay small::

    register_chunk_deep_normalizer(
        ("findings", "*", "http_methods"),
        lambda v: "; ".join(v) if isinstance(v, list) else v,
    )

Mutations are applied in place on the parsed dict; do not stash shared mutable defaults
on the callable.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Tuple

# Path tuples: "*" traverses every element of a JSON array at that position.
EXPLOITATION_CONDITIONS_PATH: Tuple[str, ...] = ("findings", "*", "exploitation_conditions")


def _coerce_exploitation_conditions_list(value: Any) -> Any:
    if isinstance(value, list):
        return "; ".join(str(item) for item in value)
    return value


# Declarative registry: extend by adding (path_tuple, normalizer).
# Normalizers at a leaf receive the current value; list coercion helpers expect a list.
CHUNK_DEEP_LIST_FIELD_NORMALIZERS: Dict[Tuple[str, ...], Callable[[Any], Any]] = {
    EXPLOITATION_CONDITIONS_PATH: _coerce_exploitation_conditions_list,
}


def register_chunk_deep_normalizer(
    path: Tuple[str, ...],
    normalizer: Callable[[Any], Any],
) -> None:
    """Register or replace a path-based normalizer (typically list coercion at a leaf)."""
    CHUNK_DEEP_LIST_FIELD_NORMALIZERS[path] = normalizer


def apply_normalizer_by_path(
    payload: Any,
    path: Tuple[str, ...],
    normalizer: Callable[[Any], Any],
) -> bool:
    """
    Walk payload along ``path`` and apply ``normalizer`` at the leaf for each matching node.

    Returns True if any leaf value was changed. Wildcard ``*`` expands one list level.
    """
    if not path:
        return False
    token = path[0]
    remaining = path[1:]
    changed = False

    if token == "*":
        # Wildcard: exactly one list level. Non-list payloads are a silent no-op (registry
        # paths like ``("findings", "*", ...)`` assume ``findings`` is a list of dicts).
        # Non-dict elements in that list are skipped when descending with the remaining path.
        if isinstance(payload, list):
            for item in payload:
                if apply_normalizer_by_path(item, remaining, normalizer):
                    changed = True
        return changed

    if not isinstance(payload, dict) or token not in payload:
        return False

    if not remaining:
        current = payload[token]
        if isinstance(current, list):
            new_val = normalizer(current)
            if new_val != current:
                payload[token] = new_val
                return True
        return False

    return apply_normalizer_by_path(payload[token], remaining, normalizer)


def chunk_deep_normalization_change_samples(
    before: Dict[str, Any],
    after: Dict[str, Any],
    *,
    max_items: int = 5,
) -> List[Dict[str, Any]]:
    """
    Build a small list of ``{path, before, after}`` for finding entries that changed.

    Used for debug logging after in-place normalization (e.g. list→string coercion).
    """
    out: List[Dict[str, Any]] = []
    b_f = before.get("findings")
    a_f = after.get("findings")
    if not isinstance(b_f, list) or not isinstance(a_f, list):
        return out
    for i, (item_b, item_a) in enumerate(zip(b_f, a_f)):
        if len(out) >= max_items:
            break
        if not isinstance(item_b, dict) or not isinstance(item_a, dict):
            continue
        for key in sorted(set(item_b) | set(item_a)):
            if len(out) >= max_items:
                break
            vb, va = item_b.get(key), item_a.get(key)
            if vb != va:
                out.append({"path": f"findings[{i}].{key}", "before": vb, "after": va})
    return out


def normalize_chunk_deep_payload_dict(payload: Dict[str, Any]) -> List[str]:
    """
    Apply all entries in ``CHUNK_DEEP_LIST_FIELD_NORMALIZERS``.

    Returns dotted path labels (for logging) for each rule that changed the payload.
    """
    normalized_fields: List[str] = []
    normalized_fields.extend(
        ".".join(path)
        for path, normalizer in CHUNK_DEEP_LIST_FIELD_NORMALIZERS.items()
        if apply_normalizer_by_path(payload, path, normalizer)
    )
    return normalized_fields


def validation_detail_is_exploitation_conditions_retryable(detail: dict) -> bool:
    """
    True when this ValidationError detail is a known recoverable shape for exploitation_conditions.

    Uses structured ``loc`` / ``type`` / ``msg`` only (not the stringified full error).
    """
    loc = detail.get("loc") or ()
    err_type = str(detail.get("type", ""))
    err_msg = str(detail.get("msg", "")).lower()
    return (
        len(loc) >= 3
        and loc[0] == "findings"
        and isinstance(loc[1], int)
        and loc[2] == EXPLOITATION_CONDITIONS_PATH[-1]
        and (
            "string_type" in err_type
            or "field required" in err_msg
            or "value_error.missing" in err_type
        )
    )


# Compact rules shared in meaning with ``chunk_deep_prompt_output_constraint_block`` (keep both aligned).
CHUNK_DEEP_SCHEMA_TYPE_RULES_COMPACT = (
    "Respect schema types (string fields as JSON strings, never arrays/objects); "
    "exploitation_conditions must be one string sentence, not a list; "
    "use \\n and \\\" inside strings as needed; "
    "if uncertain return "
    '{"findings": [], "notes": "Unable to produce confident structured output", '
    '"validation_error": true, "potential_vulnerabilities": true, "truncated": false}; '
    "only standard JSON string escapes (\\\\ \\\" \\/ \\b \\f \\n \\r \\t \\uXXXX); "
    "no markdown fences in values; the response must end at the root object's closing `}`.\n"
)


def _shared_structured_retry_body() -> str:
    """Lines shared by generic and ChunkDeepAnalysis retry suffixes."""
    return (
        "Return valid JSON only (single object matching the required schema).\n"
        "Do NOT use markdown code fences.\n"
        "Return compact JSON with no explanations, no repeated filler tokens, and no trailing commentary.\n"
        "Ensure every quote/bracket is closed and output ends with the final '}' of the JSON object.\n"
        + CHUNK_DEEP_SCHEMA_TYPE_RULES_COMPACT
        + "Never include raw multi-line code with unescaped quotes in JSON string fields.\n"
    )


def generic_structured_retry_suffix() -> str:
    """Retry reminder for non-ChunkDeepAnalysis structured models (e.g. MediumRiskAnalysis)."""
    return "\n\nCORRECTION: " + _shared_structured_retry_body()


def chunk_deep_structured_retry_suffix() -> str:
    """Retry reminder including ChunkDeepAnalysis-specific field typing (exploitation_conditions)."""
    return (
        "\n\nCORRECTION: "
        + _shared_structured_retry_body()
        + "Example: exploitation_conditions must be a single string, not a list.\n"
    )


def chunk_deep_prompt_output_constraint_block() -> str:
    """
    Bullet block for the \"Output constraints\" section of deep structured instructions.

    Keep in sync with ``CHUNK_DEEP_SCHEMA_TYPE_RULES_COMPACT`` and ``chunk_deep_structured_retry_suffix``.
    """
    # Detailed bullets for the model; typing intent matches CHUNK_DEEP_SCHEMA_TYPE_RULES_COMPACT.
    return """Output constraints (strict):
- Return JSON ONLY, exactly one object, no prose before or after.
- Keep values concise to avoid truncation; prioritize complete valid JSON over verbosity.
- Never repeat filler tokens (e.g. "the the the"), and never emit partial or unfinished strings.
- Ensure the response ends with a fully closed JSON object (`}` as appropriate).
- Follow field types exactly as defined in the schema.
- If a schema field is type string, output a single string value, never an array or object.
- exploitation_conditions MUST be a single string sentence (not list).
- Keep `secure_code_example` short (max 5 lines) and escape line breaks as `\\n` inside JSON.
- Escape any `\\"` characters inside string values; never emit raw unescaped `"` inside a JSON string.
- Avoid long prose in `notes`; keep one short sentence (max 20 words).
- Do not include markdown fences, backticks, or pseudo-JSON fragments inside any field value.
- Do NOT include markdown code fences (``` or similar) anywhere inside field values.
- The last character of the entire response must be the root object's closing `}`; no trailing text.
- Inside strings use only valid JSON escapes; do not emit `\\x`, `\\'`, or invalid `\\` + letter sequences (use `\\\\` for a literal backslash).
- If you are genuinely uncertain or the context is too ambiguous to populate fields confidently, return a minimal object like {"findings": [], "notes": "Unable to produce confident structured output", "validation_error": true, "potential_vulnerabilities": true, "truncated": false}."""
