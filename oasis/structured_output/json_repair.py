"""
Low-level JSON repair for ChunkDeepAnalysis model output only.

``SecurityAnalyzer`` delegates here so orchestration stays separate from string parsing.
All public entry points assume the caller already verified ``ChunkDeepAnalysis`` intent.

**Pipeline (``repair_chunk_deep_structured_json_raw``)**

1. ``strip_code_fences`` — outer markdown wrapper only (opening line + one trailing fence).
2. ``strip_control_chars`` — remove illegal C0 controls.
3. ``extract_first_json_object_candidate`` — drop preamble before the first ``{``.
4. ``decode_chunk_deep_json_object`` — fast path when the buffer is already valid JSON.
5. ``apply_structured_json_repair_steps`` — balance ``{``/``[`` (see ``json_repair_scan``), strip
   trailing commas (same submodule).
6. ``decode_chunk_deep_json_object`` again on the repaired string.
7. ``fix_invalid_json_string_escapes`` (``json_repair_scan``) — fix invalid ``\\`` sequences inside strings.
8. ``build_safe_minimal_chunk_json`` — last-resort empty findings + notes, or return best-effort text.

Character-level scanners live in ``json_repair_scan`` (state machines, ASCII sketches there).
"""

from __future__ import annotations

import json
import re
from contextlib import suppress
from typing import Any, Dict, Optional

from .json_repair_scan import (
    fix_invalid_json_string_escapes,
    scan_open_delimiter_stack_outside_strings,
    strip_trailing_commas_outside_strings,
)
from ..tools import logger


def strip_code_fences(candidate: str) -> str:
    """
    Strip an outer markdown fence only when the opening line is a fence line (optionally ``json``).

    Inline backticks on the same line as content are not treated as opening fences.

    The closing fence is removed **at most once** and only when it appears at the **very
    end** of the buffer (after the opening line was stripped). We do not scan for ``^`````
    on every line, because a JSON string value may legally contain a newline followed by
    `` ``` `` at column zero (e.g. embedded markdown examples).
    """
    if not candidate.startswith("```"):
        return candidate
    # Opening: first line of the buffer only (no MULTILINE — avoids matching inner lines).
    candidate = re.sub(
        r"^```(?:json)?[ \t]*\r?\n",
        "",
        candidate,
        count=1,
        flags=re.IGNORECASE,
    )
    # Closing: one trailing fence line only (not every ```-only line in the payload).
    candidate = re.sub(r"\r?\n?```\s*$", "", candidate, count=1)
    return candidate


def strip_control_chars(candidate: str) -> str:
    """Remove C0 control characters except tab/newline, which often break ``json.loads``."""
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", candidate)


def extract_first_json_object_candidate(candidate: str) -> str:
    """Drop leading non-JSON noise before the first ``{`` (e.g. model preamble text)."""
    first_obj = candidate.find("{")
    return candidate[first_obj:] if first_obj > 0 else candidate


def _delimiter_structural_failure_fallback(candidate: str) -> str:
    """
    When delimiter scanning finds an impossible structure, avoid appending bogus closers.

    Prefer a minimal valid ChunkDeepAnalysis-shaped payload when ``findings`` is present;
    otherwise return ``candidate`` unchanged for later repair stages.

    Example: ``{]`` would parse as balanced if we naively appended ``}``; we instead
    emit safe-minimal when ``"findings"`` is present so downstream validation stays honest.
    """
    minimal = build_safe_minimal_chunk_json(candidate)
    return minimal if minimal is not None else candidate


def balance_json_delimiters_outside_strings(candidate: str) -> str:
    """
    Append missing closing ``}`` / ``]`` only when ``scan_open_delimiter_stack_outside_strings``
    reports a consistent open stack.

    If the scan returns ``None``, we do **not** append artificial closers: that can yield
    syntactically valid but misleading JSON. In those cases we fall back to
    ``build_safe_minimal_chunk_json`` when possible.

    Assumptions and limits:
    - Treats ``"`` as string delimiter only; does not support JSON5 single-quoted strings.
    - Escape handling is limited to ``\\`` before ``"`` inside strings (standard JSON escaping).
      Malformed escape sequences can still desynchronize the in-string state.
    - Best-effort for *truncated* output with consistent open containers left on the stack.
    """
    stack = scan_open_delimiter_stack_outside_strings(candidate)
    if stack is None:
        # e.g. ``{]``, extra ``}``, or ``{"k":"`` — appending ``}`` would hide the real failure.
        return _delimiter_structural_failure_fallback(candidate)
    suffix = "".join("}" if op == "{" else "]" for op in reversed(stack))
    return candidate + suffix


def apply_structured_json_repair_steps(candidate: str) -> str:
    """
    Run structural repairs: balance delimiters, then strip trailing commas.

    Order matters: balancing first can expose comma issues before closers.
    """
    candidate = balance_json_delimiters_outside_strings(candidate)
    candidate = strip_trailing_commas_outside_strings(candidate)
    return candidate


def decode_chunk_deep_json_object(candidate: str) -> Optional[Dict[str, Any]]:
    """
    Parse the first JSON object from ``candidate``.

    Uses ``json.loads`` when the full buffer is valid, otherwise ``JSONDecoder.raw_decode``
    to drop trailing garbage (common LLM failure: valid object + extra prose).
    """
    if not candidate.strip():
        return None
    with suppress(json.JSONDecodeError, TypeError, ValueError):
        obj = json.loads(candidate)
        if isinstance(obj, dict):
            return obj
    decoder = json.JSONDecoder()
    with suppress(json.JSONDecodeError, TypeError, ValueError):
        obj, _end = decoder.raw_decode(candidate.strip())
        if isinstance(obj, dict):
            return obj
    return None


def build_safe_minimal_chunk_json(raw: str) -> Optional[str]:
    """
    Build a safe minimal ChunkDeepAnalysis payload when repair cannot recover.

    ``notes`` extraction order:
    1. ``decode_chunk_deep_json_object(raw)`` — first object + tolerates trailing noise.
    2. ``json.loads(raw)`` — full-document parse when the buffer is valid JSON.
    3. Regex ``"notes"\\s*:\\s*"([^"]*)"`` — last resort on broken syntax; may truncate
       if the value contains an unescaped ``"`` (rare on this failure path).
    """
    if not re.search(r'"findings"\s*:', raw):
        return None

    notes_source: Optional[str] = None
    decoded = decode_chunk_deep_json_object(raw)
    if isinstance(decoded, dict):
        n = decoded.get("notes")
        if isinstance(n, str):
            notes_source = n
    if notes_source is None:
        with suppress(json.JSONDecodeError, TypeError, ValueError):
            loaded = json.loads(raw.strip())
            if isinstance(loaded, dict):
                n = loaded.get("notes")
                if isinstance(n, str):
                    notes_source = n
    if notes_source is None:
        if note_match := re.search(r'"notes"\s*:\s*"([^"]*)"', raw, flags=re.DOTALL):
            notes_source = note_match[1]

    notes = "Model returned malformed JSON; findings omitted."
    if isinstance(notes_source, str):
        extracted = notes_source.strip().replace("\n", " ").replace("\r", " ")
        if extracted := re.sub(r"\s+", " ", extracted):
            notes = extracted[:220]

    payload = {
        "findings": [],
        "notes": notes,
        "validation_error": True,
        "potential_vulnerabilities": True,
        "truncated": True,
    }
    return json.dumps(payload)


def repair_chunk_deep_structured_json_raw(raw: str, *, model_display: str) -> str:
    """
    Repair malformed JSON intended for ``ChunkDeepAnalysis``.

    Caller must ensure this path is only used for ChunkDeepAnalysis outputs.

    Preserves progressive cleanup in the returned string when possible: if no parseable
    object and safe-minimal cannot be built, returns the best-effort repaired string
    (fence/control-char stripped, balanced, escape-fixed) rather than the original ``raw``.
    """
    if not raw:
        return raw

    original_raw = raw
    candidate = strip_code_fences(raw.strip())
    candidate = strip_control_chars(candidate)
    candidate = extract_first_json_object_candidate(candidate)

    def dump_normalized(obj: Dict[str, Any]) -> str:
        return json.dumps(obj, ensure_ascii=False)

    decoded = decode_chunk_deep_json_object(candidate)
    if decoded is not None:
        if candidate != raw.strip():
            logger.debug("Applied light JSON cleanup for deep structured output (%s)", model_display)
        return dump_normalized(decoded)

    repaired = apply_structured_json_repair_steps(candidate)
    decoded = decode_chunk_deep_json_object(repaired)
    if decoded is not None:
        logger.debug("Applied JSON repair heuristics for deep structured output (%s)", model_display)
        return dump_normalized(decoded)

    escaped = fix_invalid_json_string_escapes(repaired)
    if escaped != repaired:
        decoded = decode_chunk_deep_json_object(escaped)
        if decoded is not None:
            logger.debug(
                "Applied invalid-escape fix for deep structured output (%s)",
                model_display,
            )
            return dump_normalized(decoded)

    # Prefer a minimal valid object when we see ``"findings"`` (ChunkDeep-shaped garbage).
    safe_minimal = build_safe_minimal_chunk_json(repaired)
    if safe_minimal is None:
        safe_minimal = build_safe_minimal_chunk_json(escaped)
    if safe_minimal is None:
        # No ``"findings"`` hint: synthetic minimal would be misleading; return the most
        # repaired buffer we have (fences/controls stripped, balance/escapes attempted)
        # so logs and any downstream retry still see progress vs. raw model output.
        best_effort = escaped if escaped != repaired else repaired
        if best_effort and best_effort != original_raw.strip():
            logger.debug(
                "Deep JSON repair returning best-effort string (no safe-minimal) (%s)",
                model_display,
            )
            return best_effort
        return original_raw

    # Parsed object still invalid but buffer looked like a chunk report: empty findings
    # + extracted notes beats failing the whole chunk (see ``build_safe_minimal_chunk_json``).
    logger.debug(
        "Falling back to safe minimal deep JSON after repair failure (%s)",
        model_display,
    )
    return safe_minimal


__all__ = [
    "apply_structured_json_repair_steps",
    "balance_json_delimiters_outside_strings",
    "build_safe_minimal_chunk_json",
    "decode_chunk_deep_json_object",
    "extract_first_json_object_candidate",
    "fix_invalid_json_string_escapes",
    "repair_chunk_deep_structured_json_raw",
    "scan_open_delimiter_stack_outside_strings",
    "strip_code_fences",
    "strip_control_chars",
    "strip_trailing_commas_outside_strings",
]
