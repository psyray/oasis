"""
Character-level scanners for JSON-ish repair (ChunkDeepAnalysis buffers only).

No ``json.loads``, no markdown fences, no ``logger``. Used by
``oasis.structured_output.json_repair`` in this order as part of the larger pipeline:

    strip fences / controls / leading noise  (in the parent module)
    → try ``decode_chunk_deep_json_object``
    → balance delimiters (uses ``scan_open_delimiter_stack_outside_strings``)
    → ``strip_trailing_commas_outside_strings``
    → ``fix_invalid_json_string_escapes``
    → ``build_safe_minimal_chunk_json`` / best-effort return (parent module)

``json_repair`` re-exports public names so tests and callers can import from there.
"""

from __future__ import annotations

from typing import List, Optional

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _is_simple_json_escape_char(next_char: str) -> bool:
    """True if ``\\`` + this char is a standard single-character JSON escape."""
    return next_char in '"\\/bfnrt'


def _is_unicode_escape_at(s: str, backslash_index: int) -> bool:
    """
    True if ``s[backslash_index:]`` begins ``\\uXXXX`` with four hex digits.

    ``backslash_index`` points at the backslash inside a JSON string.
    """
    if backslash_index + 6 > len(s) or s[backslash_index + 1] != "u":
        return False
    return all(c in _HEX_DIGITS for c in s[backslash_index + 2 : backslash_index + 6])


def scan_open_delimiter_stack_outside_strings(candidate: str) -> Optional[List[str]]:
    """
    Walk ``candidate`` and track ``{``/``[`` stack outside JSON double-quoted strings.

    **Pre:** ``candidate`` is the buffer to scan (may be truncated LLM output).

    **Post:**
    - Returns a list of still-open ``{`` / ``[`` (in order) if the scan ends **outside**
      a string and no structural mismatch occurred.
    - Returns ``None`` if a closer has no opener, brace/bracket types mismatch, or the
      scan ends **inside** an unterminated string (unsafe to append synthetic closers).

    **State sketch** (``O`` = outside string, ``I`` = inside ``"..."``)::

        O -- '"' ------------------------> I
        O -- '{' '[' --------------------> push on stack (stay O)
        O -- '}' ']' --------------------> pop; empty/mismatch -> None
        I -- '\\' -----------------------> next char skipped (escaped)
        I -- '"' (not after '\\') ------> O
        I -- other ----------------------> stay I

    **Edge cases:** ``]`` / ``}`` inside a string do not touch the stack. Truncation
    mid-string leaves ``I`` at EOF -> ``None`` (caller must not append closers).

    **Examples:**

    - ``{"a":1`` → ``["{"]`` (truncated object; caller may append ``}``).
    - ``{"a":1}`` → ``[]`` (balanced).
    - ``{]`` → ``None`` (malformed; do not balance).
    - ``{"x":"`` → ``None`` (truncated inside string).
    """
    stack: List[str] = []
    in_string = False
    escaped = False
    for ch in candidate:
        if in_string:
            if escaped:
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            escaped = False
            continue
        if ch in "{[":
            stack.append(ch)
            continue
        if ch in "}]":
            if not stack:
                return None
            top = stack[-1]
            if ch == "}" and top != "{":
                return None
            if ch == "]" and top != "[":
                return None
            stack.pop()
            continue

    return None if in_string else stack


def _comma_is_trailing_before_close(candidate: str, comma_index: int) -> bool:
    """True if ``candidate[comma_index]`` is a comma followed only by whitespace then ``}`` or ``]``."""
    j = comma_index + 1
    while j < len(candidate) and candidate[j].isspace():
        j += 1
    return j < len(candidate) and candidate[j] in "}]"


def strip_trailing_commas_outside_strings(candidate: str) -> str:
    """
    Remove a comma immediately before ``}`` or ``]`` when outside double-quoted strings.

    Same string/escape assumptions as delimiter scanning in this module.
    Does not rewrite commas inside strings; if string state is wrong, behavior is undefined.
    """
    out: List[str] = []
    in_string = False
    escaped = False
    i = 0
    while i < len(candidate):
        char = candidate[i]
        if escaped:
            out.append(char)
            escaped = False
            i += 1
            continue
        if char == "\\" and in_string:
            out.append(char)
            escaped = True
            i += 1
            continue
        if char == '"':
            out.append(char)
            in_string = not in_string
            i += 1
            continue
        if not in_string and char == "," and _comma_is_trailing_before_close(candidate, i):
            # Drop this comma: JSON disallows it; LLMs often emit one before ``}``.
            i += 1
            continue
        out.append(char)
        i += 1
    return "".join(out)


def _consume_backslash_inside_json_string(
    s: str, i: int, n: int, out: List[str]
) -> int:
    """
    Handle ``\\`` at index ``i`` **inside** a JSON string (caller ensures ``in_string``).

    **Pre:** ``0 <= i < n`` and ``s[i] == "\\"``.

    **Post:** Appends the corrected escape sequence fragment to ``out`` and returns the
    new read index (always ``> i``).

    **Examples:**

    - ``...\\n...`` at ``i`` → append ``\\n``, return ``i + 2``.
    - ``...\\\\...`` → append ``\\\\`` (one JSON escaped backslash), return ``i + 2``.
    - ``...\\x...`` (invalid) → append ``\\\\`` only; return ``i + 1`` so ``x`` is copied
      as a normal character on the next loop (literal ``x`` in the string value).
    - trailing ``\\`` at end of buffer → append ``\\\\`` (literal backslash), return ``n``.
    """
    if i + 1 >= n:
        out.append("\\\\")
        return n
    nxt = s[i + 1]
    if nxt == "\\":
        out.append("\\\\")
        return i + 2
    if _is_simple_json_escape_char(nxt):
        out.extend(("\\", nxt))
        return i + 2
    if _is_unicode_escape_at(s, i):
        out.append(s[i : i + 6])
        return i + 6
    # Invalid escape (e.g. ``\x``, ``\'``): JSON rejects ``\`` + unknown; double the
    # backslash so the following character is read as literal content.
    out.append("\\\\")
    return i + 1


def fix_invalid_json_string_escapes(s: str) -> str:
    """
    Escape backslashes that start invalid JSON escape sequences inside double-quoted strings.

    JSON allows only \\\", \\\\, \\/, \\b, \\f, \\n, \\r, \\t, \\uXXXX. Sequences like \\x or \\'
    break parsing; doubling the backslash preserves intent (literal backslash + next char).

    Backslash handling is delegated to ``_consume_backslash_inside_json_string`` so each
    ``\\`` is resolved in one step (valid escape, ``\\\\``, ``\\uXXXX``, or invalid prefix).

    **State sketch** (structural ``"`` toggles only; braces outside strings are copied)::

        O (outside) -- '"' ------------> I (inside string value)
        O -- any other char -----------> copy (structure pass-through)
        I -- '"' ----------------------> O   (end of string token)
        I -- '\\' --------------------> emit via _consume_*; advance index
        I -- plain char --------------> copy

    **Invariant:** Outside strings the buffer is copied verbatim so keys/braces stay
    aligned. Inside strings, only ``\\`` sequences are rewritten. If the scan is already
    mis-synchronized (e.g. an odd ``"`` in a code snippet), output may be wrong.
    """
    out: List[str] = []
    i = 0
    n = len(s)
    in_string = False
    while i < n:
        ch = s[i]
        if not in_string:
            if ch == '"':
                in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_string = False
            out.append(ch)
            i += 1
            continue
        if ch == "\\":
            i = _consume_backslash_inside_json_string(s, i, n, out)
            continue
        out.append(ch)
        i += 1
    return "".join(out)
