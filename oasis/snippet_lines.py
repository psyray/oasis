"""
Resolve 1-based inclusive line ranges for vulnerable snippets inside a chunk.

Used after LLM analysis so SARIF and JSON can point at the snippet when it is
locatable in the analyzed segment (heuristic; not AST-based).
"""

from __future__ import annotations

from typing import Optional, Tuple


def substring_line_span_1based(haystack: str, needle: str) -> Optional[Tuple[int, int]]:
    """
    Return 1-based inclusive (start_line, end_line) for the first occurrence of
    ``needle`` in ``haystack``. Lines follow newline boundaries in ``haystack``.
    """
    n = (needle or "").strip()
    if not n:
        return None

    def span_for_char_range(start_char: int, end_char_inclusive: int) -> Tuple[int, int]:
        start_ln = haystack.count("\n", 0, start_char) + 1
        end_ln = haystack.count("\n", 0, end_char_inclusive + 1) + 1
        return (start_ln, end_ln)

    idx = haystack.find(n)
    if idx >= 0:
        return span_for_char_range(idx, idx + len(n) - 1)

    first_line = n.split("\n", 1)[0].strip()
    if len(first_line) >= 8:
        k = haystack.find(first_line)
        if k >= 0:
            return span_for_char_range(k, k + len(first_line) - 1)

    return None


def absolute_snippet_lines_in_file(
    chunk_text: str,
    chunk_start_line: int,
    vulnerable_code: str,
) -> Optional[Tuple[int, int]]:
    """Map a snippet inside ``chunk_text`` to absolute 1-based file lines."""
    rel = substring_line_span_1based(chunk_text, vulnerable_code)
    if rel is None:
        return None
    rel_s, rel_e = rel
    return (chunk_start_line + rel_s - 1, chunk_start_line + rel_e - 1)
