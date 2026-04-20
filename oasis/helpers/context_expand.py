"""
Expand code windows around suspicious chunk spans for richer deep-analysis context.

Pure helpers (no LLM calls). Budget is enforced in characters to stay predictable
without requiring a tokenizer.
"""

from __future__ import annotations

from typing import List, Tuple

from ..config import CONTEXT_EXPAND_MAX_CHARS, CONTEXT_EXPAND_PADDING_AFTER, CONTEXT_EXPAND_PADDING_BEFORE


def _join_line_window(lines: List[str], idx_lo: int, idx_hi: int) -> str:
    """Join lines[idx_lo : idx_hi + 1] with newlines (idx_* are 0-based inclusive)."""
    return "\n".join(lines[idx_lo : idx_hi + 1])


def expand_line_window(
    lines: List[str],
    start_line: int,
    end_line: int,
    *,
    padding_before: int,
    padding_after: int,
    max_chars: int,
) -> Tuple[str, int, int]:
    """
    Return a code window covering [start_line, end_line] (1-based inclusive) plus padding.

    Args:
        lines: Full file split with splitlines() (no trailing newline per line).
        start_line: First line of interest (1-based).
        end_line: Last line of interest (1-based).
        padding_before: Lines to include above start_line.
        padding_after: Lines to include below end_line.
        max_chars: Hard cap on returned text length. Context outside
            [start_line, end_line] may be trimmed to satisfy the budget; the
            suspicious lines are always kept when physically possible (except a
            raw prefix cut when that span alone exceeds max_chars).

    Returns:
        (window_text, window_start_line, window_end_line) all 1-based inclusive.
    """
    if not lines:
        return "", start_line, end_line

    n = len(lines)
    lo = max(1, start_line - max(0, padding_before))
    hi = min(n, end_line + max(0, padding_after))
    segment = lines[lo - 1 : hi]
    text = "\n".join(segment)
    if len(text) <= max_chars:
        return text, lo, hi

    # Ensure [start_line, end_line] stays inside the returned window; trim padding
    # around it (roughly symmetric expansion under budget).
    susp_lo = max(lo, start_line)
    susp_hi = min(hi, end_line)
    susp_start_idx = susp_lo - lo
    susp_end_idx = susp_hi - lo

    win_lo_idx = susp_start_idx
    win_hi_idx = susp_end_idx

    curr_text = _join_line_window(segment, win_lo_idx, win_hi_idx)
    if len(curr_text) > max_chars:
        prefix = curr_text[:max_chars]
        end_ln = susp_lo + prefix.count("\n")
        return prefix, susp_lo, end_ln

    while True:
        can_left = win_lo_idx > 0
        can_right = win_hi_idx < len(segment) - 1
        if can_left and can_right:
            cand_lo, cand_hi = win_lo_idx - 1, win_hi_idx + 1
        elif can_left:
            cand_lo, cand_hi = win_lo_idx - 1, win_hi_idx
        elif can_right:
            cand_lo, cand_hi = win_lo_idx, win_hi_idx + 1
        else:
            break

        cand_text = _join_line_window(segment, cand_lo, cand_hi)
        if len(cand_text) > max_chars:
            break
        win_lo_idx, win_hi_idx = cand_lo, cand_hi
        curr_text = cand_text

    orig_lo = lo
    lo = orig_lo + win_lo_idx
    hi = orig_lo + win_hi_idx
    return curr_text, lo, hi


def expand_suspicious_chunk_records(
    file_content: str,
    suspicious_chunks: List[Tuple[int, str, int, int]],
    *,
    padding_before: int = CONTEXT_EXPAND_PADDING_BEFORE,
    padding_after: int = CONTEXT_EXPAND_PADDING_AFTER,
    max_chars: int = CONTEXT_EXPAND_MAX_CHARS,
) -> List[Tuple[int, str, int, int]]:
    """
    Replace each (idx, chunk, start_line, end_line) with an expanded window.

    Preserves chunk index ordering; empty file yields an empty list.
    """
    if not suspicious_chunks:
        return []
    lines = file_content.splitlines()
    out: List[Tuple[int, str, int, int]] = []
    for idx, _chunk, sl, el in suspicious_chunks:
        win, wl, wh = expand_line_window(
            lines,
            sl,
            el,
            padding_before=padding_before,
            padding_after=padding_after,
            max_chars=max_chars,
        )
        out.append((idx, win, wl, wh))
    return out
