"""Inline ignore markers: drop findings annotated in the analyzed source.

Findings whose vulnerable lines carry a triage marker (``# noqa``, ``# nosec``,
``# nosemgrep``, or the OASIS-specific ``# oasisignore``) are removed **in
place** from the deep-pass results right after the transverse dedup and before
scan-time validation and report generation — canonical JSON, stats, exports
and dashboards never see them.

Detection is deterministic and language-agnostic (no comment-syntax parsing):
a marker is honored when it appears as a word token

- inside the finding's ``vulnerable_code`` snippet, or
- on the file lines of the resolved ``snippet_start_line`` /
  ``snippet_end_line`` span extended by one trailing line (trailing-comment
  convention: ``password = "..."  # noqa``).

A marker on the line *above* the snippet is deliberately not honored: it may
belong to a different statement. Fail-open by design: unreadable files,
malformed rows and unknown shapes are skipped and never abort the deep pass.

Chunks whose findings are dropped get their ``notes`` rewritten with a
deterministic ``N finding(s) skipped via inline ignore marker`` sentence, so
reports and dashboards display the ignore instead of the stale LLM claim;
the original LLM notes are preserved after an ``Original notes:`` label.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from oasis.helpers.assistant.scan.scan_utils import read_text_safely
from oasis.helpers.assistant.web.sink_resolution import (
    coerce_positive_int_line,
    resolve_report_file_path,
)
from oasis.helpers.findings_dedupe import (
    finding_field,
    iter_structured_chunks,
    set_chunk_field,
    set_chunk_findings,
)

logger = logging.getLogger(__name__)

#: Markers honored by default (matched case-insensitively as word tokens).
DEFAULT_INLINE_IGNORE_TOKENS: tuple[str, ...] = ("oasisignore", "nosec", "noqa", "nosemgrep")

# File lines checked for a 1-based snippet span [start, end]: the span itself
# plus one trailing line (trailing-comment convention, e.g. `x = "p"  # noqa`).
_TRAILING_LINE_COUNT = 1

#: Canonical sentence inserted into chunk notes when findings are dropped.
_SKIP_MARKER_PHRASE = "skipped via inline ignore marker"


def normalize_inline_ignore_tokens(raw: Any) -> tuple[str, ...]:
    """Normalize raw ``--inline-ignore-tokens`` input to a lowercase token tuple.

    ``None`` falls back to :data:`DEFAULT_INLINE_IGNORE_TOKENS`. A CSV string or
    an iterable of strings is trimmed, lowercased and de-duplicated. An empty
    *string* (argparse input) falls back to the defaults with a warning, while
    an empty *iterable* explicitly disables the pass (returns an empty tuple).
    Invalid types fall back to the defaults (fail-open).
    """
    if raw is None:
        return DEFAULT_INLINE_IGNORE_TOKENS

    explicit_empty_is_disable = False
    if isinstance(raw, str):
        parts: list[Any] = raw.split(",")
    elif isinstance(raw, (list, tuple, set, frozenset)):
        parts = list(raw)
        explicit_empty_is_disable = True
    else:
        logger.warning("Ignoring invalid inline ignore tokens value %r; using defaults", raw)
        return DEFAULT_INLINE_IGNORE_TOKENS

    tokens: list[str] = []
    for part in parts:
        token = str(part).strip().lower()
        if token and token not in tokens:
            tokens.append(token)

    if not tokens:
        if explicit_empty_is_disable:
            logger.debug("Empty inline ignore tokens list; inline ignore pass disabled")
            return ()
        logger.warning(
            "Empty inline ignore tokens list; using defaults: %s",
            ", ".join(DEFAULT_INLINE_IGNORE_TOKENS),
        )
        return DEFAULT_INLINE_IGNORE_TOKENS

    return tuple(tokens)


def _compile_marker_pattern(tokens: tuple[str, ...]) -> re.Pattern:
    """Compile the word-boundary pattern matching any ignore token."""
    if not tokens:
        raise ValueError("no inline ignore tokens")
    return re.compile(r"\b(?:" + "|".join(re.escape(token) for token in tokens) + r")\b", re.IGNORECASE)


def _resolved_file_lines(
    file_path: str,
    scan_root: Path,
    cache: dict[str, list[str] | None],
) -> list[str] | None:
    """Return the line list of *file_path* (cached per pass), or ``None``.

    Resolution reuses the shared report-file-path rules (paths relative to the
    launcher directory or to *scan_root*), exactly like the scan-time finding
    validator, so both passes agree on which file a finding points at.
    """
    resolved = resolve_report_file_path(file_path, scan_root)
    if resolved is None:
        return None
    key = str(resolved)
    if key not in cache:
        text = read_text_safely(resolved)
        cache[key] = text.splitlines() if text is not None else None
    return cache[key]


def finding_has_inline_ignore_marker(
    finding: Any,
    file_path: str,
    *,
    scan_root: Path,
    pattern: re.Pattern,
    line_cache: dict[str, list[str] | None],
) -> bool:
    """Tell whether one finding is annotated with an ignore marker.

    Checks the snippet text first (markers already captured inside the quoted
    code), then the resolved file lines — snippet span plus one trailing line —
    when both line bounds resolved.
    """
    snippet = finding_field(finding, "vulnerable_code")
    if isinstance(snippet, str) and pattern.search(snippet):
        return True

    start = coerce_positive_int_line(finding_field(finding, "snippet_start_line"))
    end = coerce_positive_int_line(finding_field(finding, "snippet_end_line"))
    if start is None or end is None or end < start or not file_path:
        return False

    lines = _resolved_file_lines(file_path, scan_root, line_cache)
    if lines is None:
        return False

    window = lines[max(start - 1, 0) : end + _TRAILING_LINE_COUNT]
    return any(pattern.search(line) for line in window)


def _skipped_clause(dropped: int) -> str:
    """Deterministic sentence for *dropped* findings ignored in one chunk."""
    noun = "finding" if dropped == 1 else "findings"
    return f"{dropped} {noun} {_SKIP_MARKER_PHRASE}"


def _annotate_chunk_notes(chunk: Any, dropped: int, all_dropped: bool) -> None:
    """Rewrite chunk notes so dropped findings are honestly reported.

    When every finding of the chunk was dropped, the skip sentence leads and
    the original LLM notes are preserved after an ``Original notes:`` label for
    traceability; otherwise the sentence is appended to the untouched notes.
    Already-annotated notes are left unchanged (idempotent).
    """
    notes = finding_field(chunk, "notes")
    original = notes if isinstance(notes, str) else ""
    if _SKIP_MARKER_PHRASE in original:
        return
    clause = _skipped_clause(dropped)
    if all_dropped:
        updated = f"{clause}. Original notes: {original}" if original else f"{clause}."
    else:
        updated = f"{original}\n{clause}." if original else f"{clause}."
    set_chunk_field(chunk, "notes", updated)


def drop_inline_ignored_findings(
    rows: Any,
    *,
    scan_root: Path,
    tokens: Any = None,
) -> dict[str, int]:
    """Drop findings annotated with ignore markers, in place.

    Mirrors :func:`oasis.helpers.findings_dedupe.deduplicate_rows_findings`
    semantics: operates on the ``detailed_results`` rows right after the deep
    pass and never aborts on malformed data. *tokens* accepts the raw
    ``--inline-ignore-tokens`` value (``None``, CSV string or iterable); an
    empty marker list disables the pass.

    Returns ``{"dropped": <count>}``.
    """
    token_tuple = normalize_inline_ignore_tokens(tokens)
    if not token_tuple:
        return {"dropped": 0}

    try:
        pattern = _compile_marker_pattern(token_tuple)
    except (re.error, ValueError) as exc:  # tokens are re-escaped above; defensive only
        logger.warning("Invalid inline ignore tokens %r (%s); skipping inline ignore pass", tokens, exc)
        return {"dropped": 0}

    dropped = 0
    line_cache: dict[str, list[str] | None] = {}
    for _row_index, _chunk_index, chunk, findings, file_path in iter_structured_chunks(rows):
        kept = [
            finding
            for finding in findings
            if not finding_has_inline_ignore_marker(
                finding,
                file_path,
                scan_root=scan_root,
                pattern=pattern,
                line_cache=line_cache,
            )
        ]
        if len(kept) != len(findings):
            dropped_in_chunk = len(findings) - len(kept)
            dropped += dropped_in_chunk
            set_chunk_findings(chunk, kept)
            _annotate_chunk_notes(chunk, dropped_in_chunk, all_dropped=not kept)

    return {"dropped": dropped}


__all__ = [
    "DEFAULT_INLINE_IGNORE_TOKENS",
    "drop_inline_ignored_findings",
    "finding_has_inline_ignore_marker",
    "normalize_inline_ignore_tokens",
]