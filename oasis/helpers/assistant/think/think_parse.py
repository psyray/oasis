"""Parse model 'thinking' blocks out of assistant text for UI and API enrichment.

Models may wrap chain-of-thought in XML-like tags; we extract those segments and expose
visible markdown separately so callers can render safe assistant output without duplication.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class AssistantThinkSplit:
    """Assistant reply split into user-visible markdown and extracted thought segments."""

    visible_markdown: str
    thought_segments: List[str]


# Harmony-style reasoning channel opener (OpenAI gpt-oss et al.).
#
# Observed variants from streaming output:
# - ``<|channel>thought <channel|>`` (asymmetric pipes, short label)
# - ``<|channel>thought thought <channel|>`` (duplicated label token)
# - ``<|channel>>thought <channel|>`` (stray ``>`` glued to opener)
# - ``<|channel> most_thought <channel|>`` (prefixed label)
# - ``<|channel|>analysis<|message|>`` (fully symmetric harmony form)
# - ``<|channel|>commentary<|message|>``
#
# The label word is one of ``thought``/``analysis``/``reasoning``/``commentary``
# optionally surrounded by ``\w``/``-``; the opener may have stray ``>`` or repeats.
_CHANNEL_THOUGHT_OPEN = re.compile(
    r"<\|?channel\|?>"                           # <|channel>, <channel|>, or <|channel|>
    r"[\s>]*"                                    # tolerate stray '>' / whitespace tokens
    r"(?:[\w\-]*"                                # optional label prefix (e.g. ``most_``)
    r"(?:thought|analysis|reasoning|commentary)" # reasoning channel keyword
    r"[\w\-]*\s*)+"                              # optional suffix / repeated label tokens
    r"(?:"
    r"<\s*channel\s*\|>"                         # <channel|>
    r"|<\s*\|channel\|>"                         # <|channel|>
    r"|<\s*\|?message\|?>"                       # <|message|>, <message|>
    r")",
    re.IGNORECASE,
)

# Harmony boundaries that terminate a reasoning segment (``<|end|>``/``<|return|>``/``<|start|>``).
_HARMONY_SEGMENT_END = re.compile(
    r"<\|?(?:end|return|start)\|?>",
    re.IGNORECASE,
)

# Stray harmony/channel tokens to strip from the visible body when they survive
# structured extraction (partial tokenization, truncated streams, unknown labels).
_STRAY_HARMONY_TOKEN = re.compile(
    r"<\|?"
    r"(?:channel|message|start|end|return|refusal|analysis|final|system|user|assistant"
    r"|thought|reasoning|commentary)"
    r"\|?>",
    re.IGNORECASE,
)

_THINK_BLOCK_PATTERNS: tuple[re.Pattern[str], ...] = (
    # DeepSeek / Anthropic-style redacted blocks (optional attributes on opening tag).
    # Closing tag name may be ``redacted_thinking`` or ``think`` (provider variance).
    re.compile(
        r"<redacted_thinking[^>]*>\s*([\s\S]*?)\s*</(?:redacted_thinking|think)\s*>",
        re.IGNORECASE,
    ),
    # Generic explicit think tags
    re.compile(r"<\s*think\s*>\s*([\s\S]*?)\s*<\s*/\s*think\s*>", re.IGNORECASE),
)


def _strip_channel_thought_prefix(work: str, segments: List[str]) -> str:
    """Extract ``<|channel>thought … <|channel|>`` segments.

    End of segment (earliest wins): next channel opener (multiple reasoning blocks
    back-to-back), harmony boundary token (``<|end|>``/``<|return|>``/``<|start|>``),
    or first ``\\n\\n`` (thought vs reply). Falls back to end of string.
    """
    while True:
        m = _CHANNEL_THOUGHT_OPEN.search(work)
        if not m:
            return work
        before = work[: m.start()]
        tail = work[m.end() :]

        next_open = _CHANNEL_THOUGHT_OPEN.search(tail)
        end_tok = _HARMONY_SEGMENT_END.search(tail)
        para_idx = tail.find("\n\n")

        # Earliest terminator wins so reasoning never swallows the real reply.
        candidates: List[tuple[int, str, Any]] = []
        if next_open is not None:
            candidates.append((next_open.start(), "next_open", next_open))
        if end_tok is not None:
            candidates.append((end_tok.start(), "end_tok", end_tok))
        if para_idx != -1:
            candidates.append((para_idx, "para", None))

        if not candidates:
            thought_body = tail.strip()
            if thought_body:
                segments.append(thought_body)
            work = before
            continue

        candidates.sort(key=lambda t: t[0])
        pos, kind, obj = candidates[0]
        thought_body = tail[:pos].strip()
        if thought_body:
            segments.append(thought_body)

        if kind == "next_open":
            # Preserve the next opener so the outer loop extracts it too.
            work = before + tail[pos:]
        elif kind == "end_tok" and obj is not None:
            work = before + tail[pos + (obj.end() - obj.start()) :]
        else:  # "para"
            work = before + tail[pos + 2 :]


def parse_assistant_think(text: str) -> AssistantThinkSplit:
    """Remove known thought wrappers from *text* and collect inner segments.

    Patterns are applied in order; each match is stripped from the working string and its
    inner body (group 1) appended to ``thought_segments`` when non-empty after ``strip``.
    """
    segments: List[str] = []
    work = text or ""
    work = _strip_channel_thought_prefix(work, segments)
    for pattern in _THINK_BLOCK_PATTERNS:
        while True:
            m = pattern.search(work)
            if not m:
                break
            inner = (m.group(1) or "").strip()
            if inner:
                segments.append(inner)
            work = work[: m.start()] + work[m.end() :]
    # Final safety net: drop stray harmony tokens that survived structured extraction
    # (partial tokenization during streaming, unknown channel labels, truncated streams).
    work = _STRAY_HARMONY_TOKEN.sub("", work)
    return AssistantThinkSplit(visible_markdown=work.strip(), thought_segments=segments)


def enrich_assistant_message_dict(msg: Dict[str, Any]) -> Dict[str, Any]:
    """Return a shallow copy of *msg* with ``visible_markdown`` / ``thought_segments`` for assistants."""
    if not isinstance(msg, dict):
        return msg
    if msg.get("role") != "assistant":
        return dict(msg)
    raw = msg.get("content", "")
    content = raw if isinstance(raw, str) else ""
    split = parse_assistant_think(content)
    out = dict(msg)
    out["visible_markdown"] = split.visible_markdown
    out["thought_segments"] = split.thought_segments
    return out


def enrich_messages_for_response(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Apply :func:`enrich_assistant_message_dict` to each assistant message."""
    return [enrich_assistant_message_dict(m) if isinstance(m, dict) else m for m in messages]
