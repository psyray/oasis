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


# Open: ``<|channel>`` + one or more ``thought`` tokens; close: ``<channel|>`` or ``<|channel|>``
# (provider output varies; some models repeat ``thought`` or use a symmetric close tag).
_CHANNEL_THOUGHT_OPEN = re.compile(
    r"<\|channel>\s*(?:thought\s*)+"
    r"(?:"
    r"<\s*channel\s*\|>"  # e.g. <channel|>
    r"|<\s*\|channel\|>"  # e.g. <|channel|>
    r")",
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

    End of segment: next channel opener if any (handles multiple reasoning blocks back-to-back),
    else first ``\\n\\n`` (thought vs reply), else end of string.
    """
    while True:
        m = _CHANNEL_THOUGHT_OPEN.search(work)
        if not m:
            return work
        before = work[: m.start()]
        tail = work[m.end() :]
        next_open = _CHANNEL_THOUGHT_OPEN.search(tail)
        para_idx = tail.find("\n\n")

        if next_open is not None and (para_idx == -1 or next_open.start() < para_idx):
            end = next_open.start()
            thought_body = tail[:end].strip()
            # Keep remainder starting at the next opener so the outer loop extracts it too.
            work = before + tail[end:]
        elif para_idx != -1:
            thought_body = tail[:para_idx].strip()
            work = before + tail[para_idx + 2 :]
        else:
            thought_body = tail.strip()
            work = before

        if thought_body:
            segments.append(thought_body)


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
