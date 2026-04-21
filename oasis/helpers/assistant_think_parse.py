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


# Matches ``<|channel>thought <channel|>`` then body until ``\\n\\n`` (reply) or EOS.
_CHANNEL_THOUGHT_OPEN = re.compile(
    r"<\|channel>\s*thought\s*<\s*channel\s*\|\s*>",
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
    """Extract ``<|channel>thought <channel|>…`` blocks; optional ``\\n\\n`` splits thought vs reply."""
    while True:
        m = _CHANNEL_THOUGHT_OPEN.search(work)
        if not m:
            return work
        tail = work[m.end() :]
        parts = tail.split("\n\n", 1)
        thought_body = parts[0].strip()
        visible_rest = parts[1].strip() if len(parts) > 1 else ""
        if thought_body:
            segments.append(thought_body)
        work = work[: m.start()] + visible_rest


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
