"""Thinking-tag parsing and investigation narrative synthesis."""

from __future__ import annotations

from .investigation_synth import (
    build_synthesis_messages,
    compact_investigation_for_llm,
    enrich_investigation_with_llm_narrative,
)
from .think_parse import (
    AssistantThinkSplit,
    enrich_assistant_message_dict,
    enrich_messages_for_response,
    parse_assistant_think,
)

__all__ = [
    "AssistantThinkSplit",
    "build_synthesis_messages",
    "compact_investigation_for_llm",
    "enrich_assistant_message_dict",
    "enrich_investigation_with_llm_narrative",
    "enrich_messages_for_response",
    "parse_assistant_think",
]
