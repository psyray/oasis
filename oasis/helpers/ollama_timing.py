"""Estimate Ollama payload sizes for logging and timeout helper (no secrets)."""

from __future__ import annotations

from typing import Any, Optional


def estimate_ollama_payload_chars(payload_key: str, payload_value: Any) -> int:
    """Rough character count for chat messages or raw prompt/generate payloads."""
    if payload_key == "messages" and isinstance(payload_value, list):
        total = 0
        for m in payload_value:
            if isinstance(m, dict):
                c = m.get("content")
                if isinstance(c, str):
                    total += len(c)
        return total
    return len(payload_value) if isinstance(payload_value, str) else 0


def options_timeout_ms(options: Optional[dict]) -> Optional[int]:
    if not options or not isinstance(options, dict):
        return None
    v = options.get("timeout")
    return int(v) if isinstance(v, (int, float)) else None
