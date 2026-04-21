"""
Compose LLM prompts with optional user-provided instructions (CLI / file).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


def read_custom_instructions_file(path: Optional[str]) -> str:
    """Read UTF-8 text from path; return stripped content or empty string."""
    if not path:
        return ""
    try:
        p = Path(path).expanduser()
        return p.read_text(encoding="utf-8").strip()
    except OSError as exc:
        logger.warning("Could not read custom instructions file %s: %s", path, exc)
        return ""


def resolved_custom_instructions(args: Any) -> str:
    """
    Combine --custom-instructions-file and --custom-instructions (CLI string).
    File content first, then inline text, separated by a blank line when both are set.
    """
    file_part = read_custom_instructions_file(getattr(args, "custom_instructions_file", None))
    inline = getattr(args, "custom_instructions", None)
    inline_part = str(inline).strip() if inline else ""
    if file_part and inline_part:
        return f"{file_part}\n\n{inline_part}"
    return file_part or inline_part


def append_user_instructions(base_prompt: str, instructions: str) -> str:
    """Append user instructions block when non-empty."""
    text = (instructions or "").strip()
    if not text:
        return base_prompt
    return (
        f"{base_prompt.rstrip()}\n\n"
        "## USER_ADDITIONAL_INSTRUCTIONS\n\n"
        f"{text}\n"
    )
