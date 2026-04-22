"""Detect log statements that would leak sensitive data (passwords, tokens, PII)."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Sequence

from .scan_utils import (
    compile_groups,
    scan_patterns_best_effort,
)
from oasis.helpers.vuln.validation_patterns import LOG_SENSITIVE_PATTERNS
from oasis.schemas.analysis import Citation, ConfigFinding


_SEVERITY_MAP: Dict[str, str] = {
    "logged_password": "critical",
    "logged_token": "high",
    "logged_card": "critical",
}


def _compiled_for(kinds: Sequence[str]):
    groups: Dict[str, List[str]] = {
        k: LOG_SENSITIVE_PATTERNS[k] for k in kinds if k in LOG_SENSITIVE_PATTERNS
    }
    return compile_groups(groups)


def run_log_filter_scan(
    root: Path,
    kinds: Sequence[str] = tuple(LOG_SENSITIVE_PATTERNS.keys()),
    *,
    max_hits: int = 200,
) -> List[ConfigFinding]:
    compiled = _compiled_for(kinds)
    if not compiled:
        return []
    matches = scan_patterns_best_effort(root, compiled, max_hits=max_hits)
    return [
        ConfigFinding(
            kind=m.pattern_key,
            severity=_SEVERITY_MAP.get(m.pattern_key, "medium"),
            citation=Citation(
                file_path=str(m.file_path),
                start_line=m.line_number,
                end_line=m.line_number,
                snippet=m.line_text,
            ),
        )
        for m in matches
    ]
