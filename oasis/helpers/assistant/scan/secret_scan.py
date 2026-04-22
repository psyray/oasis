"""Hardcoded-secret scanner for the config / content-based family.

Thin wrapper around :mod:`validation_patterns.SECRETS_PATTERNS` that returns
:class:`oasis.schemas.analysis.ConfigFinding` entries. Designed for rapid
triage of the most common leaks; it is not a replacement for purpose-built
tools such as trufflehog.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Sequence

from .scan_utils import (
    compile_groups,
    scan_patterns_best_effort,
)
from oasis.helpers.vuln.validation_patterns import SECRETS_PATTERNS
from oasis.schemas.analysis import Citation, ConfigFinding


_SEVERITY_MAP: Dict[str, str] = {
    "aws_access_key": "critical",
    "generic_api_key": "high",
    "private_key": "critical",
    "bearer_literal": "high",
}


def _compiled_for(kinds: Sequence[str]):
    groups: Dict[str, List[str]] = {
        k: SECRETS_PATTERNS[k] for k in kinds if k in SECRETS_PATTERNS
    }
    return compile_groups(groups)


def run_secret_scan(
    root: Path,
    kinds: Sequence[str] = tuple(SECRETS_PATTERNS.keys()),
    *,
    max_hits: int = 200,
) -> List[ConfigFinding]:
    """Return hardcoded-secret hits under *root* restricted to *kinds*."""
    compiled = _compiled_for(kinds)
    if not compiled:
        return []
    matches = scan_patterns_best_effort(root, compiled, max_hits=max_hits)
    return [
        ConfigFinding(
            kind=m.pattern_key,
            severity=_SEVERITY_MAP.get(m.pattern_key, "high"),
            citation=Citation(
                file_path=str(m.file_path),
                start_line=m.line_number,
                end_line=m.line_number,
                snippet=m.line_text,
            ),
        )
        for m in matches
    ]
