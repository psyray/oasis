"""Configuration audit helper for the config / content-based family.

Reports misconfigured flags: DEBUG on, wildcard CORS, insecure cookies,
disabled TLS verification. Each hit is returned as a
:class:`oasis.schemas.analysis.ConfigFinding` with a severity hint so the
verdict node can aggregate without re-reading the file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Sequence

from oasis.helpers.assistant_scan_utils import (
    compile_groups,
    scan_patterns_best_effort,
)
from oasis.helpers.validation_patterns import CONFIG_AUDIT
from oasis.schemas.analysis import Citation, ConfigFinding


_SEVERITY_MAP: Dict[str, str] = {
    "debug_enabled": "high",
    "open_cors": "high",
    "insecure_cookie": "medium",
    "tls_disabled": "high",
}


def _compiled_for(kinds: Sequence[str]):
    groups: Dict[str, List[str]] = {k: CONFIG_AUDIT[k] for k in kinds if k in CONFIG_AUDIT}
    return compile_groups(groups)


def run_config_audit(
    root: Path,
    kinds: Sequence[str] = tuple(CONFIG_AUDIT.keys()),
    *,
    max_hits: int = 200,
) -> List[ConfigFinding]:
    """Return config-audit findings for *root* restricted to *kinds*."""
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
