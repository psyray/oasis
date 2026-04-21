"""Insecure cryptographic usage detection (weak hashes, DES/RC4, ECB, fixed IV)."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Sequence

from oasis.helpers.assistant_scan_utils import (
    compile_groups,
    scan_patterns_best_effort,
)
from oasis.helpers.validation_patterns import CRYPTO_PATTERNS
from oasis.schemas.analysis import Citation, ConfigFinding


_SEVERITY_MAP: Dict[str, str] = {
    "weak_hash_md5": "high",
    "weak_hash_sha1": "high",
    "weak_cipher_des": "critical",
    "weak_cipher_rc4": "critical",
    "ecb_mode": "high",
    "hardcoded_iv": "high",
}


def _compiled_for(kinds: Sequence[str]):
    groups: Dict[str, List[str]] = {
        k: CRYPTO_PATTERNS[k] for k in kinds if k in CRYPTO_PATTERNS
    }
    return compile_groups(groups)


def run_crypto_scan(
    root: Path,
    kinds: Sequence[str] = tuple(CRYPTO_PATTERNS.keys()),
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
