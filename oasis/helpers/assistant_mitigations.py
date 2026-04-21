"""Detect mitigations present on the path to a vulnerable sink.

A "mitigation" here is any sanitizer, validator, ORM call or security-aware
construct that plausibly nullifies the finding. Matching is regex-based via
:mod:`oasis.helpers.validation_patterns.MITIGATIONS`. Callers receive
:class:`oasis.schemas.analysis.MitigationHit` instances with a citation and
a flag telling whether the mitigation is strong enough to fully neutralise
the finding on its own.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Sequence

from oasis.helpers.assistant_scan_utils import (
    compile_groups,
    read_text_safely,
    scan_patterns_best_effort,
)
from oasis.helpers.validation_patterns import MITIGATIONS
from oasis.schemas.analysis import Citation, MitigationHit


# Mitigations that are considered sufficient on their own for their target family.
_NULLIFYING_MITIGATIONS = frozenset(
    {
        "sql_parameterized",
        "orm_query",
        "arg_array_exec",
        "html_escape",
        "bleach_clean",
        "autoescape_on",
        "safe_join",
        "basename_only",
        "defusedxml",
        "disable_entity_loader",
        "safe_loader",
        "ast_literal",
    }
)


def _compiled_for(kinds: Sequence[str]):
    groups: Dict[str, List[str]] = {}
    for kind in kinds:
        patterns = MITIGATIONS.get(kind)
        if patterns:
            groups[kind] = patterns
    return compile_groups(groups)


def find_mitigations_in_file(
    file_path: Path,
    mitigation_kinds: Sequence[str],
) -> List[MitigationHit]:
    """Return mitigations of *mitigation_kinds* detected inside a single file."""
    text = read_text_safely(file_path)
    if text is None or not mitigation_kinds:
        return []
    compiled = _compiled_for(mitigation_kinds)
    hits: List[MitigationHit] = []
    for line_index, line in enumerate(text.splitlines(), start=1):
        for kind, patterns in compiled.items():
            for pattern in patterns:
                if pattern.search(line):
                    hits.append(
                        MitigationHit(
                            kind=kind,
                            citation=Citation(
                                file_path=str(file_path),
                                start_line=line_index,
                                end_line=line_index,
                                snippet=line.rstrip(),
                            ),
                            nullifies=kind in _NULLIFYING_MITIGATIONS,
                        )
                    )
                    break
    return hits


def find_mitigations_in_root(
    root: Path,
    mitigation_kinds: Sequence[str],
    *,
    max_hits: int = 500,
) -> List[MitigationHit]:
    """Scan *root* for any mitigation of the requested kinds (project-wide)."""
    if not mitigation_kinds:
        return []
    compiled = _compiled_for(mitigation_kinds)
    if not compiled:
        return []
    matches = scan_patterns_best_effort(root, compiled, max_hits=max_hits)
    return [
        MitigationHit(
            kind=m.pattern_key,
            citation=Citation(
                file_path=str(m.file_path),
                start_line=m.line_number,
                end_line=m.line_number,
                snippet=m.line_text,
            ),
            nullifies=m.pattern_key in _NULLIFYING_MITIGATIONS,
        )
        for m in matches
    ]


def has_nullifying_mitigation(hits: Sequence[MitigationHit]) -> bool:
    """True when at least one of *hits* fully neutralises the finding."""
    return any(hit.nullifies for hit in hits)
