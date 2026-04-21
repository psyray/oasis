"""Authorization and ownership checks surrounding a finding.

Supports the access-control family: IDOR, CSRF, Authentication, Session,
JWT and CORS. Detection combines:

- Decorators (``@login_required``, ``@jwt_required`` ...).
- Middlewares (``CSRFProtect``, ``passport.authenticate`` ...).
- Ownership guards (``if obj.user_id == request.user.id``).

The result is either an :class:`AuthzCheckHit` (for a concrete observation)
or a :class:`ControlCheck` (present/absent summary per required control).
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Sequence

from oasis.helpers.assistant_scan_utils import (
    compile_groups,
    read_text_safely,
    scan_patterns_best_effort,
)
from oasis.helpers.validation_patterns import CONTROLS
from oasis.schemas.analysis import AuthzCheckHit, Citation, ControlCheck


def _compiled_for(kinds: Sequence[str]):
    groups: Dict[str, List[str]] = {
        kind: CONTROLS[kind] for kind in kinds if kind in CONTROLS
    }
    return compile_groups(groups)


def authz_hits_in_file(
    file_path: Path,
    control_kinds: Sequence[str],
) -> List[AuthzCheckHit]:
    """Return authz/ownership hits inside a single file."""
    text = read_text_safely(file_path)
    if text is None or not control_kinds:
        return []
    compiled = _compiled_for(control_kinds)
    hits: List[AuthzCheckHit] = []
    for line_index, line in enumerate(text.splitlines(), start=1):
        for kind, patterns in compiled.items():
            for pattern in patterns:
                if pattern.search(line):
                    hits.append(
                        AuthzCheckHit(
                            kind=kind,
                            citation=Citation(
                                file_path=str(file_path),
                                start_line=line_index,
                                end_line=line_index,
                                snippet=line.rstrip(),
                            ),
                        )
                    )
                    break
    return hits


def authz_hits_in_root(
    root: Path,
    control_kinds: Sequence[str],
    *,
    max_hits: int = 500,
) -> List[AuthzCheckHit]:
    """Scan *root* for any authz/ownership hits of the requested kinds."""
    compiled = _compiled_for(control_kinds)
    if not compiled:
        return []
    matches = scan_patterns_best_effort(root, compiled, max_hits=max_hits)
    return [
        AuthzCheckHit(
            kind=m.pattern_key,
            citation=Citation(
                file_path=str(m.file_path),
                start_line=m.line_number,
                end_line=m.line_number,
                snippet=m.line_text,
            ),
        )
        for m in matches
    ]


def evaluate_required_controls(
    hits: Sequence[AuthzCheckHit],
    required: Sequence[str],
) -> List[ControlCheck]:
    """For every required control, report presence/absence with its citations."""
    by_kind: Dict[str, List[Citation]] = {}
    for hit in hits:
        by_kind.setdefault(hit.kind, []).append(hit.citation)
    return [
        ControlCheck(
            kind=kind,
            present=kind in by_kind,
            citations=by_kind.get(kind, []),
        )
        for kind in required
    ]


def missing_controls(checks: Sequence[ControlCheck]) -> List[str]:
    """Return the kinds of controls that were expected but not detected."""
    return [check.kind for check in checks if not check.present]
