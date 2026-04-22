"""Authorization hits and access-control heuristics."""

from __future__ import annotations

from .authz import (
    authz_hits_in_file,
    authz_hits_in_root,
    evaluate_required_controls,
    missing_controls,
)
from .controls import (
    auth_hardening_scan,
    cors_hardening_scan,
    csrf_protection_scan,
    jwt_hardening_scan,
    session_hardening_scan,
)

__all__ = [
    "auth_hardening_scan",
    "authz_hits_in_file",
    "authz_hits_in_root",
    "cors_hardening_scan",
    "csrf_protection_scan",
    "evaluate_required_controls",
    "jwt_hardening_scan",
    "missing_controls",
    "session_hardening_scan",
]
