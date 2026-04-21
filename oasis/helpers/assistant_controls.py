"""High-level wrapper around :mod:`assistant_authz` for composite controls.

Where ``assistant_authz`` exposes low-level hits, this module bundles the
checks most frequently requested by the access-control family: CSRF,
session hardening, JWT verification and CORS scoping. Each helper returns a
list of :class:`ControlCheck` entries — one per expected control — so the
verdict aggregator can compute a deterministic access-control score.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Sequence

from oasis.helpers.assistant_authz import (
    authz_hits_in_root,
    evaluate_required_controls,
)
from oasis.schemas.analysis import ControlCheck


_CSRF_CONTROLS: Sequence[str] = ("csrf_protection",)
_SESSION_CONTROLS: Sequence[str] = (
    "session_secure",
    "session_httponly",
    "session_samesite",
)
_JWT_CONTROLS: Sequence[str] = ("jwt_verify", "jwt_algorithm_pinned")
_CORS_CONTROLS: Sequence[str] = (
    "cors_origin_allowlist",
    "cors_credentials_scoped",
)
_AUTH_CONTROLS: Sequence[str] = ("login_required", "password_hashing")


def _run(root: Path, required: Sequence[str]) -> List[ControlCheck]:
    hits = authz_hits_in_root(root, required)
    return evaluate_required_controls(hits, required)


def csrf_protection_scan(root: Path) -> List[ControlCheck]:
    """Check that CSRF protection is declared somewhere in *root*."""
    return _run(root, _CSRF_CONTROLS)


def session_hardening_scan(root: Path) -> List[ControlCheck]:
    """Check session cookie flags (secure, httpOnly, sameSite)."""
    return _run(root, _SESSION_CONTROLS)


def jwt_hardening_scan(root: Path) -> List[ControlCheck]:
    """Check JWT decode sites actually verify and pin the algorithm."""
    return _run(root, _JWT_CONTROLS)


def cors_hardening_scan(root: Path) -> List[ControlCheck]:
    """Check CORS configuration uses an allowlist and scopes credentials."""
    return _run(root, _CORS_CONTROLS)


def auth_hardening_scan(root: Path) -> List[ControlCheck]:
    """Check that authentication uses login decorators and password hashing."""
    return _run(root, _AUTH_CONTROLS)
