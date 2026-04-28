"""Shared Jinja2 filters for HTML report templates (numeric formatting, etc.)."""

from __future__ import annotations

from typing import Any

from jinja2 import Environment
from jinja2.runtime import Undefined


def audit_decimal_places(value: Any, places: int) -> str:
    """Format a numeric audit value with fixed precision; empty string if missing or invalid."""
    if value is None or isinstance(value, Undefined):
        return ""
    try:
        n = float(value)
    except (TypeError, ValueError):
        return ""
    if places == 1:
        return f"{n:.1f}"
    if places == 3:
        return f"{n:.3f}"
    fmt = f"{{:.{places}f}}"
    return fmt.format(n)


def register_report_template_filters(env: Environment) -> None:
    env.filters["audit_decimal"] = audit_decimal_places
