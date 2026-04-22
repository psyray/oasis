"""Vulnerability taxonomy and validation regex patterns (assistant graph).

This package ``__all__`` is exactly the sorted union of ``taxonomy.__all__`` and
``validation_patterns.__all__``—extend those leaf modules rather than editing names in two places.
"""

from __future__ import annotations

from . import taxonomy
from . import validation_patterns
from .taxonomy import *  # noqa: F401,F403
from .validation_patterns import *  # noqa: F401,F403

__all__ = sorted({*taxonomy.__all__, *validation_patterns.__all__})
