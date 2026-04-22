"""Dashboard assistant helper package (scan, authz, verdict, prompt, web, think).

Subpackages load **lazily** (first attribute access) so ``import oasis.helpers.assistant`` stays
lightweight; use ``from oasis.helpers.assistant.scan import ...`` for direct imports.
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import Any

# Submodule names surfaced as attributes; changing this set changes ``__dir__`` / ``from … import``.
_SUBPACKAGES = frozenset({"authz", "prompt", "scan", "think", "verdict", "web"})

__all__ = sorted(_SUBPACKAGES)


def __getattr__(name: str) -> Any:
    if name in _SUBPACKAGES:
        mod: ModuleType = importlib.import_module(f".{name}", __package__)
        globals()[name] = mod
        return mod
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted({*__all__, *globals()})
