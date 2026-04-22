"""Utilities to validate lazy re-export maps (``_LAZY_IMPORTS``) used by helper subpackages.

Used from tests to catch drift between ``__all__``, ``_LAZY_IMPORTS`` keys, and real submodule
attributes (and optionally submodule ``__all__`` when defined).

Building maps: use ``lazy_entry`` / ``lazy_group`` so each export name appears once and always
matches the target attribute (typos between dict key and ``(mod, attr)`` tuple are impossible).
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import List, Tuple


def lazy_entry(relative_module: str, attr_name: str) -> Tuple[str, Tuple[str, str]]:
    """One ``_LAZY_IMPORTS`` pair; export key is always ``attr_name``."""
    if not relative_module.startswith("."):
        raise ValueError(
            "relative_module must be a package-relative path starting with '.', "
            f"got {relative_module!r}"
        )
    return attr_name, (relative_module, attr_name)


def lazy_group(relative_module: str, *attr_names: str) -> List[Tuple[str, Tuple[str, str]]]:
    """Several exports from the same submodule (reduces duplicated module strings)."""
    return [lazy_entry(relative_module, n) for n in attr_names]


def validate_lazy_import_map(package: ModuleType) -> List[str]:
    """
    Check that each ``_LAZY_IMPORTS`` entry resolves and matches package ``__all__``.

    If a target submodule defines ``__all__``, the exported attribute must appear there so the
    lazy map stays aligned with the submodule's declared public API.

    Returns a list of human-readable error strings (empty when valid).
    """
    lazy = getattr(package, "_LAZY_IMPORTS", None)
    if lazy is None:
        return [f"{package.__name__}: missing _LAZY_IMPORTS"]
    errs: List[str] = []
    pkg_name = package.__name__
    lazy_keys = set(lazy.keys())
    pub = getattr(package, "__all__", None)
    if isinstance(pub, (list, tuple)):
        pub_set = set(pub)
        if lazy_keys != pub_set:
            only_lazy = sorted(lazy_keys - pub_set)
            only_all = sorted(pub_set - lazy_keys)
            errs.append(
                f"{pkg_name}: __all__ and _LAZY_IMPORTS keys differ "
                f"(only in _LAZY_IMPORTS: {only_lazy}; only in __all__: {only_all})"
            )

    for export_name, (rel_mod, attr_name) in lazy.items():
        if export_name != attr_name:
            errs.append(f"{pkg_name}: key {export_name!r} != attr_name {attr_name!r}")
            continue
        try:
            mod = importlib.import_module(rel_mod, package=pkg_name)
        except Exception as exc:  # pragma: no cover - defensive
            errs.append(f"{pkg_name}: cannot import {rel_mod!r}: {exc}")
            continue
        if not hasattr(mod, attr_name):
            errs.append(f"{pkg_name}: {mod.__name__}.{attr_name} does not exist")
            continue
        sub_all = getattr(mod, "__all__", None)
        if isinstance(sub_all, (list, tuple)) and attr_name not in sub_all:
            errs.append(
                f"{pkg_name}: {mod.__name__}.{attr_name} missing from submodule __all__ "
                f"(update {mod.__name__} or fix _LAZY_IMPORTS)"
            )

    return errs
