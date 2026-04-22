"""Executive summary: assistant scope, dashboard preview, chart metadata.

Re-exports are **lazy** (see ``_LAZY_IMPORTS``): ``import oasis.helpers.executive`` does not pull
``assistant_scope`` (and transitively ``scan_aggregate`` / ``oasis.report``) until a symbol is used.
"""

from __future__ import annotations

import importlib
from typing import Any

from oasis.helpers.lazy_export_validation import lazy_group

_LAZY_IMPORTS: dict[str, tuple[str, str]] = dict(
    [
        *lazy_group(".dashboard_preview", "augment_executive_markdown_preview_html"),
        *lazy_group(".modal_chart_meta", "rollup_severity_counts_from_model_dir"),
        *lazy_group(
            ".assistant_scope",
            "resolve_aggregate_finding_scope_payload",
            "synthetic_executive_primary_payload",
            "vulnerability_reports_for_executive_assistant",
        ),
    ]
)

__all__ = sorted(_LAZY_IMPORTS.keys())


def __getattr__(name: str) -> Any:
    spec = _LAZY_IMPORTS.get(name)
    if spec is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    mod_path, attr_name = spec
    mod = importlib.import_module(mod_path, package=__package__)
    value = getattr(mod, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(__all__)
