"""Code scanning, traces, taint, aggregates, and entry-point discovery.

Re-exports are **lazy** (see ``_LAZY_IMPORTS``): ``from ..scan.scan_utils import …`` does not
eagerly import heavier siblings such as ``scan_aggregate`` (and transitively ``oasis.report``).
"""

from __future__ import annotations

import importlib
from typing import Any

from oasis.helpers.lazy_export_validation import lazy_group

# Built with ``lazy_group`` so export keys always match submodule attributes.
# Validated by ``tests.test_helpers_lazy_subpackage_exports``.
_LAZY_IMPORTS: dict[str, tuple[str, str]] = dict(
    [
        *lazy_group(
            ".scan_aggregate",
            "build_aggregate_assistant_document",
            "first_vulnerability_payload_from_paths",
            "iter_json_report_paths_in_model_dir",
            "model_directory_from_security_report_file",
            "resolve_canonical_json_for_markdown_report",
            "security_relative_posix",
            "union_file_paths_from_vulnerability_payloads",
        ),
        *lazy_group(
            ".scan_utils",
            "citation_from_match",
            "compile_groups",
            "iter_source_files",
            "read_text_safely",
            "ripgrep_available",
            "scan_patterns",
            "scan_patterns_best_effort",
            "scan_with_ripgrep",
            "unique_hits",
        ),
        *lazy_group(".taint", "detect_flows_for_descriptor", "detect_flows_for_sink"),
        *lazy_group(
            ".entrypoints",
            "discover_entry_points",
            "entry_points_for_file",
            "invalidate_cache",
        ),
        *lazy_group(
            ".mitigations",
            "find_mitigations_in_file",
            "find_mitigations_in_root",
            "has_nullifying_mitigation",
        ),
        *lazy_group(".config_audit", "run_config_audit"),
        *lazy_group(".crypto_scan", "run_crypto_scan"),
        *lazy_group(".log_filter", "run_log_filter_scan"),
        *lazy_group(".secret_scan", "run_secret_scan"),
        *lazy_group(
            ".trace",
            "enclosing_symbol",
            "enclosing_symbol_with_line",
            "find_callers",
            "sample_files_for_scan",
            "trace_to_entry_points",
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
