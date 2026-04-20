"""Internal helper submodules: dashboard, embedding, progress, scan, langgraph_cli, poc, misc (see each file).

Submodules import without eager-loading unrelated helpers (avoids heavy optional deps when importing
only lightweight modules such as ``exec_summary_tiers``).

**Package API (lazy re-exports)**

Public names are defined only in ``_LAZY_IMPORTS``; ``__all__`` is derived from its keys so they
cannot drift (see ``tests/test_helpers_lazy_exports.py``). Prefer ``from oasis.helpers import …``
for symbols in ``__all__``. Importing the same names from submodules (``oasis.helpers.progress``,
etc.) is fine for focused modules.
"""

from __future__ import annotations

import importlib
from typing import Any

# Lazy targets must stay lightweight: each submodule should avoid importing heavy optional
# stacks at import time, and must not create import cycles back through ``oasis.helpers``
# (``importlib.import_module`` runs the submodule body once per process). Prefer defining
# symbols without eager cross-imports so ``from oasis.helpers import X`` stays cheap.

_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "EMBEDDING_PROGRESS_MIN_INTERVAL_SEC": (".embedding", "EMBEDDING_PROGRESS_MIN_INTERVAL_SEC"),
    "EmbeddingProgressThrottle": (".embedding", "EmbeddingProgressThrottle"),
    "EXEC_SUMMARY_PROGRESS_EVENT_VERSION": (".progress", "EXEC_SUMMARY_PROGRESS_EVENT_VERSION"),
    "SCAN_PROGRESS_EXTENDED_KEYS": (".progress", "SCAN_PROGRESS_EXTENDED_KEYS"),
    "tqdm_safe_log": (".progress", "tqdm_safe_log"),
    "adaptive_after_batch_extras": (".progress", "adaptive_after_batch_extras"),
    "adaptive_after_identification_extras": (".progress", "adaptive_after_identification_extras"),
    "adaptive_collect_step_extras": (".progress", "adaptive_collect_step_extras"),
    "adaptive_final_summary_extras": (".progress", "adaptive_final_summary_extras"),
    "adaptive_identification_start_extras": (".progress", "adaptive_identification_start_extras"),
    "adaptive_identifying_loop_extras": (".progress", "adaptive_identifying_loop_extras"),
    "adaptive_progress_extras": (".progress", "adaptive_progress_extras"),
    "coerce_scan_progress_event_version": (".progress", "coerce_scan_progress_event_version"),
    "reset_tqdm_phase_bar": (".progress", "reset_tqdm_phase_bar"),
    "standard_deep_phase_extras": (".progress", "standard_deep_phase_extras"),
    "standard_final_complete_extras": (".progress", "standard_final_complete_extras"),
    "standard_initial_iteration_extras": (".progress", "standard_initial_iteration_extras"),
    "standard_initial_sweep_extras": (".progress", "standard_initial_sweep_extras"),
    "standard_progress_extras": (".progress", "standard_progress_extras"),
    "PhaseTriple": (".scan", "PhaseTriple"),
    "adaptive_phases_identifying": (".scan", "adaptive_phases_identifying"),
    "adaptive_scan_phases": (".scan", "adaptive_scan_phases"),
    "adaptive_subphases_during_identification": (".scan", "adaptive_subphases_during_identification"),
    "adaptive_subphases_payload": (".scan", "adaptive_subphases_payload"),
    "embedding_phase_row": (".scan", "embedding_phase_row"),
    "phase_progress_row": (".scan", "phase_progress_row"),
    "phase_triple": (".scan", "phase_triple"),
    "safe_code_base_file_count": (".scan", "safe_code_base_file_count"),
    "standard_scan_phases": (".scan", "standard_scan_phases"),
    "standard_scan_phases_vuln_types": (".scan", "standard_scan_phases_vuln_types"),
}

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
