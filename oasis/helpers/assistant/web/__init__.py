"""Assistant HTTP contract, RAG, persistence, and request preparation.

Re-exports are **lazy** so ``import oasis.helpers.assistant.web`` (or the root ``assistant`` package)
does not load every submodule up front; attributes resolve on first access.
"""

from __future__ import annotations

import importlib
from typing import Any

from oasis.helpers.lazy_export_validation import lazy_group

# Built with ``lazy_group``; validated by ``tests.test_helpers_lazy_subpackage_exports``.
_LAZY_IMPORTS: dict[str, tuple[str, str]] = dict(
    [
        *lazy_group(".http_contract", "assistant_http_error"),
        *lazy_group(
            ".api_validate",
            "coerce_finding_indices",
            "coerce_optional_index",
            "normalize_report_rel_query_arg",
            "resolve_assistant_primary_payload",
            "resolve_assistant_report_json_path",
            "validate_assistant_messages",
        ),
        *lazy_group(
            ".persistence",
            "branch_key",
            "chat_dir_for_report_json",
            "delete_all_chat_sessions",
            "delete_chat_session",
            "ensure_session_views",
            "finding_validation_storage_key",
            "get_finding_validation_for_branch",
            "list_chat_sessions",
            "load_chat_session",
            "merge_finding_validation_into_session",
            "new_session_id",
            "normalize_validated_messages_for_storage",
            "resolve_report_json",
            "save_chat_session",
            "save_session_branch_messages",
            "utc_now_iso",
            "validate_session_id",
        ),
        *lazy_group(
            ".rag",
            "embedding_cache_file_path",
            "json_finding_slice",
            "load_embedding_code_base",
            "resolve_assistant_cache_root",
            "retrieve_relevant_snippets",
        ),
        *lazy_group(
            ".web_prepare",
            "build_assistant_finding_json_prompt_block",
            "build_report_summary_payload",
            "extract_last_user_message_text",
            "full_messages_from_system_and_dialogue",
            "prepare_aggregate_branch_paths",
            "resolve_assistant_chat_model",
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
