"""Verdict-first assistant system prompt (compatibility re-exports).

Implementation is split for maintainability:

- :mod:`oasis.helpers.assistant_verdict_validation` — ``FINDING_VALIDATION_JSON``
  compaction and ratio fit.
- :mod:`oasis.helpers.assistant_verdict_assembly` — section assembly, shrink
  cascade, subbudgets, :class:`VerdictPromptAssembly`.

Tuning index: :mod:`oasis.helpers.assistant_prompt_tuning`.
"""

from __future__ import annotations

from oasis.helpers.assistant_prompt_tuning import (
    FINDING_VALIDATION_LABEL,
    REPORT_SUMMARY_LABEL,
    RETRIEVAL_CONTEXT_LABEL,
    SELECTED_FINDING_LABEL,
    USER_NOTES_LABEL,
)
from oasis.helpers.assistant_verdict_assembly import (
    VerdictPromptAssembly,
    VerdictSectionLengths,
    assemble_verdict_first_prompt,
    compute_verdict_first_subbudgets,
    shrink_rag_block,
    shrink_user_labels_block,
)
from oasis.helpers.assistant_verdict_validation import (
    compact_validation_for_chat,
    serialize_finding_validation,
)

__all__ = [
    "FINDING_VALIDATION_LABEL",
    "REPORT_SUMMARY_LABEL",
    "RETRIEVAL_CONTEXT_LABEL",
    "SELECTED_FINDING_LABEL",
    "USER_NOTES_LABEL",
    "VerdictPromptAssembly",
    "VerdictSectionLengths",
    "assemble_verdict_first_prompt",
    "compact_validation_for_chat",
    "compute_verdict_first_subbudgets",
    "serialize_finding_validation",
    "shrink_rag_block",
    "shrink_user_labels_block",
]
