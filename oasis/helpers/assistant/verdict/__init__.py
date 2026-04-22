"""Verdict assembly, validation, and first-prompt composition.

The ``__all__`` list below is the one hand-maintained export surface (child modules do not all
define their own ``__all__``). Add re-exports here and the explicit ``from .… import`` above in
one place to limit star-import and cycle issues; for a pattern with per-file ``__all__`` only,
see :mod:`oasis.helpers.assistant.prompt`.
"""

from __future__ import annotations

from .verdict import VerdictInputs, compute_verdict
from .verdict_assembly import (
    VerdictPromptAssembly,
    VerdictSectionLengths,
    assemble_verdict_first_prompt,
    compute_verdict_first_subbudgets,
    shrink_rag_block,
    shrink_user_labels_block,
)
from .verdict_validation import (
    compact_validation_for_chat,
    serialize_finding_validation,
)

__all__ = [
    "VerdictInputs",
    "VerdictPromptAssembly",
    "VerdictSectionLengths",
    "assemble_verdict_first_prompt",
    "compact_validation_for_chat",
    "compute_verdict",
    "compute_verdict_first_subbudgets",
    "serialize_finding_validation",
    "shrink_rag_block",
    "shrink_user_labels_block",
]
