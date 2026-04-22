"""Verdict-first system prompt layout: assembly, per-section shrink cascade, subbudgets.

Validation JSON compaction: :mod:`oasis.helpers.assistant_verdict_validation`.
Label hard-cap: :mod:`oasis.helpers.assistant_prompt_shrink`.
Tuning: :mod:`oasis.helpers.assistant_prompt_tuning`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from oasis.helpers.assistant_prompt_shrink import (
    VerdictPromptHardCapConfig,
    hard_cap_verdict_prompt_if_needed,
)
from oasis.helpers.assistant_prompt_tuning import (
    CHAT_EXCERPT_TRUNC_SUFFIX,
    CHAT_RAG_TRUNC_SUFFIX,
    CHAT_SECTION_TRUNC_SUFFIX,
    FINDING_VALIDATION_LABEL,
    REPORT_SUMMARY_LABEL,
    RETRIEVAL_CONTEXT_LABEL,
    SELECTED_FINDING_LABEL,
    SUBBUDGET_REPORT_SUMMARY_MAX,
    USER_NOTES_LABEL,
    VALIDATION_MAX_RATIO,
    verdict_subbudget_ratios,
)
from oasis.helpers.assistant_verdict_validation import (
    _extract_authoritative_subset,
    _fit_validation_to_budget,
    _serialize,
    compact_validation_for_chat,
)

logger = logging.getLogger(__name__)

_VERDICT_HARD_CAP_CFG = VerdictPromptHardCapConfig(
    trunc_suffix=CHAT_SECTION_TRUNC_SUFFIX,
    section_label_prefixes=(
        FINDING_VALIDATION_LABEL,
        SELECTED_FINDING_LABEL,
        RETRIEVAL_CONTEXT_LABEL,
        REPORT_SUMMARY_LABEL,
        USER_NOTES_LABEL,
    ),
)


def _shrink(text: str, target: int, suffix: str) -> str:
    if target <= 0:
        return ""
    if len(text) <= target:
        return text
    if target <= len(suffix):
        return text[:target]
    return text[: max(0, target - len(suffix))] + suffix


def shrink_rag_block(rag_block: str, max_chars: int) -> str:
    """Truncate a RAG block with the canonical chat suffix (external callers, e.g. web)."""
    return _shrink(rag_block or "", max(0, max_chars), CHAT_RAG_TRUNC_SUFFIX)


def shrink_user_labels_block(user_labels: str, max_chars: int) -> str:
    """Truncate user triage notes with the canonical suffix."""
    return _shrink(user_labels or "", max(0, max_chars), CHAT_SECTION_TRUNC_SUFFIX)


def _labeled(label: str, body: str) -> str:
    return "\n\n" + label + "\n" + body if body else ""


def _assemble(
    *,
    intro: str,
    validation: str,
    selected_finding: str,
    rag: str,
    report_summary: str,
    labels: str,
) -> str:
    parts = [intro]
    if validation:
        parts.append(_labeled(FINDING_VALIDATION_LABEL, validation))
    if selected_finding:
        parts.append(_labeled(SELECTED_FINDING_LABEL, selected_finding))
    if rag:
        parts.append(_labeled(RETRIEVAL_CONTEXT_LABEL, rag))
    if report_summary:
        parts.append(_labeled(REPORT_SUMMARY_LABEL, report_summary))
    if labels:
        parts.append(_labeled(USER_NOTES_LABEL, labels))
    return "".join(parts)


@dataclass
class VerdictPromptAssembly:
    """Holds all mutable prompt sections for the verdict-first shrink pipeline."""

    intro: str = ""
    validation: str = ""
    selected: str = ""
    rag: str = ""
    summary: str = ""
    labels: str = ""

    def reassemble(self) -> str:
        return _assemble(
            intro=self.intro,
            validation=self.validation,
            selected_finding=self.selected,
            rag=self.rag,
            report_summary=self.summary,
            labels=self.labels,
        )


@dataclass
class VerdictSectionLengths:
    """Length diagnostics for the assembled verdict-first system prompt (stable keys)."""

    intro: int = 0
    validation: int = 0
    selected_finding: int = 0
    rag: int = 0
    report_summary: int = 0
    user_labels: int = 0
    total: int = 0
    validation_ratio_cap: int = 0
    validation_fit_pass: str = "none"
    validation_lists_dropped: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "intro": self.intro,
            "validation": self.validation,
            "selected_finding": self.selected_finding,
            "rag": self.rag,
            "report_summary": self.report_summary,
            "user_labels": self.user_labels,
            "total": self.total,
            "validation_ratio_cap": self.validation_ratio_cap,
            "validation_fit_pass": self.validation_fit_pass,
            "validation_lists_dropped": list(self.validation_lists_dropped),
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]


def _prepare_validation_block(
    finding_validation: Optional[Dict[str, Any]],
    total_budget: int,
) -> Tuple[str, Dict[str, Any], int]:
    fit_stats: Dict[str, Any] = {
        "validation_fit_pass": "none",
        "validation_lists_dropped": [],
    }
    if not finding_validation:
        return "", fit_stats, 0
    compact = compact_validation_for_chat(finding_validation) or {}
    ratio_cap = max(0, int(total_budget * VALIDATION_MAX_RATIO))
    if ratio_cap > 0:
        serialized, fit_stats = _fit_validation_to_budget(compact, max_chars=ratio_cap)
        return serialized, fit_stats, ratio_cap
    serialized = _serialize(_extract_authoritative_subset(compact))
    fit_stats["validation_fit_pass"] = "core_only_no_budget"
    return serialized, fit_stats, ratio_cap


def _shrink_labels_then_drop(
    assembly: VerdictPromptAssembly, body: str, total_budget: int
) -> str:
    if len(body) <= total_budget or not assembly.labels:
        return body
    overhead = len(body) - total_budget
    labels = assembly.labels
    shrunk = _shrink(
        labels, max(0, len(labels) - overhead), CHAT_SECTION_TRUNC_SUFFIX
    )
    if shrunk and shrunk != labels:
        assembly.labels = shrunk
        body = assembly.reassemble()
    if len(body) > total_budget and assembly.labels:
        assembly.labels = ""
        body = assembly.reassemble()
    return body


_SimpleShrinkStep = Tuple[str, str, Optional[str]]
_SIMPLE_SHRINK_STEPS: Tuple[_SimpleShrinkStep, ...] = (
    ("summary", CHAT_EXCERPT_TRUNC_SUFFIX, None),
    ("rag", CHAT_RAG_TRUNC_SUFFIX, None),
    (
        "selected",
        CHAT_SECTION_TRUNC_SUFFIX,
        "SELECTED_FINDING_JSON truncated to fit system budget (len=%s)",
    ),
)


def _apply_simple_shrink_cascade(
    assembly: VerdictPromptAssembly, body: str, total_budget: int
) -> str:
    for section_key, suffix, warn_fmt in _SIMPLE_SHRINK_STEPS:
        if len(body) <= total_budget:
            return body
        text: str = getattr(assembly, section_key)
        if not text:
            continue
        overhead = len(body) - total_budget
        shrunk = _shrink(text, max(0, len(text) - overhead), suffix)
        if shrunk == text:
            continue
        setattr(assembly, section_key, shrunk)
        body = assembly.reassemble()
        if warn_fmt:
            logger.warning(warn_fmt, len(shrunk))
    return body


def _try_refit_validation(
    assembly: VerdictPromptAssembly,
    body: str,
    finding_validation: Optional[Dict[str, Any]],
    fit_stats: Dict[str, Any],
    total_budget: int,
) -> str:
    if (
        len(body) <= total_budget
        or not assembly.validation
        or finding_validation is None
    ):
        return body
    overhead = len(body) - total_budget
    new_cap = max(0, len(assembly.validation) - overhead)
    if new_cap <= 0:
        return body
    compact = compact_validation_for_chat(finding_validation) or {}
    validation_raw, extra_stats = _fit_validation_to_budget(compact, max_chars=new_cap)
    assembly.validation = validation_raw
    fit_stats["validation_fit_pass"] = extra_stats.get(
        "validation_fit_pass", fit_stats["validation_fit_pass"]
    )
    if dropped_extra := extra_stats.get("validation_lists_dropped") or []:
        existing = set(fit_stats.get("validation_lists_dropped") or [])
        existing.update(dropped_extra)
        fit_stats["validation_lists_dropped"] = sorted(existing)
    body = assembly.reassemble()
    logger.warning(
        "FINDING_VALIDATION_JSON further compacted to fit system budget "
        "(new_len=%s pass=%s)",
        len(validation_raw),
        fit_stats["validation_fit_pass"],
    )
    return body


def _run_verdict_first_shrink_stages(
    assembly: VerdictPromptAssembly,
    body: str,
    total_budget: int,
    finding_validation: Optional[Dict[str, Any]],
    fit_stats: Dict[str, Any],
) -> str:
    body = _shrink_labels_then_drop(assembly, body, total_budget)
    body = _apply_simple_shrink_cascade(assembly, body, total_budget)
    body = _try_refit_validation(
        assembly, body, finding_validation, fit_stats, total_budget
    )
    return hard_cap_verdict_prompt_if_needed(
        body,
        total_budget,
        len(assembly.validation),
        config=_VERDICT_HARD_CAP_CFG,
        logger=logger,
    )


def assemble_verdict_first_prompt(
    *,
    system_intro: str,
    finding_validation: Optional[Dict[str, Any]],
    selected_finding_json: str,
    rag_block: str,
    report_summary: str,
    user_labels: str,
    total_budget: int,
) -> Tuple[str, VerdictSectionLengths]:
    """Build the final system prompt with verdict-first layout."""
    assembly = VerdictPromptAssembly(
        intro=system_intro or "",
        selected=selected_finding_json or "",
        rag=rag_block or "",
        summary=report_summary or "",
        labels=user_labels or "",
        validation="",
    )
    validation_raw, fit_stats, validation_ratio_cap = _prepare_validation_block(
        finding_validation, total_budget
    )
    assembly.validation = validation_raw

    body = assembly.reassemble()
    body = _run_verdict_first_shrink_stages(
        assembly, body, total_budget, finding_validation, fit_stats
    )

    section_lengths = VerdictSectionLengths(
        intro=len(assembly.intro),
        validation=len(assembly.validation),
        selected_finding=len(assembly.selected),
        rag=len(assembly.rag),
        report_summary=len(assembly.summary),
        user_labels=len(assembly.labels),
        total=len(body),
        validation_ratio_cap=validation_ratio_cap,
        validation_fit_pass=str(fit_stats.get("validation_fit_pass", "none")),
        validation_lists_dropped=list(fit_stats.get("validation_lists_dropped") or []),
    )

    if (
        validation_ratio_cap > 0
        and assembly.validation
        and len(assembly.validation) >= validation_ratio_cap
    ):
        logger.warning(
            "FINDING_VALIDATION_JSON hit the chat ratio cap (len=%s cap=%s pass=%s); "
            "consider reviewing validation volume for this finding.",
            len(assembly.validation),
            validation_ratio_cap,
            fit_stats.get("validation_fit_pass"),
        )

    return body, section_lengths


def compute_verdict_first_subbudgets(total_budget: int) -> Dict[str, int]:
    """Per-section soft caps (characters) for sizing inputs before assembly."""
    total = max(0, total_budget)
    ratios = verdict_subbudget_ratios()
    return {
        "selected_finding": int(total * ratios["selected_finding"]),
        "rag": int(total * ratios["rag"]),
        "report_summary": min(
            int(total * ratios["report_summary"]),
            SUBBUDGET_REPORT_SUMMARY_MAX,
        ),
        "user_labels": int(total * ratios["user_labels"]),
    }
