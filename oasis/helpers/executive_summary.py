"""Executive-summary shaping helpers shared by JSON and HTML report rendering."""

from __future__ import annotations

import hashlib
import math
from typing import Any, Dict, List, Optional, TypedDict, Tuple

import markdown

from oasis.config import REPORT
from oasis.helpers.dashboard import (
    EXEC_SUMMARY_EMBEDDING_TIER_ORDER,
    EXEC_SUMMARY_EMBEDDING_TIERS,
    dashboard_reports_href,
    executive_summary_tier_heading,
    preferred_detail_relative_path_and_format,
)
from oasis.helpers.progress import (
    scan_progress_status_meta,
    scan_progress_vulnerability_counts,
)
from oasis.tools import logger


class ExecutiveSimilarityFindingInput(TypedDict, total=False):
    """Input finding shape used to build executive similarity highlight rows."""

    vuln_type: str
    file_path: str
    score: Any


class ExecutiveSimilarityHighlightRow(TypedDict, total=False):
    """Row shape consumed by executive summary JSON and HTML tables."""

    tier_id: str
    tier_name: str
    tier_description: str
    vuln_type: str
    file_path: str
    similarity_score: float
    detail_href: str


class ExecutiveGuidanceVariant(TypedDict):
    id: str
    markdown: str


_EXECUTIVE_GUIDANCE_VARIANTS: Tuple[ExecutiveGuidanceVariant, ...] = (
    {"id": "default.v1", "markdown": REPORT["EXPLAIN_EXECUTIVE_SUMMARY"].strip()},
)
_EXECUTIVE_GUIDANCE_BY_ID: Dict[str, str] = {
    variant["id"]: variant["markdown"] for variant in _EXECUTIVE_GUIDANCE_VARIANTS
}
_EXECUTIVE_GUIDANCE_HASH_TO_ID: Dict[str, str] = {
    hashlib.sha256(variant["markdown"].encode("utf-8")).hexdigest(): variant["id"]
    for variant in _EXECUTIVE_GUIDANCE_VARIANTS
}
_DEFAULT_EXECUTIVE_GUIDANCE_ID = _EXECUTIVE_GUIDANCE_VARIANTS[0]["id"]


# Similarity score + tier metadata helpers (shared by canonical JSON and HTML enrichment).
def _safe_similarity_score(
    raw_score: Any,
    *,
    fallback: float = 0.0,
    vuln_type: str = "",
    file_path: str = "",
) -> float:
    """Convert executive-summary similarity score defensively."""
    score_ctx = f" vuln_type={vuln_type!r} file_path={file_path!r}" if (vuln_type or file_path) else ""
    try:
        parsed = float(raw_score)
    except (TypeError, ValueError):
        logger.warning(
            "Executive summary JSON: non-numeric similarity score encountered; "
            "falling back to %s. raw_score=%r.%s",
            fallback,
            raw_score,
            score_ctx,
        )
        return fallback
    if not math.isfinite(parsed):
        logger.warning(
            "Executive summary JSON: non-finite similarity score encountered; "
            "falling back to %s. raw_score=%r.%s",
            fallback,
            raw_score,
            score_ctx,
        )
        return fallback
    return parsed


def executive_tier_name_and_description_for_id(tier_id: str) -> Tuple[str, str]:
    """Canonical tier label and tooltip text for ``tier_id``."""
    tier_obj = next((t for t in EXEC_SUMMARY_EMBEDDING_TIERS if t["id"] == tier_id), None)
    if tier_obj is None:
        return tier_id, tier_id
    return tier_obj["name"], executive_summary_tier_heading(tier_obj)


def trusted_guidance_markdown_for_executive_html(payload: Dict[str, Any]) -> str:
    """Return trusted guidance markdown for executive-summary HTML rendering.

    Trust policy:
    - require ``guidance_id`` mapped to a known variant,
    - require ``guidance_markdown`` to match that variant text and digest,
    - fallback to default bundled guidance for unknown/mismatched payloads.
    """
    raw = payload.get("guidance_markdown")
    if isinstance(raw, str) and raw.strip():
        normalized = raw.strip()
        guidance_id = str(payload.get("guidance_id") or "").strip()
        trusted = _EXECUTIVE_GUIDANCE_BY_ID.get(guidance_id)
        if trusted is None:
            msg = "Executive summary HTML: %s guidance_id=%r; using built-in explanation."
            if guidance_id:
                logger.warning(msg, "unknown", guidance_id)
            else:
                logger.debug(msg, "missing", None)
            return _EXECUTIVE_GUIDANCE_BY_ID[_DEFAULT_EXECUTIVE_GUIDANCE_ID]
        computed_guidance_id = _guidance_variant_id_from_markdown(normalized)
        expected_digest = hashlib.sha256(trusted.encode("utf-8")).hexdigest()
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        if normalized == trusted and digest == expected_digest:
            return normalized
        logger.warning(
            "Executive summary HTML: guidance content mismatch for guidance_id=%r "
            "(computed=%r, expected_sha256=%s..., actual_sha256=%s...); "
            "using built-in explanation.",
            guidance_id or None,
            computed_guidance_id,
            expected_digest[:12],
            digest[:12],
        )
    return _EXECUTIVE_GUIDANCE_BY_ID[_DEFAULT_EXECUTIVE_GUIDANCE_ID]


def executive_tier_definitions_payload() -> List[Dict[str, str]]:
    return [
        {
            "id": tier["id"],
            "name": tier["name"],
            "description": executive_summary_tier_heading(tier),
        }
        for tier in EXEC_SUMMARY_EMBEDDING_TIERS
    ]


def executive_similarity_highlights_rows(
    similarity_groups: Dict[str, List[ExecutiveSimilarityFindingInput]],
    *,
    max_per_tier: int = 25,
) -> List[ExecutiveSimilarityHighlightRow]:
    rows: List[ExecutiveSimilarityHighlightRow] = []
    for tier_id, _ in EXEC_SUMMARY_EMBEDDING_TIER_ORDER:
        findings = list(similarity_groups.get(tier_id) or [])
        scored_findings: List[Tuple[ExecutiveSimilarityFindingInput, float]] = []
        for finding in findings:
            vuln_type = str(finding.get("vuln_type", ""))
            file_path = str(finding.get("file_path", ""))
            safe_score = _safe_similarity_score(
                finding.get("score", 0.0),
                vuln_type=vuln_type,
                file_path=file_path,
            )
            scored_findings.append((finding, safe_score))
        scored_findings.sort(key=lambda pair: pair[1], reverse=True)
        rows.extend(
            _row_with_resolved_tier_metadata(
                {
                    "tier_id": tier_id,
                    "vuln_type": str(finding.get("vuln_type", "")),
                    "file_path": str(finding.get("file_path", "")),
                    "similarity_score": round(safe_score, 4),
                }
            )
            for finding, safe_score in scored_findings[:max_per_tier]
        )
    return rows


def enrich_similarity_highlight_row_for_executive_html(
    row: Dict[str, Any],
    report: Any,
) -> ExecutiveSimilarityHighlightRow:
    """Add tier tooltip and dashboard detail link to one executive highlight row."""
    merged = _row_with_resolved_tier_metadata(dict(row))
    stem = _detail_report_stem_from_similarity_row(merged)
    detail_href = ""
    if stem:
        try:
            rel_path, _fmt = preferred_detail_relative_path_and_format(report, stem)
            detail_href = dashboard_reports_href(rel_path)
        except (FileNotFoundError, KeyError, ValueError) as exc:
            logger.warning(
                "Executive summary HTML: could not build detail link for vuln_type=%r; %s",
                merged.get("vuln_type"),
                exc,
            )
            detail_href = ""
    merged["detail_href"] = detail_href
    return merged


def _row_with_resolved_tier_metadata(row: Dict[str, Any]) -> ExecutiveSimilarityHighlightRow:
    """Ensure row exposes canonical ``tier_name`` and ``tier_description`` from ``tier_id``."""
    merged: ExecutiveSimilarityHighlightRow = dict(row)
    tid = str(merged.get("tier_id") or "").strip()
    if not tid:
        return merged
    tier_name, tier_description = executive_tier_name_and_description_for_id(tid)
    merged["tier_id"] = tid
    if not str(merged.get("tier_name") or "").strip():
        merged["tier_name"] = tier_name
    if not str(merged.get("tier_description") or "").strip():
        merged["tier_description"] = tier_description
    return merged


# Guidance and top-level summary normalization helpers.
def _sorted_summary_items(mapping: Any) -> List[Tuple[Any, Any]]:
    if not isinstance(mapping, dict):
        return []
    return sorted(mapping.items(), key=lambda item: str(item[0]).lower())


def _render_guidance_html(payload: Dict[str, Any]) -> str:
    return markdown.markdown(
        trusted_guidance_markdown_for_executive_html(payload),
        extensions=["tables", "fenced_code", "codehilite"],
    )


def _executive_summary_lead_text() -> str:
    lead = REPORT.get("EXECUTIVE_SUMMARY_LEAD")
    return str(lead).strip() if isinstance(lead, str) else ""


def _derive_overview_defaults(
    payload: Dict[str, Any],
    vulnerability_summary_items: List[Tuple[Any, Any]],
    highlights_in: List[Dict[str, Any]],
) -> Dict[str, Any]:
    overview_raw = payload.get("overview")
    overview_in = dict(overview_raw) if isinstance(overview_raw, dict) else {}
    overview: Dict[str, Any] = {
        "vulnerability_types_count": _coerce_non_negative_int(
            overview_in.get("vulnerability_types_count"),
            fallback=len(vulnerability_summary_items),
            key_name="vulnerability_types_count",
        ),
        "embedding_comparisons_total": _coerce_non_negative_int(
            overview_in.get("embedding_comparisons_total"),
            fallback=None,
            key_name="embedding_comparisons_total",
            allow_none_fallback=True,
        ),
        "unique_source_files": _coerce_optional_non_negative_int(
            overview_in.get("unique_source_files"),
            key_name="unique_source_files",
        ),
    }
    if overview.get("unique_source_files") is None and highlights_in:
        unique_paths = {
            str(fp)
            for row in highlights_in
            if isinstance(row, dict) and (fp := row.get("file_path"))
        }
        if unique_paths:
            overview["unique_source_files"] = len(unique_paths)
    return overview


def _normalize_similarity_highlights(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = payload.get("similarity_highlights")
    if not isinstance(raw, list):
        return []
    return [_row_with_resolved_tier_metadata(row) for row in raw if isinstance(row, dict)]


def _normalize_tier_definitions(payload: Dict[str, Any]) -> List[Dict[str, str]]:
    raw = payload.get("tier_definitions")
    if not isinstance(raw, list):
        return executive_tier_definitions_payload()
    normalized: List[Dict[str, str]] = []
    for row in raw:
        if not isinstance(row, dict):
            continue
        tier_id = str(row.get("id") or "").strip()
        tier_name = str(row.get("name") or "").strip()
        tier_desc = str(row.get("description") or "").strip()
        if not tier_id and not tier_name and not tier_desc:
            continue
        if not tier_name and tier_id:
            tier_name, _default_desc = executive_tier_name_and_description_for_id(tier_id)
        if not tier_desc and tier_id:
            _default_name, tier_desc = executive_tier_name_and_description_for_id(tier_id)
        normalized.append(
            {
                "id": tier_id,
                "name": tier_name,
                "description": tier_desc,
            }
        )
    return normalized or executive_tier_definitions_payload()


def _coerce_non_negative_int(
    raw: Any,
    *,
    fallback: Optional[int],
    key_name: str,
    allow_none_fallback: bool = False,
) -> Optional[int]:
    if raw is None and allow_none_fallback:
        return fallback
    try:
        val = int(raw)
        return max(0, val)
    except (TypeError, ValueError):
        if raw is not None:
            logger.warning(
                "Executive summary HTML: invalid %s=%r; using fallback %s",
                key_name,
                raw,
                fallback,
            )
        return fallback


def _coerce_optional_non_negative_int(raw: Any, *, key_name: str) -> Optional[int]:
    if raw is None:
        return None
    return _coerce_non_negative_int(raw, fallback=None, key_name=key_name, allow_none_fallback=True)


def _guidance_variant_id_from_markdown(markdown_text: str) -> Optional[str]:
    digest = hashlib.sha256(markdown_text.encode("utf-8")).hexdigest()
    return _EXECUTIVE_GUIDANCE_HASH_TO_ID.get(digest)


def _detail_report_stem_from_similarity_row(row: Dict[str, Any]) -> str:
    """Resolve detail-report stem from canonical row keys before fallback derivation."""
    for key in ("vuln_stem", "vuln_slug", "vulnerability_stem", "vulnerability_slug"):
        raw = row.get(key)
        if isinstance(raw, str) and raw.strip():
            return raw.strip().lower()
    raw_vuln = str(row.get("vuln_type", "")).strip()
    return raw_vuln.lower().replace(" ", "_")


# Progress payload shaping helper.
def _build_progress_summary(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    prog = payload.get("progress")
    if not isinstance(prog, dict):
        return None
    try:
        completed, total = scan_progress_vulnerability_counts(prog)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        logger.warning(
            "Executive summary HTML: invalid progress counts payload; %s",
            exc,
        )
        return None
    try:
        is_partial, _sk, status_label = scan_progress_status_meta(prog)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        logger.warning(
            "Executive summary HTML: invalid progress status payload; %s",
            exc,
        )
        return None
    return {
        "status_label": status_label,
        "completed": completed,
        "total": total,
        "is_partial": bool(is_partial),
    }


def build_executive_summary_html_view_model(
    payload: Dict[str, Any],
    report: Any,
) -> Dict[str, Any]:
    """Shape canonical executive-summary JSON plus HTML-only fields for Jinja."""
    vulnerability_summary_items = _sorted_summary_items(payload.get("vulnerability_summary"))
    similarity_tier_items = _sorted_summary_items(payload.get("similarity_tier_counts"))
    guidance_html = _render_guidance_html(payload)
    highlights_in = _normalize_similarity_highlights(payload)
    overview = _derive_overview_defaults(payload, vulnerability_summary_items, highlights_in)

    tier_definitions = _normalize_tier_definitions(payload)

    similarity_rows: List[ExecutiveSimilarityHighlightRow] = [
        enrich_similarity_highlight_row_for_executive_html(row, report)
        for row in highlights_in
    ]
    progress_summary = _build_progress_summary(payload)

    safe_payload: Dict[str, Any] = {
        "title": str(payload.get("title") or "Executive Summary"),
        "executive_lead": _executive_summary_lead_text(),
        "generated_at": str(payload.get("generated_at") or "N/A"),
        "deep_model": str(payload.get("deep_model") or payload.get("model_name") or "N/A"),
        "small_model": str(payload.get("small_model") or "N/A"),
        "embedding_model": str(payload.get("embedding_model") or "N/A"),
        "vulnerability_summary": vulnerability_summary_items,
        "similarity_tier_counts": similarity_tier_items,
        "project": payload.get("project"),
        "analysis_root": payload.get("analysis_root"),
        "guidance_html": guidance_html,
        "overview": overview,
        "tier_definitions": tier_definitions,
        "similarity_rows": similarity_rows,
        "progress_summary": progress_summary,
    }
    oasis_raw = payload.get("oasis_version")
    if oasis_raw not in (None, ""):
        safe_payload["oasis_version"] = str(oasis_raw).strip()
    return safe_payload
