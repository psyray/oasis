"""CI gating helpers: evaluate a finished run against a severity threshold.

The gate reads the canonical vulnerability JSON documents written under a run's
output directory (``json/*.json``, in every model directory), so evaluation is
independent from in-memory analyzer state and reuses the on-disk contract.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Ordered lowest → highest. Keys match the canonical finding severities and the
# DashboardStats ``*_risk`` counters.
SEVERITY_ORDER: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Dedicated exit code so CI can distinguish "findings at/above threshold"
# (3) from operational failures (1) and argparse usage errors (2).
EXIT_FINDINGS_ABOVE_THRESHOLD = 3

_MAX_DOC_JSON_BYTES = 64 * 1024 * 1024


def normalize_severity(value: Any) -> str | None:
    """Lower-cased severity name when recognized, else ``None``."""
    if not isinstance(value, str):
        return None
    key = value.strip().lower()
    return key if key in SEVERITY_ORDER else None


def is_severity_at_or_above(severity: Any, threshold: Any) -> bool:
    """True when ``severity`` ranks at or above ``threshold`` (unknown values never trip)."""
    threshold_rank = SEVERITY_ORDER.get(normalize_severity(threshold) or "", None)
    severity_rank = SEVERITY_ORDER.get(normalize_severity(severity) or "", None)
    if threshold_rank is None or severity_rank is None:
        return False
    return severity_rank >= threshold_rank


def iter_vulnerability_document_paths(run_dir: Path) -> list[Path]:
    """Canonical vulnerability JSON paths under a run output directory.

    Accepts either a model directory (containing ``json/``) or any parent of
    model directories; files are discovered as ``json/*.json`` below ``run_dir``.
    Non-vulnerability documents (executive summaries, audit reports) are
    filtered later by ``report_type``; progress sidecars are skipped here via
    their leading ``_`` name.
    """
    root = Path(run_dir)
    if not root.is_dir():
        return []
    paths: list[Path] = []
    for candidate in sorted(root.rglob("json/*.json")):
        if not candidate.is_file():
            continue
        if candidate.name.startswith("_"):
            continue
        paths.append(candidate)
    return paths


def _load_json_object(path: Path) -> dict[str, Any] | None:
    try:
        if path.stat().st_size > _MAX_DOC_JSON_BYTES:
            logger.warning("CI gate skipping oversized report document: %s", path)
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.warning("CI gate skipping unreadable report document %s: %s", path, exc)
        return None
    return data if isinstance(data, dict) else None


def _count_findings_by_severity(doc: dict[str, Any]) -> dict[str, int]:
    """Count finding severities directly from ``files[].chunk_analyses[].findings``."""
    counts: dict[str, int] = {name: 0 for name in SEVERITY_ORDER}
    files = doc.get("files")
    if not isinstance(files, list):
        return counts
    for file_entry in files:
        if not isinstance(file_entry, dict) or file_entry.get("error"):
            continue
        chunks = file_entry.get("chunk_analyses")
        if not isinstance(chunks, list):
            continue
        for chunk in chunks:
            if not isinstance(chunk, dict):
                continue
            findings = chunk.get("findings")
            if not isinstance(findings, list):
                continue
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                severity = normalize_severity(finding.get("severity"))
                if severity is not None:
                    counts[severity] += 1
    return counts


def evaluate_fail_on_gate(run_dir: Path, fail_on: Any) -> dict[str, Any]:
    """
    Evaluate whether a finished run reports findings at or above ``fail_on``.

    Returns a summary dict with ``tripped``, per-severity counts, and the number
    of canonical documents scanned (unreadable or non-vulnerability files are
    skipped with a warning rather than failing the gate).
    """
    threshold = normalize_severity(fail_on)
    counts: dict[str, int] = {name: 0 for name in SEVERITY_ORDER}
    documents_scanned = 0
    for path in iter_vulnerability_document_paths(run_dir):
        doc = _load_json_object(path)
        if doc is None:
            continue
        if str(doc.get("report_type") or "") != "vulnerability":
            continue
        documents_scanned += 1
        doc_counts = _count_findings_by_severity(doc)
        for name, total in doc_counts.items():
            counts[name] += total

    findings_at_or_above = 0
    if threshold is not None:
        threshold_rank = SEVERITY_ORDER[threshold]
        findings_at_or_above = sum(
            total for name, total in counts.items() if SEVERITY_ORDER[name] >= threshold_rank
        )

    return {
        "fail_on": threshold,
        "tripped": bool(threshold) and findings_at_or_above > 0,
        "findings_at_or_above": findings_at_or_above,
        "counts_by_severity": counts,
        "documents_scanned": documents_scanned,
    }


def log_fail_on_gate(gate: dict[str, Any]) -> None:
    """Log a one-line human summary of the gate outcome."""
    threshold = gate.get("fail_on")
    if not threshold:
        return
    counts = gate.get("counts_by_severity") or {}
    totals = ", ".join(f"{name}={counts.get(name, 0)}" for name in SEVERITY_ORDER)
    logger.info(
        "CI gate --fail-on %s: findings at or above threshold: %s (%s)",
        threshold,
        gate.get("findings_at_or_above", 0),
        totals,
    )
    if gate.get("tripped"):
        logger.error(
            "CI gate tripped: %s finding(s) at or above '%s' severity (exit code %s).",
            gate.get("findings_at_or_above", 0),
            threshold,
            EXIT_FINDINGS_ABOVE_THRESHOLD,
        )