"""Finding suppression registry: persist triage decisions across runs.

A registry file maps stable finding fingerprints (file path + vulnerability
type + normalized snippet) to a triage entry with an optional note. Findings
whose fingerprint appears in the registry are exported with a native SARIF
``suppressions`` entry so scanners consuming the SARIF output can filter them.

Recommended location: ``<project>/.oasis_suppressions.json``.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from ..tools import generate_timestamp

logger = logging.getLogger(__name__)

DEFAULT_SUPPRESSIONS_FILENAME = ".oasis_suppressions.json"

_CANDIDATES_ARTIFACT_NAME = "suppression_candidates.json"

_MAX_DOC_JSON_BYTES = 64 * 1024 * 1024

_SNIPPET_PREVIEW_MAX_CHARS = 240


def normalize_snippet_text(text: Any) -> str:
    """Normalize a snippet for fingerprinting (line endings, trailing spaces, blank edges)."""
    if not isinstance(text, str):
        return ""
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def finding_fingerprint(file_path: Any, vulnerability_name: Any, snippet: Any) -> str:
    """Stable content hash for one finding across runs."""
    normalized_file = str(file_path or "").strip().replace("\\", "/")
    normalized_vuln = str(vulnerability_name or "").strip().lower()
    normalized_snippet = normalize_snippet_text(snippet)
    joined = "\x00".join([normalized_file, normalized_vuln, normalized_snippet])
    digest = hashlib.sha256(joined.encode("utf-8", errors="replace")).hexdigest()
    return f"sha256:{digest}"


def _normalize_registry_entry(value: Any) -> dict[str, str] | None:
    """Accept ``"note"`` strings or ``{"note": ...}`` objects; reject anything else."""
    if isinstance(value, str):
        return {"note": value}
    if isinstance(value, dict):
        note = value.get("note")
        if note is not None and not isinstance(note, str):
            return None
        return {"note": str(note or "")}
    return None


def load_suppressions(path: Path) -> dict[str, dict[str, str]]:
    """
    Load a suppressions registry, returning ``{fingerprint: {"note": str}}``.

    Accepts either ``{"suppressions": {fp: entry}}`` or a flat ``{fp: entry}``
    object. Missing files return an empty registry; unreadable or malformed
    files log a warning and return an empty registry (fail-open, never blocks
    a scan).
    """
    registry_path = Path(path)
    if not registry_path.is_file():
        return {}
    try:
        data = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.warning("Suppressions registry unreadable (%s): %s", registry_path, exc)
        return {}
    if not isinstance(data, dict):
        logger.warning("Suppressions registry must be a JSON object: %s", registry_path)
        return {}

    nested = data.get("suppressions")
    raw_entries = nested if isinstance(nested, dict) else data
    entries: dict[str, dict[str, str]] = {}
    for fingerprint, value in raw_entries.items():
        if not isinstance(fingerprint, str) or not fingerprint.strip():
            continue
        normalized = _normalize_registry_entry(value)
        if normalized is None:
            logger.warning(
                "Suppressions registry entry ignored for %s (expected note string or object)",
                fingerprint,
            )
            continue
        entries[fingerprint.strip()] = normalized
    return entries


def _load_json_object(path: Path) -> dict[str, Any] | None:
    try:
        if path.stat().st_size > _MAX_DOC_JSON_BYTES:
            logger.warning("Suppressions skipping oversized report document: %s", path)
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.warning("Suppressions skipping unreadable report document %s: %s", path, exc)
        return None
    return data if isinstance(data, dict) else None


def _candidate_from_finding(doc: dict[str, Any], file_path: str, finding: dict[str, Any]) -> dict[str, str]:
    vulnerability_name = str(doc.get("vulnerability_name") or "")
    snippet = str(finding.get("vulnerable_code") or "")
    preview = normalize_snippet_text(snippet)
    if len(preview) > _SNIPPET_PREVIEW_MAX_CHARS:
        preview = preview[:_SNIPPET_PREVIEW_MAX_CHARS] + "…"
    return {
        "fingerprint": finding_fingerprint(file_path, vulnerability_name, snippet),
        "file_path": file_path,
        "vulnerability_name": vulnerability_name,
        "title": str(finding.get("title") or ""),
        "severity": str(finding.get("severity") or ""),
        "snippet_preview": preview,
    }


def iter_findings_from_documents(docs: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Flatten canonical vulnerability documents into suppression candidates."""
    candidates: list[dict[str, str]] = []
    for doc in docs:
        if str(doc.get("report_type") or "") != "vulnerability":
            continue
        files = doc.get("files")
        if not isinstance(files, list):
            continue
        for file_entry in files:
            if not isinstance(file_entry, dict) or file_entry.get("error"):
                continue
            file_path = str(file_entry.get("file_path") or "")
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
                    if isinstance(finding, dict):
                        candidates.append(_candidate_from_finding(doc, file_path, finding))
    return candidates


def iter_vulnerability_documents(output_dir: Path) -> list[dict[str, Any]]:
    """Canonical vulnerability documents under a run output directory."""
    root = Path(output_dir)
    if not root.is_dir():
        return []
    docs: list[dict[str, Any]] = []
    for candidate in sorted(root.rglob("json/*.json")):
        if not candidate.is_file() or candidate.name.startswith("_"):
            continue
        doc = _load_json_object(candidate)
        if doc is not None and str(doc.get("report_type") or "") == "vulnerability":
            docs.append(doc)
    return docs


def write_suppression_candidates(output_dir: Path) -> int:
    """
    Write ``suppression_candidates.json`` under ``output_dir`` and return the
    candidate count. The file lists every finding fingerprint of the run so
    entries can be copied into a suppressions registry with a triage note.
    """
    candidates = iter_findings_from_documents(iter_vulnerability_documents(output_dir))
    payload = {
        "schema_version": 1,
        "generated_at": generate_timestamp(),
        "hint": (
            "Copy the fingerprint entries you want to suppress into your "
            f"{DEFAULT_SUPPRESSIONS_FILENAME} under \"suppressions\" and add a triage note."
        ),
        "candidates": candidates,
    }
    target = Path(output_dir) / _CANDIDATES_ARTIFACT_NAME
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Suppression candidates written to %s", target)
    return len(candidates)


def count_suppressed_findings(output_dir: Path, suppressions: dict[str, dict[str, str]]) -> int:
    """Number of findings in a finished run whose fingerprint is suppressed."""
    if not suppressions:
        return 0
    return sum(
        1
        for candidate in iter_findings_from_documents(iter_vulnerability_documents(output_dir))
        if candidate["fingerprint"] in suppressions
    )