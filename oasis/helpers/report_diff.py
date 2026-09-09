"""Baseline diff helpers: compare canonical vulnerability JSON across two runs.

Fingerprints are content-stable (file path + vulnerability type + normalized
snippet) so the same unfixed finding maps to the same identity in both runs.
The public entry point :func:`write_diff_artifacts` writes a
``diff/diff_report.json`` (``DiffReportDocument``) plus a Markdown sibling under
the current run output directory.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from ..export.writers import write_utf8_text
from ..schemas.analysis import (
    DiffCounts,
    DiffFindingRef,
    DiffReportDocument,
    DiffSeverityChange,
)
from ..tools import generate_timestamp

logger = logging.getLogger(__name__)

_MAX_DOC_JSON_BYTES = 64 * 1024 * 1024

_DIFF_ARTIFACT_STEM = "diff_report"


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


def _load_json_object(path: Path) -> dict[str, Any] | None:
    try:
        if path.stat().st_size > _MAX_DOC_JSON_BYTES:
            logger.warning("Diff skipping oversized report document: %s", path)
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.warning("Diff skipping unreadable report document %s: %s", path, exc)
        return None
    return data if isinstance(data, dict) else None


def iter_json_document_paths(source: Path) -> list[Path]:
    """JSON report paths for a diff source: one file, or ``json/*.json`` under a directory."""
    if source.is_file():
        return [source]
    if not source.is_dir():
        return []
    paths: list[Path] = []
    for candidate in sorted(source.rglob("json/*.json")):
        if candidate.is_file() and not candidate.name.startswith("_"):
            paths.append(candidate)
    return paths


def iter_findings_from_document(doc: dict[str, Any]) -> list[dict[str, str]]:
    """Flatten one canonical vulnerability document into fingerprinted finding refs."""
    refs: list[dict[str, str]] = []
    if str(doc.get("report_type") or "") != "vulnerability":
        return refs
    vulnerability_name = str(doc.get("vulnerability_name") or "")
    files = doc.get("files")
    if not isinstance(files, list):
        return refs
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
                if not isinstance(finding, dict):
                    continue
                snippet = str(finding.get("vulnerable_code") or "")
                refs.append(
                    {
                        "file_path": file_path,
                        "vulnerability_name": vulnerability_name,
                        "title": str(finding.get("title") or ""),
                        "severity": str(finding.get("severity") or ""),
                        "snippet": snippet,
                        "fingerprint": finding_fingerprint(file_path, vulnerability_name, snippet),
                    }
                )
    return refs


def collect_finding_refs(source: Path) -> tuple[list[dict[str, str]], int]:
    """All fingerprinted findings from a diff source; second value is the document count."""
    refs: list[dict[str, str]] = []
    documents = 0
    for path in iter_json_document_paths(source):
        doc = _load_json_object(path)
        if doc is None:
            continue
        if str(doc.get("report_type") or "") != "vulnerability":
            continue
        documents += 1
        refs.extend(iter_findings_from_document(doc))
    return refs, documents


def _refs_by_fingerprint(refs: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    by_fp: dict[str, dict[str, str]] = {}
    for ref in refs:
        fingerprint = ref.get("fingerprint") or ""
        if fingerprint and fingerprint not in by_fp:
            by_fp[fingerprint] = ref
    return by_fp


def diff_finding_refs(
    baseline_refs: list[dict[str, str]],
    current_refs: list[dict[str, str]],
) -> dict[str, Any]:
    """Bucket findings into new / fixed / persistent plus severity changes."""
    baseline_by_fp = _refs_by_fingerprint(baseline_refs)
    current_by_fp = _refs_by_fingerprint(current_refs)

    new_refs = [r for fp, r in current_by_fp.items() if fp not in baseline_by_fp]
    fixed_refs = [r for fp, r in baseline_by_fp.items() if fp not in current_by_fp]
    persistent_refs = [r for fp, r in current_by_fp.items() if fp in baseline_by_fp]

    severity_changes: list[DiffSeverityChange] = []
    for ref in persistent_refs:
        baseline_ref = baseline_by_fp[ref["fingerprint"]]
        baseline_severity = str(baseline_ref.get("severity") or "").strip()
        current_severity = str(ref.get("severity") or "").strip()
        if baseline_severity.lower() != current_severity.lower():
            severity_changes.append(
                DiffSeverityChange(
                    fingerprint=ref["fingerprint"],
                    file_path=ref.get("file_path") or "",
                    vulnerability_name=ref.get("vulnerability_name") or "",
                    title=ref.get("title") or "",
                    baseline_severity=baseline_severity,
                    current_severity=current_severity,
                )
            )

    return {
        "new": [DiffFindingRef(**ref) for ref in new_refs],
        "fixed": [DiffFindingRef(**ref) for ref in fixed_refs],
        "persistent": [DiffFindingRef(**ref) for ref in persistent_refs],
        "severity_changes": severity_changes,
        "counts": DiffCounts(
            new=len(new_refs),
            fixed=len(fixed_refs),
            persistent=len(persistent_refs),
            severity_changes=len(severity_changes),
        ),
    }


def _diff_markdown_lines(doc: DiffReportDocument) -> list[str]:
    baseline_label = doc.baseline_path or "(none)"
    lines = [
        f"# {doc.title}",
        "",
        f"- **Baseline**: {baseline_label}",
        f"- **Generated**: {doc.generated_at}",
        "",
        "## Summary",
        "",
        f"- **New findings**: {doc.counts.new}",
        f"- **Fixed findings**: {doc.counts.fixed}",
        f"- **Persistent findings**: {doc.counts.persistent}",
        f"- **Severity changes**: {doc.counts.severity_changes}",
        "",
    ]

    def _ref_table(rows: list[DiffFindingRef]) -> list[str]:
        if not rows:
            return ["_(none)_", ""]
        table = ["| Severity | Vulnerability | File | Title |", "|---|---|---|---|"]
        for ref in rows:
            severity = (ref.severity or "-").strip() or "-"
            title = (ref.title or "-").replace("|", "\\|")
            table.append(f"| {severity} | {ref.vulnerability_name} | {ref.file_path} | {title} |")
        table.append("")
        return table

    lines.extend(["## New findings", ""])
    lines.extend(_ref_table(doc.new))
    lines.extend(["## Fixed findings", ""])
    lines.extend(_ref_table(doc.fixed))

    lines.extend(["## Severity changes", ""])
    if not doc.severity_changes:
        lines.extend(["_(none)_", ""])
    else:
        lines.extend(["| File | Vulnerability | Baseline | Current |", "|---|---|---|---|"])
        for change in doc.severity_changes:
            lines.append(
                f"| {change.file_path} | {change.vulnerability_name} "
                f"| {change.baseline_severity or '-'} | {change.current_severity or '-'} |"
            )
        lines.append("")
    return lines


def write_diff_artifacts(output_dir: Path, baseline_source: Path) -> dict[str, Any] | None:
    """
    Compare the current run documents under ``output_dir`` against ``baseline_source``
    and write ``diff/diff_report.json`` + ``diff/diff_report.md``.

    Returns the built document (dict form) for logging, or ``None`` when the
    current run directory does not exist.
    """
    current_dir = Path(output_dir)
    if not current_dir.is_dir():
        logger.warning("Diff report skipped: current run directory not found: %s", current_dir)
        return None

    baseline_refs, baseline_documents = collect_finding_refs(Path(baseline_source))
    if baseline_documents == 0:
        logger.warning(
            "Diff baseline contains no readable vulnerability documents: %s "
            "(every current finding will appear as new)",
            baseline_source,
        )
    current_refs, _ = collect_finding_refs(current_dir)

    buckets = diff_finding_refs(baseline_refs, current_refs)
    doc = DiffReportDocument(
        generated_at=generate_timestamp(),
        baseline_path=str(baseline_source),
        current_path=str(current_dir),
        **buckets,
    )

    diff_dir = current_dir / "diff"
    diff_dir.mkdir(parents=True, exist_ok=True)
    write_utf8_text(diff_dir / f"{_DIFF_ARTIFACT_STEM}.json", doc.model_dump_json(indent=2))
    write_utf8_text(diff_dir / f"{_DIFF_ARTIFACT_STEM}.md", "\n".join(_diff_markdown_lines(doc)))
    logger.info("Diff report written to %s", diff_dir / f"{_DIFF_ARTIFACT_STEM}.json")
    return doc.model_dump(mode="json")