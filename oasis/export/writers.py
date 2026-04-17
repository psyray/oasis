"""Low-level disk writers for report exports (no Jinja orchestration)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

from weasyprint import HTML

from ..schemas.analysis import VulnerabilityReportDocument
from .result_types import ArtifactWriteStatusMap


def ensure_parent_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_utf8_text(path: Path, text: str) -> None:
    ensure_parent_dir(path)
    path.write_text(text, encoding="utf-8")


def write_markdown_lines(path: Path, lines: List[str], logger: logging.Logger) -> None:
    try:
        ensure_parent_dir(path)
        path.write_text("\n".join(lines), encoding="utf-8")
    except Exception as e:
        logger.exception("Error writing markdown file: %s", e)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Full error:", exc_info=True)


def write_json_document(path: Path, doc: VulnerabilityReportDocument) -> None:
    ensure_parent_dir(path)
    path.write_text(doc.model_dump_json(indent=2), encoding="utf-8")


def write_sarif_json(path: Path, payload: dict) -> None:
    ensure_parent_dir(path)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_pdf_from_html(
    path: Path,
    html_str: str,
    *,
    logger: logging.Logger,
    context_label: str,
) -> bool:
    """
    Write PDF from full HTML string. Returns True on success, False on failure.
    """
    ensure_parent_dir(path)
    try:
        HTML(string=html_str, media_type="print").write_pdf(path)
        return True
    except Exception as e:
        logger.exception("PDF conversion failed for %s: %s: %s", context_label, e.__class__.__name__, e)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("HTML (first 500 chars): %s", html_str[:500])
        return False


def write_html_pdf_from_rendered(
    output_files: Dict[str, Path],
    rendered_html: str,
    *,
    logger: logging.Logger,
    context_label: str,
) -> ArtifactWriteStatusMap:
    """
    Persist rendered HTML and optional PDF for paths present in ``output_files``.

    Returns an ``ArtifactWriteStatusMap`` (see ``oasis.export.result_types``).

    **Contract:** ``output_files`` is not modified. The return value is a shallow copy
    that may replace ``"html"`` and/or ``"pdf"`` values with ``None`` when conversion
    fails (PDF failure sets ``result["pdf"]`` to ``None``; a caught outer exception returns
    only ``html`` / ``pdf`` keys that were present in ``output_files``, each set to ``None``).
    On success, returned paths match the input paths for html/pdf. Callers must use the
    returned dict to observe failure, not the original ``output_files`` dict.
    """
    result: Dict[str, Path | None] = dict(output_files)
    try:
        if "html" in output_files:
            write_utf8_text(output_files["html"], rendered_html)
        if "pdf" in output_files:
            ok = write_pdf_from_html(
                output_files["pdf"],
                rendered_html,
                logger=logger,
                context_label=context_label,
            )
            if not ok:
                result["pdf"] = None
        return result
    except Exception as e:
        return handle_html_pdf_conversion_error(
            logger, context_label, e, output_files
        )

def handle_html_pdf_conversion_error(logger, context_label, e, output_files):
    logger.exception("Error converting %s to other formats: %s: %s", context_label, e.__class__.__name__, e)
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Full error:", exc_info=True)
    out: Dict[str, Path | None] = {}
    if "html" in output_files:
        out["html"] = None
    if "pdf" in output_files:
        out["pdf"] = None
    return out
