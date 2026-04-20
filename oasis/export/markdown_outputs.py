"""Persist HTML/PDF produced from markdown-based reports (audit, executive summary)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict

from .result_types import ArtifactWriteStatusMap
from .writers import write_html_pdf_from_rendered


def write_rendered_markdown_formats(
    output_files: Dict[str, Path],
    rendered_html: str,
    *,
    logger: logging.Logger,
    context_label: str,
) -> ArtifactWriteStatusMap:
    """
    Write HTML and PDF keys present in ``output_files`` from fully rendered HTML.

    Returns an ``ArtifactWriteStatusMap`` (see ``oasis.export.result_types``):
    shallow copy of ``output_files`` merged with :func:`write_html_pdf_from_rendered`.
    ``output_files`` is not mutated in place.
    """
    merged: ArtifactWriteStatusMap = dict(output_files)
    subset = {k: v for k, v in output_files.items() if k in ("html", "pdf")}
    if not subset:
        return merged
    written = write_html_pdf_from_rendered(subset, rendered_html, logger=logger, context_label=context_label)
    merged |= written
    return merged
