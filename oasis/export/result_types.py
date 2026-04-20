"""
Shared typing aliases for multi-artifact report exports.

**Artifact write status map** (``ArtifactWriteStatusMap``):

- Returned by :func:`~oasis.export.vulnerability.write_vulnerability_artifacts`,
  :func:`~oasis.export.writers.write_html_pdf_from_rendered`, and
  :func:`~oasis.export.markdown_outputs.write_rendered_markdown_formats`.
- Keys are format names (e.g. ``"json"``, ``"html"``, ``"pdf"``) as in the input path dict.
- Values are ``pathlib.Path`` when that artifact was written successfully, or ``None`` when
  the write failed or was skipped after failure. The input dict is not mutated; callers
  must inspect the return value to detect failures.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional

ArtifactWriteStatusMap = Dict[str, Optional[Path]]
