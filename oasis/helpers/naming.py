"""Low-level naming primitives shared across the codebase.

This module intentionally stays small so :mod:`oasis.helpers.report_project`,
:mod:`oasis.tools`, and callers avoid circular imports.

**Relationship to report project naming**

- :func:`sanitize_name` replaces non-alphanumeric characters with ``_`` on the last path
  segment (same contract as legacy ``oasis.tools.sanitize_name``). Use it for generic
  filesystem-safe segments (model dirs, stems, etc.).
- :data:`PROJECT_ALIAS_PATTERN` defines allowed characters for an **explicit** project
  alias (``--project-name`` / programmatic override). It is stricter than a slug.
- For disk layout under ``security_reports`` and cache keys derived from arbitrary
  labels (including derived-from-input names with spaces), use
  :func:`oasis.helpers.report_project.project_slug_for_report_storage`, which builds on
  :func:`sanitize_name` and adds underscore compaction plus a ``project`` fallback.

Flow (high level): explicit alias → validated by ``PROJECT_ALIAS_PATTERN``; derived
label from ``--input`` → :func:`~oasis.helpers.report_project.project_label_for_report_storage`;
either label → :func:`~oasis.helpers.report_project.project_slug_for_report_storage` for
the path segment.
"""

from __future__ import annotations

import re
from typing import Final

PROJECT_ALIAS_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9_-]+$")


def sanitize_name(value: str) -> str:
    """
    Sanitize a value for filesystem-safe segments while matching legacy behavior.

    Takes the last ``/`` segment and maps non-alphanumeric characters to ``_``.
    Does not collapse repeated underscores (see ``project_slug_for_report_storage``).
    """
    base_name = value.split("/")[-1]
    return re.sub(r"[^a-zA-Z0-9]", "_", base_name)
