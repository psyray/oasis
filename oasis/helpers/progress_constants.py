"""Wire contract constants for incremental scan / executive-summary progress payloads.

Canonical definitions live here; ``oasis/helpers/progress.py`` imports and re-exports them.
Keep in sync with ``publish_incremental_summary``, ``Report``, and ``oasis.web`` dashboard readers.
"""

# Bump when incremental progress payloads are no longer backward-compatible for consumers.
EXEC_SUMMARY_PROGRESS_EVENT_VERSION = 3

SCAN_PROGRESS_STATUS_EXPLICIT = frozenset(
    {
        "in_progress",
        "complete",
        "aborted",
        "failed",
        "succeeded",
        "finished",
    }
)

SCAN_PROGRESS_NON_PARTIAL_STATUSES = frozenset({"complete", "succeeded", "finished"})

# Human-readable markdown labels aligned with SCAN_PROGRESS_STATUS_EXPLICIT keys (reports only).
SCAN_PROGRESS_STATUS_MARKDOWN_LABELS: dict[str, str] = {
    "in_progress": "Partial (scan in progress)",
    "complete": "Complete",
    "aborted": "Aborted",
    "failed": "Failed",
    "succeeded": "Succeeded",
    "finished": "Finished",
}

SCAN_PROGRESS_EXTENDED_KEYS = frozenset(
    {
        "updated_at",
        "active_phase",
        "phases",
        "adaptive_subphases",
        "overall",
        "scan_mode",
        "event_version",
        "vulnerability_types_total",
        "status",
    }
)
