"""Canonical keys for executive-summary progress payload extensions (wire JSON / Markdown).

Keep in sync across :func:`oasis.report.publish_incremental_summary`,
:class:`oasis.report.Report`, and dashboard readers in :mod:`oasis.web`.
"""

# Wire protocol version for incremental scan progress (REST / Socket.IO / embedded JSON).
EXEC_SUMMARY_PROGRESS_EVENT_VERSION = 2

# Explicit ``status`` overrides (e.g. aborted mid-run) for :func:`publish_incremental_summary`.
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

# Terminal success-style statuses: when set explicitly, ``is_partial`` is false.
SCAN_PROGRESS_NON_PARTIAL_STATUSES = frozenset({"complete", "succeeded", "finished"})

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
