"""Shared error strings and HTTP bodies for dashboard assistant API routes."""

from __future__ import annotations

from typing import Any, Dict, Tuple

JsonErr = Tuple[Dict[str, Any], int]

# --- Status codes (assistant chat family; reuse for consistency) ---
HTTP_BAD_REQUEST = 400
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_UNPROCESSABLE = 422
HTTP_INTERNAL = 500
HTTP_BAD_GATEWAY = 502

# --- Error messages: chat context & validation ---
ERR_INVALID_JSON = "Invalid JSON"
ERR_REPORT_PATH_REQUIRED = "report_path required"
ERR_MESSAGES_REQUIRED = "messages required"
ERR_TOO_MANY_MESSAGES = "too many messages"
ERR_INVALID_MESSAGE = "invalid message"
ERR_INVALID_ROLE = "invalid role"
ERR_INVALID_CONTENT = "invalid content"
ERR_MESSAGE_TOO_LONG = "message too long"
ERR_AGGREGATE_REQUIRES_EXECUTIVE = (
    "aggregate_model_json requires json/_executive_summary.json (or its md sibling)"
)
ERR_COULD_NOT_READ_REPORT = "Could not read report"
ERR_INVALID_REPORT = "Invalid report"
ERR_AGGREGATE_MODEL_DIR = "Could not resolve model directory for aggregate assistant"
ERR_NO_JSON_REPORTS_AGGREGATE = "No JSON reports found for aggregate assistant"
ERR_CHAT_MODEL_REQUIRED = "model required (pass model or ensure report has model_name)"
ERR_INVALID_PATH = "Invalid path"
ERR_REPORT_NOT_FOUND = "Report not found"
ERR_COULD_NOT_RESOLVE_MODEL_DIR = "Could not resolve model directory"


def assistant_http_error(message: str, status: int = HTTP_BAD_REQUEST) -> JsonErr:
    """Return a ``({'error': ...}, status)`` tuple for Flask ``jsonify``."""
    return ({"error": message}, status)
