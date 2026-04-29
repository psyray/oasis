from collections import OrderedDict
from collections.abc import Iterable
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
import json
import os
from pathlib import Path
import re
import secrets
import socket
import string
from threading import Thread
from typing import Any, Dict, List, Optional, Tuple, Union

from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
from functools import wraps
try:
    from flask_socketio import SocketIO, emit
except ModuleNotFoundError:  # pragma: no cover - fallback for minimal test envs
    from threading import Thread
    import time

    class SocketIO:  # type: ignore[override]
        def __init__(self, app, **_kwargs):
            self.app = app

        def on(self, _event):
            def decorator(func):
                return func
            return decorator

        def emit(self, event, data=None, **_kwargs):
            return None

        def run(self, app, **kwargs):
            app.run(**kwargs)

        def start_background_task(self, target, *args, **kwargs):
            thread = Thread(target=target, args=args, kwargs=kwargs, daemon=True)
            thread.start()
            return thread

        def sleep(self, seconds):
            time.sleep(seconds)

    def emit(event, data=None, **_kwargs):  # type: ignore[override]
        return None


from .config import DEFAULT_ARGS, REPORT, VULNERABILITY_MAPPING, MODEL_EMOJIS, VULN_EMOJIS, LANGUAGES
from .config import OLLAMA_URL
from .export.filenames import (
    AUDIT_REPORT_ARTIFACT_STEM,
    artifact_filename,
    report_dir_glob_for_format,
)
from .helpers.dashboard import (
    AUDIT_METRIC_LABELS,
    AUDIT_METRIC_TABLE_ROW_PATTERN,
    AUDIT_METRICS_SECTION_HEADING_PATTERN,
    AUDIT_METRICS_TABLE_HEADER_LABELS,
    audit_metric_key_from_label,
    audit_metrics_from_audit_payload,
    audit_metrics_from_markdown_content,
    dashboard_format_display_order,
    expand_socketio_cors_config_entries,
    iter_audit_metrics_table_rows,
    normalize_audit_metric_label,
    parse_audit_metric_table_row,
    parse_first_float_metric,
    parse_first_int_metric,
    parse_phase_counts_from_progress_cell,
    rewrite_report_preview_anchor_hrefs,
    slice_markdown_section_after_heading,
    socketio_lan_http_origins,
    strip_report_header_for_web_preview,
)
from .helpers.progress import SCAN_PROGRESS_EXTENDED_KEYS, coerce_scan_progress_event_version
from .report import Report, executive_summary_progress_sidecar_path, is_executive_summary_progress_sidecar
from .ollama_manager import OllamaManager
from .helpers.analysis_root_path import (
    CODEBASE_UNAVAILABLE_DETAIL,
    CODEBASE_UNAVAILABLE_SHORT,
    assistant_context_warning,
    codebase_access_state,
    resolve_assistant_cache_root,
    resolve_first_existing_scan_root,
)
from .helpers.assistant.web.rag import (
    embedding_cache_file_path,
    load_embedding_code_base,
    retrieve_relevant_snippets,
)
from .helpers.context.path_containment import is_path_within_root
from .helpers.report_project import (
    is_legacy_run_dirname,
    is_run_timestamp_dirname,
    report_date_display_from_run_key,
)
from .helpers.dashboard.json_sibling import json_sibling_for_format_artifact
from .helpers.assistant.web.api_validate import (
    coerce_finding_indices,
    normalize_report_rel_query_arg,
    resolve_assistant_primary_payload,
    validate_assistant_messages,
)
from .helpers.assistant.prompt.chat_context import (
    assemble_verdict_first_prompt,
    compute_verdict_first_subbudgets,
    shrink_rag_block,
    shrink_user_labels_block,
)
from .helpers.assistant.prompt.prompt_tuning import REPORT_SUMMARY_AGGREGATE_MERGE_BUDGET_FACTOR
from .helpers.assistant.prompt.report_excerpt import compact_report_excerpt
from .helpers.assistant.web.http_contract import (
    ERR_AGGREGATE_REQUIRES_EXECUTIVE,
    ERR_CHAT_MODEL_REQUIRED,
    ERR_COULD_NOT_READ_REPORT,
    ERR_INVALID_JSON,
    ERR_INVALID_REPORT,
    ERR_REPORT_PATH_REQUIRED,
    HTTP_BAD_REQUEST,
    HTTP_INTERNAL,
    HTTP_UNPROCESSABLE,
    assistant_http_error,
)
from .helpers.assistant.web.web_prepare import (
    build_assistant_finding_json_prompt_block,
    build_report_summary_payload,
    extract_last_user_message_text,
    full_messages_from_system_and_dialogue,
    prepare_aggregate_branch_paths,
    resolve_assistant_chat_model,
)
from .helpers.assistant.web.sink_resolution import (
    coerce_positive_int_line,
    resolve_sink_from_finding_indices,
)
from .helpers.assistant.web.result_presentation import (
    apply_presentation_filter_to_result,
)
from .helpers.assistant.web.persistence import (
    delete_all_chat_sessions,
    delete_chat_session,
    ensure_session_views,
    finding_validation_storage_key,
    get_finding_validation_for_branch,
    list_chat_sessions,
    load_chat_session,
    merge_finding_validation_into_session,
    new_session_id,
    normalize_validated_messages_for_storage,
    save_chat_session,
    save_session_branch_messages,
    utc_now_iso,
    validate_session_id,
)
from .helpers.assistant.think.think_parse import (
    AssistantThinkSplit,
    enrich_messages_for_response,
    parse_assistant_think,
)
from .helpers.assistant.prompt.context_budget import assistant_total_system_budget_chars
from .helpers.assistant.scan.scan_aggregate import model_directory_from_security_report_file
from .helpers.dashboard.severity_filter import (
    empty_severity_finding_totals,
    merge_severity_finding_totals_for_report,
    parse_severity_filter_param,
    report_passes_dashboard_severity_filter,
)
from .helpers.executive.dashboard_preview import augment_executive_markdown_preview_html
from .helpers.executive.modal_chart_meta import rollup_severity_counts_from_model_dir
from .helpers.executive.assistant_scope import (
    synthetic_executive_primary_payload,
    vulnerability_reports_for_executive_assistant,
)
from .tools import parse_iso_date, parse_report_date

logger = logging.getLogger(__name__)

_CODEBASE_ACCESS_STATE_CACHE_MAX = 512


def normalize_dashboard_project_key(value: Any) -> str:
    """Normalize project label for dashboard filters and aggregated statistics keys."""
    return str(value or "").strip().lower()


@dataclass(frozen=True)
class AssistantChatPrepError:
    """HTTP error produced while building assistant chat context (Flask ``jsonify`` body + status)."""

    body: Dict[str, Any]
    status: int

    @staticmethod
    def from_http_tuple(pair: Tuple[Dict[str, Any], int]) -> "AssistantChatPrepError":
        body, status = pair
        return AssistantChatPrepError(body=body, status=status)


@dataclass(frozen=True)
class _AssistantChatReportLoad:
    messages: List[Dict[str, Any]]
    approx_msg_chars: int
    resolved_report: Path
    primary_payload: Dict[str, Any]
    report_rel: str
    aggregate_mode: bool
    json_paths_for_union: List[Path]
    extra_rag_paths: Optional[List[str]]
    rag_source_payload: Dict[str, Any]
    md_obj: Optional[Path]


@dataclass(frozen=True)
class _AssistantChatBudgetSummary:
    chat_model: str
    total_budget: int
    budget_meta: Any
    subbudgets: Dict[str, int]
    report_summary_text: str
    excerpt_truncated: bool
    report_sum_budget: int


class WebServer:
    _PROGRESS_DASHBOARD_HIDDEN_KEYS = frozenset({"adaptive_subphases"})
    _PROGRESS_SUMMARY_PHASE_IDS = frozenset(
        {
            "embeddings",
            "initial_scan",
            "deep_analysis",
            "adaptive_scan",
            "graph_discover",
            "graph_chunk_scan",
            "graph_context_expand",
            "graph_deep",
            "graph_verify",
        }
    )
    _PROGRESS_SUMMARY_PHASE_LABELS = frozenset(
        {
            "embeddings",
            "initial scan",
            "deep analysis",
            "adaptive scan",
            "discover candidates",
            "structured chunk scan",
            "context expansion",
            "verify structured output",
        }
    )
    _AUDIT_METRICS_SECTION_HEADING_PATTERN = AUDIT_METRICS_SECTION_HEADING_PATTERN
    _AUDIT_METRIC_LABELS: dict[str, tuple[str, str]] = AUDIT_METRIC_LABELS
    _AUDIT_METRICS_TABLE_HEADER_LABELS = AUDIT_METRICS_TABLE_HEADER_LABELS
    _AUDIT_METRIC_TABLE_ROW_PATTERN = AUDIT_METRIC_TABLE_ROW_PATTERN
    _ASSISTANT_MAX_REPORT_JSON_CHARS = 28000
    _ASSISTANT_MAX_TOTAL_REPORT_CHARS = _ASSISTANT_MAX_REPORT_JSON_CHARS * 4
    _ASSISTANT_MAX_MESSAGES = 40
    _ASSISTANT_MAX_MESSAGE_CHARS = 12000
    _ASSISTANT_SYSTEM_INTRO_PREFIX = (
        "You are a defensive security assistant helping triage static-analysis findings "
        "and understand code context. Only provide guidance for authorized testing.\n"
        "\n"
        "Authoritative sources (strict):\n"
        "- Treat FINDING_VALIDATION_JSON as the ground-truth verdict. Never contradict its "
        "`status`, `confidence`, `family`, `vulnerability_name`, or `summary` fields. "
        "If those fields mark the finding as `confirmed_exploitable`, do NOT call it a "
        "false positive; if marked `false_positive`, do not call it exploitable.\n"
        "- When FINDING_VALIDATION_JSON is absent, say so explicitly instead of inventing a verdict.\n"
        "- Cite only file paths and line numbers that appear in FINDING_VALIDATION_JSON, "
        "SELECTED_FINDING_JSON, RETRIEVAL_CONTEXT, or REPORT_SUMMARY. Never fabricate paths, "
        "line numbers, or frameworks.\n"
        "\n"
        "Output requirements:\n"
        "- Reply in concise Markdown (3–6 short paragraphs, optional bullet lists). "
        "No JSON, no code fences wrapping the whole answer.\n"
        "- Do not emit internal channel tokens (e.g. `<|channel>`, `<bos>`, `<|turn|>`), "
        "reasoning tags, or raw tokenizer artifacts.\n"
        "- Stay in English unless the user writes in another language first.\n"
    )

    def __init__(
        self,
        report,
        debug=False,
        web_expose='local',
        web_password=None,
        web_port=5000,
        web_ollama_url=None,
        web_embed_model=None,
        web_assistant_rag=True,
        default_ollama_url=None,
    ):
        """Initialize a dashboard server bound to a single runtime session.

        Runtime attributes (`app`, `socketio`, progress monitor flags) are reset
        at each `run()` invocation so the same instance can be reused safely in
        tests without carrying stale realtime state across runs.
        """
        self.report = report
        self.debug = debug
        self.web_expose = web_expose
        self.web_password = web_password
        self.web_port = web_port
        self.web_ollama_url = web_ollama_url
        self.web_embed_model = web_embed_model
        self.web_assistant_rag = bool(web_assistant_rag)
        self._default_ollama_url = default_ollama_url or OLLAMA_URL
        self._assistant_ollama_manager: Optional[OllamaManager] = None
        self.report_data = None
        self.global_stats: Optional[Dict[str, Any]] = None
        self.socketio = None
        self.app = None
        self._progress_monitor_started = False
        self._stop_progress_monitor = False
        self._last_emitted_progress_key = None
        self._canonical_json_fields_cache: Dict[
            Path, Tuple[Optional[str], Optional[str]]
        ] = {}
        self._codebase_access_state_cache: OrderedDict[
            Tuple[Optional[str], Path], Tuple[Optional[Path], bool]
        ] = OrderedDict()
        if not isinstance(report, Report):
            raise ValueError("Report must be an instance of Report")
        
        self.input_path = Path(report.input_path)
        if not self.input_path.exists():
            raise FileNotFoundError(f"Input path not found at {self.input_path}")
        self.input_path_absolute = self.input_path.resolve()

        self.security_dir = self.input_path_absolute.parent / "security_reports"
        if not self.security_dir.exists():
            logger.warning(
                "Security reports directory did not exist at %s; creating it now.",
                self.security_dir,
            )
        self.security_dir.mkdir(parents=True, exist_ok=True)

    def _assistant_llm_debug_payload(self, prep: Dict[str, Any]) -> Dict[str, Any]:
        """Structured metadata logged alongside Ollama messages when ``self.debug`` is True."""
        sl = prep.get("section_lengths")
        if sl is not None and hasattr(sl, "to_dict"):
            sl = sl.to_dict()  # VerdictSectionLengths
        return {
            "chat_model": prep.get("chat_model"),
            "report_rel": prep.get("report_rel"),
            "session_id_hint": prep.get("session_id_hint"),
            "aggregate_mode": prep.get("aggregate_mode"),
            "total_budget": prep.get("total_budget"),
            "runtime_num_ctx": prep.get("runtime_num_ctx"),
            "context_source": prep.get("context_source"),
            "excerpt_truncated": prep.get("excerpt_truncated"),
            "rag_unavailable": prep.get("rag_unavailable"),
            "section_lengths": sl,
            "validated_dialogue_messages": prep.get("messages"),
        }

    def _log_assistant_llm_debug(self, event: str, payload: Dict[str, Any]) -> None:
        """Log full assistant ↔ Ollama payloads when running ``oasis --web --debug``."""
        if not self.debug:
            return
        try:
            body = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
        except Exception:
            body = repr(payload)
        logger.debug("[assistant_llm] %s\n%s", event, body)

    def run(self):
        """Serve reports via a web interface."""
        from .__init__ import __version__

        # Reset runtime state for each run to avoid leaking previous session state
        # when a WebServer instance is reused (common in tests).
        self.socketio = None
        self.app = None
        self._progress_monitor_started = False
        self._stop_progress_monitor = False
        self._last_emitted_progress_key = None
        self._assistant_ollama_manager = None
        self._canonical_json_fields_cache.clear()
        self._codebase_access_state_cache.clear()

        app = Flask(
            __name__, template_folder=str(Path(__file__).parent / "templates"),
            static_folder=str(Path(__file__).parent / "static")
        )
        self.app = app
        self.socketio = SocketIO(app, **self._socketio_options())
        
        # Generate a random secret key for session management
        app.secret_key = secrets.token_hex(16)
        
        # Add context processor to inject version into all templates
        @app.context_processor
        def inject_version():
            return {'version': __version__}
        
        # Setup password protection if enabled
        if self.web_password is None:
            # Generate a random password if none provided
            self.web_password = self._generate_random_password()
            print(f"\n[OASIS] Web interface protected by password: {self.web_password}\n")

        # Auth decorator
        def login_required(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if self.web_password and not session.get('logged_in'):
                    return redirect(url_for('login', next=request.url))
                return f(*args, **kwargs)
            return decorated_function
            
        # Login route
        @app.route('/login', methods=['GET', 'POST'])
        def login():
            error = None
            if request.method == 'POST':
                if request.form['password'] == self.web_password:
                    session['logged_in'] = True
                    return redirect(request.args.get('next') or url_for('dashboard'))
                else:
                    error = 'Incorrect password.'
            return self._render_login_template(error)
        
        # Process and collect all report data
        self.collect_report_data()

        # Register routes with authentication
        app = self.register_routes(app, self, login_required)
        self._register_socket_handlers()
        self._start_progress_monitor()

        # Determine the host based on the expose setting
        host = '127.0.0.1' if self.web_expose == 'local' else '0.0.0.0'
        
        # Run the server. When ``debug=True``, Werkzeug's reloader would spawn a
        # child process that re-runs this entrypoint: a new random ``web_password``
        # and ``secret_key`` are generated, so the password printed in the parent
        # no longer matches — login always fails. Disable the reloader; Flask
        # still serves interactive tracebacks.
        if self.debug:
            self.socketio.run(
                app,
                debug=True,
                use_reloader=False,
                host=host,
                port=self.web_port,
            )
        else:
            self.socketio.run(app, host=host, port=self.web_port)

    def run_in_background(self):
        """Start the web dashboard server in a background thread."""
        thread = Thread(target=self.run, daemon=True)
        thread.start()
        return thread

    def _register_socket_handlers(self):
        if not self.socketio:
            return

        @self.socketio.on("connect")
        def handle_connect():
            if self.web_password and not session.get("logged_in"):
                return False
            payload = self._build_scan_progress_payload()
            if payload:
                emit("scan_progress", payload)
            return True

    def _start_progress_monitor(self):
        if not self.socketio or self._progress_monitor_started:
            return
        self._stop_progress_monitor = False
        self._progress_monitor_started = True
        self.socketio.start_background_task(self._progress_monitor_loop)

    def stop_progress_monitor(self) -> None:
        """Request background progress monitor shutdown."""
        self._stop_progress_monitor = True
        self._progress_monitor_started = False

    def _progress_monitor_loop(self):
        while not self._stop_progress_monitor and self.socketio:
            try:
                self.collect_report_data()
                payload = self._build_scan_progress_payload()
                progress_key = (
                    payload.get("completed_vulnerabilities"),
                    payload.get("total_vulnerabilities"),
                    payload.get("is_partial"),
                    str(payload.get("status") or ""),
                    payload.get("model"),
                    payload.get("path"),
                    payload.get("updated_at"),
                    payload.get("active_phase"),
                    repr(payload.get("phases")),
                    repr(payload.get("adaptive_subphases")),
                ) if payload else None
                if payload and progress_key != self._last_emitted_progress_key:
                    self.socketio.emit("scan_progress", payload)
                    self._last_emitted_progress_key = progress_key
            except Exception:
                logger.debug("Progress monitor loop failed", exc_info=True)
            self.socketio.sleep(self._progress_monitor_interval_seconds())

    def emit_scan_progress(self, progress: dict) -> None:
        if not self.socketio:
            return
        if payload := self._build_scan_progress_payload(progress):
            self.socketio.emit("scan_progress", payload)
        else:
            return

    def _build_scan_progress_payload(self, progress: dict | None = None) -> dict:
        """Build realtime progress event payload from explicit or latest report progress."""
        if progress is None:
            progress = self._latest_scan_progress_from_report_data()
        if not progress:
            return {}
        payload = self._normalize_scan_progress_payload(progress, has_progress=True)
        payload["event_version"] = coerce_scan_progress_event_version(payload.get("event_version"))
        return payload

    @staticmethod
    def _progress_monitor_interval_seconds() -> float:
        """Polling interval for background progress monitor loop."""
        raw_interval = REPORT.get("DASHBOARD_PROGRESS_MONITOR_INTERVAL_SECONDS", 2.0)
        try:
            return max(0.25, float(raw_interval))
        except (TypeError, ValueError):
            return 2.0

    def _socketio_cors_allowed_origins(self) -> list[str]:
        """Origins allowed for Socket.IO, aligned with ``web_port`` and ``web_expose``.

        Must match how users open the dashboard (same host + port as the CLI).
        Optional ``REPORT['DASHBOARD_SOCKETIO_CORS_ALLOWED_ORIGINS']`` entries may use
        ``{port}`` and are merged after runtime origins.
        """
        try:
            port = int(self.web_port)
        except (TypeError, ValueError):
            port = 5000

        configured = REPORT.get("DASHBOARD_SOCKETIO_CORS_ALLOWED_ORIGINS")
        if isinstance(configured, str):
            parts = [p.strip() for p in configured.split(",") if p.strip()]
            cors_list = parts or ([configured.strip()] if configured.strip() else [])
        else:
            cors_list = list(configured or [])

        expanded_config = expand_socketio_cors_config_entries(cors_list, port)

        # Always allow this instance: same port as ``socketio.run(..., port=web_port)``.
        runtime: list[str] = [
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
        ]
        expose = str(self.web_expose or "local").strip().lower()
        if expose != "local":
            runtime.extend(socketio_lan_http_origins(port))

        merged: list[str] = []
        seen: set[str] = set()
        for origin in runtime + expanded_config:
            if origin and origin not in seen:
                seen.add(origin)
                merged.append(origin)

        logger.debug(
            "Socket.IO CORS allowed origins (web_port=%s, web_expose=%s): %s",
            port,
            self.web_expose,
            merged,
        )
        return merged

    def _socketio_options(self) -> dict:
        """Build Socket.IO kwargs for ``SocketIO(app, **...)``."""
        options: dict = {
            "cors_allowed_origins": self._socketio_cors_allowed_origins(),
        }
        async_mode = str(REPORT.get("DASHBOARD_SOCKETIO_ASYNC_MODE", "auto") or "auto").strip().lower()
        if async_mode and async_mode != "auto":
            options["async_mode"] = async_mode
        return options

    @staticmethod
    def _normalize_scan_progress_payload(progress: dict | None, has_progress: bool) -> dict:
        """Normalize scan progress payload for REST and Socket.IO consumers."""
        progress = dict(progress or {})
        tested_vulnerabilities = [
            str(item).strip()
            for item in (progress.get("tested_vulnerabilities") or [])
            if str(item).strip()
        ]
        completed = int(progress.get("completed_vulnerabilities", 0))
        total = int(progress.get("total_vulnerabilities", 0))
        is_partial = bool(progress.get("is_partial", False))
        status = str(progress.get("status") or ("in_progress" if is_partial else "complete"))
        payload = {
            "has_progress": has_progress,
            "completed_vulnerabilities": completed,
            "total_vulnerabilities": total,
            "is_partial": is_partial,
            "status": status,
            "model": progress.get("model"),
            "date": progress.get("date"),
            "path": progress.get("path"),
            "current_vulnerability": str(
                progress.get("current_vulnerability") or ""
            ),
            "tested_vulnerabilities": tested_vulnerabilities,
            "phases": WebServer._summary_phase_rows(progress.get("phases")),
        }
        for key in SCAN_PROGRESS_EXTENDED_KEYS:
            if key in WebServer._PROGRESS_DASHBOARD_HIDDEN_KEYS:
                continue
            if key == "phases":
                continue
            if key in progress:
                payload[key] = progress[key]
        return payload

    @staticmethod
    def _summary_phase_rows(raw_phases: object) -> list[dict]:
        """Keep only high-level pipeline phases for dashboard scan progress."""
        if not isinstance(raw_phases, list):
            return []
        rows: list[dict] = []
        for row in raw_phases:
            if not isinstance(row, dict):
                continue
            phase_id = str(row.get("id") or "").strip().lower()
            label = str(row.get("label") or "").strip().lower()
            if phase_id and phase_id in WebServer._PROGRESS_SUMMARY_PHASE_IDS:
                rows.append(row)
                continue
            if label in WebServer._PROGRESS_SUMMARY_PHASE_LABELS:
                rows.append(row)
        return rows

    @staticmethod
    def _summary_phase_catalog() -> dict[str, list[str]]:
        """Expose canonical summary phase ids/labels for dashboard JS filtering."""
        return {
            "ids": sorted(WebServer._PROGRESS_SUMMARY_PHASE_IDS),
            "labels": sorted(WebServer._PROGRESS_SUMMARY_PHASE_LABELS),
        }

    def _latest_scan_progress_from_report_data(self) -> dict:
        """Resolve latest executive-summary progress from indexed report data."""
        reports = self.report_data or []
        return self._latest_scan_progress_from_reports(reports)

    @staticmethod
    def _latest_scan_progress_from_reports(reports: list[dict]) -> dict:
        """Extract latest executive-summary progress object from report rows."""
        summary_reports = [
            report
            for report in (reports or [])
            if report.get("vulnerability_type") == "Executive Summary"
            and report.get("progress")
        ]
        summary_reports.sort(key=lambda report: report.get("date") or "", reverse=True)
        if not summary_reports:
            return {}
        latest = summary_reports[0]
        progress = dict(latest.get("progress") or {})
        progress["model"] = latest.get("model")
        progress["date"] = latest.get("date")
        progress["path"] = latest.get("path")
        return progress

    def _generate_random_password(self, length=10):
        """Generate a random password with letters, digits and special characters"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
        
    def _render_login_template(self, error=None):
        """Render the login template"""
        return render_template('login.html', error=error)

    def _report_preview_error_response(self, logger_message: str):
        logger.exception(logger_message)
        return (
            jsonify(
                {
                    'error': 'Failed to generate report preview. Please contact support if the problem persists.'
                }
            ),
            500,
        )

    def _resolve_assistant_ollama_url(self) -> str:
        for raw in (
            self.web_ollama_url,
            os.environ.get("OASIS_WEB_OLLAMA_URL"),
            self._default_ollama_url,
            OLLAMA_URL,
        ):
            if raw is None:
                continue
            if candidate := str(raw).strip():
                return candidate
        return str(OLLAMA_URL).strip()

    def _get_assistant_ollama_manager(self) -> OllamaManager:
        if self._assistant_ollama_manager is None:
            self._assistant_ollama_manager = OllamaManager(self._resolve_assistant_ollama_url())
        return self._assistant_ollama_manager

    def _embed_model_for_assistant(self, report_payload: Optional[Dict[str, Any]]) -> str:
        if self.web_embed_model and str(self.web_embed_model).strip():
            return str(self.web_embed_model).strip()
        if report_payload:
            em = report_payload.get("embed_model")
            if isinstance(em, str) and em.strip():
                return em.strip()
        return str(DEFAULT_ARGS.get("EMBED_MODEL") or "nomic-embed-text")

    def _assistant_chat_options(
        self, prep: Dict[str, Any], *, temperature: float
    ) -> Dict[str, Any]:
        """
        Build Ollama chat ``options`` dict.

        When the resolved runtime ``num_ctx`` is known (via ``ps()`` or
        ``Modelfile``), it is forwarded so Ollama is asked to honor the same
        context window the budget calculation assumes. Falls back to just
        ``temperature`` when the runtime window cannot be determined.
        """
        options: Dict[str, Any] = {'temperature': temperature}
        runtime_num_ctx = prep.get('runtime_num_ctx')
        if isinstance(runtime_num_ctx, int) and runtime_num_ctx > 0:
            options['num_ctx'] = runtime_num_ctx
        return options

    def _assistant_run_rag_retrieval(
        self,
        *,
        last_user: str,
        report_payload: Dict[str, Any],
        report_rel: str,
        rag_expand_project: bool,
        extra_report_file_paths: Optional[List[str]] = None,
    ) -> Tuple[str, bool]:
        """Return ``(rag_block, rag_unavailable)`` for assistant context."""
        em_model = self._embed_model_for_assistant(report_payload)
        root_path = resolve_assistant_cache_root(
            report_payload,
            self.security_dir.resolve(),
            self.input_path_absolute,
        )
        project_name = report_payload.get("project") if isinstance(report_payload, dict) else None
        cache_path = embedding_cache_file_path(root_path, em_model, project_name=project_name)

        try:
            cb = load_embedding_code_base(cache_path)
        except OSError as exc:
            logger.warning(
                "Assistant RAG cache read failed report_path=%s cache=%s err=%s",
                report_rel,
                cache_path,
                type(exc).__name__,
            )
            return "", True

        if not cb:
            return "", False

        try:
            client = self._get_assistant_ollama_manager().get_client()
            er = client.embeddings(model=em_model, prompt=last_user[:8000])
        except Exception as exc:
            logger.warning(
                "Assistant RAG embedding request failed report_path=%s embed_model=%s cache=%s err=%s",
                report_rel,
                em_model,
                cache_path,
                type(exc).__name__,
                exc_info=True,
            )
            return "", True

        qe = er.get("embedding") if isinstance(er, dict) else None
        if not isinstance(qe, list) or not qe:
            logger.warning(
                "Assistant RAG missing query embedding report_path=%s embed_model=%s",
                report_rel,
                em_model,
            )
            return "", True

        fps: List[str] = []
        for fe in report_payload.get("files") or []:
            if isinstance(fe, dict):
                fp = fe.get("file_path")
                if isinstance(fp, str):
                    fps.append(fp)

        rag_stats: Dict[str, int] = {}
        try:
            rag_block = retrieve_relevant_snippets(
                code_base=cb,
                report_file_paths=fps,
                query_embedding=qe,
                top_k=5,
                expand_project_wide=rag_expand_project,
                extra_report_file_paths=extra_report_file_paths,
                stats_out=rag_stats,
                cache_path=cache_path,
                embed_model=em_model,
            )
        except Exception as exc:
            logger.warning(
                "Assistant RAG snippet retrieval failed report_path=%s embed_model=%s cache=%s err=%s",
                report_rel,
                em_model,
                cache_path,
                type(exc).__name__,
                exc_info=True,
            )
            return "", True

        return rag_block, False

    def _assistant_load_primary_payload_from_disk_or_synthetic(
        self,
        resolved_report: Path,
        primary_synthetic: Optional[Any],
    ):
        """Return ``(payload_dict, None)`` or ``(None, http_error_tuple)``."""
        if primary_synthetic is not None:
            payload = primary_synthetic
        else:
            try:
                with open(resolved_report, 'r', encoding='utf-8') as rf:
                    payload = json.load(rf)
            except Exception:
                return None, assistant_http_error(ERR_COULD_NOT_READ_REPORT, HTTP_INTERNAL)
        if not isinstance(payload, dict):
            return None, assistant_http_error(ERR_INVALID_REPORT, HTTP_UNPROCESSABLE)
        return payload, None

    def _assistant_fetch_rag_block_if_enabled(
        self,
        data: Dict[str, Any],
        messages: List[Dict[str, Any]],
        rag_source_payload: Dict[str, Any],
        report_rel: str,
        rag_budget: int,
        extra_rag_paths: Optional[List[str]],
    ) -> Tuple[str, bool]:
        rag_block = ''
        rag_unavailable = False
        if not self.web_assistant_rag or bool(data.get('rag_disabled')):
            return rag_block, rag_unavailable
        last_user = extract_last_user_message_text(messages)
        if not last_user.strip():
            return rag_block, rag_unavailable
        rag_block, rag_unavailable = self._assistant_run_rag_retrieval(
            last_user=last_user,
            report_payload=rag_source_payload,
            report_rel=report_rel,
            rag_expand_project=bool(data.get('rag_expand_project')),
            extra_report_file_paths=extra_rag_paths,
        )
        if rag_block and len(rag_block) > rag_budget:
            rag_block = shrink_rag_block(rag_block, rag_budget)
        return rag_block, rag_unavailable

    def _assistant_shrink_user_labels_if_any(
        self,
        data: Dict[str, Any],
        labels_budget: int,
    ) -> str:
        labels_note = data.get('user_finding_labels')
        if isinstance(labels_note, str) and labels_note.strip():
            return shrink_user_labels_block(labels_note.strip(), labels_budget)
        return ''

    def _assistant_load_persisted_finding_validation(
        self,
        data: Dict[str, Any],
        report_rel: str,
        chat_model: str,
        finding_key_for_prompt: str,
    ) -> Optional[Dict[str, Any]]:
        sid_ctx = data.get('session_id')
        try:
            if isinstance(sid_ctx, str) and validate_session_id(sid_ctx.strip()):
                loaded_sess = load_chat_session(
                    self.security_dir, report_rel, sid_ctx.strip()
                )
                return get_finding_validation_for_branch(
                    loaded_sess,
                    chat_model,
                    finding_key_for_prompt,
                )
        except Exception:
            logger.warning(
                'Assistant chat context build failed; continuing without persisted finding validation',
                exc_info=True,
            )
        return None

    def _assistant_diagnose_runtime_ctx_budget(
        self,
        budget_meta: Any,
        section_lengths: Dict[str, Any],
        total_budget: int,
    ) -> Optional[int]:
        """Best-effort compare assembled prompt size to Ollama runtime ``num_ctx``."""
        runtime_num_ctx: Optional[int] = None
        context_source = budget_meta.context_source or ""
        try:
            runtime_num_ctx = budget_meta.ollama_runtime_num_ctx()
            configured = budget_meta.effective_chars_per_token()
            total_len = int(section_lengths["total"])
            if (
                runtime_num_ctx
                and configured is not None
                and total_len > runtime_num_ctx * configured
            ):
                prompt_chars_per_ctx_token = total_len / runtime_num_ctx
                logger.warning(
                    "Assistant system prompt larger than runtime context allows "
                    "(prompt_chars=%s runtime_num_ctx=%s prompt_chars_per_ctx_token=%.2f "
                    "configured_chars_per_token=%s context_source=%s budget=%s)",
                    total_len,
                    runtime_num_ctx,
                    prompt_chars_per_ctx_token,
                    configured,
                    context_source,
                    total_budget,
                )
        except Exception:
            logger.warning(
                "Assistant budget/section length diagnostic failed; skipping ctx-size warning",
                exc_info=True,
            )
        return runtime_num_ctx

    def _assistant_chat_validate_and_load_report(
        self,
        data: Dict[str, Any],
    ) -> Union[_AssistantChatReportLoad, AssistantChatPrepError]:
        messages, msg_err = validate_assistant_messages(
            data.get('messages'),
            max_messages=self._ASSISTANT_MAX_MESSAGES,
            max_message_chars=self._ASSISTANT_MAX_MESSAGE_CHARS,
        )
        if msg_err is not None:
            return AssistantChatPrepError.from_http_tuple(msg_err)
        assert messages is not None

        approx_msg_chars = sum(
            len(str(m.get('content') or '')) for m in messages if isinstance(m, dict)
        )

        report_rel_raw = str(data.get('report_path') or '').strip()
        if not report_rel_raw:
            return AssistantChatPrepError.from_http_tuple(
                assistant_http_error(ERR_REPORT_PATH_REQUIRED, HTTP_BAD_REQUEST)
            )

        security_root = self.security_dir.resolve()
        resolved_report, primary_synthetic, path_err = resolve_assistant_primary_payload(
            self.security_dir,
            report_rel_raw,
        )
        if path_err is not None:
            return AssistantChatPrepError.from_http_tuple(path_err)
        assert resolved_report is not None

        aggregate_mode = bool(data.get('aggregate_model_json'))
        if aggregate_mode and resolved_report.stem.lower() != '_executive_summary':
            return AssistantChatPrepError.from_http_tuple(
                assistant_http_error(ERR_AGGREGATE_REQUIRES_EXECUTIVE, HTTP_BAD_REQUEST)
            )

        primary_payload, load_err = self._assistant_load_primary_payload_from_disk_or_synthetic(
            resolved_report,
            primary_synthetic,
        )
        if load_err is not None:
            return AssistantChatPrepError.from_http_tuple(load_err)
        assert primary_payload is not None

        report_rel = str(resolved_report.relative_to(security_root)).replace('\\', '/')

        json_paths_for_union: List[Path] = []
        extra_rag_paths: Optional[List[str]] = None
        rag_source_payload: Dict[str, Any] = primary_payload
        md_obj: Optional[Path] = None

        if aggregate_mode:
            md_obj, json_paths_for_union, rag_source_payload, extra_rag_paths, agg_err = (
                prepare_aggregate_branch_paths(
                    security_root,
                    resolved_report,
                    primary_payload,
                )
            )
            if agg_err is not None:
                return AssistantChatPrepError.from_http_tuple(agg_err)

        return _AssistantChatReportLoad(
            messages=messages,
            approx_msg_chars=approx_msg_chars,
            resolved_report=resolved_report,
            primary_payload=primary_payload,
            report_rel=report_rel,
            aggregate_mode=aggregate_mode,
            json_paths_for_union=json_paths_for_union,
            extra_rag_paths=extra_rag_paths,
            rag_source_payload=rag_source_payload,
            md_obj=md_obj,
        )

    def _assistant_chat_budget_and_report_summary(
        self,
        data: Dict[str, Any],
        loaded: _AssistantChatReportLoad,
    ) -> Union[_AssistantChatBudgetSummary, AssistantChatPrepError]:
        security_root = self.security_dir.resolve()
        chat_model = resolve_assistant_chat_model(
            data,
            loaded.primary_payload,
            loaded.aggregate_mode,
            loaded.json_paths_for_union,
            loaded.rag_source_payload,
        )
        if not chat_model:
            return AssistantChatPrepError.from_http_tuple(
                assistant_http_error(ERR_CHAT_MODEL_REQUIRED, HTTP_BAD_REQUEST)
            )

        total_budget, budget_meta = assistant_total_system_budget_chars(
            fallback_total=self._ASSISTANT_MAX_TOTAL_REPORT_CHARS,
            ollama_manager=self._get_assistant_ollama_manager(),
            chat_model=chat_model,
            approx_message_chars_in_request=loaded.approx_msg_chars,
        )
        subbudgets = compute_verdict_first_subbudgets(total_budget)
        report_sum_budget = subbudgets["report_summary"]
        merge_budget = report_sum_budget * REPORT_SUMMARY_AGGREGATE_MERGE_BUDGET_FACTOR
        report_summary_payload, excerpt_truncated = build_report_summary_payload(
            aggregate_mode=loaded.aggregate_mode,
            json_paths_for_union=loaded.json_paths_for_union,
            security_root=security_root,
            primary_payload=loaded.primary_payload,
            aggregate_char_budget=merge_budget,
        )
        report_summary_text = compact_report_excerpt(
            report_summary_payload,
            max_chars=report_sum_budget,
        )
        return _AssistantChatBudgetSummary(
            chat_model=chat_model,
            total_budget=total_budget,
            budget_meta=budget_meta,
            subbudgets=subbudgets,
            report_summary_text=report_summary_text,
            excerpt_truncated=excerpt_truncated,
            report_sum_budget=report_sum_budget,
        )

    def _assistant_chat_finalize_context_dict(
        self,
        data: Dict[str, Any],
        loaded: _AssistantChatReportLoad,
        summary: _AssistantChatBudgetSummary,
    ) -> Union[Dict[str, Any], AssistantChatPrepError]:
        security_root = self.security_dir.resolve()
        subbudgets = summary.subbudgets

        fi, ci, gi = coerce_finding_indices(data)
        finding_scope_for_key = ''
        if loaded.aggregate_mode:
            scope_raw = data.get('finding_scope_report_path')
            if isinstance(scope_raw, str) and scope_raw.strip():
                finding_scope_for_key = scope_raw.strip()
        finding_key_for_prompt = finding_validation_storage_key(
            finding_scope_for_key,
            fi,
            ci,
            gi,
        )
        finding_json, finding_scope_err = build_assistant_finding_json_prompt_block(
            aggregate_mode=loaded.aggregate_mode,
            primary_payload=loaded.primary_payload,
            data=data,
            security_root=security_root,
            resolved_report=loaded.resolved_report,
            md_obj=loaded.md_obj,
            fi=fi,
            ci=ci,
            gi=gi,
            finding_max=subbudgets['selected_finding'],
        )
        if finding_scope_err is not None:
            return AssistantChatPrepError.from_http_tuple(
                assistant_http_error(finding_scope_err, HTTP_BAD_REQUEST)
            )
        assert finding_json is not None

        rag_block, rag_unavailable = self._assistant_fetch_rag_block_if_enabled(
            data,
            loaded.messages,
            loaded.rag_source_payload,
            loaded.report_rel,
            subbudgets['rag'],
            loaded.extra_rag_paths,
        )

        user_labels = self._assistant_shrink_user_labels_if_any(data, subbudgets['user_labels'])

        finding_validation_for_prompt = self._assistant_load_persisted_finding_validation(
            data,
            loaded.report_rel,
            summary.chat_model,
            finding_key_for_prompt,
        )

        system_content, section_lengths = assemble_verdict_first_prompt(
            system_intro=self._ASSISTANT_SYSTEM_INTRO_PREFIX,
            finding_validation=finding_validation_for_prompt,
            selected_finding_json=finding_json,
            rag_block=rag_block,
            report_summary=summary.report_summary_text,
            user_labels=user_labels,
            total_budget=summary.total_budget,
        )

        context_source = summary.budget_meta.context_source or ""
        runtime_num_ctx = self._assistant_diagnose_runtime_ctx_budget(
            summary.budget_meta,
            section_lengths,
            summary.total_budget,
        )
        if summary.excerpt_truncated:
            logger.info(
                "Assistant aggregate report summary inputs truncated (budget=%s)",
                summary.report_sum_budget,
            )

        full_messages = full_messages_from_system_and_dialogue(system_content, loaded.messages)

        return {
            'full_messages': full_messages,
            'chat_model': summary.chat_model,
            'messages': loaded.messages,
            'primary_payload': loaded.primary_payload,
            'report_rel': loaded.report_rel,
            'aggregate_mode': loaded.aggregate_mode,
            'rag_unavailable': bool(rag_unavailable),
            'total_budget': summary.total_budget,
            'runtime_num_ctx': runtime_num_ctx,
            'context_source': context_source,
            'excerpt_truncated': summary.excerpt_truncated,
            'section_lengths': section_lengths,
            'session_id_hint': data.get('session_id'),
        }

    def _prepare_assistant_chat_context(self, data: Any):
        """Build the assistant chat context shared by JSON and streaming endpoints.

        Returns either a context dict ready for an LLM call or :class:`AssistantChatPrepError`
        (surface with ``jsonify(err.body), err.status``).

        The dict contains: ``full_messages`` (list for ollama), ``chat_model``,
        ``messages`` (validated user-visible), ``primary_payload``, ``report_rel``,
        ``aggregate_mode``, ``rag_unavailable``, ``total_budget``, ``excerpt_truncated``
        and ``session_id_hint`` (raw session_id from request, may be ``None``).
        """
        if not isinstance(data, dict):
            return AssistantChatPrepError.from_http_tuple(
                assistant_http_error(ERR_INVALID_JSON, HTTP_BAD_REQUEST)
            )

        loaded = self._assistant_chat_validate_and_load_report(data)
        if isinstance(loaded, AssistantChatPrepError):
            return loaded

        summary = self._assistant_chat_budget_and_report_summary(data, loaded)
        if isinstance(summary, AssistantChatPrepError):
            return summary

        return self._assistant_chat_finalize_context_dict(data, loaded, summary)

    def _resolve_assistant_session_id(self, session_id_hint: Any) -> str:
        if isinstance(session_id_hint, str) and validate_session_id(session_id_hint.strip()):
            return session_id_hint.strip()
        return new_session_id()

    def _persist_assistant_reply(self, prep: Dict[str, Any], raw: str, sess_id: str) -> None:
        ts = utc_now_iso()
        persist_msgs = normalize_validated_messages_for_storage(prep['messages'], default_at=ts)
        persist_msgs.append({'role': 'assistant', 'content': raw, 'at': ts})
        if prep['aggregate_mode']:
            vuln_label = 'Executive summary (aggregate)'
        else:
            vn = prep['primary_payload'].get('vulnerability_name')
            vuln_label = vn.strip() if isinstance(vn, str) else ''
        try:
            save_chat_session(
                self.security_dir,
                prep['report_rel'],
                sess_id,
                persist_msgs,
                prep['chat_model'],
                vuln_label,
            )
        except (ValueError, OSError):
            logger.warning('Assistant session save failed', exc_info=True)

    def _persist_partial_assistant_stream_reply(
        self,
        prep: Dict[str, Any],
        sess_id: str,
        content_parts: List[str],
        thinking_parts: List[str],
    ) -> None:
        """Best-effort persist when streaming stops after partial output (error mid-stream)."""
        raw = ''.join(content_parts).strip()
        thinking = ''.join(thinking_parts).strip()
        if not raw and not thinking:
            return
        stored = raw or thinking
        self._persist_assistant_reply(prep, stored, sess_id)

    def _finalize_assistant_chat_response(self, prep: Dict[str, Any], raw: str) -> Dict[str, Any]:
        split = parse_assistant_think(raw)
        sess_id = self._resolve_assistant_session_id(prep.get('session_id_hint'))
        self._persist_assistant_reply(prep, raw, sess_id)
        return {
            'message': raw,
            'visible_markdown': split.visible_markdown,
            'thought_segments': split.thought_segments,
            'session_id': sess_id,
            'model': prep['chat_model'],
            'rag_unavailable': bool(prep['rag_unavailable']),
            'system_budget_chars': prep['total_budget'],
            'assistant_aggregate': prep['aggregate_mode'],
        }

    def _stream_assistant_chat_response(self, prep: Dict[str, Any]):
        """Return a Flask streaming response yielding NDJSON assistant events."""
        from flask import Response, stream_with_context

        def ndjson(event: Dict[str, Any]) -> str:
            return json.dumps(event, ensure_ascii=False) + '\n'

        def event_stream():
            sess_id = self._resolve_assistant_session_id(prep.get('session_id_hint'))
            stream_opts = self._assistant_chat_options(prep, temperature=0.2)
            self._log_assistant_llm_debug(
                'POST /api/assistant/chat-stream ollama_request',
                {
                    'model': prep['chat_model'],
                    'options': stream_opts,
                    'messages': prep['full_messages'],
                    'context': self._assistant_llm_debug_payload(prep),
                },
            )
            yield ndjson(
                {
                    'type': 'start',
                    'session_id': sess_id,
                    'model': prep['chat_model'],
                    'rag_unavailable': bool(prep['rag_unavailable']),
                    'system_budget_chars': prep['total_budget'],
                    'assistant_aggregate': prep['aggregate_mode'],
                }
            )
            content_parts: List[str] = []
            thinking_parts: List[str] = []
            stream_chunks: List[Any] = []
            try:
                om = self._get_assistant_ollama_manager()
                for chunk in om.chat_stream(
                    prep['chat_model'],
                    prep['full_messages'],
                    options=stream_opts,
                ):
                    if isinstance(chunk, dict) and chunk.get('type') == 'error':
                        self._persist_partial_assistant_stream_reply(
                            prep, sess_id, content_parts, thinking_parts
                        )
                        err = chunk.get('error')
                        err_msg = err if isinstance(err, str) else f'{type(err).__name__}'
                        self._log_assistant_llm_debug(
                            'POST /api/assistant/chat-stream ollama_stream_error',
                            {
                                'error': err_msg,
                                'partial_content': ''.join(content_parts),
                                'partial_thinking': ''.join(thinking_parts),
                                'chunks': stream_chunks,
                            },
                        )
                        yield ndjson({'type': 'error', 'error': err_msg})
                        return
                    if isinstance(chunk, dict):
                        stream_chunks.append(chunk)
                    msg = chunk.get('message') if isinstance(chunk, dict) else None
                    if not isinstance(msg, dict):
                        continue
                    # Ollama-python exposes ``thinking`` separately when ``think=True``
                    # is negotiated; forward it as a dedicated delta so the UI can
                    # render reasoning without polluting the visible markdown body.
                    thinking_delta = msg.get('thinking') or ''
                    if isinstance(thinking_delta, str) and thinking_delta:
                        thinking_parts.append(thinking_delta)
                        yield ndjson({'type': 'delta', 'channel': 'thinking', 'content': thinking_delta})
                    content_delta = msg.get('content') or ''
                    if isinstance(content_delta, str) and content_delta:
                        content_parts.append(content_delta)
                        yield ndjson({'type': 'delta', 'channel': 'content', 'content': content_delta})
            except Exception as exc:
                logger.exception('Assistant chat stream failed')
                self._persist_partial_assistant_stream_reply(
                    prep, sess_id, content_parts, thinking_parts
                )
                self._log_assistant_llm_debug(
                    'POST /api/assistant/chat-stream ollama_exception',
                    {
                        'error': f'{type(exc).__name__}: {exc}',
                        'partial_content': ''.join(content_parts),
                        'partial_thinking': ''.join(thinking_parts),
                        'chunks': stream_chunks,
                    },
                )
                yield ndjson(
                    {
                        'type': 'error',
                        'error': f'Assistant request failed: {type(exc).__name__}',
                    }
                )
                return
            raw = ''.join(content_parts)
            split = parse_assistant_think(raw)
            # Prepend any native ``thinking`` stream to thought segments so the UI
            # surfaces reasoning even when the model never emits harmony tags.
            native_thinking = ''.join(thinking_parts).strip()
            if native_thinking:
                split = AssistantThinkSplit(
                    visible_markdown=split.visible_markdown,
                    thought_segments=[native_thinking, *split.thought_segments],
                )
            self._persist_assistant_reply(prep, raw, sess_id)
            done_event = {
                'type': 'done',
                'message': raw,
                'visible_markdown': split.visible_markdown,
                'thought_segments': split.thought_segments,
                'session_id': sess_id,
                'model': prep['chat_model'],
                'rag_unavailable': bool(prep['rag_unavailable']),
                'system_budget_chars': prep['total_budget'],
                'assistant_aggregate': prep['aggregate_mode'],
            }
            self._log_assistant_llm_debug(
                'POST /api/assistant/chat-stream ollama_stream_complete',
                {
                    'done': done_event,
                    'native_thinking_concat': native_thinking,
                    'stream_chunk_count': len(stream_chunks),
                    'raw_ollama_chunks': stream_chunks,
                },
            )
            yield ndjson(done_event)

        return Response(
            stream_with_context(event_stream()),
            mimetype='application/x-ndjson',
            headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
        )

    def register_routes(self, app, server, login_required):
        # Logout route
        @app.route('/logout', methods=['GET'])
        def logout():
            session.pop('logged_in', None)
            return redirect(url_for('login'))

        @app.route('/')
        @login_required
        def dashboard():
            """Main dashboard page"""

            return render_template(
                'dashboard.html',
                model_emojis=MODEL_EMOJIS,
                vuln_emojis=VULN_EMOJIS,
                languages=LANGUAGES,
                progress_summary_phases=WebServer._summary_phase_catalog(),
                dashboard_realtime_enabled=bool(REPORT.get("DASHBOARD_REALTIME_ENABLED", True)),
                dashboard_socketio_client_url=str(REPORT.get("DASHBOARD_SOCKETIO_CLIENT_URL") or "").strip(),
                debug=self.debug,
                report_output_formats=REPORT.get('OUTPUT_FORMATS', []),
                dashboard_format_display_order=dashboard_format_display_order(),
                dashboard_assistant_enabled=True,
                dashboard_assistant_rag_default=bool(getattr(self, "web_assistant_rag", True)),
            )

        @app.route('/api/reports')
        @login_required
        def get_reports():
            # Get filter parameters
            model_filter = request.args.get('model', '')
            format_filter = request.args.get('format', '')
            vuln_filter = request.args.get('vulnerability', '')
            severity_filter = request.args.get('severity', '')
            language_filter = request.args.get('language', '')
            project_filter = request.args.get('project', '')
            start_date = request.args.get('start_date', None)
            end_date = request.args.get('end_date', None)
            md_dates_only = request.args.get('md_dates_only', '1') == '1'

            if request.args.get('force', '0') == '1':
                self.collect_report_data()
            # Filter reports based on parameters
            filtered_data = self.filter_reports(
                model_filter=model_filter,
                format_filter=format_filter,
                vuln_filter=vuln_filter,
                severity_filter=severity_filter,
                language_filter=language_filter,
                project_filter=project_filter,
                start_date=start_date,
                end_date=end_date,
                md_dates_only=md_dates_only,
            )
            return jsonify(filtered_data)

        @app.route('/api/stats')
        @login_required
        def get_stats():
            # Filter reports based on parameters
            filtered_data = self.filter_reports(
                model_filter=request.args.get('model', ''),
                format_filter=request.args.get('format', ''),
                vuln_filter=request.args.get('vulnerability', ''),
                severity_filter=request.args.get('severity', ''),
                language_filter=request.args.get('language', ''),
                project_filter=request.args.get('project', ''),
                start_date=request.args.get('start_date', None),
                end_date=request.args.get('end_date', None),
                md_dates_only=request.args.get('md_dates_only', '1') == '1',
            )
            return jsonify(self.get_report_statistics(filtered_reports=filtered_data))

        @app.route('/api/progress')
        @login_required
        def get_progress():
            filtered_data = self.filter_reports(
                model_filter=request.args.get('model', ''),
                format_filter='',
                vuln_filter='Executive Summary',
                severity_filter=request.args.get('severity', ''),
                language_filter=request.args.get('language', ''),
                project_filter=request.args.get('project', ''),
                start_date=request.args.get('start_date', None),
                end_date=request.args.get('end_date', None),
                md_dates_only=request.args.get('md_dates_only', '1') == '1',
            )
            return jsonify(self.get_scan_progress(filtered_reports=filtered_data))

        @app.route('/reports/<path:filename>')
        @login_required
        def serve_report(filename):
            security_dir = self.security_dir
            # The complete path now includes the timestamp directory
            return send_from_directory(security_dir, filename)

        def _path_allowed_by_active_filters(resolved_path: Path, security_root: Path) -> bool:
            """True when ``resolved_path`` belongs to the currently filtered dashboard dataset."""
            filter_kwargs = self._request_dashboard_filter_kwargs(request.args)
            if not self._has_any_active_dashboard_filter(filter_kwargs):
                return True
            filtered_reports = list(self.filter_reports(**filter_kwargs))
            allowed_paths = self._allowed_paths_for_filtered_reports(filtered_reports)
            try:
                rel_path = WebServer._normalize_dashboard_relative_report_path(
                    resolved_path.relative_to(security_root).as_posix()
                )
            except ValueError:
                return False
            return rel_path in allowed_paths

        def _filtered_out_preview_response():
            return jsonify({'error': 'Report path is outside the active filter scope'}), 409

        @app.route('/api/report-content/<path:filename>')
        @login_required
        def get_report_content(filename):
            # Legacy markdown preview only when no canonical JSON exists for the same stem.
            try:
                allow_canonical_json_preview = request.args.get('allow_canonical_json_preview', '0') == '1'
                file_path = self.security_dir / filename
                security_root = self.security_dir.resolve()
                resolved_path = file_path.resolve(strict=False)

                if not is_path_within_root(resolved_path, security_root):
                    return jsonify({'error': 'Invalid path'}), 403

                if not resolved_path.exists() or resolved_path.suffix != '.md':
                    return jsonify({'error': 'File not found or not a markdown file'}), 404
                if not _path_allowed_by_active_filters(resolved_path, security_root):
                    return _filtered_out_preview_response()

                rel_path = resolved_path.relative_to(security_root)
                rel_parts = rel_path.parts
                if len(rel_parts) < 2:
                    return jsonify({'error': 'Invalid report path'}), 400

                json_path = json_sibling_for_format_artifact(resolved_path)
                if json_path.exists() and not allow_canonical_json_preview:
                    return (
                        jsonify(
                            {
                                'error': 'Canonical report is JSON; use JSON preview endpoint.',
                            }
                        ),
                        409,
                    )
                html_content = self.report.read_and_convert_markdown(resolved_path)
                html_content = rewrite_report_preview_anchor_hrefs(html_content, resolved_path, security_root)
                if resolved_path.stem.lower() == "_executive_summary" and resolved_path.suffix.lower() == ".md":
                    html_content = augment_executive_markdown_preview_html(html_content)
                return jsonify({'content': html_content})
            except Exception:
                return self._report_preview_error_response("Error while generating markdown report preview")

        @app.route('/api/report-json/<path:filename>')
        @login_required
        def get_report_json(filename):
            try:
                file_path = self.security_dir / filename
                security_root = self.security_dir.resolve()
                resolved_path = file_path.resolve(strict=False)

                if not is_path_within_root(resolved_path, security_root):
                    return jsonify({'error': 'Invalid path'}), 403
                if resolved_path.suffix.lower() != '.json':
                    return jsonify({'error': 'File not found or not JSON'}), 404
                if not resolved_path.exists():
                    if resolved_path.stem.lower() == '_executive_summary':
                        md_only = resolved_path.parent.parent / 'md' / '_executive_summary.md'
                        if md_only.is_file():
                            md_dir = model_directory_from_security_report_file(security_root, md_only)
                            if md_dir is not None:
                                return jsonify(synthetic_executive_primary_payload(md_dir))
                    return jsonify({'error': 'File not found or not JSON'}), 404
                if not _path_allowed_by_active_filters(resolved_path, security_root):
                    return _filtered_out_preview_response()
                if is_executive_summary_progress_sidecar(resolved_path):
                    return jsonify(
                        {'error': 'Incremental progress sidecar is not a canonical vulnerability report JSON'}
                    ), 404
                with open(resolved_path, 'r', encoding='utf-8') as f:
                    payload = json.load(f)
                if not isinstance(payload, dict):
                    return jsonify({'error': 'Invalid JSON report payload'}), 422
                severity_tiers = parse_severity_filter_param(request.args.get('severity', ''))
                payload = self._filter_vulnerability_payload_by_severity_tiers(
                    payload,
                    severity_tiers,
                    rewrite_stats_totals=True,
                )
                return jsonify(payload)
            except Exception:
                return self._report_preview_error_response("Error while generating JSON report preview")

        @app.route('/api/source-snippet', methods=['GET'])
        @login_required
        def get_source_snippet():
            rel = request.args.get('path', '').strip()
            if not rel or rel.startswith('/') or '..' in Path(rel).parts:
                return jsonify({'error': 'Invalid path'}), 400
            try:
                start_line = int(request.args.get('start_line', '1'))
                end_line = int(request.args.get('end_line', '1'))
            except ValueError:
                return jsonify({'error': 'Invalid line range'}), 400
            root = self.input_path_absolute.resolve()
            target = (root / rel).resolve(strict=False)
            if not is_path_within_root(target, root):
                return jsonify({'error': 'Invalid path'}), 403
            if not target.is_file():
                return jsonify({'error': 'File not found'}), 404
            try:
                text = target.read_text(encoding='utf-8', errors='replace')
            except OSError:
                return jsonify({'error': 'Unreadable file'}), 500
            lines = text.splitlines()
            start_line = max(1, start_line)
            end_line = max(start_line, end_line)
            chunk = lines[start_line - 1 : end_line]
            return jsonify({'lines': chunk, 'start_line': start_line, 'end_line': end_line, 'path': rel})

        @app.route('/api/executive-preview-meta', methods=['GET'])
        @login_required
        def executive_preview_meta():
            rel = request.args.get('path', '').strip()
            if not rel:
                return jsonify({'error': 'path required'}), 400
            try:
                file_path = self.security_dir / rel
                security_root = self.security_dir.resolve()
                resolved = file_path.resolve(strict=False)
                if not is_path_within_root(resolved, security_root):
                    return jsonify({'error': 'Invalid path'}), 403
                if not resolved.is_file():
                    return jsonify({'error': 'File not found'}), 404
                model_dir = model_directory_from_security_report_file(security_root, resolved)
                if model_dir is None:
                    return jsonify({'error': 'Could not resolve model directory'}), 400
                filter_kwargs = self._request_dashboard_filter_kwargs(request.args)
                if not self._has_any_active_dashboard_filter(filter_kwargs):
                    meta = rollup_severity_counts_from_model_dir(model_dir)
                    meta['vulnerability_reports'] = vulnerability_reports_for_executive_assistant(
                        model_dir, security_root
                    )
                    return jsonify(meta)
                filtered_reports = list(self.filter_reports(**filter_kwargs))
                allowed_paths = self._allowed_paths_for_filtered_reports(filtered_reports)
                if not allowed_paths:
                    return jsonify({'severity_counts': {}, 'vulnerability_reports': []})

                model_rel_prefix = WebServer._normalize_dashboard_relative_report_path(
                    model_dir.relative_to(security_root).as_posix()
                ).rstrip("/") + "/"
                scoped_reports = [
                    report
                    for report in filtered_reports
                    if WebServer._normalize_dashboard_relative_report_path(str(report.get("path") or "")).startswith(
                        model_rel_prefix
                    )
                    and str(report.get("format") or "").lower() == "json"
                    and str(report.get("vulnerability_type") or "") != "Executive Summary"
                ]
                severity_counts = empty_severity_finding_totals()
                for report in scoped_reports:
                    merge_severity_finding_totals_for_report(severity_counts, report)
                vuln_reports = [
                    item
                    for item in vulnerability_reports_for_executive_assistant(model_dir, security_root)
                    if WebServer._normalize_dashboard_relative_report_path(item.get("relative_path"))
                    in allowed_paths
                ]
                meta = {
                    "severity_counts": severity_counts,
                    "vulnerability_report_files": len(vuln_reports),
                    "vulnerability_reports": vuln_reports,
                }
                return jsonify(meta)
            except Exception:
                return self._report_preview_error_response("Error while building executive preview meta")

        @app.route('/api/assistant/chat-models', methods=['GET'])
        @login_required
        def assistant_chat_models():
            try:
                names = self._get_assistant_ollama_manager().list_chat_model_names()
            except Exception:
                names = []
            return jsonify({'models': names})

        @app.route('/api/assistant/chat', methods=['POST'])
        @login_required
        def assistant_chat():
            prep = self._prepare_assistant_chat_context(request.get_json(silent=True))
            if isinstance(prep, AssistantChatPrepError):
                return jsonify(prep.body), prep.status

            chat_opts = self._assistant_chat_options(prep, temperature=0.2)
            self._log_assistant_llm_debug(
                'POST /api/assistant/chat ollama_request',
                {
                    'model': prep['chat_model'],
                    'options': chat_opts,
                    'messages': prep['full_messages'],
                    'context': self._assistant_llm_debug_payload(prep),
                },
            )
            try:
                om = self._get_assistant_ollama_manager()
                resp = om.chat(
                    prep['chat_model'],
                    prep['full_messages'],
                    options=chat_opts,
                )
            except Exception as exc:
                logger.exception('Assistant chat failed')
                return jsonify({'error': f'Assistant request failed: {type(exc).__name__}'}), 502

            self._log_assistant_llm_debug(
                'POST /api/assistant/chat ollama_response',
                {'raw': resp},
            )
            msg = resp.get('message') if isinstance(resp, dict) else None
            raw = ''
            if isinstance(msg, dict):
                raw = msg.get('content') or ''
            body = self._finalize_assistant_chat_response(prep, raw if isinstance(raw, str) else '')
            return jsonify(body)

        @app.route('/api/assistant/chat-stream', methods=['POST'])
        @login_required
        def assistant_chat_stream():
            prep = self._prepare_assistant_chat_context(request.get_json(silent=True))
            if isinstance(prep, AssistantChatPrepError):
                return jsonify(prep.body), prep.status
            return self._stream_assistant_chat_response(prep)

        @app.route('/api/assistant/investigate', methods=['POST'])
        @login_required
        def assistant_investigate():
            from oasis.agent.assistant_invoke import (
                coerce_investigation_budget,
                invoke_assistant_validation,
            )
            from oasis.helpers.executive.assistant_scope import (
                resolve_aggregate_finding_scope_payload,
            )
            from oasis.schemas.analysis import InvestigationScope

            try:
                data = request.get_json(silent=True)
            except Exception:
                data = None
            if not isinstance(data, dict):
                return jsonify({'error': 'Invalid JSON'}), 400

            report_rel_raw = str(data.get('report_path') or '').strip()
            if not report_rel_raw:
                return jsonify({'error': 'report_path required'}), 400

            security_root = self.security_dir.resolve()
            resolved_report, primary_synthetic, path_err = resolve_assistant_primary_payload(
                self.security_dir,
                report_rel_raw,
            )
            if path_err is not None:
                err_body, status = path_err
                return jsonify(err_body), status
            assert resolved_report is not None

            if primary_synthetic is not None:
                primary_payload = primary_synthetic
            else:
                try:
                    with open(resolved_report, 'r', encoding='utf-8') as rf:
                        primary_payload = json.load(rf)
                except Exception:
                    return jsonify({'error': 'Could not read report'}), 500
            if not isinstance(primary_payload, dict):
                return jsonify({'error': 'Invalid report'}), 422

            vulnerability_name = str(data.get('vulnerability_name') or '').strip() or str(primary_payload.get('vulnerability_name') or '').strip()

            # Candidate scan roots, in priority order:
            #   1. explicit ``scan_root`` from the request payload
            #   2. ``analysis_root`` stored inside the report JSON (may be stale if
            #      the report was generated on another machine / path)
            #   3. the scan root currently served by this WebServer instance
            scan_root_candidates: List[str] = []
            for raw in (
                data.get('scan_root'),
                primary_payload.get('analysis_root'),
                str(self.input_path_absolute) if getattr(self, 'input_path_absolute', None) else None,
            ):
                if isinstance(raw, str) and raw.strip():
                    scan_root_candidates.append(raw.strip())

            scan_root = resolve_first_existing_scan_root(
                scan_root_candidates,
                security_root,
            )

            if scan_root is None:
                if not scan_root_candidates:
                    return jsonify({'error': 'scan_root required (pass scan_root or ensure report has analysis_root)'}), 400
                return jsonify({'error': 'scan_root does not exist'}), 404

            fi, ci, gi = coerce_finding_indices(data)
            scope_merge_raw = data.get('finding_scope_report_path')
            finding_scope_merge = (
                scope_merge_raw.strip()
                if isinstance(scope_merge_raw, str) and scope_merge_raw.strip()
                else ''
            )

            # When the request points to the executive summary (no ``files`` array
            # of its own), ``finding_scope_report_path`` resolves to the matching
            # vulnerability JSON so finding indices can map to a real sink.
            scope_payload: Optional[Dict[str, Any]] = None
            if finding_scope_merge:
                md_obj = model_directory_from_security_report_file(
                    security_root, resolved_report
                )
                if md_obj is not None:
                    scope_payload, scope_err = resolve_aggregate_finding_scope_payload(
                        finding_scope_merge,
                        security_root=security_root,
                        executive_report_path=resolved_report,
                        model_dir=md_obj,
                    )
                    if scope_err is not None:
                        return jsonify({'error': scope_err}), 400

            sink_file, sink_line = resolve_sink_from_finding_indices(
                primary_payload,
                scope_payload,
                fi=fi,
                ci=ci,
                gi=gi,
                scan_root=scan_root,
            )

            # Client-provided sink_file / sink_line hints take precedence when
            # they resolve inside scan_root; useful when indices refer to a
            # synthesized scope (executive aggregate) or when the report JSON
            # is incomplete.
            client_sink_file_raw = data.get('sink_file')
            if isinstance(client_sink_file_raw, str) and client_sink_file_raw.strip():
                hint = Path(client_sink_file_raw.strip())
                candidate = hint if hint.is_absolute() else (scan_root / hint)
                candidate = candidate.resolve(strict=False)
                if is_path_within_root(candidate, scan_root) and candidate.is_file():
                    sink_file = candidate
            client_sink_line = coerce_positive_int_line(data.get('sink_line'))
            if client_sink_line is not None:
                sink_line = client_sink_line

            budget_seconds = coerce_investigation_budget(data.get('budget_seconds'))

            try:
                result = invoke_assistant_validation(
                    vulnerability_name=vulnerability_name,
                    scan_root=scan_root,
                    sink_file=sink_file,
                    sink_line=sink_line,
                    budget_seconds=budget_seconds,
                )
            except Exception as exc:
                return jsonify({'error': f'investigation failed: {exc}'}), 500

            # Expose the resolved investigation scope so the dashboard can show
            # exactly which file/line was analysed (avoids ambiguity when only
            # zero-based indices are sent over the wire).
            try:
                sink_file_rel: Optional[str] = None
                if sink_file is not None:
                    try:
                        sink_file_rel = str(sink_file.relative_to(scan_root))
                    except ValueError:
                        sink_file_rel = str(sink_file)
                result.scope = InvestigationScope(
                    scan_root=str(scan_root),
                    sink_file=sink_file_rel,
                    sink_line=sink_line,
                    vulnerability_name=vulnerability_name,
                    family=result.family,
                )
            except Exception:
                pass

            # Presentation-time filter: keep entry_points anchored on scope.sink_file
            # for FLOW/ACCESS so narration and "Related to" panel match the finding.
            # The deterministic verdict was already computed on the full evidence.
            result = apply_presentation_filter_to_result(result)

            synthesize_raw = data.get('synthesize_narrative')
            synthesize_narrative = True if synthesize_raw is None else bool(synthesize_raw)
            if synthesize_narrative:
                chat_model_inv = data.get('model')
                if isinstance(chat_model_inv, str) and chat_model_inv.strip():
                    chat_model_inv = chat_model_inv.strip()
                else:
                    mn_inv = primary_payload.get('model_name')
                    chat_model_inv = (
                        mn_inv.strip() if isinstance(mn_inv, str) and mn_inv.strip() else ''
                    )
                if chat_model_inv:
                    try:
                        from oasis.helpers.assistant.think.investigation_synth import (
                            enrich_investigation_with_llm_narrative,
                        )

                        result = enrich_investigation_with_llm_narrative(
                            result,
                            ollama_manager=self._get_assistant_ollama_manager(),
                            chat_model=chat_model_inv,
                        )
                    except Exception as exc:
                        logger.warning(
                            'Investigation narrative enrichment failed: %s',
                            type(exc).__name__,
                            exc_info=True,
                        )
                        result = result.model_copy(
                            update={
                                'synthesis_error': f'{type(exc).__name__}: {exc}',
                            }
                        )

            report_rel_save = str(resolved_report.relative_to(security_root)).replace('\\', '/')
            sid_merge = data.get('session_id')
            chat_model_merge = data.get('model')
            if isinstance(chat_model_merge, str) and chat_model_merge.strip():
                chat_model_merge = chat_model_merge.strip()
            else:
                mn_m = primary_payload.get('model_name')
                chat_model_merge = (
                    mn_m.strip() if isinstance(mn_m, str) and mn_m.strip() else ''
                )
            merge_fk = finding_validation_storage_key(
                finding_scope_merge,
                fi,
                ci,
                gi,
            )
            if (
                isinstance(sid_merge, str)
                and validate_session_id(sid_merge.strip())
                and chat_model_merge
                and merge_fk
            ):
                try:
                    merge_finding_validation_into_session(
                        security_root,
                        report_rel_save,
                        sid_merge.strip(),
                        chat_model_merge,
                        result.model_dump(mode='json'),
                        vulnerability_name,
                        finding_key=merge_fk,
                    )
                except (ValueError, OSError) as exc:
                    logger.warning(
                        'merge finding validation into session failed: %s',
                        exc,
                        exc_info=True,
                    )

            return jsonify(result.model_dump())

        @app.route('/api/assistant/session-branch', methods=['POST'])
        @login_required
        def assistant_session_branch():
            try:
                body = request.get_json(silent=True)
            except Exception:
                body = None
            if not isinstance(body, dict):
                return jsonify({'error': 'Invalid JSON'}), 400

            report_rel_raw = str(body.get('report_path') or '').strip()
            if not report_rel_raw:
                return jsonify({'error': 'report_path required'}), 400

            security_root = self.security_dir.resolve()
            resolved_report, primary_synthetic, path_err = resolve_assistant_primary_payload(
                self.security_dir,
                report_rel_raw,
            )
            if path_err is not None:
                err_body, status = path_err
                return jsonify(err_body), status
            assert resolved_report is not None

            if primary_synthetic is not None:
                primary_payload = primary_synthetic
            else:
                try:
                    with open(resolved_report, 'r', encoding='utf-8') as rf:
                        primary_payload = json.load(rf)
                except Exception:
                    primary_payload = {}
            if not isinstance(primary_payload, dict):
                primary_payload = {}

            report_rel = str(resolved_report.relative_to(security_root)).replace('\\', '/')

            sid = body.get('session_id', '')
            if not isinstance(sid, str) or not validate_session_id(sid.strip()):
                return jsonify({'error': 'session_id required'}), 400
            model = body.get('model')
            if not isinstance(model, str) or not model.strip():
                return jsonify({'error': 'model required'}), 400

            msgs, msg_err = validate_assistant_messages(
                body.get('messages'),
                max_messages=self._ASSISTANT_MAX_MESSAGES,
                max_message_chars=self._ASSISTANT_MAX_MESSAGE_CHARS,
                allow_empty=True,
            )
            if msg_err is not None:
                err_body, status = msg_err
                return jsonify(err_body), status
            assert msgs is not None

            ts = utc_now_iso()
            persist_msgs = normalize_validated_messages_for_storage(msgs, default_at=ts)

            vn = str(body.get('vulnerability_name') or '').strip() or str(primary_payload.get('vulnerability_name') or '').strip()

            try:
                save_session_branch_messages(
                    self.security_dir,
                    report_rel,
                    sid.strip(),
                    model.strip(),
                    persist_msgs,
                    vn,
                    set_as_active=bool(body.get('set_as_active')),
                )
            except (ValueError, OSError) as exc:
                return jsonify({'error': str(exc)}), 400
            return jsonify({'ok': True})

        @app.route('/api/assistant/sessions', methods=['GET'])
        @login_required
        def assistant_sessions():
            report_rel = normalize_report_rel_query_arg(request.args.get('report_path'))
            if not report_rel:
                return jsonify({'error': 'report_path required'}), 400
            try:
                lim = int(request.args.get('limit', '20'))
            except ValueError:
                lim = 20
            rows = list_chat_sessions(self.security_dir, report_rel, limit=lim)
            return jsonify(rows)

        @app.route('/api/assistant/session', methods=['GET'])
        @login_required
        def assistant_session_get():
            report_rel = normalize_report_rel_query_arg(request.args.get('report_path'))
            sid = request.args.get('session_id', '').strip()
            if not report_rel or not sid:
                return jsonify({'error': 'report_path and session_id required'}), 400
            doc = load_chat_session(self.security_dir, report_rel, sid)
            if not doc:
                return jsonify({'error': 'session not found'}), 404
            doc = ensure_session_views(doc)
            doc = dict(doc)
            msgs = doc.get('messages')
            if isinstance(msgs, list):
                doc['messages'] = enrich_messages_for_response([m for m in msgs if isinstance(m, dict)])
            branches = doc.get('model_branches')
            if isinstance(branches, dict):
                coerced_branches: Dict[str, Any] = {}
                for bk, branch in branches.items():
                    if isinstance(branch, dict):
                        branch_copy = dict(branch)
                        bm = branch_copy.get('messages')
                        if isinstance(bm, list):
                            branch_copy['messages'] = enrich_messages_for_response(
                                [m for m in bm if isinstance(m, dict)]
                            )
                        coerced_branches[bk] = branch_copy
                    else:
                        coerced_branches[bk] = branch
                doc['model_branches'] = coerced_branches
            return jsonify(doc)

        @app.route('/api/assistant/session', methods=['DELETE'])
        @login_required
        def assistant_session_delete():
            try:
                body = request.get_json(silent=True)
            except Exception:
                body = None
            data = body if isinstance(body, dict) else {}
            report_rel = data.get('report_path', '')
            sid = data.get('session_id', '')
            if not isinstance(report_rel, str) or not report_rel.strip():
                return jsonify({'error': 'report_path required'}), 400
            if not isinstance(sid, str) or not sid.strip():
                return jsonify({'error': 'session_id required'}), 400
            deleted = delete_chat_session(self.security_dir, report_rel.strip(), sid.strip())
            if not deleted:
                return jsonify({'error': 'session not found'}), 404
            return jsonify({'deleted': True})

        @app.route('/api/assistant/sessions', methods=['DELETE'])
        @login_required
        def assistant_sessions_delete_all():
            try:
                body = request.get_json(silent=True)
            except Exception:
                body = None
            data = body if isinstance(body, dict) else {}
            report_rel = data.get('report_path', '')
            if not isinstance(report_rel, str) or not report_rel.strip():
                return jsonify({'error': 'report_path required'}), 400
            n = delete_all_chat_sessions(self.security_dir, report_rel.strip())
            return jsonify({'deleted_count': n})

        def _load_report_html_from_json_path(filename: str):
            try:
                file_path = self.security_dir / filename
                security_root = self.security_dir.resolve()
                resolved_path = file_path.resolve(strict=False)

                if not is_path_within_root(resolved_path, security_root):
                    return jsonify({'error': 'Invalid path'}), 403
                if not resolved_path.exists() or resolved_path.suffix != '.json':
                    return jsonify({'error': 'File not found or not JSON'}), 404
                if not _path_allowed_by_active_filters(resolved_path, security_root):
                    return _filtered_out_preview_response()
                if is_executive_summary_progress_sidecar(resolved_path):
                    return jsonify(
                        {
                            "error": (
                                "Path is an incremental progress sidecar, not a canonical report JSON; "
                                "open the executive summary JSON instead."
                            )
                        }
                    ), 404

                with open(resolved_path, 'r', encoding='utf-8') as f:
                    payload = json.load(f)
                if not isinstance(payload, dict):
                    return jsonify({'error': 'Invalid JSON report payload'}), 422
                severity_tiers = parse_severity_filter_param(request.args.get('severity', ''))
                payload = self._filter_vulnerability_payload_by_severity_tiers(
                    payload,
                    severity_tiers,
                    rewrite_stats_totals=True,
                )

                ar_raw = payload.get("analysis_root")
                ar_text = ar_raw.strip() if isinstance(ar_raw, str) else None
                _, codebase_ok = self._cached_codebase_access_state(ar_text)
                preview_ctx = {
                    "show_codebase_warning": not codebase_ok,
                    "codebase_warning_short": CODEBASE_UNAVAILABLE_SHORT,
                    "codebase_warning_detail": (
                        "" if codebase_ok else CODEBASE_UNAVAILABLE_DETAIL
                    ),
                    "active_severity_filter": [tier.capitalize() for tier in severity_tiers],
                    # Internal-only context for executive-summary detail link fallback.
                    "_security_root": security_root,
                    "_current_report_path": resolved_path,
                }
                html_content = self.report.render_report_html_from_json_payload(
                    payload,
                    preview_context=preview_ctx,
                )
                html_content = strip_report_header_for_web_preview(html_content)
                return jsonify({'content': html_content}), 200
            except Exception:
                return self._report_preview_error_response("Error while generating HTML preview from canonical JSON report")

        @app.route('/api/report-html')
        @login_required
        def get_report_html_query():
            filename = request.args.get('path', '')
            if not filename:
                return jsonify({'error': 'No path provided'}), 400
            return _load_report_html_from_json_path(filename)

        @app.route('/api/report-html/<path:filename>')
        @login_required
        def get_report_html(filename):
            # Backward-compatible route for previous clients.
            return _load_report_html_from_json_path(filename)

        @app.route('/api/download')
        @login_required
        def download_report():
            # Get the report path
            report_path = request.args.get('path', '')
            if not report_path:
                return jsonify({'error': 'No path provided'}), 400

            try:
                # Convert the relative path to absolute
                abs_path = self.security_dir / report_path

                # Security check - make sure path is within the security reports directory
                if not str(abs_path.resolve()).startswith(str(self.security_dir.resolve())):
                    return jsonify({'error': 'Invalid path'}), 403

                if not abs_path.exists():
                    return jsonify({'error': 'File not found'}), 404

                # Get the directory and filename
                directory = abs_path.parent
                filename = abs_path.name

                # Set the appropriate content type based on file extension
                content_types = {
                    '.md': 'text/markdown',
                    '.html': 'text/html',
                    '.pdf': 'application/pdf',
                    '.json': 'application/json',
                    '.sarif': 'application/sarif+json',
                }
                content_type = content_types.get(abs_path.suffix, 'application/octet-stream')

                return send_from_directory(
                    directory=str(directory),
                    path=filename,
                    mimetype=content_type,
                    as_attachment=True
                )
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        @app.route('/api/dates')
        @login_required
        def get_dates_by_model():
            """Get dates available for a specific model and vulnerability type"""
            model_filter = [value.strip() for value in request.args.getlist('model') if value.strip()]
            if not model_filter:
                single_model = (request.args.get('model') or '').strip()
                if single_model:
                    model_filter = [single_model]
            vulnerability_filter = (request.args.get('vulnerability') or '').strip()
            severity_filter = request.args.get('severity', '')
            # Filter reports based on parameters
            filtered_data = self.filter_reports(
                model_filter=model_filter,
                vuln_filter=vulnerability_filter,
                severity_filter=severity_filter,
                mandatory_filters=['model', 'vulnerability'],
            )

            # Extract dates from filtered reports
            dates = []
            for report in filtered_data:
                if 'date' in report:
                    # Create a dictionary date_info from the date string
                    date_info = {'date': report['date']}

                    af = report.get('alternative_formats', {})
                    open_path = None
                    open_fmt = None
                    # Prefer human-readable formats first (same order as dashboard)
                    for fmt in dashboard_format_display_order():
                        if af.get(fmt):
                            open_path = af[fmt]
                            open_fmt = fmt
                            break
                    if open_path:
                        date_info['path'] = open_path
                        date_info['format'] = open_fmt
                    elif report.get('path'):
                        date_info['path'] = report['path']
                        date_info['format'] = report.get('format', 'md')
                    date_info['language'] = report.get('language', 'en')
                    date_info['model'] = report.get('model')
                    date_info['project'] = report.get('project')
                    date_info['analysis_root'] = report.get('analysis_root')
                    date_info['codebase_accessible'] = report.get('codebase_accessible')
                    date_info['assistant_context_warning'] = report.get('assistant_context_warning')
                    dates.append(date_info)

            # Sort dates from newest to oldest
            dates.sort(key=lambda x: x.get('date', ''), reverse=True)

            return jsonify({'dates': dates})

        return app

    @staticmethod
    def _stats_from_json_report_file(report_file: Path) -> dict:
        """Load dashboard stats from a canonical vulnerability JSON report."""
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            st = data.get('stats') or {}
            return {
                'files_analyzed': int(st.get('files_analyzed', 0)),
                'high_risk': int(st.get('high_risk', 0)),
                'medium_risk': int(st.get('medium_risk', 0)),
                'low_risk': int(st.get('low_risk', 0)),
                'critical_risk': int(st.get('critical_risk', 0)),
                'total_findings': int(st.get('total_findings', 0)),
            }
        except (OSError, json.JSONDecodeError):
            return {}
        except Exception as exc:
            logger.warning(
                "Failed to load stats from JSON report '%s': %s",
                report_file,
                exc,
            )
            return {}

    @staticmethod
    def _scan_progress_updated_at_key(payload: dict) -> str | None:
        """Lexicographic ordering key for ``updated_at`` (ISO Z suffix matches chronological order)."""
        raw = payload.get("updated_at")
        if raw is None:
            return None
        text = str(raw).strip()
        return text or None

    @staticmethod
    def _parse_summary_progress_from_json_data(data: dict) -> dict | None:
        progress = data.get("progress")
        if not isinstance(progress, dict):
            return None

        try:
            completed = int(progress.get("completed_vulnerabilities", 0))
            total = int(progress.get("total_vulnerabilities", 0))
            is_partial = bool(progress.get("is_partial", False))
        except (TypeError, ValueError):
            return None

        tested_vulnerabilities = [
            str(item).strip()
            for item in (progress.get("tested_vulnerabilities") or [])
            if str(item).strip()
        ]
        current_vulnerability = str(progress.get("current_vulnerability") or "").strip()

        result = {
            "completed_vulnerabilities": completed,
            "total_vulnerabilities": total,
            "is_partial": is_partial,
            "status": str(
                progress.get("status")
                or ("in_progress" if is_partial else "complete")
            ).strip().lower(),
            "current_vulnerability": current_vulnerability,
            "tested_vulnerabilities": tested_vulnerabilities,
        }
        for key in SCAN_PROGRESS_EXTENDED_KEYS:
            if key in progress:
                result[key] = progress[key]
        return result

    @staticmethod
    def _load_summary_progress_json_file(path: Path) -> dict | None:
        if not path.is_file():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return None
        return WebServer._parse_summary_progress_from_json_data(data)

    @staticmethod
    def _summary_progress_from_json_report_file(report_file: Path) -> dict:
        """Load optional executive summary progress metadata from JSON report.

        When both a sidecar (``*.progress.json``) and embedded ``progress`` exist, the newer
        ``updated_at`` wins so a stale partial sidecar cannot override fresher embedded data.
        When timestamps are absent on both, sidecar is preferred first (legacy behavior).
        """
        sidecar_path = executive_summary_progress_sidecar_path(report_file)
        from_sidecar = WebServer._load_summary_progress_json_file(sidecar_path)
        from_embedded = WebServer._load_summary_progress_json_file(report_file)

        if from_sidecar is not None and from_embedded is not None:
            ts_side = WebServer._scan_progress_updated_at_key(from_sidecar)
            ts_emb = WebServer._scan_progress_updated_at_key(from_embedded)
            if ts_side is not None:
                if ts_emb is not None:
                    if ts_side > ts_emb:
                        return from_sidecar
                    return from_embedded if ts_side < ts_emb else from_sidecar
                return from_sidecar
            return from_embedded if ts_emb is not None else from_sidecar
        if from_sidecar is not None:
            return from_sidecar
        return from_embedded if from_embedded is not None else {}

    @staticmethod
    def _summary_progress_from_markdown_report_file(report_file: Path) -> dict:
        """Load optional executive summary progress metadata from markdown report."""
        try:
            content = report_file.read_text(encoding="utf-8")
        except OSError:
            return {}

        if "## Scan Progress" not in content:
            return {}

        match = re.search(
            r"\|\s*(Partial \(scan in progress\)|Complete|Aborted)\s*\|\s*(\d+)\s*/\s*(\d+)\s*\|",
            content,
            re.IGNORECASE,
        )
        if not match:
            return {}

        status = match[1].strip().lower()
        current_match = re.search(r"-\s*Current vulnerability:\s*(.+)", content, re.IGNORECASE)
        if tested_match := re.search(
            r"-\s*Tested vulnerabilities:\s*(.+)", content, re.IGNORECASE
        ):
            tested_vulnerabilities = [
                part.strip() for part in tested_match[1].split(",") if part.strip()
            ]
        else:
            tested_vulnerabilities = []
        result = {
            "completed_vulnerabilities": int(match[2]),
            "total_vulnerabilities": int(match[3]),
            "is_partial": status.startswith("partial"),
            "status": (
                "aborted"
                if status.startswith("aborted")
                else (
                    "in_progress" if status.startswith("partial") else "complete"
                )
            ),
            "current_vulnerability": (
                current_match[1].strip() if current_match else ""
            ),
            "tested_vulnerabilities": tested_vulnerabilities,
        }
        if phases := WebServer._pipeline_phases_from_executive_summary_markdown(
            content
        ):
            result["phases"] = phases
        return result

    @staticmethod
    def _normalize_audit_metric_label(raw_label: str) -> str:
        return normalize_audit_metric_label(raw_label)

    @staticmethod
    def _parse_first_int_metric(raw_value: str) -> int | None:
        return parse_first_int_metric(raw_value)

    @staticmethod
    def _parse_first_float_metric(raw_value: str) -> float | None:
        return parse_first_float_metric(raw_value)

    @staticmethod
    def _audit_metric_key_from_label(normalized_label: str) -> tuple[str, str]:
        """
        Return metric kind/key tuple where kind is ``int`` or ``float``.
        """
        return audit_metric_key_from_label(normalized_label)

    @staticmethod
    def _slice_markdown_section_after_heading(content: str, heading_match: re.Match[str]) -> str:
        """Return markdown slice between heading and the next heading of same level."""
        return slice_markdown_section_after_heading(content, heading_match)

    @staticmethod
    def _parse_audit_metric_table_row(line: str) -> tuple[str, str] | None:
        """Parse a markdown ``| label | value |`` row."""
        return parse_audit_metric_table_row(line)

    @staticmethod
    def _is_audit_metrics_table_header_row(label: str, value: str) -> bool:
        """True when the row is the ``| Metric | Value |`` header."""
        return (
            label in WebServer._AUDIT_METRICS_TABLE_HEADER_LABELS
            and normalize_audit_metric_label(value) in WebServer._AUDIT_METRICS_TABLE_HEADER_LABELS
        )

    @staticmethod
    def _iter_audit_metrics_table_rows(metrics_section: str):
        """Yield normalized ``(label, value)`` rows from the first audit metrics table."""
        yield from iter_audit_metrics_table_rows(metrics_section)

    @staticmethod
    def _audit_metrics_from_markdown_report_file(report_file: Path) -> dict:
        """
        Parse comparable audit metrics from markdown audit report.
        """
        try:
            content = report_file.read_text(encoding="utf-8")
        except OSError:
            return {}
        # Return partial metrics; dashboard rendering handles missing fields with placeholders.
        return audit_metrics_from_markdown_content(content)

    @staticmethod
    def _audit_metrics_from_audit_json_report_file(report_file: Path) -> dict:
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError, TypeError):
            return {}
        if not isinstance(data, dict) or data.get("report_type") != "audit":
            return {}
        return audit_metrics_from_audit_payload(data)

    @staticmethod
    def _pipeline_phases_from_executive_summary_markdown(content: str) -> list[dict]:
        """Parse optional ``### Pipeline phases`` markdown table into phase dict rows.

        Rows are split on ``|`` so minor spacing/extra text in the progress column (e.g.
        percentages) still yields counts when at least two integers appear.
        """
        if "### Pipeline phases" not in content:
            return []
        phases: list[dict] = []
        capture = False
        for raw in content.splitlines():
            line = raw.strip()
            if "### Pipeline phases" in line:
                capture = True
                continue
            if capture:
                if line.startswith("### ") and "Pipeline phases" not in line:
                    break
                if not line.startswith("|"):
                    continue
                if "---" in line:
                    continue
                cells = [c.strip() for c in line.split("|")]
                if cells and cells[0] == "":
                    cells = cells[1:]
                if cells and cells[-1] == "":
                    cells = cells[:-1]
                if len(cells) < 3:
                    continue
                cl0, cl1 = cells[0].lower(), cells[1].lower()
                if "phase" in cl0 and "status" in cl1:
                    continue
                if not cells[0].strip("-"):
                    continue
                label, status, prog_cell = cells[0], cells[1], cells[2]
                pair = parse_phase_counts_from_progress_cell(prog_cell)
                if pair is None:
                    continue
                c, t = pair
                phases.append(
                    {
                        "label": label.strip(),
                        "status": status.strip(),
                        "completed": max(c, 0),
                        "total": max(t, 0),
                    }
                )
        return phases

    @staticmethod
    def _language_from_json_report_file(report_file: Path) -> str | None:
        """Load report language from canonical vulnerability JSON report.

        Returns ``None`` when the field is missing/empty or when the report file
        cannot be read/parsed, so callers can fallback to legacy ``language.txt``
        when available.
        """
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            # Only swallow expected I/O / parsing issues; let other exceptions
            # propagate so they can be surfaced and fixed.
            return None

        language = str(data.get('language') or '').strip().lower()
        return language or None

    @staticmethod
    def _language_from_legacy_file(report_file: Path) -> str | None:
        """Load report language from legacy ``language.txt`` sidecar."""
        lang_file = report_file.parent.parent / 'language.txt'
        if not lang_file.exists():
            return None
        try:
            with open(lang_file, 'r', encoding='utf-8') as f:
                language = f.read().strip().lower()
            return language or None
        except Exception:
            return None
        
    def _collect_reports_from_directories(self):
        """Extract reports data from directory structure"""
        reports: List[Dict[str, Any]] = []
        security_reports_dir = self.security_dir
        if not security_reports_dir.is_dir():
            return reports

        for run_dir, run_key, report_date in self._iter_run_directories(security_reports_dir):
            for model_dir in (d for d in run_dir.iterdir() if d.is_dir()):
                model_name = self._desanitize_name(model_dir.name)
                reports.extend(
                    self._process_model_directory(
                        model_dir, model_name, report_date, run_key
                    )
                )

        reports.sort(key=lambda x: x["date"] or "", reverse=True)
        return reports

    def collect_report_data(self) -> None:
        """Refresh ``report_data`` and ``global_stats`` from ``security_reports`` layout."""
        reports = self._collect_reports_from_directories()
        self.report_data = reports
        self.global_stats = self._calculate_global_statistics(reports)

    def _iter_run_directories(self, security_reports_dir: Path):
        """
        Legacy top-level run dirs, top-level ``YYYYMMDD_HHMMSS`` runs, and
        ``<project_slug>/<YYYYMMDD_HHMMSS>/`` nested runs.
        """
        for report_dir in sorted(
            (d for d in security_reports_dir.iterdir() if d.is_dir()),
            key=lambda p: p.name,
        ):
            name = report_dir.name
            if is_legacy_run_dirname(name) or is_run_timestamp_dirname(name):
                run_key = name
                report_date = report_date_display_from_run_key(run_key)
                yield report_dir, run_key, report_date
                continue
            try:
                nested_dirs = sorted(
                    (d for d in report_dir.iterdir() if d.is_dir()),
                    key=lambda p: p.name,
                )
            except OSError:
                logger.debug(
                    "Skipping unreadable project reports directory: %s",
                    report_dir,
                    exc_info=True,
                )
                continue
            for sub in nested_dirs:
                if is_run_timestamp_dirname(sub.name):
                    run_key = f"{name}/{sub.name}"
                    report_date = report_date_display_from_run_key(run_key)
                    yield sub, run_key, report_date

    def _process_model_directory(self, model_dir, model_name, report_date, run_key: str):
        """Process all formats in a model directory"""
        model_reports = []

        for fmt_dir in (d for d in model_dir.iterdir() if d.is_dir()):
            fmt = fmt_dir.name

            if fmt not in REPORT["OUTPUT_FORMATS"]:
                continue

            globber = fmt_dir.glob(report_dir_glob_for_format(fmt))
            model_reports.extend(
                self._process_report_file(
                    report_file,
                    model_name,
                    fmt,
                    report_date,
                    run_key,
                    model_dir,
                )
                for report_file in globber
                if fmt != "json"
                or not is_executive_summary_progress_sidecar(report_file)
            )
        return model_reports

    def _progress_payload_for_dashboard_entry(
        self, vulnerability_type: str, fmt: str, report_file: Path
    ) -> Dict[str, Any]:
        if vulnerability_type != "Executive Summary":
            return {}
        if fmt == "json":
            return self._summary_progress_from_json_report_file(report_file)
        if fmt == "md":
            return self._summary_progress_from_markdown_report_file(report_file)
        return {}

    def _audit_metrics_for_dashboard_entry(
        self, vulnerability_type: str, fmt: str, report_file: Path
    ) -> Dict[str, Any]:
        if vulnerability_type != "Audit Report":
            return {}
        if fmt == "json":
            return self._audit_metrics_from_audit_json_report_file(report_file)
        if fmt == "md":
            json_side = json_sibling_for_format_artifact(report_file)
            if json_side.is_file():
                return self._audit_metrics_from_audit_json_report_file(json_side)
            return self._audit_metrics_from_markdown_report_file(report_file)
        return {}

    def _language_for_dashboard_entry(self, report_file: Path, fmt: str) -> str:
        if fmt == "json":
            language = self._language_from_json_report_file(report_file)
        else:
            sibling_json = json_sibling_for_format_artifact(report_file)
            language = (
                self._language_from_json_report_file(sibling_json)
                if sibling_json.exists()
                else None
            )
        if language is None:
            language = self._language_from_legacy_file(report_file)
        return language if language is not None else "en"

    def _project_and_analysis_root_for_dashboard_entry(
        self, fmt: str, report_file: Path, run_key: str
    ) -> Tuple[Optional[str], Optional[str]]:
        project: Optional[str] = None
        analysis_root_raw: Optional[str] = None
        if fmt == "json":
            project, analysis_root_raw = self._canonical_json_fields_from_path(report_file)
        else:
            json_side = json_sibling_for_format_artifact(report_file)
            if json_side.is_file():
                project, analysis_root_raw = self._canonical_json_fields_from_path(json_side)
        if project is None:
            project = self._project_inferred_from_run_key(run_key)
        return project, analysis_root_raw

    def _process_report_file(
        self,
        report_file: Path,
        model_name,
        fmt,
        report_date,
        run_key: str,
        model_dir,
    ) -> Dict[str, Any]:
        """Build one dashboard index entry for a report artifact."""
        vulnerability_type = self._extract_vulnerability_type(report_file.stem)
        stats = self._stats_from_json_report_file(report_file) if fmt == "json" else {}
        progress = self._progress_payload_for_dashboard_entry(
            vulnerability_type, fmt, report_file
        )
        audit_metrics = self._audit_metrics_for_dashboard_entry(
            vulnerability_type, fmt, report_file
        )
        relative_path = report_file.relative_to(self.security_dir)
        alternative_formats = self._find_alternative_formats(model_dir, report_file.stem)
        language = self._language_for_dashboard_entry(report_file, fmt)
        project, analysis_root_raw = self._project_and_analysis_root_for_dashboard_entry(
            fmt, report_file, run_key
        )
        resolved_root, codebase_ok = self._cached_codebase_access_state(
            analysis_root_raw
        )

        return {
            "model": model_name,
            "format": fmt,
            "path": str(relative_path),
            "filename": report_file.name,
            "vulnerability_type": vulnerability_type,
            "stats": stats,
            "alternative_formats": alternative_formats,
            "date": report_date,
            "timestamp_dir": run_key,
            "language": language,
            "progress": progress,
            "audit_metrics": audit_metrics,
            "project": project,
            "analysis_root": analysis_root_raw,
            "analysis_root_resolved": str(resolved_root) if resolved_root else None,
            "codebase_accessible": codebase_ok,
            "assistant_context_warning": assistant_context_warning(not codebase_ok),
        }
        
    def _calculate_global_statistics(self, reports):
        """Calculate global statistics from all reports"""
        stats = {
            "total_reports": 0,
            "models": {},
            "vulnerabilities": {},
            "formats": {},
            "dates": {},
            "risk_summary": {
                "critical": sum(report.get("stats", {}).get("critical_risk", 0) for report in reports if report["format"] == "json"),
                "high": sum(report.get("stats", {}).get("high_risk", 0) for report in reports if report["format"] == "json"),
                "medium": sum(report.get("stats", {}).get("medium_risk", 0) for report in reports if report["format"] == "json"),
                "low": sum(report.get("stats", {}).get("low_risk", 0) for report in reports if report["format"] == "json"),
            }
        }
        
        for report in reports:
            self._update_stats_from_report(stats, report)
            
        return stats
        
    def _update_stats_from_report(self, stats, report):
        """Update statistics based on a single report"""
        if report["format"] == "json":
            stats["total_reports"] += 1

            self._increment_stat_count(
                report, "model", stats, "models"
            )
            self._increment_stat_count(
                report, "vulnerability_type", stats, "vulnerabilities"
            )
            if report["date"]:
                date_only = report["date"].split()[0]
                if date_only not in stats["dates"]:
                    stats["dates"][date_only] = 0
                stats["dates"][date_only] += 1

        self._increment_stat_count(
            report, "format", stats, "formats"
        )

    def _increment_stat_count(self, report, arg1, stats, arg3):
        model = report[arg1]
        if model not in stats[arg3]:
            stats[arg3][model] = 0
        stats[arg3][model] += 1

    def _desanitize_name(self, sanitized_name):
        """Convert sanitized name back to display name"""
        name = sanitized_name.replace('_', ' ')
        return name.title()

    @staticmethod
    def _extract_date_from_dirname(run_key: str) -> str:
        """Back-compat: extract date from a run folder name or ``project/run_ts`` key."""
        return report_date_display_from_run_key(run_key)

    @staticmethod
    def _project_field_cache_key(json_path: Path) -> Path:
        """
        Return a stable absolute cache key without symlink resolution.

        Using ``absolute()`` keeps a consistent key shape for relative and absolute
        inputs even when ``resolve()`` is unavailable or raises.
        """
        return json_path.expanduser().absolute()

    def _cached_codebase_access_state(
        self, stored_raw: Optional[str]
    ) -> Tuple[Optional[Path], bool]:
        """Memoize :func:`codebase_access_state` per normalized ``analysis_root`` key."""
        sec_resolved = self.security_dir.resolve()
        if isinstance(stored_raw, str):
            key_raw = stored_raw.strip() or None
        else:
            key_raw = None
        key = (key_raw, sec_resolved)
        cache = self._codebase_access_state_cache
        if key in cache:
            cache.move_to_end(key)
            return cache[key]
        out = codebase_access_state(
            stored_raw=key_raw,
            security_reports_root=sec_resolved,
        )
        cache[key] = out
        cache.move_to_end(key)
        while len(cache) > _CODEBASE_ACCESS_STATE_CACHE_MAX:
            cache.popitem(last=False)
        return out

    def _canonical_json_fields_from_path(
        self, json_path: Path
    ) -> Tuple[Optional[str], Optional[str]]:
        """Return ``(project, analysis_root)`` from a canonical report JSON file."""
        key = self._project_field_cache_key(json_path)
        if key in self._canonical_json_fields_cache:
            return self._canonical_json_fields_cache[key]
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError, TypeError):
            self._canonical_json_fields_cache[key] = (None, None)
            return None, None
        if not isinstance(data, dict):
            self._canonical_json_fields_cache[key] = (None, None)
            return None, None
        proj_val: Optional[str] = None
        p = data.get("project")
        if isinstance(p, str) and p.strip():
            proj_val = p.strip()
        ar_raw = data.get("analysis_root")
        ar_val: Optional[str] = None
        if isinstance(ar_raw, str) and ar_raw.strip():
            ar_val = ar_raw.strip()
        self._canonical_json_fields_cache[key] = (proj_val, ar_val)
        return proj_val, ar_val

    def _project_field_from_json_path(self, json_path: Path) -> Optional[str]:
        return self._canonical_json_fields_from_path(json_path)[0]

    @staticmethod
    def _project_inferred_from_run_key(run_key: str) -> Optional[str]:
        s = (run_key or "").replace("\\", "/").strip("/")
        return s.split("/")[0] or None if "/" in s else None

    def _find_alternative_formats(self, model_dir, report_stem):
        """Find all available formats for a specific report (paths relative to ``security_dir``)."""
        formats: Dict[str, str] = {}
        security_root = self.security_dir.resolve()
        for fmt in REPORT["OUTPUT_FORMATS"]:
            fmt_dir = model_dir / fmt
            if fmt_dir.exists() and fmt_dir.is_dir():
                file_path = fmt_dir / artifact_filename(report_stem, fmt)
                if file_path.exists():
                    try:
                        relative_path = file_path.relative_to(security_root)
                    except ValueError:
                        continue
                    formats[fmt] = str(relative_path)
        return formats
    
    def _extract_vulnerability_type(self, filename):
        """Extract vulnerability type from filename"""
        # Handle executive summary
        if 'executive_summary' in filename:
            return 'Executive Summary'

        # Handle audit report (stem ``AUDIT_REPORT_ARTIFACT_STEM``; see export.filenames).
        if AUDIT_REPORT_ARTIFACT_STEM in filename:
            return 'Audit Report'

        vulnerability_patterns = {
            VULNERABILITY_MAPPING[vulnerability]['name'].lower().replace(' ', '_'): VULNERABILITY_MAPPING[vulnerability]['name']
            for vulnerability in VULNERABILITY_MAPPING
        }

        return next(
            (
                full_name
                for pattern, full_name in vulnerability_patterns.items()
                if pattern in filename.lower()
            ),
            filename,
        )
    
    def _apply_date_filter(self, reports, start_date, end_date):
        """
        Apply date filtering to reports
        
        Args:
            reports: List of reports to filter
            start_date: ISO format date string for start date
            end_date: ISO format date string for end date
            
        Returns:
            Filtered list of reports
        """
        filtered_reports = reports.copy()
        
        # Apply start date filter if provided
        if parsed_start_date := parse_iso_date(start_date):
            filtered_reports = [r for r in filtered_reports if r.get('date') and 
                               parse_report_date(r['date']) is not None and
                               parse_report_date(r['date']) >= parsed_start_date]
        
        # Apply end date filter if provided
        if parsed_end_date := parse_iso_date(end_date):
            filtered_reports = [r for r in filtered_reports if r.get('date') and 
                               parse_report_date(r['date']) is not None and
                               parse_report_date(r['date']) <= parsed_end_date]
                               
        return filtered_reports

    @staticmethod
    def _is_date_visible_for_report(report: dict) -> bool:
        """Return True when report date should be displayed in md_dates_only mode."""
        has_json = bool(report.get("alternative_formats", {}).get("json"))
        report_format = report.get("format")
        return report_format == "json" or (report_format == "md" and not has_json)

    def filter_reports(self, model_filter='', format_filter='', vuln_filter='', severity_filter='', language_filter='', project_filter='', start_date=None, end_date=None, md_dates_only=True, mandatory_filters=None):
        """Filter reports based on criteria"""
        if not self.report_data:
            self.collect_report_data()

        filtered = self.report_data

        if mandatory_filters:
            values = {
                "model": model_filter,
                "format": format_filter,
                "vulnerability": vuln_filter,
                "language": language_filter,
                "project": project_filter,
                "start_date": start_date,
                "end_date": end_date,
            }
            for filter_name in mandatory_filters:
                if not values.get(filter_name):
                    return []

        # Apply model filter (common to both branches)
        if model_filter:
            if isinstance(model_filter, (list, tuple, set)):
                model_filters = [str(m).strip().lower() for m in model_filter if str(m).strip()]
            else:
                model_filters = [m.strip().lower() for m in str(model_filter).split(',') if m.strip()]
            filtered = [r for r in filtered if any(m in r['model'].lower() for m in model_filters)]

        # Apply date filtering (common to both branches)
        filtered = self._apply_date_filter(filtered, start_date, end_date)

        # Standard branch - apply format and vulnerability filters
        if format_filter:
            format_filters = [f.lower() for f in format_filter.split(',')]
            filtered = [r for r in filtered if r['format'].lower() in format_filters]

        if vuln_filter:
            vuln_filters = [v.lower() for v in vuln_filter.split(',')]
            filtered = [
                r
                for r in filtered
                if r.get("vulnerability_type") == "Executive Summary"
                or any(v in r['vulnerability_type'].lower() for v in vuln_filters)
            ]

        if language_filter:
            language_filters = [lang.strip().lower() for lang in language_filter.split(',') if lang.strip()]
            filtered = [
                r for r in filtered
                if ((r.get("language") or "en").strip().lower() in language_filters)
            ]

        if project_filter:
            if isinstance(project_filter, (list, tuple, set)):
                project_filters = [str(p).strip().lower() for p in project_filter if str(p).strip()]
            else:
                project_filters = [
                    p.strip().lower() for p in str(project_filter).split(',') if p.strip()
                ]
            filtered = [
                r
                for r in filtered
                if normalize_dashboard_project_key(r.get("project")) in project_filters
            ]

        severity_tiers = parse_severity_filter_param(severity_filter)
        if severity_tiers:
            filtered = [
                r for r in filtered if report_passes_dashboard_severity_filter(r, severity_tiers)
            ]

        for report in filtered:
            report["date_visible"] = self._is_date_visible_for_report(report) if md_dates_only else True

        return filtered

    def get_report_statistics(self, filtered_reports=None):
        """
        Get statistics for reports
        
        Parameters:
        - filtered_reports: Optional list of already filtered reports. 
                           If provided, statistics will be calculated only for these reports.
        """
        # Check if we need to force a refresh of report data
        force_refresh = request.args.get('force', '0') == '1'
        if force_refresh or not self.report_data:
            self.collect_report_data()

        # Use filtered reports if provided, otherwise use all reports
        reports_to_analyze = filtered_reports if filtered_reports is not None else self.report_data

        # Initialize statistics structure
        stats = {
            "total_reports": 0,
            "models": {},
            "vulnerabilities": {},
            "languages": {},
            "formats": {},
            "dates": {},
            "projects": {},
            "severity_finding_totals": empty_severity_finding_totals(),
            "risk_summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }
        }

        # Calculate statistics based on the provided reports
        for report in reports_to_analyze:
            if report["format"] == "json":
                self._update_stats_for_report(stats, report)
                merge_severity_finding_totals_for_report(stats["severity_finding_totals"], report)

            # count all available formats
            fmt = report["format"]
            if fmt not in stats["formats"]:
                stats["formats"][fmt] = 0
            stats["formats"][fmt] += 1

        # Return the calculated statistics
        return stats

    def get_scan_progress(self, filtered_reports=None):
        """
        Return latest executive summary progress metadata from JSON reports.
        """
        force_refresh = request.args.get('force', '0') == '1'
        if force_refresh or not self.report_data:
            self.collect_report_data()

        reports_to_analyze = filtered_reports if filtered_reports is not None else self.report_data
        progress = self._latest_scan_progress_from_report_data() if filtered_reports is None else self._latest_scan_progress_from_filtered_reports(reports_to_analyze)
        if not progress:
            return self._normalize_scan_progress_payload({}, has_progress=False)
        normalized = self._normalize_scan_progress_payload(progress, has_progress=True)
        if "event_version" in normalized:
            normalized["event_version"] = coerce_scan_progress_event_version(normalized.get("event_version"))
        return normalized

    @staticmethod
    def _latest_scan_progress_from_filtered_reports(reports_to_analyze) -> dict:
        return WebServer._latest_scan_progress_from_reports(reports_to_analyze)

    @staticmethod
    def _merge_json_report_stats_into_risk_summary(
        risk_summary: Dict[str, int], report_stats: Dict[str, Any]
    ) -> None:
        """Accumulate vulnerability JSON ``stats`` into dashboard ``risk_summary`` counters."""
        risk_summary["total_findings"] += report_stats.get("total_findings", 0)
        risk_summary["critical"] += report_stats.get("critical_risk", 0)
        risk_summary["high"] += report_stats.get("high_risk", 0)
        risk_summary["medium"] += report_stats.get("medium_risk", 0)
        risk_summary["low"] += report_stats.get("low_risk", 0)

    def _request_dashboard_filter_kwargs(self, req_args: Any) -> Dict[str, Any]:
        """Extract active dashboard filters from request args for preview-scope checks."""
        return {
            "model_filter": req_args.get('model', ''),
            "format_filter": req_args.get('format', ''),
            "vuln_filter": req_args.get('vulnerability', ''),
            "severity_filter": req_args.get('severity', ''),
            "language_filter": req_args.get('language', ''),
            "project_filter": req_args.get('project', ''),
            "start_date": req_args.get('start_date', None),
            "end_date": req_args.get('end_date', None),
            # Preview-scope checks must match full dashboard scope, not markdown-only date subset.
            "md_dates_only": False,
        }

    @staticmethod
    def _has_any_active_dashboard_filter(filter_kwargs: Dict[str, Any]) -> bool:
        for key in (
            "model_filter",
            "format_filter",
            "vuln_filter",
            "severity_filter",
            "language_filter",
            "project_filter",
            "start_date",
            "end_date",
        ):
            if str(filter_kwargs.get(key) or "").strip():
                return True
        return False

    @staticmethod
    def _allowed_paths_for_filtered_reports(
        filtered_reports: Iterable[Dict[str, Any]] | None,
    ) -> set[str]:
        if not filtered_reports:
            return set()
        allowed_paths: set[str] = set()
        for report in filtered_reports:
            report_path = WebServer._normalize_dashboard_relative_report_path(report.get("path"))
            if report_path:
                allowed_paths.add(report_path)
            alt = report.get("alternative_formats") or {}
            if isinstance(alt, dict):
                for candidate in alt.values():
                    candidate_path = WebServer._normalize_dashboard_relative_report_path(candidate)
                    if candidate_path:
                        allowed_paths.add(candidate_path)
        return allowed_paths

    @staticmethod
    def _normalize_dashboard_relative_report_path(path_value: Any) -> str:
        """Canonicalize report relative paths for filter-scope comparisons."""
        if not isinstance(path_value, str):
            return ""
        raw = path_value.strip()
        if not raw:
            return ""
        if raw.startswith(("/", "\\")):
            return ""
        normalized = os.path.normpath(raw.replace("\\", "/")).replace("\\", "/")
        if normalized in ("", ".", ".."):
            return ""
        if normalized.startswith("../"):
            return ""
        if normalized.startswith("./"):
            normalized = normalized[2:]
        return normalized.lstrip("/")

    @staticmethod
    def _filter_vulnerability_payload_by_severity_tiers(
        payload: Dict[str, Any],
        tiers: Tuple[str, ...],
        *,
        rewrite_stats_totals: bool = False,
    ) -> Dict[str, Any]:
        """Filter canonical vulnerability payload findings to selected severity tiers."""
        if not tiers:
            return payload
        if str(payload.get("report_type") or "").strip().lower() != "vulnerability":
            return payload
        wanted = {str(t or "").strip().lower() for t in tiers if str(t or "").strip()}
        if not wanted:
            return payload

        data = deepcopy(payload)
        files = data.get("files")
        if not isinstance(files, list):
            return data

        filtered_files: List[Dict[str, Any]] = []
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_findings_count = 0
        potential_chunk_count = 0

        for file_item in files:
            if not isinstance(file_item, dict):
                continue
            chunk_list = file_item.get("chunk_analyses")
            kept_chunks: List[Dict[str, Any]] = []
            if isinstance(chunk_list, list):
                for chunk in chunk_list:
                    if not isinstance(chunk, dict):
                        continue
                    findings = chunk.get("findings")
                    if not isinstance(findings, list):
                        continue
                    kept_findings: List[Dict[str, Any]] = []
                    for finding in findings:
                        if not isinstance(finding, dict):
                            continue
                        sev = str(finding.get("severity") or "").strip().lower()
                        if sev in wanted:
                            kept_findings.append(finding)
                            total_findings_count += 1
                            if sev in sev_counts:
                                sev_counts[sev] += 1
                    if kept_findings:
                        chunk_copy = dict(chunk)
                        chunk_copy["findings"] = kept_findings
                        kept_chunks.append(chunk_copy)
                        if bool(chunk_copy.get("potential_vulnerabilities")):
                            potential_chunk_count += 1
            if kept_chunks or file_item.get("error"):
                file_copy = dict(file_item)
                file_copy["chunk_analyses"] = kept_chunks
                filtered_files.append(file_copy)

        data["files"] = filtered_files
        stats = data.get("stats")
        original_stats = dict(stats) if isinstance(stats, dict) else {}
        stats_copy = dict(stats) if isinstance(stats, dict) else {}
        if rewrite_stats_totals:
            stats_copy["critical_risk"] = sev_counts["critical"]
            stats_copy["high_risk"] = sev_counts["high"]
            stats_copy["medium_risk"] = sev_counts["medium"]
            stats_copy["low_risk"] = sev_counts["low"]
            # Keep totals aligned with kept findings even when non-canonical severities are present.
            stats_copy["total_findings"] = total_findings_count
            stats_copy["files_analyzed"] = len(filtered_files)
            # Compatibility note: ``potential_findings`` remains chunk-granular (historical behavior).
            stats_copy["potential_findings"] = potential_chunk_count
        data["stats"] = stats_copy
        if rewrite_stats_totals and original_stats:
            data["stats_unfiltered"] = original_stats
        return data

    def _update_stats_for_report(self, stats: dict, report: dict) -> None:
        stats["total_reports"] += 1
        if model := report.get("model"):
            stats["models"][model] = stats["models"].get(model, 0) + 1

        if vulnerability_type := report.get("vulnerability_type"):
            stats["vulnerabilities"][vulnerability_type] = (
                stats["vulnerabilities"].get(vulnerability_type, 0) + 1
            )

        language = (report.get("language") or "en").lower()
        stats["languages"][language] = stats["languages"].get(language, 0) + 1

        normalized_project = normalize_dashboard_project_key(report.get("project"))
        if normalized_project:
            stats["projects"][normalized_project] = (
                stats["projects"].get(normalized_project, 0) + 1
            )

        if report_date := report.get("date"):
            date_only = report_date.split()[0]
            stats["dates"][date_only] = stats["dates"].get(date_only, 0) + 1

        if "stats" in report and report["stats"]:
            WebServer._merge_json_report_stats_into_risk_summary(
                stats["risk_summary"], report["stats"]
            )

