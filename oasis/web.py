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
from typing import Any, Dict, List, Optional, Tuple

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
from .export.filenames import artifact_filename, report_dir_glob_for_format
from .helpers.dashboard import (
    AUDIT_METRIC_LABELS,
    AUDIT_METRIC_TABLE_ROW_PATTERN,
    AUDIT_METRICS_SECTION_HEADING_PATTERN,
    AUDIT_METRICS_TABLE_HEADER_LABELS,
    audit_metric_key_from_label,
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
)
from .helpers.progress import SCAN_PROGRESS_EXTENDED_KEYS, coerce_scan_progress_event_version
from .report import Report, executive_summary_progress_sidecar_path, is_executive_summary_progress_sidecar
from .ollama_manager import OllamaManager
from .helpers.assistant_rag import (
    embedding_cache_file_path,
    json_finding_slice,
    load_embedding_code_base,
    retrieve_relevant_snippets,
)
from .helpers.path_containment import is_path_within_root
from .helpers.assistant_api_validate import (
    coerce_finding_indices,
    normalize_report_rel_query_arg,
    resolve_assistant_primary_payload,
    validate_assistant_messages,
)
from .helpers.assistant_chat_context import append_validation_then_balance_rag
from .helpers.assistant_persistence import (
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
from .helpers.assistant_think_parse import enrich_messages_for_response, parse_assistant_think
from .helpers.assistant_context_budget import assistant_total_system_budget_chars
from .helpers.assistant_scan_aggregate import (
    build_aggregate_assistant_document,
    first_vulnerability_payload_from_paths,
    iter_json_report_paths_in_model_dir,
    model_directory_from_security_report_file,
    union_file_paths_from_vulnerability_payloads,
)
from .helpers.executive_dashboard_preview import augment_executive_markdown_preview_html
from .helpers.executive_modal_chart_meta import rollup_severity_counts_from_model_dir
from .helpers.executive_assistant_scope import (
    resolve_aggregate_finding_scope_payload,
    synthetic_executive_primary_payload,
    vulnerability_reports_for_executive_assistant,
)
from .tools import parse_iso_date, parse_report_date

logger = logging.getLogger(__name__)


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
        'You are a defensive security assistant helping triage static-analysis findings '
        'and understand code context. Only provide guidance for authorized testing. '
        'Prefer citing file paths from REPORT_JSON_EXCERPT or RETRIEVAL_CONTEXT.\n\n'
        'REPORT_JSON_EXCERPT:\n'
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
        self.socketio = None
        self.app = None
        self._progress_monitor_started = False
        self._stop_progress_monitor = False
        self._last_emitted_progress_key = None
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
        
        # Run the server
        if self.debug:
            self.socketio.run(app, debug=True, host=host, port=self.web_port)
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

    def _assistant_reserved_chars_for_extras(self) -> int:
        total = self._ASSISTANT_MAX_TOTAL_REPORT_CHARS
        r = int(total * 0.25)
        return max(512, min(4096, r))

    @staticmethod
    def _assistant_reserved_chars_for_total_budget(total_budget: int) -> int:
        r = int(max(1, total_budget) * 0.25)
        return max(512, min(4096, r))

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
        ar = report_payload.get("analysis_root")
        root_path = Path(ar).resolve() if isinstance(ar, str) and ar.strip() else self.input_path_absolute
        cache_path = embedding_cache_file_path(root_path, em_model)

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
            language_filter = request.args.get('language', '')
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
                language_filter=language_filter,
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
                language_filter=request.args.get('language', ''),
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
                language_filter=request.args.get('language', ''),
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

                rel_path = resolved_path.relative_to(security_root)
                rel_parts = rel_path.parts
                if len(rel_parts) < 2:
                    return jsonify({'error': 'Invalid report path'}), 400

                json_rel_path = Path("json", *rel_parts[1:]).with_suffix(".json")
                json_path = security_root / json_rel_path
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
                if is_executive_summary_progress_sidecar(resolved_path):
                    return jsonify(
                        {'error': 'Incremental progress sidecar is not a canonical vulnerability report JSON'}
                    ), 404
                with open(resolved_path, 'r', encoding='utf-8') as f:
                    payload = json.load(f)
                if not isinstance(payload, dict):
                    return jsonify({'error': 'Invalid JSON report payload'}), 422
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
                meta = rollup_severity_counts_from_model_dir(model_dir)
                meta['vulnerability_reports'] = vulnerability_reports_for_executive_assistant(
                    model_dir, security_root
                )
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
            try:
                data = request.get_json(silent=True)
            except Exception:
                data = None
            if not isinstance(data, dict):
                return jsonify({'error': 'Invalid JSON'}), 400

            messages, msg_err = validate_assistant_messages(
                data.get('messages'),
                max_messages=self._ASSISTANT_MAX_MESSAGES,
                max_message_chars=self._ASSISTANT_MAX_MESSAGE_CHARS,
            )
            if msg_err is not None:
                err_body, status = msg_err
                return jsonify(err_body), status
            assert messages is not None

            approx_msg_chars = sum(
                len(str(m.get('content') or '')) for m in messages if isinstance(m, dict)
            )

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

            aggregate_mode = bool(data.get('aggregate_model_json'))
            if aggregate_mode and resolved_report.stem.lower() != '_executive_summary':
                return jsonify(
                    {
                        'error': 'aggregate_model_json requires json/_executive_summary.json (or its md sibling)',
                    }
                ), 400

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

            report_rel = str(resolved_report.relative_to(security_root)).replace('\\', '/')

            json_paths_for_union: List[Path] = []
            extra_rag_paths: Optional[List[str]] = None
            rag_source_payload: Dict[str, Any] = primary_payload
            md_obj: Optional[Path] = None

            if aggregate_mode:
                md_obj = model_directory_from_security_report_file(security_root, resolved_report)
                if md_obj is None:
                    return jsonify({'error': 'Could not resolve model directory for aggregate assistant'}), 400
                json_paths_for_union = iter_json_report_paths_in_model_dir(md_obj)
                if not json_paths_for_union:
                    return jsonify({'error': 'No JSON reports found for aggregate assistant'}), 404
                vp = first_vulnerability_payload_from_paths(json_paths_for_union)
                rag_source_payload = vp if vp is not None else primary_payload
                extra_rag_paths = union_file_paths_from_vulnerability_payloads(json_paths_for_union)

            chat_model = data.get('model')
            if isinstance(chat_model, str) and chat_model.strip():
                chat_model = chat_model.strip()
            else:
                mn = primary_payload.get('model_name')
                chat_model = mn.strip() if isinstance(mn, str) and mn.strip() else ''
                if not chat_model and aggregate_mode:
                    for jp in json_paths_for_union:
                        try:
                            jd = json.loads(jp.read_text(encoding='utf-8'))
                        except Exception:
                            continue
                        if isinstance(jd, dict):
                            mnx = jd.get('model_name')
                            if isinstance(mnx, str) and mnx.strip():
                                chat_model = mnx.strip()
                                break
                if not chat_model:
                    mn2 = rag_source_payload.get('model_name')
                    chat_model = mn2.strip() if isinstance(mn2, str) and mn2.strip() else ''
            if not chat_model:
                return jsonify({'error': 'model required (pass model or ensure report has model_name)'}), 400

            total_budget, _budget_meta = assistant_total_system_budget_chars(
                fallback_total=self._ASSISTANT_MAX_TOTAL_REPORT_CHARS,
                ollama_manager=self._get_assistant_ollama_manager(),
                chat_model=chat_model,
                approx_message_chars_in_request=approx_msg_chars,
            )
            reserved_extras = self._assistant_reserved_chars_for_total_budget(total_budget)
            excerpt_budget = max(total_budget - reserved_extras, 0)

            excerpt_truncated = False
            if aggregate_mode:
                report_payload, _agg_meta = build_aggregate_assistant_document(
                    json_paths_for_union,
                    security_root,
                    total_char_budget=excerpt_budget,
                )
                excerpt_truncated = bool(_agg_meta.get('truncated'))
            else:
                report_payload = primary_payload

            excerpt = json.dumps(report_payload, ensure_ascii=False)
            if excerpt_budget > 0 and len(excerpt) > excerpt_budget:
                excerpt = excerpt[:excerpt_budget] + '\n…(truncated)…'
                excerpt_truncated = True
            elif excerpt_budget <= 0:
                excerpt = ''
                excerpt_truncated = True

            fi, ci, gi = coerce_finding_indices(data)
            finding_scope_for_key = ''
            if aggregate_mode:
                scope_raw = data.get('finding_scope_report_path')
                if isinstance(scope_raw, str) and scope_raw.strip():
                    finding_scope_for_key = scope_raw.strip()
            finding_key_for_prompt = finding_validation_storage_key(
                finding_scope_for_key,
                fi,
                ci,
                gi,
            )
            used_after_excerpt = len(self._ASSISTANT_SYSTEM_INTRO_PREFIX) + len(excerpt)
            remaining_for_prompt = max(0, total_budget - used_after_excerpt)
            finding_header_len = len('\n\nSELECTED_FINDING_JSON:\n')
            finding_max = max(0, min(12000, remaining_for_prompt - finding_header_len - 200))
            finding_json = ''
            if not aggregate_mode:
                finding_json = json_finding_slice(
                    primary_payload,
                    fi,
                    ci,
                    gi,
                    max_chars=finding_max,
                )
            elif aggregate_mode:
                scope_raw = data.get('finding_scope_report_path')
                if isinstance(scope_raw, str) and scope_raw.strip():
                    scope_payload, scope_err = resolve_aggregate_finding_scope_payload(
                        scope_raw.strip(),
                        security_root=security_root,
                        executive_report_path=resolved_report,
                        model_dir=md_obj,
                    )
                    if scope_err is not None:
                        return jsonify({'error': scope_err}), 400
                    if scope_payload is not None:
                        finding_json = json_finding_slice(
                            scope_payload,
                            fi,
                            ci,
                            gi,
                            max_chars=finding_max,
                        )

            use_rag = self.web_assistant_rag and not bool(data.get('rag_disabled'))
            rag_block = ''
            rag_unavailable = False
            if use_rag:
                last_user = ''
                for m in reversed(messages):
                    if isinstance(m, dict) and m.get('role') == 'user':
                        c = m.get('content', '')
                        last_user = c if isinstance(c, str) else ''
                        break
                if last_user.strip():
                    rag_block, rag_unavailable = self._assistant_run_rag_retrieval(
                        last_user=last_user,
                        report_payload=rag_source_payload,
                        report_rel=report_rel,
                        rag_expand_project=bool(data.get('rag_expand_project')),
                        extra_report_file_paths=extra_rag_paths,
                    )

            prompt_chunks: List[str] = [self._ASSISTANT_SYSTEM_INTRO_PREFIX + excerpt]
            if finding_json:
                prompt_chunks.extend(['', 'SELECTED_FINDING_JSON:', finding_json])
            prompt_core = '\n'.join(prompt_chunks)

            finding_validation_for_prompt: Optional[Dict[str, Any]] = None
            sid_ctx = data.get('session_id')
            try:
                if isinstance(sid_ctx, str) and validate_session_id(sid_ctx.strip()):
                    loaded_sess = load_chat_session(
                        self.security_dir, report_rel, sid_ctx.strip()
                    )
                    finding_validation_for_prompt = get_finding_validation_for_branch(
                        loaded_sess,
                        chat_model,
                        finding_key_for_prompt,
                    )
                core_so_far = append_validation_then_balance_rag(
                    prompt_core=prompt_core,
                    finding_validation=finding_validation_for_prompt,
                    rag_block=rag_block,
                    total_budget=total_budget,
                )
            except Exception:
                logger.warning(
                    'Assistant chat context build failed; continuing without persisted finding validation',
                    exc_info=True,
                )
                rag_fallback = ''
                if rag_block:
                    rag_fallback = '\n\nRETRIEVAL_CONTEXT:\n' + rag_block
                core_so_far = prompt_core + rag_fallback

            labels_note = data.get('user_finding_labels')
            labels_header = '\n\nUSER_LOCAL_TRIAGE_NOTES:\n'
            labels_cap = max(0, total_budget - len(core_so_far) - len(labels_header))
            system_content = core_so_far
            if isinstance(labels_note, str) and labels_note.strip():
                note = labels_note.strip()
                if labels_cap > 0 and len(note) > labels_cap:
                    note = note[:labels_cap] + '\n…(truncated)…'
                elif labels_cap <= 0:
                    note = ''
                if note:
                    system_content = core_so_far + '\n\nUSER_LOCAL_TRIAGE_NOTES:\n' + note
            if len(system_content) > total_budget:
                logger.info(
                    "Assistant system prompt capped (chars=%s budget=%s excerpt_truncated=%s)",
                    len(system_content),
                    total_budget,
                    excerpt_truncated,
                )
                system_content = system_content[:total_budget] + '\n…(truncated)…'
            elif excerpt_truncated:
                logger.info(
                    "Assistant report JSON excerpt truncated (budget=%s reserved_extras=%s)",
                    excerpt_budget,
                    reserved_extras,
                )
            full_messages: List[Dict[str, str]] = [{'role': 'system', 'content': system_content}]
            for m in messages:
                role = str(m.get('role', ''))
                content = m.get('content', '')
                if isinstance(content, str):
                    full_messages.append({'role': role, 'content': content})

            try:
                om = self._get_assistant_ollama_manager()
                resp = om.chat(chat_model, full_messages, options={'temperature': 0.2})
            except Exception as exc:
                logger.exception('Assistant chat failed')
                return jsonify({'error': f'Assistant request failed: {type(exc).__name__}'}), 502

            msg = resp.get('message') if isinstance(resp, dict) else None
            raw = ''
            if isinstance(msg, dict):
                raw = msg.get('content') or ''
            split = parse_assistant_think(raw if isinstance(raw, str) else '')
            sid_raw = data.get('session_id')
            if isinstance(sid_raw, str) and validate_session_id(sid_raw.strip()):
                sess_id = sid_raw.strip()
            else:
                sess_id = new_session_id()
            ts = utc_now_iso()
            persist_msgs = normalize_validated_messages_for_storage(messages, default_at=ts)
            persist_msgs.append({'role': 'assistant', 'content': raw if isinstance(raw, str) else '', 'at': ts})
            if aggregate_mode:
                vuln_label = 'Executive summary (aggregate)'
            else:
                vn = primary_payload.get('vulnerability_name')
                vuln_label = vn.strip() if isinstance(vn, str) else ''
            try:
                save_chat_session(
                    self.security_dir,
                    report_rel,
                    sess_id,
                    persist_msgs,
                    chat_model,
                    vuln_label,
                )
            except (ValueError, OSError):
                logger.warning('Assistant session save failed', exc_info=True)

            return jsonify(
                {
                    'message': raw,
                    'visible_markdown': split.visible_markdown,
                    'thought_segments': split.thought_segments,
                    'session_id': sess_id,
                    'model': chat_model,
                    'rag_unavailable': bool(rag_unavailable),
                    'system_budget_chars': total_budget,
                    'assistant_aggregate': aggregate_mode,
                }
            )

        @app.route('/api/assistant/investigate', methods=['POST'])
        @login_required
        def assistant_investigate():
            from oasis.agent.assistant_invoke import (
                coerce_investigation_budget,
                invoke_assistant_validation,
            )
            from oasis.helpers.vuln_taxonomy import ALL_VULN_NAMES
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

            scan_root: Optional[Path] = None
            for candidate_raw in scan_root_candidates:
                candidate = Path(candidate_raw).expanduser().resolve(strict=False)
                if candidate.exists() and candidate.is_dir():
                    scan_root = candidate
                    break

            if scan_root is None:
                if not scan_root_candidates:
                    return jsonify({'error': 'scan_root required (pass scan_root or ensure report has analysis_root)'}), 400
                return jsonify({'error': 'scan_root does not exist'}), 404

            fi, ci, gi = coerce_finding_indices(data)
            scope_merge = data.get('finding_scope_report_path')
            finding_scope_merge = (
                scope_merge.strip()
                if isinstance(scope_merge, str) and scope_merge.strip()
                else ''
            )
            sink_file: Optional[Path] = None
            sink_line: Optional[int] = None
            try:
                if fi is not None and isinstance(primary_payload.get('files'), list):
                    file_entry = primary_payload['files'][fi] if fi < len(primary_payload['files']) else None
                    if isinstance(file_entry, dict):
                        fp = file_entry.get('file_path')
                        if isinstance(fp, str) and fp.strip():
                            candidate = (scan_root / fp).resolve(strict=False)
                            if is_path_within_root(candidate, scan_root) and candidate.is_file():
                                sink_file = candidate
                        chunks = file_entry.get('chunk_analyses') or []
                        if ci is not None and ci < len(chunks) and isinstance(chunks[ci], dict):
                            chunk = chunks[ci]
                            findings = chunk.get('findings') or []
                            if gi is not None and gi < len(findings) and isinstance(findings[gi], dict):
                                line_val = findings[gi].get('snippet_start_line') or chunk.get('start_line')
                                if isinstance(line_val, int) and line_val > 0:
                                    sink_line = line_val
            except Exception:
                sink_file = None
                sink_line = None

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
            client_sink_line_raw = data.get('sink_line')
            if isinstance(client_sink_line_raw, int) and client_sink_line_raw > 0:
                sink_line = client_sink_line_raw

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

            synthesize_raw = data.get('synthesize_narrative')
            if synthesize_raw is None:
                synthesize_narrative = True
            else:
                synthesize_narrative = bool(synthesize_raw)

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
                        from oasis.helpers.assistant_investigation_synth import (
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
            msgs = doc.get('messages')
            if isinstance(msgs, list):
                doc = dict(doc)
                doc['messages'] = enrich_messages_for_response([m for m in msgs if isinstance(m, dict)])
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

                html_content = self.report.render_report_html_from_json_payload(payload)
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
            # Filter reports based on parameters
            filtered_data = self.filter_reports(
                model_filter=model_filter,
                vuln_filter=vulnerability_filter,
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
                    dates.append(date_info)
            
            # Sort dates from newest to oldest
            dates.sort(key=lambda x: x.get('date', ''), reverse=True)
            
            return jsonify({'dates': dates})

        return app

    def collect_report_data(self):
        """Collect and process all report data for efficient filtering and display"""
        reports = self._collect_reports_from_directories()
        self.report_data = reports
        self.global_stats = self._calculate_global_statistics(reports)

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
                    logger.debug(
                        "Skipping pipeline phase row without parseable counts: %s",
                        line[:120],
                    )
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
        reports = []
        security_reports_dir = self.security_dir
            
        # Explore reports in each subdirectory (based on date/timestamp directories)
        for report_dir in [d for d in security_reports_dir.iterdir() if d.is_dir()]:
            # Extract date from directory name
            report_date = self._extract_date_from_dirname(report_dir.name)
            
            # Explore model directories
            for model_dir in [d for d in report_dir.iterdir() if d.is_dir()]:
                # Desanitize model name
                model_name = self._desanitize_name(model_dir.name)
                reports.extend(self._process_model_directory(model_dir, model_name, report_date, report_dir.name))
                
        # Sort reports by date (from newest to oldest)
        reports.sort(key=lambda x: x['date'] or "", reverse=True)
        return reports
        
    def _process_model_directory(self, model_dir, model_name, report_date, timestamp_dir):
        """Process all formats in a model directory"""
        model_reports = []

        # Explore format directories
        for fmt_dir in [d for d in model_dir.iterdir() if d.is_dir()]:
            fmt = fmt_dir.name

            # Check if it's a valid format
            if fmt not in REPORT["OUTPUT_FORMATS"]:
                continue

            globber = fmt_dir.glob(report_dir_glob_for_format(fmt))
            model_reports.extend(
                self._process_report_file(
                    report_file,
                    model_name,
                    fmt,
                    report_date,
                    timestamp_dir,
                    model_dir,
                )
                for report_file in globber
                if fmt != "json"
                or not is_executive_summary_progress_sidecar(report_file)
            )
        return model_reports
        
    def _process_report_file(self, report_file, model_name, fmt, report_date, timestamp_dir, model_dir):
        """Process a single report file and extract metadata"""
        # Extract vulnerability type from filename
        vulnerability_type = self._extract_vulnerability_type(report_file.stem)

        stats = self._stats_from_json_report_file(report_file) if fmt == 'json' else {}
        progress = {}
        if vulnerability_type == "Executive Summary":
            if fmt == "json":
                progress = self._summary_progress_from_json_report_file(report_file)
            elif fmt == "md":
                progress = self._summary_progress_from_markdown_report_file(report_file)
        audit_metrics = {}
        if vulnerability_type == "Audit Report" and fmt == "md":
            audit_metrics = self._audit_metrics_from_markdown_report_file(report_file)

        # Build relative path for web access
        relative_path = report_file.relative_to(self.security_dir)

        # Find alternative formats available (including timestamp)
        alternative_formats = self._find_alternative_formats(model_dir, report_file.stem, timestamp_dir)

        language = None
        if fmt == 'json':
            language = self._language_from_json_report_file(report_file)
        else:
            sibling_json = model_dir / 'json' / f"{report_file.stem}.json"
            if sibling_json.exists():
                language = self._language_from_json_report_file(sibling_json)
        if language is None:
            language = self._language_from_legacy_file(report_file)
        if language is None:
            language = 'en'

        return {
            "model": model_name,
            "format": fmt,
            "path": str(relative_path),
            "filename": report_file.name,
            "vulnerability_type": vulnerability_type,
            "stats": stats,
            "alternative_formats": alternative_formats,
            "date": report_date,
            "timestamp_dir": timestamp_dir,
            "language": language,
            "progress": progress,
            "audit_metrics": audit_metrics,
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

    def _extract_date_from_dirname(self, dirname):
        """Extract date from directory name format [input_path]_[%Y%m%d_%H%M%S]"""
        try:
            # Search for a pattern that resembles YYYYmmdd_HHMMSS at the end of the name
            if match := re.search(r'_(\d{8}_\d{6})$', dirname):
                date_str = match[1]
                # Convert to datetime object
                date_obj = datetime.strptime(date_str, '%Y%m%d_%H%M%S')
                return date_obj.strftime('%Y-%m-%d %H:%M:%S')  # Readable format

            return ""  # If no match, return empty string
        except Exception as e:
            print(f"Error extracting date from {dirname}: {e}")
            return ""

    def _find_alternative_formats(self, model_dir, report_stem, timestamp_dir=None):
        """Find all available formats for a specific report"""
        formats = {}
        
        for fmt in REPORT['OUTPUT_FORMATS']:
            fmt_dir = model_dir / fmt
            if fmt_dir.exists() and fmt_dir.is_dir():
                file_path = fmt_dir / artifact_filename(report_stem, fmt)
                if file_path.exists():
                    # Include timestamp directory in the path
                    if timestamp_dir:
                        relative_path = file_path.relative_to(model_dir.parent.parent)
                        formats[fmt] = str(relative_path)
                    else:
                        formats[fmt] = str(file_path.relative_to(model_dir.parent))
        
        return formats
    
    def _extract_vulnerability_type(self, filename):
        """Extract vulnerability type from filename"""
        # Handle executive summary
        if 'executive_summary' in filename:
            return 'Executive Summary'

        # Handle audit report
        if 'audit_report' in filename:
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

    def filter_reports(self, model_filter='', format_filter='', vuln_filter='', language_filter='', start_date=None, end_date=None, md_dates_only=True, mandatory_filters=None):
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

        if report_date := report.get("date"):
            date_only = report_date.split()[0]
            stats["dates"][date_only] = stats["dates"].get(date_only, 0) + 1

        if "stats" in report and report["stats"]:
            WebServer._merge_json_report_stats_into_risk_summary(
                stats["risk_summary"], report["stats"]
            )

