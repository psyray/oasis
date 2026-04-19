import contextlib
from datetime import datetime, timezone
import logging
from typing import Any
import json
from pathlib import Path
import re
import secrets
import socket
import string
from threading import Thread

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

        def emit(self, _event, _payload):
            return None

        def run(self, app, **kwargs):
            app.run(**kwargs)

        def start_background_task(self, target, *args, **kwargs):
            thread = Thread(target=target, args=args, kwargs=kwargs, daemon=True)
            thread.start()
            return thread

        def sleep(self, seconds):
            time.sleep(seconds)

    def emit(_event, _payload=None):  # type: ignore[override]
        return None


from .config import REPORT, VULNERABILITY_MAPPING, MODEL_EMOJIS, VULN_EMOJIS, LANGUAGES
from .export.filenames import artifact_filename, report_dir_glob_for_format
from .helpers.pipeline_phase_md import parse_phase_counts_from_progress_cell
from .helpers.progress_constants import SCAN_PROGRESS_EXTENDED_KEYS
from .report import Report, executive_summary_progress_sidecar_path
from .tools import parse_iso_date, parse_report_date


def _coerce_scan_progress_event_version(raw: Any) -> int:
    """Normalize ``event_version`` to int for Socket.IO / REST consumers (matches dashboard coercion).

    Integer-like values (non-boolean ints or integer strings) are returned as ints; all other
    values (including booleans and empty/invalid strings) fall back to ``1``.
    """
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    if raw is None:
        return 1
    try:
        text = str(raw).strip()
        return int(text, 10) if text else 1
    except (TypeError, ValueError):
        return 1

logger = logging.getLogger(__name__)


def _dashboard_format_display_order() -> list[str]:
    """Ordered formats for dashboard chips, date-picker open preference, and /api/dates.

    Matching between DASHBOARD_FORMAT_DISPLAY_ORDER and OUTPUT_FORMATS is
    case-insensitive, but the returned list preserves the original casing
    from OUTPUT_FORMATS.
    """
    preferred = REPORT.get("DASHBOARD_FORMAT_DISPLAY_ORDER") or []
    allowed = list(REPORT.get("OUTPUT_FORMATS") or [])

    normalized_to_original: dict[str, str] = {}
    for fmt in allowed:
        key = fmt.lower()
        if key not in normalized_to_original:
            normalized_to_original[key] = fmt

    seen_normalized: set[str] = set()
    out: list[str] = []

    for fmt in preferred:
        key = fmt.lower()
        original = normalized_to_original.get(key)
        if original is not None and key not in seen_normalized:
            out.append(original)
            seen_normalized.add(key)

    for fmt in allowed:
        key = fmt.lower()
        if key not in seen_normalized:
            out.append(fmt)
            seen_normalized.add(key)

    return out

def _socketio_lan_http_origins(port: int) -> list[str]:
    """Best-effort LAN URLs for Socket.IO CORS when the server binds to all interfaces.

    Browsers send ``Origin`` with the host the user typed (e.g. ``http://192.168.1.10:5001``).
    We discover likely interface addresses without requiring extra dependencies.
    """
    out: list[str] = []
    seen: set[str] = set()

    def add_origin(url: str) -> None:
        if url not in seen:
            seen.add(url)
            out.append(url)

    with contextlib.suppress(OSError):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.connect(("192.0.2.1", 80))
            ip = udp.getsockname()[0]
            if ip and not ip.startswith("127."):
                add_origin(f"http://{ip}:{port}")
    with contextlib.suppress(OSError):
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip and not ip.startswith("127."):
                add_origin(f"http://{ip}:{port}")
    return out

def _expand_socketio_cors_config_entries(entries: list[str] | tuple[str, ...], port: int) -> list[str]:
    """Replace ``{port}`` in configured origin strings."""
    expanded: list[str] = []
    for raw in entries:
        if not raw or not isinstance(raw, str):
            continue
        s = raw.strip()
        if not s:
            continue
        if "{port}" in s:
            s = s.format(port=port)
        expanded.append(s)
    return expanded


class WebServer:
    def __init__(self, report, debug=False, web_expose='local', web_password=None, web_port=5000):
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
        self._register_socket_handlers(login_required)
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

    def _register_socket_handlers(self, login_required):
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
        while not self._stop_progress_monitor and self.socketio and not (hasattr(self.socketio, "server") and getattr(self.socketio, "server") is None):
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
        payload["event_version"] = _coerce_scan_progress_event_version(payload.get("event_version"))
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

        expanded_config = _expand_socketio_cors_config_entries(cors_list, port)

        # Always allow this instance: same port as ``socketio.run(..., port=web_port)``.
        runtime: list[str] = [
            f"http://127.0.0.1:{port}",
            f"http://localhost:{port}",
        ]
        expose = str(self.web_expose or "local").strip().lower()
        if expose != "local":
            runtime.extend(_socketio_lan_http_origins(port))

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
        }
        for key in SCAN_PROGRESS_EXTENDED_KEYS:
            if key in progress:
                payload[key] = progress[key]
        return payload

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

    def _is_within_security_root(self, path: Path, root: Path) -> bool:
        """Compatibility-safe path containment check (Python 3.9+ and older).

        Both inputs are resolved here so containment checks always operate on
        normalized absolute paths, regardless of caller behavior.
        """
        path = path.resolve(strict=False)
        root = root.resolve()
        is_relative_to = getattr(path, "is_relative_to", None)
        if callable(is_relative_to):
            return path.is_relative_to(root)
        try:
            path.relative_to(root)
            return True
        except ValueError:
            return False

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
                dashboard_realtime_enabled=bool(REPORT.get("DASHBOARD_REALTIME_ENABLED", True)),
                dashboard_socketio_client_url=str(REPORT.get("DASHBOARD_SOCKETIO_CLIENT_URL") or "").strip(),
                debug=self.debug,
                report_output_formats=REPORT.get('OUTPUT_FORMATS', []),
                dashboard_format_display_order=_dashboard_format_display_order(),
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

                if not self._is_within_security_root(resolved_path, security_root):
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

                if not self._is_within_security_root(resolved_path, security_root):
                    return jsonify({'error': 'Invalid path'}), 403
                if not resolved_path.exists() or resolved_path.suffix != '.json':
                    return jsonify({'error': 'File not found or not JSON'}), 404
                with open(resolved_path, 'r', encoding='utf-8') as f:
                    payload = json.load(f)
                if not isinstance(payload, dict):
                    return jsonify({'error': 'Invalid JSON report payload'}), 422
                return jsonify(payload)
            except Exception:
                return self._report_preview_error_response("Error while generating JSON report preview")

        def _load_report_html_from_json_path(filename: str):
            try:
                file_path = self.security_dir / filename
                security_root = self.security_dir.resolve()
                resolved_path = file_path.resolve(strict=False)

                if not self._is_within_security_root(resolved_path, security_root):
                    return jsonify({'error': 'Invalid path'}), 403
                if not resolved_path.exists() or resolved_path.suffix != '.json':
                    return jsonify({'error': 'File not found or not JSON'}), 404

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
            # Filter reports based on parameters
            filtered_data = self.filter_reports(mandatory_filters=['model', 'vulnerability'])

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
                    for fmt in _dashboard_format_display_order():
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
            if ts_side is not None and ts_emb is not None:
                if ts_side > ts_emb:
                    return from_sidecar
                if ts_side < ts_emb:
                    return from_embedded
                return from_sidecar
            if ts_side is not None and ts_emb is None:
                return from_sidecar
            if ts_side is None and ts_emb is not None:
                return from_embedded
            return from_sidecar

        if from_sidecar is not None:
            return from_sidecar
        if from_embedded is not None:
            return from_embedded
        return {}

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
                "high": sum(report.get("stats", {}).get("high_risk", 0) for report in reports if report["format"] == "json"),
                "medium": sum(report.get("stats", {}).get("medium_risk", 0) for report in reports if report["format"] == "json"),
                "low": sum(report.get("stats", {}).get("low_risk", 0) for report in reports if report["format"] == "json")
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
            model_filters = [m.lower() for m in model_filter.split(',')]
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
                "high": 0,
                "medium": 0,
                "low": 0
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
            normalized["event_version"] = _coerce_scan_progress_event_version(normalized.get("event_version"))
        return normalized

    @staticmethod
    def _latest_scan_progress_from_filtered_reports(reports_to_analyze) -> dict:
        return WebServer._latest_scan_progress_from_reports(reports_to_analyze)

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
            report_stats = report["stats"]
            stats["risk_summary"]["total_findings"] += report_stats.get("total_findings", 0)
            stats["risk_summary"]["high"] += report_stats.get("high_risk", 0)
            stats["risk_summary"]["medium"] += report_stats.get("medium_risk", 0)
            stats["risk_summary"]["low"] += report_stats.get("low_risk", 0)

