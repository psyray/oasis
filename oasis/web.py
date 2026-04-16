from datetime import datetime, timezone
import logging
import json
from pathlib import Path
import re
import secrets
import string

from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
from functools import wraps


from .config import VULNERABILITY_MAPPING, MODEL_EMOJIS, VULN_EMOJIS
from .report import Report
from .tools import parse_iso_date, parse_report_date

logger = logging.getLogger(__name__)

class WebServer:
    def __init__(self, report, debug=False, web_expose='local', web_password=None, web_port=5000):
        self.report = report
        self.debug = debug
        self.web_expose = web_expose
        self.web_password = web_password
        self.web_port = web_port
        self.report_data = None
        if not isinstance(report, Report):
            raise ValueError("Report must be an instance of Report")
        
        self.input_path = Path(report.input_path)
        if not self.input_path.exists():
            raise FileNotFoundError(f"Input path not found at {self.input_path}")
        self.input_path_absolute = self.input_path.resolve()

        self.security_dir = self.input_path_absolute.parent / "security_reports"
        if not self.security_dir.exists():
            raise FileNotFoundError(f"Security reports directory not found at {self.security_dir}")

    def run(self):
        """Serve reports via a web interface."""
        from .__init__ import __version__

        app = Flask(
            __name__, template_folder=str(Path(__file__).parent / "templates"),
            static_folder=str(Path(__file__).parent / "static")
        )
        
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

        # Determine the host based on the expose setting
        host = '127.0.0.1' if self.web_expose == 'local' else '0.0.0.0'
        
        # Run the server
        if self.debug:
            app.run(debug=True, host=host, port=self.web_port)
        else:
            app.run(host=host, port=self.web_port)

    def _generate_random_password(self, length=10):
        """Generate a random password with letters, digits and special characters"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
        
    def _render_login_template(self, error=None):
        """Render the login template"""
        return render_template('login.html', error=error)

    def _is_within_security_root(self, path: Path, root: Path) -> bool:
        """Compatibility-safe path containment check (Python 3.9+ and older)."""
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
            
            return render_template('dashboard.html', 
                                   model_emojis=MODEL_EMOJIS,
                                   vuln_emojis=VULN_EMOJIS,
                                   debug=self.debug)
            
        @app.route('/api/reports')
        @login_required
        def get_reports():
            # Get filter parameters
            model_filter = request.args.get('model', '')
            format_filter = request.args.get('format', '')
            vuln_filter = request.args.get('vulnerability', '')
            start_date = request.args.get('start_date', None)
            end_date = request.args.get('end_date', None)
            md_dates_only = request.args.get('md_dates_only', '1') == '1'

            if request.args.get('force', '0') == '1':
                self.collect_report_data()

            # Filter reports based on parameters
            filtered_data = self.filter_reports(
                model_filter, 
                format_filter, 
                vuln_filter, 
                start_date, 
                end_date, 
                md_dates_only=md_dates_only
            )
            return jsonify(filtered_data)
            
        @app.route('/api/stats')
        @login_required
        def get_stats():
            # Check if there are any filter parameters
            model_filter = request.args.get('model', '')
            format_filter = request.args.get('format', '')
            vuln_filter = request.args.get('vulnerability', '')
            start_date = request.args.get('start_date')
            end_date = request.args.get('end_date')
            
            # If any filters are applied, get filtered reports first
            if any([model_filter, format_filter, vuln_filter, start_date, end_date]):
                filtered_reports = self.filter_reports(
                    model_filter=model_filter,
                    format_filter=format_filter,
                    vuln_filter=vuln_filter,
                    start_date=start_date,
                    end_date=end_date
                )
                return jsonify(self.get_report_statistics(filtered_reports=filtered_reports))
            else:
                # No filters, get global statistics
                return jsonify(self.get_report_statistics())

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
            model = request.args.get('model', '')
            vulnerability = request.args.get('vulnerability', '')
            
            if not model or not vulnerability:
                return jsonify({'error': 'Model and vulnerability parameters are required'}), 400
            
            # Normalize vulnerability type for comparison
            vulnerability = vulnerability.lower()
            
            # Filter reports by model and vulnerability
            filtered_reports = []
            for report in self.report_data:
                report_vuln = report.get('vulnerability_type', '').lower()
                report_model = report.get('model', '')
                
                if model == report_model and vulnerability in report_vuln:
                    filtered_reports.append(report)
            
            # Extract dates from filtered reports
            dates = []
            for report in filtered_reports:
                if 'date' in report:
                    # Create a dictionary date_info from the date string
                    date_info = {'date': report['date']}
                    
                    af = report.get('alternative_formats', {})
                    if af.get('json'):
                        date_info['path'] = af['json']
                        date_info['format'] = 'json'
                    elif af.get('md'):
                        date_info['path'] = af['md']
                        date_info['format'] = 'md'
                    elif report.get('path'):
                        date_info['path'] = report['path']
                        date_info['format'] = report.get('format', 'md')

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
        except Exception as exc:
            logger.warning(
                "Failed to load stats from JSON report '%s': %s",
                report_file,
                exc,
            )
            return {}
        
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
            if fmt not in ['json', 'md', 'html', 'pdf']:
                continue

            globber = fmt_dir.glob('*.json') if fmt == 'json' else fmt_dir.glob('*.*')
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
        
        # Build relative path for web access
        relative_path = report_file.relative_to(self.security_dir)
        
        # Find alternative formats available (including timestamp)
        alternative_formats = self._find_alternative_formats(model_dir, report_file.stem, timestamp_dir)
        
        return {
            "model": model_name,
            "format": fmt,
            "path": str(relative_path),
            "filename": report_file.name,
            "vulnerability_type": vulnerability_type,
            "stats": stats,
            "alternative_formats": alternative_formats,
            "date": report_date,
            "timestamp_dir": timestamp_dir
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

            model = report["model"]
            if model not in stats["models"]:
                stats["models"][model] = 0
            stats["models"][model] += 1

            vuln_type = report["vulnerability_type"]
            if vuln_type not in stats["vulnerabilities"]:
                stats["vulnerabilities"][vuln_type] = 0
            stats["vulnerabilities"][vuln_type] += 1

            if report["date"]:
                date_only = report["date"].split()[0]
                if date_only not in stats["dates"]:
                    stats["dates"][date_only] = 0
                stats["dates"][date_only] += 1

        # count all available formats
        fmt = report["format"]
        if fmt not in stats["formats"]:
            stats["formats"][fmt] = 0
        stats["formats"][fmt] += 1

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
        
        for fmt in ['json', 'md', 'html', 'pdf']:
            fmt_dir = model_dir / fmt
            if fmt_dir.exists() and fmt_dir.is_dir():
                file_path = fmt_dir / f"{report_stem}.{fmt}"
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

    def filter_reports(self, model_filter='', format_filter='', vuln_filter='', start_date=None, end_date=None, md_dates_only=True):
        """Filter reports based on criteria"""
        if not self.report_data:
            self.collect_report_data()

        filtered = self.report_data

        # Apply model filter (common to both branches)
        if model_filter:
            model_filters = [m.lower() for m in model_filter.split(',')]
            filtered = [r for r in filtered if any(m in r['model'].lower() for m in model_filters)]

        # Apply date filtering (common to both branches)
        filtered = self._apply_date_filter(filtered, start_date, end_date)

        if md_dates_only and not format_filter:
            # MD dates only branch - apply vulnerability filter
            if vuln_filter:
                vuln_filters = [v.lower() for v in vuln_filter.split(',')]
                filtered = [r for r in filtered if any(v in r['vulnerability_type'].lower() for v in vuln_filters)]

            # For each report that isn't MD, mark date_visible=False
            for report in filtered:
                report["date_visible"] = self._is_date_visible_for_report(report)

        else:
            # Standard branch - apply format and vulnerability filters
            if format_filter:
                format_filters = [f.lower() for f in format_filter.split(',')]
                filtered = [r for r in filtered if r['format'].lower() in format_filters]

            if vuln_filter:
                vuln_filters = [v.lower() for v in vuln_filter.split(',')]
                filtered = [r for r in filtered if any(v in r['vulnerability_type'].lower() for v in vuln_filters)]

            # Mark all reports as visible in dates
            for report in filtered:
                report['date_visible'] = True

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
            "formats": {},
            "dates": {},
            "risk_summary": {
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }
        
        # Calculate statistics based on the provided reports
        for report in reports_to_analyze:
            if report["format"] == "json":
                stats["total_reports"] += 1

                model = report["model"]
                if model not in stats["models"]:
                    stats["models"][model] = 0
                stats["models"][model] += 1

                vuln_type = report["vulnerability_type"]
                if vuln_type not in stats["vulnerabilities"]:
                    stats["vulnerabilities"][vuln_type] = 0
                stats["vulnerabilities"][vuln_type] += 1

                if report["date"]:
                    date_only = report["date"].split()[0]
                    if date_only not in stats["dates"]:
                        stats["dates"][date_only] = 0
                    stats["dates"][date_only] += 1

                if "stats" in report and report["stats"]:
                    stats["risk_summary"]["high"] += report["stats"].get("high_risk", 0)
                    stats["risk_summary"]["medium"] += report["stats"].get("medium_risk", 0)
                    stats["risk_summary"]["low"] += report["stats"].get("low_risk", 0)

            # count all available formats
            fmt = report["format"]
            if fmt not in stats["formats"]:
                stats["formats"][fmt] = 0
            stats["formats"][fmt] += 1
        
        # Return the calculated statistics
        return stats
        