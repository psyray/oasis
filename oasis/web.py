from datetime import datetime, timezone
from pathlib import Path
import re
import secrets
import string

from flask import Flask, render_template, request, jsonify, send_from_directory, session, redirect, url_for
from functools import wraps

from .config import VULNERABILITY_MAPPING, MODEL_EMOJIS
from .report import Report

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
                                   model_emojis=MODEL_EMOJIS)
            
        @app.route('/api/reports')
        @login_required
        def get_reports():
            # Get filter parameters
            model_filter = request.args.get('model', '')
            format_filter = request.args.get('format', '')
            vuln_filter = request.args.get('vulnerability', '')
            start_date = request.args.get('start_date', None)
            end_date = request.args.get('end_date', None)
            
            # Filter reports based on parameters
            filtered_data = self.filter_reports(model_filter, format_filter, vuln_filter, start_date, end_date)
            return jsonify(filtered_data)
            
        @app.route('/api/stats')
        @login_required
        def get_stats():
            # Return aggregated statistics about all reports
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
            # Return content of markdown file for previewing
            try:
                file_path = self.security_dir / filename
                if file_path.exists() and file_path.suffix == '.md':
                    html_content = self.report.read_and_convert_markdown(file_path)
                    return jsonify({'content': html_content})
                return jsonify({'error': 'File not found or not a markdown file'}), 404
            except Exception as e:
                return jsonify({'error': str(e)}), 500

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
                    '.pdf': 'application/pdf'
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
                if 'dates' in report:
                    for date_info in report['dates']:
                        # Add the path to the MD file if available
                        if report.get('formats', {}).get('md', {}).get('path'):
                            date_info['path'] = report['formats']['md']['path']
                        dates.append(date_info)
            
            # Sort dates from newest to oldest
            dates.sort(key=lambda x: x.get('date', ''), reverse=True)
            
            return jsonify({'dates': dates})

        return app

    def collect_report_data(self):
        """Collect and process all report data for efficient filtering and display"""
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
                
                # Explore format directories
                for fmt_dir in [d for d in model_dir.iterdir() if d.is_dir()]:
                    fmt = fmt_dir.name
                    
                    # Check if it's a valid format
                    if fmt not in ['md', 'html', 'pdf']:
                        continue
                    
                    # Explore report files
                    for report_file in fmt_dir.glob('*.*'):
                        # Extract vulnerability type from filename
                        vulnerability_type = self._extract_vulnerability_type(report_file.stem)
                        
                        # Extract report stats if it's a markdown
                        stats = self._extract_report_stats(report_file) if fmt == 'md' else {}
                        
                        # Build relative path for web access
                        relative_path = report_file.relative_to(security_reports_dir)
                        
                        # Find alternative formats available (including timestamp)
                        alternative_formats = self._find_alternative_formats(model_dir, report_file.stem, report_dir.name)
                        
                        reports.append({
                            "model": model_name,
                            "format": fmt,
                            "path": str(relative_path),
                            "filename": report_file.name,
                            "vulnerability_type": vulnerability_type,
                            "stats": stats,
                            "alternative_formats": alternative_formats,
                            "date": report_date,
                            "timestamp_dir": report_dir.name
                        })
        
        # Sort reports by date (from newest to oldest)
        reports.sort(key=lambda x: x['date'] or "", reverse=True)
        
        self.report_data = reports

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
        
        for fmt in ['md', 'html', 'pdf']:
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
            vulnerability: VULNERABILITY_MAPPING[vulnerability]['name']
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
    
    def _extract_report_stats(self, report_file):
        """Extract statistics from a report file"""
        if not report_file.exists() or report_file.suffix != '.md':
            return {}

        try:
            return self._extracted_from__extract_report_stats_(report_file)
        except Exception as e:
            print(f"Error extracting stats from {report_file}: {e}")
            return {}

    # TODO Rename this here and in `_extract_report_stats`
    def _extracted_from__extract_report_stats_(self, report_file):
        with open(report_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Extract metrics using regex patterns
        stats = {}

        if findings_match := re.search(r'Analyzed\s+(\d+)\s+files', content):
            stats['files_analyzed'] = int(findings_match[1])

        # Extract risk levels
        high_risk = len(re.findall(r'High Risk Findings', content))
        medium_risk = len(re.findall(r'Medium Risk Findings', content))
        low_risk = len(re.findall(r'Low Risk Findings', content))

        # Count table rows as an estimation of vulnerabilities
        table_rows = len(re.findall(r'\|\s+\`[^\`]+\`\s+\|\s+[\d\.]+\s+\|', content))

        stats |= {
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'low_risk': low_risk,
            'total_findings': table_rows,
        }

        return stats
    
    def filter_reports(self, model_filter='', format_filter='', vuln_filter='', start_date=None, end_date=None):
        """Filter reports based on criteria"""
        if not self.report_data:
            self.collect_report_data()
            
        filtered = self.report_data
        
        if model_filter:
            model_filters = [m.lower() for m in model_filter.split(',')]
            filtered = [r for r in filtered if any(m in r['model'].lower() for m in model_filters)]
            
        if format_filter:
            format_filters = [f.lower() for f in format_filter.split(',')]
            filtered = [r for r in filtered if r['format'].lower() in format_filters]
            
        if vuln_filter:
            vuln_filters = [v.lower() for v in vuln_filter.split(',')]
            filtered = [r for r in filtered if any(v in r['vulnerability_type'].lower() for v in vuln_filters)]
        
        # Filter by date
        if start_date:
            start_date = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            filtered = [r for r in filtered if r.get('date') and datetime.strptime(r['date'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc) >= start_date]
            
        if end_date:
            end_date = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            filtered = [r for r in filtered if r.get('date') and datetime.strptime(r['date'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc) <= end_date]
        
        return filtered
    
    def get_report_statistics(self):
        """Get overall statistics for all reports"""
        if not self.report_data:
            self.collect_report_data()
            
        stats = {
            'total_reports': len(self.report_data),
            'models': {},
            'vulnerabilities': {},
            'formats': {},
            'risk_summary': {
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        # Count reports by model, vulnerability type, and format
        for report in self.report_data:
            model = report['model']
            vuln_type = report['vulnerability_type']
            fmt = report['format']
            
            stats['models'][model] = stats['models'].get(model, 0) + 1
            stats['vulnerabilities'][vuln_type] = stats['vulnerabilities'].get(vuln_type, 0) + 1
            stats['formats'][fmt] = stats['formats'].get(fmt, 0) + 1
            
            # Aggregate risk levels
            report_stats = report.get('stats', {})
            stats['risk_summary']['high'] += report_stats.get('high_risk', 0)
            stats['risk_summary']['medium'] += report_stats.get('medium_risk', 0)
            stats['risk_summary']['low'] += report_stats.get('low_risk', 0)
            
        return stats
        