from pathlib import Path
import re

from oasis.tools import sanitize_name


class WebServer:
    def __init__(self, report):
        self.report = report
        self.report_data = None

    def run(self):
        """Serve reports via a web interface."""
        from flask import Flask, render_template, send_from_directory, request, jsonify
        app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"),
                   static_folder=str(Path(__file__).parent / "static"))
        
        # Process and collect all report data
        self.collect_report_data()

        @app.route('/')
        def index():
            return render_template('dashboard.html')
            
        @app.route('/api/reports')
        def get_reports():
            # Get filter parameters
            model_filter = request.args.get('model', '')
            format_filter = request.args.get('format', '')
            vuln_filter = request.args.get('vulnerability', '')
            
            # Filter reports based on parameters
            filtered_data = self.filter_reports(model_filter, format_filter, vuln_filter)
            return jsonify(filtered_data)
            
        @app.route('/api/stats')
        def get_stats():
            # Return aggregated statistics about all reports
            return jsonify(self.get_report_statistics())

        @app.route('/reports/<path:filename>')
        def serve_report(filename):
            return send_from_directory(self.report.output_dir, filename)
            
        @app.route('/api/report-content/<path:filename>')
        def get_report_content(filename):
            # Return content of markdown file for previewing
            try:
                file_path = self.report.output_dir / filename
                if file_path.exists() and file_path.suffix == '.md':
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    return jsonify({'content': content})
                return jsonify({'error': 'File not found or not a markdown file'}), 404
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        app.run(debug=True, host='0.0.0.0', port=5000)
        
    def collect_report_data(self):
        """Collect and process all report data for efficient filtering and display"""
        reports = []
        
        for model in self.report.models:
            model_name = sanitize_name(model)
            for fmt in self.report.output_format:
                report_dir = self.report.report_dirs.get(model_name, {}).get(fmt)
                if not report_dir:
                    continue
                    
                for report_file in report_dir.glob('*.*'):
                    # Extract vulnerability type from filename
                    vulnerability_type = self._extract_vulnerability_type(report_file.stem)
                    
                    # Extract stats from report content if it's a markdown file
                    stats = self._extract_report_stats(report_file) if fmt == 'md' else {}
                    
                    reports.append({
                        "model": model,
                        "format": fmt,
                        "path": str(report_file.relative_to(self.report.output_dir)),
                        "filename": report_file.name,
                        "vulnerability_type": vulnerability_type,
                        "stats": stats
                    })
        
        self.report_data = reports
        return reports
    
    def _extract_vulnerability_type(self, filename):
        """Extract vulnerability type from filename"""
        # Handle executive summary
        if 'executive_summary' in filename:
            return 'Executive Summary'

        # Handle audit report
        if 'audit_report' in filename:
            return 'Audit Report'

        # Try to match with known vulnerability patterns
        # This is a simple heuristic - you might need to adjust based on your naming conventions
        vulnerability_patterns = {
            'sqli': 'SQL Injection',
            'xss': 'Cross-Site Scripting',
            'csrf': 'Cross-Site Request Forgery',
            'rce': 'Remote Code Execution',
            'ssrf': 'Server-Side Request Forgery',
            'xxe': 'XML External Entity',
            'path': 'Path Traversal',
            'idor': 'Insecure Direct Object Reference',
            'auth': 'Authentication Issues',
            'input': 'Insufficient Input Validation',
            'data': 'Sensitive Data Exposure',
            'session': 'Session Management Issues',
            'config': 'Security Misconfiguration',
            'logging': 'Sensitive Data Logging',
            'crypto': 'Insecure Cryptographic Function Usage'
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
    
    def filter_reports(self, model_filter='', format_filter='', vuln_filter=''):
        """Filter reports based on criteria"""
        if not self.report_data:
            self.collect_report_data()
            
        filtered = self.report_data
        
        if model_filter:
            filtered = [r for r in filtered if model_filter.lower() in r['model'].lower()]
            
        if format_filter:
            filtered = [r for r in filtered if format_filter.lower() == r['format'].lower()]
            
        if vuln_filter:
            filtered = [r for r in filtered if vuln_filter.lower() in r['vulnerability_type'].lower()]
            
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

    def display_report_structure(self):
        """Display the report structure."""
        print(self.report.report_structure)

    def display_report(self):
        """Display the report."""
        print(self.report.report)

    def display_vulnerabilities(self):
        """Display the vulnerabilities."""
        print(self.report.vulnerabilities)

    def display_audit(self):
        """Display the audit."""
        print(self.report.audit)

    def display_executive_summary(self):
        """Display the executive summary."""
        print(self.report.executive_summary)
        
        