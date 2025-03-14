import markdown
from markdown.extensions import Extension
from markdown.preprocessors import Preprocessor
from weasyprint import HTML, CSS
from datetime import datetime
from pathlib import Path
from typing import List, Dict
import logging

# Import from other modules
from tools import logger

class PageBreakExtension(Extension):
    """Markdown extension to handle page breaks"""
    def extendMarkdown(self, md):
        md.preprocessors.register(PageBreakPreprocessor(md), 'page_break', 27)

class PageBreakPreprocessor(Preprocessor):
    """Preprocessor to convert marker to HTML"""
    def run(self, lines):
        new_lines = []
        for line in lines:
            if line.strip() == '<div class="page-break"></div>':
                new_lines.append('<div style="page-break-after: always"></div>')
            else:
                new_lines.append(line)
        return new_lines

def convert_md_to_pdf(markdown_file: Path, output_pdf: Path = None, 
                    output_html: Path = None) -> None:
    """
    Convert markdown file to PDF and optionally HTML
    Args:
        markdown_file: Path to markdown file
        output_pdf: Path for PDF output (default: same as markdown with .pdf)
        output_html: Path for HTML output (default: same as markdown with .html)
    """
    try:
        # Set default output paths if not provided
        if not output_pdf:
            output_pdf = markdown_file.with_suffix('.pdf')
        if not output_html:
            output_html = markdown_file.with_suffix('.html')

        # Read markdown content
        with open(markdown_file, 'r', encoding='utf-8') as f:
            markdown_content = f.read()

        # Convert markdown to HTML with page break extension
        html_content = markdown.markdown(
            markdown_content,
            extensions=['tables', 'fenced_code', 'codehilite', PageBreakExtension()]
        )

        # Add CSS styling with page break support
        html_template = f"""
        <html>
        <head>
            <style>
                @page {{
                    margin: 1cm;
                    size: A4;
                    @top-right {{
                        content: counter(page);
                    }}
                }}
                
                /* Force page break - multiple approaches */
                div[style*="page-break-after: always"],
                div.page-break {{
                    page-break-after: always !important;
                    break-after: page !important;
                    margin: 0 !important;
                    padding: 0 !important;
                    height: 0 !important;
                    visibility: hidden !important;
                }}
                
                body {{ 
                    font-family: Arial, sans-serif;
                    font-size: 11pt;
                    line-height: 1.4;
                    max-width: none;
                    margin: 0;
                    padding: 0;
                }}
                
                code {{
                    background-color: #f5f5f5;
                    padding: 2px 4px;
                    border-radius: 4px;
                    font-family: monospace;
                    font-size: 9pt;
                    word-wrap: break-word;
                    white-space: pre-wrap;
                }}
                
                pre {{
                    background-color: #f5f5f5;
                    padding: 1em;
                    border-radius: 4px;
                    margin: 1em 0;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                    font-size: 9pt;
                }}
                
                h1 {{ 
                    color: #2c3e50;
                    font-size: 20pt;
                    margin-top: 0;
                }}
                
                h2 {{ 
                    color: #34495e;
                    font-size: 16pt;
                    margin-top: 1em;
                }}
                
                h3 {{ 
                    color: #7f8c8d;
                    font-size: 14pt;
                }}
                
                p {{
                    margin: 0.5em 0;
                }}
                
                ul, ol {{
                    margin: 0.5em 0;
                    padding-left: 2em;
                }}
                
                table {{ 
                    border-collapse: collapse; 
                    width: 100%; 
                    margin: 1em 0;
                }}
                
                th, td {{ 
                    border: 1px solid #ddd; 
                    padding: 8px; 
                    text-align: left;
                }}
                
                th {{ 
                    background-color: #f5f5f5;
                    font-weight: bold;
                }}
                
                .risk-high {{ color: #d73a49; }}
                .risk-medium {{ color: #e36209; }}
                .risk-low {{ color: #2cbe4e; }}
            </style>
        </head>
        <body>
            {html_content}
        </body>
        </html>
        """

        # Save HTML file
        with open(output_html, 'w', encoding='utf-8') as f:
            f.write(html_template)

        # Convert HTML to PDF with page numbers
        HTML(string=html_template).write_pdf(
            output_pdf,
            stylesheets=[CSS(string='@page { margin: 1cm; size: A4; @top-right { content: counter(page); } }')]
        )
        
    except Exception as e:
        logger.error(f"Error converting markdown to PDF: {str(e)}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Full error:", exc_info=True)

def generate_markdown_report(vulnerability_type: str, results: List[Dict], 
                           output_file: Path, model_name: str) -> None:
    """
    Generate a markdown report for a vulnerability type
    Args:
        vulnerability_type: Type of vulnerability
        results: List of analysis results
        output_file: Path to output file
        model_name: Name of model used for analysis
    """
    try:
        # Ensure parent directory exists
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Create the report header
        report = [
            f"# {vulnerability_type} Security Analysis",
            f"\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"\nModel: {model_name}"
        ]
        
        # Add summary section
        report.extend([
            "\n## Summary",
            f"\nAnalyzed {len(results)} files for {vulnerability_type} vulnerabilities.",
            "\n| File | Similarity Score |",
            "|------|-----------------|"
        ])
        
        # Add each file with its score
        for result in results:
            score = result['similarity_score']
            file_path = result['file_path']
            report.append(f"| `{file_path}` | {score:.3f} |")
        
        # Add each detailed analysis
        report.append("\n## Detailed Analysis\n")
        
        for i, result in enumerate(results):
            file_path = result['file_path']
            analysis = result['analysis']
            score = result['similarity_score']
            
            # Add page break between files except for the first one
            if i > 0:
                report.append('\n<div class="page-break"></div>\n')
            
            report.extend([
                f"### File: {file_path}",
                f"Similarity Score: {score:.3f}",
                "\n#### Analysis Results\n",
                analysis
            ])
        
        # Write the report to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))
            
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Full error:", exc_info=True)

def generate_executive_summary(all_results: Dict, output_base_dir: Path, model_name: str) -> None:
    """
    Generate an executive summary of all vulnerabilities
    Args:
        all_results: Dictionary of all vulnerability analysis results
        output_base_dir: Base directory for output files
        model_name: Name of model used for analysis
    """
    try:
        # Create required directories if they don't exist
        for subdir in ['markdown', 'pdf', 'html']:
            (output_base_dir / subdir).mkdir(exist_ok=True)
            
        # Start building the executive summary
        report = [
            "# Security Analysis Executive Summary",
            f"\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"\nModel: {model_name}",
            "\n## Overview",
            f"\nAnalyzed {len(all_results)} vulnerability types across the codebase."
        ]
        
        # Build a vulnerability overview
        vulnerability_count = {}
        for vuln_type, results in all_results.items():
            vulnerability_count[vuln_type] = len(results)
        
        # Add vulnerability summary table
        report.extend([
            "\n### Vulnerability Summary",
            "| Vulnerability Type | Files Analyzed |",
            "|-------------------|----------------|"
        ])
        
        for vuln_type, count in vulnerability_count.items():
            report.append(f"| {vuln_type} | {count} |")
            
        # Organize findings by severity
        severity_groups = {
            'High': [],
            'Medium': [],
            'Low': []
        }
        
        for vuln_type, results in all_results.items():
            for result in results:
                # Determine severity based on similarity score
                score = result['similarity_score']
                if score >= 0.8:
                    severity = 'High'
                elif score >= 0.6:
                    severity = 'Medium'
                else:
                    severity = 'Low'
                
                severity_groups[severity].append({
                    'vuln_type': vuln_type,
                    'file_path': result['file_path'],
                    'score': score
                })

        # Add findings by severity
        for severity in ['High', 'Medium', 'Low']:
            if severity_groups[severity]:
                report.extend([
                    f"\n### {severity} Risk Findings ({len(severity_groups[severity])} issues)",
                    "| Vulnerability Type | File | Score | Report Link |",
                    "|-------------------|------|-------|--------------|"
                ])
                
                # Sort by score within each severity group
                for finding in sorted(severity_groups[severity], key=lambda x: x['score'], reverse=True):
                    vuln_file = finding['vuln_type'].lower().replace(' ', '_') + '.pdf'
                    report_path = f"../pdf/{vuln_file}"
                    report.append(
                        f"| {finding['vuln_type']} | `{finding['file_path']}` | {finding['score']:.2f} | [Details]({report_path}) |"
                    )

        # Add timestamp at the bottom
        report.extend([
            "\n---",
            f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Model: {model_name}"
        ])

        # Save reports in all formats
        summary_files = {
            'md': output_base_dir / 'markdown' / 'executive_summary.md',
            'pdf': output_base_dir / 'pdf' / 'executive_summary.pdf',
            'html': output_base_dir / 'html' / 'executive_summary.html'
        }

        # Write markdown
        with open(summary_files['md'], 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))

        # Convert to PDF and HTML
        convert_md_to_pdf(
            markdown_file=summary_files['md'],
            output_pdf=summary_files['pdf'],
            output_html=summary_files['html']
        )

    except Exception as e:
        logger.error(f"Error generating executive summary: {str(e)}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Full error:", exc_info=True) 