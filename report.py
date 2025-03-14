import markdown
from markdown.extensions import Extension
from markdown.preprocessors import Preprocessor
from weasyprint import HTML, CSS
from datetime import datetime
from pathlib import Path
from typing import List, Dict
import logging
from jinja2 import Environment, FileSystemLoader

# Import from other modules
from tools import logger, sanitize_model_name

# Configurer l'environnement Jinja2
template_dir = Path(__file__).parent / 'templates'
template_env = Environment(loader=FileSystemLoader(searchpath=str(template_dir)))

def render_template(content: str) -> str:
    """Render HTML content using Jinja2 template"""
    try:
        template = template_env.get_template('report_template.html')
        return template.render(content=content)
    except Exception as e:
        logger.error(f"Error rendering template: {str(e)}")
        # Fallback to basic HTML if template fails
        return f"<html><body>{content}</body></html>"

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

def get_output_paths(markdown_file: Path, output_pdf: Path = None, output_html: Path = None) -> tuple:
    """
    Get output paths for PDF and HTML files, using defaults if not provided
    Args:
        markdown_file: Path to markdown file
        output_pdf: Path for PDF output (default: same as markdown with .pdf)
        output_html: Path for HTML output (default: same as markdown with .html)
    Returns:
        Tuple of (output_pdf, output_html) paths
    """
    if not output_pdf:
        output_pdf = markdown_file.with_suffix('.pdf')
    if not output_html:
        output_html = markdown_file.with_suffix('.html')
    return output_pdf, output_html

def read_and_convert_markdown(markdown_file: Path) -> str:
    """
    Read markdown file and convert to HTML with extensions
    Args:
        markdown_file: Path to markdown file
    Returns:
        HTML content
    """
    # Read markdown content
    with open(markdown_file, 'r', encoding='utf-8') as f:
        markdown_content = f.read()

    # Convert markdown to HTML with page break extension
    return markdown.markdown(
        markdown_content,
        extensions=['tables', 'fenced_code', 'codehilite', PageBreakExtension()]
    )

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
        output_pdf, output_html = get_output_paths(markdown_file, output_pdf, output_html)

        # Read and convert markdown to HTML
        html_content = read_and_convert_markdown(markdown_file)

        # Render HTML using the template
        rendered_html = render_template(html_content)
        
        # Save HTML file and convert to PDF
        with open(output_html, 'w', encoding='utf-8') as f:
            f.write(rendered_html)

        HTML(string=rendered_html).write_pdf(output_pdf)
        
    except Exception as e:
        logger.error(f"Error converting markdown to PDF: {str(e)}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Full error:", exc_info=True)

def create_report_header(vulnerability_type: str, model_name: str) -> list:
    """Create standard report header with title, date and model info"""
    return [
        f"# {vulnerability_type} Security Analysis",
        f"\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"\nModel: {model_name}"
    ]

def ensure_parent_directory(file_path: Path) -> None:
    """Ensure parent directory exists for a given file path"""
    file_path.parent.mkdir(parents=True, exist_ok=True)

def normalize_heading_levels(content: str, base_level: int = 5) -> str:
    """
    Adjust the markdown heading levels to start at a specified level
    
    Args:
        content: Markdown content to normalize
        base_level: Base level for the highest heading (default: 5)
        
    Returns:
        Content with normalized heading levels
    """
    lines = content.split('\n')
    result = []
    
    # Find the lowest heading level (less #)
    min_level = float('inf')
    for line in lines:
        if line.strip().startswith('#'):
            # Count the # at the beginning
            level = 0
            for char in line:
                if char == '#':
                    level += 1
                else:
                    break
            min_level = min(min_level, level)
    
    # If no heading found, return original content
    if min_level == float('inf'):
        return content
    
    # Normalize the headings
    for line in lines:
        if line.strip().startswith('#'):
            # Count the # at the beginning
            level = 0
            for char in line:
                if char == '#':
                    level += 1
                else:
                    break
            
            # Calculate the new level
            new_level = base_level + (level - min_level)
            # Rebuild the line with the correct number of #
            new_line = '#' * new_level + line[level:]
            result.append(new_line)
        else:
            result.append(line)
    
    return '\n'.join(result)

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
        ensure_parent_directory(output_file)
        
        # Create the report header
        report = create_report_header(vulnerability_type, model_name)
        
        # Add summary section
        report.extend([
            "\n## Summary",
            f"\nAnalyzed {len(results)} files for {vulnerability_type} vulnerabilities.",
            "\n| File | Similarity Score |",
            "|------|-----------------|"
        ])
        
        # Add each file with its score
        for result in results:
            score = result.get('similarity_score', 0.0)
            file_path = result.get('file_path', 'Unknown file')
            report.append(f"| `{file_path}` | {score:.3f} |")
        
        # Add each detailed analysis
        report.append("\n## Detailed Analysis\n")
        
        for i, result in enumerate(results):
            file_path = result.get('file_path', 'Unknown file')
            score = result.get('similarity_score', 0.0)
            
            # Add page break between files except for the first one
            if i > 0:
                report.append('\n<div class="page-break"></div>\n')
            
            # Check if analysis key exists
            if 'analysis' in result:
                # Normalize the heading levels in the analysis
                analysis = normalize_heading_levels(result['analysis'], base_level=5)
            elif 'error' in result:
                analysis = f"**Error during analysis:** {result['error']}"
            else:
                analysis = "No detailed analysis available"
            
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
        build_executive_summary_report(output_base_dir, model_name, all_results)
    except Exception as e:
        logger.error(f"Error generating executive summary: {str(e)}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Full error:", exc_info=True)

def build_executive_summary_report(output_base_dir, model_name, all_results):
    """Build and write executive summary report in multiple formats"""
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

    vulnerability_count = {
        vuln_type: len(results) for vuln_type, results in all_results.items()
    }
    # Add vulnerability summary table
    report.extend([
        "\n### Vulnerability Summary",
        "| Vulnerability Type | Files Analyzed |",
        "|-------------------|----------------|"
    ])

    report.extend(
        f"| {vuln_type} | {count} |"
        for vuln_type, count in vulnerability_count.items()
    )
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

def setup_model_directories(model, output_dir):
    """Create and setup directories for a specific model"""
    model_name = sanitize_model_name(model)
    model_dir = output_dir / model_name
    model_dir.mkdir(exist_ok=True)
    
    # Create format-specific directories
    report_dirs = {
        'md': model_dir / 'markdown',
        'pdf': model_dir / 'pdf',
        'html': model_dir / 'html'
    }
    
    # Create all format directories
    for dir_path in report_dirs.values():
        dir_path.mkdir(exist_ok=True)
        
    return model_name, model_dir, report_dirs

def display_report_structure(selected_models, output_dir):
    """Display the structure of generated report files"""
    logger.info("\nAnalysis complete!")
    abs_report_path = str(output_dir.absolute())
    logger.info(f"\nReports have been generated in: {abs_report_path}")
    logger.info("\nGenerated files structure:")
    
    for model in selected_models:
        model_name = sanitize_model_name(model)
        model_dir = output_dir / model_name
        if not model_dir.is_dir():
            continue
            
        logger.info(f"\n{model_name}/")
        for fmt_dir in model_dir.glob('*'):
            if not fmt_dir.is_dir():
                continue
                
            logger.info(f"  └── {fmt_dir.name}/")
            for report in fmt_dir.glob('*.*'):
                logger.info(f"       └── {report.name}")

