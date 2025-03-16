import markdown
from markdown.extensions import Extension
from markdown.preprocessors import Preprocessor
from weasyprint import HTML
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import logging
from jinja2 import Environment, FileSystemLoader

# Import from other modules
from .tools import logger, sanitize_model_name, get_output_directory

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

class Report:
    """Class for generating security analysis reports in multiple formats"""
    
    def __init__(self, input_path: str | Path, output_format: List[str]):
        """
        Initialize the report generator
        
        Args:
            input_path: Path to the input file or directory
            output_format: List of output formats to generate
        """
        # Create output directory for reports
        self.output_format = output_format
        self.report_dirs = self.create_report_directories(input_path)

        # Configure the Jinja2 environment
        template_dir = Path(__file__).parent / 'templates'
        self.template_env = Environment(loader=FileSystemLoader(searchpath=str(template_dir)))

    def ensure_directory(self, directory: Path) -> None:
        """Ensure directory exists"""
        directory.mkdir(parents=True, exist_ok=True)
    
    def create_report_directories(self, input_path: str | Path, sub_dir: str = None) -> Dict[str, Path]:
        """
        Create format-specific directories for reports
        
        Args:
            input_path: Path to the input file or directory
            sub_dir: Optional subdirectory name
            
        Returns:
            Dictionary of format-specific directory paths
        """
        if isinstance(input_path, str):
            input_path = Path(input_path)

        self.output_base_dir = input_path.resolve().parent / "security_reports"
        self.output_dir = get_output_directory(input_path, self.output_base_dir)
        self.ensure_directory(self.output_base_dir)

        base_dir = self.output_dir
        if sub_dir:
            base_dir = base_dir / sub_dir
            self.ensure_directory(base_dir)
        
        # Create format-specific directories
        report_dirs = {
            'md': base_dir / 'markdown',
            'pdf': base_dir / 'pdf',
            'html': base_dir / 'html'
        }

        # Filter out formats that are not in the output_format list
        report_dirs = {
            fmt: report_dirs[fmt] for fmt in self.output_format
        }
        
        # Create all directories
        for dir_path in report_dirs.values():
            self.ensure_directory(dir_path)
            
        return report_dirs
    
    def create_header(self, title: str, model_name: Optional[str] = None) -> List[str]:
        """
        Create a standard report header
        
        Args:
            title: Report title
            model_name: Optional model name to include
            
        Returns:
            List of header lines
        """
        header = [
            f"# {title}",
            f"\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        ]
        
        if model_name:
            header.append(f"\nModel: {model_name}")
            
        return header
    
    def generate_vulnerability_report(self, vulnerability_type: str, results: List[Dict], 
                                     model_name: str) -> Dict[str, Path]:
        """
        Generate a report for a specific vulnerability type
        
        Args:
            vulnerability_type: Name of the vulnerability
            results: Analysis results
            model_name: Model name used for analysis
            
        Returns:
            Dictionary of report file paths
        """
        # Clean vulnerability name for filenames
        safe_name = vulnerability_type.lower().replace(' ', '_')
        
        # Set output file paths and filter by output format in one step
        output_files = self.filter_output_files(safe_name)

        # Create report content
        report = self.create_header(f"{vulnerability_type} Security Analysis", model_name)
        
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
        
        # Add detailed analysis section
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
                analysis = self.normalize_heading_levels(result['analysis'], base_level=5)
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
        
        # Write markdown
        self.write_markdown(output_files['md'], report)
        
        # Convert to PDF and HTML
        self.convert_to_all_formats(output_files['md'])
        
        return output_files
    
    def generate_audit_report(self, analyzer_results: Dict[str, Dict], 
                            embedding_manager) -> Dict[str, Path]:
        """
        Generate audit report from analyzer results
        
        Args:
            analyzer_results: Results from EmbeddingAnalyzer
            embedding_manager: EmbeddingManager instance
            
        Returns:
            Dictionary of report file paths
        """
        # Set output file paths and filter by output format in one step
        output_files = self.filter_output_files("audit_report")

        # Create report content
        report = [
            "# Embeddings Distribution Analysis Report",
            f"\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"\nEmbedding Model: {embedding_manager.embedding_model}",
            f"\nTotal Files Analyzed: {embedding_manager.get_embeddings_info()['total_files']}"
        ]
        
        # Add explanation section
        report.extend([
            "\n## About This Report",
            "\nThis security analysis report uses embedding similarity to identify potential vulnerabilities in your codebase.",
            "\n### Understanding Similarity Scores",
            "- **Similarity Score**: Measures how closely code resembles known vulnerability patterns (0.0-1.0)",
            "- **High Risk**: Scores ≥ 0.8 indicate high likelihood of vulnerability",
            "- **Medium Risk**: Scores between 0.6-0.8 warrant investigation",
            "- **Low Risk**: Scores < 0.6 are less likely to be problematic",
            "\n### How to Use This Report",
            "- Focus first on high-risk findings with high similarity scores",
            "- Review threshold analysis to understand vulnerability distribution",
            "- Use statistics to gauge overall codebase health",
            "- Compare top matches against vulnerability patterns to confirm issues",
            "\n### Next Steps",
            "- Review all high-risk findings immediately",
            "- Schedule code reviews for medium-risk items",
            "- Consider incorporating these checks into your CI/CD pipeline"
        ])

        if vuln_stats := analyzer_results.get('vulnerability_statistics', []):
            report.extend([
                "\n## Vulnerability Statistics\n",
                "| Vulnerability Type | Total | High | Medium | Low |",
                "|-------------------|-------|------|--------|-----|"
            ])

            for stat in vuln_stats:
                if stat.get('is_total', False):
                    report.append(
                        f"| **{stat['name']}** | **{stat['total']}** | **{stat['high']}** | **{stat['medium']}** | **{stat['low']}** |"
                    )
                else:
                    report.append(
                        f"| {stat['name']} | {stat['total']} | {stat['high']} | {stat['medium']} | {stat['low']} |"
                    )

        # Add detailed analysis section
        report.append("\n## Analysis Results\n")

        # Add analysis for each vulnerability type
        for i, (vuln_name, data) in enumerate(analyzer_results.items()):
            # Skip the vulnerability_statistics key
            if vuln_name == 'vulnerability_statistics':
                continue

            if i > 0:
                report.append('\n<div class="page-break"></div>\n')

            report.extend([
                f"### {vuln_name}",
                "#### Threshold Analysis",
                "| Threshold | Matching Items | Percentage |",
                "|-----------|----------------|------------|"
            ])

            # Add threshold analysis
            for analysis in data['threshold_analysis']:
                threshold = analysis['threshold']
                matching_items = analysis['matching_items']
                percentage = analysis['percentage']
                report.append(
                    f"| {threshold:.1f} | {matching_items} | {percentage:.1f}% |"
                )

            # Add top results
            report.extend([
                "\n#### Top Matches",
                "| Score | Item |",
                "|-------|------|"
            ])

            for result in data['results'][:10]:  # Show top 10
                score = result['similarity_score']
                item_id = result['item_id']
                report.append(
                    f"| {score:.3f} | {item_id} |"
                )

            # Add statistics
            stats = data['statistics']
            report.extend([
                "\n#### Statistics",
                f"- **Average similarity**: {stats['avg_score']:.3f}",
                f"- **Median similarity**: {stats['median_score']:.3f}",
                f"- **Maximum similarity**: {stats['max_score']:.3f}",
                f"- **Minimum similarity**: {stats['min_score']:.3f}",
            ])

        # Write markdown
        self.write_markdown(output_files['md'], report)

        # Convert to PDF and HTML
        self.convert_to_all_formats(output_files['md'])

        logger.info("\nAudit report generated successfully")
        logger.info(f"Report location: {self.output_dir.absolute()}")

        return output_files
    
    def generate_executive_summary(self, all_results: Dict[str, List[Dict]], 
                                 model_name: str) -> Dict[str, Path]:
        """
        Generate executive summary report
        
        Args:
            all_results: Dictionary of all vulnerability results
            model_name: Name of model used
            
        Returns:
            Dictionary of report file paths
        """
        # Set output file paths and filter by output format in one step
        output_files = self.filter_output_files("_executive_summary")

        # Start building the executive summary
        report = self.create_header("Security Analysis Executive Summary", model_name)
        
        report.extend([
            "\n## Overview",
            f"\nAnalyzed {len(all_results)} vulnerability types across the codebase."
        ])
        
        # Add interpretation guidance section
        report.extend([
            "\n## About This Summary",
            "\nThis executive summary provides a high-level overview of security vulnerabilities detected in your codebase.",
            "\n### Understanding Risk Levels",
            "- **High Risk (Score ≥ 0.8)**: Critical issues requiring immediate attention; high confidence of actual vulnerabilities",
            "- **Medium Risk (Score 0.6-0.8)**: Potential vulnerabilities that should be investigated soon",
            "- **Low Risk (Score < 0.6)**: Possible concerns with lower confidence; review as resources permit",
            "\n### Key Metrics to Consider",
            "- **Number of High Risk Issues**: Primary indicator of security health",
            "- **Distribution Across Vulnerability Types**: Identifies security training needs",
            "- **Affected Files**: Helps prioritize which components to review first",
            "\n### Recommended Actions",
            "- Address all High Risk findings before the next release cycle",
            "- Assign Medium Risk issues to upcoming sprints",
            "- Consider security training focused on most common vulnerability types",
            "- Implement automated scanning in CI/CD pipelines"
        ])
        
        # Count vulnerabilities
        vulnerability_count = {
            vuln_type: len(results) for vuln_type, results in all_results.items()
        }
        
        # Add vulnerability summary table
        report.extend([
            "\n## Vulnerability Summary",
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
                    f"\n## {severity} Risk Findings ({len(severity_groups[severity])} issues)",
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
        
        # Write markdown
        self.write_markdown(output_files['md'], report)
        
        # Convert to PDF and HTML
        self.convert_to_all_formats(output_files['md'])
        
        return output_files
    
    def write_markdown(self, file_path: Path, content: List[str]) -> None:
        """
        Write content to markdown file
        
        Args:
            file_path: Path to output file
            content: List of content lines
        """
        try:
            # Ensure parent directory exists
            self.ensure_directory(file_path.parent)
            
            # Write content to file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(content))
                
        except Exception as e:
            logger.error(f"Error writing markdown file: {str(e)}")
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Full error:", exc_info=True)
    
    def convert_to_all_formats(self, markdown_file: Path) -> Dict[str, Path]:
        """
        Convert markdown file to PDF and HTML
        
        Args:
            markdown_file: Path to markdown file
            
        Returns:
            Dictionary of output files
        """
        # Set output file paths and filter by output format in one step
        output_files = self.filter_output_files(markdown_file.stem)
        
        try:
            # Read and convert markdown to HTML
            html_content = self.read_and_convert_markdown(markdown_file)
            
            # Render HTML using the template
            rendered_html = self.render_template(html_content)
            
            # Write HTML file
            with open(output_files['html'], 'w', encoding='utf-8') as f:
                f.write(rendered_html)
            
            # Convert to PDF
            try:
                HTML(string=rendered_html).write_pdf(output_files['pdf'])
            except Exception as e:
                logger.error(f"PDF conversion failed for {markdown_file.name}: {e.__class__.__name__}: {str(e)}")
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"HTML content causing PDF conversion failure (first 500 chars): {rendered_html[:500]}")
                output_files['pdf'] = None
            
            return output_files
            
        except Exception as e:
            logger.error(f"Error converting {markdown_file.name} to other formats: {e.__class__.__name__}: {str(e)}")
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Full error:", exc_info=True)
            
            return {
                'md': markdown_file,
                'pdf': None,
                'html': None
            }
    
    def read_and_convert_markdown(self, markdown_file: Path) -> str:
        """
        Read markdown file and convert to HTML
        
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
    
    def render_template(self, content: str) -> str:
        """
        Render HTML content using Jinja2 template
        
        Args:
            content: HTML content to render
            
        Returns:
            Rendered HTML
        """
        try:
            template = self.template_env.get_template('report_template.html')
            return template.render(content=content)
        except Exception as e:
            logger.error(f"Error rendering template: {str(e)}")
            # Fallback to basic HTML if template fails
            return f"<html><body>{content}</body></html>"
    
    def normalize_heading_levels(self, content: str, base_level: int = 5) -> str:
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
    
    def display_report_structure(self, selected_models: List[str]) -> None:
        """
        Display the structure of generated report files
        
        Args:
            selected_models: List of model names with reports
        """
        logger.info("\nAnalysis complete!")
        abs_report_path = str(self.output_base_dir.absolute())
        logger.info(f"\nReports have been generated in: {abs_report_path}")
        logger.info("\nGenerated files structure:")
        
        for model in selected_models:
            model_name = sanitize_model_name(model)
            model_dir = self.output_base_dir / model_name
            if not model_dir.is_dir():
                continue
                
            logger.info(f"\n{model_name}/")
            for fmt_dir in model_dir.glob('*'):
                if not fmt_dir.is_dir():
                    continue
                    
                logger.info(f"  └── {fmt_dir.name}/")
                for report in fmt_dir.glob('*.*'):
                    logger.info(f"       └── {report.name}")

    def filter_output_files(self, safe_name: str) -> Dict[str, Path]:
        """
        Filter output files based on the output_format list

        Args:
            safe_name: Safe name for the report
            
        Returns:
            Dictionary of output files
        """
        return {
            fmt: self.report_dirs[fmt] / f"{safe_name}.{fmt}"
            for fmt in self.output_format
        }
