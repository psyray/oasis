from typing import List, Dict, Tuple
from pathlib import Path
from tqdm import tqdm
from multiprocessing import Pool, cpu_count
import logging
from datetime import datetime

# Import from configuration
from config import VULNERABILITY_MAPPING, VULNERABILITY_PROMPT_EXTENSION, EMBEDDING_THRESHOLDS

# Import from other modules
from ollama_manager import get_ollama_client
from tools import chunk_content, logger, calculate_similarity
from embedding import analyze_vulnerability_parallel
from report import convert_md_to_pdf, generate_executive_summary, generate_markdown_report

class SecurityAnalyzer:
    def __init__(self, llm_model: str, embedding_model: str, code_base: Dict):
        """
        Initialize the security analyzer
        Args:
            llm_model: Model to use for analysis
            embedding_model: Model to use for embeddings
            code_base: Dictionary of code files with embeddings
        """
        try:
            self.client = get_ollama_client()
        except Exception as e:
            logger.error("Failed to initialize Ollama client")
            logger.error("Please make sure Ollama is running and accessible")
            logger.debug(f"Initialization error: {str(e)}")
            raise RuntimeError("Could not connect to Ollama server") from e

        self.llm_model = llm_model
        self.embedding_model = embedding_model
        self.code_base = code_base

    def search_vulnerabilities(self, vulnerability_type: str, threshold: float = 0.5) -> List[Tuple[str, float]]:
        """
        Search for potential vulnerabilities in the code base
        Args:
            vulnerability_type: Type of vulnerability to search for
            threshold: Similarity threshold
        Returns:
            List of (file_path, similarity_score) tuples
        """
        try:
            # Get embedding for vulnerability type
            vulnerability_response = self.client.embeddings(
                model=self.embedding_model,
                prompt=vulnerability_type
            )
            
            if not vulnerability_response or 'embedding' not in vulnerability_response:
                logger.error(f"Failed to get embedding for {vulnerability_type}")
                return []

            # Get the actual embedding vector
            vuln_vector = vulnerability_response['embedding']
            
            # Compare with all files
            results = []
            for file_path, data in self.code_base.items():
                try:
                    if isinstance(data.get('embedding'), dict):
                        # Extract embedding vector from response if needed
                        file_vector = data['embedding'].get('embedding')
                    else:
                        file_vector = data.get('embedding')
                    
                    if not file_vector:
                        logger.error(f"Invalid embedding for file {file_path}")
                        continue
                    
                    # Calculate similarity
                    similarity = calculate_similarity(vuln_vector, file_vector)
                    if similarity >= threshold:
                        results.append((file_path, similarity))
                    
                except Exception as e:
                    logger.error(f"Error processing file {file_path}: {str(e)}")
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("Full error:", exc_info=True)
                    continue
            
            # Sort by similarity score in descending order
            return sorted(results, key=lambda x: x[1], reverse=True)
            
        except Exception as e:
            logger.error(f"Error during search: {str(e)}")
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Full error:", exc_info=True)
            return []

    def analyze_vulnerability(self, file_path: str, vulnerability_type: str) -> str:
        try:
            if file_path not in self.code_base:
                return "File not found in indexed code base"

            code = self.code_base[file_path]['content']
            
            MAX_CHUNK_SIZE = 7500
            code_chunks = chunk_content(code, MAX_CHUNK_SIZE)
            
            analyses = []
            for i, chunk in enumerate(code_chunks):
                prompt = f"""You are a cybersecurity expert. Focus ONLY on finding {vulnerability_type} vulnerabilities in the following code segment ({i+1}/{len(code_chunks)}).
                DO NOT analyze any other type of vulnerability.
                
                Provide a detailed analysis with:
                1. Quote the exact vulnerable code snippets related to {vulnerability_type}
                2. Explain specifically how this code is vulnerable to {vulnerability_type}
                3. Severity level (Critical/High/Medium/Low) specific to {vulnerability_type}
                4. Potential impact of this {vulnerability_type} vulnerability
                5. Remediation recommendations with secure code example
                
                If you don't find any {vulnerability_type} vulnerability in this code segment, do not report it."

                Format your response in Markdown, and for each vulnerability found, start with the vulnerable code block in a code fence.

                Code segment to analyze:
                {chunk}

                {VULNERABILITY_PROMPT_EXTENSION}
                """

                response = self.client.chat(
                    model=self.llm_model,
                    messages=[{'role': 'user', 'content': prompt}]
                )
                analyses.append(response['message']['content'])
            
            return "\n\n=== Next Code Segment ===\n\n".join(analyses)

        except Exception as e:
            logger.error(f"Error during analysis: {str(e)}")
            return f"Error during analysis: {str(e)}"

def get_vulnerability_mapping() -> Dict[str, Dict[str, any]]:
    """Return the vulnerability mapping"""
    return VULNERABILITY_MAPPING

def analyze_embeddings_distribution(embedding_manager, vulnerability_types: List[Dict], thresholds: List[float] = None) -> None:
    """
    Analyze embeddings distribution for each vulnerability type
    Args:
        embedding_manager: Initialized EmbeddingManager
        vulnerability_types: List of vulnerability types to analyze
        thresholds: List of thresholds to test
    """
    if thresholds is None:
        thresholds = EMBEDDING_THRESHOLDS
        
    logger.info("\nEmbeddings Distribution Analysis")
    logger.info("================================\n")

    for vuln in vulnerability_types:
        logger.info(f"\nAnalyzing: {vuln['name']}")
        logger.info("-" * (11 + len(vuln['name'])))

        # Get similarity scores for all files
        results = []
        for file_path, data in embedding_manager.code_base.items():
            try:
                # Get embedding for vulnerability type
                vuln_response = embedding_manager.client.embeddings(
                    model=embedding_manager.embedding_model,
                    prompt=vuln['name']
                )

                if not vuln_response or 'embedding' not in vuln_response:
                    continue

                similarity = calculate_similarity(
                    vuln_response['embedding'],
                    data['embedding']
                )
                results.append((file_path, similarity))
            except Exception as e:
                logger.debug(f"Error processing {file_path}: {str(e)}")
                continue

        if not results:
            logger.warning("No results found")
            continue

        # Sort by similarity score
        results.sort(key=lambda x: x[1], reverse=True)

        # Print threshold analysis
        logger.info("\nThreshold Analysis:")
        logger.info("------------------")
        for threshold in thresholds:
            matching_files = sum(score >= threshold for _, score in results)
            percentage = (matching_files / len(results)) * 100
            logger.info(f"Threshold {threshold:.1f}: {matching_files:3d} files ({percentage:5.1f}%)")

        # Print top 5 most similar files
        logger.info("\nTop 5 Most Similar Files:")
        logger.info("------------------------")
        for file_path, score in results[:5]:
            logger.info(f"{score:.3f} - {file_path}")

        # Basic statistical analysis
        scores = [score for _, score in results]
        avg_score = sum(scores) / len(scores)
        median_score = sorted(scores)[len(scores)//2]

        logger.info("\nStatistics:")
        logger.info("-----------")
        logger.info(f"Average similarity: {avg_score:.3f}")
        logger.info(f"Median similarity: {median_score:.3f}")
        logger.info(f"Max similarity: {max(scores):.3f}")
        logger.info(f"Min similarity: {min(scores):.3f}")

def generate_audit_report(embedding_manager, vulnerability_types: List[Dict], output_dir: Path, thresholds: List[float] = None) -> Dict:
    """
    Generate audit report with parallel processing
    Args:
        embedding_manager: Initialized EmbeddingManager
        vulnerability_types: List of vulnerability types to analyze
        output_dir: Directory to save reports
        thresholds: List of thresholds to test
    Returns:
        Dictionary of report file paths
    """
    # Extract methods for better code organization
    def _init_report():
        # Initialize basic report structure
        return [
            "# Embeddings Distribution Analysis Report",
            f"\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"\nEmbedding Model: {embedding_manager.embedding_model}",
            f"\nTotal Files Analyzed: {len(embedding_manager.code_base)}",
            "\n## Analysis Results\n"
        ]
    
    def _analyze_vulnerability(vuln, report_sections, i):
        # Analyze single vulnerability type
        logger.info(f"\nAnalyzing {vuln['name']} ({i+1}/{len(vulnerability_types)})")
        
        if i > 0:
            report_sections.append('\n<div class="page-break"></div>\n')
            
        report_sections.extend([
            f"### {vuln['name']}",
            "#### Threshold Analysis",
            "| Threshold | Matching Files | Percentage |",
            "|-----------|----------------|------------|"
        ])
        
        # Prepare arguments for parallel processing
        process_args = [
            (file_path, data, vuln['name'], embedding_manager.embedding_model)
            for file_path, data in embedding_manager.code_base.items()
        ]

        # Single progress bar for files
        with tqdm(total=len(process_args), desc="Processing files", 
                 leave=True) as file_pbar:

            # Run analysis in parallel with manual progress update
            results = []
            with Pool(processes=num_processes) as pool:
                for result in pool.imap(analyze_vulnerability_parallel, process_args):
                    results.append(result)
                    file_pbar.update(1)

        # Filter out errors and sort by similarity score
        valid_results = [r for r in results if 'error' not in r]

        if not valid_results:
            logger.warning(f"No valid results for {vuln['name']}")
            report_sections.extend([
                "| - | No valid results | - |",
                "\n#### No valid results found for this vulnerability type\n"
            ])
            return []

        valid_results.sort(key=lambda x: x['similarity_score'], reverse=True)

        # Store results for statistics
        return valid_results
    
    def _generate_statistics(all_results):
        # Generate vulnerability statistics section
        vuln_stats = [
            "\n## Vulnerability Statistics\n",
            "| Vulnerability Type | Total | High | Medium | Low |",
            "|-------------------|-------|------|--------|-----|"
        ]
        
        total_high = 0
        total_medium = 0
        total_low = 0

        for vuln_type, results in all_results.items():
            high = sum(r['similarity_score'] >= 0.8 for r in results)
            medium = sum(0.6 <= r['similarity_score'] < 0.8 for r in results)
            low = sum(r['similarity_score'] < 0.6 for r in results)
            total = len(results)

            total_high += high
            total_medium += medium
            total_low += low

            if total > 0:
                vuln_stats.append(
                    f"| {vuln_type} | {total} | {high} | {medium} | {low} |"
                )

        # Add total row
        total_issues = sum(len(results) for results in all_results.values())
        vuln_stats.append(
            f"| **TOTAL** | **{total_issues}** | **{total_high}** | **{total_medium}** | **{total_low}** |"
        )
        
        return vuln_stats
    
    # Main function logic
    if thresholds is None:
        thresholds = EMBEDDING_THRESHOLDS
        
    report = _init_report()
    output_dir = output_dir / 'audit'
    all_results = {}

    # Calculate optimal number of processes
    num_processes = min(cpu_count(), len(embedding_manager.code_base))
    logger.info(f"\nUsing {num_processes} processes for parallel analysis\n")
    
    # Process each vulnerability type
    for i, vuln in enumerate(vulnerability_types):
        results = _analyze_vulnerability(vuln, report, i)
        all_results[vuln['name']] = results
    
    # Add vulnerability statistics
    vuln_stats = _generate_statistics(all_results)
    insert_pos = report.index("\n## Analysis Results\n")
    report[insert_pos:insert_pos] = vuln_stats
    
    # Save reports in all formats
    return _save_reports(report, output_dir)

def _save_reports(report_content, output_dir):
    """
    Save reports in multiple formats
    Args:
        report_content: List of report lines
        output_dir: Directory to save reports
    Returns:
        Dictionary of report file paths
    """
    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create directories for each format
    markdown_dir = output_dir / 'markdown'
    pdf_dir = output_dir / 'pdf'
    html_dir = output_dir / 'html'
    
    for dir_path in [markdown_dir, pdf_dir, html_dir]:
        dir_path.mkdir(exist_ok=True)
    
    # Join report content into a single string
    report_text = '\n'.join(report_content)
    
    # Save markdown report
    md_path = markdown_dir / 'distribution_analysis.md'
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(report_text)
    
    # Save PDF and HTML versions
    pdf_path = pdf_dir / 'distribution_analysis.pdf'
    html_path = html_dir / 'distribution_analysis.html'
    
    try:
        convert_md_to_pdf(md_path, pdf_path, html_path)
        logger.info("✅ Distribution analysis report saved")
    except Exception as e:
        logger.error(f"Error generating PDF/HTML: {str(e)}")
    
    # Return paths dictionary
    return {
        'markdown': md_path,
        'pdf': pdf_path,
        'html': html_path
    }

def process_analysis_with_model(model, vulnerabilities, embedding_manager, args, report_dirs):
    """Process vulnerability analysis with a specific model"""
    min_threshold = 0.3
    
    # Create analyzer with current model
    analyzer = SecurityAnalyzer(
        llm_model=model,
        embedding_model=args.embed_model,
        code_base=embedding_manager.code_base
    )
    
    # Store all results for executive summary
    all_results = {}
    
    # Analysis for each vulnerability type
    with tqdm(total=len(vulnerabilities), 
             desc="Analyzing vulnerabilities", 
             disable=args.silent) as vuln_pbar:
        for vuln in vulnerabilities:
            # First, find potentially vulnerable files
            results = analyzer.search_vulnerabilities(vuln['name'], threshold=min_threshold)
            
            filtered_results = [(path, score) for path, score in results if score >= args.threshold]
            
            # Then analyze each file in detail with progress bar
            detailed_results = []
            with tqdm(filtered_results, 
                     desc=f"Analyzing {vuln['name']} details", 
                     disable=args.silent,
                     leave=False) as file_pbar:
                for file_path, similarity_score in file_pbar:
                    file_pbar.set_postfix_str(f"File: {Path(file_path).name}")
                    analysis = analyzer.analyze_vulnerability(file_path, vuln['name'])
                    detailed_results.append({
                        'file_path': file_path,
                        'similarity_score': similarity_score,
                        'analysis': analysis
                    })

            # Store results for executive summary
            all_results[vuln['name']] = detailed_results

            # Create report files in appropriate directories
            report_files = {
                'md': report_dirs['md'] / f"{vuln['name'].lower().replace(' ', '_')}.md",
                'pdf': report_dirs['pdf'] / f"{vuln['name'].lower().replace(' ', '_')}.pdf",
                'html': report_dirs['html'] / f"{vuln['name'].lower().replace(' ', '_')}.html"
            }

            # Generate markdown report with detailed analysis
            generate_markdown_report(
                vulnerability_type=vuln['name'],
                results=detailed_results,
                output_file=report_files['md'],
                model_name=model
            )

            # Convert to PDF if not disabled
            if not args.no_pdf:
                convert_md_to_pdf(
                    markdown_file=report_files['md'],
                    output_pdf=report_files['pdf'],
                    output_html=report_files['html']
                )

            # Update main progress bar
            vuln_pbar.update(1)
    
    # Generate executive summary after all vulnerabilities are analyzed
    generate_executive_summary(all_results, report_dirs['md'].parent, model)
    
    return all_results

def get_vulnerabilities_to_check(args, vuln_mapping):
    """Determine which vulnerabilities to check based on args"""
    if args.vulns.lower() == 'all':
        return list(vuln_mapping.values()), None

    selected_tags = [tag.strip() for tag in args.vulns.split(',')]
    if invalid_tags := [
        tag for tag in selected_tags if tag not in vuln_mapping
    ]:
        logger.error(f"Invalid vulnerability tags: {', '.join(invalid_tags)}")
        logger.error("Use --help to see available tags")
        return None, invalid_tags

    return [vuln_mapping[tag] for tag in selected_tags], None

