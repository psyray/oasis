import ollama
from typing import List, Dict, Tuple
from pathlib import Path
from tqdm import tqdm
from multiprocessing import Pool, cpu_count
import logging
from datetime import datetime

# Import from other modules
from tools import logger, calculate_similarity
from embedding import analyze_vulnerability_parallel
from report import convert_md_to_pdf

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
            self.client = ollama.Client()
            # Verify connection by trying to list models
            self.client.list()
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
            code_chunks = self._split_code_into_chunks(code, MAX_CHUNK_SIZE)
            
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

    def _split_code_into_chunks(self, code: str, max_chunk_size: int) -> List[str]:
        """
        Split code into chunks based on logical boundaries
        """
        lines = code.split('\n')
        chunks = []
        current_chunk = []
        current_size = 0
        
        for line in lines:
            line_size = len(line) + 1  # +1 for newline
            if current_size + line_size > max_chunk_size and current_chunk:
                chunks.append('\n'.join(current_chunk))
                current_chunk = [line]
                current_size = line_size
            else:
                current_chunk.append(line)
                current_size += line_size
        
        if current_chunk:
            chunks.append('\n'.join(current_chunk))
        
        return chunks

def get_vulnerability_mapping() -> Dict[str, Dict[str, any]]:
    """Return mapping of vulnerability tags to their full names and search patterns"""
    return {
        'sqli': {
            'name': "SQL Injection",
            'patterns': [
                "SQL Injection",
                "SQL query vulnerability",
                "database injection vulnerability",
                "unsafe database query",
                "SQL string concatenation vulnerability"
            ]
        },
        'xss': {
            'name': "Cross-Site Scripting (XSS)",
            'patterns': [
                "Cross-Site Scripting",
                "XSS vulnerability",
                "unsafe HTML output",
                "unescaped user input",
                "DOM-based XSS"
            ]
        },
        'input': {
            'name': "Insufficient Input Validation",
            'patterns': [
                "input validation missing",
                "unvalidated user input",
                "unsafe type casting",
                "buffer overflow risk",
                "command injection risk",
                "path traversal vulnerability",
                "unsafe deserialization"
            ]
        },
        'data': {
            'name': "Sensitive Data Exposure",
            'patterns': [
                "sensitive data exposure",
                "plaintext credentials",
                "hardcoded secrets",
                "API keys in code",
                "unencrypted sensitive data",
                "information disclosure",
                "data leakage"
            ]
        },
        'session': {
            'name': "Session Management Issues",
            'patterns': [
                "session fixation",
                "insecure session handling",
                "session hijacking risk",
                "missing session timeout",
                "weak session ID generation",
                "session token exposure",
                "cookie security missing"
            ]
        },
        'config': {
            'name': "Security Misconfiguration",
            'patterns': [
                "security misconfiguration",
                "default credentials",
                "debug mode enabled",
                "insecure permissions",
                "unnecessary features enabled",
                "missing security headers",
                "verbose error messages",
                "directory listing enabled"
            ]
        },
        'logging': {
            'name': "Sensitive Data Logging",
            'patterns': [
                "sensitive data in logs",
                "password logging",
                "PII in logs",
                "credit card logging",
                "token logging",
                "unsafe error logging",
                "debug logging in production"
            ]
        },
        'crypto': {
            'name': "Insecure Cryptographic Function Usage",
            'patterns': [
                "weak encryption",
                "insecure random number generation",
                "weak hash algorithm",
                "MD5 usage",
                "SHA1 usage",
                "ECB mode encryption",
                "static initialization vector",
                "hardcoded encryption key",
                "insufficient key size"
            ]
        }
    }

def analyze_embeddings_distribution(embedding_manager, vulnerability_types: List[Dict], 
                                  thresholds: List[float] = [0.5, 0.6, 0.7, 0.8, 0.9]) -> None:
    """
    Analyze embeddings distribution for each vulnerability type
    Args:
        embedding_manager: Initialized EmbeddingManager
        vulnerability_types: List of vulnerability types to analyze
        thresholds: List of thresholds to test
    """
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

def generate_audit_report(embedding_manager, vulnerability_types: List[Dict], 
                         output_dir: Path, thresholds: List[float] = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]) -> Dict:
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
    report = [
        "# Embeddings Distribution Analysis Report",
        f"\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"\nEmbedding Model: {embedding_manager.embedding_model}",
        f"\nTotal Files Analyzed: {len(embedding_manager.code_base)}",
        "\n## Analysis Results\n"
    ]
    output_dir = output_dir / 'audit'

    # Calculate optimal number of processes
    num_processes = min(cpu_count(), len(embedding_manager.code_base))
    all_results = {}

    logger.info(f"\nUsing {num_processes} processes for parallel analysis\n")

    for i, vuln in enumerate(vulnerability_types):
        logger.info(f"\nAnalyzing {vuln['name']} ({i+1}/{len(vulnerability_types)})")

        if i > 0:
            report.append('\n<div class="page-break"></div>\n')

        report.extend([
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
            report.extend([
                "| - | No valid results | - |",
                "\n#### No valid results found for this vulnerability type\n"
            ])
            all_results[vuln['name']] = []
            continue

        valid_results.sort(key=lambda x: x['similarity_score'], reverse=True)

        # Store results for statistics
        all_results[vuln['name']] = valid_results

        # Add threshold analysis
        for threshold in thresholds:
            matching_files = sum(r['similarity_score'] >= threshold for r in valid_results)
            percentage = (matching_files / len(valid_results)) * 100 if valid_results else 0
            report.append(f"| {threshold:.1f} | {matching_files} | {percentage:.1f}% |")

        # Add top 5 most similar files
        report.extend([
            "\n#### Top 5 Most Similar Files",
            "| File | Similarity Score |",
            "|------|-----------------|"
        ])

        report.extend(
            f"| `{result['file_path']}` | {result['similarity_score']:.3f} |"
            for result in valid_results[:5]
        )
        # Add statistical analysis
        scores = [r['similarity_score'] for r in valid_results]
        report.extend([
            "\n#### Statistical Analysis",
            "| Metric | Value |",
            "|--------|--------|",
            f"| Average Similarity | {sum(scores) / len(scores):.3f} |",
            f"| Median Similarity | {sorted(scores)[len(scores)//2]:.3f} |",
            f"| Maximum Similarity | {max(scores):.3f} |",
            f"| Minimum Similarity | {min(scores):.3f} |"
        ])

    # Add vulnerability statistics section at the start
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

    # Insert vulnerability statistics after the overview
    insert_pos = report.index("\n## Analysis Results\n")
    report[insert_pos:insert_pos] = vuln_stats

    # Save reports in all formats
    report_files = {
        'md': output_dir / 'markdown' / 'audit_analysis.md',
        'pdf': output_dir / 'pdf' / 'audit_analysis.pdf',
        'html': output_dir / 'html' / 'audit_analysis.html'
    }

    # Ensure directories exist
    for file_path in report_files.values():
        file_path.parent.mkdir(parents=True, exist_ok=True)

    # Write markdown
    with open(report_files['md'], 'w', encoding='utf-8') as f:
        f.write('\n'.join(report))

    # Convert to PDF and HTML
    convert_md_to_pdf(
        markdown_file=report_files['md'],
        output_pdf=report_files['pdf'],
        output_html=report_files['html']
    )

    return report_files 