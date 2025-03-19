import argparse
from typing import List, Dict, Tuple, Any, Union
from pathlib import Path
from tqdm import tqdm
from multiprocessing import Pool, cpu_count

# Import from configuration
from .config import VULNERABILITY_PROMPT_EXTENSION, EMBEDDING_THRESHOLDS, MAX_CHUNK_SIZE, DEFAULT_ARGS

# Import from other modules
from .ollama_manager import OllamaManager
from .tools import chunk_content, logger, calculate_similarity, sanitize_name
from .report import Report
from .embedding import EmbeddingManager, build_vulnerability_embedding_prompt

class SecurityAnalyzer:
    def __init__(self, llm_model: str, embedding_manager: EmbeddingManager, ollama_manager: OllamaManager):
        """
        Initialize the security analyzer

        Args:
            llm_model: Model to use for analysis
            embedding_manager: Embedding manager to use for embeddings
        """
        try:
            self.ollama_manager = ollama_manager
            self.client = self.ollama_manager.get_client()
        except Exception as e:
            logger.error("Failed to initialize Ollama client")
            logger.error("Please make sure Ollama is running and accessible")
            logger.exception(f"Initialization error: {str(e)}")
            raise RuntimeError("Could not connect to Ollama server") from e

        self.llm_model = llm_model
        self.embedding_manager = embedding_manager
        self.embedding_model = embedding_manager.embedding_model
        self.code_base = embedding_manager.code_base
        self.analyze_type = embedding_manager.analyze_type
        self.analyze_by_function = embedding_manager.analyze_by_function
        self.threshold = embedding_manager.threshold

    def search_vulnerabilities(self, vulnerability: Union[str, Dict], threshold: float = DEFAULT_ARGS['THRESHOLD']) -> List[Tuple[str, float]]:
        """
        Search for potential vulnerabilities in the code base

        Args:
            vulnerability: Type of vulnerability to search for (string name or complete dict)
            threshold: Similarity threshold (default: 0.5)

        Returns:
            List of (identifier, similarity_score) tuples where identifier is either file_path or function_id
        """
        try:
            vuln_name = vulnerability['name']
            
            # Get embedding for vulnerability type using complete information if available
            vuln_vector = self.embedding_manager.get_vulnerability_embedding(vulnerability)
            if not vuln_vector:
                logger.error(f"Failed to get embedding for vulnerability type '{vuln_name}'. No embedding returned.")
                return []
                
            results = []
            
            # Process all files
            for file_path, data in self.code_base.items():
                if self.analyze_by_function:
                    # Process functions for this file
                    self._process_functions(file_path, data, vuln_vector, threshold, results)
                else:
                    # Process file as a whole
                    self._process_file(file_path, data, vuln_vector, threshold, results)
                    
            # Sort by similarity score in descending order
            return sorted(results, key=lambda x: x[1], reverse=True)
                
        except Exception as e:
            logger.exception(f"Error during vulnerability search: {str(e)}")
            return []

    def analyze_vulnerability(self, file_path: str, vulnerability: Union[str, Dict]) -> str:
        """
        Analyze a file for a specific vulnerability.

        Args:
            file_path: Path to the file to analyze
            vulnerability: Vulnerability to analyze
        """
        try:
            if file_path not in self.code_base:
                return "File not found in indexed code base"

            vuln_name, vuln_desc, vuln_patterns, vuln_impact, vuln_mitigation = self._get_vulnerability_details(vulnerability)
            if not vuln_name:  # Check if vulnerability details extraction failed
                return "Invalid vulnerability type"

            code = self.code_base[file_path]['content']
            code_chunks = chunk_content(code, MAX_CHUNK_SIZE)

            analyses = []
            with tqdm(total=len(code_chunks), 
                     desc=f"Analyzing chunks of {Path(file_path).name}", 
                     leave=False) as chunk_pbar:
                for i, chunk in enumerate(code_chunks):
                    prompt = self._build_analysis_prompt(vuln_name, vuln_desc, vuln_patterns, vuln_impact, vuln_mitigation, chunk, i, len(code_chunks))
                    analysis_result = self._analyze_code_chunk(prompt, i+1, len(code_chunks))
                    analyses.append(analysis_result)
                    chunk_pbar.update(1)
                    chunk_pbar.set_postfix_str(f"Chunk {i+1}/{len(code_chunks)}")

            return "\n\n<div class=\"page-break\"></div>\n\n".join(analyses)

        except Exception as e:
            logger.exception(f"Error during analysis: {str(e)}")
            return f"Error during analysis: {str(e)}"

    def process_analysis_with_model(self, vulnerabilities, args, report: Report):
        """
        Process vulnerability analysis with current model
        
        Args:
            vulnerabilities: List of vulnerability types to analyze
            args: Command line arguments
            report: Report object
            
        Returns:
            Dictionary with analysis results
        """
        # Store all results for executive summary
        all_results = {}

        # Determine if we're analyzing by function or by file
        logger.info(f"Analyzing by {self.analyze_type}")

        # Analysis for each vulnerability type
        with tqdm(total=len(vulnerabilities), 
                 desc="Analyzing vulnerabilities", 
                 disable=args.silent) as vuln_pbar:
            for vuln in vulnerabilities:
                # First, find potentially vulnerable files using complete vulnerability data
                results = self.search_vulnerabilities(
                    vuln,
                    threshold=self.threshold
                )
                
                filtered_results = [(path, score) for path, score in results if score >= args.threshold]
                
                # Then analyze each file in detail with progress bar
                detailed_results = []
                with tqdm(filtered_results, 
                         desc=f"Analyzing {vuln['name']} details", 
                         disable=args.silent,
                         leave=False) as file_pbar:
                    for file_path, similarity_score in file_pbar:
                        file_pbar.set_postfix_str(f"File: {Path(file_path).name}")
                        
                        # Use the complete vulnerability object for detailed analysis
                        analysis = self.analyze_vulnerability(file_path, vuln)
                        
                        detailed_results.append({
                            'file_path': file_path,
                            'similarity_score': similarity_score,
                            'analysis': analysis,
                            'vulnerability': {
                                'name': vuln['name'],
                                'description': vuln['description'],
                                'impact': vuln['impact'],
                                'mitigation': vuln['mitigation']
                            }
                        })

                # Store results for executive summary
                all_results[vuln['name']] = detailed_results

                # Generate vulnerability report with enhanced vulnerability information
                report.generate_vulnerability_report(
                    vulnerability=vuln,
                    results=detailed_results,
                    model_name=self.llm_model,
                )

                # Update main progress bar
                vuln_pbar.update(1)
        
        # Generate executive summary with enhanced data
        report.generate_executive_summary(all_results, self.llm_model)
        report.report_generated(report_type='Executive Summary', report_structure=False)

        return all_results
    
    @staticmethod
    def get_vulnerabilities_to_check(args, vuln_mapping):
        """
        Determine which vulnerabilities to check based on args
        
        Args:
            args: Command line arguments
            vuln_mapping: Dictionary mapping vulnerability tags to definitions
            
        Returns:
            Tuple of (vulnerability_list, invalid_tags)
        """
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

    def _get_vulnerability_details(self, vulnerability: Union[str, Dict]) -> Tuple[str, str, list, str, str]:
        """
        Extract vulnerability details from dict or return empty strings if invalid.

        Args:
            vulnerability: Vulnerability to extract details from
            
        Returns:
            Tuple of (vulnerability name, description, patterns, impact, mitigation)
        """
        if isinstance(vulnerability, dict):
            return (vulnerability.get('name', ''), vulnerability.get('description', ''), vulnerability.get('patterns', []),
                    vulnerability.get('impact', ''), vulnerability.get('mitigation', ''))
        logger.error(f"Invalid vulnerability type: {vulnerability}")
        return "", "", [], "", ""

    def _build_analysis_prompt(self, vuln_name: str, vuln_desc: str, vuln_patterns: list,
                               vuln_impact: str, vuln_mitigation: str, chunk: str, i: int, total_chunks: int) -> str:
        """
        Construct the prompt for the LLM analysis.
        
        Args:
            vuln_name: Name of the vulnerability
            vuln_desc: Description of the vulnerability
            vuln_patterns: Common patterns associated with the vulnerability
            vuln_impact: Security impact of the vulnerability
            vuln_mitigation: Mitigation strategies for the vulnerability
            chunk: Code chunk to analyze
            i: Current chunk index
            total_chunks: Total number of chunks
            
        Returns:
            Formatted prompt for LLM analysis
        """
        # Format vulnerability info section
        vuln_info = (
            f"- Name: {vuln_name}\n"
            f"- Description: {vuln_desc}\n"
            f"- Common patterns: {', '.join(vuln_patterns[:5]) if vuln_patterns else 'N/A'}\n"
            f"- Security impact: {vuln_impact}\n"
            f"- Mitigation: {vuln_mitigation}"
        )
        
        # Build the complete prompt with clear sections
        return f"""You are a cybersecurity expert specialized in code analysis. Focus ONLY on finding {vuln_name} vulnerabilities in the following code segment ({i + 1}/{total_chunks}).
DO NOT analyze any other type of vulnerability.

VULNERABILITY DETAILS:
{vuln_info}

Provide a detailed analysis with:
1. Quote the exact vulnerable code snippets related to {vuln_name}
2. Explain specifically how this code is vulnerable to {vuln_name}
3. Severity level (Critical/High/Medium/Low) specific to this vulnerability
4. Potential impact of this vulnerability
5. Remediation recommendations with secure code example

If you don't find any {vuln_name} vulnerability in this code segment, clearly state: "No {vuln_name} vulnerabilities found in this segment".

Format your response in Markdown, and for each vulnerability found, start with the vulnerable code block in a code fence.

Code segment to analyze:
```
{chunk}
```

{VULNERABILITY_PROMPT_EXTENSION}
"""

    def _analyze_code_chunk(self, prompt: str, chunk_index: int = None, total_chunks: int = None) -> str:
        """
        Analyze a single code chunk with the LLM.

        Args:
            prompt: Prompt to analyze
            chunk_index: Current chunk index (optional)
            total_chunks: Total number of chunks to analyze (optional)
        """
        try:
            response = self.client.chat(model=self.llm_model, messages=[{'role': 'user', 'content': prompt}])
            return response['message']['content']
        except Exception as e:
            logger.exception(f"Error during chunk analysis: {str(e)}")
            return f"Error during chunk analysis: {str(e)}"

    def _process_functions(self, file_path: str, data: Dict, vuln_vector: List[float], 
                          threshold: float, results: List[Tuple[str, float]]) -> None:
        """
        Process functions in a file

        Args:
            file_path: Path to the file to process
            data: Data to process
        """
        if 'functions' not in data:
            return
            
        for func_id, func_data in data['functions'].items():
            if not func_data.get('embedding'):
                continue
                
            try:
                similarity = calculate_similarity(vuln_vector, func_data['embedding'])
                if similarity >= threshold:
                    results.append((func_id, similarity))
            except Exception as e:
                logger.exception(f"Error processing function {func_id}: {str(e)}")
                
    def _process_file(self, file_path: str, data: Dict, vuln_vector: List[float], 
                     threshold: float, results: List[Tuple[str, float]]) -> None:
        """
        Process entire file

        Args:
            file_path: Path to the file to process
            data: Data to process
        """
        try:
            # Extract embedding based on its structure
            file_vectors = self._extract_file_vectors(data)
            if not file_vectors:
                return
                
            # For multiple chunks, find the highest similarity
            if isinstance(file_vectors, list) and isinstance(file_vectors[0], list):
                highest_similarity = max(calculate_similarity(vuln_vector, vec) for vec in file_vectors)
                if highest_similarity >= threshold:
                    results.append((file_path, highest_similarity))
            else:
                # Single vector
                similarity = calculate_similarity(vuln_vector, file_vectors)
                if similarity >= threshold:
                    results.append((file_path, similarity))
        except Exception as e:
            logger.exception(f"Error processing file {file_path}: {str(e)}")
            
    def _extract_file_vectors(self, data: Dict) -> Union[List[float], List[List[float]], None]:
        """
        Extract embedding vectors from file data

        Args:
            data: Data to extract vectors from
        """
        embedding = data.get('embedding')
        if not embedding:
            return None
            
        if isinstance(embedding, dict):
            return embedding.get('embedding')
        elif isinstance(embedding, list) and all(isinstance(item, list) for item in embedding):
            return embedding  # Chunked embeddings
        else:
            return embedding  # Single embedding vector

class EmbeddingAnalyzer:
    """
    Class for analyzing embeddings against vulnerability types

    Args:
        embedding_manager: Initialized EmbeddingManager
    """
    
    def __init__(self, embedding_manager: EmbeddingManager, ollama_manager: OllamaManager):
        """
        Initialize the embedding analyzer
        
        Args:
            embedding_manager: Initialized EmbeddingManager
        """
        self.ollama_manager = ollama_manager
        self.embedding_manager = embedding_manager
        self.code_base = embedding_manager.code_base
        self.embedding_model = embedding_manager.embedding_model
        self.results_cache = {}  # Cache for results by vulnerability type
        self.analyze_type = embedding_manager.analyze_type
        self.analyze_by_function = embedding_manager.analyze_by_function

    def analyze_vulnerability(self, vuln: Dict) -> List[Dict[str, Any]]:
        """
        Analyze a single vulnerability type.

        Args:
            vuln: Vulnerability to analyze
        """

        cache_key = f"{sanitize_name(vuln['name'])}_{self.analyze_type}"
        if cache_key in self.results_cache:
            return self.results_cache[cache_key]

        logger.info(f"🚨 Analyzing vulnerability: {vuln['name']}")

        process_args = self._prepare_analysis_args(vuln)
        results = self._execute_parallel_analysis(process_args)

        results.sort(key=lambda x: x['similarity_score'], reverse=True)
        self.results_cache[cache_key] = results
        return results
    
    def generate_threshold_analysis(self, results: List[Dict], thresholds: List[float] = None) -> List[Dict]:
        """
        Generate threshold analysis for results
        
        Args:
            results: List of result dictionaries
            thresholds: List of thresholds to analyze
            
        Returns:
            List of dictionaries with threshold analysis
        """
        if not thresholds:
            thresholds = EMBEDDING_THRESHOLDS
            
        threshold_analysis = []
        
        total_items = len(results)
        if total_items == 0:
            return []
            
        for threshold in thresholds:
            matching_items = sum(r['similarity_score'] >= threshold for r in results)
            percentage = (matching_items / total_items) * 100
            
            threshold_analysis.append({
                'threshold': threshold,
                'matching_items': matching_items,
                'percentage': percentage
            })
            
        return threshold_analysis
    
    def calculate_statistics(self, results: List[Dict]) -> Dict[str, float]:
        """
        Calculate statistics for results
        
        Args:
            results: List of result dictionaries
            
        Returns:
            Dictionary with statistics
        """
        if not results:
            return {
                'avg_score': 0,
                'median_score': 0,
                'max_score': 0,
                'min_score': 0
            }
            
        scores = [r['similarity_score'] for r in results]
        
        return {
            'avg_score': sum(scores) / len(scores),
            'median_score': sorted(scores)[len(scores)//2],
            'max_score': max(scores),
            'min_score': min(scores),
            'count': len(scores)
        }
    
    def analyze_all_vulnerabilities(self, vulnerabilities: List[Dict], 
                                   thresholds: List[float] = None,
                                   console_output: bool = True) -> Dict[str, Dict]:
        """
        Analyze all vulnerability types
        
        Args:
            vulnerabilities: List of vulnerabilities
            thresholds: List of thresholds
            console_output: Whether to print results to console
            
        Returns:
            Dictionary with results for all vulnerabilities
        """
        all_results = {}

        if console_output:
            logger.info("\nEmbeddings Distribution Analysis")
            logger.info("===================================\n")

        # Analyze each vulnerability
        for vuln in vulnerabilities:
            vuln_name = vuln['name']

            # Get results for this vulnerability
            results = self.analyze_vulnerability(vuln)

            # Generate threshold analysis
            threshold_analysis = self.generate_threshold_analysis(results, thresholds)

            # Calculate statistics
            statistics = self.calculate_statistics(results)

            # Store in all_results
            all_results[vuln_name] = {
                'results': results,
                'threshold_analysis': threshold_analysis,
                'statistics': statistics
            }

            # Console output if requested
            if console_output:
                self._print_vulnerability_analysis(vuln_name, results, threshold_analysis, statistics)

        return all_results

    def generate_vulnerability_statistics(self, all_results: Dict[str, Dict]) -> List[Dict]:
        """
        Generate vulnerability statistics for all results
        
        Args:
            all_results: Dictionary with results for all vulnerabilities
            
        Returns:
            List of dictionaries with vulnerability statistics
        """
        vuln_stats = []
        
        total_high = 0
        total_medium = 0
        total_low = 0
        total_items = 0
        
        for vuln_type, data in all_results.items():
            results = data['results']
            
            high = sum(r['similarity_score'] >= 0.8 for r in results)
            medium = sum(0.6 <= r['similarity_score'] < 0.8 for r in results)
            low = sum(0.4 <= r['similarity_score'] < 0.6 for r in results)
            total = len(results)
            
            total_high += high
            total_medium += medium
            total_low += low
            total_items += total
            
            if total > 0:
                vuln_stats.append({
                    'name': vuln_type,
                    'total': total,
                    'high': high,
                    'medium': medium,
                    'low': low
                })
        
        # Add totals
        vuln_stats.append({
            'name': 'TOTAL',
            'total': total_items,
            'high': total_high,
            'medium': total_medium,
            'low': total_low,
            'is_total': True
        })
        
        return vuln_stats

    def _prepare_analysis_args(self, vuln: Dict) -> list:
        """
        Prepare arguments for parallel processing.

        Args:
            vuln: Dictionary containing vulnerability information
            
        Returns:
            List of processed arguments
        """
        
        # Initialize the list once
        process_args = []

        # Common parameters for all arguments
        common_args = {
            "vulnerability": vuln,
            "embedding_model": self.embedding_model,
            "api_url": self.ollama_manager.api_url
        }
        
        # Process each element based on analysis mode
        for file_path, data in self.code_base.items():
            if self.analyze_by_function:
                if 'functions' in data:
                    # Process each function individually
                    for func_id, func_data in data['functions'].items():
                        if func_data.get('embedding'):
                            args = {
                                "item_id": func_id,
                                "data": func_data,
                                "is_function": True,
                                **common_args
                            }
                            process_args.append(argparse.Namespace(**args))
            elif data.get('embedding'):
                # Process the entire file
                args = {
                    "item_id": file_path,
                    "data": data,
                    "is_function": False,
                    **common_args
                }
                process_args.append(argparse.Namespace(**args))
        
        return process_args

    def _execute_parallel_analysis(self, process_args: list) -> list:
        """
        Execute analysis in parallel and collect results.

        Args:
            process_args: List of processed arguments
            
        Returns:
            List of analysis results
        """

        num_processes = max(1, min(cpu_count(), len(process_args)))
        results = []
        with tqdm(total=len(process_args), desc="Analyzing", leave=True) as pbar:
            with Pool(processes=num_processes) as pool:
                for result in pool.imap(analyze_item_parallel, process_args):
                    if result and 'error' not in result:
                        results.append(result)
                    pbar.update(1)
        return results

    def _print_vulnerability_analysis(self, vuln_name: str, results: List[Dict], 
                                     threshold_analysis: List[Dict], statistics: Dict):
        """
        Print vulnerability analysis to console
        
        Args:
            vuln_name: Name of the vulnerability
            results: List of result dictionaries
            threshold_analysis: List of threshold analysis dictionaries
            statistics: Dictionary with statistics
        """
        logger.info(f"\nAnalyzing: {vuln_name}")
        logger.info("-" * (14 + len(vuln_name)))
        
        # Print threshold analysis
        logger.info("\nThreshold Analysis:")
        logger.info("----------------------")
        for analysis in threshold_analysis:
            threshold = analysis['threshold']
            matching_items = analysis['matching_items']
            percentage = analysis['percentage']
            logger.info(f"Threshold {threshold:.1f}: {matching_items:3d} items ({percentage:5.1f}%)")
        
        # Print top 5 most similar items
        logger.info("\nTop 5 Most Similar Items:")
        logger.info("----------------------------")
        for result in results[:5]:
            score = result['similarity_score']
            item_id = result['item_id']
            logger.info(f"{score:.3f} - {item_id}", extra={'emoji': False})
        
        # Print statistics
        logger.info("\nStatistics:")
        logger.info("--------------")
        logger.info(f"Average similarity: {statistics['avg_score']:.3f}")
        logger.info(f"Median similarity: {statistics['median_score']:.3f}")
        logger.info(f"Max similarity: {statistics['max_score']:.3f}")
        logger.info(f"Min similarity: {statistics['min_score']:.3f}")
        logger.info("")
    
def analyze_item_parallel(args: tuple) -> Dict:
    """
    Parallel processing of embeddings
    
    Args:
        args: Tuple containing analysis arguments
        
    Returns:
        Dict with analysis results
    """
    try:
        # Create a new Ollama client for each process
        client = OllamaManager(args.api_url).get_client()
        
        # Build vulnerability embedding prompt directly
        vuln_data = args.vulnerability
        
        rich_prompt = build_vulnerability_embedding_prompt(vuln_data)

        # Get vulnerability embedding
        vuln_response = client.embeddings(
            model=args.embedding_model,
            prompt=rich_prompt
        )

        if not vuln_response or 'embedding' not in vuln_response:
            return None

        # Get embedding from data
        if args.is_function:
            item_embedding = args.data['embedding']
        elif isinstance(args.data.get('embedding'), dict):
            item_embedding = args.data['embedding'].get('embedding')
        elif isinstance(args.data.get('embedding'), list) and isinstance(args.data['embedding'][0], list):
            # Handle chunked files - use chunk with highest similarity
            chunk_vectors = args.data['embedding']
            similarities = []
            for chunk_vec in chunk_vectors:
                sim = calculate_similarity(vuln_response['embedding'], chunk_vec)
                similarities.append(sim)

            # Return highest similarity
            return (
                {
                    'item_id': args.item_id,
                    'similarity_score': max(similarities),
                    'is_function': args.is_function,
                }
                if similarities
                else None
            )
        else:
            item_embedding = args.data.get('embedding')

        if not item_embedding:
            return None

        # Calculate similarity
        similarity = calculate_similarity(
            vuln_response['embedding'],
            item_embedding
        )

        return {
            'item_id': args.item_id,
            'similarity_score': similarity,
            'is_function': args.is_function
        }

    except Exception as e:
        logger.exception(f"Error analyzing {args.item_id}: {str(e)}")
        return {
            'item_id': args.item_id,
            'error': str(e),
            'is_function': args.is_function
        }
