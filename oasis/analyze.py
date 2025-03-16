from typing import List, Dict, Tuple, Any
from pathlib import Path
from tqdm import tqdm
from multiprocessing import Pool, cpu_count

# Import from configuration
from .config import EXTRACT_FUNCTIONS_ANALYSIS_TYPE, VULNERABILITY_MAPPING, VULNERABILITY_PROMPT_EXTENSION, EMBEDDING_THRESHOLDS, MAX_CHUNK_SIZE

# Import from other modules
from .ollama_manager import OllamaManager
from .tools import chunk_content, logger, calculate_similarity
from .report import Report
from .embedding import EmbeddingManager

class SecurityAnalyzer:
    def __init__(self, llm_model: str, embedding_manager: EmbeddingManager):
        """
        Initialize the security analyzer
        Args:
            llm_model: Model to use for analysis
            embedding_manager: Embedding manager to use for embeddings
        """
        try:
            self.ollama_manager = OllamaManager()
            self.client = self.ollama_manager.get_client()
        except Exception as e:
            logger.error("Failed to initialize Ollama client")
            logger.error("Please make sure Ollama is running and accessible")
            logger.debug(f"Initialization error: {str(e)}")
            raise RuntimeError("Could not connect to Ollama server") from e

        self.llm_model = llm_model
        self.embedding_model = embedding_manager.embedding_model
        self.code_base = embedding_manager.code_base

    def search_vulnerabilities(self, vulnerability_type: str, threshold: float = 0.3, analyze_by_function: bool = False) -> List[Tuple[str, float]]:
        """
        Search for potential vulnerabilities in the code base
        Args:
            vulnerability_type: Type of vulnerability to search for
            threshold: Similarity threshold (default: 0.3)
            analyze_by_function: Whether to analyze by function or file
        Returns:
            List of (identifier, similarity_score) tuples where identifier is either file_path or function_id
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

            # Compare with all files or functions
            results = []

            for file_path, data in self.code_base.items():
                if analyze_by_function:
                    if 'functions' not in data:
                        continue

                    for func_id, func_data in data['functions'].items():
                        try:
                            if not func_data.get('embedding'):
                                continue

                            similarity = calculate_similarity(vuln_vector, func_data['embedding'])
                            if similarity >= threshold:
                                results.append((func_id, similarity))
                        except Exception as e:
                            logger.error(f"Error processing function {func_id}: {str(e)}")
                else:
                    try:
                        # Handle different embedding structures
                        if isinstance(data.get('embedding'), dict):
                            # Extract embedding vector from response if needed
                            file_vector = data['embedding'].get('embedding')
                        elif isinstance(data.get('embedding'), list) and isinstance(data['embedding'][0], list):
                            # Handle chunked files - use the chunk with highest similarity
                            chunk_vectors = data['embedding']
                            highest_similarity = 0
                            for chunk_vec in chunk_vectors:
                                similarity = calculate_similarity(vuln_vector, chunk_vec)
                                highest_similarity = max(highest_similarity, similarity)

                            if highest_similarity >= threshold:
                                results.append((file_path, highest_similarity))
                            continue
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
                        continue

            # Sort by similarity score in descending order
            return sorted(results, key=lambda x: x[1], reverse=True)

        except Exception as e:
            logger.error(f"Error during search: {str(e)}")
            return []

    def analyze_vulnerability(self, file_path: str, vulnerability_type: str) -> str:
        try:
            if file_path not in self.code_base:
                return "File not found in indexed code base"

            code = self.code_base[file_path]['content']            
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
        min_threshold = 0.3
        
        # Store all results for executive summary
        all_results = {}

        # Determine if we're analyzing by function or by file
        analyze_by_function = args.analyze_type == EXTRACT_FUNCTIONS_ANALYSIS_TYPE
        logger.info(f"Analyzing by {args.analyze_type}")

        # Analysis for each vulnerability type
        with tqdm(total=len(vulnerabilities), 
                 desc="Analyzing vulnerabilities", 
                 disable=args.silent) as vuln_pbar:
            for vuln in vulnerabilities:
                # First, find potentially vulnerable files
                results = self.search_vulnerabilities(
                    vuln['name'], 
                    threshold=min_threshold, 
                    analyze_by_function=analyze_by_function
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
                        analysis = self.analyze_vulnerability(file_path, vuln['name'])
                        detailed_results.append({
                            'file_path': file_path,
                            'similarity_score': similarity_score,
                            'analysis': analysis
                        })

                # Store results for executive summary
                all_results[vuln['name']] = detailed_results

                # Generate vulnerability report
                report.generate_vulnerability_report(
                    vulnerability_type=vuln['name'],
                    results=detailed_results,
                    model_name=self.llm_model,
                )

                # Update main progress bar
                vuln_pbar.update(1)
        
        # Generate executive summary after all vulnerabilities are analyzed
        report.generate_executive_summary(all_results, self.llm_model)
        
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

class EmbeddingAnalyzer:
    """Class for analyzing embeddings against vulnerability types"""
    
    def __init__(self, embedding_manager):
        """
        Initialize the embedding analyzer
        
        Args:
            embedding_manager: Initialized EmbeddingManager
        """
        self.ollama_manager = OllamaManager()
        self.embedding_manager = embedding_manager
        self.code_base = embedding_manager.code_base
        self.embedding_model = embedding_manager.embedding_model
        self.results_cache = {}  # Cache for results by vulnerability type
        
    def analyze_vulnerability(self, vuln_name: str, analyze_by_function: bool = False) -> List[Dict[str, Any]]:
        """
        Analyze a single vulnerability type
        
        Args:
            vuln_name: Name of the vulnerability type
            analyze_by_function: Whether to analyze by function 
            
        Returns:
            List of results (dictionaries with file_path/func_id and similarity_score)
        """
        # Return cached results if available
        cache_key = f"{vuln_name}_{analyze_by_function}"
        if cache_key in self.results_cache:
            return self.results_cache[cache_key]
            
        logger.info(f"Analyzing vulnerability: {vuln_name}")
        
        # Prepare arguments for parallel processing based on analysis type
        process_args = []
        
        if analyze_by_function:
            # Create args for function analysis
            for file_path, data in self.code_base.items():
                if 'functions' not in data:
                    continue
                    
                for func_id, func_data in data['functions'].items():
                    if not func_data.get('embedding'):
                        continue
                        
                    process_args.append(
                        (func_id, func_data, vuln_name, self.embedding_model, True)
                    )
        else:
            # Create args for file analysis
            for file_path, data in self.code_base.items():
                if not data.get('embedding'):
                    continue
                    
                process_args.append(
                    (file_path, data, vuln_name, self.embedding_model, False)
                )
        
        # Calculate optimal number of processes
        num_processes = max(1, min(cpu_count(), len(process_args)))
        
        # Process in parallel with progress bar
        results = []
        with tqdm(total=len(process_args), desc=f"Analyzing {vuln_name}", leave=True) as pbar:
            with Pool(processes=num_processes) as pool:
                for result in pool.imap(analyze_item_parallel, process_args):
                    if result and 'error' not in result:
                        results.append(result)
                    pbar.update(1)
        
        # Sort by similarity score
        results.sort(key=lambda x: x['similarity_score'], reverse=True)
        
        # Cache results for future use
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
    
    def analyze_all_vulnerabilities(self, vulnerability_types: List[Dict], 
                                   thresholds: List[float] = None,
                                   analyze_by_function: bool = False,
                                   console_output: bool = True) -> Dict[str, Dict]:
        """
        Analyze all vulnerability types
        
        Args:
            vulnerability_types: List of vulnerability types
            thresholds: List of thresholds
            analyze_by_function: Whether to analyze by function
            console_output: Whether to print results to console
            
        Returns:
            Dictionary with results for all vulnerabilities
        """
        if not thresholds:
            thresholds = EMBEDDING_THRESHOLDS

        all_results = {}

        if console_output:
            logger.info("\nEmbeddings Distribution Analysis")
            logger.info("================================\n")

        # Analyze each vulnerability type
        for vuln in vulnerability_types:
            vuln_name = vuln['name']

            # Get results for this vulnerability
            results = self.analyze_vulnerability(vuln_name, analyze_by_function)

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
                self._print_vulnerability_analysis(vuln_name, results, threshold_analysis, statistics, thresholds)

        return all_results
    
    def _print_vulnerability_analysis(self, vuln_name: str, results: List[Dict], 
                                     threshold_analysis: List[Dict], statistics: Dict,
                                     thresholds: List[float]):
        """
        Print vulnerability analysis to console
        
        Args:
            vuln_name: Name of the vulnerability
            results: List of result dictionaries
            threshold_analysis: List of threshold analysis dictionaries
            statistics: Dictionary with statistics
            thresholds: List of thresholds
        """
        logger.info(f"\nAnalyzing: {vuln_name}")
        logger.info("-" * (11 + len(vuln_name)))
        
        # Print threshold analysis
        logger.info("\nThreshold Analysis:")
        logger.info("------------------")
        for analysis in threshold_analysis:
            threshold = analysis['threshold']
            matching_items = analysis['matching_items']
            percentage = analysis['percentage']
            logger.info(f"Threshold {threshold:.1f}: {matching_items:3d} items ({percentage:5.1f}%)")
        
        # Print top 5 most similar items
        logger.info("\nTop 5 Most Similar Items:")
        logger.info("------------------------")
        for result in results[:5]:
            score = result['similarity_score']
            item_id = result['item_id']
            logger.info(f"{score:.3f} - {item_id}")
        
        # Print statistics
        logger.info("\nStatistics:")
        logger.info("-----------")
        logger.info(f"Average similarity: {statistics['avg_score']:.3f}")
        logger.info(f"Median similarity: {statistics['median_score']:.3f}")
        logger.info(f"Max similarity: {statistics['max_score']:.3f}")
        logger.info(f"Min similarity: {statistics['min_score']:.3f}")
    
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

def analyze_item_parallel(args: tuple) -> Dict:
    """
    Parallel processing of embeddings
    
    Args:
        args: Tuple of (item_id, data, vulnerability_type, embedding_model, is_function)
        
    Returns:
        Dict with analysis results
    """
    item_id, data, vulnerability_type, embedding_model, is_function = args

    try:
        # Create a new Ollama client for each process
        client = OllamaManager().get_client()

        # Get vulnerability embedding
        vuln_response = client.embeddings(
            model=embedding_model,
            prompt=vulnerability_type
        )

        if not vuln_response or 'embedding' not in vuln_response:
            return None

        # Get embedding from data
        if is_function:
            item_embedding = data['embedding']
        elif isinstance(data.get('embedding'), dict):
            item_embedding = data['embedding'].get('embedding')
        elif isinstance(data.get('embedding'), list) and isinstance(data['embedding'][0], list):
            # Handle chunked files - use chunk with highest similarity
            chunk_vectors = data['embedding']
            similarities = []
            for chunk_vec in chunk_vectors:
                sim = calculate_similarity(vuln_response['embedding'], chunk_vec)
                similarities.append(sim)

            # Return highest similarity
            return (
                {
                    'item_id': item_id,
                    'similarity_score': max(similarities),
                    'is_function': is_function,
                }
                if similarities
                else None
            )
        else:
            item_embedding = data.get('embedding')

        if not item_embedding:
            return None

        # Calculate similarity
        similarity = calculate_similarity(
            vuln_response['embedding'],
            item_embedding
        )

        return {
            'item_id': item_id,
            'similarity_score': similarity,
            'is_function': is_function
        }

    except Exception as e:
        logger.error(f"Error analyzing {item_id}: {str(e)}")
        return {
            'item_id': item_id,
            'error': str(e),
            'is_function': is_function
        }
