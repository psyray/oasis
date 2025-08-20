import argparse
from typing import List, Dict, Tuple, Any, Union
from pathlib import Path
from tqdm import tqdm
from multiprocessing import Pool, cpu_count
import re

# Import from configuration
from .config import CHUNK_ANALYZE_TIMEOUT, MODEL_EMOJIS, VULNERABILITY_PROMPT_EXTENSION, EMBEDDING_THRESHOLDS, MAX_CHUNK_SIZE, DEFAULT_ARGS

# Import from other modules
from .ollama_manager import OllamaManager
from .tools import chunk_content, logger, calculate_similarity, sanitize_name
from .report import Report
from .embedding import EmbeddingManager, build_vulnerability_embedding_prompt
from .cache import CacheManager
from .enums import AnalysisMode, AnalysisType

# Define analysis modes and types
class SecurityAnalyzer:
    def __init__(self, args, llm_model: str, embedding_manager: EmbeddingManager, ollama_manager: OllamaManager,
                 scan_model: str = None):
        """
        Initialize the security analyzer with support for tiered model analysis

        Args:
            args: Command line arguments
            llm_model: Main model to use for deep analysis
            embedding_manager: Embedding manager to use for embeddings
            ollama_manager: Ollama manager for model interactions
            scan_model: Lightweight model for initial scanning (if None, uses llm_model)
        """
        try:
            self.ollama_manager = ollama_manager
            self.client = self.ollama_manager.get_client()
        except Exception as e:
            logger.error("Failed to initialize Ollama client")
            logger.error("Please make sure Ollama is running and accessible")
            logger.exception(f"Initialization error: {str(e)}")
            raise RuntimeError("Could not connect to Ollama server") from e

        # Set up primary (deep) model
        self.llm_model = llm_model
        
        # Set up scanning model (lighter model for initial passes)
        self.scan_model = scan_model or llm_model
        self.ollama_manager.ensure_model_available(self.scan_model)
        logger.info("\n")
        logger.info(f"{MODEL_EMOJIS['default']} Using {self.ollama_manager.get_model_display_name(self.scan_model)} for initial scanning and {self.ollama_manager.get_model_display_name(self.llm_model)} for deep analysis")
        
        self.embedding_manager = embedding_manager
        self.embedding_model = embedding_manager.embedding_model
        self.code_base = embedding_manager.code_base
        self.analyze_type = embedding_manager.analyze_type
        self.analyze_by_function = embedding_manager.analyze_by_function
        self.threshold = embedding_manager.threshold
        
        # Cache parameters
        self.clear_cache_scan = args.clear_cache_scan if hasattr(args, 'clear_cache_scan') else False
        self.cache_days = args.cache_days if hasattr(args, 'cache_days') else DEFAULT_ARGS['CACHE_DAYS']
        
        # Cache for suspicious sections (to avoid re-scanning)
        self.suspicious_sections = {}
        
        # Initialize the cache manager and adaptive analysis pipeline
        self.cache_manager = CacheManager(
            input_path=embedding_manager.input_path,
            llm_model=self.llm_model,
            scan_model=self.scan_model,
            cache_days=self.cache_days
        )
        
        self.analysis_pipeline = AdaptiveAnalysisPipeline(self)

        # Clear scan cache if requested
        if hasattr(self, 'clear_cache_scan') and self.clear_cache_scan:
            analysis_type = AnalysisType.ADAPTIVE if self.analyze_by_function else AnalysisType.STANDARD
            self.cache_manager.clear_scan_cache(analysis_type)
        
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
                               vuln_impact: str, vuln_mitigation: str, chunk_text: str, i: int, total_chunks: int) -> str:
        """
        Construct the prompt for the LLM analysis.
        
        Args:
            vuln_name: Name of the vulnerability
            vuln_desc: Description of the vulnerability
            vuln_patterns: Common patterns associated with the vulnerability
            vuln_impact: Security impact of the vulnerability
            vuln_mitigation: Mitigation strategies for the vulnerability
            chunk_text: Code chunk to analyze
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
        
        # Get common format requirements
        common_prompt = _get_common_prompt(vuln_name)
        
        # Build the complete prompt with clear sections and strict instructions
        return f"""You are a cybersecurityy expert specialized in {vuln_name} vulnerabilities ONLY. 

CRITICAL INSTRUCTION: You must ONLY analyze the code for {vuln_name} vulnerabilities.
DO NOT mention, describe, or analyze ANY other type of vulnerability.
If you find other security issues, IGNORE them completely.

VULNERABILITY DETAILS:
{vuln_info}

CODE SEGMENT TO ANALYZE:
```
{chunk_text}
```

YOUR TASK:
Analyze this code segment ({i + 1}/{total_chunks}) for {vuln_name} vulnerabilities ONLY.

{common_prompt}

{VULNERABILITY_PROMPT_EXTENSION}
"""

    def _analyze_code_chunk(self, prompt: str, file_path: str = None, chunk_text: str = None, 
                           vuln_name: str = None, mode: AnalysisMode = AnalysisMode.DEEP,
                           analysis_type: AnalysisType = AnalysisType.STANDARD) -> str:
        """
        Analyze a single code chunk with the appropriate LLM based on mode.
        
        Args:
            prompt: Prompt to analyze
            file_path: Path to the file being analyzed (for caching)
            chunk_text: The code chunk being analyzed (for caching)
            vuln_name: Vulnerability name (for better organization)
            mode: Analysis mode (scan or deep)
            analysis_type: Analysis type (standard or adaptive)
        """
        # Select the appropriate model
        model = self.scan_model if mode == AnalysisMode.SCAN else self.llm_model

        # Display model name with emoji
        model_display = self.ollama_manager.get_model_display_name(model)

        # If caching info is provided, check appropriate cache first
        if self.cache_manager.has_caching_info(file_path, chunk_text, vuln_name, analysis_type):
            if cached_result := self.cache_manager.get_cached_analysis(file_path, chunk_text, vuln_name, prompt, mode, analysis_type):
                logger.debug(f"Using cached {mode.value} {analysis_type.value} analysis for chunk in {file_path} with {model_display}")
                return cached_result

        try:
            # Add timeout to prevent infinite waiting
            timeout = CHUNK_ANALYZE_TIMEOUT  # Timeout in seconds (2 minutes)

            logger.debug(f"Analyzing chunk with {model_display}")

            # Make the API call with timeout
            response = self.client.chat(
                model=model,
                messages=[{'role': 'user', 'content': prompt}],
                options={"timeout": timeout * 1000}  # Convert to milliseconds if API supports it
            )

            result = response['message']['content']

            # Cache the result if caching info is provided
            if self.cache_manager.has_caching_info(file_path, chunk_text, vuln_name, analysis_type):
                self.cache_manager.store_analysis(file_path, chunk_text, vuln_name, prompt, result, mode, analysis_type)

            return result
        except Exception as e:
            logger.exception(f"Error during chunk analysis with {model_display}: {str(e)}")
            return f"Error during chunk analysis: {str(e)}"

    def _build_scan_prompt(self, vuln_name: str, vuln_desc: str, chunk_text: str) -> str:
        """
        Build a simplified prompt for initial scanning with lightweight models
        
        Args:
            vuln_name: Name of the vulnerability to scan for
            vuln_desc: Brief description of the vulnerability
            chunk_text: Code chunk to analyze
            
        Returns:
            Simplified prompt optimized for lightweight models
        """
        return f"""You are performing a preliminary security scan for {vuln_name} vulnerabilities.
Description of vulnerability: {vuln_desc}

IMPORTANT INSTRUCTIONS:
1. Analyze the code below for ONLY {vuln_name} vulnerabilities
2. DO NOT provide any explanations, details, or reasoning
3. Respond with EXACTLY ONE WORD from these two options:
   - "SUSPICIOUS" if there might be ANY {vuln_name} vulnerabilities
   - "CLEAN" if you're confident there are NO {vuln_name} vulnerabilities

YOUR RESPONSE MUST BE ONLY ONE OF THESE TWO WORDS: "SUSPICIOUS" or "CLEAN"

Code to analyze:
```
{chunk_text}
```
YOUR FINAL ANSWER (MUST BE EXACTLY "SUSPICIOUS" OR "CLEAN"):
"""

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

    def analyze_vulnerability_adaptive(self, file_path: str, vulnerability: Union[str, Dict], threshold: float = 0.7) -> str:
        """
        Analyze a file for a specific vulnerability using an adaptive multi-level approach.
        
        Args:
            file_path: Path to the file to analyze
            vulnerability: Vulnerability to analyze
            threshold: Similarity threshold for filtering
            
        Returns:
            Analysis results as string
        """
        # Delegate to the analysis pipeline
        return self.analysis_pipeline.run(file_path, vulnerability, threshold)

    def process_analysis_with_model(self, vulnerabilities, args, report: Report):
        """
        Process vulnerability analysis with current model using either:
        - Standard two-phase approach (scan + deep analysis)
        - Adaptive multi-level analysis
        
        Args:
            vulnerabilities: List of vulnerability types to analyze
            args: Command line arguments
            report: Report object
            
        Returns:
            Dictionary with analysis results
        """
        # Determine analysis type
        adaptive = hasattr(args, 'adaptive') and args.adaptive
        
        # Select appropriate workflow based on analysis type
        if adaptive:
            all_results = self.analysis_pipeline.perform_adaptive_analysis(vulnerabilities, args, report)
        else:
            all_results = self._perform_standard_analysis(vulnerabilities, args, report)
        
        # Generate final executive summary
        logger.info("GENERATING FINAL REPORT")
        report.generate_executive_summary(all_results, self.llm_model)
        
        return all_results

    def _perform_standard_analysis(self, vulnerabilities, args, report):
        """
        Perform standard two-phase analysis:
        1. Scan all files to identify suspicious chunks
        2. Perform deep analysis on suspicious chunks only
        
        Args:
            vulnerabilities: List of vulnerability types to analyze
            args: Command line arguments
            report: Report object
        
        Returns:
            Dictionary with analysis results
        """
        all_results = {}
        
        # Main progress bar for vulnerabilities
        with tqdm(total=len(vulnerabilities), desc="Overall vulnerability progress", 
                 position=0, leave=True, disable=args.silent) as vuln_pbar:
            
            # Phase 1: Initial scanning of all suspicious files with lightweight model
            suspicious_data = self._perform_initial_scanning(vulnerabilities, args, vuln_pbar)
            
            # Phase 2: Deep analysis of suspicious chunks with the powerful model
            all_results = self._perform_deep_analysis(suspicious_data, args, report, vuln_pbar)
        
        return all_results

    def _perform_initial_scanning(self, vulnerabilities, args, main_pbar=None):
        """
        Perform initial scanning on all files for all vulnerabilities using lightweight model
        
        Args:
            vulnerabilities: List of vulnerability types to analyze
            args: Command-line arguments
            main_pbar: Optional main progress bar to update
            
        Returns:
            Dictionary with suspicious data for later deep analysis
        """
        logger.info("\n")
        logger.info("===== PHASE 1: INITIAL SCANNING =====")
        logger.info(f"Using {self.ollama_manager.get_model_display_name(self.scan_model)} for initial scanning")
        logger.info(f"Analyzing by {self.analyze_type}")

        # Dictionary to store suspicious chunks and related data
        all_suspicious_data = {}

        # First, find potentially vulnerable files for each vulnerability type
        suspicious_files_by_vuln = self._identify_suspicious_files(vulnerabilities, args.threshold)

        # Scan all suspicious files with lightweight model
        logger.debug("\nPerforming initial scan on all suspicious files...")

        # Progress bar for vulnerabilities in initial scan phase
        with tqdm(total=len(suspicious_files_by_vuln), desc="Vulnerabilities analyzed (initial scan)", 
                 position=1, leave=False, disable=args.silent) as vuln_scan_pbar:
            for vuln_name, data in suspicious_files_by_vuln.items():
                vuln = data['vuln_data']
                vuln_details = self._get_vulnerability_details(vuln)
                vuln_name = vuln_details[0]  # Extract name from details tuple
                suspicious_files = data['files']

                # Update main progress bar to show current vulnerability
                if main_pbar:
                    main_pbar.set_postfix_str(f"Scanning: {vuln_name}")

                # Progress bar for files for this vulnerability
                with tqdm(total=len(suspicious_files), desc=f"Scanning files for {vuln_name}", 
                         position=2, leave=False, disable=args.silent) as file_pbar:
                    for file_path, similarity_score in suspicious_files:
                        # Skip files not in code base
                        if file_path not in self.code_base:
                            file_pbar.update(1)
                            continue

                        if suspicious_chunks := self._scan_file_for_vulnerability(
                            file_path, 
                            vuln, 
                            vuln_details,
                            similarity_score,
                            args.silent,
                        ):
                            key = (file_path, vuln_name)
                            all_suspicious_data[key] = {
                                'chunks': suspicious_chunks,
                                'vuln_data': vuln,
                                'similarity_score': similarity_score
                            }

                        file_pbar.update(1)

                vuln_scan_pbar.update(1)
                
                if main_pbar:
                    main_pbar.update(0.5)

        return {
            'suspicious_data': all_suspicious_data,
            'files_by_vuln': suspicious_files_by_vuln
        }
    
    def _scan_file_for_vulnerability(self, file_path, vuln, vuln_details, similarity_score, silent=False):
        """
        Scan a file for a specific vulnerability using lightweight model
        
        Args:
            file_path: Path to the file to scan
            vuln: Vulnerability data
            vuln_details: Extracted vulnerability details tuple
            similarity_score: Similarity score from embedding comparison
            silent: Whether to disable progress bars
            
        Returns:
            List of suspicious chunks in the file
        """
        vuln_name, vuln_desc, _, _, _ = vuln_details
        
        # Get the file content and chunk it
        code = self.code_base[file_path]['content']
        code_chunks = chunk_content(code, MAX_CHUNK_SIZE)
        
        # Initialize suspicious chunks for this file
        suspicious_chunks = []
        
        # Scan each chunk with the lightweight model
        with tqdm(total=len(code_chunks), 
                desc=f"Chunks in {Path(file_path).name}", 
                position=3, leave=False, disable=silent) as chunk_pbar:
            for i, chunk in enumerate(code_chunks):
                # Use a simplified prompt for the scanning phase
                scan_prompt = self._build_scan_prompt(vuln_name, vuln_desc, chunk)
                scan_result = self._analyze_code_chunk(
                    scan_prompt, file_path, chunk, vuln_name, 
                    mode=AnalysisMode.SCAN, 
                    analysis_type=AnalysisType.STANDARD
                )
                
                # Check if chunk is flagged as suspicious
                if scan_result.strip() == "SUSPICIOUS":
                    suspicious_chunks.append((i, chunk))
                    
                chunk_pbar.update(1)
        
        # Store indices for potential future use
        self.suspicious_sections[(file_path, vuln_name)] = [idx for idx, _ in suspicious_chunks]
        
        return suspicious_chunks
    
    def _perform_deep_analysis(self, suspicious_data, args, report, main_pbar=None):
        """
        Perform deep analysis on all suspicious chunks using powerful model
        
        Args:
            suspicious_data: Data from initial scanning phase
            args: Command-line arguments
            report: Report object
            main_pbar: Optional main progress bar to update
            
        Returns:
            Dictionary with analysis results for all vulnerabilities
        """
        logger.info("\n")
        logger.info("===== PHASE 2: DEEP ANALYSIS =====")
        logger.info(f"Using {self.ollama_manager.get_model_display_name(self.llm_model)} for deep analysis")
        
        all_suspicious_chunks = suspicious_data['suspicious_data']
        suspicious_files_by_vuln = suspicious_data['files_by_vuln']
        
        # Dictionary to store results for all vulnerabilities
        all_results = {}
        
        # Process each vulnerability separately for reporting
        with tqdm(total=len(suspicious_files_by_vuln), desc="Vulnerabilities analyzed (deep analysis)", 
                 position=1, leave=False, disable=args.silent) as deep_vuln_pbar:
            for vuln_name, data in suspicious_files_by_vuln.items():
                vuln = data['vuln_data']

                # Update main progress bar before starting the deep analysis
                if main_pbar:
                    main_pbar.set_postfix_str(f"Analyzing: {vuln_name}")
                
                detailed_results = self._analyze_vulnerability_deep(vuln, vuln_name, all_suspicious_chunks, args.silent)
                
                # Store results for this vulnerability
                all_results[vuln_name] = detailed_results
                
                # Generate vulnerability report
                if detailed_results:
                    report.generate_vulnerability_report(
                        vulnerability=vuln,
                        results=detailed_results,
                        model_name=self.llm_model,
                    )
                else:
                    logger.info(f"No suspicious code found for {vuln_name}")
                
                # Update progress bars
                deep_vuln_pbar.update(1)
                if main_pbar:
                    main_pbar.update(0.5)

        return all_results
    
    def _analyze_vulnerability_deep(self, vuln, vuln_name, all_suspicious_chunks, silent=False):
        """
        Perform deep analysis for a specific vulnerability across all files
        
        Args:
            vuln: Vulnerability data
            vuln_name: Name of the vulnerability
            all_suspicious_chunks: Dictionary with suspicious chunks data
            silent: Whether to disable progress bars
            
        Returns:
            List of detailed results for this vulnerability
        """
        deep_results = []

        # Get all files with suspicious chunks for this vulnerability
        suspicious_files = [file_path for (file_path, vname), _ in all_suspicious_chunks.items() 
                          if vname == vuln_name]

        if not suspicious_files:
            logger.info(f"No suspicious chunks found for {vuln_name}")
            return []

        logger.debug(f"\nAnalyzing {len(suspicious_files)} files with suspicious chunks for {vuln_name}")

        # Progress bar for files being analyzed
        with tqdm(total=len(suspicious_files), desc=f"Analyzing files for {vuln_name}", 
                 position=2, leave=False, disable=silent) as file_pbar:
            # Analyze all suspicious files for this vulnerability
            for file_path in suspicious_files:
                key = (file_path, vuln_name)
                suspicious_data = all_suspicious_chunks[key]

                if file_result := self._analyze_file_suspicious_chunks(
                    file_path, suspicious_data, vuln, silent
                ):
                    deep_results.append(file_result)

                file_pbar.update(1)

        return deep_results
    
    def _analyze_file_suspicious_chunks(self, file_path, suspicious_data, vuln, silent=False):
        """
        Analyze suspicious chunks in a specific file for a vulnerability
        
        Args:
            file_path: Path to the file
            suspicious_data: Data about suspicious chunks in this file
            vuln: Vulnerability data
            silent: Whether to disable progress bars
            
        Returns:
            Detailed analysis result for this file
        """
        suspicious_chunks = suspicious_data['chunks']
        similarity_score = suspicious_data['similarity_score']

        vuln_name, vuln_desc, vuln_patterns, vuln_impact, vuln_mitigation = self._get_vulnerability_details(vuln)

        # Perform deep analysis on suspicious chunks
        analyses = []
        with tqdm(total=len(suspicious_chunks), 
                 desc=f"Chunks in {Path(file_path).name}", 
                 position=3, leave=False, disable=silent) as chunk_pbar:
            for chunk_idx, chunk in suspicious_chunks:
                # Build a detailed prompt for deep analysis
                prompt = self._build_analysis_prompt(
                    vuln_name, vuln_desc, vuln_patterns, vuln_impact, vuln_mitigation, 
                    chunk, chunk_idx, len(suspicious_chunks)
                )

                # Analyze with the deep model
                analysis_result = self._analyze_code_chunk(
                    prompt, file_path, chunk, vuln_name, 
                    mode=AnalysisMode.DEEP,
                    analysis_type=AnalysisType.STANDARD
                )
                analyses.append(analysis_result)
                chunk_pbar.update(1)

        # Skip files with no analyses
        if not analyses:
            return None

        # Combine all analyses for this file
        combined_analysis = "\n\n<div class=\"page-break\"></div>\n\n".join(analyses)

        # Create detailed result for this file
        return {
            'file_path': file_path,
            'similarity_score': similarity_score,
            'analysis': combined_analysis,
            'vulnerability': {
                'name': vuln_name,
                'description': vuln_desc,
                'impact': vuln_impact,
                'mitigation': vuln_mitigation
            }
        }
    
    def _identify_suspicious_files(self, vulnerabilities, threshold):
        """
        Identify potentially suspicious files for each vulnerability based on embedding similarity
        
        Args:
            vulnerabilities: List of vulnerability types
            threshold: Similarity threshold for filtering
            
        Returns:
            Dictionary mapping vulnerability names to suspicious files
        """
        suspicious_files_by_vuln = {}
        
        # Progress bar for vulnerability similarity analysis
        with tqdm(total=len(vulnerabilities), desc="Searching for similarities by vulnerability", 
                 position=0, leave=False) as vuln_pbar:
            for vuln in vulnerabilities:
                # Find potentially vulnerable files based on embedding similarity
                results = self.search_vulnerabilities(vuln, threshold=self.threshold)
                filtered_results = [(path, score) for path, score in results if score >= threshold]
                
                logger.debug(f"Found {len(filtered_results)} potentially vulnerable files for {vuln['name']}")
                
                # Store these files for later analysis
                suspicious_files_by_vuln[vuln['name']] = {
                    'files': filtered_results,
                    'vuln_data': vuln
                }
                
                vuln_pbar.update(1)
            
        return suspicious_files_by_vuln

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

    def _process_functions(self, file_path: str, data: Dict, vuln_vector: List[float], 
                          threshold: float, results: List[Tuple[str, float]]) -> None:
        """
        Process functions in a file

        Args:
            file_path: Path to the file to process
            data: Data to process
            vuln_vector: Vulnerability vector to compare against
            threshold: Similarity threshold
            results: List to store results
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
            vuln_vector: Vulnerability vector to compare against
            threshold: Similarity threshold
            results: List to store results
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
            
        Returns:
            Embedding vectors or None if not available
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
        self.embedding_analysis_type = embedding_manager.embedding_analysis_type
        self.analyze_by_function = embedding_manager.analyze_by_function
        self.analyze_type = embedding_manager.analyze_type

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

class AdaptiveAnalysisPipeline:
    """
    Pipeline for adaptive multi-level security analysis
    """
    def __init__(self, analyzer: SecurityAnalyzer):
        """
        Initialize the adaptive analysis pipeline
        
        Args:
            analyzer: SecurityAnalyzer instance with required methods and attributes
        """
        self.analyzer = analyzer
        self.ollama_manager = analyzer.ollama_manager
        self.client = analyzer.client
        self.llm_model = analyzer.llm_model
        self.scan_model = analyzer.scan_model
        self.cache_manager = analyzer.cache_manager
        self.code_base = analyzer.code_base
        
    def run(self, file_path: str, vulnerability: Union[str, Dict], threshold: float = 0.7) -> str:
        """
        Run adaptive analysis on a single file/vulnerability
        
        Args:
            file_path: Path to the file to analyze
            vulnerability: Vulnerability to analyze
            threshold: Similarity threshold for filtering
            
        Returns:
            Analysis results as string
        """
        # Generate analysis task
        task = [(file_path, vulnerability, threshold)]
        
        # Check if we have a batch processor already running
        if not hasattr(self, '_batch_processor'):
            # Create new batch processor
            self._batch_processor = BatchAdaptiveAnalysis(self)
        
        # Submit task to batch processor
        return self._batch_processor.submit_task(task)

    def _static_pattern_analysis(self, code_chunks: List[str], vuln_patterns: List[str]) -> List[Tuple[int, str]]:
        """
        Perform fast pattern-based static analysis on code chunks.
        
        Args:
            code_chunks: List of code chunks
            vuln_patterns: List of vulnerability patterns to look for
            
        Returns:
            List of potentially suspicious chunks with their indices
        """
        suspicious_chunks = []
        
        with tqdm(total=len(code_chunks), desc="Static pattern analysis", leave=False) as pbar:
            for i, chunk in enumerate(code_chunks):
                # Convert all patterns and chunk to lowercase for case-insensitive matching
                chunk_lower = chunk.lower()
                
                # Check for common vulnerability patterns
                # TODO: Add more patterns
                for pattern in vuln_patterns:
                    if pattern and pattern.lower() in chunk_lower:
                        suspicious_chunks.append((i, chunk))
                        break
                
                pbar.update(1)
        
        logger.debug(f"Static analysis identified {len(suspicious_chunks)}/{len(code_chunks)} suspicious chunks")
        return suspicious_chunks
    
    def _lightweight_model_scan(self, file_path: str, code_chunks: List[str], 
                              static_suspicious_chunks: List[Tuple[int, str]], 
                              vuln_name: str, vuln_desc: str) -> List[Tuple[int, str]]:
        """
        Scan code chunks with lightweight model.
        
        Args:
            file_path: Path to the file
            code_chunks: All code chunks
            static_suspicious_chunks: Chunks identified as suspicious by static analysis
            vuln_name: Name of the vulnerability
            vuln_desc: Description of the vulnerability
            
        Returns:
            Updated list of suspicious chunks
        """
        # Create a set of indices of chunks already identified as suspicious
        suspicious_indices = {i for i, _ in static_suspicious_chunks}
        final_suspicious_chunks = static_suspicious_chunks.copy()
        
        # Only scan chunks not already identified as suspicious
        remaining_chunks = [(i, chunk) for i, chunk in enumerate(code_chunks) if i not in suspicious_indices]
        
        with tqdm(total=len(remaining_chunks), desc="Lightweight model scan", leave=False) as pbar:
            for i, chunk in remaining_chunks:
                # Use simplified scan prompt
                scan_prompt = self.analyzer._build_scan_prompt(vuln_name, vuln_desc, chunk)
                scan_result = self.analyzer._analyze_code_chunk(
                    scan_prompt, file_path, chunk, vuln_name, 
                    mode=AnalysisMode.SCAN,
                    analysis_type=AnalysisType.ADAPTIVE
                )
                
                # Add to suspicious chunks if flagged
                if scan_result and scan_result.strip() == "SUSPICIOUS":
                    final_suspicious_chunks.append((i, chunk))
                
                pbar.update(1)
        
        logger.debug(f"After lightweight scan: {len(final_suspicious_chunks)}/{len(code_chunks)} suspicious chunks")
        return final_suspicious_chunks
    
    def _identify_context_sensitive_chunks(self, suspicious_chunks: List[Tuple[int, str]], vuln_name: str) -> List[Tuple[int, str]]:
        """
        Identify chunks that require context-sensitive analysis.
        
        Args:
            suspicious_chunks: List of suspicious chunks from previous analysis levels
            vuln_name: Name of the vulnerability being analyzed
            
        Returns:
            List of chunks that need context-sensitive analysis
        """
        context_sensitive_chunks = []
        
        # Context-sensitive keywords and patterns
        context_patterns = [
            'function', 'def ', 'class ', 'import ', 'require', 
            'parameter', 'argument', 'argv', 'input(',
            'request', 'response', 'query', 'params', 
            'from_user', 'user_input', 'data flow', 'sanitize'
        ]
        
        with tqdm(total=len(suspicious_chunks), desc="Identifying context-sensitive chunks", leave=False) as pbar:
            for chunk_idx, chunk_text in suspicious_chunks:
                chunk_lower = chunk_text.lower()
                
                # Check for context patterns
                for pattern in context_patterns:
                    if pattern in chunk_lower:
                        context_sensitive_chunks.append((chunk_idx, chunk_text))
                        break
                
                pbar.update(1)
        
        logger.debug(f"Identified {len(context_sensitive_chunks)}/{len(suspicious_chunks)} context-sensitive chunks")
        return context_sensitive_chunks
    
    def _medium_model_analysis(self, file_path: str, context_chunks: List[Tuple[int, str]], 
                               vuln_name: str, vuln_desc: str, vuln_patterns: List[str],
                               vuln_impact: str, vuln_mitigation: str) -> List[Dict]:
        """
        Perform medium-depth analysis on context-sensitive chunks.
        
        Args:
            file_path: Path to the file being analyzed
            context_chunks: Context-sensitive chunks to analyze
            vuln_name: Name of the vulnerability
            vuln_desc: Description of the vulnerability
            vuln_patterns: Patterns associated with the vulnerability
            vuln_impact: Impact of the vulnerability
            vuln_mitigation: Mitigation strategies
            
        Returns:
            List of analysis results with risk scores
        """
        results = []

        with tqdm(total=len(context_chunks), desc="Medium-depth analysis", leave=False) as pbar:
            for idx, (chunk_idx, chunk_text) in enumerate(context_chunks):
                # Build a more detailed prompt than the scan prompt, but less detailed than deep analysis
                prompt = f"""You are a security analyst specialized in {vuln_name} vulnerabilities.

VULNERABILITY INFORMATION:
- Name: {vuln_name}
- Description: {vuln_desc}
- Common patterns: {', '.join(vuln_patterns[:3]) if vuln_patterns else 'N/A'}

CODE TO ANALYZE:
```
{chunk_text}
```

INSTRUCTIONS:
1. Analyze this code ONLY for {vuln_name} vulnerabilities
2. Provide a brief analysis (max 3 sentences)
3. Rate the risk level from 0-100 where:
   - 0-25: No risk or very low risk
   - 26-50: Low risk
   - 51-75: Medium risk
   - 76-100: High risk
4. Format your response EXACTLY as follows:
RISK_SCORE: [number]
ANALYSIS: [brief analysis]

DO NOT include any other text in your response.
"""

                # Use the same model as scan but with different prompt
                analysis_result = self.analyzer._analyze_code_chunk(
                    prompt, file_path, chunk_text, vuln_name,
                    mode=AnalysisMode.SCAN,  # Using scan model but with medium-depth prompt
                    analysis_type=AnalysisType.ADAPTIVE
                )

                # Parse the result to extract risk score and analysis
                risk_score = 0
                analysis = ""

                try:
                    # Extract risk score
                    if analysis_result and "RISK_SCORE:" in analysis_result:
                        risk_line = [line for line in analysis_result.split('\n') if "RISK_SCORE:" in line][0]
                        risk_score = int(re.search(r'RISK_SCORE:\s*(\d+)', risk_line)[1])

                    # Extract analysis
                    if analysis_result and "ANALYSIS:" in analysis_result:
                        analysis_line = [line for line in analysis_result.split('\n') if "ANALYSIS:" in line][0]
                        analysis = re.search(r'ANALYSIS:\s*(.*)', analysis_line)[1]
                except Exception as e:
                    logger.warning(f"Error parsing medium analysis result: {str(e)}")
                    risk_score = 50  # Default to medium risk if parsing fails
                    analysis = "Error parsing analysis result"

                results.append({
                    'chunk_idx': chunk_idx,
                    'risk_score': risk_score,
                    'analysis': analysis,
                    'content': chunk_text
                })

                pbar.update(1)

        return results
    
    def _identify_high_risk_chunks(self, suspicious_chunks: List[Tuple[int, str]], 
                               medium_results: List[Dict], risk_threshold: int = 70) -> List[Tuple[int, str]]:
        """
        Identify high-risk chunks that need deep analysis.
        
        Args:
            suspicious_chunks: List of all suspicious chunks
            medium_results: Results from medium-depth analysis
            risk_threshold: Risk score threshold for high-risk classification
            
        Returns:
            List of high-risk chunks
        """
        # Create a mapping from chunk_idx to risk score
        risk_map = {result['chunk_idx']: result['risk_score'] for result in medium_results}
        
        # Select high-risk chunks based on risk threshold
        high_risk_chunks = [
            (chunk_idx, chunk_text) for chunk_idx, chunk_text in suspicious_chunks
            if risk_map.get(chunk_idx, 0) >= risk_threshold
        ]
        
        logger.debug(f"Identified {len(high_risk_chunks)}/{len(suspicious_chunks)} high-risk chunks")
        return high_risk_chunks

    def _deep_model_analysis(self, file_path: str, high_risk_chunks: List[Tuple[int, str]],
                            vuln_name: str, vuln_desc: str, vuln_patterns: List[str],
                            vuln_impact: str, vuln_mitigation: str) -> List[Dict]:
        """
        Perform deep analysis on high-risk chunks.
        
        Args:
            file_path: Path to the file being analyzed
            high_risk_chunks: High-risk chunks to analyze
            vuln_name: Name of the vulnerability
            vuln_desc: Description of the vulnerability
            vuln_patterns: Patterns associated with the vulnerability
            vuln_impact: Impact of the vulnerability
            vuln_mitigation: Mitigation strategies
            
        Returns:
            List of deep analysis results
        """
        deep_results = []
        
        # Get common format requirements
        common_prompt = _get_common_prompt(vuln_name)
        
        with tqdm(total=len(high_risk_chunks), desc="Deep analysis of high-risk chunks", leave=False) as pbar:
            for chunk_idx, chunk_text in high_risk_chunks:
                # Build comprehensive analysis prompt
                prompt = f"""You are a cybersecurity expert specialized in {vuln_name} vulnerabilities ONLY.

VULNERABILITY DETAILS:
- Name: {vuln_name}
- Description: {vuln_desc}
- Common patterns: {', '.join(vuln_patterns) if vuln_patterns else 'N/A'}
- Security impact: {vuln_impact}
- Mitigation: {vuln_mitigation}

CODE SEGMENT TO ANALYZE:

```
{chunk_text}
```

YOUR TASK:
Analyze this code segment for {vuln_name} vulnerabilities ONLY.

{common_prompt}
"""

                # Use deep model for comprehensive analysis
                analysis_result = self.analyzer._analyze_code_chunk(
                    prompt, file_path, chunk_text, vuln_name,
                    mode=AnalysisMode.DEEP,
                    analysis_type=AnalysisType.ADAPTIVE
                )
                
                deep_results.append({
                    'chunk_idx': chunk_idx,
                    'analysis': analysis_result,
                    'content': chunk_text
                })
                
                pbar.update(1)
        
        return deep_results

    def _combine_adaptive_results(self, file_path: str, code_chunks: List[str],
                                suspicious_chunks: List[Tuple[int, str]],
                                medium_results: List[Dict], deep_results: List[Dict]) -> str:
        """
        Combine results from different analysis levels into a comprehensive report.
        
        Args:
            file_path: Path to the file being analyzed
            code_chunks: All code chunks from the file
            suspicious_chunks: All chunks identified as suspicious
            medium_results: Results from medium-depth analysis
            deep_results: Results from deep analysis
            
        Returns:
            Combined analysis results as formatted string
        """
        # Extract all chunk indices
        suspicious_indices = {idx for idx, _ in suspicious_chunks}
        medium_indices = {result['chunk_idx'] for result in medium_results}
        deep_indices = {result['chunk_idx'] for result in deep_results}
        
        # Statistics for summary
        total_chunks = len(code_chunks)
        suspicious_count = len(suspicious_indices)
        medium_analyzed = len(medium_indices)
        deep_analyzed = len(deep_indices)
        
        # Identify vulnerable chunks (those with deep analysis that found vulnerabilities)
        vulnerable_chunks = [
            result for result in deep_results 
            if "No" not in result['analysis'] or "vulnerabilities found" not in result['analysis']
        ]

        # 1. Summary section
        summary = f"""## Adaptive Security Analysis for {Path(file_path).name}

### Analysis Summary:
- **Total code chunks analyzed**: {total_chunks}
- **Suspicious chunks identified**: {suspicious_count} ({(suspicious_count/total_chunks*100):.1f}%)
- **Context-sensitive chunks analyzed**: {medium_analyzed}
- **High-risk chunks deeply analyzed**: {deep_analyzed}
- **Vulnerable chunks found**: {len(vulnerable_chunks)}
"""
        report_parts = [summary]
        
        # 2. Vulnerabilities section (only if vulnerabilities found)
        if vulnerable_chunks:
            report_parts.append("\n## Identified Vulnerabilities\n")

            for i, result in enumerate(vulnerable_chunks):
                chunk_idx = result['chunk_idx']
                analysis = result['analysis']

                section_header = f"### Vulnerability #{i+1} - Chunk {chunk_idx+1}\n"
                report_parts.extend(
                    (
                        section_header + analysis,
                        "\n<div class=\"page-break\"></div>\n",
                    )
                )
        else:
            report_parts.append("\n## No vulnerabilities were found in the deep analysis phase.\n")

        # 3. Combine all parts
        return "\n".join(report_parts)

    def perform_adaptive_analysis(self, vulnerabilities, args, report):
        """
        Perform adaptive multi-level analysis that adjusts depth based on risk
        assessment for each file and vulnerability, optimized for RAM usage
        
        Args:
            vulnerabilities: List of vulnerability types to analyze
            args: Command line arguments
            report: Report object
        
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"Using {self.ollama_manager.get_model_display_name(self.llm_model)} for adaptive analysis")

        all_results = {}

        # Initialize batch processor if not exists
        if not hasattr(self, '_batch_processor'):
            self._batch_processor = BatchAdaptiveAnalysis(self)

        # 1. Collect all vulnerability-file pairs that need analysis
        all_vulnerability_files = {}
        all_tasks = []

        # Main progress bar for vulnerabilities identification
        with tqdm(total=len(vulnerabilities), desc="Identifying vulnerable files", 
                      position=0, leave=True, disable=args.silent) as vuln_pbar:
            
            for vuln in vulnerabilities:
                vuln_name = vuln['name']
                vuln_pbar.set_postfix_str(f"Scanning: {vuln_name}")

                # Find potentially vulnerable files using embeddings
                results = self.analyzer.search_vulnerabilities(vuln, threshold=args.threshold)
                filtered_results = [(path, score) for path, score in results if score >= args.threshold]

                # Skip if no files found
                if not filtered_results:
                    logger.info(f"No files found above threshold for {vuln_name}")
                    vuln_pbar.update(1)
                    continue

                # Store for later use
                all_vulnerability_files[vuln_name] = {
                    'files': filtered_results,
                    'vuln_data': vuln
                }

                # Create batch tasks for these files
                all_tasks.extend(
                    (file_path, vuln, args.threshold)
                    for file_path, _ in filtered_results
                )
                vuln_pbar.update(1)

        # 2. Process all tasks at once with optimized model loading
        if all_tasks:
            logger.info(f"Processing {len(all_tasks)} tasks with optimized model loading")
            self._batch_processor.process_all_tasks_in_batches(all_tasks)

        # 3. Now collect results and organize by vulnerability for reporting
        with tqdm(total=len(all_vulnerability_files), desc="Collecting results", 
                 position=0, leave=True, disable=args.silent) as vuln_pbar:

            for vuln_name, data in all_vulnerability_files.items():
                vuln = data['vuln_data']
                filtered_results = data['files']
                vuln_pbar.set_postfix_str(f"Analyzing: {vuln_name}")

                # Process all files for this vulnerability using adaptive approach
                detailed_results = self._collect_vulnerability_results(filtered_results, vuln)

                # Store results
                all_results[vuln_name] = detailed_results

                # Generate vulnerability report
                if detailed_results:
                    report.generate_vulnerability_report(
                        vulnerability=vuln,
                        results=detailed_results,
                        model_name=self.llm_model,
                    )

                vuln_pbar.update(1)

        return all_results
    
    def _collect_vulnerability_results(self, filtered_results, vuln):
        """
        Collect analysis results for a specific vulnerability
        
        Args:
            filtered_results: List of (file_path, similarity_score) tuples
            vuln: Vulnerability data
            
        Returns:
            List of detailed analysis results
        """
        detailed_results = []
        vuln_name = vuln['name']
        
        # Get the batch processor results
        for file_path, similarity_score in filtered_results:
            result_key = (file_path, vuln_name)
            
            # Get analysis result from batch processor
            analysis = self._batch_processor.get_result(result_key)
            
            if analysis and not analysis.startswith("Error") and not analysis.startswith("No results"):
                # Format the result exactly as _process_files_adaptively did
                detailed_results.append({
                    'file_path': file_path,
                    'similarity_score': similarity_score,
                    'analysis': analysis,
                    'vulnerability': {
                        'name': vuln_name,
                        'description': vuln.get('description', ''),
                        'impact': vuln.get('impact', ''),
                        'mitigation': vuln.get('mitigation', '')
                    }
                })
        
        return detailed_results

class BatchAdaptiveAnalysis:
    """Handles batch processing of adaptive analysis tasks to optimize model loading"""
    
    def __init__(self, pipeline: AdaptiveAnalysisPipeline):
        """
        Initialize batch processor

        Args:
            pipeline: Reference to parent AdaptiveAnalysisPipeline
        """
        self.pipeline = pipeline
        self.analyzer = pipeline.analyzer
        self.ollama_manager = pipeline.ollama_manager
        self.client = pipeline.client
        self.llm_model = pipeline.llm_model
        self.scan_model = pipeline.scan_model
        self.cache_manager = pipeline.cache_manager
        self.code_base = pipeline.code_base
        
        # Accumulated tasks waiting for processing
        self.pending_tasks = []
        
        # Results from processing
        self.results = {}  # Sera modifié pour utiliser (file_path, vuln_name) comme clé
        
        # Analysis data for all tasks
        self.analysis_data = {}
        
        # Flag to track if models have been loaded
        self.models_loaded = {"scan": False, "deep": False}
        
    def submit_task(self, task: List[Tuple[str, str, Any]]):
        """
        Submit a task for batch processing
        
        Args:
            task: Analysis task tuple (file_path, vulnerability, threshold)
            
        Returns:
            Analysis result if already available, or schedules task for processing
        """
        file_path = task[0][0]
        vulnerability = task[0][1]

        # Extract vulnerability name for cache key
        vuln_name, _, _, _, _ = self.analyzer._get_vulnerability_details(vulnerability)

        # Create a composite key (file_path, vuln_name) for results
        result_key = (file_path, vuln_name)

        # Check if we already have the result in memory
        if result_key in self.results:
            return self.results[result_key]

        # Check if results exist in cache
        # We use a placeholder for chunk_text and prompt since adaptive analysis 
        # caches entire file results, not individual chunks
        if self.cache_manager.has_caching_info(file_path, "", vuln_name, AnalysisType.ADAPTIVE):
            if cached_result := self.cache_manager.get_cached_analysis(
                file_path=file_path,
                chunk="",  # Placeholder for chunk
                vuln_name=vuln_name,
                prompt="",  # Placeholder for prompt
                mode=AnalysisMode.DEEP,
                analysis_type=AnalysisType.ADAPTIVE,
            ):
                logger.info(f"Using cached adaptive analysis for {file_path} - {vuln_name}")
                self.results[result_key] = cached_result
                return cached_result

        # Add task to pending tasks if new
        if task not in self.pending_tasks:
            self.pending_tasks.extend(task)

        # Perform initial processing and return result
        self._process_all_tasks()
        return self.results.get(result_key, f"No results for {file_path} - {vuln_name}")
    
    def _process_all_tasks(self):
        """Process all pending tasks with optimized model loading"""
        if not self.pending_tasks:
            return
            
        # 1. Static analysis phase (no model needed)
        self._perform_static_analysis()
        
        # 2. Lightweight and medium analysis phases (scan model)
        self._perform_scan_model_phases()
        
        # 3. Deep analysis phase (llm model)
        self._perform_deep_model_phase()
        
        # 4. Generate final results
        self._generate_final_results()
        
        # Clear pending tasks
        self.pending_tasks = []
        
    def _perform_static_analysis(self):
        """Perform static analysis on all pending tasks (no model needed)"""
        for file_path, vulnerability, threshold in self.pending_tasks:
            try:
                # Extract vulnerability details
                vuln_name, vuln_desc, vuln_patterns, vuln_impact, vuln_mitigation = self.analyzer._get_vulnerability_details(vulnerability)
                analysis_cache_key = f"{sanitize_name(file_path)}_{sanitize_name(vuln_name)}"
                
                # Skip if result already in cache
                if analysis_cache_key in self.cache_manager.adaptive_analysis_cache:
                    self.results[file_path] = self.cache_manager.adaptive_analysis_cache[analysis_cache_key]
                    continue
                    
                # Skip if file not in code base
                if file_path not in self.code_base:
                    self.results[file_path] = "File not found in indexed code base"
                    continue
                
                # Static analysis phase
                code = self.code_base[file_path]['content']
                code_chunks = chunk_content(code, MAX_CHUNK_SIZE)
                
                logger.debug(f"PHASE 1: Static pattern analysis for {file_path} - {vuln_name}")
                suspicious_chunks = self.pipeline._static_pattern_analysis(code_chunks, vuln_patterns)
                
                # Store results for next phases
                self.analysis_data[(file_path, vuln_name)] = {
                    'file_path': file_path,
                    'code_chunks': code_chunks,
                    'suspicious_chunks': suspicious_chunks,
                    'vuln_data': vulnerability,
                    'vuln_details': (vuln_name, vuln_desc, vuln_patterns, vuln_impact, vuln_mitigation),
                    'threshold': threshold,
                    'cache_key': analysis_cache_key,
                    'medium_results': [],
                    'deep_results': [],
                    'context_sensitive_chunks': [],
                    'high_risk_chunks': []
                }
            except Exception as e:
                logger.exception(f"Error during static analysis for {file_path}: {str(e)}")
                self.results[file_path] = f"Error during static analysis: {str(e)}"
    
    def _perform_scan_model_phases(self):
        """Perform all lightweight and medium analyses with scan model"""
        # Filter tasks for scan model
        scan_tasks = [(key, data) for key, data in self.analysis_data.items()
                      if key[0] not in self.results]
        
        if not scan_tasks:
            return
            
        # Only load model once for all scan tasks
        if not self.models_loaded["scan"]:
            logger.debug(f"\nPHASE 2-3: Loading scan model {self.ollama_manager.get_model_display_name(self.scan_model)}")
            self.ollama_manager.ensure_model_available(self.scan_model)
            self.models_loaded["scan"] = True
        
        # PHASE 2: Lightweight scanning for all files/vulnerabilities
        for (file_path, vuln_name), data in scan_tasks:
            try:
                logger.debug(f"PHASE 2: Lightweight model scan for {file_path} - {vuln_name}")
                code_chunks = data['code_chunks']
                suspicious_chunks = data['suspicious_chunks']
                vuln_details = data['vuln_details']
                threshold = data['threshold']
                
                # Only scan if static analysis filtered enough chunks
                if len(suspicious_chunks) < len(code_chunks) * threshold:
                    suspicious_chunks = self.pipeline._lightweight_model_scan(
                        file_path, code_chunks, suspicious_chunks, vuln_details[0], vuln_details[1]
                    )
                    # Update suspicious chunks
                    self.analysis_data[(file_path, vuln_name)]['suspicious_chunks'] = suspicious_chunks
            except Exception as e:
                logger.exception(f"Error during lightweight scan for {file_path}: {str(e)}")
                self.results[file_path] = f"Error during lightweight scan: {str(e)}"
        
        # PHASE 3: Medium-depth analysis for all files/vulnerabilities
        for (file_path, vuln_name), data in scan_tasks:
            if file_path in self.results:
                continue
                
            try:
                logger.debug(f"PHASE 3: Context-sensitive analysis for {file_path} - {vuln_name}")
                suspicious_chunks = data['suspicious_chunks']
                vuln_details = data['vuln_details']
                
                # Identify context-sensitive chunks
                context_sensitive_chunks = self.pipeline._identify_context_sensitive_chunks(suspicious_chunks, vuln_name)
                self.analysis_data[(file_path, vuln_name)]['context_sensitive_chunks'] = context_sensitive_chunks
                
                # Analyze with medium model
                if context_sensitive_chunks:
                    medium_results = self.pipeline._medium_model_analysis(
                        file_path, context_sensitive_chunks, *vuln_details
                    )
                    self.analysis_data[(file_path, vuln_name)]['medium_results'] = medium_results
                    
                    # Identify high-risk chunks for deep analysis
                    high_risk_chunks = self.pipeline._identify_high_risk_chunks(suspicious_chunks, medium_results)
                    self.analysis_data[(file_path, vuln_name)]['high_risk_chunks'] = high_risk_chunks
            except Exception as e:
                logger.exception(f"Error during medium analysis for {file_path}: {str(e)}")
                self.results[file_path] = f"Error during medium analysis: {str(e)}"
    
    def _perform_deep_model_phase(self):
        """Perform all deep analyses with llm model"""
        # Filter tasks for deep model
        deep_tasks = [(key, data) for key, data in self.analysis_data.items()
                     if key[0] not in self.results and data['high_risk_chunks']]
        
        if not deep_tasks:
            return
            
        # Only load model once for all deep tasks
        if not self.models_loaded["deep"]:
            logger.debug(f"\nPHASE 4: Loading deep model {self.ollama_manager.get_model_display_name(self.llm_model)}")
            self.ollama_manager.ensure_model_available(self.llm_model)
            self.models_loaded["deep"] = True
        
        # PHASE 4: Deep analysis for all files/vulnerabilities
        for (file_path, vuln_name), data in deep_tasks:
            try:
                logger.debug(f"PHASE 4: Deep analysis for {file_path} - {vuln_name}")
                high_risk_chunks = data['high_risk_chunks']
                vuln_details = data['vuln_details']
                
                # Deep analysis
                deep_results = self.pipeline._deep_model_analysis(
                    file_path, high_risk_chunks, *vuln_details
                )
                self.analysis_data[(file_path, vuln_name)]['deep_results'] = deep_results
            except Exception as e:
                logger.exception(f"Error during deep analysis for {file_path}: {str(e)}")
                self.results[file_path] = f"Error during deep analysis: {str(e)}"
    
    def _generate_final_results(self):
        """Generate final results for all processed tasks"""
        for (file_path, vuln_name), data in self.analysis_data.items():
            # Create a composite key for results
            result_key = (file_path, vuln_name)
            
            # Skip if result already generated
            if result_key in self.results:
                continue
                
            try:
                # Combine results
                result = self.pipeline._combine_adaptive_results(
                    file_path,
                    data['code_chunks'],
                    data['suspicious_chunks'],
                    data['medium_results'],
                    data['deep_results']
                )
                
                # Store result in memory
                self.results[result_key] = result
                
                # Store result in cache using standard cache methods
                self.cache_manager.store_analysis(
                    file_path=file_path,
                    chunk="",  # Placeholder for chunk
                    vuln_name=vuln_name,
                    prompt="",  # Placeholder for prompt
                    result=result,
                    mode=AnalysisMode.DEEP,
                    analysis_type=AnalysisType.ADAPTIVE
                )
                
                logger.debug(f"Stored adaptive analysis result in cache for {file_path} - {vuln_name}")
                
            except Exception as e:
                logger.exception(f"Error combining results for {file_path} - {vuln_name}: {str(e)}")
                self.results[result_key] = f"Error combining results: {str(e)}"

    def process_all_tasks_in_batches(self, tasks):
        """
        Process all tasks in optimized batches to minimize model loading
        
        Args:
            tasks: List of tasks [(file_path, vulnerability, threshold),...]
        """
        if not tasks:
            return
        
        # Add all tasks to pending queue
        self.pending_tasks = list(tasks)
        
        # Process all tasks together to optimize model loading
        self._process_all_tasks_in_batches()
    
    def get_result(self, result_key):
        """
        Get result for a specific file and vulnerability
        
        Args:
            result_key: Tuple of (file_path, vuln_name)
            
        Returns:
            Analysis result or error message
        """
        return self.results.get(result_key, f"No results for {result_key[0]} - {result_key[1]}")
    
    def _process_all_tasks_in_batches(self):
        """Process all pending tasks with optimized model loading in batches"""
        if not self.pending_tasks:
            return
            
        # 1. Perform static analysis on all tasks (no model needed)
        logger.debug(f"PHASE 1: Performing static pattern analysis for {len(self.pending_tasks)} tasks")
        self._perform_static_analysis_batch()
        
        # 2. Perform lightweight and medium analysis on all tasks with SCAN model
        logger.debug("PHASES 2-3: Processing all tasks with lightweight model")
        self._perform_scan_model_phases_batch()
        
        # 3. Perform deep analysis on all high-risk chunks with DEEP model
        logger.debug("PHASE 4: Processing high-risk chunks with deep model")
        self._perform_deep_model_phase_batch()
        
        # 4. Generate final results for all tasks
        logger.debug("Generating final results for all tasks")
        self._generate_final_results_batch()
    
    def _perform_static_analysis_batch(self):
        """Perform static analysis on all pending tasks in batch (no model needed)"""
        # Initialize cache statistics
        self.cache_stats = {
            "static": {"total": len(self.pending_tasks), "cache_hits": 0},
            "scan": {"total": 0, "cache_hits": 0},
            "deep": {"total": 0, "cache_hits": 0}
        }
        
        with tqdm(total=len(self.pending_tasks), desc="Static analysis", leave=False) as pbar:
            for file_path, vulnerability, threshold in self.pending_tasks:
                try:
                    # Extract vulnerability details
                    vuln_name, vuln_desc, vuln_patterns, vuln_impact, vuln_mitigation = self.analyzer._get_vulnerability_details(vulnerability)

                    # Create a composite key for results
                    result_key = (file_path, vuln_name)

                    # Check for complete cached results and store them, but still perform analysis
                    cached_result = None
                    if self.cache_manager.has_caching_info(file_path, "", vuln_name, AnalysisType.ADAPTIVE):
                        cached_result = self.cache_manager.get_cached_analysis(
                            file_path=file_path,
                            chunk="",
                            vuln_name=vuln_name,
                            prompt="",
                            mode=AnalysisMode.DEEP,
                            analysis_type=AnalysisType.ADAPTIVE,
                        )
                    
                    if cached_result:
                        logger.debug(f"Using cached adaptive analysis for {file_path} - {vuln_name}")
                        self.results[result_key] = cached_result
                        self.cache_stats["static"]["cache_hits"] += 1

                    # Skip if file not in code base
                    if file_path not in self.code_base:
                        if result_key not in self.results:  # Only set if not already set from cache
                            self.results[result_key] = "File not found in indexed code base"
                        pbar.update(1)
                        continue

                    # Static analysis phase - always perform regardless of cache
                    code = self.code_base[file_path]['content']
                    code_chunks = chunk_content(code, MAX_CHUNK_SIZE)

                    suspicious_chunks = self.pipeline._static_pattern_analysis(code_chunks, vuln_patterns)

                    # Store results for next phases
                    self.analysis_data[result_key] = {
                        'file_path': file_path,
                        'code_chunks': code_chunks,
                        'suspicious_chunks': suspicious_chunks,
                        'vuln_data': vulnerability,
                        'vuln_details': (vuln_name, vuln_desc, vuln_patterns, vuln_impact, vuln_mitigation),
                        'threshold': threshold,
                        'medium_results': [],
                        'deep_results': [],
                        'context_sensitive_chunks': [],
                        'high_risk_chunks': [],
                        'has_cached_result': cached_result is not None
                    }

                except Exception as e:
                    logger.exception(f"Error during static analysis for {file_path}: {str(e)}")
                    self.results[(file_path, vuln_name)] = f"Error during static analysis: {str(e)}"

                pbar.update(1)

        logger.info(f"Cache utilization - Static analysis: {self.cache_stats['static']['cache_hits']}/{self.cache_stats['static']['total']} files ({self.cache_stats['static']['cache_hits']/self.cache_stats['static']['total']*100:.1f}%)")
    
    def _perform_scan_model_phases_batch(self):
        """Perform lightweight and medium analysis on all tasks with scan model loaded once"""
        # Process all tasks, regardless of whether they have results in cache
        scan_tasks = self.analysis_data
        
        if not scan_tasks:
            return

        # Load the scan model ONCE for all tasks
        if not self.models_loaded["scan"]:
            logger.info(f"Loading scan model {self.ollama_manager.get_model_display_name(self.scan_model)} for all tasks")
            self.ollama_manager.ensure_model_available(self.scan_model)
            self.models_loaded["scan"] = True

        # PHASE 2: Lightweight scanning for all files/vulnerabilities
        logger.info(f"PHASE 2: Lightweight model scan for {len(scan_tasks)} tasks")
        self.cache_stats["scan"]["total"] = len(scan_tasks)
        
        with tqdm(total=len(scan_tasks), desc="Lightweight scanning", leave=False) as pbar:
            for result_key, data in scan_tasks.items():
                try:
                    file_path, vuln_name = result_key
                    code_chunks = data['code_chunks']
                    suspicious_chunks = data['suspicious_chunks']
                    vuln_details = data['vuln_details']
                    threshold = data['threshold']
                    has_cached_result = data.get('has_cached_result', False)

                    pbar.set_postfix_str(f"File: {Path(file_path).name}, Vuln: {vuln_name}")

                    # If we have a cached result, count it but still perform analysis
                    if has_cached_result:
                        self.cache_stats["scan"]["cache_hits"] += 1
                        logger.debug(f"Using cached result for scan phase: {file_path} - {vuln_name}")

                    # Only scan if static analysis didn't find enough
                    if len(suspicious_chunks) < len(code_chunks) * threshold:
                        suspicious_chunks = self.pipeline._lightweight_model_scan(
                            file_path, code_chunks, suspicious_chunks, vuln_details[0], vuln_details[1]
                        )
                        # Update suspicious chunks
                        self.analysis_data[result_key]['suspicious_chunks'] = suspicious_chunks

                except Exception as e:
                    logger.exception(f"Error during lightweight scan for {file_path} - {vuln_name}: {str(e)}")
                    if result_key not in self.results:  # Only set if not already set from cache
                        self.results[result_key] = f"Error during lightweight scan: {str(e)}"

                pbar.update(1)

        logger.info(f"Cache utilization - Lightweight scan: {self.cache_stats['scan']['cache_hits']}/{self.cache_stats['scan']['total']} files ({self.cache_stats['scan']['cache_hits']/self.cache_stats['scan']['total']*100:.1f}%)")

        # PHASE 3: Medium-depth analysis for all files/vulnerabilities
        logger.info(f"PHASE 3: Context-sensitive analysis for {len(scan_tasks)} tasks")
        
        with tqdm(total=len(scan_tasks), desc="Medium-depth analysis", leave=False) as pbar:
            for result_key, data in scan_tasks.items():
                try:
                    file_path, vuln_name = result_key
                    suspicious_chunks = data['suspicious_chunks']
                    vuln_details = data['vuln_details']
                    has_cached_result = data.get('has_cached_result', False)

                    pbar.set_postfix_str(f"File: {Path(file_path).name}, Vuln: {vuln_name}")

                    # Identify context-sensitive chunks
                    context_sensitive_chunks = self.pipeline._identify_context_sensitive_chunks(suspicious_chunks, vuln_name)
                    self.analysis_data[result_key]['context_sensitive_chunks'] = context_sensitive_chunks

                    # Analyze with medium model
                    if context_sensitive_chunks:
                        medium_results = self.pipeline._medium_model_analysis(
                            file_path, context_sensitive_chunks, *vuln_details
                        )
                        self.analysis_data[result_key]['medium_results'] = medium_results

                        # Identify high-risk chunks for deep analysis
                        high_risk_chunks = self.pipeline._identify_high_risk_chunks(suspicious_chunks, medium_results)
                        self.analysis_data[result_key]['high_risk_chunks'] = high_risk_chunks

                except Exception as e:
                    logger.exception(f"Error during medium analysis for {file_path} - {vuln_name}: {str(e)}")
                    if result_key not in self.results:  # Only set if not already set from cache
                        self.results[result_key] = f"Error during medium analysis: {str(e)}"

                pbar.update(1)
    
    def _perform_deep_model_phase_batch(self):
        """Perform deep analysis on all high-risk chunks with llm model loaded once"""
        # Process all tasks that have high-risk chunks, regardless of cache status
        deep_tasks = {key: data for key, data in self.analysis_data.items() 
                     if data['high_risk_chunks']}
        
        if not deep_tasks:
            logger.info("No high-risk chunks identified for deep analysis")
            return
        
        # Load the deep model ONCE for all tasks
        if not self.models_loaded["deep"]:
            logger.info(f"Loading deep model {self.ollama_manager.get_model_display_name(self.llm_model)} for all tasks")
            self.ollama_manager.ensure_model_available(self.llm_model)
            self.models_loaded["deep"] = True
        
        # PHASE 4: Deep analysis for all high-risk chunks
        logger.info(f"PHASE 4: Deep analysis for {len(deep_tasks)} tasks with high-risk chunks")
        self.cache_stats["deep"]["total"] = len(deep_tasks)
        
        with tqdm(total=len(deep_tasks), desc="Deep analysis", leave=False) as pbar:
            for result_key, data in deep_tasks.items():
                try:
                    file_path, vuln_name = result_key
                    high_risk_chunks = data['high_risk_chunks']
                    vuln_details = data['vuln_details']
                    has_cached_result = data.get('has_cached_result', False)
                    
                    pbar.set_postfix_str(f"File: {Path(file_path).name}, Vuln: {vuln_name}")
                    
                    # If we have a cached result, count it but still perform analysis
                    if has_cached_result:
                        self.cache_stats["deep"]["cache_hits"] += 1
                        logger.debug(f"Using cached result for deep phase: {file_path} - {vuln_name}")
                    
                    # Deep analysis
                    deep_results = self.pipeline._deep_model_analysis(
                        file_path, high_risk_chunks, *vuln_details
                    )
                    self.analysis_data[result_key]['deep_results'] = deep_results
                    
                except Exception as e:
                    logger.exception(f"Error during deep analysis for {file_path} - {vuln_name}: {str(e)}")
                    if result_key not in self.results:  # Only set if not already set from cache
                        self.results[result_key] = f"Error during deep analysis: {str(e)}"
                
                pbar.update(1)
        
        logger.info(f"Cache utilization - Deep analysis: {self.cache_stats['deep']['cache_hits']}/{self.cache_stats['deep']['total']} files ({self.cache_stats['deep']['cache_hits']/self.cache_stats['deep']['total']*100:.1f}%)")
    
    def _generate_final_results_batch(self):
        """Generate final results for all processed tasks"""
        with tqdm(total=len(self.analysis_data), desc="Generating reports", leave=False) as pbar:
            for result_key, data in self.analysis_data.items():
                # Only generate new results if we don't already have them from cache
                if result_key not in self.results:
                    try:
                        file_path, vuln_name = result_key
                        
                        # Combine results using existing method
                        result = self.pipeline._combine_adaptive_results(
                            file_path,
                            data['code_chunks'],
                            data['suspicious_chunks'],
                            data['medium_results'],
                            data['deep_results']
                        )
                        
                        # Store result in memory
                        self.results[result_key] = result
                        
                        # Store in cache
                        self.cache_manager.store_analysis(
                            file_path=file_path,
                            chunk="",  # Placeholder for chunk
                            vuln_name=vuln_name,
                            prompt="",  # Placeholder for prompt
                            result=result,
                            mode=AnalysisMode.DEEP,
                            analysis_type=AnalysisType.ADAPTIVE
                        )
                        
                    except Exception as e:
                        logger.exception(f"Error combining results for {file_path} - {vuln_name}: {str(e)}")
                        self.results[result_key] = f"Error combining results: {str(e)}"
                
                pbar.update(1)
    
    # All existing methods remain intact

def _get_common_prompt(vuln_name: str) -> str:
    """
    Generate common formatting instructions used in different prompts.
    
    Args:
        vuln_name: Name of the vulnerability
        
    Returns:
        Formatting instructions as a string
    """
    return f"""
If you find {vuln_name} vulnerabilities:
1. Quote the exact vulnerable code snippets related ONLY to {vuln_name}
2. Explain specifically how this code is vulnerable to {vuln_name}
3. Provide severity level (Critical/High/Medium/Low) for this {vuln_name} vulnerability
4. Describe the potential impact specific to this {vuln_name} vulnerability
5. Identify the application entry point and execution path:
   - Determine the initial entry point (route, API endpoint, function or method)
   - Create an ASCII flowchart showing the complete execution path from entry point to vulnerability
   - Show all relevant functions/methods called in the execution chain
6. Identify the complete attack/exploitation path:
   - HTTP methods involved (GET, POST, PUT, DELETE)
   - Specific parameters or variables that can be manipulated (form fields, URL parameters, headers)
   - Step-by-step exploitation scenario with example payloads
   - Any dependencies or conditions required for successful exploitation
7. Provide detailed remediation recommendations with secure code examples

FORMAT REQUIREMENTS:
- Use Markdown formatting
- For each {vuln_name} vulnerability found, delimitate clearly the previous section with a "Vulnerability found" title and then the vulnerable code block in a code fence
- DO NOT MENTION any other vulnerability types besides {vuln_name}
- Focus ONLY on {vuln_name} - this is extremely important
- Step-by-step exploitation scenario with example payloads, including precise request methods (e.g., GET, POST) and explicit parameter names (e.g., 'user_id', 'token')
- When providing the ASCII flowchart, make sure to do the following:
  1. Begin with a header "## Execution Path"
  2. Use a properly formatted code block with triple backticks (```) at the beginning AND end
  3. Do not add any other content inside the code block besides the ASCII diagram
  4. Format the ASCII diagram like this:
  ```
  Entry Point: /api/endpoint
       |
       v
  [process_data]
       |
       v
  [validate_input]
       |
       v
  [parse_user_data] <-- Vulnerable Function
  ```
  5. After the closing triple backticks, continue with the next section
"""
