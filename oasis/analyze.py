import argparse
from typing import List, Dict, Tuple, Any, Union
from pathlib import Path
from tqdm import tqdm
from multiprocessing import Pool, cpu_count
import pickle
import hashlib
from enum import Enum

# Import from configuration
from .config import CHUNK_ANALYZE_TIMEOUT, VULNERABILITY_PROMPT_EXTENSION, EMBEDDING_THRESHOLDS, MAX_CHUNK_SIZE, DEFAULT_ARGS, ANALYSIS_VERSION

# Import from other modules
from .ollama_manager import OllamaManager
from .tools import chunk_content, logger, calculate_similarity, sanitize_name
from .report import Report
from .embedding import EmbeddingManager, build_vulnerability_embedding_prompt

# Define analysis modes and types
class AnalysisMode(Enum):
    SCAN = "scan"  # Lightweight scanning mode
    DEEP = "deep"  # Deep analysis mode

class AnalysisType(Enum):
    STANDARD = "standard"  # Standard two-phase analysis
    ADAPTIVE = "adaptive"  # Multi-level adaptive analysis

class SecurityAnalyzer:
    def __init__(self, llm_model: str, embedding_manager: EmbeddingManager, ollama_manager: OllamaManager,
                 scan_model: str = None):
        """
        Initialize the security analyzer with support for tiered model analysis

        Args:
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
        logger.info(f"Using {self.ollama_manager.get_model_display_name(self.scan_model)} for initial scanning and {self.ollama_manager.get_model_display_name(self.llm_model)} for deep analysis")
        
        self.embedding_manager = embedding_manager
        self.embedding_model = embedding_manager.embedding_model
        self.code_base = embedding_manager.code_base
        self.analyze_type = embedding_manager.analyze_type
        self.analyze_by_function = embedding_manager.analyze_by_function
        self.threshold = embedding_manager.threshold
        
        # Cache for suspicious sections (to avoid re-scanning)
        self.suspicious_sections = {}
        
        # Initialize chunk cache
        self._initialize_chunk_cache()

    def _initialize_chunk_cache(self):
        """
        Initialize the chunk cache system with support for multiple models and analysis types
        """
        # Create base cache directory
        input_path = Path(self.embedding_manager.input_path)
        if input_path.is_dir():
            self.cache_dir = input_path.parent / '.oasis_cache'
        else:
            self.cache_dir = input_path.parent / '.oasis_cache'
            
        self.cache_dir.mkdir(exist_ok=True)
        
        # Create model-specific cache directories
        self.model_cache_dir = self.cache_dir / sanitize_name(self.llm_model)
        self.model_cache_dir.mkdir(exist_ok=True)
        
        # Create scan model cache directory if different from main model
        if self.scan_model != self.llm_model:
            self.scan_model_cache_dir = self.cache_dir / sanitize_name(self.scan_model)
            self.scan_model_cache_dir.mkdir(exist_ok=True)
        else:
            self.scan_model_cache_dir = self.model_cache_dir
        
        # Create analysis type subdirectories for both models
        self.standard_cache_dir = {
            AnalysisMode.DEEP: self.model_cache_dir / AnalysisType.STANDARD.value,
            AnalysisMode.SCAN: self.scan_model_cache_dir / AnalysisType.STANDARD.value
        }
        
        self.adaptive_cache_dir = {
            AnalysisMode.DEEP: self.model_cache_dir / AnalysisType.ADAPTIVE.value,
            AnalysisMode.SCAN: self.scan_model_cache_dir / AnalysisType.ADAPTIVE.value
        }
        
        # Create all required directories
        for directory in list(self.standard_cache_dir.values()) + list(self.adaptive_cache_dir.values()):
            directory.mkdir(exist_ok=True)
        
        # Initialize cache dictionaries for current session
        self.chunk_cache = {
            AnalysisType.STANDARD: {},
            AnalysisType.ADAPTIVE: {}
        }
        self.scan_chunk_cache = {
            AnalysisType.STANDARD: {},
            AnalysisType.ADAPTIVE: {}
        }
        
        # Initialize adaptive cache for storing intermediate results
        self.adaptive_analysis_cache = {}

    def _get_chunk_cache_path(self, file_path: str, mode: AnalysisMode = AnalysisMode.DEEP, 
                             analysis_type: AnalysisType = AnalysisType.STANDARD) -> Path:
        """
        Get the path to the chunk cache file for a specific analyzed file

        Args:
            file_path: Path to the analyzed file
            mode: Analysis mode (scan or deep)
            analysis_type: Analysis type (standard or adaptive)
            
        Returns:
            Path object to the cache file
        """
        sanitized_file_name = sanitize_name(file_path)

        if analysis_type == AnalysisType.STANDARD:
            return self.standard_cache_dir[mode] / f"{sanitized_file_name}.cache"
        else:
            return self.adaptive_cache_dir[mode] / f"{sanitized_file_name}.cache"

    def _get_cache_dict(self, mode: AnalysisMode, analysis_type: AnalysisType = AnalysisType.STANDARD):
        """
        Get the appropriate cache dictionary based on analysis mode and type
        
        Args:
            mode: Analysis mode (scan or deep)
            analysis_type: Analysis type (standard or adaptive)
            
        Returns:
            Appropriate cache dictionary
        """
        if mode == AnalysisMode.SCAN:
            return self.scan_chunk_cache[analysis_type]
        else:
            return self.chunk_cache[analysis_type]

    def _process_cache(self, action: str, file_path: str, mode: AnalysisMode, 
                      analysis_type: AnalysisType = AnalysisType.STANDARD):
        """
        Process cache operations (load or save)
        
        Args:
            action: Action to perform ('load' or 'save')
            file_path: Path to the file
            mode: Analysis mode (scan or deep)
            analysis_type: Analysis type (standard or adaptive)
        
        Returns:
            For 'load' action, returns the loaded cache
            For 'save' action, returns None
        """
        cache_path = self._get_chunk_cache_path(file_path, mode, analysis_type)
        cache_dict = self._get_cache_dict(mode, analysis_type)
        
        if action == 'load':
            if file_path in cache_dict:
                return cache_dict[file_path]
            
            if not cache_path.exists():
                cache_dict[file_path] = {}
                return {}
            
            try:
                with open(cache_path, 'rb') as f:
                    cache_dict[file_path] = pickle.load(f)
                    logger.debug(f"Loaded {mode.value} {analysis_type.value} chunk cache for {file_path}: {len(cache_dict[file_path])} entries")
                    return cache_dict[file_path]
            except Exception as e:
                logger.exception(f"Error loading {mode.value} {analysis_type.value} chunk cache: {str(e)}")
                cache_dict[file_path] = {}
                return {}
        
        elif action == 'save':
            if file_path not in cache_dict:
                return
            
            try:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                with open(cache_path, 'wb') as f:
                    pickle.dump(cache_dict[file_path], f)
                    logger.debug(f"Saved {mode.value} {analysis_type.value} chunk cache for {file_path}: {len(cache_dict[file_path])} entries")
            except Exception as e:
                logger.exception(f"Error saving {mode.value} {analysis_type.value} chunk cache: {str(e)}")

    def _load_specific_chunk_cache(self, file_path: str, mode: AnalysisMode = AnalysisMode.DEEP,
                                 analysis_type: AnalysisType = AnalysisType.STANDARD) -> Dict:
        """
        Load appropriate chunk cache for a specific file based on mode and analysis type
        
        Args:
            file_path: Path to the file
            mode: Analysis mode (scan or deep)
            analysis_type: Analysis type (standard or adaptive)
            
        Returns:
            Dictionary with cached analysis results
        """
        return self._process_cache('load', file_path, mode, analysis_type)
            
    def _save_specific_chunk_cache(self, file_path: str, mode: AnalysisMode = AnalysisMode.DEEP,
                                 analysis_type: AnalysisType = AnalysisType.STANDARD):
        """
        Save appropriate chunk cache for a specific file based on mode and analysis type
        
        Args:
            file_path: Path to the file
            mode: Analysis mode (scan or deep)
            analysis_type: Analysis type (standard or adaptive)
        """
        self._process_cache('save', file_path, mode, analysis_type)

    def _has_caching_info(self, file_path: str, chunk: str, vuln_name: str) -> bool:
        """
        Check if all necessary information for caching is provided
        
        Args:
            file_path: Path to the file being analyzed
            chunk: Code chunk content
            vuln_name: Vulnerability name
            
        Returns:
            True if all info is provided, False otherwise
        """
        return file_path is not None and chunk is not None and vuln_name is not None

    def _get_cached_analysis(self, file_path: str, chunk: str, vuln_name: str, prompt: str, 
                           mode: AnalysisMode = AnalysisMode.DEEP,
                           analysis_type: AnalysisType = AnalysisType.STANDARD) -> str:
        """
        Check if analysis for a chunk is already cached
        
        Args:
            file_path: Path to the file
            chunk: Code chunk content
            vuln_name: Vulnerability name (for better organization)
            prompt: Complete analysis prompt (to detect changes in prompt structure)
            mode: Analysis mode (scan or deep)
            analysis_type: Analysis type (standard or adaptive)
            
        Returns:
            Cached analysis result or None if not found
        """
        # Load cache for this file if not already loaded
        cache_dict = self._get_cache_dict(mode, analysis_type)
        if file_path not in cache_dict:
            self._load_specific_chunk_cache(file_path, mode, analysis_type)
        
        chunk_key = self._generate_cache_key(chunk, prompt, vuln_name)
        
        # Check if analysis exists in cache
        return cache_dict[file_path].get(chunk_key)

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

    def analyze_vulnerability(self, file_path: str, vulnerability: Union[str, Dict], adaptive: bool = False) -> str:
        """
        Analyze a file for a specific vulnerability.
        
        Args:
            file_path: Path to the file to analyze
            vulnerability: Vulnerability to analyze
            adaptive: Whether to use adaptive analysis or standard two-phase approach
            
        Returns:
            Analysis results as string
        """
        if adaptive:
            return self.analyze_vulnerability_adaptive(file_path, vulnerability)
        
        try:
            if file_path not in self.code_base:
                return "File not found in indexed code base"

            vuln_name, vuln_desc, vuln_patterns, vuln_impact, vuln_mitigation = self._get_vulnerability_details(vulnerability)
            if not vuln_name:  # Check if vulnerability details extraction failed
                return "Invalid vulnerability type"

            code = self.code_base[file_path]['content']
            code_chunks = chunk_content(code, MAX_CHUNK_SIZE)

            # Phase 1: Quick scan with lightweight model
            suspicious_chunks = []
            with tqdm(total=len(code_chunks), 
                    desc=f"Initial scanning of {Path(file_path).name}", 
                    leave=False) as chunk_pbar:
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
                    chunk_pbar.set_postfix_str(f"Chunk {i+1}/{len(code_chunks)}")
                    
            # Store results for potential future use
            self.suspicious_sections[(file_path, vuln_name)] = [idx for idx, _ in suspicious_chunks]
            
            if not suspicious_chunks:
                return f"No {vuln_name} vulnerabilities found in initial scan. File appears to be clean."

            # Phase 2: Deep analysis of suspicious chunks only
            logger.info(f"Found {len(suspicious_chunks)} suspicious chunks, performing deep analysis")
            
            analyses = []
            with tqdm(total=len(suspicious_chunks), 
                    desc=f"Deep analysis of {Path(file_path).name}", 
                    leave=False) as chunk_pbar:
                for i, (chunk_idx, chunk) in enumerate(suspicious_chunks):
                    # Use the full detailed prompt for the deep analysis phase
                    prompt = self._build_analysis_prompt(
                        vuln_name, vuln_desc, vuln_patterns, vuln_impact, vuln_mitigation, 
                        chunk, chunk_idx, len(code_chunks)
                    )
                    analysis_result = self._analyze_code_chunk(
                        prompt, file_path, chunk, vuln_name, 
                        mode=AnalysisMode.DEEP,
                        analysis_type=AnalysisType.STANDARD
                    )
                    analyses.append(analysis_result)
                    chunk_pbar.update(1)
                    chunk_pbar.set_postfix_str(f"Chunk {i+1}/{len(suspicious_chunks)}")

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
                        # Use adaptive analysis if requested via argument
                        analysis = self.analyze_vulnerability(
                            file_path, 
                            vuln, 
                            adaptive=args.adaptive
                        )
                        
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
        
        # Build the complete prompt with clear sections and strict instructions
        return f"""You are a cybersecurityy expert specialized in {vuln_name} vulnerabilities ONLY. 

CRITICAL INSTRUCTION: You must ONLY analyze the code for {vuln_name} vulnerabilities.
DO NOT mention, describe, or analyze ANY other type of vulnerability.
If you find other security issues, IGNORE them completely.

VULNERABILITY DETAILS:
{vuln_info}

CODE SEGMENT TO ANALYZE:
```
{chunk}
```

YOUR TASK:
Analyze this code segment ({i + 1}/{total_chunks}) for {vuln_name} vulnerabilities ONLY.

If you find {vuln_name} vulnerabilities:
1. Quote the exact vulnerable code snippets related ONLY to {vuln_name}
2. Explain specifically how this code is vulnerable to {vuln_name}
3. Provide severity level (Critical/High/Medium/Low) for this {vuln_name} vulnerability
4. Describe the potential impact specific to this {vuln_name} vulnerability
5. Provide remediation recommendations with secure code examples

If NO {vuln_name} vulnerabilities are found, respond with ONLY:
"No {vuln_name} vulnerabilities found in this segment."

FORMAT REQUIREMENTS:
- Use Markdown formatting
- For each {vuln_name} vulnerability found, start with the vulnerable code block in a code fence
- DO NOT MENTION any other vulnerability types besides {vuln_name}
- Focus ONLY on {vuln_name} - this is extremely important

{VULNERABILITY_PROMPT_EXTENSION}
"""

    def _analyze_code_chunk(self, prompt: str, file_path: str = None, chunk: str = None, 
                           vuln_name: str = None, mode: AnalysisMode = AnalysisMode.DEEP,
                           analysis_type: AnalysisType = AnalysisType.STANDARD) -> str:
        """
        Analyze a single code chunk with the appropriate LLM based on mode.

        Args:
            prompt: Prompt to analyze
            file_path: Path to the file being analyzed (for caching)
            chunk: The code chunk being analyzed (for caching)
            vuln_name: Vulnerability name (for better organization)
            mode: Analysis mode (scan or deep)
            analysis_type: Analysis type (standard or adaptive)
        """
        # Select the appropriate model and cache
        model = self.scan_model if mode == AnalysisMode.SCAN else self.llm_model
        cache_dict = self._get_cache_dict(mode, analysis_type)

        # Display model name with emoji
        model_display = self.ollama_manager.get_model_display_name(model)

        # If caching info is provided, check appropriate cache first
        if self._has_caching_info(file_path, chunk, vuln_name):
            # Load cache for this file if not already loaded
            if file_path not in cache_dict:
                self._load_specific_chunk_cache(file_path, mode, analysis_type)

            chunk_key = self._generate_cache_key(chunk, prompt, vuln_name)
            if cached_result := cache_dict.get(file_path, {}).get(chunk_key):
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
            if self._has_caching_info(file_path, chunk, vuln_name):
                if file_path not in cache_dict:
                    cache_dict[file_path] = {}

                chunk_key = self._generate_cache_key(chunk, prompt, vuln_name)
                cache_dict[file_path][chunk_key] = result

                # Save cache after each analysis to allow resuming at any point
                self._save_specific_chunk_cache(file_path, mode, analysis_type)

            return result
        except Exception as e:
            logger.exception(f"Error during chunk analysis with {model_display}: {str(e)}")
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

    def _generate_cache_key(self, chunk: str, prompt: str, vuln_name: str):
        """Generate a robust cache key that takes all factors into account"""
        # Factors that could affect the analysis
        factors = {
            'chunk_content': chunk,
            'chunk_length': len(chunk),
            'prompt': prompt,
            'vuln_name': vuln_name,
            'analysis_version': self._get_analysis_version(),
        }
        
        # Composite hash
        composite_string = ":".join([str(v) for k, v in sorted(factors.items())])
        return hashlib.sha256(composite_string.encode('utf-8')).hexdigest()

    def _get_analysis_version(self):
        """
        Return the version of the analysis algorithm, which determines cache compatibility.
        This constant must be incremented manually ONLY when the analysis behavior changes in a way that would make cached results obsolete.
        """
        return ANALYSIS_VERSION

    def _build_scan_prompt(self, vuln_name: str, vuln_desc: str, chunk: str) -> str:
        """
        Build a simplified prompt for initial scanning with lightweight models
        
        Args:
            vuln_name: Name of the vulnerability to scan for
            vuln_desc: Brief description of the vulnerability
            chunk: Code chunk to analyze
            
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
{chunk}
```
YOUR FINAL ANSWER (MUST BE EXACTLY "SUSPICIOUS" OR "CLEAN"):
"""

    def analyze_vulnerability_adaptive(self, file_path: str, vulnerability: Union[str, Dict]) -> str:
        """
        Analyze a file for a specific vulnerability using an adaptive multi-level approach.
        
        Args:
            file_path: Path to the file to analyze
            vulnerability: Vulnerability to analyze
            
        Returns:
            Analysis results as string
        """
        try:
            if file_path not in self.code_base:
                return "File not found in indexed code base"

            vuln_name, vuln_desc, vuln_patterns, vuln_impact, vuln_mitigation = self._get_vulnerability_details(vulnerability)
            if not vuln_name:
                return "Invalid vulnerability type"

            # Generate cache key for this analysis
            analysis_cache_key = f"{file_path}_{vuln_name}"
            
            # Check if we have already analyzed this file/vulnerability combination
            if analysis_cache_key in self.adaptive_analysis_cache:
                logger.info(f"Using cached adaptive analysis for {file_path} - {vuln_name}")
                return self.adaptive_analysis_cache[analysis_cache_key]

            code = self.code_base[file_path]['content']
            code_chunks = chunk_content(code, MAX_CHUNK_SIZE)
            
            # LEVEL 1: Pattern-based static analysis (fastest)
            suspicious_chunks = self._static_pattern_analysis(code_chunks, vuln_patterns)
            
            # LEVEL 2: Lightweight model scan (fast)
            if len(suspicious_chunks) < len(code_chunks) * 0.7:  # Only if static analysis filtered some chunks
                # Analyze remaining chunks with lightweight model
                suspicious_chunks = self._lightweight_model_scan(
                    file_path, code_chunks, suspicious_chunks, vuln_name, vuln_desc
                )
            
            # LEVEL 3: Medium-depth analysis for context-sensitive chunks
            context_specific_chunks = self._identify_context_sensitive_chunks(suspicious_chunks, vuln_name)
            
            # Analyze context-sensitive chunks with medium model
            medium_results = self._medium_model_analysis(
                file_path, context_specific_chunks, vuln_name, vuln_desc, vuln_patterns, vuln_impact, vuln_mitigation
            )
            
            # LEVEL 4: Deep analysis only for highly suspicious chunks
            high_risk_chunks = self._identify_high_risk_chunks(suspicious_chunks, medium_results)
            
            # Analyze high-risk chunks with powerful model
            deep_results = self._deep_model_analysis(
                file_path, high_risk_chunks, vuln_name, vuln_desc, vuln_patterns, vuln_impact, vuln_mitigation
            )
            
            # Combine results from different levels
            result = self._combine_adaptive_results(
                file_path, code_chunks, suspicious_chunks, medium_results, deep_results
            )
            
            # Cache the final result
            self.adaptive_analysis_cache[analysis_cache_key] = result
            
            return result
            
        except Exception as e:
            logger.exception(f"Error during adaptive vulnerability analysis: {str(e)}")
            return f"Error during analysis: {str(e)}"

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
                for pattern in vuln_patterns:
                    if pattern.lower() in chunk_lower:
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
                scan_prompt = self._build_scan_prompt(vuln_name, vuln_desc, chunk)
                scan_result = self._analyze_code_chunk(
                    scan_prompt, file_path, chunk, vuln_name, 
                    mode=AnalysisMode.SCAN,
                    analysis_type=AnalysisType.ADAPTIVE
                )
                
                # Add to suspicious chunks if flagged
                if scan_result.strip() == "SUSPICIOUS":
                    final_suspicious_chunks.append((i, chunk))
                
                pbar.update(1)
        
        logger.debug(f"After lightweight scan: {len(final_suspicious_chunks)}/{len(code_chunks)} suspicious chunks")
        return final_suspicious_chunks

    def _identify_context_sensitive_chunks(self, suspicious_chunks: List[Tuple[int, str]], vuln_name: str) -> List[Tuple[int, str]]:
        """
        Identify chunks that require more context-sensitive analysis based on vulnerability type.
        
        Args:
            suspicious_chunks: List of suspicious chunks
            vuln_name: Name of the vulnerability
            
        Returns:
            List of chunks requiring context-sensitive analysis
        """
        # Different vulnerabilities require different levels of context sensitivity
        context_sensitivity = {
            'SQL Injection': 0.8,       # High - needs data flow analysis
            'XSS': 0.7,                 # High - needs output context
            'CSRF': 0.9,                # Very high - needs session context
            'Path Traversal': 0.6,      # Medium - needs file operations
            'SSRF': 0.7,                # High - needs network calls context
            'XXE': 0.8,                 # High - needs XML processing context
            'IDOR': 0.9,                # Very high - needs access control context
            'RCE': 0.9,                 # Very high - needs command execution context
            'Authentication Issues': 0.8, # High - needs auth flow context
            'Sensitive Data Exposure': 0.5, # Medium - more pattern-based
            'Insecure Cryptographic Usage': 0.6, # Medium - mostly API usage patterns
        }
        
        # Default sensitivity if vulnerability not in the list
        default_sensitivity = 0.7
        sensitivity = context_sensitivity.get(vuln_name, default_sensitivity)
        
        # Select chunks based on sensitivity threshold
        # Higher sensitivity means more chunks will be selected for deeper analysis
        selected_count = max(1, int(len(suspicious_chunks) * sensitivity))
        return suspicious_chunks[:selected_count]

    def _medium_model_analysis(self, file_path: str, context_chunks: List[Tuple[int, str]], 
                             vuln_name: str, vuln_desc: str, vuln_patterns: List[str],
                             vuln_impact: str, vuln_mitigation: str) -> Dict[int, Dict]:
        """
        Analyze context-sensitive chunks with medium-depth model.
        
        Args:
            file_path: Path to the file
            context_chunks: Chunks requiring context-sensitive analysis
            vuln_name, vuln_desc, etc.: Vulnerability details
            
        Returns:
            Dictionary mapping chunk indices to analysis results
        """
        results = {}
        
        # Define a simplified prompt for medium analysis (less detailed than full analysis)
        medium_prompt_template = """You are a security expert analyzing code for {vuln_name} vulnerabilities.
Focus ONLY on {vuln_name} and analyze this code segment carefully.

Vulnerability details:
- Description: {vuln_desc}
- Common patterns: {patterns}

Code to analyze:
```
{chunk}
```

Provide a brief analysis:
1. Is this code vulnerable to {vuln_name}? (Yes/No)
2. If yes, briefly explain why and rate the severity (Low/Medium/High/Critical)
3. Do NOT analyze other vulnerability types
"""
    
        with tqdm(total=len(context_chunks), desc="Medium-depth analysis", leave=False) as pbar:
            for i, chunk in context_chunks:
                patterns_str = ", ".join(vuln_patterns[:3]) if vuln_patterns else "N/A"
                
                medium_prompt = medium_prompt_template.format(
                    vuln_name=vuln_name,
                    vuln_desc=vuln_desc,
                    patterns=patterns_str,
                    chunk=chunk
                )
                
                # Analyze with medium settings
                result = self._analyze_code_chunk(
                    medium_prompt, file_path, chunk, vuln_name, 
                    mode=AnalysisMode.SCAN,
                    analysis_type=AnalysisType.ADAPTIVE
                )
                
                # Store result
                results[i] = {
                    'result': result,
                    'is_vulnerable': 'yes' in result.lower() and 'no ' not in result.lower()[:3],  # Quick check
                    'severity': self._extract_severity_from_result(result)
                }
                
                pbar.update(1)
        
        logger.debug(f"Medium analysis completed for {len(context_chunks)} chunks")
        return results

    def _identify_high_risk_chunks(self, suspicious_chunks: List[Tuple[int, str]], 
                              medium_results: Dict[int, Dict]) -> List[Tuple[int, str]]:
        """
        Identify highest-risk chunks that need deep analysis.
        
        Args:
            suspicious_chunks: All suspicious chunks
            medium_results: Results from medium-depth analysis
            
        Returns:
            List of highest-risk chunks
        """
        high_risk_chunks = []
        
        # Calculate risk scores
        for i, chunk in suspicious_chunks:
            # If chunk was analyzed at medium level
            if i in medium_results:
                result = medium_results[i]
                
                # Calculate risk score based on medium analysis
                risk_score = 0
                
                # Increase score if marked as vulnerable
                if result['is_vulnerable']:
                    risk_score += 2
                    
                # Increase score based on severity
                severity_scores = {
                    'critical': 3,
                    'high': 2,
                    'medium': 1,
                    'low': 0
                }
                
                risk_score += severity_scores.get(result['severity'].lower(), 0)
                
                # High risk if score >= 3
                if risk_score >= 3:
                    high_risk_chunks.append((i, chunk))
            else:
                # If chunk wasn't analyzed at medium level, include based on static analysis
                # This is a fallback and shouldn't typically happen
                high_risk_chunks.append((i, chunk))
        
        # Limit to reasonable number to prevent excessive deep analysis
        max_deep_chunks = min(5, max(1, len(suspicious_chunks) // 3))
        selected_chunks = high_risk_chunks[:max_deep_chunks]
        
        logger.debug(f"Selected {len(selected_chunks)} high-risk chunks for deep analysis")
        return selected_chunks

    def _deep_model_analysis(self, file_path: str, high_risk_chunks: List[Tuple[int, str]],
                           vuln_name: str, vuln_desc: str, vuln_patterns: List[str],
                           vuln_impact: str, vuln_mitigation: str) -> Dict[int, str]:
        """
        Perform deep analysis on high-risk chunks.
        
        Args:
            file_path: Path to the file
            high_risk_chunks: List of high-risk chunks
            vuln_name, vuln_desc, etc.: Vulnerability details
            
        Returns:
            Dictionary mapping chunk indices to detailed analysis results
        """
        results = {}
        
        with tqdm(total=len(high_risk_chunks), desc="Deep analysis", leave=False) as pbar:
            for i, chunk in high_risk_chunks:
                # Use the full analysis prompt for deep analysis
                prompt = self._build_analysis_prompt(
                    vuln_name, vuln_desc, vuln_patterns, vuln_impact, vuln_mitigation,
                    chunk, i, len(high_risk_chunks)
                )
                
                # Analyze with deep model
                result = self._analyze_code_chunk(
                    prompt, file_path, chunk, vuln_name, 
                    mode=AnalysisMode.DEEP,
                    analysis_type=AnalysisType.ADAPTIVE
                )
                
                # Store result
                results[i] = result
                pbar.update(1)
        
        logger.debug(f"Deep analysis completed for {len(high_risk_chunks)} chunks")
        return results

    def _extract_severity_from_result(self, result: str) -> str:
        """
        Extract severity from analysis result.
        
        Args:
            result: Analysis result text
            
        Returns:
            Severity level (Critical, High, Medium, Low, or Unknown)
        """
        result_lower = result.lower()
        
        if 'critical' in result_lower:
            return 'Critical'
        elif 'high' in result_lower:
            return 'High'
        elif 'medium' in result_lower:
            return 'Medium'
        elif 'low' in result_lower:
            return 'Low'
        else:
            return 'Unknown'

    def _combine_adaptive_results(self, file_path: str, code_chunks: List[str], 
                               suspicious_chunks: List[Tuple[int, str]],
                               medium_results: Dict[int, Dict], 
                               deep_results: Dict[int, str]) -> str:
        """
        Combine results from different analysis levels into a cohesive report.
        
        Args:
            file_path: Path to the file
            code_chunks: All code chunks
            suspicious_chunks: All suspicious chunks
            medium_results: Results from medium-depth analysis
            deep_results: Results from deep analysis
            
        Returns:
            Combined analysis report
        """
        # Collect all chunk indices that were analyzed
        analyzed_chunk_indices = {i for i, _ in suspicious_chunks}

        # Start building the report
        report = [
            "# Adaptive Security Analysis Report\n",
            f"File: {file_path}\n",
            f"Total chunks: {len(code_chunks)}\n",
            f"Suspicious chunks: {len(suspicious_chunks)} ({len(suspicious_chunks) / len(code_chunks) * 100:.1f}%)\n",
            f"Medium-analyzed chunks: {len(medium_results)}\n",
            f"Deep-analyzed chunks: {len(deep_results)}\n\n",
        ]

        # Add deep analysis results (most detailed)
        if deep_results:
            report.append("## Deep Analysis Results\n")
            for i, result in deep_results.items():
                report.extend((f"### Chunk {i + 1}\n", result, "\n"))

        # Add medium analysis results for chunks not covered by deep analysis
        if medium_results:
            added_medium = False

            for i, result in medium_results.items():
                if i not in deep_results:
                    if not added_medium:
                        report.append("## Medium Analysis Results\n")
                        added_medium = True

                    report.extend((f"### Chunk {i + 1}\n", result['result'], "\n"))
        # Add summary of chunks considered clean
        clean_chunks = len(code_chunks) - len(suspicious_chunks)
        if clean_chunks > 0:
            report.append("## Clean Chunks\n")
            report.append(f"{clean_chunks} chunks were determined to be free of vulnerabilities after initial scanning.\n")

        return "\n".join(report)

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
