import argparse
import json
from pathlib import Path
import pickle
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional
from multiprocessing import Pool, cpu_count
from tqdm import tqdm
import re
import ast

# Import configuration
from .config import EXTRACT_FUNCTIONS_ANALYSIS_TYPE, SUPPORTED_EXTENSIONS, EXTRACT_FUNCTIONS_MODEL, EXTRACT_FUNCTIONS_PROMPT

# Import from other modules
from .ollama_manager import OllamaManager
from .tools import logger, chunk_content, parse_input, sanitize_model_name, open_file

class EmbeddingManager:
    def __init__(self, args):
        """
        Initialize the embedding manager
        Args:
            embedding_model: Model to use for embeddings
            extensions: List of file extensions to analyze (without dots)
            chunk_size: Maximum size of text chunks for embedding
        """
        try:
            self.ollama_manager = OllamaManager()
            self.ollama_client = self.ollama_manager.get_client()

        except Exception as e:
            logger.error("Failed to initialize Ollama client")
            logger.error("Please make sure Ollama is running and accessible")
            logger.debug(f"Initialization error: {str(e)}")
            raise RuntimeError("Could not connect to Ollama server") from e

        self.input_path = args.input_path
        self.clear_cache = args.clear_cache 
        self.cache_days = args.cache_days
        self.embedding_model = args.embed_model
        self.code_base: Dict = {}
        self.cache_file = None  # Will be set when directory is provided

        # Normalize extensions to a list regardless of input format
        self.supported_extensions = self._normalize_extensions(args.extensions)
        self.chunk_size = args.chunk_size
        self.setup()

    def _normalize_extensions(self, extensions_arg) -> List[str]:
        """
        Normalize extensions to a list format regardless of input type
        
        Args:
            extensions_arg: Extensions from command line (string or list or None)
            
        Returns:
            List of extension strings without dots
        """
        if not extensions_arg:
            # No extensions provided, use defaults
            return list(SUPPORTED_EXTENSIONS)
        
        # If extensions is already a list, return it
        if isinstance(extensions_arg, list):
            return extensions_arg
            
        # If extensions is a string (comma-separated), split it
        if isinstance(extensions_arg, str):
            return [ext.strip() for ext in extensions_arg.split(',')]
            
        # Fallback - convert whatever we got to list
        return list(extensions_arg)
        
    def setup(self):
        """Set up the embedding manager and cache file"""
        # Setup cache file
        input_path = Path(self.input_path)
        if input_path.is_dir():
            cache_dir = input_path / '.oasis_cache'
        else:
            cache_dir = input_path.parent / '.oasis_cache'
            
        cache_dir.mkdir(exist_ok=True)
        self.cache_file = cache_dir / f"embeddings_{sanitize_model_name(self.embedding_model)}.pkl"
        
        # Clear cache if requested
        if self.clear_cache:
            self.clear_embeddings_cache()
        
        # Check if cache is valid based on age
        if not self.clear_cache and self.is_cache_valid(self.cache_days):
            self.load_cache()

    def is_valid_file(self, file_path: Path) -> bool:
        """
        Check if file should be analyzed based on extension
        Args:
            file_path: Path to the file
        Returns:
            bool: True if file should be analyzed
        """
        return file_path.suffix.lower()[1:] in self.supported_extensions

    def index_code_files(self, files: List[Path], analyze_by_function: bool = False) -> None:
        """
        Generate embeddings for code files in parallel
        Args:
            files: List of file paths to analyze
            analyze_by_function: Boolean indicating whether to analyze by function
        """
        try:
            # Calculate optimal number of processes
            num_processes = max(1, min(cpu_count(), len(files)))

            # Prepare arguments for parallel processing and filter files, including the analyze_by_function flag
            process_args = [
                argparse.Namespace(
                    input_path=str(file_path),
                    embed_model=self.embedding_model,
                    chunk_size=self.chunk_size,
                    analyze_by_function=analyze_by_function,
                    extensions=self.supported_extensions,
                    clear_cache=self.clear_cache,
                    cache_days=self.cache_days
                )
                for file_path in files 
                if analyze_by_function or str(file_path) not in self.code_base
            ]
            if not process_args:
                return

            # Process files in parallel with progress bar
            with Pool(processes=num_processes) as pool:
                with tqdm(total=len(process_args), desc="Generating embeddings", leave=True) as pbar:
                    for result in pool.imap_unordered(process_file_static, process_args):
                        if result:
                            file_path, content, embedding, is_function_analysis, function_embeddings = result

                            # Store file data
                            if file_path not in self.code_base:
                                self.code_base[file_path] = {
                                    'content': content,
                                    'embedding': embedding,
                                    'chunks': chunk_content(content, self.chunk_size),
                                    'timestamp': datetime.now().isoformat()
                                }

                            # If analyzing by function, store function data
                            if is_function_analysis and function_embeddings:
                                if 'functions' not in self.code_base[file_path]:
                                    self.code_base[file_path]['functions'] = {}

                                # Store function embeddings
                                for func_id, (func_content, func_embedding) in function_embeddings.items():
                                    self.code_base[file_path]['functions'][func_id] = {
                                        'content': func_content,
                                        'embedding': func_embedding,
                                        'timestamp': datetime.now().isoformat()
                                    }

                        pbar.update(1)

            # Save after batch processing
            self.save_cache()

        except Exception as e:
            logger.error(f"Error during parallel embedding generation: {str(e)}")

    def process_input_files(self, args):
        """Process input files and update embeddings"""
        # Parse input files and generate embeddings
        files_to_analyze = parse_input(args.input_path)
        if not files_to_analyze:
            logger.error("No valid files to analyze")
            return []

        # Filter files by supported extensions
        valid_files = []
        for file_path in files_to_analyze:
            if self.is_valid_file(file_path):
                valid_files.append(file_path)
            else:
                logger.debug(f"Skipping unsupported file: {file_path}")

        if not valid_files:
            logger.error("No files with supported extensions found for analysis")
            return []

        logger.info(f"Found {len(valid_files)} files with supported extensions out of {len(files_to_analyze)} total files")

        # Determine if we're analyzing by file or by function
        analyze_by_function = args.analyze_type == EXTRACT_FUNCTIONS_ANALYSIS_TYPE

        # Generate embeddings only for new files or functions
        new_files = []
        for file_path in valid_files:
            file_key = str(file_path)

            if analyze_by_function:
                # For function analysis, we need to process the file to extract functions
                if file_key not in self.code_base or 'functions' not in self.code_base[file_key]:
                    new_files.append(file_path)
            elif (file_key not in self.code_base or 
                    not isinstance(self.code_base[file_key], dict) or
                    'embedding' not in self.code_base[file_key] or 
                    'chunks' not in self.code_base[file_key] or
                    'timestamp' not in self.code_base[file_key]):
                new_files.append(file_path)

        if new_files:
            logger.info(f"Generating embeddings for {len(new_files)} new files")
            self.index_code_files(new_files, analyze_by_function=analyze_by_function)
        else:
            logger.debug("All files found in cache with valid structure")

        return valid_files

    def generate_content_embedding(self, text_content, args):
        """Generate content embedding
        Args:
            text_content: Content to embed
            args: Arguments (input_path, embed_model, chunk_size)
        Returns:
            Embedding
        """
        # Create a new Ollama client for this process
        client = self.ollama_client

        chunks = chunk_content(text_content, args.chunk_size)

        if len(chunks) == 1:
            # For small content, use entire content
            response = client.embeddings(
                model=args.embed_model,
                prompt=chunks[0]
            )
            if response and 'embedding' in response:
                return response['embedding']
            logger.debug(f"Invalid response for chunk {text_content[:24]}... of {args.input_path}")
        else:
            # For large content, keep chunk embeddings separately
            chunk_embeddings = []
            for chunk in chunks:
                response = client.embeddings(
                    model=args.embed_model,
                    prompt=chunk
                )
                if response and 'embedding' in response:
                    chunk_embeddings.append(response['embedding'])

            if chunk_embeddings:
                return chunk_embeddings

        return None

    def normalize_cache_entry(self, entry: Any) -> Dict:
        """
        Normalize a cache entry to ensure it has the correct structure
        Args:
            entry: Cache entry to normalize
        Returns:
            Dict with normalized cache entry
        """
        # Create default values for all required fields
        default = {
            'content': entry if isinstance(entry, str) else '',
            'embedding': [],
            'chunks': [],
            'timestamp': datetime.now().isoformat()
        }

        # If entry is already a dict, update missing fields
        if isinstance(entry, dict):
            # Make a copy to avoid modifying the original
            normalized = entry.copy()
            
            # Ensure all required fields are present
            for key, default_value in default.items():
                if key not in normalized:
                    normalized[key] = default_value
                    
            return normalized
            
        # If entry is not a dict, return the default
        return default

    def save_cache(self):
        """Save embeddings to cache"""
        if not self.cache_file:
            logger.warning("Cache file path not set, cannot save cache")
            return

        try:
            # Normalize all cache entries
            for file_path, data in self.code_base.items():
                self.code_base[file_path] = self.normalize_cache_entry(data)

            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.code_base, f)
            logger.debug(f"Saved {len(self.code_base)} entries to cache")
        except Exception as e:
            logger.error(f"Error saving cache: {str(e)}")

    def load_cache(self) -> None:
        """Load embeddings from cache file"""
        if self.cache_file is None:
            logger.warning("Cache file path not set, cannot load cache")
            self.code_base = {}
            return
        
        try:
            # Ensure cache directory exists
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            
            if not self.cache_file.exists():
                logger.info(f"Creating new cache file {self.cache_file}")
                self.code_base = {}
                self.save_cache()
                return

            with open(self.cache_file, 'rb') as f:
                try:
                    cached_data = pickle.load(f)
                    # Strict check of cache structure
                    if (isinstance(cached_data, dict) and 
                        all(isinstance(v, dict) and 
                            'embedding' in v and 
                            'chunks' in v and 
                            'timestamp' in v 
                            for v in cached_data.values())):
                        self.code_base = cached_data
                        logger.debug(f"Loaded {len(self.code_base)} entries from cache")
                        
                        # Filter code_base by supported extensions
                        self.filter_code_base_by_extensions()
                        
                    else:
                        logger.warning("Invalid cache structure, starting fresh")
                        self.code_base = {}
                        self.save_cache()
                except EOFError:
                    logger.error("Cache file is empty or corrupted. Starting with fresh cache.")
                    self.code_base = {}
                    self.save_cache()
        except Exception as e:
            logger.error(f"Error loading cache: {str(e)}")
            self.code_base = {}
            self.save_cache()

    def clear_embeddings_cache(self) -> None:
        """Clear embeddings cache file and memory"""
        try:
            if self.cache_file is None:
                logger.warning("Cache file path not set, cannot clear cache file")
            elif self.cache_file.exists():
                self.cache_file.unlink()  # Delete the cache file
                logger.info(f"Cache file {self.cache_file} deleted successfully")
            
            self.code_base = {}  # Clear memory cache anyway
            logger.debug("Memory cache cleared")
        except Exception as e:
            logger.error(f"Error clearing cache: {str(e)}")

    def get_embeddings_info(self) -> dict:
        """Get information about cached embeddings"""
        info = {
            'total_files': len(self.code_base),
            'files': {}
        }
        
        for file_path in self.code_base:
            file_info = {
                'size': len(self.code_base[file_path]['content']),
                'embedding_dimensions': len(self.code_base[file_path]['embedding'])
            }
            info['files'][file_path] = file_info
            
        return info
    
    def is_cache_valid(self, max_age_days: int = 7) -> bool:
        """
        Check if cache file exists and is not too old
        Args:
            max_age_days: Maximum age of cache in days
        Returns:
            bool: True if cache is valid, False otherwise
        """
        if self.cache_file is None or not self.cache_file.exists():
            return False
            
        # Check cache age
        cache_age = datetime.now() - datetime.fromtimestamp(self.cache_file.stat().st_mtime)
        if cache_age.days > max_age_days:
            return False
            
        # Try to load cache to verify integrity
        try:
            with open(self.cache_file, 'rb') as f:
                cached_data = pickle.load(f)
            return bool(cached_data)  # Return True if cache is not empty
        except Exception as e:
            logger.debug(f"Cache validation failed: {str(e)}")
            return False 

    def filter_code_base_by_extensions(self) -> None:
        """
        Filter code_base to only include files with supported extensions
        """
        if not self.code_base:
            return
        
        # Store initial count
        initial_count = len(self.code_base)
        
        # Filter code_base using dictionary comprehension
        self.code_base = {
            file_path: data 
            for file_path, data in self.code_base.items() 
            if self.is_valid_file(Path(file_path))
        }
        
        # Log the filtering results
        filtered_count = initial_count - len(self.code_base)
        if filtered_count > 0:
            logger.info(f"Filtered out {filtered_count} files that don't match the specified extensions") 

    def parse_functions_from_file(self, file_path: str, content: str) -> Dict[str, str]:
        """
        Extract individual functions from a file based on its extension
        
        Args:
            file_path: Path to the source file
            content: File content
            
        Returns:
            Dictionary mapping function identifiers to function content
        """
        extension = file_path.split('.')[-1].lower()
        functions = {}
        
        # First try using LLM approach
        use_llm = True  # Configurable via args
        
        if use_llm:
            functions = self.extract_functions_with_llm(file_path, content)
            
            # If LLM extraction succeeds, return results
            if functions:
                return functions
        
        # Fallback methods if LLM approach fails or is disabled
        if extension == 'py':
            try:
                # Use AST to parse Python code
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        # Get the source code for this function
                        function_code = content[node.lineno-1:node.end_lineno]
                        function_name = node.name
                        functions[f"{file_path}::{function_name}"] = function_code
                        
            except SyntaxError:
                # Fallback to regex for files with syntax errors
                functions = self.extract_functions_with_regex(file_path, content, 'py')
        else:
            # Use regex-based extraction for other languages
            functions = self.extract_functions_with_regex(file_path, content, extension)
            
        # If no functions were extracted, treat the whole file as one unit
        if not functions:
            functions[file_path] = content
            
        return functions

    def extract_functions_with_regex(self, file_path: str, content: str, lang: str) -> Dict[str, str]:
        """Extract functions using regex patterns based on language"""
        functions = {}
        
        pattern = self.language_patterns(lang)
        logger.info(f"Extracting functions from {file_path} with language: {lang} and pattern: {pattern}")
        
        # Find all matches in the content
        matches = re.finditer(pattern, content, re.DOTALL)
        last_end = 0
        logger.info(f"Matches found: {len(matches)}")

        for match in matches:
            func_start = match.start()
            func_name = match.group(1) or "anonymous_function"
            
            # Skip if this function starts before the end of the last processed function
            if func_start < last_end:
                continue
                
            # Find the function body
            if lang in ['py', 'sh']:
                # For Python and Shell, specific logic here
                pass
            else:
                # For C-like languages, count braces to find matching closing brace
                brace_level = 0
                func_end = func_start
                in_string = False
                string_char = None
                
                for i in range(func_start, len(content)):
                    c = content[i]
                    
                    # Handle strings to avoid counting braces inside strings
                    if not in_string and (c == '"' or c == "'"):
                        in_string = True
                        string_char = c
                    elif in_string and c == string_char:
                        in_string = False
                    
                    if not in_string:
                        if c == '{':
                            brace_level += 1
                        elif c == '}':
                            brace_level -= 1
                            if brace_level == 0:
                                func_end = i + 1
                                break
                
                if func_end > func_start:
                    functions[f"{file_path}::{func_name}"] = content[func_start:func_end]
                    last_end = func_end
        
        return functions

    def extract_shell_functions(self, file_path: str, content: str) -> Dict[str, str]:
        """Extract functions from shell scripts"""
        functions = {}
        
        # Simple pattern for shell functions
        pattern = r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\)\s*{|([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\)\s*{'
        
        # Find all matches
        matches = re.finditer(pattern, content, re.MULTILINE)
        
        for match in matches:
            func_start = match.start()
            func_name = match.group(1) or match.group(2)
            
            # Find closing brace at the same level
            brace_level = 0
            func_end = func_start
            
            for i in range(func_start, len(content)):
                if content[i] == '{':
                    brace_level += 1
                elif content[i] == '}':
                    brace_level -= 1
                    if brace_level == 0:
                        func_end = i + 1
                        break
            
            if func_end > func_start:
                functions[f"{file_path}::{func_name}"] = content[func_start:func_end]
        
        return functions 

    def language_patterns(self, lang: str) -> str:
        """Return the regex pattern for a given language"""
        # Define regex patterns for different languages
        patterns = {
            # Python - fonctions et méthodes
            'py': r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|async\s+def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',

            # JavaScript/TypeScript - diverses formes de fonctions
            'js': r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*function\s*\(|([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*function\s*\(|([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\(.*?\)\s*=>|async\s+function\s+([a-zA-Z_][a-zA-Z0-9_]*)|([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*?\)\s*:\s*\w+',
            'ts': r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*function\s*\(|([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*function\s*\(|([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\(.*?\)\s*=>|async\s+function\s+([a-zA-Z_][a-zA-Z0-9_]*)|([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*?\)\s*:\s*\w+',

            # Java et langages similaires
            'java': r'(?:public|private|protected)?\s+(?:static)?\s+(?:final)?\s+(?:\w+(?:<.*?>)?)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*?\)\s*(?:throws\s+\w+(?:\s*,\s*\w+)*)?\s*{',
            'c': r'(?:\w+\s+)+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*?\)\s*{',
            'cpp': r'(?:\w+\s+)+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*?\)(?:\s*const)?\s*(?:noexcept)?\s*{|([a-zA-Z_][a-zA-Z0-9_]*)\s*::\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            'cs': r'(?:public|private|protected|internal)?\s+(?:static|virtual|override|abstract)?\s+(?:async)?\s+\w+(?:<.*?>)?\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*?\)\s*(?:where\s+\w+(?:\s*,\s*\w+)*)?\s*{',

            # PHP
            'php': r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|public\s+function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|private\s+function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|protected\s+function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',

            # Ruby
            'rb': r'def\s+([a-zA-Z_][a-zA-Z0-9_?!]*)|def\s+self\.([a-zA-Z_][a-zA-Z0-9_?!]*)',

            # Go
            'go': r'func\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|func\s+\([^)]+\)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',

            # Rust
            'rs': r'fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|impl\s+.*?\{\s*(?:pub\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]*)',

            # Swift
            'swift': r'func\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|class\s+func\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|static\s+func\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',

            # Kotlin
            'kt': r'fun\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|fun\s+[A-Z][a-zA-Z0-9_]*\.\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',

            # Shell/Bash
            'sh': r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\)|([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*\)',
            'bash': r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\)|([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*\)',

            # PowerShell
            'ps1': r'function\s+([a-zA-Z_][a-zA-Z0-9_\-]*)|filter\s+([a-zA-Z_][a-zA-Z0-9_\-]*)',

            # Perl
            'pl': r'sub\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*{|sub\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',

            # R
            'r': r'([a-zA-Z_][a-zA-Z0-9_\.]*)\s*<-\s*function\s*\(|function\s*\(.*?\)\s*{',

            # Scala
            'scala': r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|object\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\{',

            # Groovy
            'groovy': r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|void\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',

            # Objective-C
            'm': r'[-+]\s*\([^)]*\)\s*([a-zA-Z_][a-zA-Z0-9_:]*)',

            # Matlab
            'matlab': r'function\s+(?:[^=]*=)?\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',

            # Lua
            'lua': r'function\s+([a-zA-Z_][a-zA-Z0-9_\.]*)\s*\(|([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*function\s*\(',

            # Haskell
            'hs': r'([a-zA-Z_][a-zA-Z0-9_\']*)\s*::|([a-zA-Z_][a-zA-Z0-9_\']*)\s*(?:\w+\s+)*=',

            # Dart
            'dart': r'(?:void|[A-Za-z_][A-Za-z0-9_<>]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',

            # Elixir
            'ex': r'def\s+([a-zA-Z_][a-zA-Z0-9_?!]*)\s*\(|defp\s+([a-zA-Z_][a-zA-Z0-9_?!]*)\s*\(',

            # F#
            'fs': r'let\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\w+\s+)*=|let\s+rec\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        }
        return (
            r'(?:function|def)\s+([a-zA-Z_][a-zA-Z0-9_]*)'
            if lang not in patterns
            else patterns[lang]
        )

    def extract_functions_with_llm(self, file_path: str, content: str) -> Dict[str, str]:
        """
        Extract functions from code using a lightweight LLM
        
        Args:
            file_path: Path to the source file
            content: File content
            
        Returns:
            Dictionary mapping function identifiers to function content
        """
        # Determine file extension
        extension = file_path.split('.')[-1].lower()

        # Use a small, fast model for this task
        extraction_model = EXTRACT_FUNCTIONS_MODEL
        if not self.ollama_manager.ensure_model_available(extraction_model):
            return {}
        
        # Make sure we're using a normalized version of the content
        # This ensures the same text is used for LLM analysis and extraction
        normalized_content = content.replace('\r\n', '\n')
        
        # Create prompt
        prompt = f"""
            Extract all functions and methods from the following {extension} code.
            {EXTRACT_FUNCTIONS_PROMPT}
            Here is the code:
            ```{extension}
            {normalized_content}
            ```
            """

        try:
            # Get client from existing function
            client = self.ollama_client

            # Generate response with a short context model
            response = client.generate(
                model=extraction_model,
                prompt=prompt,
            )

            if not response or not response.response:
                logger.warning(f"No valid response from LLM for function extraction in {file_path}")
                return {}

            # Extract JSON part from response
            json_match = re.search(r'({[\s\S]*})', response.response)
            if not json_match:
                logger.warning(f"No valid JSON found in LLM response for {file_path}")
                return {}

            try:
                result = json.loads(json_match[1])

                # Extract functions using provided indices
                functions = {}
                for func in result.get("functions", []):
                    name = func.get("name", "anonymous")
                    start = func.get("start")
                    end = func.get("end")
                    body = func.get("body")
                    parameters = func.get("parameters")
                    return_type = func.get("return_type")

                    if start is not None and end is not None and start < end and end <= len(normalized_content):
                        # Extract from the normalized content that was sent to the LLM
                        func_content = normalized_content[start:end]
                        
                        # Validate that the extracted content looks like a function
                        # Simple check that the content contains the function name
                        if name in func_content:
                            functions[f"{file_path}::{name}"] = func_content
                        else:
                            logger.warning(f"Function extraction mismatch for {name} in {file_path}")
                            # TODO: implement a fallback or more advanced validation

                return functions

            except json.JSONDecodeError as e:
                logger.warning(f"Invalid JSON in LLM response for {file_path}: {str(e)}")
                logger.debug(f"Raw JSON response: {json_match[1][:200]}...")
                return {}

        except Exception as e:
            logger.error(f"Error using LLM for function extraction in {file_path}: {str(e)}")
            # Fallback to regex approach
            logger.info(f"Falling back to regex-based extraction for {file_path}")
            return self.extract_functions_with_regex(file_path, content, extension)

        return {}

def process_file_static(args: tuple) -> Tuple[str, str, List[float], bool, Optional[Dict[str, Tuple[str, List[float]]]]]:
    """
    Static method to process a file in a separate process
    Args:
        args: Tuple of (input_path, embedding_model, chunk_size, analyze_by_function, extensions, clear_cache, cache_days)
    Returns:
        Tuple of (input_path, content, embedding, analyze_by_function, function_embeddings)
    """

    try:
        # Initialize embedding manager
        embedding_manager = EmbeddingManager(args)

        # Read file content
        if not (content := open_file(args.input_path)):
            return None

        # Helper function to generate embeddings for text content
        if args.analyze_by_function:
            # Extract functions from file
            functions = embedding_manager.parse_functions_from_file(args.input_path, content)

            # Generate embeddings for each function
            function_embeddings = {}
            for func_id, func_content in functions.items():
                func_embedding = embedding_manager.generate_content_embedding(func_content, args)
                if func_embedding is not None:
                    function_embeddings[func_id] = (func_content, func_embedding)

            # Also generate embedding for entire file for comparison
            file_embedding = embedding_manager.generate_content_embedding(content, args)
            if file_embedding is not None:
                return args.input_path, content, file_embedding, True, function_embeddings
        else:
            # Standard file analysis (no function extraction)
            file_embedding = embedding_manager.generate_content_embedding(content, args)
            if file_embedding is not None:
                return args.input_path, content, file_embedding, False, None

    except Exception as e:
        logger.error(f"Error processing {args.input_path}: {str(e)}")

    return None
