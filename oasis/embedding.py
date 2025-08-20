import argparse
import json
from pathlib import Path
import pickle
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional, Union
from multiprocessing import Pool, cpu_count
from tqdm import tqdm
import re
import ast

# Import configuration
from .config import EXTRACT_FUNCTIONS, SUPPORTED_EXTENSIONS, DEFAULT_ARGS

# Import from other modules
from .ollama_manager import OllamaManager
from .tools import create_cache_dir, logger, chunk_content, parse_input, sanitize_name, open_file

class EmbeddingManager:
    def __init__(self, args, ollama_manager: OllamaManager):
        """
        Initialize the embedding manager

        Args:
            args: Arguments
            ollama_manager: Ollama manager
        """
        try:
            self.ollama_manager = ollama_manager
            self.ollama_client = self.ollama_manager.get_client()

        except Exception as e:
            logger.error("Failed to initialize Ollama client")
            logger.error("Please make sure Ollama is running and accessible")
            logger.exception(f"Initialization error: {str(e)}")
            raise RuntimeError("Could not connect to Ollama server") from e

        self.input_path = args.input_path
        self.clear_cache = args.clear_cache_embeddings
        self.cache_days = args.cache_days or DEFAULT_ARGS['CACHE_DAYS']
        self.embedding_model = args.embed_model or DEFAULT_ARGS['EMBED_MODEL']

        # Analysis type
        self.analyze_type = args.analyze_type or DEFAULT_ARGS['ANALYSIS_TYPE']
        self.embedding_analysis_type = args.embeddings_analyze_type or DEFAULT_ARGS['EMBEDDING_ANALYSIS_TYPE']
        self.analyze_by_function = self.embedding_analysis_type == 'function'
        
        self.threshold = args.threshold or DEFAULT_ARGS['THRESHOLD']
        self.code_base: Dict = {}
        self.cache_file = None  # Will be set when directory is provided

        # Normalize extensions to a list regardless of input format
        self.supported_extensions = self._normalize_extensions(args.extensions)
        self.chunk_size = args.chunk_size or DEFAULT_ARGS['CHUNK_SIZE']
        self._setup_cache()

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
        
    def _setup_cache(self):
        """
        Set up the embedding manager cache

        Args:
            args: Arguments
        """
        # Create cache directory
        cache_dir=create_cache_dir(self.input_path)
        self.cache_file = cache_dir / f"{sanitize_name(self.input_path)}_{sanitize_name(self.embedding_model)}.cache"
        logger.debug(f"Cache file: {self.cache_file}")
        
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

    def index_code_files(self, files: List[Path]) -> None:
        """
        Generate embeddings for code files in parallel
        Args:
            files: List of file paths to analyze
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
                    analyze_by_function=self.analyze_by_function,
                    api_url=self.ollama_manager.api_url
                )
                for file_path in files 
                if self.analyze_by_function or str(file_path) not in self.code_base
            ]
            if not process_args:
                return

            # Process files in parallel with progress bar
            with Pool(processes=num_processes) as pool:
                with tqdm(total=len(process_args), desc="Generating embeddings", leave=True) as pbar:
                    for result in pool.imap_unordered(process_file_parallel, process_args):
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
            logger.exception(f"Error during parallel embedding generation: {str(e)}")

    def process_input_files(self, args):
        """
        Process input files and update embeddings

        Args:
            args: Arguments
        """
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

        # Generate embeddings only for new files or functions
        new_files = []
        for file_path in valid_files:
            file_key = str(file_path)

            if self.analyze_by_function:
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
            self.index_code_files(new_files)
        else:
            logger.debug("All files found in cache with valid structure")

        return valid_files

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

            # Validate embedding dimension consistency if embedding is present
            if 'embedding' in normalized and isinstance(normalized['embedding'], list):
                if not hasattr(self, 'embedding_dim') or self.embedding_dim is None:
                    self.embedding_dim = len(normalized['embedding'])
                    logger.debug(f"Initialized self.embedding_dim to {self.embedding_dim} based on the first embedding encountered")
                elif len(normalized['embedding']) != self.embedding_dim:
                    logger.error(f"Inconsistent embedding dimension: expected {self.embedding_dim}, got {len(normalized['embedding'])} for entry")

            return normalized

        # If entry is not a dict, return the default
        return default

    def save_cache(self):
        """
        Save embeddings to cache

        Args:
            None
        """
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
            logger.exception(f"Error saving cache: {str(e)}")

    def load_cache(self) -> None:
        """
        Load embeddings from cache file

        Args:
            None
        """
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
                        logger.info(f"Loaded {len(self.code_base)} entries from cache")
                        
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
            logger.exception(f"Error loading cache: {str(e)}")
            self.code_base = {}
            self.save_cache()

    def clear_embeddings_cache(self) -> None:
        """
        Clear embeddings cache file and memory

        Args:
            None
        """
        try:
            if self.cache_file is None:
                logger.warning("Cache file path not set, cannot clear cache file")
            elif self.cache_file.exists():
                self.cache_file.unlink()  # Delete the cache file
                logger.info(f"Cache file {self.cache_file} deleted successfully")
            
            self.code_base = {}  # Clear memory cache anyway
            logger.debug("Memory cache cleared")
        except Exception as e:
            logger.exception(f"Error clearing cache: {str(e)}")

    def get_embeddings_info(self) -> dict:
        """
        Get information about cached embeddings

        Returns:
            Dictionary containing information about cached embeddings
        """
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
            logger.exception(f"Cache validation failed: {str(e)}")
            return False 

    def filter_code_base_by_extensions(self) -> None:
        """
        Filter code_base to only include files with supported extensions

        Args:
            None
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

    # TODO: This is a temporary function to extract functions from a file based on its extension
    # TODO: We should use the LLM approach to extract functions from a file
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
        """
        Extract functions using regex patterns based on language
        
        Args:
            file_path: Path to the source file
            content: File content
            lang: Programming language extension
            
        Returns:
            Dictionary mapping function identifiers to function content
        """
        functions = {}
        
        try:
            # Get appropriate pattern for the language
            pattern = self.language_patterns(lang)
            
            # Find all function declarations
            matches = list(re.finditer(pattern, content, re.DOTALL))
            
            # Process each match
            for i, match in enumerate(matches):
                func_start = match.start()
                func_name = next((g for g in match.groups() if g), f"anonymous_function_{i}")
                
                # Determine function end boundary
                func_end = self._find_function_end(content, func_start, lang)
                
                if func_end > func_start:
                    func_id = f"{file_path}::{func_name}"
                    functions[func_id] = content[func_start:func_end].strip()
        
        except Exception as e:
            logger.exception(f"Error extracting functions from {file_path}: {e}")
            # Fallback - use whole file
            functions[file_path] = content
            
        return functions
        
    def _find_function_end(self, content: str, start_pos: int, lang: str) -> int:
        """
        Find the end position of a function based on language syntax
        
        Args:
            content: Source code content
            start_pos: Starting position of the function
            lang: Programming language extension
            
        Returns:
            End position of the function
        """
        # Default to end of content
        if start_pos >= len(content):
            return len(content)

        # Delegate to appropriate handler based on language type
        if lang in {'js', 'ts', 'java', 'c', 'cpp', 'cs', 'php', 'go'}:
            return self._find_brace_function_end(content, start_pos)
        elif lang in {'py', 'rb'}:
            return self._find_indentation_function_end(content, start_pos)

        # Fallback for unsupported languages
        return len(content)
        
    def _find_brace_function_end(self, content: str, start_pos: int) -> int:
        """Find end position for languages using braces (C-family, etc.)"""
        brace_level = 0
        in_string = False
        string_char = None
        
        for i in range(start_pos, len(content)):
            char = content[i]
            
            # Handle string boundaries
            if char in ['"', "'"] and (i == 0 or content[i-1] != '\\'):
                if not in_string:
                    in_string, string_char = True, char
                elif char == string_char:
                    in_string = False
            
            # Only count braces outside of strings
            if not in_string:
                if char == '{':
                    brace_level += 1
                elif char == '}':
                    brace_level -= 1
                    if brace_level == 0 and i > start_pos:
                        return i + 1
                        
        return len(content)
        
    def _find_indentation_function_end(self, content: str, start_pos: int) -> int:
        """Find end position for languages using indentation (Python, Ruby)"""
        lines = content[start_pos:].split('\n')
        if len(lines) <= 1:
            return len(content)
            
        # Find indentation of first non-empty line in function body
        body_indent = None
        
        for i, line in enumerate(lines[1:], 1):
            stripped = line.lstrip()
            # Skip empty lines and comments
            if not stripped or stripped.startswith('#'):
                continue
                
            # Calculate indentation of this line
            current_indent = len(line) - len(stripped)
            
            if body_indent is None:
                body_indent = current_indent
            elif current_indent <= body_indent and i > 1:
                # Found a line with same or less indentation - end of function
                line_pos = start_pos + sum(len(li) + 1 for li in lines[:i])
                return min(line_pos, len(content))
        
        return len(content)

    def extract_shell_functions(self, file_path: str, content: str) -> Dict[str, str]:
        """
        Extract functions from shell scripts

        Args:
            file_path: Path to the source file
            content: File content
        """
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
        """
        Return the regex pattern for a given language

        Args:
            lang: Programming language
        """
        # Define regex patterns for different languages
        patterns = {
            # Python - functions and methods
            'py': r'def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|async\s+def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',

            # JavaScript/TypeScript - various forms of functions
            'js': r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*function\s*\(|([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*function\s*\(|([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\(.*?\)\s*=>|async\s+function\s+([a-zA-Z_][a-zA-Z0-9_]*)|([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*?\)\s*:\s*\w+',
            'ts': r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(|([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*function\s*\(|([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*function\s*\(|([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\(.*?\)\s*=>|async\s+function\s+([a-zA-Z_][a-zA-Z0-9_]*)|([a-zA-Z_][a-zA-Z0-9_]*)\s*\(.*?\)\s*:\s*\w+',

            # Java and similar languages
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
        extraction_model = EXTRACT_FUNCTIONS['MODEL']
        if not self.ollama_manager.ensure_model_available(extraction_model):
            return {}
        
        # Make sure we're using a normalized version of the content
        # This ensures the same text is used for LLM analysis and extraction
        normalized_content = content.replace('\r\n', '\n')
        
        # Create prompt
        prompt = f"""
            Extract all functions and methods from the following {extension} code.
            {EXTRACT_FUNCTIONS['PROMPT']}
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
                    # TODO: add body, parameters and return_type
                    # body = func.get("body")
                    # parameters = func.get("parameters")
                    # return_type = func.get("return_type")

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
                logger.exception(f"Invalid JSON in LLM response for {file_path}: {str(e)}")
                logger.debug(f"Raw JSON response: {json_match[1][:200]}...")
                return {}

        except Exception as e:
            logger.exception(f"Error using LLM for function extraction in {file_path}: {str(e)}")
            # Fallback to regex approach
            logger.info(f"Falling back to regex-based extraction for {file_path}")
            return self.extract_functions_with_regex(file_path, content, extension)

        return {}

    def get_vulnerability_embedding(self, vulnerability: Union[str, Dict]) -> List[float]:
        """
        Get embedding vector for a vulnerability type

        Args:
            vulnerability: Vulnerability type to get embedding for (string or dict)
            
        Returns:
            Embedding vector as list of floats
        """
        try:
            # Build the prompt with our utility method
            prompt = build_vulnerability_embedding_prompt(vulnerability)
            
            response = self.ollama_client.embeddings(model=self.embedding_model, prompt=prompt)
            return response.get('embedding') if response and 'embedding' in response else None
        except Exception as e:
            # Log error with appropriate vulnerability information
            vuln_name = vulnerability['name'] if isinstance(vulnerability, dict) else vulnerability
            logger.exception(f"Failed to get embedding for {vuln_name}: {str(e)}")
            return None

def process_file_parallel(args: tuple) -> Tuple[str, str, List[float], bool, Optional[Dict[str, Tuple[str, List[float]]]]]:
    """
    Process a file in a separate process without creating a full EmbeddingManager
    
    Args:
        args: Arguments for processing
        
    Returns:
        Tuple of (file_path, content, embedding, is_function_analysis, function_embeddings)
    """
    try:
        # Create a new Ollama client for each process
        ollama_manager = OllamaManager(args.api_url)

        # Read file content
        if not (content := open_file(args.input_path)):
            logger.warning(f"Empty or unreadable file content for file: {args.input_path}")
            return None
            
        # Extract embeddings based on analysis type
        if args.analyze_by_function:
            # Extract functions
            functions = extract_functions_from_file(args.input_path, content, ollama_manager)
            
            # Generate embeddings for functions
            function_embeddings = {}
            for func_id, func_content in functions.items():
                func_embedding = generate_content_embedding(
                    func_content, 
                    args.embed_model, 
                    args.chunk_size,
                    ollama_manager
                )
                if func_embedding is not None:
                    function_embeddings[func_id] = (func_content, func_embedding)
                    
            # Also generate embedding for entire file
            file_embedding = generate_content_embedding(
                content, 
                args.embed_model, 
                args.chunk_size,
                ollama_manager
            )
            if file_embedding is not None:
                return args.input_path, content, file_embedding, True, function_embeddings
        else:
            # Standard file analysis
            file_embedding = generate_content_embedding(
                content, 
                args.embed_model, 
                args.chunk_size,
                ollama_manager
            )
            if file_embedding is not None:
                return args.input_path, content, file_embedding, False, None
                
    except Exception as e:
        logger.exception(f"Error processing {args.input_path}: {str(e)}")
        
    return None

def build_vulnerability_embedding_prompt(vulnerability: Union[str, Dict]) -> str:
    """
    Build a rich prompt for vulnerability embedding
    
    Args:
        vulnerability: Vulnerability type (string name or complete dict)
        
    Returns:
        Rich prompt string for embedding
    """
    # Handle both string and dictionary inputs
    if isinstance(vulnerability, dict):
        return f"""
        Vulnerability: {vulnerability['name']}
        
        Description: 
        {vulnerability['description']}
        
        Common patterns:
        {' | '.join(vulnerability['patterns'])}
        
        Security impact:
        {vulnerability['impact']}
        
        Mitigation strategies:
        {vulnerability['mitigation']}
        
        Analyze code to identify this vulnerability.
        """
    else:
        # Use the string directly
        return str(vulnerability)
def generate_content_embedding(content: str, model: str, chunk_size: int = DEFAULT_ARGS['CHUNK_SIZE'], ollama_manager: OllamaManager = None) -> List[float]:
    """
    Generate embedding for content

    Args:
        content: Content to embed
        model: Embedding model name
        chunk_size: Maximum size of text chunks for embedding

    Returns:
        Embedding vector as list of floats, aggregated if content was chunked
    """
    if ollama_manager is None:
        raise ValueError("ollama_manager must be provided and cannot be None")

    try:
        client = ollama_manager.get_client()

        # For large content, chunk and get embeddings for each chunk
        if len(content) > chunk_size:
            chunks = chunk_content(content, chunk_size)
            chunk_embeddings = []

            for chunk in chunks:
                response = client.embeddings(model=model, prompt=chunk)
                if response and 'embedding' in response:
                    chunk_embeddings.append(response['embedding'])

            # Aggregate chunk embeddings if we have any
            if chunk_embeddings:
                # Average all embeddings together (element-wise) using zip
                aggregated_embedding = [sum(col) / len(col) for col in zip(*chunk_embeddings)]
                return [val / len(chunk_embeddings) for val in aggregated_embedding]
            return None
        else:
            # For small content, get single embedding
            response = client.embeddings(model=model, prompt=content)
            return response.get('embedding') if response and 'embedding' in response else None

    except Exception as e:
        logger.exception(f"Error generating embedding: {str(e)}")
        return None

def extract_functions_from_file(file_path: str, content: str, extraction_model: str = EXTRACT_FUNCTIONS['MODEL'], ollama_manager: OllamaManager = None) -> Dict[str, str]:
    """
    Extract functions from file content
    
    Args:
        file_path: Path to source file
        content: File content
        extraction_model: Model to use for extraction
        
    Returns:
        Dictionary mapping function IDs to function content
    """
    if ollama_manager is None:
        raise ValueError("ollama_manager must be provided")

    # Determine file extension
    extension = file_path.split('.')[-1].lower()
    
    # Make sure we're using a normalized version of the content
    normalized_content = content.replace('\r\n', '\n')
    
    try:
        # Get client 
        client = ollama_manager.get_client()
        
        # Ensure model is available
        if not ollama_manager.ensure_model_available(extraction_model):
            return {}
            
        # Create prompt
        prompt = f"""
            Extract all functions and methods from the following {extension} code.
            {EXTRACT_FUNCTIONS['PROMPT']}
            Here is the code:
            ```{extension}
            {normalized_content}
            ```
            """
            
        # Generate response
        response = client.generate(
            model=extraction_model,
            prompt=prompt,
        )
        
        if not response or not response.response:
            logger.warning(f"No valid response from LLM for function extraction in {file_path}")
            return {}
            
        # Process response and extract functions
        # ... (code from extract_functions_with_llm that parses the JSON response)
        
    except Exception as e:
        logger.exception(f"Error extracting functions from {file_path}: {str(e)}")
        # Fallback to regex approach if needed
        
    return {}
