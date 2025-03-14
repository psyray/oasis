from pathlib import Path
import ollama
import pickle
from datetime import datetime
from typing import List, Tuple, Dict
from multiprocessing import Pool, cpu_count
from tqdm import tqdm
import numpy as np

# Import from other modules
from tools import logger, chunk_content, calculate_similarity

def process_file_static(args: tuple) -> Tuple[str, str, List[float]]:
    """
    Process a single file for parallel embedding generation
    Args:
        args: Tuple of (file_path, embedding_model, chunk_size)
    Returns:
        Tuple of (file_path, content, embedding) or None if error
    """
    file_path, embedding_model, chunk_size = args
    try:
        client = ollama.Client()
        
        # Try different encodings
        encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
        content = None
        
        for encoding in encodings:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.error(f"Error reading {file_path} with {encoding}: {str(e)}")
                continue
        
        if content is None:
            logger.error(f"Failed to read {file_path} with any supported encoding")
            return None

        # Split content into chunks if necessary
        chunks = chunk_content(content, max_length=chunk_size)
        embeddings = []
        
        # Get embeddings for each chunk
        for i, chunk in enumerate(chunks):
            try:
                if len(chunk) > chunk_size:  # Additional verification
                    logger.debug(f"Chunk {i+1} size ({len(chunk)}) exceeds limit ({chunk_size})")
                    chunk = chunk[:chunk_size]  # Truncate if necessary
                    
                response = client.embeddings(
                    model=embedding_model,
                    prompt=chunk  # Use chunk instead of full content
                )
                if response and 'embedding' in response:
                    embeddings.append(response['embedding'])
                else:
                    logger.debug(f"Invalid response for chunk {i+1} of {file_path}")
            except Exception as e:
                logger.error(f"Error processing chunk {i+1} of {file_path}: {str(e)}")
                continue

        # Average the embeddings if we had multiple chunks
        if embeddings:
            if len(embeddings) == 1:
                final_embedding = embeddings[0]
            else:
                final_embedding = np.mean(embeddings, axis=0).tolist()
            return file_path, content, final_embedding
            
    except Exception as e:
        logger.error(f"Error processing {file_path}: {str(e)}")
        return None

def analyze_vulnerability_parallel(args: tuple) -> Dict:
    """
    Wrapper function for parallel processing
    Args:
        args: Tuple of (file_path, data, vulnerability_type, embedding_model)
    Returns:
        Dict with analysis results
    """
    file_path, data, vulnerability_type, embedding_model = args
    try:
        # Create a new Ollama client for each process
        client = ollama.Client()
        
        # Get vulnerability embedding
        vuln_response = client.embeddings(
            model=embedding_model,
            prompt=vulnerability_type
        )
        
        # Calculate similarity
        similarity = calculate_similarity(
            vuln_response['embedding'],
            data['embedding']
        )

        return {
            'file_path': file_path,
            'similarity_score': similarity
        }
            
    except Exception as e:
        logger.error(f"Error analyzing {file_path}: {str(e)}")
        return {
            'file_path': file_path,
            'error': str(e)
        }

class EmbeddingManager:
    def __init__(self, embedding_model: str, extensions: List[str] = None, chunk_size: int = 2048):
        """
        Initialize the embedding manager
        Args:
            embedding_model: Model to use for embeddings
            extensions: List of file extensions to analyze (without dots)
            chunk_size: Maximum size of text chunks for embedding
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

        self.embedding_model = embedding_model
        self.code_base: Dict = {}
        self.cache_file = None  # Will be set when directory is provided
        
        # Default extensions if none provided
        self.supported_extensions = extensions or [
            # Web Development
            'html', 'htm', 'css', 'js', 'jsx', 'ts', 'tsx', 'php', 'asp', 'aspx', 'jsp',
            'vue', 'svelte',
            
            # Programming Languages
            'py', 'pyc', 'pyd', 'pyo', 'pyw',  # Python
            'java', 'class', 'jar',              # Java
            'cpp', 'c', 'cc', 'cxx', 'h', 'hpp', 'hxx',  # C/C++
            'cs',                                  # C#
            'go',                                  # Go
            'rs',                                  # Rust
            'rb', 'rbw',                         # Ruby
            'swift',                              # Swift
            'kt', 'kts',                         # Kotlin
            'scala',                              # Scala
            'pl', 'pm',                          # Perl
            'php', 'phtml', 'php3', 'php4', 'php5', 'phps',  # PHP
            
            # Mobile Development
            'swift',                              # iOS
            'm', 'mm',                           # Objective-C
            'java', 'kt',                        # Android
            'dart',                               # Flutter
            
            # Shell Scripts
            'sh', 'bash', 'csh', 'tcsh', 'zsh', 'fish',
            'bat', 'cmd', 'ps1',                # Windows Scripts
            
            # Database
            'sql', 'mysql', 'pgsql', 'sqlite',
            
            # Configuration & Data
            'xml', 'yaml', 'yml', 'json', 'ini', 'conf', 'config',
            'toml', 'env',
            
            # System Programming
            'asm', 's',                          # Assembly
            'f', 'for', 'f90', 'f95',         # Fortran
            
            # Other Languages
            'lua',                                # Lua
            'r', 'R',                           # R
            'matlab', 'm',                      # MATLAB
            'groovy',                            # Groovy
            'pl',                                # Prolog
            'erl',                               # Erlang
            'ex', 'exs',                        # Elixir
            'hs',                                # Haskell
            'lisp', 'lsp', 'cl',              # Lisp
            'clj', 'cljs',                     # Clojure
            
            # Smart Contracts
            'sol',                               # Solidity
            
            # Template Files
            'tpl', 'tmpl', 'template',
            
            # Documentation
            'md', 'rst', 'adoc',              # Documentation files
            
            # Build & Package
            'gradle', 'maven',
            'rake', 'gemspec',
            'cargo', 'cabal',
            'cmake', 'make',
            
            # Container & Infrastructure
            'dockerfile', 'containerfile',
            'tf', 'tfvars',                    # Terraform
            'yaml', 'yml',                     # Kubernetes, Docker Compose
            
            # Version Control
            'gitignore', 'gitattributes', 'gitmodules'
        ]
        self.chunk_size = chunk_size

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
            
            # Prepare arguments for parallel processing
            process_args = [
                (str(file_path), self.embedding_model, self.chunk_size)
                for file_path in files 
                if str(file_path) not in self.code_base
            ]
            
            if not process_args:
                return

            # Process files in parallel with progress bar
            with Pool(processes=num_processes) as pool:
                with tqdm(total=len(process_args), desc="Progress", leave=True) as pbar:
                    for result in pool.imap_unordered(process_file_static, process_args):
                        if result:
                            file_path, content, embedding = result
                            self.code_base[file_path] = {
                                'content': content,
                                'embedding': embedding,
                                'chunks': chunk_content(content, self.chunk_size),
                                'timestamp': datetime.now().isoformat()
                            }
                        pbar.update(1)

            # Save after batch processing
            self.save_cache()

        except Exception as e:
            logger.error(f"Error during parallel embedding generation: {str(e)}")

    def save_cache(self):
        """Save embeddings to cache"""
        if not self.cache_file:
            logger.warning("Cache file path not set, cannot save cache")
            return

        try:
            # Ensure each entry has the correct structure
            for file_path, data in self.code_base.items():
                if not isinstance(data, dict):
                    # Si ce n'est pas un dictionnaire, créer la structure
                    self.code_base[file_path] = {
                        'content': data if isinstance(data, str) else '',
                        'embedding': [],
                        'chunks': [],
                        'timestamp': datetime.now().isoformat()
                    }
                elif any(
                    k not in data
                    for k in ['content', 'embedding', 'chunks', 'timestamp']
                ):
                    # Si la structure est incomplète, la compléter
                    self.code_base[file_path].update({
                        'content': data.get('content', ''),
                        'embedding': data.get('embedding', []),
                        'chunks': data.get('chunks', []),
                        'timestamp': data.get('timestamp', datetime.now().isoformat())
                    })

            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.code_base, f)
            logger.debug(f"Saved {len(self.code_base)} entries to cache")
        except Exception as e:
            logger.error(f"Error saving cache: {str(e)}")

    def load_cache(self) -> None:
        """Load embeddings from cache file"""
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
                        logger.debug(f"Loaded {len(self.code_base)} valid entries from cache")
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

    def clear_cache(self) -> None:
        """Clear embeddings cache file and memory"""
        try:
            if self.cache_file and self.cache_file.exists():
                self.cache_file.unlink()  # Delete the cache file
                logger.info(f"Cache file {self.cache_file} deleted successfully")
            self.code_base = {}  # Clear memory cache
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
        if not self.cache_file or not self.cache_file.exists():
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
