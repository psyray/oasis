import os
import ollama
from pathlib import Path
import numpy as np
from typing import List, Tuple, Dict
import logging
from tqdm import tqdm
import json
import pickle
from datetime import datetime
import argparse
import markdown
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration
from weasyprint.logger import LOGGER as weasyprint_logger
from fontTools.subset import Subsetter, Options
from markdown.extensions import Extension
from markdown.preprocessors import Preprocessor
from multiprocessing import Pool, cpu_count
from functools import partial

# Initialize logger with module name
logger = logging.getLogger('oasis')

def setup_logging(debug=False, silent=False):
    """
    Setup all loggers with proper configuration
    Args:
        debug: Enable debug logging
        silent: Disable all output
    """
    # Set root logger level
    root_logger = logging.getLogger()
    if debug:
        root_logger.setLevel(logging.DEBUG)
    else:
        root_logger.setLevel(logging.WARNING)

    # Configure OASIS logger with custom formatter
    class EmojiFormatter(logging.Formatter):
        def format(self, record):
            if not hasattr(record, 'formatted_message'):
                if record.levelno == logging.DEBUG:
                    record.levelname = '🪲 '  # Debug: beetle
                elif record.levelno == logging.INFO:
                    record.levelname = ''    # Info: no prefix
                elif record.levelno == logging.WARNING:
                    record.levelname = '⚠️ '   # Warning: warning sign
                elif record.levelno == logging.ERROR:
                    record.levelname = '❌ '   # Error: cross mark
                record.formatted_message = f"{record.levelname}{record.msg}"
            return record.formatted_message

    # Configure handlers based on silent mode
    if not silent:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(EmojiFormatter())
        logger.addHandler(console_handler)
    
    logger.propagate = False  # Prevent duplicate logging
    
    # Set OASIS logger level based on mode
    if silent:
        logger.setLevel(logging.CRITICAL + 1)  # Above all levels
    elif debug:
        logger.setLevel(logging.DEBUG)         # Show all messages
    else:
        logger.setLevel(logging.INFO)          # Show info, warning, error

    # Configure other loggers
    fonttools_logger = logging.getLogger('fontTools')
    fonttools_logger.setLevel(logging.ERROR)
    
    weasyprint_logger.setLevel(logging.ERROR)

    # Disable other verbose loggers
    logging.getLogger('PIL').setLevel(logging.WARNING)
    logging.getLogger('markdown').setLevel(logging.WARNING)

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

def chunk_content(content: str, max_length: int = 2048) -> List[str]:
    """
    Split content into chunks of maximum length while preserving line integrity
    Args:
        content: Text content to split
        max_length: Maximum length of each chunk (reduced to 2048 to be safe)
    Returns:
        List of content chunks
    """
    if len(content) <= max_length:
        return [content]
    
    chunks = []
    lines = content.splitlines()
    current_chunk = []
    current_length = 0
    
    for line in lines:
        line_length = len(line) + 1  # +1 for newline
        if current_length + line_length > max_length:
            if current_chunk:
                chunks.append('\n'.join(current_chunk))
            current_chunk = [line]
            current_length = line_length
        else:
            current_chunk.append(line)
            current_length += line_length
    
    if current_chunk:
        chunks.append('\n'.join(current_chunk))
    
    if len(content) > max_length:
        logger.debug(f"Split content of {len(content)} chars into {len(chunks)} chunks")
    
    return chunks

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

class CodeSecurityAuditor:
    def __init__(self, embedding_model: str = 'nomic-embed-text', llm_model: str = None, extensions: List[str] = None, chunk_size: int = 2048):
        """
        Initialize the security auditor
        Args:
            embedding_model: Model to use for embeddings
            llm_model: Model to use for analysis
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
        self.llm_model = llm_model
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

    def _is_valid_file(self, file_path: Path) -> bool:
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
                elif not all(k in data for k in ['content', 'embedding', 'chunks', 'timestamp']):
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
                logger.info("Creating new cache file")
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
                logger.info("Cache file deleted successfully")
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
                    similarity = self.calculate_similarity(vuln_vector, file_vector)
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

    def calculate_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """
        Calculate cosine similarity between two vectors
        Args:
            vec1: First vector
            vec2: Second vector
        Returns:
            Similarity score between 0 and 1
        """
        try:
            # Convert to numpy arrays for efficient calculation
            v1 = np.array(vec1)
            v2 = np.array(vec2)
            
            # Calculate cosine similarity
            dot_product = np.dot(v1, v2)
            norm1 = np.linalg.norm(v1)
            norm2 = np.linalg.norm(v2)
            
            if norm1 == 0 or norm2 == 0:
                return 0.0
                
            return dot_product / (norm1 * norm2)
            
        except Exception as e:
            logger.error(f"Error calculating similarity: {str(e)}")
            return 0.0

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

    def _estimate_token_count(self, text: str) -> int:
        """
        Approximate token count estimation
        (4 characters ~ 1 token on average)
        """
        return len(text) // 4

    def _optimize_chunk_size(self, code: str) -> int:
        """
        Optimize chunk size based on code
        """
        estimated_tokens = self._estimate_token_count(code)
        if estimated_tokens <= 7500:
            return len(code)
        
        return (7500 * len(code)) // estimated_tokens

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

def get_vulnerability_mapping():
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

def convert_md_to_pdf(markdown_file: Path, output_pdf: Path = None, 
                     output_html: Path = None) -> None:
    """
    Convert markdown file to PDF and optionally HTML
    Args:
        markdown_file: Path to markdown file
        output_pdf: Path for PDF output (default: same as markdown with .pdf)
        output_html: Path for HTML output (default: same as markdown with .html)
        debug: Enable debug logging
    """
    try:
        # Set default output paths if not provided
        if not output_pdf:
            output_pdf = markdown_file.with_suffix('.pdf')
        if not output_html:
            output_html = markdown_file.with_suffix('.html')

        # Read markdown content
        with open(markdown_file, 'r', encoding='utf-8') as f:
            markdown_content = f.read()

        # Convert markdown to HTML with page break extension
        html_content = markdown.markdown(
            markdown_content,
            extensions=['tables', 'fenced_code', 'codehilite', PageBreakExtension()]
        )

        # Add CSS styling with page break support
        html_template = f"""
        <html>
        <head>
            <style>
                @page {{
                    margin: 1cm;
                    size: A4;
                    @top-right {{
                        content: counter(page);
                    }}
                }}
                
                /* Force page break - multiple approaches */
                div[style*="page-break-after: always"],
                div.page-break {{
                    page-break-after: always !important;
                    break-after: page !important;
                    margin: 0 !important;
                    padding: 0 !important;
                    height: 0 !important;
                    visibility: hidden !important;
                }}
                
                body {{ 
                    font-family: Arial, sans-serif;
                    font-size: 11pt;
                    line-height: 1.4;
                    max-width: none;
                    margin: 0;
                    padding: 0;
                }}
                
                code {{
                    background-color: #f5f5f5;
                    padding: 2px 4px;
                    border-radius: 4px;
                    font-family: monospace;
                    font-size: 9pt;
                    word-wrap: break-word;
                    white-space: pre-wrap;
                }}
                
                pre {{
                    background-color: #f5f5f5;
                    padding: 1em;
                    border-radius: 4px;
                    margin: 1em 0;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                    font-size: 9pt;
                }}
                
                h1 {{ 
                    color: #2c3e50;
                    font-size: 20pt;
                    margin-top: 0;
                }}
                
                h2 {{ 
                    color: #34495e;
                    font-size: 16pt;
                    margin-top: 1em;
                }}
                
                h3 {{ 
                    color: #7f8c8d;
                    font-size: 14pt;
                }}
                
                p {{
                    margin: 0.5em 0;
                }}
                
                ul, ol {{
                    margin: 0.5em 0;
                    padding-left: 2em;
                }}
                
                table {{ 
                    border-collapse: collapse; 
                    width: 100%; 
                    margin: 1em 0;
                }}
                
                th, td {{ 
                    border: 1px solid #ddd; 
                    padding: 8px; 
                    text-align: left;
                }}
                
                th {{ 
                    background-color: #f5f5f5;
                    font-weight: bold;
                }}
                
                .risk-high {{ color: #d73a49; }}
                .risk-medium {{ color: #e36209; }}
                .risk-low {{ color: #2cbe4e; }}
            </style>
        </head>
        <body>
            {html_content}
        </body>
        </html>
        """

        # Save HTML file
        with open(output_html, 'w', encoding='utf-8') as f:
            f.write(html_template)

        # Convert HTML to PDF with page numbers
        HTML(string=html_template).write_pdf(
            output_pdf,
            stylesheets=[CSS(string='@page { margin: 1cm; size: A4; @top-right { content: counter(page); } }')]
        )

    except Exception as e:
        logger.error(f"Error converting markdown to PDF: {str(e)}")
        logger.debug("Full error:", exc_info=True)

def parse_input(input_path: str) -> List[Path]:
    """
    Parse input path and return list of files to analyze
    Args:
        input_path: Path to file, directory, or file containing paths
    Returns:
        List of Path objects to analyze
    """
    input_path = Path(input_path)
    files_to_analyze = []

    # Case 1: Input is a file containing paths
    if input_path.suffix == '.txt':
        try:
            with open(input_path, 'r') as f:
                paths = [line.strip() for line in f if line.strip()]
                for path in paths:
                    p = Path(path)
                    if p.is_file():
                        files_to_analyze.append(p)
                    elif p.is_dir():
                        files_to_analyze.extend(
                            f for f in p.rglob('*') 
                            if f.is_file()
                        )
        except Exception as e:
            logger.error(f"Error reading paths file: {str(e)}")
            return []

    # Case 2: Input is a single file
    elif input_path.is_file():
        files_to_analyze.append(input_path)

    # Case 3: Input is a directory
    elif input_path.is_dir():
        files_to_analyze.extend(
            f for f in input_path.rglob('*') 
            if f.is_file()
        )

    else:
        logger.error(f"Invalid input path: {input_path}")
        return []

    return files_to_analyze

def generate_markdown_report(vulnerability_type: str, results: List[Dict], 
                           output_file: Path, model_name: str) -> None:
    """
    Generate a markdown report for a vulnerability analysis
    Args:
        vulnerability_type: Type of vulnerability analyzed
        results: List of dicts containing file_path, similarity_score, and analysis
        output_file: Path to save the markdown report
        model_name: Name of the model used for analysis
    """
    try:
        # Create report header
        report = [
            f"# Security Analysis Report - {vulnerability_type}",
            f"\nAnalysis performed using model: **{model_name}**",
            f"\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "\n## Results\n"
        ]

        if not results:
            report.append("No potential vulnerabilities found.")
        else:
            # Add summary table
            report.extend([
                "### Summary Table",
                "| File | Similarity Score | Risk Level |",
                "|------|-----------------|------------|"
            ])

            # Add results sorted by similarity score
            for result in sorted(results, key=lambda x: x['similarity_score'], reverse=True):
                score = result['similarity_score']
                # Determine risk level based on similarity score
                if score >= 0.8:
                    risk = "High"
                elif score >= 0.6:
                    risk = "Medium"
                else:
                    risk = "Low"
                
                # Add table row
                report.append(
                    f"| `{result['file_path']}` | {score:.2f} | {risk} |"
                )

            # Add page break before detailed analysis
            report.extend([
                "\n<div class=\"page-break\"></div>\n",
                "## Detailed Analysis\n"
            ])

            # Add detailed analysis for each file
            for i, result in enumerate(sorted(results, key=lambda x: x['similarity_score'], reverse=True)):
                # Add page break before each file analysis (except the first one)
                if i > 0:
                    report.append("\n<div class=\"page-break\"></div>\n")
                
                report.extend([
                    f"### File: {result['file_path']}",
                    f"Similarity Score: {result['similarity_score']:.2f}\n",
                    result['analysis'],
                    "\n---\n"
                ])

            # Add page break before statistics
            report.extend([
                "\n<div class=\"page-break\"></div>\n",
                f"\n### Statistics",
                f"- Total files analyzed: {len(results)}",
                f"- High risk files: {sum(1 for r in results if r['similarity_score'] >= 0.8)}",
                f"- Medium risk files: {sum(1 for r in results if 0.6 <= r['similarity_score'] < 0.8)}",
                f"- Low risk files: {sum(1 for r in results if r['similarity_score'] < 0.6)}"
            ])

        # Add timestamp and model info at the bottom
        report.extend([
            "\n---",
            f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Model: {model_name}"
        ])

        # Write report to file
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))

    except Exception as e:
        logger.error(f"Error generating markdown report: {str(e)}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Full error:", exc_info=True)

def generate_executive_summary(all_results: Dict[str, List[Dict]], output_base_dir: Path, model_name: str) -> None:
    """
    Generate an executive summary of all vulnerabilities found
    Args:
        all_results: Dict mapping vulnerability types to their results
        output_base_dir: Base directory for the model's reports
        model_name: Name of the model used for analysis
    """
    try:
        # Create report header
        report = [
            "# Security Audit Executive Summary",
            f"\nAnalysis performed using model: **{model_name}**",
            f"\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "\n## Overview\n"
        ]

        # Add quick statistics
        total_files = len(set(result['file_path'] for results in all_results.values() for result in results))
        total_issues = sum(len(results) for results in all_results.values())
        
        report.extend([
            f"- Total files analyzed with issues: {total_files}",
            f"- Total potential vulnerabilities found: {total_issues}",
            "\n## Vulnerability Statistics\n",
            "| Vulnerability Type | Total | High | Medium | Low |",
            "|-------------------|-------|------|--------|-----|"
        ])

        # Calculate statistics for each vulnerability type
        for vuln_type, results in sorted(all_results.items()):
            high = sum(1 for r in results if r['similarity_score'] >= 0.8)
            medium = sum(1 for r in results if 0.6 <= r['similarity_score'] < 0.8)
            low = sum(1 for r in results if r['similarity_score'] < 0.6)
            total = len(results)
            
            # Add row only if there are findings
            if total > 0:
                report.append(
                    f"| {vuln_type} | {total} | {high} | {medium} | {low} |"
                )

        # Add total row
        total_high = sum(1 for results in all_results.values() 
                        for r in results if r['similarity_score'] >= 0.8)
        total_medium = sum(1 for results in all_results.values() 
                          for r in results if 0.6 <= r['similarity_score'] < 0.8)
        total_low = sum(1 for results in all_results.values() 
                       for r in results if r['similarity_score'] < 0.6)
        
        report.extend([
            f"| **TOTAL** | **{total_issues}** | **{total_high}** | **{total_medium}** | **{total_low}** |",
            "\n## Detailed Findings\n"
        ])

        # Group findings by severity
        severity_groups = {
            'High': [],
            'Medium': [],
            'Low': []
        }

        # Process each vulnerability type
        for vuln_type, results in all_results.items():
            for result in results:
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
                    f"\n### {severity} Risk Findings ({len(severity_groups[severity])} issues)",
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

        # Save reports in all formats
        summary_files = {
            'md': output_base_dir / 'markdown' / 'executive_summary.md',
            'pdf': output_base_dir / 'pdf' / 'executive_summary.pdf',
            'html': output_base_dir / 'html' / 'executive_summary.html'
        }

        # Write markdown
        with open(summary_files['md'], 'w', encoding='utf-8') as f:
            f.write('\n'.join(report))

        # Convert to PDF and HTML
        convert_md_to_pdf(
            markdown_file=summary_files['md'],
            output_pdf=summary_files['pdf'],
            output_html=summary_files['html']
        )

    except Exception as e:
        logger.error(f"Error generating executive summary: {str(e)}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Full error:", exc_info=True)

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

def calculate_similarity(embedding1: List[float], embedding2: List[float]) -> float:
    """
    Calculate cosine similarity between two embeddings
    Args:
        embedding1: First embedding vector
        embedding2: Second embedding vector
    Returns:
        Cosine similarity score (0-1)
    """
    # Convert to numpy arrays for efficient computation
    vec1 = np.array(embedding1)
    vec2 = np.array(embedding2)
    
    # Calculate cosine similarity
    dot_product = np.dot(vec1, vec2)
    norm1 = np.linalg.norm(vec1)
    norm2 = np.linalg.norm(vec2)
    
    if norm1 == 0 or norm2 == 0:
        return 0.0
        
    return float(dot_product / (norm1 * norm2))

def generate_audit_report(auditor: CodeSecurityAuditor, vulnerability_types: List[Dict], 
                         output_dir: Path, thresholds: List[float] = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]) -> None:
    """Generate audit report with parallel processing"""
    report = [
        "# Embeddings Distribution Analysis Report",
        f"\nDate: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"\nEmbedding Model: {auditor.embedding_model}",
        f"\nTotal Files Analyzed: {len(auditor.code_base)}",
        "\n## Analysis Results\n"
    ]
    output_dir = output_dir / 'audit'

    # Calculate optimal number of processes
    num_processes = min(cpu_count(), len(auditor.code_base))
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
            (file_path, data, vuln['name'], auditor.embedding_model)
            for file_path, data in auditor.code_base.items()
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
            matching_files = sum(1 for r in valid_results if r['similarity_score'] >= threshold)
            percentage = (matching_files / len(valid_results)) * 100 if valid_results else 0
            report.append(f"| {threshold:.1f} | {matching_files} | {percentage:.1f}% |")

        # Add top 5 most similar files
        report.extend([
            "\n#### Top 5 Most Similar Files",
            "| File | Similarity Score |",
            "|------|-----------------|"
        ])
        
        for result in valid_results[:5]:
            report.append(
                f"| `{result['file_path']}` | {result['similarity_score']:.3f} |"
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
        high = sum(1 for r in results if r['similarity_score'] >= 0.8)
        medium = sum(1 for r in results if 0.6 <= r['similarity_score'] < 0.8)
        low = sum(1 for r in results if r['similarity_score'] < 0.6)
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

def get_vulnerability_help() -> str:
    """Generate help text for vulnerability arguments"""
    vuln_map = get_vulnerability_mapping()
    vuln_list = []
    for tag, vuln in vuln_map.items():
        vuln_list.append(f"{tag:<8} - {vuln['name']}")

    return (
        "Vulnerability types to check (comma-separated).\n"
        + "Available tags:\n"
        + "\n".join(f"  {v}" for v in vuln_list)
        + "\n\nUse 'all' to check all vulnerabilities (default)"
    )

def get_available_models() -> List[str]:
    """
    Get list of available models from Ollama API
    Returns:
        List of model names
    """
    excluded_models = [
        'embed',
        'instructor',
        'text-',
        'minilm',
        'e5-',
        'cline'
    ]
    try:
        client = ollama.Client()
        models = client.list()
        # Filter out embedding models and sort in reverse order
        model_names = [
            model.get('model') 
            for model in models.get('models', [])
            if not any(pattern in model.get('model', '').lower() for pattern in excluded_models)
        ]
        model_names.sort(reverse=False)
        logger.debug(model_names)
        return model_names
    except Exception as e:
        logger.error(f"Error fetching models: {str(e)}")
        logger.debug("Full error:", exc_info=True)
        
        # Fallback to default models if API fails
        default_models = [
            'llama2',
            'llama2:13b',
            'codellama',
            'codellama:13b',
            'gemma:2b',
            'gemma:7b',
            'mistral',
            'mixtral'
        ]
        logger.warning(f"Using default model list: {', '.join(default_models)}")
        return default_models

def select_models(available_models: List[str]) -> List[str]:
    """
    Interactive model selection
    Args:
        available_models: List of available model names
    Returns:
        List of selected model names
    """
    logger.info("\nAvailable models:")
    for i, model in enumerate(available_models, 1):
        logger.info(f"{i}. {model}")
    
    while True:
        choice = input("\nSelect models (comma-separated numbers or 'all'): ").strip().lower()
        if choice == 'all':
            return available_models
        
        try:
            indices = [int(x.strip()) - 1 for x in choice.split(',')]
            selected = [available_models[i] for i in indices if 0 <= i < len(available_models)]
            if selected:
                return selected
        except (ValueError, IndexError):
            pass
        
        logger.error("Invalid selection. Please try again.")

def sanitize_model_name(model: str) -> str:
    """
    Sanitize model name for directory creation
    Args:
        model: Original model name (e.g. 'rfc/whiterabbitneo:latest')
    Returns:
        Sanitized name (e.g. 'whiterabbitneo_latest')
    """
    # Get the last part after the last slash (if any)
    base_name = model.split('/')[-1]
    # Replace any remaining special characters
    return base_name.replace(':', '_')

def check_ollama_connection() -> bool:
    """
    Check if Ollama server is running and accessible
    Returns:
        bool: True if connection is successful, False otherwise
    """
    try:
        client = ollama.Client()
        # Try to list models to verify connection
        client.list()
        return True
    except Exception as e:
        logger.error("Failed to connect to Ollama server")
        logger.error("Please make sure Ollama is running and accessible")
        logger.debug(f"Connection error: {str(e)}")
        return False

def analyze_embeddings_distribution(auditor: CodeSecurityAuditor, vulnerability_types: List[Dict], 
                                  thresholds: List[float] = [0.5, 0.6, 0.7, 0.8, 0.9]) -> None:
    """
    Analyze embeddings distribution for each vulnerability type
    Args:
        auditor: Initialized CodeSecurityAuditor
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
        for file_path, data in auditor.code_base.items():
            try:
                # Get embedding for vulnerability type
                vuln_response = auditor.client.embeddings(
                    model=auditor.embedding_model,
                    prompt=vuln['name']
                )
                
                if not vuln_response or 'embedding' not in vuln_response:
                    continue

                similarity = auditor.calculate_similarity(
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
            matching_files = sum(1 for _, score in results if score >= threshold)
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

def get_output_directory(input_path: Path, base_reports_dir: Path) -> Path:
    """
    Generate output directory path based on input path
    Args:
        input_path: Path being analyzed
        base_reports_dir: Base directory for security reports
    Returns:
        Path object for the output directory
    """
    # Convert input path to absolute path
    abs_input = input_path.absolute()
    
    # Create a sanitized directory name from the input path
    dir_name = abs_input.name
    if not dir_name:  # Handle root directory case Error during analysis
        dir_name = 'root'
    
    # Create timestamped directory to avoid overwrites
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = base_reports_dir / f"{dir_name}_{timestamp}"
    
    return output_dir

def display_logo():
    logo = """
     .d88b.    db    .d8888.  _\\\\|//_ .d8888. 
    .8P  Y8.  d88b   88'  YP    \\\\//  88'  YP 
    88    88 d8'`8b  `8bo.       ||     `8bo.   
    88    88 88ooo88   `Y8b.     ||       `Y8b. 
    `8b  d8' 88~~~88 db   8D    /||\\   db   8D 
     `Y88P'  YP  YP  `8888Y' __/_||_\\_ `8888Y' 

╔════════════════════════════════════════════════╗
║ Ollama Automated Security Intelligence Scanner ║
╚════════════════════════════════════════════════╝
"""
    logger.info(logo)

def detect_optimal_chunk_size(model: str) -> int:
    """
    Detect optimal chunk size by querying Ollama model parameters
    Args:
        model: Name of the embedding model
    Returns:
        Optimal chunk size in characters
    """
    try:
        client = ollama.Client()
        logger.debug(f"Querying model information for {model}...")
        
        # Query model information
        model_info = client.show(model)
        logger.debug(f"Raw model info type: {type(model_info)}")
        
        # Try to get num_ctx from parameters
        if hasattr(model_info, 'parameters'):
            params = model_info.parameters
            logger.debug(f"Parameters: {params}")
            
            if 'num_ctx' in params:
                context_length = int(params.split()[1])
                chunk_size = int(context_length * 0.9)
                logger.info(f"📏 Model {model} context length: {context_length}")
                logger.info(f"🔄 Using chunk size: {chunk_size}")
                return chunk_size
        
        # If we couldn't get the information, use a conservative default
        logger.warning(f"Could not detect context length for {model}, using default size: 2048")
        return 2048
        
    except Exception as e:
        logger.error(f"Error detecting chunk size: {str(e)}")
        logger.warning("Using conservative default chunk size: 2048")
        return 2048

def check_model_availability(model_name: str) -> bool:
    """
    Check if a model is available on Ollama server
    Args:
        model_name: Name of the model to check
    Returns:
        True if model is available, False otherwise
    """
    try:
        client = ollama.Client()
        models = client.list()
        return any(model.model == model_name for model in models.models)
    except Exception as e:
        logger.error(f"Error checking model availability: {str(e)}")
        return False

def install_model(model_name: str) -> bool:
    """
    Install a model from Ollama
    Args:
        model_name: Name of the model to install
    Returns:
        True if installation successful, False otherwise
    """
    try:
        client = ollama.Client()
        logger.info(f"Installing model {model_name}...")
        
        with tqdm(desc=f"Downloading {model_name}", unit='B', unit_scale=True, unit_divisor=1024) as pbar:
            for response in client.pull(model_name, stream=True):
                if 'status' in response:
                    status = response['status']
                    if 'completed' in status:
                        pbar.update(pbar.total - pbar.n)  # Complete the bar
                    elif 'pulling' in status:
                        if 'total' in response and 'completed' in response:
                            total = int(response['total'])
                            completed = int(response['completed'])
                            if pbar.total != total:
                                pbar.total = total
                            pbar.n = completed
                            pbar.refresh()
        
        logger.info(f"Model {model_name} installed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"Error installing model: {str(e)}")
        return False

def ensure_model_available(model_name: str) -> bool:
    """
    Ensure a model is available, prompt for installation if not
    Args:
        model_name: Name of the model to check/install
    Returns:
        True if model is available or successfully installed
    """
    if check_model_availability(model_name):
        logger.debug(f"Model {model_name} is available")
        return True
    
    logger.warning(f"Model {model_name} is not available")
    while True:
        response = input(f"\nModel {model_name} is not installed. Would you like to:\n"
                        "1. Install it now\n"
                        "2. Quit\n"
                        "Choose (1/2): ").strip()
        
        if response == "1":
            return install_model(model_name)
        elif response == "2":
            return False
        else:
            print("Invalid choice. Please enter 1 or 2.")

def main():
    # Parse command line arguments
    class CustomFormatter(argparse.RawDescriptionHelpFormatter):
        def _split_lines(self, text, width):
            if text.startswith('Vulnerability types'):
                return text.splitlines()
            return super()._split_lines(text, width)

    parser = argparse.ArgumentParser(
        description='OASIS - Ollama Automated Security Intelligence Scanner',
        formatter_class=CustomFormatter
    )
    parser.add_argument('input_path', type=str, 
                       help='Path to file, directory, or .txt file containing paths to analyze',
                       nargs='?')
    parser.add_argument('-t', '--threshold', type=float, default=0.5, 
                       help='Similarity threshold (default: 0.5)')
    parser.add_argument('-v', '--vulns', type=str, default='all', 
                       help=get_vulnerability_help())
    parser.add_argument('-np', '--no-pdf', action='store_true', 
                       help='Skip PDF generation')
    parser.add_argument('-d', '--debug', action='store_true',
                       help='Enable debug output')
    parser.add_argument('-s', '--silent', action='store_true',
                       help='Disable all output messages')
    parser.add_argument('-em', '--embed-model', type=str, default='nomic-embed-text:latest',
                      help='Model to use for embeddings (default: nomic-embed-text:latest)')
    parser.add_argument('-m', '--models', type=str,
                       help='Comma-separated list of models to use (bypasses interactive selection)')
    parser.add_argument('-lm', '--list-models', action='store_true',
                       help='List available models and exit')
    parser.add_argument('-x', '--extensions', type=str,
                       help='Comma-separated list of file extensions to analyze (e.g., "py,js,java")')
    parser.add_argument('-cc', '--clear-cache', action='store_true',
                       help='Clear embeddings cache before starting')
    parser.add_argument('-a', '--audit', action='store_true',
                       help='Run embedding distribution analysis')
    parser.add_argument('-cd', '--cache-days', type=int, default=7, 
                       help='Maximum age of cache in days (default: 7)')
    parser.add_argument('-ch', '--chunk-size', type=int,
                       help='Maximum size of text chunks for embedding (default: auto-detected)')

    args = parser.parse_args()
    
    # Setup logging BEFORE detecting chunk size
    setup_logging(debug=args.debug)
    
    # Auto-detect chunk size if not specified
    if args.chunk_size is None:
        args.chunk_size = detect_optimal_chunk_size(args.embed_model)
    else:
        logger.info(f"Using manual chunk size: {args.chunk_size}")

    # Check if --list-models is used
    if args.list_models:
        # Get available models
        available_models = get_available_models()
        if not available_models:
            logger.error("No models available. Please check Ollama installation.")
            return
        logger.info("\nAvailable models:")
        for model in available_models:
            logger.info(f"- {model}")
        return

    # Check if input_path is provided when not using --list-models
    if not args.input_path:
        parser.error("input_path is required when not using --list-models")

    # Check Ollama connection before proceeding
    if not check_ollama_connection():
        logger.error("\nError: Could not connect to Ollama server")
        logger.error("Please ensure that:")
        logger.error("1. Ollama is installed (https://ollama.ai)")
        logger.error("2. Ollama server is running (usually with 'ollama serve')")
        logger.error("3. Ollama is accessible (default: http://localhost:11434)")
        return

    if not args.audit:
        # Get available models
        available_models = get_available_models()
        if not available_models:
            logger.error("No models available. Please check Ollama installation.")
            return
        if args.list_models:
            logger.info("\nAvailable models:")
            for model in available_models:
                logger.info(f"- {model}")
            return

        # Select models to use
        if args.models:
            selected_models = [m.strip() for m in args.models.split(',')]
            # Check if the analysis models are available
            for model in selected_models:
                if not ensure_model_available(model):
                    logger.error(f"Analysis model {model} not available. Skipping.")
                    selected_models.remove(model)
            
            if not selected_models:
                logger.error("No analysis models available. Exiting.")
                return
        else:
            selected_models = select_models(available_models)

        logger.debug(f"Selected models: {', '.join(selected_models)}")

    # Check if the embedding model is available
    if not ensure_model_available(args.embed_model):
        logger.error("Embedding model not available. Exiting.")
        return
    
    # Get vulnerability mapping
    vuln_mapping = get_vulnerability_mapping()

    # Create base reports directory relative to input path
    base_reports_dir = Path(args.input_path).resolve().parent / "security_reports"
    base_reports_dir.mkdir(exist_ok=True)

    # Get specific output directory for this analysis
    output_dir = get_output_directory(Path(args.input_path), base_reports_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Parse extensions if provided
    custom_extensions = None
    if args.extensions:
        custom_extensions = [ext.strip().lower() for ext in args.extensions.split(',')]
        logger.debug(f"Using custom extensions: {', '.join(custom_extensions)}")

    # Create a single embeddings auditor for all models
    embedding_auditor = CodeSecurityAuditor(
        embedding_model=args.embed_model,
        llm_model=None,  # No need for LLM model here
        extensions=custom_extensions,
        chunk_size=args.chunk_size
    )
    
    # Set cache file path and load cache
    embedding_auditor.cache_file = Path(args.input_path).parent / "embeddings_cache.pkl"

    # Clear cache if requested
    if args.clear_cache:
        logger.info("Clearing embeddings cache...")
        embedding_auditor.clear_cache()

    embedding_auditor.load_cache()  # Load existing cache first
    
    # Generate embeddings once for all files
    files_to_analyze = parse_input(args.input_path)
    if not files_to_analyze:
        logger.error("No valid files to analyze")
        return

    # Filter files and generate embeddings only for new ones
    new_files = []
    for file_path in files_to_analyze:
        file_key = str(file_path)
        # Strict check of cache structure
        if (file_key not in embedding_auditor.code_base or 
            not isinstance(embedding_auditor.code_base[file_key], dict) or
            'embedding' not in embedding_auditor.code_base[file_key] or 
            'chunks' not in embedding_auditor.code_base[file_key] or
            'timestamp' not in embedding_auditor.code_base[file_key]):
            new_files.append(file_path)
            
    if new_files:
        logger.info(f"Generating embeddings for {len(new_files)} new files")
        embedding_auditor.index_code_files(new_files)
    else:
        logger.debug("All files found in cache with valid structure")

    # If audit mode is enabled, only analyze embeddings distribution
    if args.audit:
        logger.info("\nRunning in Audit Mode")
        logger.info("====================")

        # Get vulnerability types
        vuln_mapping = get_vulnerability_mapping()
        vulnerabilities = list(vuln_mapping.values())
        # Analyze embeddings distribution
        #analyze_embeddings_distribution(embedding_auditor, vulnerabilities)

        # Generate and save analysis report with progress indication
        logger.info("\nGenerating audit report...")
        report_files = generate_audit_report(
            embedding_auditor, 
            vulnerabilities,
            output_dir
        )
        
        logger.info("\nAudit analysis completed!")
        logger.info("\nReports generated:")
        for fmt, path in report_files.items():
            logger.info(f"- {fmt.upper()}: {path}")
        
        return

    # Analyze with each selected model
    for model in selected_models:
        logger.info(f"\nAnalyzing with model: {model}")

        # Create model-specific directory and its format subdirectories
        model_name = sanitize_model_name(model)
        model_dir = output_dir / model_name
        model_dir.mkdir(exist_ok=True)
        
        # Create format-specific directories under the model directory
        report_dirs = {
            'md': model_dir / 'markdown',
            'pdf': model_dir / 'pdf',
            'html': model_dir / 'html'
        }
        
        # Create all format directories
        for dir_path in report_dirs.values():
            dir_path.mkdir(exist_ok=True)

        # Create analysis auditor with shared embeddings
        analysis_auditor = CodeSecurityAuditor(
            embedding_model=args.embed_model,
            llm_model=model,
            extensions=custom_extensions,
            chunk_size=args.chunk_size
        )
        
        # Share the embeddings from the embedding auditor
        analysis_auditor.code_base = embedding_auditor.code_base
        analysis_auditor.cache_file = embedding_auditor.cache_file

        # Determine which vulnerabilities to check
        if args.vulns.lower() == 'all':
            vulnerabilities = list(vuln_mapping.values())
        else:
            selected_tags = [tag.strip() for tag in args.vulns.split(',')]
            invalid_tags = [tag for tag in selected_tags if tag not in vuln_mapping]
            if invalid_tags:
                logger.error(f"Invalid vulnerability tags: {', '.join(invalid_tags)}")
                logger.error("Use --help to see available tags")
                continue
            vulnerabilities = [vuln_mapping[tag] for tag in selected_tags]

        # Store all results for executive summary
        all_results = {}

        # Analysis for each vulnerability type
        with tqdm(total=len(vulnerabilities), 
                 desc="Analyzing vulnerabilities", 
                 disable=args.silent) as vuln_pbar:
            for vuln in vulnerabilities:
                # First, find potentially vulnerable files
                results = analysis_auditor.search_vulnerabilities(vuln['name'], threshold=args.threshold)
                
                # Then analyze each file in detail with progress bar
                detailed_results = []
                with tqdm(results, 
                         desc=f"Analyzing {vuln['name']} details", 
                         disable=args.silent,
                         leave=False) as file_pbar:
                    for file_path, similarity_score in file_pbar:
                        file_pbar.set_postfix_str(f"File: {Path(file_path).name}")
                        analysis = analysis_auditor.analyze_vulnerability(file_path, vuln['name'])
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
            generate_executive_summary(all_results, model_dir, model)

    # Print summary of generated files
    logger.info("\nAnalysis complete!")
    abs_report_path = os.path.abspath(output_dir)
    logger.info(f"\nReports have been generated in: {abs_report_path}")
    logger.info("\nGenerated files structure:")
    
    # Display only the models that were just analyzed
    for model in selected_models:
        model_name = sanitize_model_name(model)
        model_dir = output_dir / model_name
        if model_dir.is_dir():
            logger.info(f"\n{model_name}/")
            for fmt_dir in model_dir.glob('*'):
                if fmt_dir.is_dir():
                    logger.info(f"  └── {fmt_dir.name}/")
                    for report in fmt_dir.glob('*.*'):
                        logger.info(f"       └── {report.name}")

    logger.info(f"\nCache file: {embedding_auditor.cache_file}")

if __name__ == "__main__":
    display_logo()
    main()