from pathlib import Path
from typing import Union, Dict
from datetime import datetime
import hashlib
import pickle

from .enums import AnalysisMode, AnalysisType
from .tools import sanitize_name, logger

class CacheManager:
    """
    Manages caching operations for security analysis results
    """
    def __init__(self, input_path: Union[str, Path], llm_model: str, scan_model: str, cache_days: int):
        """
        Initialize the cache manager
        
        Args:
            input_path: Path to the input being analyzed
            llm_model: Main model name
            scan_model: Scanning model name
            cache_days: Number of days to keep cache files
        """
        self.cache_days = cache_days
        
        # Create base cache directory
        input_path = Path(input_path)
        if input_path.is_dir():
            self.cache_dir = input_path.parent / '.oasis_cache'
        else:
            self.cache_dir = input_path.parent / '.oasis_cache'
            
        self.cache_dir.mkdir(exist_ok=True)
        
        # Create model-specific cache directories
        self.model_cache_dir = self.cache_dir / sanitize_name(llm_model)
        self.model_cache_dir.mkdir(exist_ok=True)
        
        # Create scan model cache directory if different from main model
        if scan_model != llm_model:
            self.scan_model_cache_dir = self.cache_dir / sanitize_name(scan_model)
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
        
        # Validate cache files and clean expired ones
        self.validate_cache_expiration()
    
    def get_cache_path(self, file_path: str, mode: AnalysisMode, 
                     analysis_type: AnalysisType) -> Path:
        """
        Get the path to the cache file for a specific analyzed file
        
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
    
    def get_cache_dict(self, mode: AnalysisMode, analysis_type: AnalysisType) -> Dict:
        """
        Get the appropriate cache dictionary based on mode and type
        
        Args:
            mode: Analysis mode (scan or deep)
            analysis_type: Analysis type (standard or adaptive)
            
        Returns:
            Cache dictionary
        """
        if analysis_type == AnalysisType.ADAPTIVE:
            return self.adaptive_analysis_cache
            
        # Standard analysis cache selection
        if mode == AnalysisMode.SCAN:
            return self.scan_chunk_cache[analysis_type]
        return self.chunk_cache[analysis_type]
    
    def process_cache(self, action: str, file_path: str, mode: AnalysisMode, 
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
        cache_path = self.get_cache_path(file_path, mode, analysis_type)
        cache_dict = self.get_cache_dict(mode, analysis_type)
        
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
    
    def load_chunk_cache(self, file_path: str, mode: AnalysisMode = AnalysisMode.DEEP,
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
        return self.process_cache('load', file_path, mode, analysis_type)
            
    def save_chunk_cache(self, file_path: str, mode: AnalysisMode = AnalysisMode.DEEP,
                       analysis_type: AnalysisType = AnalysisType.STANDARD):
        """
        Save appropriate chunk cache for a specific file based on mode and analysis type
        
        Args:
            file_path: Path to the file
            mode: Analysis mode (scan or deep)
            analysis_type: Analysis type (standard or adaptive)
        """
        self.process_cache('save', file_path, mode, analysis_type)
    
    def has_caching_info(self, file_path: str, chunk: str, vuln_name: str, analysis_type: AnalysisType = AnalysisType.STANDARD) -> bool:
        """
        Check if we have enough info to cache this analysis
        
        Args:
            file_path: Path to the file
            chunk: Code chunk content
            vuln_name: Vulnerability name
            analysis_type: Type of analysis (standard or adaptive)
            
        Returns:
            True if we have enough info to cache
        """
        # For adaptive analysis, we only need file_path and vuln_name
        if analysis_type == AnalysisType.ADAPTIVE:
            return bool(file_path and vuln_name)
            
        # For standard analysis, we need all three
        return bool(file_path and chunk and vuln_name)
    
    def get_cached_analysis(self, file_path: str, chunk: str, vuln_name: str, prompt: str, 
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
        cache_dict = self.get_cache_dict(mode, analysis_type)
        if file_path not in cache_dict:
            self.load_chunk_cache(file_path, mode, analysis_type)
        
        chunk_key = self.generate_cache_key(chunk, prompt, vuln_name, file_path)
        
        # Check if analysis exists in cache
        return cache_dict[file_path].get(chunk_key)
    
    def store_analysis(self, file_path: str, chunk: str, vuln_name: str, prompt: str, result: str,
                     mode: AnalysisMode, analysis_type: AnalysisType):
        """
        Store analysis result in cache
        
        Args:
            file_path: Path to the file
            chunk: Code chunk content
            vuln_name: Vulnerability name
            prompt: Analysis prompt
            result: Analysis result
            mode: Analysis mode
            analysis_type: Analysis type
        """
        if not self.has_caching_info(file_path, chunk, vuln_name, analysis_type):
            return
            
        cache_dict = self.get_cache_dict(mode, analysis_type)
        if file_path not in cache_dict:
            cache_dict[file_path] = {}

        chunk_key = self.generate_cache_key(chunk, prompt, vuln_name, file_path)
        cache_dict[file_path][chunk_key] = result

        # Save cache after each analysis to allow resuming at any point
        self.save_chunk_cache(file_path, mode, analysis_type)
    
    def generate_cache_key(self, chunk: str, prompt: str, vuln_name: str, file_path: str = None) -> str:
        """
        Generate a cache key for a chunk
        
        Args:
            chunk: Code chunk content
            prompt: Analysis prompt
            vuln_name: Vulnerability name
            file_path: Path to the file (for adaptive analysis)
            
        Returns:
            Cache key
        """
        # For adaptive analysis (empty chunk)
        if not chunk:
            if file_path:
                return f"{sanitize_name(file_path)}_{sanitize_name(vuln_name)}"
            return sanitize_name(vuln_name)
            
        # For standard analysis
        chunk_hash = hashlib.md5(chunk.encode()).hexdigest()
        prompt_hash = hashlib.md5(prompt.encode()).hexdigest()
        return f"{chunk_hash}_{prompt_hash}_{sanitize_name(vuln_name)}"
    
    def clear_scan_cache(self, analysis_type: AnalysisType = None) -> None:
        """
        Clear scan cache files
        
        Args:
            analysis_type: Analysis type to clear (if None, clears all)
        """
        try:
            # Determine which cache directories to clear
            if analysis_type is None:
                # Clear only the current analysis type directories
                cache_dirs = [
                    self.standard_cache_dir[AnalysisMode.SCAN] if AnalysisType.STANDARD in self.scan_chunk_cache else None,
                    self.standard_cache_dir[AnalysisMode.DEEP] if AnalysisType.STANDARD in self.chunk_cache else None,
                    self.adaptive_cache_dir[AnalysisMode.SCAN] if AnalysisType.ADAPTIVE in self.scan_chunk_cache else None,
                    self.adaptive_cache_dir[AnalysisMode.DEEP] if AnalysisType.ADAPTIVE in self.chunk_cache else None
                ]
            else:
                # Clear only the specified analysis type
                cache_dirs = [
                    self.standard_cache_dir[AnalysisMode.SCAN] if analysis_type == AnalysisType.STANDARD else None,
                    self.standard_cache_dir[AnalysisMode.DEEP] if analysis_type == AnalysisType.STANDARD else None,
                    self.adaptive_cache_dir[AnalysisMode.SCAN] if analysis_type == AnalysisType.ADAPTIVE else None,
                    self.adaptive_cache_dir[AnalysisMode.DEEP] if analysis_type == AnalysisType.ADAPTIVE else None
                ]
            cache_dirs = [d for d in cache_dirs if d is not None]
            if not cache_dirs:
                logger.warning("No cache directories to clear")
                return

            # Delete all cache files in these directories
            files_count = 0
            for cache_dir in cache_dirs:
                if cache_dir.exists():
                    for cache_file in cache_dir.glob("*.cache"):
                        cache_file.unlink()
                        files_count += 1

            # Reset cache dictionaries for the current session
            if analysis_type is None or analysis_type == AnalysisType.STANDARD:
                self.chunk_cache[AnalysisType.STANDARD] = {}
                self.scan_chunk_cache[AnalysisType.STANDARD] = {}

            if analysis_type is None or analysis_type == AnalysisType.ADAPTIVE:
                self.chunk_cache[AnalysisType.ADAPTIVE] = {}
                self.scan_chunk_cache[AnalysisType.ADAPTIVE] = {}
                self.adaptive_analysis_cache = {}

            logger.info(f"Cleared {files_count} scan cache files")

        except Exception as e:
            logger.exception(f"Error clearing scan cache: {str(e)}")
    
    def validate_cache_expiration(self):
        """
        Check all cache files and remove expired ones based on cache_days setting
        """
        try:
            # Get current time
            now = datetime.now()
            expired_count = 0
            
            # Check both standard and adaptive cache directories
            all_cache_dirs = list(self.standard_cache_dir.values()) + list(self.adaptive_cache_dir.values())
            
            for cache_dir in all_cache_dirs:
                if not cache_dir.exists():
                    continue
                    
                # Check each cache file in this directory
                for cache_file in cache_dir.glob("*.cache"):
                    # Get file modification time
                    mod_time = datetime.fromtimestamp(cache_file.stat().st_mtime)
                    cache_age = now - mod_time
                    
                    # Check if file is older than cache_days
                    if cache_age.days > self.cache_days:
                        try:
                            cache_file.unlink()
                            expired_count += 1
                        except Exception as e:
                            logger.warning(f"Could not delete expired cache file {cache_file}: {e}")
            
            if expired_count > 0:
                logger.info(f"Removed {expired_count} expired cache files older than {self.cache_days} days")
            
        except Exception as e:
            logger.exception(f"Error validating cache expiration: {str(e)}")
