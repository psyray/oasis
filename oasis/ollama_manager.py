import contextlib
import threading
import ollama
from typing import List, Optional, Any
from tqdm import tqdm
import logging

# Import from configuration
from .config import MODEL_EMOJIS,OLLAMA_URL, EXCLUDED_MODELS, DEFAULT_MODELS, MAX_CHUNK_SIZE

# Import from other modules
from .tools import logger

class OllamaManager:
    """
    Class for managing Ollama interactions and model operations

    Args:
        api_url: URL for Ollama API
    """
    
    def __init__(self, api_url: str = OLLAMA_URL):
        """
        Initialize the Ollama manager
        
        Args:
            api_url: URL for Ollama API
        """
        self.client = None
        self.api_url = api_url
        self.excluded_models = EXCLUDED_MODELS
        self.default_models = DEFAULT_MODELS
        self._client_lock = threading.Lock()
        self.formatted_models = []
        # Cache for storing model information to avoid repeated API calls
        self._model_info_cache = {}
    
    def get_client(self) -> ollama.Client:
        """
        Get the Ollama client instance, checking connection first
        
        Returns:
            ollama.Client: Connected Ollama client
            
        Raises:
            ConnectionError: If Ollama server is not accessible
        """
        with self._client_lock:
            if not self.client:
                try:
                    self.client = ollama.Client(self.api_url)
                    # Try to list models to verify connection
                    self.client.list()
                except Exception as e:
                    self._log_connection_error(e)
                    raise ConnectionError(f"Cannot connect to Ollama server: {str(e)}") from e
        return self.client
    
    def check_connection(self) -> bool:
        """
        Check if Ollama server is running and accessible

        Returns:
            bool: True if connection is successful, False otherwise
        """
        try:
            self.get_client()
            return True
        except ConnectionError:
            return False
    
    def get_available_models(self, show_formatted: bool = False) -> List[str]:
        """
        Get list of available models from Ollama API

        Args:
            show_formatted: If True, show formatted model list with progress
        Returns:
            List of model names
        """
        try:
            model_names = self._get_models(self.excluded_models)
            
            # If requested, display formatted list
            if self.formatted_models:
                return self.formatted_models

            if show_formatted and model_names:
                self.formatted_models = self.format_model_display_batch(model_names)
                logger.info("\nAvailable models:")
                for i, (model_name, formatted_model) in enumerate(zip(model_names, self.formatted_models), 1):
                    # Align model numbers with proper spacing
                    prefix = " " if i < 10 else ""
                    logger.info(f"{prefix}{i}. {formatted_model}")
                    logger.info(f"       Use with --models: '{model_name}' or '{i}'")
            return model_names
        except Exception as e:
            logger.exception(f"Error fetching models: {str(e)}")
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Full error:", exc_info=True)

            logger.warning(f"Using default model list: {', '.join(self.default_models)}")
            return self.default_models
    
    def _get_models(self, excluded_models: List[str]) -> List[str]:
        """
        Get filtered list of models from Ollama
        
        Args:
            excluded_models: List of patterns to exclude from model names
            
        Returns:
            List of available model names
        """
        try:
            client = self.get_client()
            models = client.list()
            # Filter out embedding models and sort in reverse order
            model_names = [
                model.get('model')
                for model in models.get('models', [])
                if all(
                    pattern not in model.get('model', '').lower()
                    for pattern in excluded_models
                )
            ]
            model_names.sort(reverse=False)
            logger.debug(", ".join(model_names))
            return model_names
        except ConnectionError as e:
            logger.exception(f"Connection error while getting models: {str(e)}")
            raise
    
    def _get_model_info(self, model: str):
        """
        Get detailed information about a model from Ollama API
        Uses a cache to avoid repeated API calls for the same model

        Args:
            model: Name of the model
            
        Returns:
            Model information from Ollama API or cache
        """
        # Check if the model info is already in the cache
        if model in self._model_info_cache:
            logger.debug(f"Using cached model information for {model}")
            return self._model_info_cache[model]
            
        # Not in cache, query the API
        client = self.get_client()
        logger.debug(f"Querying model information for {model} from Ollama API...")
        
        try:
            model_info = client.show(model)
            # Store in cache for future use
            self._model_info_cache[model] = model_info
            return model_info
        except Exception as e:
            logger.warning(f"Error fetching model info for {model}: {str(e)}")
            # Return empty dict to avoid further errors
            return {}
            
    def clear_model_cache(self, model: str = None):
        """
        Clear the model information cache
        
        Args:
            model: Optional specific model to clear from cache.
                  If None, clears the entire cache.
        """
        if model:
            if model in self._model_info_cache:
                logger.debug(f"Clearing cache for model: {model}")
                del self._model_info_cache[model]
        else:
            logger.debug("Clearing entire model information cache")
            self._model_info_cache = {}
        
    def detect_optimal_chunk_size(self, model: str) -> int:
        """
        Detect optimal chunk size by querying Ollama model parameters

        Args:
            model: Name of the embedding model
        Returns:
            Optimal chunk size in characters
        """
        try:
            return self._detect_optimal_chunk_size(model)
        except Exception as e:
            logger.exception(f"Error detecting chunk size: {str(e)}")
            logger.debug("Using default chunk size", exc_info=True)
            return MAX_CHUNK_SIZE

    def _detect_optimal_chunk_size(self, model):
        model_info = self._get_model_info(model)
        logger.debug(f"Raw model info type: {type(model_info)}")

        if hasattr(model_info, 'parameters'):
            params = model_info.parameters
            logger.debug(f"Parameters: {params}")

        if 'num_ctx' in params:
            context_length = int(params.split()[1])
            chunk_size = int(context_length * 0.9)
            logger.info(f"Model {model} context length: {context_length}")
            logger.info(f"🔄 Using chunk size: {chunk_size}")
            return chunk_size

        logger.warning(f"Could not detect context length for {model}, using default size: {MAX_CHUNK_SIZE}")
        return MAX_CHUNK_SIZE
    
    def select_models(self, available_models: List[str], show_formatted: bool = True, max_models: int = None, msg: str = "") -> List[str]:
        """
        Let user select models interactively

        Args:
            available_models: List of available model names
            show_formatted: Whether to show formatted model names
            max_models: Maximum number of models to select
        Returns:
            List of selected model names
        """
        if not available_models:
            logger.error("No models available for selection")
            return []
            
        # Format models if requested
        if show_formatted:
            formatted_models = self.format_model_display_batch(available_models)
        else:
            formatted_models = available_models
            
        # Display available models
        logger.info("\nAvailable models:")
        for i, (model_name, formatted_name) in enumerate(zip(available_models, formatted_models), 1):
            logger.info(f"{i}. {formatted_name}")
        
        limit_text = f" (max {max_models})" if max_models else ""
            
        # Get user input for model selection
        try:
            selected_models = []
            while len(selected_models) < (max_models or len(available_models)):
                logger.info(f"{msg}")
                selection = input(f"\nEnter model numbers separated by comma (e.g., 1,3,5), or 'all'{limit_text}: ")
                
                # Handle 'all' case
                if selection.strip().lower() == 'all':
                    if max_models:
                        logger.error(f"You can only select up to {max_models} models")
                        continue
                    logger.info(f"Selected all {len(available_models)} models")
                    return available_models
                    
                # Parse selected indices
                try:
                    selected_indices = [int(idx.strip()) for idx in selection.split(',') if idx.strip()]
                    # Convert to 0-based indices
                    selected_indices = [idx - 1 for idx in selected_indices]
                    
                    # Check if all indices are valid
                    if not all(0 <= idx < len(available_models) for idx in selected_indices):
                        logger.error(f"Invalid selection. Numbers must be between 1 and {len(available_models)}")
                        continue
                    
                    # Check max_models limit
                    if max_models and len(selected_indices) > max_models:
                        logger.error(f"You can only select up to {max_models} models")
                        continue
                        
                    # Get corresponding model names
                    selected_models = [available_models[idx] for idx in selected_indices]
                    
                    if not selected_models:
                        logger.error("No models selected")
                        continue
                        
                    logger.debug(f"Selected models: {', '.join(selected_models)}")
                    return selected_models
                    
                except ValueError:
                    logger.error("Invalid input. Please enter numbers separated by commas")
                    
        except KeyboardInterrupt:
            logger.info("\nModel selection interrupted")
            return []
    
    def format_model_display(self, model_name: str) -> str:
        """
        Format a model name with emoji and technical info
        
        Args:
            model_name: Name of the model
            
        Returns:
            Formatted string with emoji and technical info
        """
        try:
            # Get model information using Ollama API
            model_info = self._get_model_info(model_name)
            
            # Extract emoji, parameters, context, and parent model info
            model_emoji = self._get_model_emoji(model_name)
            param_str = self._extract_model_parameters(model_info) or ""
            ctx_str = self._extract_token_context(model_info) or ""
            parent_info = self._extract_parent_model_info(model_info)
            
            # Build final formatted string
            return self._build_formatted_string(model_name, model_emoji, param_str, ctx_str, parent_info)
            
        except Exception as e:
            # Fallback to simple formatting if API fails
            logger.exception(f"Error fetching model details: {str(e)}")
            model_emoji = self._get_model_emoji(model_name)
            return f"{model_emoji}{model_name.split(':')[0]}"
    
    def _preload_model_info(self, model_names: List[str]) -> None:
        """
        Preload information for multiple models at once to reduce API calls
        
        Args:
            model_names: List of model names to preload information for
        """
        models_to_load = [m for m in model_names if m not in self._model_info_cache]
        
        if not models_to_load:
            logger.debug("All models already cached, no need to preload")
            return
            
        logger.debug(f"Preloading information for {len(models_to_load)} models")
        client = self.get_client()
        
        for model in tqdm(models_to_load, desc="Preloading model info", unit="model"):
            try:
                if model not in self._model_info_cache:
                    model_info = client.show(model)
                    self._model_info_cache[model] = model_info
            except Exception as e:
                logger.warning(f"Error preloading model info for {model}: {str(e)}")
                # Use empty dict to avoid repeated attempts
                self._model_info_cache[model] = {}
    
    def format_model_display_batch(self, model_names: List[str]) -> List[str]:
        """
        Format multiple model names
        
        Args:
            model_names: List of model names to format
            
        Returns:
            List of formatted model strings
        """
        logger.info("Getting detailed model information...")
        
        # Preload model information to reduce API calls
        self._preload_model_info(model_names)
        
        # Now format each model using the cached information
        return [self.format_model_display(model) for model in model_names]
    
    def _filter_lightweight_models(self, models: List[str]) -> List[str]:
        """
        Filter models to only include lightweight models (less than 10B parameters)
        
        Args:
            models: List of model names to filter
            
        Returns:
            List of lightweight model names
        """
        if not models:
            return []

        # Preload model information to reduce API calls
        self._preload_model_info(models)

        lightweight_models = []

        for model in models:
            try:
                # Get model information from cache
                model_info = self._get_model_info(model)
                parameters = 0

                # Extract parameter count using the same robust handling as in _extract_model_parameters
                try:
                    # Check if model_info is a dictionary (newer Ollama API format)
                    if isinstance(model_info, dict):
                        # First check if 'details' contains parameter info
                        if 'details' in model_info and model_info['details']:
                            details = model_info['details']
                            if isinstance(details, dict) and 'parameter_size' in details:
                                param_size = details['parameter_size']
                                if isinstance(param_size, str) and 'B' in param_size:
                                    parameters = float(param_size.replace('B', '')) * 1_000_000_000
                                elif isinstance(param_size, str) and 'M' in param_size:
                                    parameters = float(param_size.replace('M', '')) * 1_000_000
                                else:
                                    parameters = float(param_size)

                        # Then check if 'modelinfo' contains parameter count
                        if parameters == 0 and 'modelinfo' in model_info and model_info['modelinfo']:
                            modelinfo = model_info['modelinfo']
                            if isinstance(modelinfo, dict) and 'general.parameter_count' in modelinfo:
                                parameters = int(modelinfo['general.parameter_count'])

                    elif hasattr(model_info, 'details') and model_info.details:
                        details = model_info.details
                        if hasattr(details, 'parameter_size') and details.parameter_size:
                            with contextlib.suppress(ValueError, TypeError):
                                # Handle strings like "8.0B"
                                param_size = details.parameter_size
                                if isinstance(param_size, str) and 'B' in param_size:
                                    parameters = float(param_size.replace('B', '')) * 1_000_000_000
                                elif isinstance(param_size, str) and 'M' in param_size:
                                    parameters = float(param_size.replace('M', '')) * 1_000_000
                                else:
                                    parameters = float(param_size)
                    # Also check in modelinfo attribute
                    if parameters == 0 and hasattr(model_info, 'modelinfo') and model_info.modelinfo:
                        modelinfo = model_info.modelinfo
                        if isinstance(modelinfo, dict) and 'general.parameter_count' in modelinfo:
                            with contextlib.suppress(ValueError, TypeError):
                                parameters = int(modelinfo['general.parameter_count'])
                except Exception as inner_e:
                    logger.debug(f"Error parsing parameter information for {model}: {str(inner_e)}")
                    # If we can't parse, assume it's a lightweight model
                    parameters = 0

                # Add to lightweight models if less than 10B parameters or unknown size
                if parameters == 0 or parameters <= 10_000_000_000:
                    lightweight_models.append(model)

            except Exception as e:
                # If we can't get model info, include it by default
                logger.debug(f"Could not get parameter info for {model}: {str(e)}")
                lightweight_models.append(model)

        return lightweight_models
    
    def select_analysis_type(self) -> str:
        """
        Let user select analysis type interactively
        
        Returns:
            Selected analysis type ('standard' or 'adaptive')
        """
        logger.info("\n==== ANALYSIS TYPE SELECTION ====")
        logger.info("\nSelect the type of vulnerability analysis to perform:")
        logger.info("1. Standard - Two-phase analysis (quick scan, then deep analysis)")
        logger.info("2. Adaptive - Multi-level analysis that adjusts depth based on risk assessment")
        
        while True:
            try:
                selection = input("\nEnter your choice (1 or 2): ")
                
                if selection.strip() == "1":
                    logger.info("Selected standard analysis")
                    return "standard"
                elif selection.strip() == "2":
                    logger.info("Selected adaptive analysis")
                    return "adaptive"
                else:
                    logger.error("Invalid selection. Please enter 1 or 2.")
            except KeyboardInterrupt:
                logger.info("\nAnalysis type selection interrupted")
                return "standard"  # Default to standard if interrupted
    
    def select_analysis_models(self, args, available_models):
        """
        Select models for security analysis
        
        Args:
            args: Command line arguments
            available_models: List of available models
            
        Returns:
            Dictionary with selected models, containing 'scan_model' and 'main_models' keys
        """
        if not args.models:
            # First, select analysis type if not specified
            if not hasattr(args, 'adaptive') or not args.adaptive:
                analysis_type = self.select_analysis_type()
                # Set the adaptive flag based on selection
                args.adaptive = (analysis_type == "adaptive")
                
                if args.adaptive:
                    logger.info("Using adaptive analysis mode for enhanced risk-based scanning")
                else:
                    logger.info("Using standard two-phase analysis mode")
            
            # Let user select models interactively - first scan model, then main model
            logger.info("\n==== MODEL SELECTION ====")
            
            # First, select the scan model - only show lightweight models
            lightweight_models = self._filter_lightweight_models(available_models)
            if not lightweight_models:
                logger.warning("No lightweight models found, displaying all available models.")
                lightweight_models = available_models
            else:
                logger.info(f"Filtering models to display only lightweight models (< 10B parameters): {len(lightweight_models)} models found.")
            
            msg = "\nFirst, for your quick scan (initial filtering), you should choose a lightweight model (< 10B parameters):"
            scan_model = self.select_models(lightweight_models, show_formatted=True, max_models=1, msg=msg)
            if not scan_model:
                return None
                
            # Then, select the main analysis model - show all models
            msg = "\nThen, choose your main model for deep vulnerability analysis:"
            main_model = self.select_models(available_models, show_formatted=True, msg=msg)
            if not main_model:
                return None
                
            # Combine models, ensuring no duplicates
            selected_models = scan_model + [m for m in main_model if m not in scan_model]
            
            # send a structured dictionary:
            result = {
                'scan_model': None,
                'main_models': []
            }
            
            # If the user specified a scan_model via the -sm argument, use it
            if hasattr(args, 'scan_model') and args.scan_model:
                result['scan_model'] = args.scan_model
            # Otherwise, if models were selected interactively, use the first as scan_model
            elif selected_models:
                result['scan_model'] = selected_models[0]
            
            # For the main models:
            # If the user specified models via the -m argument, use them
            if hasattr(args, 'model') and args.model:
                if isinstance(args.model, list):
                    result['main_models'] = args.model
                else:
                    result['main_models'] = [args.model]
            # Otherwise, if multiple models were selected interactively, use the others (after the first)
            elif len(selected_models) > 1:
                result['main_models'] = selected_models[1:]
            # If only one model was selected (and it's already used as scan_model), use it also as main_model
            elif selected_models:
                result['main_models'] = [selected_models[0]]
            
            return result

        if args.models.lower().strip() == "all":
            return available_models

        # Parse comma-separated list of models or indices
        requested_items = [item.strip() for item in args.models.split(',')]
        selected_models = []

        for item in requested_items:
            # Check if item is a number (index)
            if item.isdigit():
                index = int(item) - 1  # Convert to 0-based index
                if 0 <= index < len(available_models):
                    selected_models.append(available_models[index])
                else:
                    logger.error(f"Invalid model index: {item} (must be between 1 and {len(available_models)})")
                    return None
            elif item in available_models:
                selected_models.append(item)
            elif self.ensure_model_available(item):
                selected_models.append(item)
            else:
                logger.error(f"Model not available: {item}")
                logger.error("Use --list-models to see available models")
                return None

        logger.info(f"Using specified models: {', '.join(selected_models)}")
        return selected_models

    def ensure_model_available(self, model: str) -> bool:
        """
        Ensure a model is available, pull if needed

        Args:
            model: Model name to check/pull
        Returns:
            True if model is available, False if error
        """
        try:
            client = self.get_client()
            available_models = self._get_models([])
            
            # Check if model is already available
            if model in available_models:
                logger.debug(f"Model {model} is already available")
                return True
                
            # Model not available, try to pull it
            logger.info(f"🤖 Model {model} not found locally, pulling from Ollama library...")

            try:
                with tqdm(desc=f"Downloading {model}", unit='B', unit_scale=True, unit_divisor=1024) as pbar:
                    for response in client.pull(model, stream=True):
                        if 'status' in response:
                            status = response['status']
                            if 'completed' in status:
                                if 'completed' in response:
                                    completed = int(response['completed'])
                                    delta = completed - pbar.n
                                    if delta > 0:
                                        pbar.update(delta)
                                else:
                                    pbar.update(pbar.total - pbar.n)  # Fallback update if no detailed progress available
                            elif 'pulling' in status:
                                if 'total' in response and 'completed' in response:
                                    total = int(response['total'])
                                    completed = int(response['completed'])
                                    if pbar.total != total:
                                        pbar.total = total
                                    pbar.n = completed
                                    pbar.refresh()

                logger.info(f"Successfully pulled model {model}")
                
                # Clear the model cache entry if it exists to force a refresh
                self.clear_model_cache(model)
                
                return True
                
            except Exception as pull_error:
                logger.exception(f"Failed to pull model {model}: {str(pull_error)}")
                logger.error("Please check that the model name is correct and available from Ollama")
                return False
                
        except Exception as e:
            logger.exception(f"Error checking model availability: {str(e)}")
            return False

    def _log_connection_error(self, error):
        """
        Log detailed Ollama connection error messages

        Args:
            error: Exception
        """
        logger.error("\nError: Could not connect to Ollama server")
        logger.info("Please ensure that:")
        logger.info("1. Ollama is installed (https://ollama.ai)")
        logger.info("2. Ollama server is running (usually with 'ollama serve')")
        logger.info(f"3. Ollama is accessible ({self.api_url})")
        logger.debug(f"Connection error: {str(error)}")

    def _extract_model_parameters(self, model_info: Any) -> Optional[str]:
        """
        Extract and format parameter information from model info

        Args:
            model_info: Model information
        Returns:
            Formatted parameter information
        """
        parameters = 0
        
        # Handle different types of responses from Ollama API
        try:
            # 1. Check if model_info is a dictionary (newer Ollama API format)
            if isinstance(model_info, dict):
                # First check if 'details' contains parameter info
                if 'details' in model_info and model_info['details']:
                    details = model_info['details']
                    if isinstance(details, dict) and 'parameter_size' in details:
                        param_size = details['parameter_size']
                        if isinstance(param_size, str) and 'B' in param_size:
                            parameters = float(param_size.replace('B', '')) * 1_000_000_000
                        elif isinstance(param_size, str) and 'M' in param_size:
                            parameters = float(param_size.replace('M', '')) * 1_000_000
                        else:
                            parameters = float(param_size)
                
                # Then check if 'modelinfo' contains parameter count
                if parameters == 0 and 'modelinfo' in model_info and model_info['modelinfo']:
                    modelinfo = model_info['modelinfo']
                    if isinstance(modelinfo, dict) and 'general.parameter_count' in modelinfo:
                        parameters = int(modelinfo['general.parameter_count'])
                        
            # 2. Check if model_info is an object with attributes (older format)
            elif hasattr(model_info, 'details') and model_info.details:
                details = model_info.details
                if hasattr(details, 'parameter_size') and details.parameter_size:
                        try:
                            # Handle strings like "8.0B"
                            param_size = details.parameter_size
                            if isinstance(param_size, str) and 'B' in param_size:
                                parameters = float(param_size.replace('B', '')) * 1_000_000_000
                            elif isinstance(param_size, str) and 'M' in param_size:
                                parameters = float(param_size.replace('M', '')) * 1_000_000
                            else:
                                parameters = float(param_size)
                        except (ValueError, TypeError):
                            pass

            # Also check in modelinfo attribute
            if parameters == 0 and hasattr(model_info, 'modelinfo') and model_info.modelinfo:
                modelinfo = model_info.modelinfo
                if isinstance(modelinfo, dict) and 'general.parameter_count' in modelinfo:
                        try:
                            parameters = int(modelinfo['general.parameter_count'])
                        except (ValueError, TypeError):
                            pass
        
        except Exception as e:
            logger.debug(f"Error extracting parameters: {str(e)}")
            return ""

        # Format parameter count in billions or millions
        if parameters >= 1_000_000_000:
            param_str = f"{parameters/1_000_000_000:.1f}B params"
            # Add turtle emoji for models larger than 26B
            if parameters > 26_000_000_000:
                param_str = f"🐢 {param_str}"
            # Add fast emoji for models with parameters <= 10B
            if parameters <= 10_000_000_000:
                param_str = f"⚡ {param_str}"
            return param_str
        elif parameters > 0:
            # Small models are considered fast
            return f"⚡ {parameters:,} params"
        return ""
    
    def _extract_token_context(self, model_info: Any) -> Optional[str]:
        """
        Extract token context window size from model info

        Args:
            model_info: Model information
        Returns:
            Formatted token context window size
        """
        try:
            # Check for dictionary format (newer API)
            if isinstance(model_info, dict):
                if 'parameters' in model_info and model_info['parameters']:
                    parameters = model_info['parameters']
                    if isinstance(parameters, dict) and 'num_ctx' in parameters:
                        ctx_size = int(parameters['num_ctx'])
                        if ctx_size >= 1000:
                            return f"{ctx_size // 1000}k context"
                        else:
                            return f"{ctx_size} context"
                    
                # Check for object format (older API)
                elif hasattr(model_info, 'parameters'):
                    parameters = model_info.parameters
                    if parameters and isinstance(parameters, dict) and 'num_ctx' in parameters:
                        ctx_size = int(parameters['num_ctx'])
                        if ctx_size >= 1000:
                            return f"{ctx_size // 1000}k context"
                        else:
                            return f"{ctx_size} context"
        except Exception as e:
            logger.debug(f"Error extracting context window: {str(e)}")
        
        return None
    
    def _extract_parent_model_info(self, model_info: Any, default_emoji: str = "🤖 ") -> str:
        """
        Extract and format parent model information

        Args:
            model_info: Model information
            default_emoji: Default emoji to use if no match
        """
        try:
            # Check for dictionary format (newer API)
            if isinstance(model_info, dict):
                if ('details' in model_info and model_info['details'] and 
                    isinstance(model_info['details'], dict) and 
                    'parent_model' in model_info['details'] and 
                    model_info['details']['parent_model']):
                    
                    parent_model = model_info['details']['parent_model']
                    parent_lower = parent_model.lower()
                    # Extract base name without version
                    parent_basename = parent_lower.split('/')[-1].split(':')[0]

                    # Get emoji for parent model
                    parent_emoji = next(
                        (
                            emoji
                            for model_id, emoji in MODEL_EMOJIS.items()
                            if model_id in parent_basename or model_id in parent_lower
                        ),
                        default_emoji,
                    )
                    
                    # Return formatted parent model info
                    return f"{parent_emoji}{parent_model.split(':')[0]}"
            
            # Check for object format (older API)
            elif (hasattr(model_info, 'details') and model_info.details and 
                  hasattr(model_info.details, 'parent_model') and 
                  model_info.details.parent_model):
                
                    parent_model = model_info.details.parent_model
                    parent_lower = parent_model.lower()
                    # Extract base name without version
                    parent_basename = parent_lower.split('/')[-1].split(':')[0]

                    # Get emoji for parent model
                    parent_emoji = next(
                        (
                            emoji
                            for model_id, emoji in MODEL_EMOJIS.items()
                            if model_id in parent_basename or model_id in parent_lower
                        ),
                        default_emoji,
                    )
                    
                    # Return formatted parent model info
                    return f"{parent_emoji}{parent_model.split(':')[0]}"
        
        except Exception as e:
            logger.debug(f"Error extracting parent model info: {str(e)}")
        
        return ""
    
    def _build_formatted_string(self, model_name: str, model_emoji: str, param_str: str, ctx_str: str, parent_info: str = "") -> str:
        """
        Build the final formatted string with all available information

        Args:
            model_name: Name of the model
            model_emoji: Emoji for the model
            param_str: Formatted parameter information
        """
        # Remove version tag (everything after colon) for display only
        display_name = model_name.split(':')[0]
        
        formatted_parts = [f"{model_emoji}{display_name}"]
        
        # Format technical info parts
        tech_info_parts = []
        if param_str:
            tech_info_parts.append(param_str)
        if ctx_str:
            tech_info_parts.append(ctx_str)
        if parent_info:
            tech_info_parts.append(f"based on {parent_info}")
        
        # Add technical info if available
        if tech_info_parts:
            formatted_parts.append(f"({', '.join(tech_info_parts)})")
        
        return " ".join(formatted_parts)
    
    def get_model_display_name(self, model_name: str) -> str:
        """
        Get a display name for a model with appropriate emoji
        
        Args:
            model_name: Raw model name
            
        Returns:
            Formatted model name with emoji
        """
        emoji = self._get_model_emoji(model_name)
        return f"{emoji}{model_name}"
    
    @staticmethod
    def _get_model_emoji(model_name: str, default_emoji: str = "🤖 ") -> str:
        """
        Select an appropriate emoji for a model based on its name
        
        Args:
            model_name: Name of the model
            default_emoji: Default emoji to use if no match
        
        Returns:
            Emoji string with trailing space
        """
        model_lower = model_name.lower()
        
        # Extract the base name without version and family name if possible
        model_parts = model_lower.split('/')
        model_basename = model_parts[-1].split(':')[0]  # base name without version
        model_family = model_parts[0] if len(model_parts) > 1 else None  # potential family
        model_families = model_parts[:-1]  # all potential family parts
        
        # Default emoji
        model_emoji = default_emoji
        
        # Try matching with full priority order - this time checking specifically
        # for matches in the basename to give higher priority
        best_match_length = 0
        for model_id, emoji in MODEL_EMOJIS.items():
            if model_id in model_basename and len(model_id) > best_match_length:
                model_emoji = emoji
                best_match_length = len(model_id)
        
        # If no basename match, try other matches
        if best_match_length == 0:
            for model_id, emoji in MODEL_EMOJIS.items():
                # Check in full name, family and families
                if (model_id in model_lower or
                    (model_family and model_id in model_family) or
                    any(model_id in family for family in model_families)):
                    model_emoji = emoji
                    # Don't break - continue to find the most specific match
        
        return model_emoji
    