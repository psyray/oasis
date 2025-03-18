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
            if show_formatted and model_names:
                formatted_models = self.format_model_display_batch(model_names)
                logger.info("\nAvailable models:")
                for i, (model_name, formatted_model) in enumerate(zip(model_names, formatted_models), 1):
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

        Args:
            model: Name of the model
        """
        client = self.get_client()
        logger.debug(f"Querying model information for {model}...")
        return client.show(model)
        
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
    
    def select_models(self, available_models: List[str], show_formatted: bool = True) -> List[str]:
        """
        Let user select models interactively

        Args:
            available_models: List of available model names
            show_formatted: Whether to show formatted model names
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
            
        # Get user input for model selection
        try:
            while True:
                selection = input("\nEnter model numbers separated by comma (e.g., 1,3,5), or 'all': ")
                
                # Handle 'all' case
                if selection.strip().lower() == 'all':
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
                        
                    # Get corresponding model names
                    selected_models = [available_models[idx] for idx in selected_indices]
                    
                    if not selected_models:
                        logger.error("No models selected")
                        continue
                        
                    logger.info(f"Selected models: {', '.join(selected_models)}")
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
    
    def format_model_display_batch(self, model_names: List[str]) -> List[str]:
        """
        Format multiple model names with progress bar
        
        Args:
            model_names: List of model names to format
            
        Returns:
            List of formatted model strings
        """
        from tqdm import tqdm

        logger.info("Getting detailed model information...")
        
        return [
            self.format_model_display(model)
            for model in tqdm(
                model_names, desc="Getting model details", unit="model"
            )
        ]
    
    def select_analysis_models(self, args, available_models: List[str]) -> List[str]:
        """
        Select models for security analysis
        
        Args:
            args: Command-line arguments
            available_models: List of available model names
            
        Returns:
            List of selected model names
        """
        if not args.models:
            # Let user select models interactively
            return self.select_models(available_models)

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
        # 1. Check in model_info.details
        if hasattr(model_info, 'details') and model_info.details:
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

        # 2. Check in modelinfo['general.parameter_count']
        if parameters == 0 and hasattr(model_info, 'modelinfo') and model_info.modelinfo:
            modelinfo = model_info.modelinfo
            if isinstance(modelinfo, dict) and 'general.parameter_count' in modelinfo:
                with contextlib.suppress(ValueError, TypeError):
                    parameters = int(modelinfo['general.parameter_count'])

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
        # Check if model has parameter info with context window
        if not hasattr(model_info, 'parameters'):
            return None
            
        parameters = model_info.parameters
        if not parameters or 'num_ctx' not in parameters:
            return None
            
        # Format context window size
        ctx_size = int(parameters['num_ctx'])
        if ctx_size >= 1000:
            return f"{ctx_size // 1000}k context"
        else:
            return f"{ctx_size} context"
    
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
    
    def _extract_parent_model_info(self, model_info: Any, default_emoji: str = "🤖 ") -> str:
        """
        Extract and format parent model information

        Args:
            model_info: Model information
            default_emoji: Default emoji to use if no match
        """
        # Try to get parent model from details
        if not (hasattr(model_info, 'details') and model_info.details and 
                hasattr(model_info.details, 'parent_model') and model_info.details.parent_model):
            return ""  # Return early if no parent model

        # Extract parent model
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
    