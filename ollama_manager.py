import contextlib
import ollama
from typing import List
from tqdm import tqdm
import logging

# Import from other modules
from tools import logger, EmojiFormatter

# Import configuration
from config import OLLAMA_API_URL, EXCLUDED_MODELS, DEFAULT_MODELS, MAX_CHUNK_SIZE

def get_ollama_client() -> ollama.Client:
    """
    Get the Ollama client instance, checking connection first
    
    Returns:
        ollama.Client: Connected Ollama client
        
    Raises:
        ConnectionError: If Ollama server is not accessible
    """
    try:
        client = ollama.Client()
        # Use the configured API URL
        client.BASE_URL = OLLAMA_API_URL
        # Try to list models to verify connection
        client.list()
        return client
    except Exception as e:
        logger.error("\nError: Could not connect to Ollama server")
        logger.error("Please ensure that:")
        logger.error("1. Ollama is installed (https://ollama.ai)")
        logger.error("2. Ollama server is running (usually with 'ollama serve')")
        logger.error("3. Ollama is accessible (default: http://localhost:11434)")
        logger.debug(f"Connection error: {str(e)}")
        raise ConnectionError(f"Cannot connect to Ollama server: {str(e)}") from e

def check_ollama_connection() -> bool:
    """
    Check if Ollama server is running and accessible
    Returns:
        bool: True if connection is successful, False otherwise
    """
    try:
        get_ollama_client()
        return True
    except ConnectionError:
        return False

def get_available_models(show_formatted: bool = False) -> List[str]:
    """
    Get list of available models from Ollama API
    Args:
        show_formatted: If True, show formatted model list with progress
    Returns:
        List of model names
    """
    try:
        model_names = _get_models(EXCLUDED_MODELS)
        
        # If requested, display formatted list
        if show_formatted and model_names:
            logger.info("\nAvailable models:")
            formatted_models = format_model_display_batch(model_names)
            for i, (model_name, formatted_model) in enumerate(zip(model_names, formatted_models), 1):
                logger.info(f"{i}. {formatted_model}")
                logger.info(f"   Use with --models: '{model_name}' or '{i}'")
                
        return model_names
    except Exception as e:
        logger.error(f"Error fetching models: {str(e)}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Full error:", exc_info=True)


        logger.warning(f"Using default model list: {', '.join(DEFAULT_MODELS)}")
        return DEFAULT_MODELS

def _get_models(excluded_models):
    try:
        client = get_ollama_client()
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
        logger.debug(model_names)
        return model_names
    except ConnectionError as e:
        logger.error(f"Connection error while getting models: {str(e)}")
        raise

def detect_optimal_chunk_size(model: str) -> int:
    """
    Detect optimal chunk size by querying Ollama model parameters
    Args:
        model: Name of the embedding model
    Returns:
        Optimal chunk size in characters
    """
    try:
        client = get_ollama_client()
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
                logger.info(f"Model {model} context length: {context_length}")
                logger.info(f"🔄 Using chunk size: {chunk_size}")
                return chunk_size
        
        # If we couldn't get the information, use a conservative default
        logger.warning(f"Could not detect context length for {model}, using default size: {MAX_CHUNK_SIZE}")
        return MAX_CHUNK_SIZE
        
    except Exception as e:
        logger.error(f"Error detecting chunk size: {str(e)}")
        logger.warning("Using conservative default chunk size: {MAX_CHUNK_SIZE}")
        return MAX_CHUNK_SIZE

def check_model_availability(model_name: str) -> bool:
    """
    Check if a model is available on Ollama server
    Args:
        model_name: Name of the model to check
    Returns:
        True if model is available, False otherwise
    """
    try:
        client = get_ollama_client()
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
        client = get_ollama_client()
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
                        "2. Continue without it\n"
                        "Choose (1/2): ").strip()
        
        if response == "1":
            return install_model(model_name)
        elif response == "2":
            return False
        else:
            print("Invalid choice. Please enter 1 or 2.")

def select_models(available_models: List[str]) -> List[str]:
    """
    Interactive model selection with improved display
    Args:
        available_models: List of available model names
    Returns:
        List of selected model names
    """
    from tqdm import tqdm

    logger.info("\nGetting detailed model information...")

    # Pre-format all models with progress bar
    formatted_models = []

    # Use tqdm to display progress
    formatted_models.extend(
        (i + 1, format_model_display(model), model)
        for i, model in enumerate(
            tqdm(available_models, desc="Getting model details", unit="model")
        )
    )
    # Display all formatted models in one block
    logger.info("\nAvailable models:")
    for idx, formatted_model, _ in formatted_models:
        logger.info(f"{idx}. {formatted_model}")

    while True:
        choice = input("\nSelect models (comma-separated numbers or 'all'): ").strip().lower()
        if choice == 'all':
            return available_models

        with contextlib.suppress(ValueError, IndexError):
            indices = [int(x.strip()) - 1 for x in choice.split(',')]
            if selected := [
                available_models[i]
                for i in indices
                if 0 <= i < len(available_models)
            ]:
                return selected
        logger.error("Invalid selection. Please try again.")

def format_model_display(model_name: str) -> str:
    """
    Format model name with additional information retrieved from ollama
    
    Args:
        model_name: Name of the model
    
    Returns:
        Formatted string with model information
    """
    # Default emoji to use in case of errors
    default_emoji = "🤖 "
    
    try:
        client = get_ollama_client()
        model_info = client.show(model_name)
        
        # Extract formatted model info based on actual structure
        return _format_model_with_info(model_name, model_info, default_emoji)
    except Exception as e:
        logger.debug(f"Error getting model details: {str(e)}")
        # Fallback to model name with default emoji
        return f"{default_emoji}{model_name}"

def _format_model_with_info(model_name: str, model_info, default_emoji: str = "🤖 ") -> str:
    """
    Create formatted model display using available model information
    
    Args:
        model_name: Name of the model
        model_info: Model information from ollama
        default_emoji: Default emoji to use if no matching emoji found
        
    Returns:
        Formatted model string
    """
    try:
        # Extract parameter information
        param_str = _extract_parameter_info(model_info)
        
        # Extract context length information
        ctx_str = _extract_context_info(model_info)
        
        # Get appropriate emoji
        model_emoji = _determine_model_emoji(model_name, model_info, default_emoji)
        
        # Get parent model if available
        parent_info = _extract_parent_model_info(model_info, default_emoji)
        
        # Build the formatted string
        return _build_formatted_string(model_name, model_emoji, param_str, ctx_str, parent_info)
    except Exception as e:
        logger.debug(f"Error formatting model info: {str(e)}")
        # Fallback if any error occurs during formatting
        return f"{default_emoji}{model_name}"

def _extract_parameter_info(model_info) -> str:
    """Extract and format parameter information from model info"""
    parameters = 0

    # Try different paths to parameter information
    # 1. Check in details.parameter_size (might be a string like "8.0B")
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
        return f"{parameters/1_000_000_000:.1f}B params"
    elif parameters >= 1_000_000:
        return f"{parameters/1_000_000:.1f}M params"
    elif parameters > 0:  # Fusionné les conditions pour éviter la redondance
        return f"{parameters:,} params"
    return ""  # Retourne une chaîne vide si parameters = 0

def _extract_context_info(model_info) -> str:
    """Extract and format context length information from model info"""
    context_length = 0

    # Try different paths to context length
    # 1. Check in modelinfo['llama.context_length']
    if hasattr(model_info, 'modelinfo') and model_info.modelinfo:
        modelinfo = model_info.modelinfo
        if isinstance(modelinfo, dict):
            # Look for context length in various possible keys
            for key in ['llama.context_length', 'phi.context_length', 'general.context_length']:
                if key in modelinfo:
                    with contextlib.suppress(ValueError, TypeError):
                        context_length = int(modelinfo[key])
                        break
    # 2. Check in details.context_length if still not found
    if context_length == 0 and hasattr(model_info, 'details') and model_info.details:
        details = model_info.details
        if hasattr(details, 'context_length') and details.context_length:
            with contextlib.suppress(ValueError, TypeError):
                context_length = int(details.context_length)
    # Format context length in K tokens
    if context_length >= 1000:
        return f"{context_length/1000:.0f}K ctx"
    else:
        return f"{context_length} ctx" if context_length > 0 else ""

def _determine_model_emoji(model_name: str, model_info, default_emoji: str) -> str:
    """Determine the appropriate emoji for the model"""
    model_lower = model_name.lower()
    # Get basename (removing organization prefix) for additional matching
    model_basename = model_lower.split('/')[-1].split(':')[0]
    
    # Extract model family information from various possible locations
    model_family = ""
    model_families = []
    
    # 1. Check in details.family
    if hasattr(model_info, 'details') and model_info.details:
        details = model_info.details
        if hasattr(details, 'family') and details.family:
            model_family = details.family.lower()
        # Check for families list
        if hasattr(details, 'families') and details.families:
            families = details.families
            if isinstance(families, list):
                model_families = [f.lower() for f in families if isinstance(f, str)]
    
    # Default emoji
    model_emoji = default_emoji
    
    # Try matching with full priority order - this time checking specifically
    # for matches in the basename to give higher priority
    best_match_length = 0
    for model_id, emoji in EmojiFormatter.MODEL_EMOJIS.items():
        if model_id in model_basename and len(model_id) > best_match_length:
            model_emoji = emoji
            best_match_length = len(model_id)
    
    # If no basename match, try other matches
    if best_match_length == 0:
        for model_id, emoji in EmojiFormatter.MODEL_EMOJIS.items():
            # Check in full name, family and families
            if (model_id in model_lower or
                (model_family and model_id in model_family) or
                any(model_id in family for family in model_families)):
                model_emoji = emoji
                # Don't break - continue to find the most specific match
    
    return model_emoji

def _extract_parent_model_info(model_info, default_emoji: str = "🤖 ") -> str:
    """Extract and format parent model information"""
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
            for model_id, emoji in EmojiFormatter.MODEL_EMOJIS.items()
            if model_id in parent_basename or model_id in parent_lower
        ),
        default_emoji,
    )
    
    # Return formatted parent model info
    return f"{parent_emoji}{parent_model.split(':')[0]}"

def _build_formatted_string(model_name: str, model_emoji: str, param_str: str, ctx_str: str, parent_info: str = "") -> str:
    """Build the final formatted string with all available information"""
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

def format_model_display_batch(model_names: List[str]) -> List[str]:
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
        format_model_display(model)
        for model in tqdm(
            model_names, desc="Getting model details", unit="model"
        )
    ]

def select_analysis_models(args, available_models):
    """Select models for security analysis"""
    if not args.models:
        # Let user select models interactively
        return select_models(available_models)
    
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
        # Otherwise treat as model name
        elif item in available_models:
            selected_models.append(item)
        else:
            logger.error(f"Model not available: {item}")
            logger.error("Use --list-models to see available models")
            return None
    
    logger.info(f"Using specified models: {', '.join(selected_models)}")
    return selected_models
