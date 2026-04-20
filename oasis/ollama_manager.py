import contextlib
import re
import threading
import time
import ollama
from typing import List, Optional, Any, Dict
from tqdm import tqdm
import logging

# Import from configuration
from .config import (
    MODEL_EMOJIS,
    OLLAMA_URL,
    EXCLUDED_MODELS,
    DEFAULT_MODELS,
    MAX_CHUNK_SIZE,
    OLLAMA_HTTP_CLIENT_TIMEOUT_SEC,
    OLLAMA_SLOW_CALL_WARNING_SEC,
)
from .helpers.ollama_timing import (
    estimate_ollama_payload_chars,
    options_timeout_ms,
)

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
        self._cache_lock = threading.Lock()
        self.formatted_models = []
        # Cache for storing model information to avoid repeated API calls
        self._model_info_cache = {}
        self._model_thinking_overrides: Dict[str, bool] = {}
    
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
                    self.client = ollama.Client(
                        self.api_url,
                        timeout=float(OLLAMA_HTTP_CLIENT_TIMEOUT_SEC),
                    )
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

    def set_model_thinking(self, model: str, thinking: bool) -> None:
        """
        Set thinking behavior override for a given model.

        Args:
            model: Model name
            thinking: Whether thinking is enabled for this model
        """
        self._model_thinking_overrides[model] = thinking

    def configure_analysis_model_thinking(
        self,
        scan_model: str,
        main_models: List[str],
        scan_model_thinking: bool,
        main_model_thinking: bool
    ) -> None:
        """
        Configure thinking behavior for selected scan and deep analysis models.

        Args:
            scan_model: Model used for quick scanning
            main_models: Models used for deep analysis
            scan_model_thinking: Thinking flag for scan model
            main_model_thinking: Thinking flag for deep models
        """
        if scan_model:
            self.set_model_thinking(scan_model, scan_model_thinking)
        for model in main_models or []:
            self.set_model_thinking(model, main_model_thinking)

    def _resolve_model_thinking(self, model: str) -> Optional[bool]:
        """
        Resolve whether thinking should be sent for a model.

        Args:
            model: Model name

        Returns:
            Thinking override, or None if no override is configured
        """
        return self._model_thinking_overrides.get(model)

    @staticmethod
    def _normalize_client_response(result: Any) -> Any:
        """
        Convert ollama-python SDK response objects (e.g. ChatResponse, GenerateResponse)
        into plain dicts expected by callers. Older SDK versions returned dicts directly.
        """
        if result is None or isinstance(result, dict):
            return result
        model_dump = getattr(result, "model_dump", None)
        if callable(model_dump):
            with contextlib.suppress(Exception):
                return model_dump()
        legacy_dict = getattr(result, "dict", None)
        if callable(legacy_dict):
            with contextlib.suppress(Exception):
                return legacy_dict()
        return result

    @staticmethod
    def _parse_parameter_size_value(param_size: Any) -> float:
        """Approximate parameter count from Ollama ``parameter_size`` (e.g. ``8.0B``, ``7M``)."""
        if param_size is None:
            return 0.0
        with contextlib.suppress(ValueError, TypeError):
            if isinstance(param_size, str):
                if "B" in param_size:
                    return float(param_size.replace("B", "")) * 1_000_000_000
                if "M" in param_size:
                    return float(param_size.replace("M", "")) * 1_000_000
            return float(param_size)
        return 0.0

    @staticmethod
    def _parameter_count_from_modelinfo_dict(modelinfo: Any) -> float:
        if not isinstance(modelinfo, dict):
            return 0.0
        raw = modelinfo.get("general.parameter_count")
        if raw is None:
            return 0.0
        with contextlib.suppress(ValueError, TypeError):
            return float(raw)
        return 0.0

    @staticmethod
    def _parameter_count_numeric(model_info: Any) -> float:
        """Raw parameter count for display and lightweight filtering (0 if unknown)."""
        if model_info is None:
            return 0.0
        parameters = 0.0
        try:
            if isinstance(model_info, dict):
                details = model_info.get("details")
                if isinstance(details, dict) and "parameter_size" in details:
                    parameters = OllamaManager._parse_parameter_size_value(details["parameter_size"])
                if parameters == 0.0 and (mi := model_info.get("modelinfo")):
                    parameters = OllamaManager._parameter_count_from_modelinfo_dict(mi)
            elif hasattr(model_info, "details") and model_info.details:
                details = model_info.details
                if hasattr(details, "parameter_size") and details.parameter_size:
                    parameters = OllamaManager._parse_parameter_size_value(details.parameter_size)
            if parameters == 0.0 and hasattr(model_info, "modelinfo") and (
                mi_attr := model_info.modelinfo
            ):
                parameters = OllamaManager._parameter_count_from_modelinfo_dict(mi_attr)
        except Exception:
            return 0.0
        return parameters

    def _call_with_thinking(
        self,
        method_name: str,
        model: str,
        payload_key: str,
        payload_value: Any,
        options: Optional[dict] = None,
        **kwargs: Any
    ):
        """
        Execute an Ollama client call with optional per-model thinking behavior.
        """
        client = self.get_client()
        request_kwargs = {
            "model": model,
            payload_key: payload_value
        }
        if options is not None:
            request_kwargs["options"] = options
        request_kwargs |= kwargs

        thinking = self._resolve_model_thinking(model)
        if thinking is not None:
            request_kwargs["think"] = thinking

        method = getattr(client, method_name)
        payload_chars = estimate_ollama_payload_chars(payload_key, payload_value)
        timeout_ms_opt = options_timeout_ms(options)
        has_structured_format = bool(kwargs.get("format"))
        t_round = time.monotonic()
        err_type: Optional[str] = None
        try:
            try:
                result = method(**request_kwargs)
            except TypeError as error:
                # Backward compatibility with ollama clients not supporting think=
                error_message = error.args[0] if error.args else ""
                if (
                    "think" not in request_kwargs
                    or "unexpected keyword argument 'think'"
                    not in str(error_message)
                ):
                    raise
                request_kwargs.pop("think", None)
                result = method(**request_kwargs)
            return self._normalize_client_response(result)
        except Exception as exc:
            err_type = type(exc).__name__
            raise
        finally:
            elapsed = time.monotonic() - t_round
            if err_type is None and elapsed >= OLLAMA_SLOW_CALL_WARNING_SEC:
                logger.warning(
                    "Slow Ollama call %s model=%s elapsed=%.1fs payload_chars=%s timeout_ms=%s structured=%s",
                    method_name,
                    model,
                    elapsed,
                    payload_chars,
                    timeout_ms_opt,
                    has_structured_format,
                )

    def chat(self, model: str, messages: List[dict], options: Optional[dict] = None, **kwargs):
        """
        Chat completion wrapper with per-model thinking support.
        """
        return self._call_with_thinking(
            method_name="chat",
            model=model,
            payload_key="messages",
            payload_value=messages,
            options=options,
            **kwargs
        )

    def generate(self, model: str, prompt: str, options: Optional[dict] = None, **kwargs):
        """
        Text generation wrapper with per-model thinking support.
        """
        return self._call_with_thinking(
            method_name="generate",
            model=model,
            payload_key="prompt",
            payload_value=prompt,
            options=options,
            **kwargs
        )
    
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
        with self._cache_lock:
            if model in self._model_info_cache:
                logger.debug(f"Using cached model information for {model}")
                return self._model_info_cache[model]
            
        # Not in cache, query the API
        client = self.get_client()
        logger.debug(f"Querying model information for {model} from Ollama API...")
        
        try:
            model_info = client.show(model)
            # Store in cache for future use
            with self._cache_lock:
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
        with self._cache_lock:
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

    _NUM_CTX_IN_PARAMETERS = re.compile(r"num_ctx\s+(\d+)", re.IGNORECASE)

    @staticmethod
    def _num_ctx_from_parameters_value(params: Any) -> Optional[int]:
        """Resolve num_ctx from Ollama ``parameters`` (dict or Modelfile-style string)."""
        if params is None:
            return None
        try:
            if isinstance(params, dict) and "num_ctx" in params:
                return int(params["num_ctx"])
            if isinstance(params, str):
                match = OllamaManager._NUM_CTX_IN_PARAMETERS.search(params)
                if match:
                    return int(match.group(1))
        except (TypeError, ValueError):
            pass
        return None

    @staticmethod
    def _model_info_num_ctx(model_info: Any) -> Optional[int]:
        """Parse num_ctx from Ollama client.show() payload (dict or SDK object)."""
        try:
            if isinstance(model_info, dict):
                params = model_info.get("parameters")
            elif hasattr(model_info, "parameters"):
                params = getattr(model_info, "parameters", None)
            else:
                params = None
            return OllamaManager._num_ctx_from_parameters_value(params)
        except (TypeError, ValueError):
            pass
        return None

    @staticmethod
    def _raw_modelinfo_kv(model_info: Any) -> Any:
        """GGUF KV map from ``client.show()`` (``modelinfo`` / ``model_info``)."""
        if isinstance(model_info, dict):
            return model_info.get("modelinfo") or model_info.get("model_info")
        if getattr(model_info, "modelinfo", None) is not None:
            return getattr(model_info, "modelinfo")
        if getattr(model_info, "model_info", None) is not None:
            return getattr(model_info, "model_info")
        return None

    @staticmethod
    def _modelinfo_context_length_tokens(modelinfo: Any) -> Optional[int]:
        """
        Largest ``*.context_length`` value from GGUF metadata (Model card context length).

        Used when Modelfile ``parameters`` omit ``num_ctx`` (e.g. some embedding builds).
        """
        if not isinstance(modelinfo, dict):
            return None
        best: Optional[int] = None
        for key, raw in modelinfo.items():
            if not isinstance(key, str) or not key.endswith(".context_length"):
                continue
            try:
                n = int(float(raw))
            except (TypeError, ValueError):
                continue
            if n > 0:
                best = n if best is None else max(best, n)
        return best

    @staticmethod
    def _model_info_effective_context_tokens(model_info: Any) -> tuple[Optional[int], str]:
        """
        Effective context size in tokens for chunk sizing.

        Prefer Modelfile ``num_ctx`` (runtime allocation); else GGUF ``*.context_length``.

        Returns:
            (token_count or None, source: "parameters" | "modelinfo" | "")
        """
        from_params = OllamaManager._model_info_num_ctx(model_info)
        if from_params is not None and from_params > 0:
            return from_params, "parameters"
        mi = OllamaManager._raw_modelinfo_kv(model_info)
        from_gguf = OllamaManager._modelinfo_context_length_tokens(mi)
        if from_gguf is not None and from_gguf > 0:
            return from_gguf, "modelinfo"
        return None, ""

    def _detect_optimal_chunk_size(self, model):
        model_info = self._get_model_info(model)
        logger.debug(f"Raw model info type: {type(model_info)}")

        tokens, source = self._model_info_effective_context_tokens(model_info)
        logger.debug(f"Resolved effective context tokens: {tokens} (source={source or 'none'})")
        if tokens is not None and tokens > 0:
            chunk_size = int(tokens * 0.9)
            label = (
                "Modelfile num_ctx"
                if source == "parameters"
                else "GGUF context_length"
            )
            logger.info(f"Model {model} context ({label}, tokens): {tokens}")
            logger.info(f"🔄 Using chunk size: {chunk_size}")
            return chunk_size

        logger.warning(f"Could not detect context length for {model}, using default size: {MAX_CHUNK_SIZE}")
        return MAX_CHUNK_SIZE
    
    def select_models(self, available_models: List[str], show_formatted: bool = True, max_models: int = None, msg: str = "", recommend_lightweight: bool = False) -> List[str]:
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

        # Filter models to display only lightweight models if requested
        if recommend_lightweight and (lightweight_models := self._filter_lightweight_models(available_models)):
            logger.info(f"Filtering models to display only lightweight models (< 10B parameters): {len(lightweight_models)} models found.")
            if not lightweight_models:
                logger.warning("No lightweight models found, displaying all available models.")
            else:
                available_models = lightweight_models

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
        # Check first which models are not in cache
        with self._cache_lock:
            models_to_load = [m for m in model_names if m not in self._model_info_cache]
        
        if not models_to_load:
            logger.debug("All models already cached, no need to preload")
            return
            
        logger.debug(f"Preloading information for {len(models_to_load)} models")
        client = self.get_client()
        
        for model in tqdm(models_to_load, desc="Preloading model info", unit="model"):
            try:
                model_info = client.show(model)
                with self._cache_lock:
                    if model not in self._model_info_cache:
                        self._model_info_cache[model] = model_info
            except Exception as e:
                logger.warning(f"Error preloading model info for {model}: {str(e)}")
                # Use empty dict to avoid repeated attempts
                with self._cache_lock:
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

        self._preload_model_info(models)

        lightweight_models: List[str] = []
        max_lightweight = 10_000_000_000

        for model in models:
            try:
                parameters = self._parameter_count_numeric(self._get_model_info(model))
                if parameters == 0 or parameters <= max_lightweight:
                    lightweight_models.append(model)
            except Exception as e:
                logger.debug(f"Could not get parameter info for {model}: {str(e)}")
                lightweight_models.append(model)

        return lightweight_models
    
    def select_analysis_models(self, args, available_models):
        """
        Select models for security analysis
        
        Args:
            args: Command line arguments
            available_models: List of available models
            
        Returns:
            Dictionary with selected models, containing 'scan_model' and 'main_models' keys
        """
        # Initialize variables
        main_models = []
        scan_model = None

        # If models are provided as a comma-separated list, return them
        if hasattr(args, 'models') and args.models:
            # Handle 'all' case
            if args.models.strip().lower() == 'all':
                logger.info(f"Selected all {len(available_models)} models")
                main_models = available_models
            else:
                main_models = [model.strip() for model in args.models.split(',')]

        # If a scan model is provided, return it
        if hasattr(args, 'scan_model') and args.scan_model:
            scan_model = [args.scan_model]

        if scan_model and main_models:
            return {'scan_model': scan_model, 'main_models': main_models}

        # If no models are provided, select the scan model
        # First, select the scan model - only show lightweight models
        if not hasattr(args, 'scan_model') or not scan_model:
            msg = "First, choose your quick scan model (lightweight model for initial scanning):"
            if not (scan_model := self.select_models(
                available_models,
                show_formatted=True,
                msg=msg,
                max_models=1,
                recommend_lightweight=True
            )):
                scan_model = None

        if not hasattr(args, 'models') or not main_models:
            # Then, select the main analysis model - show all models
            msg = "\nThen, choose your main model for deep vulnerability analysis:"
            if not (main_models := self.select_models(
                available_models, show_formatted=True, msg=msg
            )):
                main_models = None

        if scan_model and main_models:
            return {'scan_model': scan_model, 'main_models': main_models}

        return None

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
        parameters = self._parameter_count_numeric(model_info)
        if parameters <= 0:
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
            ctx_size, _src = self._model_info_effective_context_tokens(model_info)
            if ctx_size is not None and ctx_size > 0:
                if ctx_size >= 1000:
                    return f"{ctx_size // 1000}k context"
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
                    return self._format_parent_model_display(
                        parent_model, default_emoji
                    )
            elif (hasattr(model_info, 'details') and model_info.details and 
                  hasattr(model_info.details, 'parent_model') and 
                  model_info.details.parent_model):
                
                parent_model = model_info.details.parent_model
                return self._format_parent_model_display(
                    parent_model, default_emoji
                )
        except Exception as e:
            logger.debug(f"Error extracting parent model info: {str(e)}")

        return ""

    def _format_parent_model_display(self, parent_model, default_emoji):
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
    