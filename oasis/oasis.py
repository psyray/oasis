import argparse
import logging
import sys
from pathlib import Path
import time
import traceback
from typing import Union

# Import from configuration
from .config import MODEL_EMOJIS, REPORT, DEFAULT_ARGS

# Import from other modules
from .context_manager import TechnologyContextManager
from .tools import generate_timestamp, setup_logging, logger, display_logo, get_vulnerability_mapping
from .ollama_manager import OllamaManager
from .embedding import EmbeddingManager
from .analyze import SecurityAnalyzer, EmbeddingAnalyzer
from .report import Report
from .web import WebServer

class OasisScanner:
    """Main class for OASIS - Ollama Automated Security Intelligence Scanner"""
    
    def __init__(self):
        """Initialize the OASIS scanner"""
        self.args = None
        self.ollama_manager = None
        self.embedding_manager = None
        self.output_dir = None
        self.context_manager = None

    def setup_argument_parser(self):
        """
        Configure and return argument parser

        Returns:
            Argument parser
        """
        class CustomFormatter(argparse.RawDescriptionHelpFormatter):
            def _split_lines(self, text, width):
                if text.startswith('Vulnerability types'):
                    return text.splitlines()
                return super()._split_lines(text, width)

        parser = argparse.ArgumentParser(
            description='🏝️  OASIS - Ollama Automated Security Intelligence Scanner',
            formatter_class=CustomFormatter
        )
        
        # Input/Output Options
        io_group = parser.add_argument_group('Input/Output Options')
        io_group.add_argument('-i', '--input', dest='input_path', type=str, 
                            help='Path to file, directory, or .txt file containing paths to analyze')
        io_group.add_argument('-of', '--output-format', type=str, default=DEFAULT_ARGS['OUTPUT_FORMAT'],
                            help=f'Output format [pdf, html, md] (default: {DEFAULT_ARGS["OUTPUT_FORMAT"]})')
        io_group.add_argument('-x', '--extensions', type=str,
                            help='Comma-separated list of file extensions to analyze (e.g., "py,js,java")')
        
        # Analysis Configuration
        analysis_group = parser.add_argument_group('Analysis Configuration')
        analysis_group.add_argument('-at', '--analyze-type', choices=['standard', 'deep'], default=DEFAULT_ARGS['ANALYSIS_TYPE'],
                                    help=f'Analyze type (default: {DEFAULT_ARGS["ANALYSIS_TYPE"]})')
        analysis_group.add_argument('-l', '--language', type=str,
                                    help='Specify the programming language for context-aware analysis (e.g., "php", "python")')
        analysis_group.add_argument('-f', '--framework', type=str,
                                    help='Specify the framework for additional context (e.g., "laravel", "django")')
        analysis_group.add_argument('-eat', '--embeddings-analyze-type', choices=['file', 'function'], default=DEFAULT_ARGS['ANALYSIS_TYPE'],
                                    help=f'Analyze code by entire file or by individual functions [EXPERIMENTAL] (default: {DEFAULT_ARGS["ANALYSIS_TYPE"]})')
        analysis_group.add_argument('-ad', '--adaptive', action='store_true', 
                                    help='Use adaptive multi-level analysis that adjusts depth based on risk assessment')
        analysis_group.add_argument('-t', '--threshold', type=float, default=DEFAULT_ARGS['THRESHOLD'], 
                                    help=f'Similarity threshold (default: {DEFAULT_ARGS["THRESHOLD"]})')
        analysis_group.add_argument('-v', '--vulns', type=str, default=DEFAULT_ARGS['VULNS'], 
                                    help=self.get_vulnerability_help())
        analysis_group.add_argument('-ch', '--chunk-size', type=int,
                                    help=f'Maximum size of text chunks for embedding (default: {DEFAULT_ARGS["CHUNK_SIZE"]})')
        
        # Model Selection
        model_group = parser.add_argument_group('Model Selection')
        model_group.add_argument('-m', '--models', type=str,
                                help='Comma-separated list of models to use (bypasses interactive selection - use `all` to use all models)')
        model_group.add_argument('-sm', '--scan-model', dest='scan_model', type=str,
                                help='Model to use for quick scanning (default: same as main model)')
        model_group.add_argument('-em', '--embed-model', type=str, default=DEFAULT_ARGS['EMBED_MODEL'],
                                help=f'Model to use for embeddings (default: {DEFAULT_ARGS["EMBED_MODEL"]})')
        model_group.add_argument('-lm', '--list-models', action='store_true',
                                help='List available models and exit')
        
        # Cache Management
        cache_group = parser.add_argument_group('Cache Management', 'Options for managing cache files')
        cache_group.add_argument('-cce', '--clear-cache-embeddings', action='store_true',
                                help='Clear embeddings cache before starting')
        cache_group.add_argument('-ccs', '--clear-cache-scan', action='store_true',
                                help='Clear scan analysis cache for the current analysis type')
        cache_group.add_argument('-cd', '--cache-days', type=int, default=DEFAULT_ARGS['CACHE_DAYS'], 
                                help=f'Maximum age of cache in days (default: {DEFAULT_ARGS["CACHE_DAYS"]})')
        
        # Web Interface
        web_group = parser.add_argument_group('Web Interface')
        web_group.add_argument('-w', '--web', action='store_true',
                            help='Serve reports via a web interface')
        web_group.add_argument('-we', '--web-expose', dest='web_expose', type=str, default='local',
                            help='Web interface exposure (local: 127.0.0.1, all: 0.0.0.0) (default: local)')
        web_group.add_argument('-wpw', '--web-password', dest='web_password', type=str,
                            help='Web interface password (if not specified, a random password will be generated)')
        web_group.add_argument('-wp', '--web-port', dest='web_port', type=int, default=5000,
                            help='Web interface port (default: 5000)')
        
        # Logging and Debug
        logging_group = parser.add_argument_group('Logging and Debug')
        logging_group.add_argument('-d', '--debug', action='store_true',
                                help='Enable debug output')
        logging_group.add_argument('-s', '--silent', action='store_true',
                                help='Disable all output messages')
        
        # Special Modes
        special_group = parser.add_argument_group('Special Modes')
        special_group.add_argument('-a', '--audit', action='store_true',
                                help='Run embedding distribution analysis')
        special_group.add_argument('-ol', '--ollama-url', dest='ollama_url', type=str, 
                                help='Ollama URL (default: http://localhost:11434)')
        special_group.add_argument('-V', '--version', action='store_true',
                                help='Show OASIS version and exit')
        
        return parser
    def get_vulnerability_help(self) -> str:
        """
        Generate help text for vulnerability arguments

        Returns:
            Help text for vulnerability arguments
        """
        vuln_map = get_vulnerability_mapping()
        vuln_list = []
        vuln_list.extend(
            f"{tag:<8} - {vuln['name']}" for tag, vuln in vuln_map.items()
        )
        vuln_list = [f"{tag:<8} - {vuln['name']}" for tag, vuln in vuln_map.items()]
        return (
            "Vulnerability types to check (comma-separated).\nAvailable tags:\n"
            + "\n".join(f"  {v}" for v in vuln_list)
            + "\n\nUse 'all' to check all vulnerabilities (default)"
        )

    def run_analysis_mode(self, main_models, scan_model, vuln_mapping):
        """
        Run the security analysis with specified models
        
        Args:
            main_models: List of main models for deep analysis
            scan_model: Model for initial scanning
            vuln_mapping: Vulnerability mapping
            
        Returns:
            True if successful, False otherwise
        """
        # Get vulnerabilities to check
        vulnerabilities, invalid_tags = SecurityAnalyzer.get_vulnerabilities_to_check(self.args, vuln_mapping)
        if invalid_tags:
            return False

        logger.info(f"\nStarting security analysis at {generate_timestamp()}\n")
        start_time = time.time()

        # Determine analysis type (adaptive or standard)
        adaptive = hasattr(self.args, 'adaptive') and self.args.adaptive
        analysis_type = "🧠 adaptive" if adaptive else "📋 standard"
        logger.info(f"Using {analysis_type} analysis mode")

        # Detect or get technology stack
        language, framework = self.context_manager.detect_technology_stack()
        
        if language:
            # Initialize security analyzer with technology context
            self.security_analyzer.set_technology_context(language, framework)
            logger.info(
                f"Analyzing {language} {f'with {framework}' if framework else ''} codebase"
            )
        else:
            logger.info("Running analysis without specific technical context")

        # Process all main models one by one
        for i, main_model in enumerate(main_models):
            msg = f"Running analysis with model {i+1}/{len(main_models)}: {main_model}"
            logger.info(f"\n{'='*len(msg)}")
            logger.info(msg)
            logger.info(f"{'='*len(msg)}")

            # Create analyzer with current main model and scan model
            security_analyzer = SecurityAnalyzer(
                args=self.args,
                llm_model=main_model,
                embedding_manager=self.embedding_manager,
                ollama_manager=self.ollama_manager,
                scan_model=scan_model
            )

            # Set the current model for report generation
            self.report.current_model = main_model

            # Process analysis with selected model
            try:
                security_analyzer.process_analysis_with_model(
                    vulnerabilities, 
                    self.args, 
                    self.report
                )
            except Exception as e:
                logger.exception(f"Error during security analysis with {main_model}: {str(e)}")
                # Continue with next model instead of failing completely
                continue

        # Report generation complete
        self.report.report_generated(report_type='Security', report_structure=True)

        logger.info(f"\nAnalysis completed successfully at {generate_timestamp()}, duration: {time.time() - start_time:.2f} seconds")

        return True

    def handle_audit_mode(self, vuln_mapping):
        """Handle audit mode - analyze embeddings distribution only."""
        """
        Handle audit mode - analyze embeddings distribution only

        Args:
            vuln_mapping: Vulnerability mapping
        """
        # Get vulnerabilities to check
        vulnerabilities, invalid_tags = SecurityAnalyzer.get_vulnerabilities_to_check(self.args, vuln_mapping)
        if invalid_tags:
            return False

        # Create analyzer
        embedding_manager = EmbeddingAnalyzer(self.embedding_manager, self.ollama_manager)

        # Analyze all vulnerabilities
        analyzer_results = embedding_manager.analyze_all_vulnerabilities(vulnerabilities)

        # Set the current model for report generation
        self.report.current_model = embedding_manager.embedding_model

        # Generate audit report
        self.report.create_report_directories(self.args.input_path, models=[self.report.current_model])
        self.report.generate_audit_report(
            analyzer_results,
            self.embedding_manager
        )

        # Report generation
        self.report.report_generated(report_type='Audit', report_structure=True)

        logger.info(f'Audit completed successfully at {generate_timestamp()}')

        return True

    def run(self, args=None):
        """
        Run the OASIS scanner with the provided or parsed args

        Args:
            args: Arguments
        """
        try:
            return self._init_oasis(args)
        except KeyboardInterrupt:
            logger.info(f"\nProcess interrupted by user at {generate_timestamp()}. Exiting...")
            self._save_cache_on_exit()
            return 1
        except Exception as e:
            logger.exception(f"An unexpected error occurred: {str(e)}")
            if logger.isEnabledFor(logging.DEBUG):
                logger.exception(f"Full error trace: {traceback.format_exc()}", exc_info=True)
            return 1

    def _init_oasis(self, args):
        # Parse and validate arguments
        init_result = self._init_arguments(args)

        # Handle special early termination cases
        if init_result is None:
            return 0  # Success exit code for commands like --list-models
        elif init_result is False:
            return 1  # Error exit code for validation failures

        # Initialize report
        self.report = Report(self.args.input_path, self.args.output_format)

        # Initialize context manager
        self.context_manager = TechnologyContextManager()

        # Initialize Ollama and check connection
        if not self.args.web:
            if not self._init_ollama(self.args.ollama_url):
                return 1
            # Initialize embedding manager and process input files
            return self._execute_requested_mode() if self._init_processing() else 1

        # Serve reports via web interface
        WebServer(
            self.report, 
            debug=self.args.debug,
            web_expose=self.args.web_expose,
            web_password=self.args.web_password,
            web_port=self.args.web_port
        ).run()
        return 0  # Exit after serving the web interface
            
    def _init_arguments(self, args) -> Union[bool, None]:
        """
        Initialize and validate arguments
        
        Returns:
            None: For successful early termination cases (like --list-models)
            True: If arguments are valid and processing should continue
            False: If arguments are invalid and program should exit with error
        """
        # Parse command line arguments if not provided
        if args is None:
            parser = self.setup_argument_parser()
            self.args = parser.parse_args()
        else:
            self.args = args

        # Handle special cases that should terminate early
        if self.args.version:
            # Import here to avoid circular imports
            from .__init__ import __version__
            print(f"OASIS - Ollama Automated Security Intelligence Scanner v{__version__}")
            return None
        
        if self.args.list_models:
            # Setup minimal logging without file creation
            setup_logging(debug=self.args.debug, silent=False, error_log_file=None)
            display_logo()
            return self._handle_list_models_and_exit()
        
        # Validate required argument combinations
        if self.args.silent and not self.args.models and not self.args.audit:
            return self._handle_argument_errors(
                "When using --silent mode, you must specify models with --models/-m or use --audit"
            )
        # Check for required input path for normal operation
        if not self.args.input_path:
            return self._handle_argument_errors("--input/-i is required")
        # Now setup full logging with appropriate paths
        self._setup_logging()

        # Initialize context manager early for extension handling
        self.context_manager = TechnologyContextManager()

        # Handle extensions based on language or auto-detection
        if hasattr(self.args, 'language') and self.args.language:
            # Use extensions for specified language
            self.args.extensions = self.context_manager.get_language_extensions(self.args.language)
            logger.info(f"Using file extensions for {self.args.language}: {', '.join(self.args.extensions)}")
        elif hasattr(self.args, 'extensions') and self.args.extensions:
            # User specified extensions - keep them
            self.args.extensions = [ext.strip() for ext in self.args.extensions.split(',')]
            logger.info(f"Using user-specified extensions: {', '.join(self.args.extensions)}")
        else:
            # No language or extensions specified - use all supported extensions
            self.args.extensions = self.context_manager.get_language_extensions()
            logger.info("Using all supported file extensions")

        # Process output format
        if self.args.output_format == 'all':
            self.args.output_format = REPORT['OUTPUT_FORMATS']
        else:
            self.args.output_format = self.args.output_format.split(',')

        display_logo()
        return True

    def _init_ollama(self, ollama_url=None, check_embeddings=True):
        """
        Initialize Ollama and check connections

        Args:
            check_embeddings: Whether to check if embeddings are available
        Returns:
            True if Ollama is running and connected, False otherwise
        """
        # Initialize Ollama manager
        if ollama_url is None:
            ollama_url = self.args.ollama_url
        self.ollama_manager = OllamaManager(ollama_url)

        if self.ollama_manager.get_client() is None:
            logger.error("Ollama is not running. Please start Ollama and try again.")
            return False

        if not check_embeddings:
            return True

        # Auto-detect chunk size if not specified
        if self.args.chunk_size is None:
            self.args.chunk_size = self.ollama_manager.detect_optimal_chunk_size(self.args.embed_model)
        else:
            logger.info(f"Using manual chunk size: {self.args.chunk_size}")

        # Check Ollama connection
        if not self.ollama_manager.check_connection():
            return False

        # Check embedding model availability
        return bool(self.ollama_manager.ensure_model_available(self.args.embed_model))

    def _init_processing(self):
        """
        Initialize embedding manager and process input files

        Returns:
            True if processing is successful, False otherwise
        """

        # Initialize embedding manager
        self.embedding_manager = EmbeddingManager(self.args, self.ollama_manager)

        return self.embedding_manager.process_input_files(self.args)

    def _execute_requested_mode(self):
        """
        Execute requested analysis mode

        Returns:
            Exit code (0 for success, 1 for failure)
        """
        # Get vulnerability mapping for all modes
        vuln_mapping = get_vulnerability_mapping()

        # Determine and execute appropriate mode
        if self.args.audit:
            result = self.handle_audit_mode(vuln_mapping)
            return 0 if result else 1

        # Analysis mode
        return self._run_analysis_mode(vuln_mapping)

    def _run_analysis_mode(self, vuln_mapping):
        """
        Run security analysis with selected models

        Args:
            vuln_mapping: Vulnerability mapping
        """
        # Get analysis type
        analysis_type = self.ollama_manager.select_analysis_type(self.args)
        if not analysis_type:
            return 1

        # Get available models
        available_models = self.ollama_manager.get_available_models()
        if not available_models:
            logger.error("No models available. Please check Ollama installation.")
            return 1

        # Get selected models (either from args or interactive selection)
        selected_model_data = self.ollama_manager.select_analysis_models(self.args, available_models)
        if not selected_model_data:
            return 1
        
        # Extract the scan model and main models
        scan_model = selected_model_data['scan_model']
        main_models = selected_model_data['main_models']
        
        if not scan_model:
            logger.error("No scan model was selected.")
            return 1
            
        if not main_models:
            logger.warning("No main models were selected, using scan model for deep analysis as well")
            main_models = [scan_model]
        
        # Store the scan model in the arguments
        self.args.scan_model = scan_model
        
        # Log model selection information
        display_scan_model = self.ollama_manager.get_model_display_name(scan_model)
        display_main_models = ", ".join([self.ollama_manager.get_model_display_name(m) for m in main_models])
        if len(main_models) == 1 and scan_model == main_models[0]:
            logger.info(f"{MODEL_EMOJIS['default']}Using '{display_scan_model}' for both scanning and deep analysis")
        else:
            logger.info(f"{MODEL_EMOJIS['default']}Using '{display_scan_model}' for scanning and {display_main_models} for deep analysis")
        
        # Create the report directories for all main models
        self.report.models = main_models
        self.report.create_report_directories(self.args.input_path, models=main_models)

        # Run analysis with all main models
        result = self.run_analysis_mode(main_models, scan_model, vuln_mapping)
        if not result:
            return 1

        # Output cache file location
        logger.info(f"\nCache file: {self.embedding_manager.cache_file}")
        return 0
        
    def _save_cache_on_exit(self):
        """
        Save cache when exiting due to interruption

        Args:
            None
        """
        try:
            if hasattr(self, 'embedding_manager') and self.embedding_manager:
                self.embedding_manager.save_cache()
                logger.info("Cache saved successfully.")
        except Exception:
            logger.error("Failed to save cache on interruption.")

    def _setup_logging(self):
        """
        Configure logging based on arguments

        Args:
            None
        """
        if self.args.silent:
            logs_dir = Path(self.args.input_path).resolve().parent / REPORT['OUTPUT_DIR'] / "logs" if self.args.input_path else Path(REPORT['OUTPUT_DIR']) / "logs"
            logs_dir.mkdir(parents=True, exist_ok=True)
            log_file = logs_dir / f"oasis_errors_{generate_timestamp(for_file=True)}.log"
        else:
            log_file = None
            
        setup_logging(debug=self.args.debug, silent=self.args.silent, error_log_file=log_file)

    def _handle_argument_errors(self, arg0):
        setup_logging(debug=self.args.debug, silent=False, error_log_file=None)
        logger.error(arg0)
        return False


    def _handle_list_models_and_exit(self):
        """
        Handle --list-models option and return appropriate value for early termination
        
        Returns:
            None: Successfully listed models, program should exit with success code
            False: Error occurred, program should exit with error code
        """
        try:
            self._init_ollama(self.args.ollama_url, check_embeddings=False)
                
            logger.info("🔎 Querying available models from Ollama...")
            
            # Display formatted list of models
            available_models = self.ollama_manager.get_available_models(show_formatted=True)
            
            if not available_models:
                logger.error("No models available. Please check your Ollama installation.")
            
            # Indicate special case handling was successful
            return None  # Special return value to indicate early termination
        except Exception as e:
            return self._handle_model_list_error(e)
        
    def _handle_model_list_error(self, e):
        """
        Handle errors when listing models

        Args:
            e: Exception
        """
        logger.error(f"Error listing models: {str(e)}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Full error:", exc_info=True)
        return False

def main():
    """
    Main entry point for the OASIS scanner

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    scanner = OasisScanner()
    return scanner.run()

if __name__ == "__main__":
    sys.exit(main())