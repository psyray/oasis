import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime
import traceback
from typing import Union


# Import from configuration
from .config import REPORT, DEFAULT_ARGS

# Import from other modules
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
        
        # Add arguments (keep all existing arguments)
        parser.add_argument('-i', '--input', dest='input_path', type=str, 
                           help='Path to file, directory, or .txt file containing paths to analyze')
        parser.add_argument('-t', '--threshold', type=float, default=DEFAULT_ARGS['THRESHOLD'], 
                           help=f'Similarity threshold (default: {DEFAULT_ARGS["THRESHOLD"]})')
        parser.add_argument('-v', '--vulns', type=str, default=DEFAULT_ARGS['VULNS'], 
                           help=self.get_vulnerability_help())
        parser.add_argument('-of', '--output-format', type=str, default=DEFAULT_ARGS['OUTPUT_FORMAT'],
                           help=f'Output format [pdf, html, md] (default: {DEFAULT_ARGS["OUTPUT_FORMAT"]})')
        parser.add_argument('-d', '--debug', action='store_true',
                           help='Enable debug output')
        parser.add_argument('-s', '--silent', action='store_true',
                           help='Disable all output messages')
        parser.add_argument('-em', '--embed-model', type=str, default=DEFAULT_ARGS['EMBED_MODEL'],
                          help=f'Model to use for embeddings (default: {DEFAULT_ARGS["EMBED_MODEL"]})')
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
        parser.add_argument('-cd', '--cache-days', type=int, default=DEFAULT_ARGS['CACHE_DAYS'], 
                           help=f'Maximum age of cache in days (default: {DEFAULT_ARGS["CACHE_DAYS"]})')
        parser.add_argument('-ch', '--chunk-size', type=int,
                           help=f'Maximum size of text chunks for embedding (default: {DEFAULT_ARGS["CHUNK_SIZE"]})')
        parser.add_argument('-at', '--analyze_type', choices=['file', 'function'], default=DEFAULT_ARGS['ANALYSIS_TYPE'],
                           help=f'Analyze code by entire file or by individual functions [EXPERIMENTAL] (default: {DEFAULT_ARGS["ANALYSIS_TYPE"]})')
        parser.add_argument('-ol', '--ollama-url', dest='ollama_url', type=str, 
                           help='Ollama URL (default: http://localhost:11434)')
        parser.add_argument('-w', '--web', action='store_true',
                           help='Serve reports via a web interface')
        parser.add_argument('-we', '--web-expose', dest='web_expose', type=str, default='local',
                           help='Web interface exposure (local: 127.0.0.1, all: 0.0.0.0) (default: local)')
        parser.add_argument('-wpw', '--web-password', dest='web_password', type=str,
                           help='Web interface password (if not specified, a random password will be generated)')
        parser.add_argument('-wp', '--web-port', dest='web_port', type=int, default=5000,
                           help='Web interface port (default: 5000)')
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

    def run_analysis_mode(self, selected_models, vuln_mapping):
        """Run security analysis on selected models."""
        """
        Run security analysis on selected models

        Args:
            selected_models: List of selected models
            vuln_mapping: Vulnerability mapping
        """
        # Get vulnerabilities to check
        vulnerabilities, invalid_tags = SecurityAnalyzer.get_vulnerabilities_to_check(self.args, vuln_mapping)
        if invalid_tags:
            return False

        logger.info(f"\nStarting security analysis at {generate_timestamp()}")

        # Analyze with each selected model
        for model in selected_models:
            logger.info(f"\nAnalyzing with model: {model}")
            
            # Set the current model for report generation
            self.report.current_model = model

            # Create security analyzer for this model
            analyzer = SecurityAnalyzer(model, self.embedding_manager, self.ollama_manager)
            
            # Process analysis
            analyzer.process_analysis_with_model(vulnerabilities, self.args, self.report)

        # Report generation
        self.report.report_generated(report_type='Vulnerability', report_structure=True)

        logger.info(f"\nAnalysis completed successfully at {generate_timestamp()}")

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
        # Get available models
        available_models = self.ollama_manager.get_available_models()
        if not available_models:
            logger.error("No models available. Please check Ollama installation.")
            return 1
            
        # Select models for analysis
        selected_models = self.ollama_manager.select_analysis_models(self.args, available_models)
        if not selected_models:
            return 1
        self.report.models = selected_models
        self.report.create_report_directories(self.args.input_path, models=selected_models)
            
        # Run analysis with selected models
        result = self.run_analysis_mode(selected_models, vuln_mapping)
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