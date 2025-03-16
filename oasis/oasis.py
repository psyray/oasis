import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime

from .tools import setup_logging, logger, display_logo, get_vulnerability_mapping
from .ollama_manager import OllamaManager
from .embedding import EmbeddingManager
from .analyze import SecurityAnalyzer, EmbeddingAnalyzer
from .report import Report

class OasisScanner:
    """Main class for OASIS - Ollama Automated Security Intelligence Scanner"""
    
    def __init__(self):
        """Initialize the OASIS scanner"""
        self.args = None
        self.ollama_manager = None
        self.embedding_manager = None
        self.output_dir = None

    def setup_argument_parser(self):
        """Configure and return argument parser"""
        class CustomFormatter(argparse.RawDescriptionHelpFormatter):
            def _split_lines(self, text, width):
                if text.startswith('Vulnerability types'):
                    return text.splitlines()
                return super()._split_lines(text, width)

        parser = argparse.ArgumentParser(
            description='OASIS - Ollama Automated Security Intelligence Scanner',
            formatter_class=CustomFormatter
        )
        
        # Add arguments (keep all existing arguments)
        parser.add_argument('-i', '--input', dest='input_path', type=str, 
                           help='Path to file, directory, or .txt file containing paths to analyze')
        parser.add_argument('-t', '--threshold', type=float, default=0.5, 
                           help='Similarity threshold (default: 0.5)')
        parser.add_argument('-v', '--vulns', type=str, default='all', 
                           help=self.get_vulnerability_help())
        parser.add_argument('-of', '--output-format', type=str, default='all',
                           help='Output format (default: all)')
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
        parser.add_argument('-at', '--analyze_type', choices=['file', 'function'], default='function',
                           help='Analyze code by entire file or by individual functions')
        return parser

    def get_vulnerability_help(self) -> str:
        """Generate help text for vulnerability arguments"""
        vuln_map = get_vulnerability_mapping()
        vuln_list = []
        vuln_list.extend(
            f"{tag:<8} - {vuln['name']}" for tag, vuln in vuln_map.items()
        )
        return (
            "Vulnerability types to check (comma-separated).\n"
            + "Available tags:\n"
            + "\n".join(f"  {v}" for v in vuln_list)
            + "\n\nUse 'all' to check all vulnerabilities (default)"
        )

    def handle_list_models_option(self):
        """Handle --list-models option"""
        try:
            logger.info("Querying available models from Ollama...")
            
            # Use True for the show_formatted parameter to display numbers 
            available_models = self.ollama_manager.get_available_models(show_formatted=True)
            
            if not available_models:
                logger.error("No models available. Please check your Ollama installation.")
                return True

            return True
        except Exception as e:
            logger.error(f"Error listing models: {str(e)}")
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Full error:", exc_info=True)
            return False

    def run_analysis_mode(self, selected_models, vuln_mapping):
        """Run security analysis on selected models"""
        # Get vulnerabilities to check
        vulnerabilities, invalid_tags = SecurityAnalyzer.get_vulnerabilities_to_check(self.args, vuln_mapping)
        if invalid_tags:
            return False

        # Create timestamp for this run
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"\nStarting security analysis at {timestamp}")

        # Analyze with each selected model
        for model in selected_models:
            logger.info(f"\nAnalyzing with model: {model}")
            
            # Create security analyzer for this model
            analyzer = SecurityAnalyzer(model, self.embedding_manager)
            
            # Process analysis
            analyzer.process_analysis_with_model(vulnerabilities, self.args, self.report)
        
        # Show report structure
        self.report.display_report_structure(selected_models)
        
        return True

    def handle_audit_mode(self, vuln_mapping):
        """Handle audit mode - analyze embeddings distribution only"""
        # Get vulnerabilities to check
        vulnerabilities, invalid_tags = SecurityAnalyzer.get_vulnerabilities_to_check(self.args, vuln_mapping)
        if invalid_tags:
            return False
            
        # Create analyzer
        embedding_manager = EmbeddingAnalyzer(self.embedding_manager)
        
        # Analyze all vulnerabilities
        analyzer_results = embedding_manager.analyze_all_vulnerabilities(vulnerabilities)
        
        # Generate audit report
        self.report.generate_audit_report(
            analyzer_results,
            self.embedding_manager
        )
        
        return True

    def run(self, args=None):
        """Run the OASIS scanner with the provided or parsed args"""
        try:
            # Parse command line arguments if not provided
            if args is None:
                parser = self.setup_argument_parser()
                self.args = parser.parse_args()
            else:
                self.args = args

            # Create output directory for logs if in silent mode
            if self.args.silent:
                logs_dir = Path(self.args.input_path).resolve().parent / "security_reports" / "logs" if self.args.input_path else Path("security_reports/logs")
                logs_dir.mkdir(parents=True, exist_ok=True)
                log_file = logs_dir / f"oasis_errors_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            else:
                log_file = None

            # Setup logging
            setup_logging(debug=self.args.debug, silent=self.args.silent, error_log_file=log_file)

            # Check if models are specified when in silent mode
            if self.args.silent and not self.args.models and not self.args.list_models and not self.args.audit:
                parser.error("When using --silent mode, you must specify models with --models/-m")

            # Check if output format is specified
            if self.args.output_format == 'all':
                self.args.output_format = ['pdf', 'html', 'md']
            else:
                self.args.output_format = self.args.output_format.split(',')

            display_logo()

            # Initialize Ollama manager
            self.ollama_manager = OllamaManager()

            if self.ollama_manager.get_client() is None:
                logger.error("Ollama is not running. Please start Ollama and try again.")
                return 1

            # Auto-detect chunk size if not specified
            if self.args.chunk_size is None:
                self.args.chunk_size = self.ollama_manager.detect_optimal_chunk_size(self.args.embed_model)
            else:
                logger.info(f"Using manual chunk size: {self.args.chunk_size}")

            # Check if --list-models is used
            if self.args.list_models:
                if self.handle_list_models_option():
                    return 0
                return 1

            # Check if input_path is provided when not using --list-models
            if not self.args.input_path:
                logger.error("--input/-i is required when not using --list-models")
                return 1

            # Check Ollama connection before proceeding
            if not self.ollama_manager.check_connection():
                return 1

            # Check if the embedding model is available
            if not self.ollama_manager.ensure_model_available(self.args.embed_model):
                return 1

            self.report = Report(self.args.input_path, self.args.output_format)

            # Initialize embedding manager
            self.embedding_manager = EmbeddingManager(self.args)

            # Process input files
            valid_files = self.embedding_manager.process_input_files(self.args)
            if not valid_files:
                return 1

            # Get vulnerability mapping for all modes
            vuln_mapping = get_vulnerability_mapping()

            # If audit mode is enabled, only analyze embeddings distribution
            if self.args.audit:
                result = self.handle_audit_mode(vuln_mapping)
                return 0 if result else 1

            # Get available models for analysis mode
            available_models = self.ollama_manager.get_available_models()
            if not available_models:
                logger.error("No models available. Please check Ollama installation.")
                return 1

            # Select models for analysis
            selected_models = self.ollama_manager.select_analysis_models(self.args, available_models)
            if not selected_models:
                return 1

            # Run analysis with selected models
            result = self.run_analysis_mode(selected_models, vuln_mapping)
            if not result:
                return 1
            
            # Output cache file location
            logger.info(f"\nCache file: {self.embedding_manager.cache_file}")

            return 0

        except KeyboardInterrupt:
            logger.info("\nProcess interrupted by user. Exiting...")
            # Ensure cache is saved on interruption
            try:
                if hasattr(self, 'embedding_manager') and self.embedding_manager:
                    self.embedding_manager.save_cache()
                    logger.info("Cache saved successfully.")
            except Exception:
                logger.error("Failed to save cache on interruption.")
            return 1
        except Exception as e:
            logger.error(f"An unexpected error occurred: {str(e)}")
            if logger.isEnabledFor(logging.DEBUG):
                logger.exception("Full error trace:")
            return 1


def main():
    """Main entry point for the OASIS scanner"""
    scanner = OasisScanner()
    return scanner.run()

if __name__ == "__main__":
    sys.exit(main())