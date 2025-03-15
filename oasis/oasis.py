import argparse
import logging
import sys
from pathlib import Path
from datetime import datetime

from .tools import (
    setup_logging, logger, display_logo, get_output_directory
)
from .ollama_manager import (
    check_ollama_connection, get_available_models, detect_optimal_chunk_size,
    ensure_model_available, select_analysis_models
)
from .embedding import process_input_files, setup_embedding_manager
from .analyze import (
    get_vulnerability_mapping, analyze_embeddings_distribution,
    generate_audit_report, process_analysis_with_model, get_vulnerabilities_to_check
)
from .report import (
    setup_model_directories, display_report_structure
)

def get_vulnerability_help() -> str:
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

def handle_list_models_option(args):
    """Handle --list-models option"""
    try:
        logger.info("Querying available models from Ollama...")
        
        # Use True for the show_formatted parameter to display numbers 
        available_models = get_available_models(show_formatted=True)
        
        if not available_models:
            logger.error("No models available. Please check your Ollama installation.")
            return True

        return True
    except Exception as e:
        logger.error(f"Error listing models: {str(e)}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Full error:", exc_info=True)
        return False

def setup_argument_parser():
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
                       
    return parser

def run_analysis_mode(args, embedding_manager, selected_models, vuln_mapping, output_dir):
    """Run the analysis mode with the selected models"""
    # For each selected model
    for model in selected_models:
        logger.info(f"\nAnalyzing with model: {model}")
        
        # Setup directories for this model
        _, _, report_dirs = setup_model_directories(model, output_dir)
        
        # Determine which vulnerabilities to check
        vulnerabilities, _ = get_vulnerabilities_to_check(args, vuln_mapping)
        if vulnerabilities is None:
            # Skip this model if there are invalid tags
            continue
            
        # Process analysis with this model
        process_analysis_with_model(model, vulnerabilities, embedding_manager, args, report_dirs)

    # Display structure of generated files
    display_report_structure(selected_models, output_dir)

def handle_audit_mode(args, embedding_manager, vuln_mapping, output_dir):
    """Handle audit mode operation"""
    logger.info("\nRunning in Audit Mode")
    logger.info("====================")

    # Get vulnerability types
    vulnerabilities = list(vuln_mapping.values())

    # Analyze embeddings distribution
    analyze_embeddings_distribution(embedding_manager, vulnerabilities)

    # Generate and save analysis report
    logger.info("\nGenerating audit report...")
    report_files = generate_audit_report(
        embedding_manager, 
        vulnerabilities,
        output_dir
    )

    logger.info("\nAudit analysis completed!")
    logger.info("\nReports generated:")
    for fmt, path in report_files.items():
        logger.info(f"- {fmt.upper()}: {path}")

def main():
    try:
        # Parse command line arguments
        parser = setup_argument_parser()
        args = parser.parse_args()

        # Create output directory for logs if in silent mode
        if args.silent:
            logs_dir = Path(args.input_path).resolve().parent / "security_reports" / "logs" if args.input_path else Path("security_reports/logs")
            logs_dir.mkdir(parents=True, exist_ok=True)
            log_file = logs_dir / f"oasis_errors_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        else:
            log_file = None

        # Setup logging
        setup_logging(debug=args.debug, silent=args.silent, error_log_file=log_file)
        
        # Check if models are specified when in silent mode
        if args.silent and not args.models and not args.list_models and not args.audit:
            parser.error("When using --silent mode, you must specify models with --models/-m")
            
        display_logo()

        # Auto-detect chunk size if not specified
        if args.chunk_size is None:
            args.chunk_size = detect_optimal_chunk_size(args.embed_model)
        else:
            logger.info(f"Using manual chunk size: {args.chunk_size}")

        # Check if --list-models is used
        if args.list_models:
            if handle_list_models_option(args):
                return
            return

        # Check if input_path is provided when not using --list-models
        if not args.input_path:
            parser.error("--input/-i is required when not using --list-models")

        # Check Ollama connection before proceeding
        if not check_ollama_connection():
            return

        # Check if the embedding model is available
        if not ensure_model_available(args.embed_model):
            return

        # Create output directory for reports
        base_reports_dir = Path(args.input_path).resolve().parent / "security_reports"
        base_reports_dir.mkdir(exist_ok=True)
        output_dir = get_output_directory(Path(args.input_path), base_reports_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize embedding manager
        embedding_manager = setup_embedding_manager(args)

        # Process input files
        valid_files = process_input_files(args, embedding_manager)
        if not valid_files:
            return

        # Get vulnerability mapping for all modes
        vuln_mapping = get_vulnerability_mapping()

        # If audit mode is enabled, only analyze embeddings distribution
        if args.audit:
            handle_audit_mode(args, embedding_manager, vuln_mapping, output_dir)
            return

        # Get available models for analysis mode
        available_models = get_available_models()
        if not available_models:
            logger.error("No models available. Please check Ollama installation.")
            return

        # Select models for analysis
        selected_models = select_analysis_models(args, available_models)
        if not selected_models:
            return

        # Run analysis with selected models
        run_analysis_mode(args, embedding_manager, selected_models, vuln_mapping, output_dir)
        
        # Output cache file location
        logger.info(f"\nCache file: {embedding_manager.cache_file}")

    except KeyboardInterrupt:
        logger.info("\nProcess interrupted by user. Exiting...")
        # Ensure cache is saved on interruption
        try:
            if 'embedding_manager' in locals():
                embedding_manager.save_cache()
                logger.info("Cache saved successfully.")
        except Exception:
            logger.error("Failed to save cache on interruption.")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {str(e)}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.exception("Full error trace:")
        return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())