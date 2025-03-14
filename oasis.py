import argparse
import sys
from pathlib import Path
from tqdm import tqdm

# Import from our modules
from tools import (
    setup_logging, logger, display_logo, parse_input, get_output_directory, 
    sanitize_model_name
)
from ollama_manager import (
    check_ollama_connection, get_available_models, detect_optimal_chunk_size,
    ensure_model_available, select_models, format_model_display
)
from embedding import EmbeddingManager
from analyze import (
    SecurityAnalyzer, get_vulnerability_mapping, analyze_embeddings_distribution,
    generate_audit_report
)
from report import (
    convert_md_to_pdf, generate_markdown_report, generate_executive_summary
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

def main():
    try:
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

        args = parser.parse_args()

        # Setup logging
        setup_logging(debug=args.debug, silent=args.silent)

        # Display logo
        display_logo()

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
                logger.info(format_model_display(model))
            return

        # Check if input_path is provided when not using --list-models
        if not args.input_path:
            parser.error("--input/-i is required when not using --list-models")

        # Check Ollama connection before proceeding
        if not check_ollama_connection():
            logger.error("\nError: Could not connect to Ollama server")
            logger.error("Please ensure that:")
            logger.error("1. Ollama is installed (https://ollama.ai)")
            logger.error("2. Ollama server is running (usually with 'ollama serve')")
            logger.error("3. Ollama is accessible (default: http://localhost:11434)")
            return

        # Parse custom extensions if provided
        custom_extensions = None
        if args.extensions:
            custom_extensions = [ext.strip().lower() for ext in args.extensions.split(',')]
            logger.debug(f"Using custom extensions: {', '.join(custom_extensions)}")

        # Get available models for analysis if not in audit mode
        if not args.audit:
            available_models = get_available_models()
            if not available_models:
                logger.error("No models available. Please check Ollama installation.")
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

        # Create embedding manager (this will be shared by all analysis models)
        embedding_manager = EmbeddingManager(
            embedding_model=args.embed_model,
            extensions=custom_extensions,
            chunk_size=args.chunk_size
        )

        # Set cache file path and load cache
        embedding_manager.cache_file = Path(args.input_path).parent / "embeddings_cache.pkl"

        # Clear cache if requested
        if args.clear_cache:
            logger.info("Clearing embeddings cache...")
            embedding_manager.clear_cache()

        # Load existing cache
        embedding_manager.load_cache()

        # Parse input files and generate embeddings
        files_to_analyze = parse_input(args.input_path)
        if not files_to_analyze:
            logger.error("No valid files to analyze")
            return

        # Filter files by supported extensions
        valid_files = []
        for file_path in files_to_analyze:
            if embedding_manager.is_valid_file(file_path):
                valid_files.append(file_path)
            else:
                logger.debug(f"Skipping unsupported file: {file_path}")

        if not valid_files:
            logger.error("No files with supported extensions found for analysis")
            return

        logger.info(f"Found {len(valid_files)} files with supported extensions out of {len(files_to_analyze)} total files")

        # Generate embeddings only for new files
        new_files = []
        for file_path in valid_files:
            file_key = str(file_path)
            if (file_key not in embedding_manager.code_base or 
                not isinstance(embedding_manager.code_base[file_key], dict) or
                'embedding' not in embedding_manager.code_base[file_key] or 
                'chunks' not in embedding_manager.code_base[file_key] or
                'timestamp' not in embedding_manager.code_base[file_key]):
                new_files.append(file_path)

        if new_files:
            logger.info(f"Generating embeddings for {len(new_files)} new files")
            embedding_manager.index_code_files(new_files)
        else:
            logger.debug("All files found in cache with valid structure")

        # If audit mode is enabled, only analyze embeddings distribution
        if args.audit:
            logger.info("\nRunning in Audit Mode")
            logger.info("====================")

            # Get vulnerability types
            vulnerabilities = list(vuln_mapping.values())

            # Analyze embeddings distribution
            analyze_embeddings_distribution(embedding_manager, vulnerabilities)

            # Generate and save analysis report with progress indication
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

            # Create analyzer with current model
            analyzer = SecurityAnalyzer(
                llm_model=model,
                embedding_model=args.embed_model,
                code_base=embedding_manager.code_base
            )

            # Determine which vulnerabilities to check
            if args.vulns.lower() == 'all':
                vulnerabilities = list(vuln_mapping.values())
            else:
                selected_tags = [tag.strip() for tag in args.vulns.split(',')]
                if invalid_tags := [
                    tag for tag in selected_tags if tag not in vuln_mapping
                ]:
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
                    results = analyzer.search_vulnerabilities(vuln['name'], threshold=args.threshold)

                    # Then analyze each file in detail with progress bar
                    detailed_results = []
                    with tqdm(results, 
                             desc=f"Analyzing {vuln['name']} details", 
                             disable=args.silent,
                             leave=False) as file_pbar:
                        for file_path, similarity_score in file_pbar:
                            file_pbar.set_postfix_str(f"File: {Path(file_path).name}")
                            analysis = analyzer.analyze_vulnerability(file_path, vuln['name'])
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
        abs_report_path = str(output_dir.absolute())
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

        logger.info(f"\nCache file: {embedding_manager.cache_file}")

    except KeyboardInterrupt:
        logger.info("\n\n🛑 Analysis interrupted by user")
        logger.info("Cleaning up and saving current progress...")
        try:
            # Save any pending cache
            if 'embedding_manager' in locals():
                embedding_manager.save_cache()
            logger.info("✅ Progress saved successfully")
        except Exception as e:
            logger.error(f"❌ Error during saving progress: {str(e)}")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Unexpected error: {str(e)}")
        try:
            if args.debug:
                logger.debug("Full error:", exc_info=True)
        except NameError:
            # args not defined yet, show traceback anyway
            logger.debug("Full error (args not defined):", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()