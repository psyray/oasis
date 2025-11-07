"""
OASIS - Ollama Automated Security Intelligence Scanner

A powerful AI-powered security auditing tool that leverages Ollama models to detect
and analyze potential security vulnerabilities in codebases.

Main Features:
    - Two-phase scanning architecture for optimized analysis
    - Adaptive multi-level analysis with risk-based depth adjustment
    - Comprehensive vulnerability detection across 17+ vulnerability types
    - Multiple output formats (PDF, HTML, Markdown, JSON, SARIF)
    - Web interface with password protection
    - Intelligent caching for improved performance
    - Support for 100+ file extensions

Example:
    Basic usage from command line:
        $ oasis -i /path/to/code -m gemma3:27b

    From Python:
        >>> from oasis import main
        >>> main()

Modules:
    oasis: Main scanner class and CLI entry point
    analyze: Security analysis and vulnerability detection
    embedding: Code embedding and similarity calculations
    cache: Caching system for embeddings and analysis results
    report: Multi-format report generation
    web: Web interface for interactive exploration
    ollama_manager: Ollama model management and API interaction
    tools: Utility functions and helpers
    config: Configuration constants and defaults
    enums: Enumeration types for analysis modes

Author: psyray
License: GPL-3.0
Repository: https://github.com/psyray/oasis
"""

from .oasis import main

__version__ = "0.4.1"

__all__ = ['main', '__version__'] 