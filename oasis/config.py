"""
Configuration constants for OASIS
"""
import copy
import logging
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .legacy_vulnerability_mapping import LEGACY_VULNERABILITY_MAPPING

logger = logging.getLogger("oasis")

# Analysis version (used for cache compatibility)
# This constant must be incremented manually ONLY when the analysis behavior changes in a way that would make cached results obsolete.
#
# The rule would be simple: the analysis version must be incremented when changes are made to:
# The prompt generation (_build_analysis_prompt)
# The result interpretation logic
# The chunking logic
# The prompt extensions (VULNERABILITY_PROMPT_EXTENSION)
ANALYSIS_VERSION = "1.0"

# Default args values
DEFAULT_ARGS = {
    'THRESHOLD': 0.5,
    'CHUNK_SIZE': 'auto-detected',
    'VULNS': 'all',
    'OUTPUT_FORMAT': 'all',
    'ANALYSIS_TYPE': 'standard',
    'EMBEDDING_ANALYSIS_TYPE': 'file',
    'CACHE_DAYS': 7,
    'EMBED_MODEL': 'nomic-embed-text:latest',
    'SCAN_MODEL': None,  # If None, same as main model
}


# Set of supported file extensions (without dot)
SUPPORTED_EXTENSIONS: Set[str] = {
    # Web Development
    'html', 'htm', 'css', 'js', 'jsx', 'ts', 'tsx', 'asp', 'aspx', 'jsp',
    'vue', 'svelte',
    
    # Programming Languages
    'py', 'pyc', 'pyd', 'pyo', 'pyw',  # Python
    'java', 'class', 'jar',              # Java
    'cpp', 'c', 'cc', 'cxx', 'h', 'hpp', 'hxx',  # C/C++
    'cs',                                  # C#
    'go',                                  # Go
    'rs',                                  # Rust
    'rb', 'rbw',                         # Ruby
    'swift',                              # Swift
    'kt', 'kts',                         # Kotlin
    'scala',                              # Scala
    'pl', 'pm',                          # Perl
    'php', 'phtml', 'php3', 'php4', 'php5', 'phps',  # PHP
    
    # Mobile Development
    'm', 'mm',                           # Objective-C
    'dart',                               # Flutter
    
    # Shell Scripts
    'sh', 'bash', 'csh', 'tcsh', 'zsh', 'fish',
    'bat', 'cmd', 'ps1',                # Windows Scripts
    
    # Database
    'sql', 'mysql', 'pgsql', 'sqlite',
    
    # Configuration & Data
    'xml', 'yaml', 'yml', 'json', 'ini', 'conf', 'config',
    'toml', 'env',
    
    # System Programming
    'asm', 's',                          # Assembly
    'f', 'for', 'f90', 'f95',         # Fortran
    
    # Other Languages
    'lua',                                # Lua
    'r', 'R',                           # R
    'matlab',                            # MATLAB
    'groovy',                            # Groovy
    'erl',                               # Erlang
    'ex', 'exs',                        # Elixir
    'hs',                                # Haskell
    'lisp', 'lsp', 'cl',              # Lisp
    'clj', 'cljs',                     # Clojure
    
    # Smart Contracts
    'sol',                               # Solidity
    
    # Template Files
    'tpl', 'tmpl', 'template',
    
    # Documentation
    'md', 'rst', 'adoc',              # Documentation files
    
    # Build & Package
    'gradle', 'maven',
    'rake', 'gemspec',
    'cargo', 'cabal',
    'cmake', 'make',
    
    # Container & Infrastructure
    'dockerfile', 'containerfile',
    'tf', 'tfvars',                    # Terraform
    
    # Version Control
    'gitignore', 'gitattributes', 'gitmodules'
} 

# Chunk configuration
MAX_CHUNK_SIZE = 2048
CHUNK_ANALYZE_TIMEOUT = 120
EMBEDDING_THRESHOLDS = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]

# Ollama API endpoint
OLLAMA_URL = "http://localhost:11434"

# Models configuration
EXCLUDED_MODELS = [
    'embed',
    'instructor',
    'text-',
    'minilm',
    'e5-',
    'cline'
]

DEFAULT_MODELS = [
    'llama2',
    'llama2:13b',
    'codellama',
    'codellama:13b',
    'gemma:2b',
    'gemma:7b',
    'mistral',
    'mixtral'
]

# Keywords lists for logging emojis
KEYWORD_LISTS = {
    'INSTALL_WORDS': ['installing', 'download', 'pulling', 'fetching'],
    'START_WORDS': ['starting', 'beginning', 'beginning', 'starting'],
    'FINISH_WORDS': ['finished', 'completed', 'done', 'finished'],
    'SUCCESS_WORDS': ['success', 'done'],
    'FAIL_WORDS': ['failed', 'error', 'crash', 'exception'],
    'STOPPED_WORDS': ['interrupted', 'stopped'],
    'ANALYSIS_WORDS': ['analyzing', 'analysis', 'scanning', 'checking', 'inspecting', 'examining', 'found', 'querying'],
    'GENERATION_WORDS': ['generating', 'creating', 'building', 'processing'],
    'REPORT_WORDS': ['report'],
    'MODEL_WORDS': ['model', 'ai', 'llm'],
    'CACHE_WORDS': ['cache', 'stored', 'saving'],
    'SAVE_WORDS': ['saved', 'written', 'exported'],
    'LOAD_WORDS': ['loading', 'reading', 'importing', 'loaded'],
    'DELETE_WORDS': ['deleting', 'removing', 'deleted'],
    'STATISTICS_WORDS': ['statistics'],
    'TOP_WORDS': ['top', 'highest', 'most', 'better'],
    'VULNERABILITY_WORDS': ['vulnerability', 'vulnerabilities']
}

# Model emojis mapping
MODEL_EMOJIS = {
    # General models
    "deepseek": "🧠 ",
    "llama": "🦙 ",
    "gemma": "💎 ",
    "mistral": "💨 ",
    "mixtral": "🌪️ ", 
    "qwen": "🐧 ",
    "phi": "φ ",
    "yi": "🌐 ",
    
    # Code models
    "codestral": "🌠 ",
    "starcoder": "⭐ ",
    
    # Interaction models
    "instruct": "💬 ",
    "chat": "💬 ",
    
    # Cybersecurity models
    "cybersecurity": "🛡️  ",
    "whiterabbit": "🐇 ",
    "sast": "🛡️  ",
    
    # Other models
    "research": "🔬 ",
    "openhermes": "🌟 ",
    "solar": "☀️ ",
    "neural-chat": "🧠💬 ",
    "nous": "👥 ",
    "default": "🤖 "
}

VULN_EMOJIS = {
    # Injection vulnerabilities
    "sql_injection": "💉 ",
    "remote_code_execution": "🔥 ",
    "cross-site_scripting_(xss)": "🔀 ",
    "xml_external_entity_injection": "📄 ",
    "server-side_request_forgery": "🔄 ",
    "command_injection": "⌨️ ",
    "code_injection": "📝 ",
    
    # Authentication and Authorization
    "authentication_issues": "🔑 ",
    "cross-site_request_forgery": "↔️ ",
    "insecure_direct_object_reference": "🔢 ",
    "session_management_issues": "🍪 ",
    "auth_bypass": "🔓 ",
    "missing_access_control": "🚫 ",
    "privilege_escalation": "🔝 ",
    
    # Data Security
    "sensitive_data_exposure": "🕵️ ",
    "hardcoded_secrets": "🔐 ",
    "sensitive_data_logging": "📝 ",
    "information_disclosure": "📢 ",
    
    # File System
    "path_traversal": "📂 ",
    "lfi": "📁 ",
    "rfi": "📡 ",
    
    # Configuration
    "security_misconfiguration": "⚙️ ",
    "outdated_component": "⌛ ",
    "open_redirect": "↪️ ",
    
    # Input Validation
    "insufficient_input_validation": "⚠️ ",
    "crlf": "↩️ ",
    
    # Cryptographic
    "insecure_cryptographic_usage": "🔒 ",
    "weak_crypto": "🔒 ",
    "cert_validation": "📜 ",
    "insecure_random": "🎲 ",
    
    # Deserialization
    "insecure_deserialization": "📦 ",
    "unsafe_yaml": "📋 ",
    "pickle_issues": "🥒 ",
    
    # Performance and DoS
    "dos": "💥 ",
    "race_condition": "🏁 ",
    "buffer_overflow": "📊 ",
    "integer_overflow": "🔢 ",
    "memory_leak": "💧 ",
    
    # Other
    "mitm": "🕸️ ",
    "business_logic": "💼 ",
    "weak_credentials": "🔏 ", 
    
    # Risk Categories
    "high_risk": "🚨 ",
    "medium_risk": "⚠️ ",
    "low_risk": "📌 ",
    "info": "ℹ️ ",
    "unclassified": "❓ "
}


def _vulnerability_definition_shape_error(data: Any) -> Optional[str]:
    """
    Return a short error message if ``data`` is not a usable vulnerability definition dict,
    otherwise None.
    """
    if not isinstance(data, dict):
        return "root value must be a JSON object"
    for key in ("name", "description", "impact", "mitigation"):
        if key not in data:
            return f"missing required key {key!r}"
        val = data[key]
        if not isinstance(val, str):
            return f"{key!r} must be a string, got {type(val).__name__}"
    if "patterns" not in data:
        return "missing required key 'patterns'"
    patterns = data["patterns"]
    if not isinstance(patterns, list):
        return f"'patterns' must be a list, got {type(patterns).__name__}"
    if not patterns:
        return "'patterns' must be a non-empty list"
    for i, item in enumerate(patterns):
        if not isinstance(item, str):
            return f"'patterns'[{i}] must be a string, got {type(item).__name__}"
    return None


def load_vulnerability_definitions() -> Dict[str, Any]:
    """
    Load vulnerability definitions from JSON files in a vulnerability/ directory.

    Resolution order for the directory path:
        1. ``OASIS_VULNERABILITY_DIR`` environment variable (expanded path), if set.
           If that value cannot be resolved (invalid path, I/O errors), a warning is logged
           and resolution continues with (2).
        2. ``<repository root>/vulnerability`` (parent of the ``oasis`` package directory).

    If the directory is missing, not a directory, or no definitions load successfully
    (empty directory or only unreadable/invalid JSON), returns the legacy built-in mapping.

    Partial loads are returned when at least one file succeeds; failures are logged.

    Each JSON file must define an object with string fields ``name``, ``description``,
    ``impact``, ``mitigation``, and a non-empty ``patterns`` list of strings. Invalid
    shapes are rejected (logged, counted as failures) and are not stored.

    Returns:
        Dict containing vulnerability definitions.
    """
    vulnerabilities: Dict[str, Any] = {}
    package_dir = Path(__file__).resolve().parent
    default_vuln_dir = package_dir.parent / "vulnerability"
    env_dir = os.environ.get("OASIS_VULNERABILITY_DIR")
    if env_dir:
        try:
            vuln_dir = Path(env_dir).expanduser().resolve()
        except (OSError, RuntimeError) as exc:
            logger.warning(
                "Invalid OASIS_VULNERABILITY_DIR %r (%s); trying default directory %s.",
                env_dir,
                exc,
                default_vuln_dir,
            )
            vuln_dir = default_vuln_dir
    else:
        vuln_dir = default_vuln_dir

    if not vuln_dir.exists() or not vuln_dir.is_dir():
        logger.warning(
            "Vulnerability definitions directory not found or not a directory (%s); "
            "using built-in legacy definitions.",
            vuln_dir,
        )
        return _get_legacy_vulnerability_mapping()

    loaded_files = 0
    failed_files = 0

    for json_file in sorted(vuln_dir.glob("*.json")):
        vuln_key = json_file.stem
        if vuln_key in vulnerabilities:
            logger.warning(
                "Duplicate vulnerability key '%s' in %s; skipping to preserve the first entry.",
                vuln_key,
                json_file,
            )
            failed_files += 1
            continue
        try:
            with json_file.open("r", encoding="utf-8") as f:
                vuln_data = json.load(f)
            shape_err = _vulnerability_definition_shape_error(vuln_data)
            if shape_err is not None:
                failed_files += 1
                logger.warning(
                    "Vulnerability definition in %s has invalid shape (%s); skipping.",
                    json_file,
                    shape_err,
                )
                continue
            vulnerabilities[vuln_key] = vuln_data
            loaded_files += 1
        except json.JSONDecodeError as exc:
            failed_files += 1
            logger.warning(
                "Failed to decode vulnerability definition file %s: %s",
                json_file,
                exc,
            )
        except OSError as exc:
            failed_files += 1
            logger.warning(
                "Failed to read vulnerability definition file %s: %s",
                json_file,
                exc,
            )

    if loaded_files == 0:
        logger.warning(
            "No vulnerability definitions could be loaded from %s; "
            "using built-in legacy definitions.",
            vuln_dir,
        )
        return _get_legacy_vulnerability_mapping()

    if failed_files > 0:
        logger.warning(
            "Loaded vulnerability definitions from %d file(s) in %s, but %d file(s) failed or were skipped.",
            loaded_files,
            vuln_dir,
            failed_files,
        )

    return vulnerabilities

def _get_legacy_vulnerability_mapping() -> Dict[str, Any]:
    """
    Legacy hardcoded vulnerability definitions for backward compatibility.
    This serves as a fallback when JSON files are not available.
    """
    return copy.deepcopy(LEGACY_VULNERABILITY_MAPPING)

# Load vulnerability definitions dynamically
VULNERABILITY_MAPPING = load_vulnerability_definitions()

# Prompt extension for vulnerability analysis
VULNERABILITY_PROMPT_EXTENSION = """
    When analyzing code for security vulnerabilities:
    1. Consider both direct and indirect vulnerabilities
    2. Check for proper input validation and sanitization
    3. Evaluate authentication and authorization mechanisms
    4. Look for insecure dependencies or API usage
    5. Identify potential logic flaws that could lead to security bypasses
    6. Consider the context and environment in which the code will run
    """

# Model and prompt for function extraction
EXTRACT_FUNCTIONS = {
    'MODEL': 'gemma:2b',
    'ANALYSIS_TYPE': 'file',
    'PROMPT': """
        For each function, return:
        1. The function name
        2. The exact start and end position (character index) in the source code
        3. The source code, it's mandatory to be base64 encoded
        4. The entire function body, it's mandatory to be base64 encoded
        5. The function parameters
        6. The function return type

        Format your response as JSON:
        {{
            "functions": [
                {{
                    "name": "function_name",
                    "start": 123,
                    "end": 456,
                    "source_code": "source_code",
                    "body": "function_body",
                    "parameters": ["param1", "param2"],
                    "return_type": "return_type"
                }}
            ]
        }}
        I want the Full List of Functions, not just a few.
        Do not have any other text, advice or thinking.
        """
}

# Report configuration
REPORT = {
    'OUTPUT_FORMATS': ['json', 'sarif', 'pdf', 'html', 'md'],
    # Dashboard / API: human-readable first; any OUTPUT_FORMATS entry missing here is appended after
    'DASHBOARD_FORMAT_DISPLAY_ORDER': ['html', 'pdf', 'md', 'json', 'sarif'],
    'OUTPUT_DIR': 'security_reports',
    'BACKGROUND_COLOR': '#F5F2E9',
    'EXPLAIN_ANALYSIS': """
## About This Report
This security analysis report uses embedding similarity to identify potential vulnerabilities in your codebase.

## Understanding Code Embeddings
Code embeddings are advanced representations that convert your code into numerical vectors capturing meaning and context. Unlike simple pattern matching:

- Embeddings understand the **purpose** of code, not just its syntax
- They can detect similar **concepts** across different programming styles
- They provide a **measure of relevance** through similarity scores (0.0-1.0)

## Working with Similarity Scores
- **High (≥0.6)**: Strong contextual match requiring immediate attention
- **Medium (0.4-0.6)**: Partial match worth investigating
- **Low (<0.4)**: Minimal contextual relationship, often false positives

<div class="page-break"></div>

## How to Use This Report
- **Start with high scores**: Focus first on findings above your threshold (default 0.5)
- **Adjust threshold** with `--threshold` flag (higher for fewer false positives, lower for more coverage)
- **Compare code vs patterns**: Verify matches against the vulnerability descriptions
- **Use distribution insights**: The threshold analysis shows how vulnerabilities cluster
- **Consider context**: Some clean code may naturally resemble vulnerable patterns

## Optimizing Your Analysis
- Increase threshold (`--threshold 0.6`) when experiencing too many false positives
- Decrease threshold (`--threshold 0.3`) when conducting thorough security audits
- Run audit mode (`--audit`) to understand your codebase's embedding distribution
- Customize vulnerability types (`--vulns sqli,xss,rce`) to focus on specific risks
- Adjust chunk size (`--chunk-size 2048`) for more contextual analysis of larger functions

## Next Steps
- Review all high-risk findings immediately
- Schedule code reviews for medium-risk items
- Consider incorporating these checks into your CI/CD pipeline
- Use the executive summary to communicate risks to management
    """,
    'EXPLAIN_EXECUTIVE_SUMMARY': """
## Executive Summary
This report provides a high-level overview of security vulnerabilities detected in the codebase.
    """
}

_cfg_log = logging.getLogger(__name__)


def validate_report_dashboard_formats(report_cfg: Optional[Dict[str, Any]] = None) -> List[str]:
    """
    Return ``DASHBOARD_FORMAT_DISPLAY_ORDER`` entries that are not in ``OUTPUT_FORMATS``
    (case-insensitive). Logs a warning when any are found.

    Not run at import time: call from CLI / web entrypoints (see ``OasisScanner._init_arguments``)
    or from tests that import this function explicitly.
    """
    r = report_cfg if report_cfg is not None else REPORT
    allowed_lower = {str(x).lower() for x in (r.get("OUTPUT_FORMATS") or [])}
    order = r.get("DASHBOARD_FORMAT_DISPLAY_ORDER") or []
    bad = [x for x in order if str(x).lower() not in allowed_lower]
    if bad:
        _cfg_log.warning(
            "DASHBOARD_FORMAT_DISPLAY_ORDER contains formats missing from OUTPUT_FORMATS: %s",
            bad,
        )
    return bad
