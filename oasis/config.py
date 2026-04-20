"""
Configuration constants for OASIS.

Environment-driven tunables are grouped below under explicit section headers.

Developer guide — **safe to tweak together** vs **orthogonal knobs**:

1. **Structured-output degeneracy (deep JSON quality)** — tune together when models collapse or
   spam repeated tokens in structured output. Env vars: ``OASIS_STRUCTURED_DEGENERACY_*``
   (see ``STRUCTURED_OUTPUT_DEGENERACY_*`` below). Implemented in
   ``oasis/helpers/structured_output_degeneracy.py``. Related LLM budgets: ``OASIS_CHUNK_*``
   (timeouts / ``num_predict``) in the Ollama section above.

2. **PoC budgeting (prompts + logs, not SARIF/HTML report bodies)** — tune together when PoC
   assist/hints truncate or dominate context. Env vars: ``OASIS_POC_*`` / ``POC_*`` constants
   below; helpers in ``oasis/helpers/poc_digest.py`` and ``oasis/helpers/poc_pipeline.py``.
   Keep aligned with structured-output caps if both feed the same LLM turn.

3. **Context expansion (LangGraph)** — ``OASIS_CONTEXT_EXPAND_*`` / ``CONTEXT_EXPAND_*``;
   separate from PoC digest size but shares overall token pressure with chunk analysis.

4. **CLI debug transcripts** — ``OASIS_LLM_DEBUG_CONTENT_MAX_CHARS`` only affects ``-d`` logging,
   not report payloads.

Section overview:

- **Ollama / HTTP client** — chunk LLM timeouts, structured ``num_predict`` ceiling, HTTP client
  timeout, slow-call warning (model I/O and transport).
- **Structured-output degeneracy** — heuristics when validating deep structured JSON from models.
- **LangGraph context expansion** — padding and max chars around suspicious spans.
- **Heuristic tuning (grouped)** — ties structured-output degeneracy and ``POC_*`` caps; read
  before changing one threshold in isolation.
- **PoC pipeline** — digest size, hints markdown cap, PoC stage log cap for DEBUG.
- **CLI debug** — truncation for ``-d`` / ``llm_debug_log`` transcripts (not report payloads).

**Reference — ``OASIS_*`` env vars for structured-output tuning vs PoC (single source for docs/tests):**

Keep this list in sync when adding new ``_parse_env_int`` / ``_parse_env_float`` calls below.

Structured-output degeneracy (maps to ``STRUCTURED_OUTPUT_DEGENERACY_*``):

- ``OASIS_STRUCTURED_DEGENERACY_MIN_CHARS``
- ``OASIS_STRUCTURED_DEGENERACY_RATIO_MAX``
- ``OASIS_STRUCTURED_DEGENERACY_ZLIB_LEVEL``
- ``OASIS_STRUCTURED_DEGENERACY_REPEAT_UNIT_LEN``
- ``OASIS_STRUCTURED_DEGENERACY_REPEAT_MIN_RUNS``

LangGraph context expansion:

- ``OASIS_CONTEXT_EXPAND_PADDING_BEFORE``
- ``OASIS_CONTEXT_EXPAND_PADDING_AFTER``
- ``OASIS_CONTEXT_EXPAND_MAX_CHARS``

PoC pipeline (digest / hints / DEBUG logs):

- ``OASIS_POC_DIGEST_JSON_MAX_CHARS``
- ``OASIS_POC_STAGE_LOG_MAX_CHARS``
- ``OASIS_POC_HINTS_MAX_CHARS``

Related chunk LLM budgets (often tuned with degeneracy thresholds):

- ``OASIS_CHUNK_ANALYZE_TIMEOUT_SEC``
- ``OASIS_CHUNK_DEEP_NUM_PREDICT``

CLI debug only (orthogonal to reports):

- ``OASIS_LLM_DEBUG_CONTENT_MAX_CHARS``

Transport / diagnostics (same file, separate concern):

- ``OASIS_OLLAMA_HTTP_CLIENT_TIMEOUT_SEC``, ``OASIS_OLLAMA_SLOW_CALL_WARNING_SEC``

Static lists (extensions, models, languages, …) follow those sections.
"""
import copy
import logging
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .legacy_vulnerability_mapping import LEGACY_VULNERABILITY_MAPPING
from .helpers.executive_summary_similarity import (
    executive_summary_tiers_inline_text,
    executive_summary_tiers_markdown_bullets,
)

logger = logging.getLogger("oasis")


def _log_warning_main_process(msg: str, *args: Any, **kwargs: Any) -> None:
    """
    Emit a warning only from the main process.

    Pool workers re-import this module; repeating env clamp warnings there duplicates
    console output and interleaves with tqdm on stderr, corrupting the progress line.
    """
    try:
        from multiprocessing import current_process

        if current_process().name != "MainProcess":
            return
    except Exception:
        pass
    logger.warning(msg, *args, **kwargs)


def _parse_env_int(
    name: str,
    default: int,
    *,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
    warn_clamps: bool = True,
) -> int:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        v = default
    else:
        try:
            v = int(str(raw).strip(), 10)
        except ValueError:
            _log_warning_main_process("Invalid integer for %s=%r; using default %s", name, raw, default)
            v = default
    if minimum is not None and v < minimum:
        if warn_clamps:
            _log_warning_main_process("%s=%s below minimum %s; clamping", name, v, minimum)
        v = minimum
    if maximum is not None and v > maximum:
        if warn_clamps:
            _log_warning_main_process("%s=%s above maximum %s; clamping", name, v, maximum)
        v = maximum
    return v


def _parse_env_float(name: str, default: float, *, minimum: Optional[float] = None, maximum: Optional[float] = None) -> float:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        v = default
    else:
        try:
            v = float(str(raw).strip())
        except ValueError:
            _log_warning_main_process("Invalid float for %s=%r; using default %s", name, raw, default)
            v = default
    if minimum is not None and v < minimum:
        _log_warning_main_process("%s=%s below minimum %s; clamping", name, v, minimum)
        v = minimum
    if maximum is not None and v > maximum:
        _log_warning_main_process("%s=%s above maximum %s; clamping", name, v, maximum)
        v = maximum
    return v

# Analysis version (used for cache compatibility)
# This constant must be incremented manually ONLY when the analysis behavior changes in a way that would make cached results obsolete.
#
# The rule would be simple: the analysis version must be incremented when changes are made to:
# The prompt generation (_build_analysis_prompt)
# The result interpretation logic
# The chunking logic
# The prompt extensions (VULNERABILITY_PROMPT_EXTENSION)
ANALYSIS_VERSION = "2.0"

# Default args values
DEFAULT_ARGS = {
    'THRESHOLD': 0.5,
    'CHUNK_SIZE': 'auto-detected',
    'VULNS': 'all',
    'OUTPUT_FORMAT': 'all',
    'EMBEDDING_ANALYSIS_TYPE': 'file',
    'CACHE_DAYS': 7,
    'EMBED_MODEL': 'nomic-embed-text',
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

# Chunk configuration (static)
MAX_CHUNK_SIZE = 2048
EMBEDDING_FALLBACK_MIN_CHUNK_SIZE = _parse_env_int(
    "OASIS_EMBEDDING_FALLBACK_MIN_CHUNK_SIZE",
    256,
    minimum=64,
)
EMBEDDING_DETECTED_CHUNK_SIZE_MIN = _parse_env_int(
    "OASIS_EMBEDDING_DETECTED_CHUNK_SIZE_MIN",
    64,
    minimum=1,
)
_DETECTED_CHUNK_SIZE_MAX_RECOMMENDED = MAX_CHUNK_SIZE * 4
# Large env values are clamped silently; no CLI warning (no user action required).
EMBEDDING_DETECTED_CHUNK_SIZE_MAX = _parse_env_int(
    "OASIS_EMBEDDING_DETECTED_CHUNK_SIZE_MAX",
    262144,
    minimum=EMBEDDING_DETECTED_CHUNK_SIZE_MIN,
    maximum=_DETECTED_CHUNK_SIZE_MAX_RECOMMENDED,
    warn_clamps=False,
)

# =============================================================================
# Ollama & HTTP client — chunk LLM timeouts, generation budget, transport
# =============================================================================
# Larger ``num_predict`` and longer server timeouts increase VRAM pressure and worst-case latency.
CHUNK_ANALYZE_TIMEOUT = _parse_env_int(
    "OASIS_CHUNK_ANALYZE_TIMEOUT_SEC",
    120,
    minimum=30,
)
# Upper bound for structured deep-generation tokens (VRAM / latency guardrail for misconfigured env).
CHUNK_DEEP_NUM_PREDICT_CEILING = 32768

CHUNK_DEEP_NUM_PREDICT = _parse_env_int(
    "OASIS_CHUNK_DEEP_NUM_PREDICT",
    8192,
    minimum=256,
    maximum=CHUNK_DEEP_NUM_PREDICT_CEILING,
)

_default_ollama_http_timeout = max(CHUNK_ANALYZE_TIMEOUT + 120, 240)
OLLAMA_HTTP_CLIENT_TIMEOUT_SEC = _parse_env_int(
    "OASIS_OLLAMA_HTTP_CLIENT_TIMEOUT_SEC",
    _default_ollama_http_timeout,
    minimum=max(60, CHUNK_ANALYZE_TIMEOUT),
)

OLLAMA_SLOW_CALL_WARNING_SEC = _parse_env_float(
    "OASIS_OLLAMA_SLOW_CALL_WARNING_SEC",
    45.0,
    minimum=1.0,
)

# =============================================================================
# Heuristic tuning — structured-output degeneracy + PoC pipeline (read before changing one knob)
# =============================================================================
# These interact through prompt size, VRAM, and latency. Prefer adjusting related constants
# together and re-checking behavior under ``-d`` / DEBUG when tuning:
# - STRUCTURED_OUTPUT_DEGENERACY_* — ``oasis/helpers/structured_output_degeneracy.py`` (zlib ratio +
#   repeated-pattern probe on raw deep JSON before schema validation).
# - POC_DIGEST_JSON_MAX_CHARS, POC_HINTS_MAX_CHARS, POC_STAGE_LOG_MAX_CHARS —
#   ``oasis/helpers/poc_digest.py``, ``oasis/helpers/poc_pipeline.py`` (digest into LLM prompts,
#   optional hints markdown, DEBUG truncation for stage logs).
# Context expansion windows (CONTEXT_EXPAND_*) are separate but share the same token budget;
# see ``oasis/helpers/context_expand.py``.
# Defaults target consumer GPUs; env var names are on each constant below.

# =============================================================================
# Structured-output degeneracy — deep JSON quality probe (zlib + repeat patterns)
# =============================================================================
STRUCTURED_OUTPUT_DEGENERACY_MIN_RAW_CHARS = _parse_env_int(
    "OASIS_STRUCTURED_DEGENERACY_MIN_CHARS",
    1600,
    minimum=100,
)
STRUCTURED_OUTPUT_DEGENERACY_COMPRESSION_RATIO_MAX = _parse_env_float(
    "OASIS_STRUCTURED_DEGENERACY_RATIO_MAX",
    0.115,
    minimum=0.01,
    maximum=0.99,
)
STRUCTURED_OUTPUT_DEGENERACY_ZLIB_LEVEL = _parse_env_int(
    "OASIS_STRUCTURED_DEGENERACY_ZLIB_LEVEL",
    6,
    minimum=1,
    maximum=9,
)
STRUCTURED_OUTPUT_DEGENERACY_REPEAT_UNIT_LEN = _parse_env_int(
    "OASIS_STRUCTURED_DEGENERACY_REPEAT_UNIT_LEN",
    14,
    minimum=4,
)
STRUCTURED_OUTPUT_DEGENERACY_REPEAT_MIN_RUNS = _parse_env_int(
    "OASIS_STRUCTURED_DEGENERACY_REPEAT_MIN_RUNS",
    16,
    minimum=2,
)

# =============================================================================
# LangGraph context expansion — windows around suspicious spans (characters)
# =============================================================================
CONTEXT_EXPAND_PADDING_BEFORE = _parse_env_int("OASIS_CONTEXT_EXPAND_PADDING_BEFORE", 40, minimum=0)
CONTEXT_EXPAND_PADDING_AFTER = _parse_env_int("OASIS_CONTEXT_EXPAND_PADDING_AFTER", 40, minimum=0)
CONTEXT_EXPAND_MAX_CHARS = _parse_env_int("OASIS_CONTEXT_EXPAND_MAX_CHARS", 12000, minimum=500)

# =============================================================================
# PoC pipeline — digest JSON, hints markdown, stage DEBUG logs (not SARIF/HTML reports)
# =============================================================================
POC_DIGEST_JSON_MAX_CHARS = _parse_env_int("OASIS_POC_DIGEST_JSON_MAX_CHARS", 14000, minimum=500)
POC_STAGE_LOG_MAX_CHARS = _parse_env_int("OASIS_POC_STAGE_LOG_MAX_CHARS", 32000, minimum=500)
POC_HINTS_MAX_CHARS = _parse_env_int("OASIS_POC_HINTS_MAX_CHARS", 20000, minimum=500)

# =============================================================================
# CLI debug — ``-d`` / llm_debug_log truncation (orthogonal to PoC/report payloads)
# =============================================================================
LLM_DEBUG_CONTENT_MAX_CHARS = _parse_env_int("OASIS_LLM_DEBUG_CONTENT_MAX_CHARS", 32000, minimum=500)
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


LANGUAGES = {
    'en': {
        'name': 'English',
        'english_name': 'English',
        'emoji': '🇬🇧'
        },
    'fr': {
        'name': 'Français',
        'english_name': 'French',
        'emoji': '🇫🇷'
    },
    'es': {
        'name': 'Español',
        'english_name': 'Spanish',
        'emoji': '🇪🇸'
    },
    'de': {
        'name': 'Deutsch',
        'english_name': 'German',
        'emoji': '🇩🇪'
    },
    'it': {
        'name': 'Italiano',
        'english_name': 'Italian',
        'emoji': '🇮🇹'
    },
    'pt': {
        'name': 'Português',
        'english_name': 'Portuguese',
        'emoji': '🇵🇹'
    },
    'ru': {
        'name': 'Русский',
        'english_name': 'Russian',
        'emoji': '🇷🇺'
    },
    'zh': {
        'name': '中文',
        'english_name': 'Chinese',
        'emoji': '🇨🇳'
    },
    'ja': {
        'name': '日本語',
        'english_name': 'Japanese',
        'emoji': '🇯🇵'
    }
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
    return next(
        (
            f"'patterns'[{i}] must be a string, got {type(item).__name__}"
            for i, item in enumerate(patterns)
            if not isinstance(item, str)
        ),
        None,
    )


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
    if env_dir := os.environ.get("OASIS_VULNERABILITY_DIR"):
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
# Intentionally computed at import time: executive-summary tiers are static constants for a process run.
# If tiers become runtime-configurable later, move this interpolation to report-generation time.
_EXEC_SUMMARY_TIERS_BULLETS_MD = executive_summary_tiers_markdown_bullets()
_EXEC_SUMMARY_TIERS_INLINE_TEXT = executive_summary_tiers_inline_text()

REPORT = {
    'OUTPUT_FORMATS': ['json', 'sarif', 'pdf', 'html', 'md'],
    # Dashboard / API: human-readable first; any OUTPUT_FORMATS entry missing here is appended after
    'DASHBOARD_FORMAT_DISPLAY_ORDER': ['html', 'pdf', 'md', 'json', 'sarif'],
    # Realtime dashboard behavior
    'DASHBOARD_REALTIME_ENABLED': True,
    'DASHBOARD_SOCKETIO_CLIENT_URL': 'https://cdn.socket.io/4.7.5/socket.io.min.js',
    'DASHBOARD_SOCKETIO_ASYNC_MODE': 'auto',
    # Optional extra Socket.IO origins (use {port} for the dashboard port). Runtime always
    # adds http://127.0.0.1:{port}, http://localhost:{port}, and when web_expose is not
    # "local", discovered LAN http://<ip>:{port} URLs for remote browsers.
    'DASHBOARD_SOCKETIO_CORS_ALLOWED_ORIGINS': [],
    'DASHBOARD_PROGRESS_MONITOR_INTERVAL_SECONDS': 2.0,
    'OUTPUT_DIR': 'security_reports',
    'BACKGROUND_COLOR': '#F5F2E9',
    'EXPLAIN_ANALYSIS': f"""
## About This Report
This security analysis report uses embedding similarity to identify potential vulnerabilities in your codebase.

## Understanding Code Embeddings
Code embeddings are advanced representations that convert your code into numerical vectors capturing meaning and context. Unlike simple pattern matching:

- Embeddings understand the **purpose** of code, not just its syntax
- They can detect similar **concepts** across different programming styles
- They provide a **measure of relevance** through similarity scores (0.0-1.0)

## Working with Similarity Scores
Similarity scores (0.0–1.0) measure **semantic overlap** between a vulnerability description and your code via embeddings. They are **not** the same as structured finding severity labels from the deep analysis model.

### Executive summary tiers (embedding relevance only)
The executive summary groups matches by cosine similarity using fixed cutoffs — **independent** of `--threshold` and of per-finding severities in vulnerability reports:

{_EXEC_SUMMARY_TIERS_BULLETS_MD}

### Informal triage bands (reports and audit exploration)
When reading distribution tables or prioritizing manual review without using the executive summary tiers above, many teams use coarse bands such as:

- **Stronger contextual match (≥0.6)**: Worth reviewing early  
- **Partial match (0.4–0.6)**: Investigate with context  
- **Weaker match (<0.4)**: Often noise; verify against the vulnerability description  

Your configured **scan threshold** (`--threshold`, default 0.5) decides which files enter the scanner at all.

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
- Review the strongest embedding matches and structured findings first
- Schedule code reviews for items with substantive LLM findings or high similarity
- Consider incorporating these checks into your CI/CD pipeline
- Use the executive summary to communicate **coverage and similarity-based prioritization** to stakeholders (pair it with detail reports for actual severity)
    """,
    'EXPLAIN_EXECUTIVE_SUMMARY': f"""
## How to read this executive summary
The tables below group analyzed files by **embedding similarity** between each vulnerability type and the file (cosine similarity). This ordering reflects **retrieval relevance**, not exploit severity and not the severity labels inside per-vulnerability JSON/HTML reports.

**Tiers**: {_EXEC_SUMMARY_TIERS_INLINE_TEXT}. For authoritative finding counts and severities, open the linked vulnerability-type reports.
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
