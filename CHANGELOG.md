## 🚀 [0.5.1] - 2026-04-21

### ✨ Added
- 🛡️ **Assistant validation of findings** (`POST /api/assistant/investigate`): a deterministic, code-driven agent that classifies each vulnerability into one of three families (**flow**, **access**, **config**) and assembles a verdict (`confirmed_exploitable` / `likely_exploitable` / `needs_review` / `not_exploitable`) with confidence and full citations. It discovers framework-specific **entry points**, traces **call paths** to the sink, detects **taint flows** (source → sink inside the enclosing function), identifies **nullifying mitigations** (parameterized SQL, path normalizers, sanitizers, ORMs, etc.), verifies **required controls** (auth/CSRF/session/JWT/CORS), and runs **config/secret/crypto/log-leak** audits. Orchestrated with **LangGraph** when available, with a pure-Python fallback. Dashboard exposes a **Validate this finding** button and a verdict panel rendering every piece of collected evidence.
- 📝 **Validation LLM narrative** (`oasis/helpers/assistant_investigation_synth.py`): after the deterministic verdict, the server optionally calls the dashboard **chat model** (same Ollama endpoint as `/api/assistant/chat`) to produce `narrative_markdown` that explains the evidence without overriding `status` / `confidence` / `summary`. JSON field `synthesize_narrative` defaults to true; pass `model` or rely on the report’s `model_name`.
- 🧩 **Validation helpers** (`oasis/helpers/assistant_entrypoints.py`, `assistant_trace.py`, `assistant_taint.py`, `assistant_mitigations.py`, `assistant_authz.py`, `assistant_controls.py`, `assistant_config_audit.py`, `assistant_secret_scan.py`, `assistant_crypto_scan.py`, `assistant_log_filter.py`, `assistant_verdict.py`, `assistant_scan_utils.py`, `validation_patterns.py`, `vuln_taxonomy.py`): single-source-of-truth regex catalog for entry points / sources / sinks / mitigations / controls, ripgrep-accelerated scanning with a pure-Python fallback, and a taxonomy registry covering the 25 OASIS vulnerability types
- 📐 **Validation schemas** (`oasis/schemas/analysis.py`): `EntryPointHit`, `CallHop`, `ExecutionPath`, `TaintFlow`, `MitigationHit`, `AuthzCheckHit`, `ControlCheck`, `ConfigFinding`, `AssistantInvestigationResult`
- ✅ **Tests** `tests/test_assistant_validation.py`: per-helper units (entry-points, trace, taint, mitigations, authz, config/secrets/crypto/logs, verdict), end-to-end invocation scenarios (SQLi, IDOR, debug/secrets), and schema roundtrip

### 🐛 Fixed
- 🖼️ Dashboard HTML preview: render **Executive Summary** canonical JSON payloads (`report_type: executive_summary`) instead of raising `Unsupported canonical report type`

## 🚀 [0.5.0] - 2026-04-20

### Breaking

- **CLI**: Removed **`--adaptive` / `-ad`**; vulnerability analysis is orchestrated exclusively by **LangGraph** (Discover → Scan → Expand → Deep → Verify → Report → optional PoC stage).
- **CLI**: Removed **`--analyze-type` / `-at`** (`standard` | `deep`). Embedding similarity cache segment uses **`file`/`function`** only (`--embeddings-analyze-type` / `-eat`).

### ✨ Added
- 🤖 **Dashboard assistant** (JSON and **executive** MD/JSON): triage chat in the report modal; **executive** opens **scan-wide aggregate** context (run JSON under the model directory) with a **severity** Chart.js rollup, **chat model** list from Ollama (`/api/assistant/chat-models`), **context / system-budget** hints, and optional **embedding-cache RAG** with a **union of file paths** from vulnerability reports in the run (`--web-assistant-rag` / `--no-web-assistant-rag`, overridable per request). Single-vulnerability mode still supports focus on a structured finding via indices, Markdown answers with sanitized HTML, and collapsible **model thinking** blocks when the model emits tagged thinking sections
- 💾 **Assistant chat persistence**: conversations stored under `security_reports/<run>/json/.../chat/` (one session file per chat); list, resume, start new, and delete sessions via REST (`GET`/`DELETE` `/api/assistant/session(s)`, `POST /api/assistant/chat`)
- 🧩 **Assistant stack**: helpers for API validation, path containment, session I/O, RAG retrieval, and thinking parse (`oasis/helpers/assistant_*.py`, `path_containment.py`, `prompt_compose.py`); contract tests in `tests/test_web_assistant_api.py`, `tests/test_assistant_*.py`, `tests/test_path_containment.py`, `tests/test_prompt_compose.py`
- 📎 **CLI custom instructions** for analysis: `--custom-instructions` and `--custom-instructions-file` append user guidance to deep-analysis and **`--poc-assist`** prompts (`resolved_custom_instructions` / `append_user_instructions`)
- 🧠 Added **LangGraph** orchestration (`langgraph` + compatible **langchain-core** as required dependencies) as the sole vulnerability analysis pipeline
- 🎛️ Added **`--langgraph-max-expand`** (`N`): maximum context-expand retries after verify detects structured-output issues (default: **2**)
- 📎 Added **`--poc-hints`** and repurposed **`--poc-assist`**: hints are derived from structured findings only; PoC assist asks the deep model for executable PoC text (**no** automated execution by OASIS)
- 📄 Added canonical JSON reports (`report.json`) via `--output-format` (with `all` and comma-separated lists)
- 🛡️ Added SARIF 2.1.0 export (`sarif/*.sarif`) and dashboard downloads for SARIF
- ⚡ Added incremental reporting during analysis: vulnerability reports are written as each vulnerability completes instead of waiting for end-of-scan
- 📈 Added progressive executive summary updates with scan progress metadata (`completed_vulnerabilities`, `total_vulnerabilities`, `is_partial`) and a `/api/progress` endpoint
- 🧠 Added multi-embed audit execution in one run (`--audit -em model_a,model_b`) with per-model report generation
- 📊 Added `Audit Metrics Summary` generation in audit markdown reports (`Count`, similarity stats, high/medium/low match tiers)
- 🧩 Added dashboard audit comparison table to compare embedding-model metrics from the latest comparable audit run
- 🏷️ Added multi-model selection state in vulnerability cards (badge + model emoji in date chips)
- 📋 Added structured vulnerability analysis (Pydantic) with JSON normalization and repair for flaky model output
- 📍 Added source line metadata: chunk `start_line` / `end_line`, optional per-finding `snippet_start_line` / `snippet_end_line` when the vulnerable snippet is found in the chunk text, SARIF `region` (snippet span preferred over chunk span), and report hints (analysis schema version **3**)
- 🤔 Added Ollama thinking toggles for scan vs deep models (`--model-thinking` / `-mt`, `--small-model-thinking` / `-smt`)
- 🌍 Added report language metadata (`language`) in canonical JSON and dashboard language flags sourced from report data
- 🌐 Added dashboard language filter with emoji-flag display aligned with report language badges
- 🧭 Added `.cursor/` rules and agent skills for implementation, releases, and git conventions
- 📦 **CLI updates from GitHub releases** (no PyPI): **`--check-update`** compares the installed version to the **latest stable** release via the GitHub API (**draft** and **prerelease** releases are ignored); **`--self-update`** reinstalls from `git+https://github.com/psyray/oasis.git@<tag>` using **pipx** when the package is installed under **site-packages** (editable/dev installs get `git pull` guidance). Optional **stderr** notice when a newer stable release exists, with **24 h** on-disk cache under `XDG_CACHE_HOME` / `~/.cache/oasis/`; set **`OASIS_NO_UPDATE_CHECK=1`** to disable. Adds **`packaging`** as a declared runtime dependency for version ordering

### 🐛 Fixed
- 🔧 Fixed **`--embeddings-analyze-type`** default: was incorrectly tied to the removed analyze-type default; default is now **`file`** (`EMBEDDING_ANALYSIS_TYPE`)
- 📝 Fixed vulnerability cards: title/summary shown before the code snippet
- 🔗 Fixed broken download links in the report modal
- 🖥️ Fixed small dashboard issues (types display, parallel refresh, debug logging)
- 🧭 Fixed vulnerability filtering in dashboard so `Executive Summary` remains visible when vulnerability filters are applied
- 🧹 Fixed atomic text writer edge case by cleaning temporary files when write/replace fails
- 🧮 Fixed dashboard progress payload handling to keep only high-level pipeline phases and hide low-level adaptive subphase noise
- 🔎 Fixed report date filtering to support repeated `model` query params and list-based model filtering on the backend
- 🧷 Fixed date-chip model filtering to prefer local report index data and use API fallback only when needed

### ⚡ Changed
- 📄 Canonical JSON and export templates carry **assistant-oriented metadata** where applicable (e.g. embedding model and analysis root context) so the dashboard assistant can align RAG and explanations with the run that produced the report
- 🎨 Dashboard **report preview** styling updates for assistant UX (`dashboard.css`, `report_preview.css`, login polish)
- 🎛️ Tunable **`OASIS_*`** environment variables for Ollama timeouts, `num_predict`, PoC digest/log caps, LangGraph context-expand budgets, and structured-output degeneracy heuristics (documented in README + `oasis/config.py`)
- 🔑 Embedding analyzer per-vulnerability result cache key suffix is **`file`** or **`function`** (replaces obsolete `standard`/`deep` segment from `-at`)
- 💾 Changed cache layout: per-project folders under `.oasis_cache`, schema-aware cleanup for structured outputs
- 🗂️ Changed export writes into `oasis.export` to slim down `report.py`
- 📚 Changed README: `--input` docs, `--output-format`/thinking flags, pipx editable reinstall workflow, vulnerability tag list alignment (`pathtra` and added tags), report folder layout, LangGraph workflow and new flags (replaces adaptive-mode documentation)
- 📈 Changed progressive executive-summary payloads: **`scan_mode=graph`**, LangGraph-aligned **`phases`** rows, and **`EXEC_SUMMARY_PROGRESS_EVENT_VERSION` = 3** for the dashboard wire contract
- 🎨 Changed logo asset
- ♻️ Refactored embedding manager indexing flow into smaller helper methods (argument preparation, result storage, and input preparation reuse)
- 📚 Updated dashboard sorting/filtering helpers to centralize vulnerability ordering and model-selection encoding/decoding
- 🧪 Expanded test coverage for multi-embed audit CLI parsing, audit metrics extraction, dashboard filtering/comparison behavior, and progress payload normalization

## 🚀 [0.4.0] - 2025-03-21

### ✨ Added
- 🔐 Added web interface authentication with password protection
- 🌐 Added option to expose web interface on different network interfaces
- ⚙️ Added command line arguments for web interface configuration:
  - `--web-expose`: Control web interface exposure (local/all, default: local)
  - `--web-password`: Set a password for web interface access
  - `--web-port`: Configure the web server port (default: 5000)
- 🖥️ Added login page with consistent design to match the application's style
- 🔍 Added two-phase scanning architecture for optimized analysis workflow
- 🤖 Added support for separate scan and analysis models with `--scan-model` parameter
- 🧠 Added adaptive multi-level analysis mode that adjusts depth based on risk assessment
- 🔄 Added interactive model selection with separate prompts for scan and deep analysis models
- 💡 Added intelligent model filtering to recommend smaller parameter-count models (4-7B) for initial scanning phase
- 📊 Added enhanced progress tracking with nested progress bars for each analysis phase
- 📏 Added model parameter detection for intelligent model recommendations
- 🎮 Added new command-line options:
  - `--scan-model` / `-sm`: Specify lightweight model for initial scanning
  - `--adaptive` / `-ad`: Use adaptive multi-level analysis instead of standard
  - `--clear-cache-scan` / `-ccs`: Clear scan cache before starting

### 🐛 Fixed
- 🔄 Fixed model selection and switching to use the correct model for each phase
- 📈 Fixed progress bar rendering for nested analysis operations
- 💾 Fixed cache handling for different analysis modes
- 🔄 Fixed inconsistencies between displayed and actual models used
- 🧮 Fixed memory usage issues with large models during scanning

### ⚡ Changed
- 🚀 Improved analysis workflow to reduce model switching and optimize GPU memory usage
- 🎯 Enhanced model selection interface with clearer prompts and recommendations
- 📝 Improved logging with better status updates for each analysis phase
- 🔍 Enhanced vulnerability scanning with optimized two-phase scanning
- 🏗️ Reorganized analysis architecture for better code organization and modularity
- 📊 Updated progress bars to show more detailed progress information
- 💾 Improved caching system to handle both deep and quick scan results
- 📚 Enhanced documentation with new examples and usage patterns

## 🚀 [0.3.0] - 2025-03-17

Complete codebase refactoring and improvements.

### ✨ Added
- 🛡️ Added support for new vulnerability types (RCE, SSRF, XXE, Path Traversal, IDOR, CSRF)
- 📋 Added detailed vulnerability descriptions and examples
- 🎨 Added HTML template and CSS styling for better report readability
- 😊 Added better emoji support in logging for better readability
- 🧪 Added more comprehensive test files with vulnerability examples
- 🔗 Added support for custom Ollama URL

### ⚡ Changed
- 📁 Improved codebase organization and readability
- 🧩 Improved embedding and analysis process
- 💾 Improved cache management with dedicated .oasis_cache/ directory
- 📝 Enhanced logging system with custom EmojiFormatter
- 📊 Improved report generation with better styling and formatting
- 🏗️ Refactored package structure for better organization
- 📦 Updated dependency management in pyproject.toml

### 🐛 Fixed
- 💾 Fixed embeddings cache storage and validation
- 📄 Fixed report rendering with proper page breaks
- 📥 Fixed issue with model installation progress tracking
- 💾 Fixed issue with cache saving during interruption
- 🔍 Fixed issue with model availability check
- 📊 Fixed issue with progress bar updates
- 📝 Fixed issue with log message formatting

### 🔬 Technical
- ⚙️ Added configuration constants for better maintainability
- 🧩 Added Jinja2 templating for report generation
- 📝 Implemented normalized heading levels in reports
- 🛠️ Improved error handling and logging

### 📚 Documentation
- 📝 Enhanced code documentation with proper docstrings
- 📖 Added more comprehensive README with examples and usage instructions
- 💻 Improved command line interface documentation
- 📋 Added more detailed changelog
- 🗂️ Updated project structure documentation
- 💬 Added more comprehensive code comments
- 📖 Improved code readability and maintainability

## 🚀 [0.2.0] - 2025-01-29

### ✨ Added
- 📝 Enhanced logging system with contextual emojis
- 😊 Automatic emoji detection in log messages
- 🔍 Debug logging for file operations
- 📚 Proper docstrings and documentation
- 📊 Progress bar for model installation
- 🔍 Model availability check before analysis
- 🤖 Interactive model installation

### ⚡ Changed
- 📋 Moved keyword lists to global constants
- ⌨️ Improved KeyboardInterrupt handling
- 💾 Enhanced cache saving during interruption
- 📝 Improved error messages clarity
- 📄 Better handling of newlines in logs
- 🔄 Refactored logging formatter
- 📊 Enhanced progress bar updates
- 🏗️ Improved code organization

### 🐛 Fixed
- 🧪 Cache structure validation
- 📥 Model installation progress tracking
- 😊 Emoji spacing consistency
- 📝 Newline handling in log messages
- 💾 Cache saving during interruption
- 🛠️ Error handling robustness
- 📊 Progress bar updates

### 🔬 Technical
- 😊 Added emoji detection system
- 🛠️ Enhanced error handling architecture
- 🔍 Improved cache validation system
- 🧹 Added cleanup utilities
- 🚪 Better exit code handling
- 📊 More robust progress tracking
- 📁 Clearer code organization
- 🔬 Enhanced debugging capabilities

### 📚 Documentation
- 📝 Added detailed docstrings
- 💬 Improved code comments
- 📋 Enhanced error messages
- 📝 Better logging feedback
- 📊 Clearer progress indicators

## 🚀 [0.1.0] - 2024-01-15

### ✨ Added
- 🎉 Initial release
- 🔒 Basic code security analysis with Ollama models
- 📄 Support for multiple file types and extensions
- 💾 Embedding cache system for performance
- 📑 PDF and HTML report generation
- 💻 Command line interface with basic options
- 🎨 Logo and ASCII art display
- 📝 Basic logging system

### 🌟 Features
- 🤖 Multi-model analysis support
- 🔍 File extension filtering
- 🛡️ Vulnerability type selection
- 📊 Progress bars for analysis tracking
- 📋 Executive summary generation
- 🛠️ Basic error handling

### 🔬 Technical
- 🔗 Integration with Ollama API
- 📄 WeasyPrint for PDF generation
- 📝 Markdown report formatting
- 💾 Basic cache management
- 🏗️ Initial project structure