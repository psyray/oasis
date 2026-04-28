## 🚀 [0.6.0] - 2026-04-28

### Breaking changes

- **Report storage layout**: New scans default to **project-scoped** folders (`security_reports/<project_slug>/…`) with optional **`--project-name` / `-pn`** for the slug; this supersedes the older **flat** `security_reports/<input_basename>_…` layout for new output. The dashboard still reads legacy trees where documented.
- **Canonical JSON `analysis_root`**: New reports store the scanned project root **relative to the `security_reports/` directory**; integrations that assumed **absolute** paths must adapt (legacy absolute values remain supported via resolution heuristics in **`oasis.helpers.analysis_root_path`**).

### ✨ Added

- 📋 **Executive summary canonical JSON (`schema_version` 2)**: **`overview`** (vulnerability-type count, distinct files touched, total embedding comparisons), embedded **`guidance_markdown`** (how to interpret tiers vs severity), **`tier_definitions`**, and capped **`similarity_highlights`** rows for prioritized review; dashboard/HTML preview surfaces **at-a-glance KPIs**, tier legend, **priority match table** with links to per-type reports, and optional **scan progress** summary so the executive report acts as the central security overview for the run.
- 📊 **Audit canonical JSON**: `audit_report.json` (`report_type: "audit"`) when `json` is in output formats; Pydantic `AuditReportDocument`; Markdown/HTML generated from the same document so the **Audit Metrics Summary** stays compatible with `audit_metrics_from_markdown_content` / dashboard parsing.
- 🖥️ **Dashboard**: `/api/reports` reads audit metrics from sibling JSON when available (fallback Markdown); report modal uses `/api/report-html` for `json/audit_report.json` when opening `md/audit_report.md` (canonical JSON preview UX).
- 📁 **Project-aware reports**: optional **project alias** for organization and improved **project-based** report storage and metadata alongside existing project workflow.
- 📁 **Dashboard**: filter reports by **project** (`/api/reports?project=…`, stats include `projects` counts).
- ⚠️ **Dashboard / previews**: reports expose **`codebase_accessible`** and **`assistant_context_warning`** when the scanned tree cannot be resolved or read next to **`security_reports`**; warning banners in list chips, HTML preview (vulnerability / executive / audit), and assistant panel.

### 🐛 Fixed

- 🖼️ **Dashboard HTML preview**: Executive Summary **canonical JSON** (`json/_executive_summary.json`) uses the same compact report-modal spine as other previews: **`executive-preview`** wrapper, **table of contents**, section anchors, and **return-to-TOC** links so **Chart.js** severity rollup and styling match the markdown-augmented path.

### ⚡ Changed

- 📊 **`/api/stats`**: The per-tier sidebar counts are exposed as **`severity_finding_totals`** (finding counts per tier), replacing the former **`severities`** key — same semantics as before the label fix, clearer name. Executive JSON **`similarity_highlights`** rows include optional **`tier_description`** (embedding tier range text) for UI/tooling without another schema bump.
- 🧭 **Audit wiring**: single **artifact stem** (`audit_report`) and **`md` → `json` sibling** rules shared by indexing (`json_sibling_for_format_artifact`) and the dashboard (`audit-report-paths.js`); audit HTML preview uses **Jinja `audit_decimal`** for scores/thresholds instead of inline format strings.
- 📎 **Canonical JSON `analysis_root`**: new reports store the scanned project root **relative to the `security_reports/` directory**; legacy **absolute** paths remain supported via resolution heuristics. Helpers live in **`oasis.helpers.analysis_root_path`** (shared by assistant RAG cache root and **`scan_root`** candidate resolution).

## 🚀 [0.5.1] - 2026-04-22

### ✨ Added
- 💬 **Assistant streaming**: **`POST /api/assistant/chat-stream`** (NDJSON) emits `start`, `delta`, `done` / `error` events; dashboard renders the reply progressively under the chat with auto-scroll and falls back to the non-streaming endpoint when the stream is unavailable. Chat composition (chips, input, send) moved below the conversation log.
- 🛡️ **Validate findings**: deterministic investigation (flow / access / config families) with verdict, confidence, and citations — entry points, paths to the sink, taint, mitigations, access and protocol controls, plus config/secret/crypto/log-style checks. **LangGraph** when available, otherwise a sequential fallback. Dashboard: **Validate this finding** and a verdict panel.
- 📝 **Validation narrative**: optional follow-up call to the same **Ollama** chat model to produce readable Markdown; it does not override the deterministic verdict. Request flag to disable; model from the request or the report.
- 💬 **Chat sessions per model**: session JSON **schema_version 3** stores separate threads per chat model plus a **`finding_validations`** map (keyed by file/chunk/finding indices and executive scope path) so multiple validated findings coexist; switching chat model saves the previous thread and reloads the verdict for the currently selected finding. **`POST /api/assistant/chat`** selects the validation entry matching the request finding indices for **`FINDING_VALIDATION_JSON`** in the system prompt. **`POST /api/assistant/investigate`** merges with the same key (includes **`finding_scope_report_path`** in executive mode). Dashboard: pills above **Validate this finding** show the active finding scope.
- 🧩 **Validation support**: shared pattern catalog and taxonomy for all OASIS vulnerability types, with ripgrep-backed scanning and a code fallback.
- 📐 Structured types for validation evidence and investigation results in the analysis schema.
- ✅ Automated tests for validation helpers, APIs, and schema round-trips.

### 🐛 Fixed
- 💬 Assistant: **`POST /api/assistant/session-branch`** accepts **`messages: []`** (e.g. changing chat model before any message) instead of 400 *messages required*.
- 🖼️ Dashboard HTML preview: **Executive Summary** reports in canonical JSON no longer error in the preview path.
- 💬 Assistant streaming: harmony-style reasoning tags emitted by some models (e.g. **gpt-oss** variants like `<|channel>>thought <channel|>`, `<|channel> most_thought <channel|>`, `<|channel|>analysis<|message|>`) are now recognized and extracted into `thought_segments` instead of leaking as raw tokens into `visible_markdown`.
- 💬 Assistant streaming: ollama-python's native `message.thinking` field is forwarded as its own delta channel (`{type: "delta", channel: "thinking"}`), rendered live in a collapsible reasoning block, and appended to `thought_segments` at completion so the visible answer stays clean when `think=True` is negotiated.

## 🚀 [0.5.0] - 2026-04-20

### Breaking

- **CLI**: Removed **adaptive** mode; analysis runs only through **LangGraph** (discover → scan → expand → deep → verify → report, optional PoC).
- **CLI**: Removed **analyze-type** (`standard` / `deep`); embedding similarity cache uses **file** vs **function** only.

### ✨ Added
- 🤖 **Dashboard assistant**: triage chat from the report modal; **executive** mode uses scan-wide aggregate context, severity rollup, Ollama chat model list, system-budget hints, and optional **RAG** over the embedding cache; per-request flags to disable RAG. Single-report mode can target a finding by indices; Markdown replies, sanitized HTML, and optional collapsible **thinking** blocks.
- 💾 **Chat persistence**: conversations saved beside reports; list, open, start new, and delete via REST.
- 🧩 **Assistant plumbing**: validation, safe paths, sessions, retrieval, and parsing helpers with contract tests.
- 📎 **CLI custom instructions** for analysis and for **PoC assist** prompts.
- 🧠 **LangGraph** as the only vulnerability analysis pipeline (with matching dependencies).
- 🎛️ **LangGraph max-expand**: cap on context-expand retries after verify (default **2**).
- 📎 **PoC hints** and **PoC assist**: hints from structured findings only; assist produces suggested PoC text (**no** execution).
- 📄 Canonical **JSON** reports via **output-format** (`all` or comma-separated formats).
- 🛡️ **SARIF 2.1** export and dashboard download support.
- ⚡ **Incremental reporting**: vulnerability JSON written as each type finishes.
- 📈 **Progressive Executive Summary** with scan metadata and a **progress** API.
- 🧠 **Multi-embed audit** in one run with per-model reports.
- 📊 **Audit metrics** in markdown (counts, similarity tiers) and a dashboard **comparison** table across runs.
- 🏷️ **Multi-model** state on vulnerability cards (badges, emojis).
- 📋 **Structured analysis** (Pydantic) with normalization and repair for bad model JSON.
- 📍 Richer **source / snippet line** metadata and SARIF regions; analysis schema bump.
- 🤔 Ollama **thinking** toggles for scan vs deep models.
- 🌍 Report **language** in JSON; dashboard language filter and flags.
- 🧭 Workspace **rules and agent skills** for implementation, releases, and git conventions.
- 📦 **GitHub-based CLI updates**: check and self-update against stable releases (pipx / git), optional update notice with cache, env flag to disable; **packaging** dependency for version ordering.

### 🐛 Fixed
- 🔧 **Embeddings analyze-type** default aligned with the new model (**file**).
- 📝 Vulnerability cards: title and summary before the snippet.
- 🔗 Report modal download links.
- 🖥️ Minor dashboard issues (types, refresh, logging).
- 🧭 Filters no longer hide **Executive Summary** inappropriately.
- 🧹 Safer atomic file writes on failure.
- 🧮 Progress UI: high-level LangGraph phases only, less noisy sub-phases.
- 🔎 Report date filtering and model query handling.
- 🧷 Date-chip model filter prefers local index, API as fallback.

### ⚡ Changed
- 📄 Canonical JSON and exports include **assistant-oriented** metadata (embed model, analysis root) for RAG alignment.
- 🎨 Report preview and login styling for assistant UX.
- 🎛️ More **OASIS_*** env tunables (Ollama timeouts, generation caps, LangGraph budgets, structured-output heuristics); defaults described in the shipped documentation.
- 🔑 Embedding result cache keys use **file** / **function** only.
- 💾 Cache layout: per-project folders with schema-aware cleanup.
- 🗂️ Export logic moved into a dedicated subpackage to slim core reporting code.
- 📚 Documentation refreshed for input/output, thinking flags, pipx workflow, tags, report layout, LangGraph, and removed adaptive-mode docs.
- 📈 Executive-summary progress payload version and **phases** aligned with LangGraph.
- 🎨 Logo update.
- ♻️ Embedding manager refactor into smaller steps.
- 📚 Centralized dashboard sorting/filtering and model encoding.
- 🧪 Broader tests for audit CLI, metrics, dashboard filters, and progress payloads.

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