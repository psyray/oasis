<p align="center">
  <a href="https://github.com/psyray/oasis/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/psyray/oasis?style=for-the-badge&color=red&logo=gnu" alt="License">
  </a>
  <a href="https://github.com/psyray/oasis/releases">
    <img src="https://img.shields.io/github/v/release/psyray/oasis?style=for-the-badge&logo=github&color=C5A776" alt="Release">
  </a>
  <a href="https://python.org">
    <img src="https://img.shields.io/badge/python-3.9+-blue.svg?style=for-the-badge&color=2C7CBB&logo=python&logoColor=white" alt="Python">
  </a>
</p>

<div align="center">
  <a href="https://discord.gg/dW3sFwTtN3">
    <img src="https://img.shields.io/discord/1351288717536661647?style=for-the-badge&label=Discord&logo=discord&logoColor=white">
  </a>
</div>

<div align="center">
  <h1>OASIS</h1>
</div>
<p align="center">
  <small>🏝️ <strong>O</strong>llama <strong>A</strong>utomated <strong>S</strong>ecurity <strong>I</strong>ntelligence <strong>S</strong>canner</small>
</p>

<p align="center">
  <img src=".github/images/logo.webp" alt="OASIS Logo" width="200"/>
</p>

<p align="center">
  🛡️ An AI-powered security auditing tool that leverages Ollama models to detect and analyze potential security vulnerabilities in your code.
</p>

<p align="center">
  <em>Advanced code security analysis through the power of AI</em>
</p>

## 🌟 Features

- 🤖 **Dashboard assistant**: In the report modal, the AI assistant triages **single-vulnerability JSON** reports or **executive / scan-wide** mode (aggregated JSON under the run) with optional **RAG** over the local embedding cache, a **chat model** selector (Ollama tags), **Markdown** replies, persisted **chat sessions** keyed by the canonical report path, and configurable Ollama/RAG flags (`--web-ollama-url`, `--web-embed-model`, `--web-assistant-rag`)
- 🛡️ **Finding validation agent**: a **Validate this finding** button in the assistant panel runs a deterministic, code-driven investigation on the project sources. It classifies the vulnerability into a family (**flow**, **access**, or **config**), discovers framework **entry points** (Flask/Django/FastAPI/Express/Spring/Rails/gRPC/CLI/message handlers), traces **call paths** to the sink, detects **taint flows** (source → sink), evaluates **nullifying mitigations** (parameterized SQL, path normalizers, sanitizers, ORMs, etc.) and **required controls** (auth/CSRF/session/JWT/CORS), runs **config / secret / crypto / log-leak** audits, and returns an **exploitability verdict** (`confirmed_exploitable`, `likely_exploitable`, `needs_review`, or `not_exploitable`) with confidence and full citations. Orchestrated by **LangGraph** when installed, with a pure-Python fallback. Exposed as `POST /api/assistant/investigate` and bounded by a configurable `budget_seconds` per request. When Ollama is reachable and a **chat model** is selected (or the report provides `model_name`), the response may include an additional **`narrative_markdown`** field: an LLM-written explanation that must not contradict the deterministic verdict (`synthesize_narrative` in the JSON body defaults to true).
- 🔍 **Multi-Model Analysis**: Leverage multiple Ollama models for comprehensive security scanning
- 🔄 **Two-Phase Scanning**: Use lightweight models for initial scanning and powerful models for deep analysis
- 🧠 **LangGraph Orchestration**: Single pipeline (discover → scan → expand → deep → verify → report, optional PoC assist) with bounded context-expand retries
- 🔄 **Interactive Model Selection**: Guided selection of scan and analysis models with parameter-based filtering
- 💾 **Dual-Layer Caching**: Efficient caching for both embeddings and analysis results to dramatically speed up repeated scans
- 🔧 **Scan Result Caching**: Store and reuse vulnerability analysis results with model-specific caching
- 📊 **Rich Reporting**: Canonical JSON reports plus derived HTML, PDF, and Markdown exports
- 🔄 **Parallel Processing**: Optimized performance through parallel vulnerability analysis
- 📝 **Executive Summaries**: Clear overview of all detected vulnerabilities
- 🎯 **Customizable Scans**: Support for specific vulnerability types and file extensions
- 📈 **Distribution Analysis**: Advanced audit mode for embedding distribution analysis
- 🔄 **Content Chunking**: Intelligent content splitting for better analysis of large files
- 🤖 **Interactive Model Installation**: Guided installation for required Ollama models
- 🌐 **Web Interface**: Secure, password-protected web dashboard for exploring reports
- ⚡ **Incremental Reporting**: Vulnerability reports are published as soon as each vulnerability analysis completes
- 📈 **Live Scan Progress**: Executive summary is created early and updated progressively during long scans

## 🚀 Getting started

### Prerequisites

- **Python** 3.9+
- **[Ollama](https://ollama.ai)** installed and running; pull the models you need before scanning.
- **[pipx](https://pypa.github.io/pipx/)** (recommended CLI install):

```bash
# macOS
brew install pipx
pipx ensurepath

# Ubuntu/Debian
python3 -m pip install --user pipx
python3 -m pipx ensurepath

# Windows (with pip)
pip install --user pipx
python -m pipx ensurepath
```

### Standard run (pipx)

```bash
git clone https://github.com/psyray/oasis.git
cd oasis
pipx install -e .

oasis --input test_files/
```

Reports are written under **`security_reports/`** beside the path you analyze (see [Output structure](#-output-structure)).

### Docker (optional)

From the repository root, with Ollama on the host:

```sh
docker compose build
docker compose run --rm oasis -i /work/test_files -ol http://host.docker.internal:11434
```

Code is mounted at **`/work`**; use `-i` paths under `/work`. More options (bundled Ollama, dashboard, `docker run`) are in [Run with Docker](#-run-with-docker).

### Maintenance

**Update from GitHub releases** (recommended when you installed from tags / non-editable):

```bash
oasis --check-update   # compare installed version vs latest stable release on GitHub
oasis --self-update    # reinstall latest stable via pipx (requires pipx on PATH)
```

Stable releases only: GitHub entries marked pre-release are ignored. To skip the occasional “update available” line on stderr, set `OASIS_NO_UPDATE_CHECK=1`. For unexpected banner failures, set `OASIS_DEBUG_UPDATE` to `1`, `true`, or `yes` to print a short diagnostic on stderr (developer troubleshooting).

**Editable / development clone** — after `git pull`, your editable pipx install tracks the repo:

```bash
git pull origin master
pipx upgrade oasis
```

(`pipx upgrade` is optional for editable installs; use it when you want pipx’s recorded version to match.)

**Uninstall**

```bash
pipx uninstall oasis
```

**Feature branches** (optional, may be unstable):

```bash
git fetch --all
git checkout feat/vX.X
```

---

## 🛠️ Hardware Requirements

### Minimum Requirements
- **CPU**: 4+ cores (Intel i5/AMD Ryzen 5 or better)
- **RAM**: 16 GB minimum, 32 GB recommended
- **Storage**: 100 GB+ free space for models (more for caching large codebases)
- **GPU**: Not required for basic usage (will use CPU but really slow)

### Recommended Setup
- **CPU**: 8+ cores (Intel i7/i9 or AMD Ryzen 7/9)
- **RAM**: 32 GB-64 GB for large codebases
- **GPU**: NVIDIA with 8 GB+ VRAM (RTX 3060 or better)
- **Storage**: SSD with 100 GB+ free space

### Scaling Guidelines
- **Small Projects** (< 10,000 Lines of Code (LOC)): Minimum requirements sufficient
- **Medium Projects** (10,000-100,000  Lines of Code (LOC)): 8-core CPU, 32 GB+ RAM recommended
- **Large Projects** (> 100,000 Lines of Code (LOC)): High-end CPU, 64 GB+ RAM, dedicated GPU essential

### GPU Recommendations by Model Size
- **4-8B parameter models**: 8 GB VRAM minimum
- **12-20B parameter models**: 16 GB VRAM recommended
- **30B+ parameter models**: 24 GB+ VRAM (RTX 3090/4090/A5000 or better)

### Network Requirements
- Stable internet connection for model downloads
- Initial model downloads: 3GB-15GB per model

### Performance Tips
- Use SSD storage for cache directories
- Prioritize GPU memory over compute performance
- Consider running overnight for large codebases
- For enterprise usage, dedicated server with 128GB+ RAM and A100/H100 GPU recommended


## 🔥 Advanced Usage Examples

Standard two-phase analysis with separate models:
```bash
# Use a lightweight model for initial scanning and a powerful model for deep analysis
oasis -i [path_to_analyze] -sm gemma3:4b -m gemma3:27b
```

LangGraph pipeline (default) with optional PoC hints and expand budget:
```bash
# Same two-model setup; optional: cap context-expand retries, PoC hint bullets, and/or LLM PoC text
oasis -i [path_to_analyze] -t 0.6 -m llama3 --langgraph-max-expand 2 --poc-hints
```

Targeted vulnerability scan with caching control:
```bash
# Analyze only for SQL Injection and XSS, clear cache, specify models
oasis -i [path_to_analyze] -v sqli,xss --clear-cache-scan -sm gemma3:4b -m gemma3:27b
```

Full production scan:
```bash
# Comprehensive scan of a large codebase
oasis -i [path_to_analyze] -sm gemma3:4b -m llama3:latest,codellama:latest -t 0.7 --vulns all
```

## 🎮 Command Line Arguments

### Input/Output Options
- `--input` `-i`: Path to file, directory, or .txt file containing newline-separated paths to analyze
- `--output-format` `-of`: Comma-separated formats or `all` for json, sarif, pdf, html, md (default: all)
- `--extensions` `-x`: Custom file extensions to analyze (e.g., "py,js,java")
- `--language` `-l`: Language for reports (default: en)  
  Supported: 🇬🇧 English (en), 🇫🇷 Français (fr), 🇪🇸 Español (es), 🇩🇪 Deutsch (de), 🇮🇹 Italiano (it), 🇵🇹 Português (pt), 🇷🇺 Русский (ru), 🇨🇳 中文 (zh), 🇯🇵 日本語 (ja)

### Analysis Configuration

- **Removed flags:** `--adaptive`/`-ad` and `--analyze-type`/`-at` were dropped in favor of LangGraph-only orchestration; the CLI exits with guidance if they appear—use the options below and `-eat` for embedding segmentation instead.

- `--embeddings-analyze-type` `-eat`: Analyze code by entire file or by individual functions [file, function] (default: file)
    - file: Performs the embedding on the entire file as a single unit, preserving overall context but potentially diluting details.  
    - function (**EXPERIMENTAL**): Splits the file into individual functions for analysis, allowing for more precise detection of issues within specific code blocks but with less contextual linkage across functions.  

- **`--langgraph-max-expand`** `N`: Maximum **context-expand** retries after verify detects structured-output problems (default: **2**).
- **`--poc-hints`**: Log optional high-level PoC hint bullets from structured findings only (**no** extra LLM call; **does not** run code).
- **`--poc-assist`**: Ask the deep model for a standalone executable PoC (script or commands) from findings; **logged only** — OASIS does not run generated code.
- **`--custom-instructions`**: Extra text appended to deep-analysis and **`--poc-assist`** prompts (merged with the file variant below; does **not** inject into the dashboard assistant system prompt—the assistant uses the canonical report JSON and optional RAG).
- **`--custom-instructions-file`**: UTF-8 file merged with **`--custom-instructions`** (file first, then inline text).
- `--threshold` `-t`: Similarity threshold (default: 0.5)
- `--vulns` `-v`: Vulnerability types to check (comma-separated or 'all')
- `--chunk-size` `-ch`: Maximum size of text chunks for embedding (default: auto-detected)

### Model Selection
- `--models` `-m`: Comma-separated list of models to use for deep analysis
- `--scan-model` `-sm`: Model to use for quick scanning (default: same as main model)
- `--model-thinking` `-mt`: Enable/disable thinking for deep analysis models [yes,no] (default: no)
- `--small-model-thinking` `-smt`: Enable/disable thinking for the quick scan model [yes,no] (default: no)
- `--embed-model` `-em`: Embedding model(s); in audit mode, supports a comma-separated list (example: `-em nomic-embed-text,bge-m3`) (default: nomic-embed-text)
- `--list-models` `-lm`: List available models and exit

### Cache Management
- `--clear-cache-embeddings` `-cce`: Clear embeddings cache before starting
- `--clear-cache-scan` `-ccs`: Clear scan analysis cache for the current analysis type
- `--cache-days` `-cd`: Maximum age in days for both embedding and analysis caches (default: 7)

### Web Interface
- `--web` `-w`: Serve reports via a web interface
- `--web-expose` `-we`: Web interface exposure (local: 127.0.0.1, all: 0.0.0.0) (default: local)
- `--web-password` `-wpw`: Web interface password (if not specified, a random password will be generated)
- `--web-port` `-wp`: Web interface port (default: 5000)
- **`--web-ollama-url`**: Ollama HTTP API URL for the in-dashboard assistant (overridden by `OASIS_WEB_OLLAMA_URL`, otherwise same as `--ollama-url`).
- **`--web-embed-model`**: Embedding model for optional RAG over the local `.oasis_cache` pickle (defaults to the report’s `embed_model` or `nomic-embed-text`).
- **`--web-assistant-rag` / `--no-web-assistant-rag`**: Use embedding-cache retrieval in assistant answers (default: on).

For **JSON** reports, the dashboard modal includes an **Assistant** panel (triage, codebase context). Optional 0-based file/chunk/finding indices focus the model on one structured finding; RAG uses the same project root and cache file as the scan when available.

Assistant replies are rendered as **Markdown** (sanitized HTML). Model “thinking” sections wrapped in tags such as `<think>…</think>` are stripped from the visible answer and shown in collapsible blocks when present.

**Chat persistence** stores each conversation under `security_reports/<project_slug>/<run_timestamp>/.../json/.../<report>.json` in a sibling `chat/` folder (one JSON file per session). The UI can resume the latest session, start a new chat, or delete saved sessions. Data stays on the server filesystem next to your reports (no separate database). REST endpoints: `GET /api/assistant/sessions`, `GET /api/assistant/session`, `POST /api/assistant/chat`, `DELETE /api/assistant/session`, `DELETE /api/assistant/sessions`.

### Logging and Debug
- `--debug` `-d`: Enable debug output
- `--silent` `-s`: Disable all output messages

### Special Modes
- `--audit` `-a`: Run embedding distribution analysis
- `--ollama-url` `-ol`: Ollama URL (default: http://localhost:11434)
- `--version` `-V`: Show OASIS version and exit

### Environment overrides (advanced)

Optional **`OASIS_*`** variables tune timeouts and heuristic budgets without editing code (see `oasis/config.py` for the full list). Examples:

- **`OASIS_WEB_OLLAMA_URL`** — Ollama base URL for the dashboard assistant when `--web-ollama-url` is not set.
- **`OASIS_CHUNK_ANALYZE_TIMEOUT_SEC`** — server-side deadline for one Ollama generate call (seconds).
- **`OASIS_CHUNK_DEEP_NUM_PREDICT`** — cap on structured deep output tokens (`num_predict`).
- **`OASIS_OLLAMA_HTTP_CLIENT_TIMEOUT_SEC`** — HTTP client timeout (must cover one full generate round-trip).
- **`OASIS_POC_DIGEST_JSON_MAX_CHARS`** / **`OASIS_POC_STAGE_LOG_MAX_CHARS`** — PoC JSON prompt size and INFO log cap for PoC-stage output.
- **`OASIS_STRUCTURED_DEGENERACY_*`** — thresholds for repetitive structured-output detection.

Higher limits increase worst-case latency and memory use on the Ollama host.

## 💡 Getting the Most out of OASIS

### Model Selection Strategy

OASIS uses a two-phase scanning approach that leverages different models for optimal results:

#### Model Selection by Purpose
- **Initial Scanning Models** (4-7B parameters):
  - Optimized for speed: `gemma3:4b`, `llama3.2:3b`, `phi3:mini`
  - Used for quick pattern matching and identifying potentially suspicious code segments
  - Resource-efficient for scanning large codebases

- **Deep Analysis Models** (>20B parameters):
  - Optimized for thorough analysis: `gemma3:27b`, `deepseek-r1:32b`, `qwen2.5-coder:32b`, `mistral-nemo`, `mixtral:instruct`
  - Used only for code sections flagged as suspicious in the initial scan
  - Provides detailed vulnerability assessment

- **Specialized Code Models**:
  - Code-specific models: `codellama`, `codestral`, `starcoder`, `phind-codellama`
  - Best for specific languages and frameworks
  - `codellama` for general code, `codestral` for Python/C++, `starcoder/phind-codellama` for web technologies

#### Example Model Combinations

```bash
# For quick analysis of a small project
oasis -i ./src -sm llama3.2:3b -m llama3.2:8b

# For thorough analysis of web application code (PHP, JavaScript)
oasis -i ./webapp -sm gemma3:4b -m codellama:34b -v xss,sqli,csrf

# For security audit of Python backend with specialized models
oasis -i ./backend -sm phi3:mini -m deepseek-r1:32b,qwen2.5-coder:32b -v rce,input,data

# For critical infrastructure security analysis (most thorough)
oasis -i ./critical-service -sm gemma3:7b -m mixtral:instruct -v all -t 0.6 --langgraph-max-expand 3
```

### Scanning workflow (LangGraph)

Analysis is orchestrated by a single **LangGraph** pipeline:

1. **Discover** — embedding-based candidate files per vulnerability type  
2. **Scan** — structured chunk verdicts (`ScanVerdict`)  
3. **Expand** — widen suspicious chunk context within budget (retries capped by **`--langgraph-max-expand`**)  
4. **Deep** — `ChunkDeepAnalysis` for flagged chunks  
5. **Verify** — schema consistency; may loop back to **Expand** when retries remain  
6. **Report** — vulnerability reports + executive summary  
7. **PoC stage (optional)** — **`--poc-hints`** (hint bullets from findings) and/or **`--poc-assist`** (LLM-produced executable PoC text, not run by OASIS)

Within each run you still choose a **scan model** (`-sm`) and **deep model(s)** (`-m`) as before.

### Optimization Tips

For the best results with OASIS:

1. **Caching Strategy**:
   - Leverage the dual-layer caching system for repeated scans
   - Only clear embedding cache (`-cce`) when changing embedding models or after major code changes
   - Clear scan cache (`-ccs`) when upgrading to better models or after fixing vulnerabilities

2. **Workflow Optimization**:
   - Start with higher thresholds (0.7-0.8) for large codebases to focus on high-probability issues
   - Use `--audit` mode to understand vulnerability distribution before full analysis
   - Specify relevant vulnerability types (`-v`) and file extensions (`-x`) to target your analysis

3. **Resource Management**:
   - For large projects, run initial scans during off-hours
   - Balance CPU/GPU usage by choosing appropriate model sizes
   - Use model combinations that maximize speed and accuracy based on your hardware

4. **Report Utilization**:
   - View HTML reports for the best interactive experience
   - Use the web interface (`--web`) for team collaboration
   - Export PDF reports for documentation and sharing

## 🛡️ Supported Vulnerability Types

| Tag | Description |
|-----|-------------|
| `sqli` | SQL Injection |
| `xss` | Cross-Site Scripting |
| `input` | Insufficient Input Validation |
| `data` | Sensitive Data Exposure |
| `session` | Session Management Issues |
| `config` | Security Misconfiguration |
| `logging` | Sensitive Data Logging |
| `crypto` | Insecure Cryptographic Function Usage |
| `rce` | Remote Code Execution |
| `ssrf` | Server-Side Request Forgery |
| `xxe` | XML External Entity |
| `pathtra` | Path Traversal |
| `idor` | Insecure Direct Object Reference |
| `auth` | Authentication Issues |
| `csrf` | Cross-Site Request Forgery |
| `cmdi` | Command Injection |
| `cors` | CORS Misconfiguration |
| `debug` | Debug Information Exposure |
| `deser` | Insecure Deserialization |
| `jwt` | JWT Implementation Flaws |
| `lfi` | Local File Inclusion |
| `redirect` | Open Redirect |
| `rfi` | Remote File Inclusion |
| `secrets` | Hardcoded Secrets |
| `upload` | File Upload Vulnerabilities |

## 📁 Output Structure

Vulnerability runs are stored under **`security_reports/<project_slug>/YYYYMMDD_HHMMSS/`**, where `project_slug` is derived from the **last segment of your `--input` path** when it points to a **directory** (e.g. `example/test_files` → `test_files`), or from the **folder that contains the file** when you pass a file path, then sanitized for safe folder names. For predictable grouping in the web UI, prefer `--input` on a project folder, not a single file, and avoid generic paths like `.` or `/` as the sole argument (the CLI will warn in those cases). Older scans may still use the previous flat layout, **`security_reports/<input_basename>_YYYYMMDD_HHMMSS/`**; the dashboard reads both. For each model, per-format folders include a **canonical JSON** report (`json/*.json`) used by the web dashboard for statistics and previews. Chunk objects may include **`start_line` / `end_line`** (1-based inclusive bounds for the analyzed source segment, computed at split time, not inferred by the model). Each finding may include **`snippet_start_line` / `snippet_end_line`** when the tool can match `vulnerable_code` inside that chunk (otherwise SARIF falls back to the chunk span). **SARIF 2.1.0** (`sarif/*.sarif`) is generated from the same document for toolchains (DefectDojo, SonarQube, IDE SARIF viewers) and maps those spans to `region.startLine` / `region.endLine` when available. HTML and PDF are rendered from that JSON via Jinja2; Markdown is an additional human-readable export. Canonical JSON includes a top-level **`project`** field (human-readable label) alongside `report_type`, `title`, etc.

```
security_reports/
└── [project_slug]/
    └── YYYYMMDD_HHMMSS/
        ├── logs/
        │   └── oasis_errors_[run_id].log
        └── [sanitized_model_name]/
            ├── json/
            │   └── vulnerability_type.json
            ├── sarif/
            │   └── vulnerability_type.sarif
            ├── md/
            │   └── vulnerability_type.md
            ├── html/
            │   └── vulnerability_type.html
            └── pdf/
                └── vulnerability_type.pdf
```

## 🐋 Run with Docker

The quickest Docker flow is under [Getting started](#getting-started) → **Docker (optional)**. This section is the full reference: Compose variants, plain `docker run`, and Ollama behaviour notes.

The container installs OASIS with **pipx** (same isolation as local development). Reports are written under `security_reports/` next to the parent of your `--input` path—the project root is mounted at **`/work`**, so analyze paths under `/work`.

### Docker Compose (recommended)

From the repository root, build once:

```sh
docker compose build
```

**Ollama on the host** (Linux uses `host.docker.internal` via `extra_hosts`; ensure Ollama is listening on `0.0.0.0` or reachable from Docker):

```sh
docker compose run --rm oasis -i /work/test_files -ol http://host.docker.internal:11434
```

**Bundled Ollama** (profile `ollama`; GPU setup depends on your Docker/NVIDIA stack):

```sh
docker compose --profile ollama up -d ollama
docker compose exec ollama ollama pull mistral
docker compose exec ollama ollama pull nomic-embed-text
docker compose run --rm oasis -i /work/test_files -ol http://ollama:11434
```

**Web dashboard from the container** (`-we lan` listens on all interfaces inside the container; map the port on the host):

```sh
docker compose run --rm -p 5000:5000 oasis -w -we lan -wp 5000 -i /work/test_files -ol http://host.docker.internal:11434
```

### Docker only

The image default command is `oasis --help`. Pass the full CLI after the image name (there is no `ENTRYPOINT`, so debugging with `docker run … bash` works). Example scan:

```sh
docker build -t oasis:local .
docker run --rm -it -v "$(pwd):/work" -w /work --add-host=host.docker.internal:host-gateway oasis:local oasis -i /work/test_files -ol http://host.docker.internal:11434
```

### Ollama structured outputs

Deep and scan analysis calls use Ollama **structured outputs** (`format` with a JSON schema). Use a recent Ollama server; model quality still varies by GGUF. If structured validation fails, the analyzer falls back to safe defaults or regex (function extraction only).

### Structured output hardening

Use this priority order to reduce invalid JSON responses (`Field required`, `json_invalid`, `EOF while parsing a string`):

1. **Model selection first**
   - Choose a scan model that is stable with strict JSON outputs.
   - Keep a deep model only if it stays stable across repeated runs on the same corpus.
   - Compare candidates with the same target files and track invalid JSON rate + average chunk latency.
2. **Ollama generation settings**
   - Keep conservative generation settings for structured scan/deep calls.
   - Keep thinking disabled for strict JSON runs unless a model explicitly requires it.
   - Ensure chunk size and model context window are compatible to avoid truncated outputs.
3. **Targeted retry policy**
   - Retry only known structured failures: missing required `verdict` (scan) and invalid/truncated JSON (`json_invalid`, `EOF while parsing`) for deep responses.
   - Keep retries bounded (scan: up to 2 retries, deep: up to 1 retry) and append a strict JSON correction reminder on retries.
   - Keep final fallback behavior deterministic when retries fail.
4. **Operational safeguards**
   - Track invalid JSON ratio per run and alert when it exceeds your acceptance threshold.
   - Review `security_reports/<project_slug>/<run_timestamp>/logs/oasis_errors_<project_slug>_<run_timestamp>.log` after each scan to identify the failing model/phase/chunk quickly.

Each structured-output error log line includes context fields such as run identifier, model, phase, vulnerability (if available), file path, chunk index, exception type, and a truncated raw preview.
Retry-aware logs also include `retry_attempt` and `retry_max` so you can distinguish first failure from final fallback.

Example hardened command:

```bash
oasis -i ./critical-service -sm qwen2.5-coder:7b -m bugtraceai-apex-q4 -t 0.6 -smt no -mt no --langgraph-max-expand 3
```

### Web dashboard and Reload

- **Assistant** (when viewing a JSON-backed report): open the Assistant panel in the vulnerability modal to chat about the current report; optional **RAG** uses the same project root and `.oasis_cache` embedding pickle as the scan when enabled. You can disable RAG globally at startup (`--no-web-assistant-rag`) or per message from the UI when supported.
- Statistics and risk summaries are read from **`json/*.json`**.
- **Reload** refreshes both `/api/stats?force=1` and `/api/reports?force=1` so listings stay in sync with the filesystem.
- Canonical JSON reports are previewed in the Web UI by rendering HTML from the JSON via the Jinja template, so the modal matches the HTML/PDF structure as closely as possible.
- Markdown preview (`/api/report-content/...`) remains the fallback for legacy reports that do not have a sibling `json/<same-stem>.json`, or when canonical JSON HTML preview cannot be generated.
- Executive summary stays visible even when vulnerability filters are active, so scan-wide context is always available.
- Language filtering is available in the dashboard (`🌐 Filter by language`) and uses the same emoji-flag format as report language badges.
- Scan progress can be queried via `/api/progress` to retrieve the latest executive summary progress metadata (`completed_vulnerabilities`, `total_vulnerabilities`, `is_partial`).
- Executive summary now records all model roles used for the run: **Deep model**, **Small model** (Scan model), and **Embedding model**. These fields are rendered in markdown and therefore propagated to HTML/PDF outputs, and also included in the executive-summary progress sidecar JSON. For backward compatibility, sidecar `model` remains the legacy primary deep-model field.
- Audit cards include an embedding-model comparison table based on parsed audit markdown metrics; selecting model tags can filter both date chips and comparison rows (multi-select supported).
- Date-based filtering supports multiple `model` query params (`/api/dates?model=...&model=...&vulnerability=...`) and falls back to API fetch if local in-memory report data is stale.

## 💾 Cache Management

OASIS implements a sophisticated dual-layer caching system to optimize performance:

### Embedding Cache
- Stores vector embeddings of your codebase to avoid recomputing them for repeated analyses
- Default cache duration: 7 days
- Cache location: `.oasis_cache/[embedding_model_name]/`
- Use `--clear-cache-embeddings` (`-cce`) to force regeneration of embeddings

### Analysis Cache
- Stores the results of LLM-based vulnerability scanning for each model and analysis mode
- Separate caches for scan (lightweight) and deep analysis results
- Model-specific caching ensures results are tied to the specific model used
- Analysis mode-aware (scan vs deep artifacts; LangGraph orchestration uses graph-aligned cache layout where applicable)
- Use `--clear-cache-scan` (`-ccs`) to force fresh vulnerability scanning

This dual-layer approach dramatically improves performance:
- First-time analysis: Compute embeddings + full scanning
- Repeated analysis (same code): Reuse embeddings + scanning results
- After code changes: Update only changed file embeddings + scan only modified components

The cache system intelligently handles:
- Different model combinations (scan model + deep model)
- Different analysis types and modes
- Different vulnerability types
- Cache expiration based on configured days

For the best performance:
- Only clear the embedding cache when changing embedding models or after major code changes
- Clear the scan cache when upgrading to a newer/better model or after fixing vulnerabilities

## 📊 Audit Mode

OASIS offers a specialized Audit Mode that performs an embedding distribution analysis to help you understand your codebase's vulnerability profile before conducting a full scan.

```bash
# Run OASIS in audit mode
oasis --input [path_to_analyze] --audit

# Compare multiple embedding models in one audit run
oasis --input [path_to_analyze] --audit -em qwen3-embedding:4b,bge-m3
```

### What Audit Mode Does

- **Embedding Analysis**: Generates embeddings for your entire codebase and all vulnerability types
- **Chunk-size strategy (auto mode)**: When `--chunk-size` is not set, audit mode auto-detects chunk size once from the first embedding model and reuses it across all audit embedding models for consistent run semantics
- **Similarity Distribution**: Calculates similarity scores between your code and various vulnerability patterns
- **Threshold Analysis**: Shows the distribution of similarity scores across different thresholds
- **Statistical Overview**: Provides mean, median, and max similarity scores for each vulnerability type
- **Top Matches**: Identifies the files or functions with the highest similarity to each vulnerability type
- **Audit Metrics Summary**: Exports a stable `Metric | Value` markdown table (`Count`, `Average`, `Median`, `Max`, `Min`, high/medium/low tiers) that the dashboard parses for model-to-model comparisons

### Benefits of Audit Mode

- **Pre-Scan Intelligence**: Understand which vulnerability types are most likely to be present in your codebase
- **Threshold Optimization**: Determine the optimal similarity threshold for your specific project
- **Resource Planning**: Identify which vulnerabilities require deeper analysis with more powerful models
- **Faster Insights**: Get a quick overview without running a full security analysis
- **Targeted Scanning**: Use the results to focus your main analysis on the most relevant vulnerability types

### Example Workflow

1. **Initial Audit**: 
   ```bash
   oasis -i [path_to_analyze] --audit
   ```

2. **Targeted Analysis** based on audit results:
   ```bash
   oasis -i [path_to_analyze] -v sqli,xss,rce -t 0.65
   ```

The Audit Mode is especially valuable for large codebases where a full scan might be time-consuming, allowing you to make informed decisions about where to focus your security analysis efforts.

## 🌐 Web Interface

OASIS includes a web interface to view and explore security reports:

<img src=".github/images/webserver.png" alt="OASIS Logo" width="100%"/>

<br>

```bash
# Start the web interface with default settings (localhost:5000)
oasis --input [path_to_analyze] --web

# Start with custom port and expose to all network interfaces
oasis --input [path_to_analyze] --web --web-port 8080 --web-expose all

# Start with a specific password
oasis --input [path_to_analyze] --web --web-password mysecretpassword
```

### Security Features

- **Password Protection**: By default, a random password is generated and displayed in the console
- **Network Isolation**: By default, the server only listens on 127.0.0.1
- **Custom Port**: Configurable port to avoid conflicts with other services

When no password is specified, a secure random password will be generated and displayed in the console output. The web interface provides a dashboard to explore security reports, filter results, and view detailed vulnerability information.

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for the latest updates and changes.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. Check out our [Contributing Guidelines](CONTRIBUTING.md) for more details.

Alternatively, you can also contribute by reporting issues or suggesting features.

Come and join our [Discord server](https://discord.gg/dW3sFwTtN3) to discuss the project.

## 📄 License

[GPL v3](LICENSE) - feel free to use this project for your security needs.

## 🙏 Acknowledgments

- Built with [Ollama](https://ollama.ai)
- Uses [WeasyPrint](https://weasyprint.org/) for PDF generation
- Uses [Jinja2](https://jinja.palletsprojects.com/) for report templating
- Special thanks to all contributors and the open-source community

## 📫 Support

If you encounter any issues or have questions, come asking help on our [Discord server](https://discord.gg/dW3sFwTtN3) or please file an issue.