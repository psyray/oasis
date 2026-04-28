---
name: oasis-implementation-patterns
description: Implement OASIS features with patterns used in commit history. Use when modifying scanner flow, analysis, LangGraph agent (`oasis/agent/`), model integration, caching, CLI flags, or dashboard behavior.
---

# OASIS Implementation Patterns

## Goal

Apply the code organization and delivery style repeatedly used in OASIS commits.

## Workflow

1. Classify the change as `feat`, `fix`, or `refactor`.
2. Identify the bounded module(s) to touch instead of editing a single large file:
   - `oasis/oasis.py`: CLI and orchestration
   - `oasis/analyze.py`: `SecurityAnalyzer` — structured outputs, embedding, cache, and **LangGraph hook methods** (`langgraph_discover_and_publish`, `langgraph_scan_and_publish`, etc.) invoked by the agent layer
   - `oasis/agent/`: **LangGraph-only** — compile the DAG, state schema, node wrappers, and `invoke_oasis_langgraph` (canonical pipeline entry). Keep graph structure and stable node names in one place (see LangGraph layout below).
   - `oasis/schemas/`: Pydantic models for LLM JSON and canonical vulnerability reports
   - `oasis/report.py`: JSON-first vulnerability reports; Jinja under `oasis/templates/reports/`
   - `oasis/web.py`: dashboard indexing (`json/` stats), APIs (`/api/report-json`, `/api/progress`, Socket.IO `scan_progress`, legacy MD preview rules)
   - `oasis/ollama_manager.py`: model and Ollama interactions
   - `oasis/helpers/`: **all** shared helpers (formatting, parsing, progress helpers, small pure utilities). Do not leave helper-shaped functions in feature modules—extract them here and group by category in dedicated modules (see Design Guardrails).
   - `oasis/helpers/embed_models.py`: canonical embed-model normalization/parsing; reuse it for CLI parsing and embedding-manager primary model resolution.
   - `oasis/static/js/dashboard/*`: web dashboard behavior (JSON modal preview, `force=1` on reload for stats/reports/progress, `applyProgressPayload` / `progressState`)
3. Keep interfaces compatible unless migration is explicit.
4. Update docs (`README.md`) when user-facing flags or behavior change.
5. Prefer defensive handling around cache/model/network boundaries.
6. For reporting changes, treat canonical JSON schema as the source of truth and keep Jinja templates synchronized.
7. Before considering the task done: verify **no duplicated logic** remains (same rule in two places, mirrored constants, near-copy functions). Refactor into a single canonical implementation and import it everywhere it is needed.

### Dashboard report modals (shared architecture)

When changing **any** report preview inside `#report-modal` (vulnerability, executive summary, audit report, future canonical types), follow the **single** architecture described in `.cursor/rules/oasis-dashboard-js-patterns.mdc` (**Report modal architecture**):

- **Compact layout** + **TOC / section jumps** + **optional Chart.js** blocks, scoped CSS in `report_preview.css` under `#report-modal-content`.
- **One** post-render initializer path from `modal.js` (`_finalizeReportModalView`) for kind detection (stem, path, or `report_type`) — no scattered one-off branches.
- **Assistant**: one `mountReportAssistantPanel` pipeline with **variants** (finding selectors only for vuln JSON; aggregated or report-scoped chat for executive/audit as designed) — duplicate chat stacks per report type are not acceptable.
- **Server**: meta/preview endpoints and parsing live in `web.py` + `oasis/helpers/`; extend shared helpers instead of copying aggregation logic for each modal.

Treat **audit** modal work as reusing this spine when aligning with the vulnerability/executive experience, not as a greenfield duplicate UI stack.

### LangGraph layout (canonical analysis pipeline)

- **Product path**: `AnalysisType.GRAPH` in `oasis/enums.py` is the only orchestration mode; on-disk chunk caches live under `graph/deep` and `graph/scan` (see `oasis/cache.py`).
- **Import discipline**: Import LangGraph entry points explicitly (e.g. `from oasis.agent.invoke import invoke_oasis_langgraph`). The `oasis.agent` package docstring explains avoiding a heavy import at interpreter startup when only the submodule is needed.
- **`oasis/agent/graph_labels.py`**: Single source for node ids (`GRAPH_NODE_*`) and conditional route targets — use these strings in `graph.py`, routing, and tests instead of scattering literals.
- **`oasis/agent/graph.py`**: Builds `StateGraph(OasisGraphState)` — edges: Discover → Scan → Expand → Deep → Verify → (conditional: Expand or Report) → (conditional: PoC or END when PoC disabled) → END.
- **`oasis/agent/tools.py`**: Thin dispatch — each node calls the matching `SecurityAnalyzer.langgraph_*` method; console UX uses `oasis/helpers/langgraph_console.py` (`langgraph_emit`, `langgraph_emit_phase`, etc.).
- **`oasis/agent/state.py`**: Typed state passed between nodes (`all_results`, `expand_iterations`, `max_expand_iterations` from CLI, PoC markdown accumulator, etc.).
- **Helpers tied to the graph**:
  - `oasis/helpers/graph_progress.py` — executive-summary `phases` rows aligned with LangGraph stages (`ProgressPhaseRowId.GRAPH_*`, `ProgressActivePhase.GRAPH_PIPELINE`).
  - `oasis/helpers/langgraph_counts.py` — canonical vuln-type totals for LangGraph (`embedding_tasks_vuln_types_total`, `deep_payload_vuln_types_total`).
  - `oasis/helpers/langgraph_console.py` — numbered phases, tqdm-safe logging, post-pipeline / report-delivery banners (also used from `report.py`).
  - `oasis/helpers/scan_progress_md.py` — normalize scan progress JSON / markdown sections (keep in sync with report-side progress).
  - `oasis/helpers/context/expand.py` — pure line-window expansion around suspicious spans; defaults from `oasis/config.py` (`CONTEXT_EXPAND_*`).
  - `oasis/helpers/poc_digest.py` — compact findings digest JSON for `--poc-assist`.
  - `oasis/helpers/poc_pipeline.py` — PoC budgets (re-export from config), hints markdown (`build_poc_hints_markdown`), chat options (`poc_assist_chat_options`), stage DEBUG logging (`maybe_debug_log_poc_stage_output`).
- **CLI** (extend `README.md` when behavior changes): `--langgraph-max-expand` (`langgraph_max_expand_iterations`), `--poc-hints`, `--poc-assist`.
- **Tests**: `tests/test_analyze_orchestration.py` for the LangGraph pipeline and PoC helpers; `tests/test_oasis_cli.py` for LangGraph-related flags.

## Design Guardrails

### Incremental scan progress (see Cursor rules)

Details live in `.cursor/rules/oasis-python-architecture.mdc` (constants in `oasis/helpers/progress/__init__.py`, sidecar, helper modules) and `.cursor/rules/oasis-dashboard-js-patterns.mdc` (REST, Socket.IO, stale `updated_at` guard). Touch `oasis/helpers/progress/__init__.py`, `report.py`, `web.py`, and dashboard JS together when the wire contract changes; extend `tests/test_report_schema.py` when behavior is contract-visible.

### Audit metrics and dashboard comparison

- `Report.generate_audit_report` must keep an `Audit Metrics Summary` markdown table with stable `Metric | Value` rows (count/similarity/high-medium-low tiers).
- When **`json`** is in output formats, OASIS also writes **`audit_report.json`** (`oasis/schemas/audit_report.py`); Markdown and JSON must reflect the same document. The dashboard prefers sibling JSON for listing metrics and modal HTML via `/api/report-html` when the file exists.
- `WebServer` parses metrics into `audit_metrics` for `/api/reports` (JSON first, then Markdown). Shared **`md` → `json`** rules live in `oasis/helpers/dashboard/json_sibling.py` and dashboard **`audit-report-paths.js`**—keep them aligned with `web.py` preview routes.
- Dashboard comparison UI (`utils.js` + `views.js` + `interactions.js`) depends on those keys; treat report/web/dashboard as one contract surface and update tests in `tests/test_report_schema.py` together.

### Report storage, executive JSON, and dashboard filters

- **Output tree**: Default **`security_reports/<project_slug>/YYYYMMDD_HHMMSS/…`**; optional **`--project-name` / `-pn`** overrides slug naming—coordinate **`oasis/helpers/report_project.py`**, CLI (`oasis/oasis.py`), exporters, and **`README.md`** when behavior shifts.
- **Executive summary canonical JSON**: Rich **`schema_version`** document built in **`oasis/helpers/executive_summary.py`** and **`oasis/report.py`** (overview KPIs, **`guidance_markdown`**, **`tier_definitions`**, capped **`similarity_highlights`**). HTML preview uses **`executive_summary_from_json.html.j2`** and **`executive-preview.js`** (TOC, Chart.js)—change schema, templates, and dashboard consumers together.
- **`analysis_root`**: Stored **relative to `security_reports/`** in new JSON; resolution lives in **`oasis/helpers/analysis_root_path.py`**—reuse for assistant/RAG and **`scan_root`**; never duplicate path guessing in `web.py`.
- **Dashboard**: **Severity** (tier) + **project** filters and **scoped previews** (queries wrapped with active filters; server rejects out-of-scope paths). **`/api/stats`** exposes **`severity_finding_totals`**. Python: **`oasis/helpers/dashboard/severity_filter.py`** and **`web.py`**; JS: **`filters.js`**, **`api.js`**, **`modal.js`**.
- **Web UI theme**: Header light/dark toggle and **`oasis:theme-change`** in **`bootstrap.js`**; charts must follow (**`views.js`**, **`executive-preview.js`**).

### Duplication and centralization (strict)

- **Do not repeat code.** Treat copy-paste and “almost the same” branches as defects: merge into one function, module, or schema and reuse. **KISS** means the smallest *correct* change, not duplicating logic to save a refactor step. **DRY** is mandatory, not aspirational. **SOLID** is incompatible with parallel implementations of the same rule in different files.
- Before shipping, ask: “If this behavior changes tomorrow, is there exactly **one** place to edit?” If not, centralize first (Python: `oasis/helpers/` or `oasis/schemas/` as appropriate; JS dashboard: shared modules under `oasis/static/js/dashboard/`).
- Duplicating strings, field names, validation rules, or API shapes across modules is still duplication—use shared constants, Pydantic models, or helpers.

### Other guardrails

- Use KISS: choose the smallest change that solves the issue **after** consolidation, not instead of it.
- **Helper centralization**: Anything that matches “helper” characteristics—stateless or lightly stateful utilities, shared formatters/parsers, progress or status row builders, guards, small transforms reused outside one call site—**must** be implemented under `oasis/helpers/`, in a module that matches its **category** (e.g. progress-related code beside `scan_progress.py` / `exec_summary_progress.py`, shared types beside `progress_types.py`). When touching existing code, relocate qualifying functions into the appropriate helper module instead of growing orchestration files.
- Use SOLID: isolate responsibilities and avoid growing god functions; helpers stay thin and focused per module.
- Keep UX fixes localized for dashboard modules and templates.

## Done Criteria

- Run the relevant **`tests/test_<area>.py`** module(s) (or `unittest discover -s tests`) for code you changed; add or extend tests in the file that matches the subsystem (same layout as in the project: report contract, CLI, cache, embedding, helpers, web, LangGraph orchestration in `tests/test_analyze_orchestration.py`, etc.).
- **No new duplicated logic** (including near-duplicates); consolidation is part of the task, not optional follow-up.
- No obvious module boundary violation; **no new helper-shaped logic** left outside `oasis/helpers/` without a strong, documented reason.
- Any CLI option change is documented.
- Structured output/report changes stay aligned across `oasis/schemas/`, `oasis/report.py`, `oasis/templates/reports/`, and `tests/test_report_schema.py`.
- Incremental progress contract changes stay aligned across `oasis/helpers/progress/__init__.py`, `report.py`, `web.py`, dashboard JS, and contract tests when applicable (same spirit as report schema alignment).
- Change intent can be summarized with a conventional commit subject.
