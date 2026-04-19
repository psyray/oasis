---
name: oasis-implementation-patterns
description: Implement OASIS features with patterns used in commit history. Use when modifying scanner flow, analysis, model integration, caching, CLI flags, or dashboard behavior.
---

# OASIS Implementation Patterns

## Goal

Apply the code organization and delivery style repeatedly used in OASIS commits.

## Workflow

1. Classify the change as `feat`, `fix`, or `refactor`.
2. Identify the bounded module(s) to touch instead of editing a single large file:
   - `oasis/oasis.py`: CLI and orchestration
   - `oasis/analyze.py`: analysis logic (Ollama structured outputs for scan / deep / adaptive)
   - `oasis/schemas/`: Pydantic models for LLM JSON and canonical vulnerability reports
   - `oasis/report.py`: JSON-first vulnerability reports; Jinja under `oasis/templates/reports/`
   - `oasis/web.py`: dashboard indexing (`json/` stats), APIs (`/api/report-json`, `/api/progress`, Socket.IO `scan_progress`, legacy MD preview rules)
   - `oasis/ollama_manager.py`: model and Ollama interactions
   - `oasis/helpers/`: **all** shared helpers (formatting, parsing, progress helpers, small pure utilities). Do not leave helper-shaped functions in feature modules—extract them here and group by category in dedicated modules (see Design Guardrails).
   - `oasis/static/js/dashboard/*`: web dashboard behavior (JSON modal preview, `force=1` on reload for stats/reports/progress, `applyProgressPayload` / `progressState`)
3. Keep interfaces compatible unless migration is explicit.
4. Update docs (`README.md`) when user-facing flags or behavior change.
5. Prefer defensive handling around cache/model/network boundaries.
6. For reporting changes, treat canonical JSON schema as the source of truth and keep Jinja templates synchronized.
7. Before considering the task done: verify **no duplicated logic** remains (same rule in two places, mirrored constants, near-copy functions). Refactor into a single canonical implementation and import it everywhere it is needed.

## Design Guardrails

### Incremental scan progress (see Cursor rules)

Details live in `.cursor/rules/oasis-python-architecture.mdc` (constants, sidecar, helper modules) and `.cursor/rules/oasis-dashboard-js-patterns.mdc` (REST, Socket.IO, stale `updated_at` guard). Touch `oasis/helpers/progress_constants.py`, `report.py`, `web.py`, and dashboard JS together when the wire contract changes; extend `tests/test_report_schema.py` when behavior is contract-visible.

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

- Run the relevant **`tests/test_<area>.py`** module(s) (or `unittest discover -s tests`) for code you changed; add or extend tests in the file that matches the subsystem (same layout as in the project: report contract, CLI, cache, embedding, helpers, web, etc.).
- **No new duplicated logic** (including near-duplicates); consolidation is part of the task, not optional follow-up.
- No obvious module boundary violation; **no new helper-shaped logic** left outside `oasis/helpers/` without a strong, documented reason.
- Any CLI option change is documented.
- Structured output/report changes stay aligned across `oasis/schemas/`, `oasis/report.py`, `oasis/templates/reports/`, and `tests/test_report_schema.py`.
- Incremental progress contract changes stay aligned across `progress_constants.py`, `report.py`, `web.py`, dashboard JS, and contract tests when applicable (same spirit as report schema alignment).
- Change intent can be summarized with a conventional commit subject.
