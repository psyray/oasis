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
   - `oasis/web.py`: dashboard indexing (`json/` stats), APIs (`/api/report-json`, legacy MD preview rules)
   - `oasis/ollama_manager.py`: model and Ollama interactions
   - `oasis/static/js/dashboard/*`: web dashboard behavior (JSON modal preview, `force=1` on reload)
3. Keep interfaces compatible unless migration is explicit.
4. Update docs (`README.md`) when user-facing flags or behavior change.
5. Prefer defensive handling around cache/model/network boundaries.
6. For reporting changes, treat canonical JSON schema as the source of truth and keep Jinja templates synchronized.

## Design Guardrails

- Use KISS: choose the smallest change that solves the issue.
- Use DRY: extract repeated formatting or parsing helpers.
- Use SOLID: isolate responsibilities and avoid growing god functions.
- Keep UX fixes localized for dashboard modules and templates.

## Done Criteria

- No obvious module boundary violation.
- Any CLI option change is documented.
- Structured output/report changes stay aligned across `oasis/schemas/`, `oasis/report.py`, `oasis/templates/reports/`, and `tests/test_report_schema.py`.
- Change intent can be summarized with a conventional commit subject.
