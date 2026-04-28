---
name: oasis-release-guardrails
description: Prepare OASIS release-aligned changes based on historical release/version commits. Use when shipping versions, changelog updates, or user-facing CLI/documentation changes.
---

# OASIS Release Guardrails

## Goal

Keep release changes coherent across code, docs, and metadata like historical `release` and `version` commits.

## Checklist

- [ ] Confirm impact scope (`fix` only, feature, or release candidate).
- [ ] If version changes, bump **both** authoritative locations together: **`pyproject.toml`** `[project].version` and **`oasis/__init__.py`** `__version__` (same semver). Optionally run `oasis -V` / `pipx run … python -c "from oasis import __version__"` to verify.
- [ ] Update `CHANGELOG.md` for user-visible behavior changes.
- [ ] Verify `README.md` reflects CLI options and workflow changes (including LangGraph flags: `--langgraph-max-expand`, `--poc-hints`, `--poc-assist` when user-visible).
- [ ] If audit behavior changes, keep `README.md` aligned for multi-model embedding audits (`--audit -em model_a,model_b`), **`audit_report.json`** vs Markdown fallbacks, and dashboard comparison behavior.
- [ ] Ensure dashboard/web changes include matching template/assets updates when required (including **`bootstrap.js`** theme hooks, **`executive-preview.js`** / Chart.js, filtered-preview query params).
- [ ] For structured output/report changes, keep schema models, templates, and report contract tests in sync (executive **`schema_version`**, **`analysis_root`** semantics, audit **`AuditReportDocument`**).
- [ ] If `Audit Metrics Summary` markdown format changes, align `oasis/report.py`, `oasis/web.py` metrics parsing, dashboard audit comparison rendering, and changelog notes in one batch.
- [ ] Shared utilities introduced or refactored for the release live under `oasis/helpers/` in the correct category module, with exports updated in `oasis/helpers/__init__.py` when they are part of the public helper surface.
- [ ] **No duplicated or parallel implementations**: no copy-pasted logic, divergent duplicates, or second sources of truth for the same rule (Python or dashboard JS)—everything is centralized behind a single implementation.

## Commit Guidance

- Use `release: vX.Y.Z` for release batches.
- Use `version: bump to X.Y.Z` for isolated version metadata updates.
- Use `fix|feat|refactor|docs` for normal non-release changes.

## Quality Gate

Before finalizing:

1. Re-read changed docs and confirm they match actual CLI/runtime behavior.
2. Confirm no stale option name remains after renames.
3. Ensure change grouping is logical (avoid mixing unrelated concerns).
4. Scan the diff for **duplication** (repeated blocks, mirrored constants, second implementations); merge into one canonical place before tagging.
5. Run and review automated tests before release tagging: at minimum `tests/test_report_schema.py` for report/progress contracts; include `tests/test_analyze_orchestration.py` when the release touches LangGraph (`oasis/agent/`, `SecurityAnalyzer.langgraph_*`, or graph progress helpers); run `unittest discover` on `tests/` (or coverage via optional `[dev]` — see `.cursor/rules/oasis-dev-install-pipx.mdc`) when the release touches multiple subsystems.
6. Verify pipx-only test commands in docs/rules stay consistent with project policy (`.cursor/rules/oasis-tests-pipx-only.mdc`).
