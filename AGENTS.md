# OASIS — Agent Instructions

**OASIS** (**O**llama **A**utomated **S**ecurity **I**ntelligence **S**canner) — Python 3.9+ CLI plus a Flask/Socket.IO web dashboard for AI-powered, fully local code security auditing via Ollama models and a LangGraph pipeline. Public repo: `github.com/psyray/oasis`.

## Install / refresh (pipx only)

```bash
pipx uninstall oasis && pipx install -e .          # runtime CLI
pipx uninstall oasis && pipx install -e ".[dev]"   # + optional dev extras (coverage)
```

- Run `pipx uninstall oasis` from outside the repository if pipx mistakes the local `oasis/` directory for a package name.
- Use this flow after dependency or entrypoint changes so the isolated venv matches the working tree.
- Do not assume a global `pip install`; the project standard for local tooling is **pipx**.

## Tests (pipx only — non-negotiable)

- **NEVER** run tests outside `pipx`: no `uv`, no system Python, no direct `pytest`, no `python -m unittest` without `pipx run`.

```bash
# single module
PYTHONPATH="$(pwd)" pipx run --spec . python -m unittest tests.<module_or_class>
# broader verification in one invocation
PYTHONPATH="$(pwd)" pipx run --spec . python -m unittest tests.test_oasis_cli tests.test_embedding_pure tests.test_report_schema
```

- Coverage (requires `.[dev]`), from the repository root:

```bash
PYTHONPATH="$(pwd)" coverage run -m unittest discover -s tests
coverage report
```

- Test changes go in the matching `tests/test_<area>.py` (report contracts → `test_report_schema.py`, CLI → `test_oasis_cli.py`, LangGraph orchestration → `test_analyze_orchestration.py`, dashboard helpers → `test_helpers_dashboard.py`, finding validation → `test_assistant_validation.py`, assistant API → `test_web_assistant_api.py`), in the same change set for contract- or regression-sensitive behavior.

## Lint gates before "done"

- Run Zed diagnostics (the agent's `diagnostics` tool) on every edited Python/JS file and fix new diagnostics before the final response. "Logic is correct" is not enough — code must be lint-clean.
- State in the response which checks ran and whether diagnostics are zero for edited files.
- Python guardrails: no broad `except Exception` without justification (prefer specific exception tuples and log warnings on safe fallbacks); normalize untrusted/coerced values with defensive helpers before casting; keep shaping logic in small helpers.
- JavaScript guardrails: prefer `else if` over nested `if` inside `else`; normalize dynamic values once (`trim()`, `String(...)`) and reuse; remove redundant operations (`slice(0)`, duplicated transforms, dead branches).

## Git & docs conventions

- Conventional Commit prefixes: `feat`, `fix`, `refactor`, `docs`, `release` (`release: vX.Y.Z`), `version` (`version: bump to X.Y.Z`). Subjects short and scoped to user-visible intent; incremental commits focused on one concern.
- Version bumps update **both** authoritative locations together: `pyproject.toml` `[project].version` and `oasis/__init__.py` `__version__` (same semver).
- `README.md`: keep `Features` summary-only; place detailed behavior/usage in the relevant dedicated section (create one for new feature areas). Update README in the same change when a CLI flag or behavior changes; keep install/upgrade docs aligned with the pipx workflow.
- `CHANGELOG.md`: entries concise, style-consistent with the file's charter, filed under the version bucket matching the current branch lineage.
- Contract changes ship coordinated updates in the same change set (see the `oasis-release-guardrails` skill for the full checklist); migrate all call sites of shared logic at once so `main` never retains two competing implementations.

## Project skills (load on demand)

- `oasis-python-architecture` — Python module layout, helpers centralization, LangGraph graph layer, wire contracts.
- `oasis-dashboard-js-patterns` — dashboard JS modules, report-modal architecture, frontend/backend contracts.
- `oasis-implementation-patterns` — end-to-end workflow for features/fixes/refactors (module selection, design guardrails, done criteria).
- `oasis-release-guardrails` — release/version checklist (changelog, docs alignment, quality gate).