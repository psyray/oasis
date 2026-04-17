---
name: oasis-release-guardrails
description: Prepare OASIS release-aligned changes based on historical release/version commits. Use when shipping versions, changelog updates, or user-facing CLI/documentation changes.
---

# OASIS Release Guardrails

## Goal

Keep release changes coherent across code, docs, and metadata like historical `release` and `version` commits.

## Checklist

- [ ] Confirm impact scope (`fix` only, feature, or release candidate).
- [ ] If version changes, update authoritative version files consistently.
- [ ] Update `CHANGELOG.md` for user-visible behavior changes.
- [ ] Verify `README.md` reflects CLI options and workflow changes.
- [ ] Ensure dashboard/web changes include matching template/assets updates when required.
- [ ] For structured output/report changes, keep schema models, templates, and report contract tests in sync.

## Commit Guidance

- Use `release: vX.Y.Z` for release batches.
- Use `version: bump to X.Y.Z` for isolated version metadata updates.
- Use `fix|feat|refactor|docs` for normal non-release changes.

## Quality Gate

Before finalizing:

1. Re-read changed docs and confirm they match actual CLI/runtime behavior.
2. Confirm no stale option name remains after renames.
3. Ensure change grouping is logical (avoid mixing unrelated concerns).
4. Run and review the report contract test path (at least `tests/test_report_schema.py`) before release tagging.
