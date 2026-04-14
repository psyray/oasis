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
   - `oasis/analyze.py`: analysis logic
   - `oasis/ollama_manager.py`: model and Ollama interactions
   - `oasis/static/js/dashboard/*`: web dashboard behavior
3. Keep interfaces compatible unless migration is explicit.
4. Update docs (`README.md`) when user-facing flags or behavior change.
5. Prefer defensive handling around cache/model/network boundaries.

## Design Guardrails

- Use KISS: choose the smallest change that solves the issue.
- Use DRY: extract repeated formatting or parsing helpers.
- Use SOLID: isolate responsibilities and avoid growing god functions.
- Keep UX fixes localized for dashboard modules and templates.

## Done Criteria

- No obvious module boundary violation.
- Any CLI option change is documented.
- Change intent can be summarized with a conventional commit subject.
