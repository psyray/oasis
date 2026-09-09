# Realistic vulnerable test fixtures

This directory contains small, coherent mini-applications used by OASIS to
test data-flow aware vulnerability detection. Unlike the legacy `test_files/*.py`
catalog of isolated sinks, these fixtures have **realistic entry points**
(HTTP endpoints, CLI handlers, etc.) and **safe/vulnerable variants side-by-side**.

## Layout

```
realistic_app/
├── README.md               # this file
├── python/
│   └── ticketing_app.py      # Flask help-desk API
├── csharp/
│   └── Program.cs            # ASP.NET Core minimal API
├── php/
│   └── blog_admin.php        # procedural blog / admin panel
├── java/
│   └── DocumentManager.java  # document management API
└── js/
    └── feedback_api.js       # Express feedback / upload API
```

## Python fixture (`ticketing_app.py`)

Scenario: a Flask help-desk API with ticket search, admin diagnostics,
document reading, XML import and login.

| Endpoint | Family | Expected | Notes |
|---|---|---|---|
| `/ticket/search` | SQL injection | exploitable | raw concatenation |
| `/ticket/search-safe` | SQL injection | safe | parameterized query |
| `/ticket/<id>` | SQL injection | exploitable | path parameter concatenated |
| `/admin/ping` | Command injection | exploitable | `shell=True` with user input |
| `/admin/ping-safe` | Command injection | safe | allowlist + no shell |
| `/admin/diag` | Command injection | exploitable | full command from query string |
| `/ticket/<id>/render` | XSS | exploitable | unescaped content reflected |
| `/ticket/<id>/render-safe` | XSS | safe | `html.escape` |
| `/feedback` | XSS (reflected) | exploitable | query string reflected |
| `/internal/import` | Insecure deserialization | exploitable | `pickle.loads` |
| `/internal/import-json` | Insecure deserialization | safe | JSON parser only |
| `/docs/<filename>` | Path traversal / LFI | exploitable | user-controlled path |
| `/docs-safe/<filename>` | Path traversal / LFI | partial | `basename` only |
| `/fetch` | SSRF | exploitable | arbitrary URL fetch |
| `/fetch-safe` | SSRF | safe | strict host allowlist |
| `/goto` | Open redirect | exploitable | arbitrary redirect |
| `/goto-safe` | Open redirect | safe | path allowlist |
| `/login` + `ADMIN_PASSWORD` | Hardcoded secret | exploitable | backdoor credential |
| `hash_password` | Weak cryptography | exploitable | MD5 password hash |
| `/xml/parse` | XXE | exploitable | default DOM parser |
| `/xml/parse-safe` | XXE | safe | defusedxml |

## Design rules

- One coherent scenario per language.
- Entry point → sink in at most 3 hops.
- Vulnerable and safe variants live in the same file for precision testing.
- Only stdlib / built-in APIs (no real DB or network at runtime).
- Static test files — **do not run them as services**.

## Usage

```bash
cd /path/to/oasis/code
oasis -i test_files/realistic_app/python \
  --provider openai --api-base http://llm.example.com/v1 \
  -m Qwen/Qwen2.5-Coder-32B-Instruct \
  -sm Qwen/Qwen2.5-Coder-7B-Instruct \
  -em bge-m3
```

## OASIS scan notes (observed on 2026-09-08)

Using `Qwen3.8-27B-NVFP4` deep + `gemma4-12b` scan + `bge-m3` embeddings,
the Python fixture produced clear findings for every vulnerable endpoint
listed above. Safe variants did not generate findings except for
`/docs-safe/<filename>`, which is intentionally a partial mitigation.

If a previous run cached old findings, delete `.oasis_cache/` inside the
fixture directory before re-scanning after fixture changes.

## Automated E2E check

`scripts/e2e_fixture_scan.py` (repo root) runs the CLI on each fixture language
directory with a reduced vulnerability set (default: the Injection family —
SQL Injection, Command Injection, XSS) and checks the canonical JSON reports
for the expected detections and scan-time verdicts:

```bash
python scripts/e2e_fixture_scan.py \
  --provider openai --api-base http://llm.example.com/v1 \
  --model Qwen/Qwen2.5-Coder-32B-Instruct \
  --embed-model bge-m3
```

It prints a per-(language, vulnerability) pass/fail table and exits non-zero
when an expected detection is missing. Run outputs are kept in a temp directory
(override with `--output-dir`). It requires a live LLM server, so it is a
manual/dev tool, not a CI test.
