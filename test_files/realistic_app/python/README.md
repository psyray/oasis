# Realistic fixture: Python Flask help-desk API

File: `test_files/realistic_app/python/ticketing_app.py`

## Scenario
A small Flask help-desk application exposing endpoints for ticket search,
admin diagnostics, document reading, XML import and login.

## Covered vulnerability families

| Endpoint | Family | Expected verdict | Notes |
|---|---|---|---|
| `/ticket/search` | SQL injection | `confirmed_exploitable` | direct concatenation into raw query |
| `/ticket/search-safe` | SQL injection | `false_positive` | parameterized query |
| `/ticket/<id>` | SQL injection | `confirmed_exploitable` | path parameter concatenated |
| `/admin/ping` | Command injection | `confirmed_exploitable` | `shell=True` with user input |
| `/admin/ping-safe` | Command injection | `false_positive` | allowlist + no shell |
| `/admin/diag` | Command injection | `confirmed_exploitable` | full command from query string |
| `/ticket/<id>/render` | XSS | `confirmed_exploitable` | unescaped content reflected |
| `/ticket/<id>/render-safe` | XSS | `false_positive` | `html.escape` |
| `/feedback` | XSS (reflected) | `confirmed_exploitable` | query string reflected |
| `/internal/import` | Insecure deserialization | `confirmed_exploitable` | `pickle.loads` |
| `/internal/import-json` | Insecure deserialization | `false_positive` | JSON parser only |
| `/docs/<filename>` | Path traversal / LFI | `confirmed_exploitable` | user-controlled path |
| `/docs-safe/<filename>` | Path traversal / LFI | `likely_vulnerable` | `basename` only; extension not restricted |
| `/fetch` | SSRF | `confirmed_exploitable` | arbitrary URL fetch |
| `/fetch-safe` | SSRF | `false_positive` | strict host allowlist |
| `/goto` | Open redirect | `confirmed_exploitable` | arbitrary redirect |
| `/goto-safe` | Open redirect | `false_positive` | path allowlist |
| `/login` + `ADMIN_PASSWORD` | Hardcoded secret | `confirmed_exploitable` | backdoor credential in code |
| `hash_password` | Weak cryptography | `confirmed_exploitable` | MD5 password hash |
| `/xml/parse` | XXE | `confirmed_exploitable` | default DOM parser resolves entities |
| `/xml/parse-safe` | XXE | `false_positive` | defusedxml disables entities |

## Sample payloads

```bash
# SQLi
/ticket/search?title=' OR '1'='1

# Command injection
/admin/ping?host=127.0.0.1;id
/admin/diag?action=whoami

# XSS
/feedback?msg=<script>alert(1)</script>

# Path traversal
/docs/../../etc/passwd

# SSRF
/fetch?url=file:///etc/passwd
```

## Running
This file is intentionally dangerous and meant for static analysis only.
Do not expose it on any network.
