"""Centralized regex patterns used by the assistant validation helpers.

Single source of truth for entry points, taint sources, dangerous sinks, known
mitigations, access controls, config audits, secrets and crypto heuristics.
Keeping everything here lets the validator helpers stay small and guarantees
that adding support for a new framework only touches one file.

Every pattern is a plain Python regex string; helpers compile them on demand.
Patterns aim for broad recall (detection) rather than precision: the verdict
node aggregates signals deterministically so false positives are tolerable.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

PATTERNS_VERSION = 1


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #
# Each tuple is (pattern, label) where label is a short human tag.
# ``framework`` is used both to classify hits and to allow UI filtering.
ENTRY_POINTS: Dict[str, List[Tuple[str, str]]] = {
    "flask": [
        (r"@(?:app|bp|blueprint|api)\.route\s*\(\s*['\"]([^'\"]+)['\"]", "flask_route"),
        (r"@(?:app|bp|blueprint|api)\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", "flask_verb"),
        (r"add_url_rule\s*\(\s*['\"]([^'\"]+)['\"]", "flask_add_url_rule"),
    ],
    "django": [
        (r"\bpath\s*\(\s*['\"]([^'\"]*)['\"]", "django_path"),
        (r"\bre_path\s*\(\s*r?['\"]([^'\"]+)['\"]", "django_re_path"),
        (r"\burl\s*\(\s*r?['\"]([^'\"]+)['\"]", "django_url"),
    ],
    "fastapi": [
        (r"@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", "fastapi_verb"),
    ],
    "express": [
        (r"\b(?:app|router)\.(get|post|put|delete|patch|use)\s*\(\s*['\"]([^'\"]+)['\"]", "express_route"),
    ],
    "spring": [
        (r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)['\"]", "spring_mapping"),
    ],
    "laravel": [
        (r"\bRoute::(get|post|put|delete|patch|any)\s*\(\s*['\"]([^'\"]+)['\"]", "laravel_route"),
    ],
    "rails": [
        (r"^\s*(?:get|post|put|delete|patch)\s+['\"]([^'\"]+)['\"]", "rails_route"),
    ],
    "aspnet": [
        # ASP.NET Core attribute routing and Web API
        (r"\[(?:Http)?(?:Get|Post|Put|Delete|Patch)\s*\(\s*['\"]([^'\"]+)['\"]", "aspnet_verb"),
        (r"\[Route\s*\(\s*['\"]([^'\"]+)['\"]", "aspnet_route"),
        (r"\[ApiController\b", "aspnet_controller"),
        (r"app\.Map(?:Get|Post|Put|Delete|Patch)\s*\(\s*['\"]([^'\"]+)['\"]", "aspnet_minimal"),
        # ASP.NET Core Razor Pages
        (r"\bOn(?:Get|Post|Put|Delete|Patch)(?:Async)?\s*\(", "razor_page_handler"),
        # WCF / legacy ASMX
        (r"\[OperationContract\b", "wcf_operation"),
        (r"\[WebMethod\b", "asmx_webmethod"),
    ],
    "blazor": [
        (r"@page\s+\"([^\"]+)\"", "blazor_page"),
    ],
    "winforms_wpf_maui": [
        # Event handlers in C#/VB desktop frameworks (user inputs come via UI
        # events; treating the handler as an entry point keeps parity with web
        # routes). Matches both C# signatures and VB ``Handles ...`` clauses.
        (r"\bprivate\s+(?:async\s+)?void\s+\w+_(?:Click|Load|TextChanged|KeyDown|Submit)\s*\(", "ui_event_handler_cs"),
        (r"\bPublic\s+Sub\s+\w+_(?:Click|Load|TextChanged|KeyDown|Submit)\s*\(", "ui_event_handler_vb"),
        (r"\bICommand\b", "mvvm_command"),
        (r"\[RelayCommand\b", "mvvm_relay_command"),
    ],
    "cli": [
        (r"@(?:click|typer)\.(?:command|argument|option)\s*\(", "cli_click_typer"),
        (r"argparse\.ArgumentParser\s*\(", "cli_argparse"),
    ],
    "messaging": [
        (r"@(?:app|celery)\.task\b", "celery_task"),
        (r"\bon_message\s*\(", "queue_on_message"),
    ],
}


# --------------------------------------------------------------------------- #
# Taint sources (user-controlled inputs)
# --------------------------------------------------------------------------- #
SOURCES: Dict[str, List[str]] = {
    "http_params": [
        r"\brequest\.(?:args|query_params|GET|params|querystring)\b",
        r"\brequest\.form\b",
        r"\brequest\.values\b",
        r"\brequest\.json(?:\s*\(\s*\))?",
        r"\brequest\.get_json\s*\(",
        r"\breq\.query\b",
        r"\brouter\.query\b",
        r"\bparams\.get\s*\(",
        # ASP.NET Core
        r"\bRequest\.Query\[",
        r"\bRequest\.Form\[",
        r"\[FromQuery\b",
        r"\[FromForm\b",
        r"\[FromRoute\b",
        r"\[FromBody\b",
    ],
    "http_headers": [
        r"\brequest\.headers\b",
        r"\brequest\.META\b",
        r"\brequest\.cookies\b",
        r"\brequest\.COOKIES\b",
        r"\breq\.headers\b",
        r"\bheaders\.get\s*\(",
        r"\bRequest\.Headers\[",
        r"\bRequest\.Cookies\[",
        r"\[FromHeader\b",
    ],
    "http_body": [
        r"\brequest\.body\b",
        r"\brequest\.data\b",
        r"\brequest\.stream\b",
        r"\breq\.body\b",
        r"\bRequest\.Body\b",
        r"\bHttpContext\.Request\.Body\b",
    ],
    "http_file_upload": [
        r"\brequest\.files\b",
        r"\brequest\.FILES\b",
        r"\breq\.files\b",
        r"\bMultipartFile\b",
    ],
    "env_var": [
        r"\bos\.environ\[",
        r"\bos\.environ\.get\s*\(",
    ],
}


# --------------------------------------------------------------------------- #
# Dangerous sinks
# --------------------------------------------------------------------------- #
SINKS: Dict[str, List[str]] = {
    "sql_execute": [
        r"\b(?:cursor|conn(?:ection)?|db|session)\.(?:execute|executemany|executescript|raw)\s*\(",
        r"\.query\s*\(",
        r"\bText\s*\(\s*['\"]",
        r"\bexec_driver_sql\s*\(",
        # C# / VB.NET ADO.NET family (SqlCommand, OleDbCommand, OdbcCommand …)
        r"\bnew\s+(?:Sql|OleDb|Odbc|MySql|Npgsql|Sqlite|Oracle)Command\s*\(",
        r"\.(?:ExecuteReader|ExecuteNonQuery|ExecuteScalar|ExecuteReaderAsync|ExecuteNonQueryAsync|ExecuteScalarAsync)\s*\(",
        r"\.(?:FromSql|FromSqlRaw|FromSqlInterpolated|ExecuteSqlRaw|ExecuteSqlInterpolated)\s*\(",
        # Dapper
        r"\.(?:Query|QueryAsync|QueryFirst|QueryFirstAsync|Execute|ExecuteAsync)\s*\(",
    ],
    "os_exec": [
        r"\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\(",
        r"\bos\.(?:system|popen|execl|execv|execvp|spawnv)\s*\(",
        r"\bRuntime\.getRuntime\(\)\.exec\s*\(",
        # .NET: System.Diagnostics.Process.Start(...) and ProcessStartInfo
        r"\bProcess\.Start\s*\(",
        r"\bnew\s+ProcessStartInfo\s*\(",
    ],
    "shell_exec": [
        r"\bshell\s*=\s*True\b",
        r"\bexec\s*\(\s*['\"][^'\"]*\$\{",
    ],
    "eval_exec": [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"\bFunction\s*\(\s*['\"]",
        r"\bnew\s+Function\s*\(",
    ],
    "dynamic_import": [
        r"\b__import__\s*\(",
        r"\bimportlib\.import_module\s*\(",
    ],
    "html_render": [
        r"\brender_template_string\s*\(",
        r"\bMarkup\s*\(",
        r"\|\s*safe\b",
    ],
    "innerHTML_write": [
        r"\.innerHTML\s*=",
        r"\bdangerouslySetInnerHTML\b",
        r"\bdocument\.write\s*\(",
    ],
    "template_mark_safe": [
        r"\bmark_safe\s*\(",
    ],
    "file_open": [
        r"\bopen\s*\(",
        r"\bPath\s*\([^)]*\)\.read_text\s*\(",
        r"\bFile(?:Input|Reader)Stream\s*\(",
        r"\bfs\.(?:readFile|readFileSync|createReadStream)\s*\(",
    ],
    "path_join": [
        r"\bos\.path\.join\s*\(",
        r"\bPath\s*\([^)]*\)\s*/",
    ],
    "file_include": [
        r"\b(?:include|require)(?:_once)?\s*\(",
    ],
    "file_write": [
        r"\.save\s*\(",
        r"\bshutil\.copyfileobj\s*\(",
        r"\bopen\s*\([^)]*['\"][aw]b?['\"]",
    ],
    "url_fetch": [
        r"\brequests\.(?:get|post|put|delete|patch|request)\s*\(",
        r"\burllib\.request\.urlopen\s*\(",
        r"\bhttpx\.(?:get|post|put|delete|patch|request|AsyncClient)\s*\(",
        r"\bfetch\s*\(",
        r"\baxios\.(?:get|post|put|delete|patch|request)\s*\(",
    ],
    "redirect_call": [
        r"\bredirect\s*\(",
        r"\bres\.redirect\s*\(",
        r"\bHttpResponseRedirect\s*\(",
        r"\bLocation\s*:\s*",
    ],
    "xml_parse": [
        r"\bxml\.etree\.ElementTree\.(?:parse|fromstring|XMLParser)\s*\(",
        r"\blxml\.etree\.(?:parse|fromstring|XMLParser)\s*\(",
        r"\bDocumentBuilderFactory\b",
    ],
    "deserialize_call": [
        r"\bpickle\.loads?\s*\(",
        r"\byaml\.load\s*\(",
        r"\bjsonpickle\.decode\s*\(",
        r"\bObjectInputStream\s*\(",
        r"\bunserialize\s*\(",
    ],
    "db_get_by_id": [
        r"\.get\s*\(\s*(?:id|pk)\s*=",
        r"\.objects\.get\s*\(",
        r"\.find(?:One|ById)\s*\(",
        r"\bfindById\s*\(",
    ],
    "object_lookup": [
        r"\bget_object_or_404\s*\(",
    ],
    "state_change": [
        # Treat any POST/PUT/DELETE/PATCH route declaration as a state-changing sink
        r"methods\s*=\s*\[[^\]]*['\"](?:POST|PUT|DELETE|PATCH)['\"]",
        r"@(?:app|bp|router)\.(?:post|put|delete|patch)\b",
    ],
    "auth_check": [
        r"\bcheck_password\s*\(",
        r"\bauthenticate\s*\(",
        r"\bverify_password\s*\(",
    ],
    "config_flag": [
        r"\bDEBUG\s*=\s*True\b",
        r"\bALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]",
        r"\bapp\.debug\s*=\s*True\b",
    ],
    "debug_flag": [
        r"\bDEBUG\s*=\s*True\b",
        r"\bapp\.run\s*\([^)]*debug\s*=\s*True",
        r"\bFLASK_DEBUG\b",
    ],
    "stack_trace_render": [
        r"\btraceback\.format_exc\s*\(",
        r"\.printStackTrace\s*\(",
    ],
    "http_response": [
        r"\bjsonify\s*\(",
        r"\bJsonResponse\s*\(",
        r"\bres\.(?:json|send)\s*\(",
    ],
    "log_write": [
        r"\b(?:logger|logging|log)\.(?:debug|info|warning|error|critical|exception)\s*\(",
        r"\bprint\s*\(",
        r"\bconsole\.(?:log|error|warn)\s*\(",
    ],
    "crypto_call": [
        r"\bhashlib\.(?:md5|sha1)\s*\(",
        r"\bCrypto\.Cipher\.DES\b",
        r"\bCipher\.getInstance\s*\(\s*['\"](?:DES|RC4|ECB)",
        r"\bcrypto\.createCipher\s*\(",
    ],
    "secret_literal": [
        r"(?i)\b(?:secret|password|api[_-]?key|token)\s*[:=]\s*['\"][A-Za-z0-9/+=_\-]{12,}['\"]",
    ],
}


# --------------------------------------------------------------------------- #
# Mitigations
# --------------------------------------------------------------------------- #
MITIGATIONS: Dict[str, List[str]] = {
    "sql_parameterized": [
        r"\.execute\s*\([^,)]+,\s*[\(\[]",
        r"\bparamstyle\b",
        r"\?\s*,\s*[\(\[]",
    ],
    "orm_query": [
        r"\b(?:Model|session|db|objects)\.(?:filter|filter_by|query|all|first|get)\s*\(",
        r"\bsqlalchemy\.orm\b",
    ],
    "sql_escape": [
        r"\bescape_string\s*\(",
        r"\bmysql_real_escape_string\s*\(",
    ],
    "arg_array_exec": [
        r"\bsubprocess\.(?:run|call|Popen|check_output)\s*\(\s*\[",
    ],
    "shlex_quote": [
        r"\bshlex\.quote\s*\(",
    ],
    "allowlist_cmd": [
        r"\bif\s+cmd\s+in\s+\{?\[",
        r"\bALLOWED_COMMANDS\b",
    ],
    "ast_literal": [
        r"\bast\.literal_eval\s*\(",
    ],
    "html_escape": [
        r"\bhtml\.escape\s*\(",
        r"\bescape\s*\(",
        r"\bencodeURIComponent\s*\(",
        r"\bDOMPurify\.sanitize\s*\(",
    ],
    "bleach_clean": [
        r"\bbleach\.clean\s*\(",
    ],
    "autoescape_on": [
        r"\bautoescape\s*=\s*True\b",
        r"\{%\s*autoescape\s+on\b",
    ],
    "safe_join": [
        r"\bsafe_join\s*\(",
        r"\bwerkzeug\.utils\.secure_filename\s*\(",
    ],
    "path_normalize": [
        r"\bos\.path\.(?:realpath|abspath|normpath)\s*\(",
        r"\bPath\s*\([^)]*\)\.resolve\s*\(",
    ],
    "basename_only": [
        r"\bos\.path\.basename\s*\(",
    ],
    "allowlist_file": [
        r"\bALLOWED_(?:EXTENSIONS|FILES|PATHS)\b",
    ],
    "url_allowlist": [
        r"\bALLOWED_(?:HOSTS|URLS|DOMAINS)\b",
    ],
    "ip_block_private": [
        r"\bip_address\s*\([^)]*\)\.is_private\b",
        r"\b10\.\s*\.\s*",
        r"\b127\.0\.0\.1\b",
    ],
    "scheme_check": [
        r"urlparse\s*\([^)]+\)\.scheme",
        r"\.startswith\s*\(\s*['\"]https?",
    ],
    "same_origin_check": [
        r"\burlparse\s*\([^)]+\)\.netloc\s*==",
    ],
    "schema_validate": [
        r"\bpydantic\.BaseModel\b",
        r"\bjsonschema\.validate\s*\(",
        r"\bvalidator\s*\(",
        r"\bjoi\.validate\s*\(",
    ],
    "regex_validate": [
        r"\bre\.(?:match|fullmatch)\s*\(",
    ],
    "length_check": [
        r"\blen\s*\([^)]+\)\s*[<>]=?",
    ],
    "mime_check": [
        r"\.content_type\b",
        r"\bmagic\.from_buffer\s*\(",
    ],
    "extension_allowlist": [
        r"\bALLOWED_EXTENSIONS\b",
        r"\.endswith\s*\(\s*['\"]\.",
    ],
    "size_limit": [
        r"\bMAX_(?:CONTENT|UPLOAD)_(?:LENGTH|SIZE)\b",
        r"\.content_length\b",
    ],
    "defusedxml": [
        r"\bdefusedxml\b",
    ],
    "disable_entity_loader": [
        r"resolve_entities\s*=\s*False",
        r"setFeature\s*\(\s*['\"]http://apache.org/xml/features/disallow-doctype-decl['\"]",
    ],
    "safe_loader": [
        r"\byaml\.safe_load\s*\(",
        r"\bjson\.loads?\s*\(",
        r"\bpickle\.loads\s*\([^)]*restricted",
    ],
    "signed_token": [
        r"\bitsdangerous\b",
        r"\bjwt\.decode\s*\(",
    ],
    "mask_pii": [
        r"\bredact\w*\s*\(",
        r"\bmask\w*\s*\(",
    ],
    "tls_required": [
        r"\bSECURE_SSL_REDIRECT\b",
        r"\bstrictTransportSecurity\b",
    ],
    "env_prod_flag": [
        r"\bENV\s*=\s*['\"]production['\"]",
        r"\bDEBUG\s*=\s*False\b",
    ],
    "strong_algo": [
        r"\bhashlib\.sha(?:256|384|512)\s*\(",
        r"\bAES(?:/GCM|-GCM)\b",
        r"\bbcrypt\b",
        r"\bargon2\b",
        r"\bscrypt\b",
    ],
    "env_lookup": [
        r"\bos\.environ\.get\s*\(",
        r"\bos\.getenv\s*\(",
    ],
    "vault_lookup": [
        r"\bhvac\b",
        r"\bsecretsmanager\b",
        r"\bkeyvault\b",
    ],
}


# --------------------------------------------------------------------------- #
# Access controls
# --------------------------------------------------------------------------- #
CONTROLS: Dict[str, List[str]] = {
    "login_required": [
        r"@login_required\b",
        r"@permission_required\s*\(",
        r"@require_http_methods\s*\(",
        r"@jwt_required\b",
        r"\bisAuthenticated\s*\(",
        r"\bpassport\.authenticate\s*\(",
    ],
    "ownership_check": [
        r"if\s+[\w\.]+\.(?:user|owner|author)_id\s*==\s*",
        r"if\s+[\w\.]+\.user\s*==\s*request\.user\b",
        r"\.filter\s*\(\s*(?:user|owner)\s*=\s*request\.user\b",
    ],
    "csrf_protection": [
        r"\{%\s*csrf_token\s*%\}",
        r"@csrf\.exempt\b",
        r"\bcsrf_protect\b",
        r"\bCSRFProtect\s*\(",
        r"\bcsurf\s*\(",
        r"\bSameSite\s*=\s*['\"]?(?:Strict|Lax)['\"]?",
    ],
    "password_hashing": [
        r"\bbcrypt\.(?:hashpw|checkpw)\s*\(",
        r"\bargon2\.PasswordHasher\s*\(",
        r"\bpbkdf2_hmac\s*\(",
        r"\bmake_password\s*\(",
        r"\bcheck_password\s*\(",
    ],
    "session_secure": [
        r"\bSESSION_COOKIE_SECURE\s*=\s*True\b",
        r"\bsession\.secure\s*=\s*True\b",
    ],
    "session_httponly": [
        r"\bSESSION_COOKIE_HTTPONLY\s*=\s*True\b",
        r"\bhttpOnly\s*:\s*true\b",
    ],
    "session_samesite": [
        r"\bSESSION_COOKIE_SAMESITE\s*=\s*['\"](?:Strict|Lax)['\"]",
        r"\bsameSite\s*:\s*['\"]?(?:strict|lax)['\"]?",
    ],
    "jwt_verify": [
        r"\bjwt\.decode\s*\([^)]*verify\s*=\s*True",
        r"\bjwt\.decode\s*\([^)]*algorithms\s*=",
    ],
    "jwt_algorithm_pinned": [
        r"algorithms\s*=\s*\[\s*['\"](?:RS256|HS256|ES256)['\"]",
    ],
    "cors_origin_allowlist": [
        r"\bCORS\s*\([^)]*origins\s*=\s*\[",
        r"\bAccess-Control-Allow-Origin\b.*\bhttps?://",
    ],
    "cors_credentials_scoped": [
        r"\bAccess-Control-Allow-Credentials\s*:\s*true\b",
        r"\bsupports_credentials\s*=\s*True\b",
    ],
}


# --------------------------------------------------------------------------- #
# Simple heuristics for config / secrets / crypto / logging families
# --------------------------------------------------------------------------- #
CONFIG_AUDIT: Dict[str, List[str]] = {
    "debug_enabled": [
        r"\bDEBUG\s*=\s*True\b",
        r"\bapp\.debug\s*=\s*True\b",
        r"\bFLASK_DEBUG\s*=\s*1\b",
    ],
    "open_cors": [
        r"\bAccess-Control-Allow-Origin\s*:\s*\*",
        r"\bCORS\s*\([^)]*origins\s*=\s*['\"]\*['\"]",
    ],
    "insecure_cookie": [
        r"\bSESSION_COOKIE_SECURE\s*=\s*False\b",
    ],
    "tls_disabled": [
        r"\bverify\s*=\s*False\b",
        r"\bSSL_VERIFY\s*=\s*False\b",
    ],
}


SECRETS_PATTERNS: Dict[str, List[str]] = {
    "aws_access_key": [r"\bAKIA[0-9A-Z]{16}\b"],
    "generic_api_key": [
        r"(?i)\b(?:api[_-]?key|apikey|secret|token)\s*[:=]\s*['\"][A-Za-z0-9/+=_\-]{16,}['\"]"
    ],
    "private_key": [r"-----BEGIN [A-Z ]{0,40}KEY-----"],
    "bearer_literal": [r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}"],
}


CRYPTO_PATTERNS: Dict[str, List[str]] = {
    "weak_hash_md5": [r"\bhashlib\.md5\s*\("],
    "weak_hash_sha1": [r"\bhashlib\.sha1\s*\("],
    "weak_cipher_des": [r"\bDES\.new\s*\("],
    "weak_cipher_rc4": [r"\bARC4\.new\s*\("],
    "ecb_mode": [r"\bMODE_ECB\b", r"\b/ECB/\b"],
    "hardcoded_iv": [r"\biv\s*=\s*b?['\"][^'\"]{4,}['\"]"],
}


# Match both bare ``log(...)`` / ``print(...)`` calls and chained variants such
# as ``logging.info(...)`` / ``logger.debug(...)`` / ``console.error(...)``.
_LOG_CALL_PREFIX = (
    r"\b(?:log(?:ger|ging)?|print|console)"
    r"(?:\.(?:debug|info|warning|error|critical|exception|log|warn))?\s*\("
)

LOG_SENSITIVE_PATTERNS: Dict[str, List[str]] = {
    "logged_password": [
        _LOG_CALL_PREFIX + r"[^)]*(?:password|passwd|pwd)",
    ],
    "logged_token": [
        _LOG_CALL_PREFIX + r"[^)]*(?:token|secret|api[_-]?key)",
    ],
    "logged_card": [
        _LOG_CALL_PREFIX + r"[^)]*(?:credit_?card|cc_?num|cvv)",
    ],
}


def all_pattern_groups() -> Dict[str, Dict[str, List[str]]]:
    """Return every pattern registry keyed by logical name (for diagnostics)."""
    return {
        "entry_points": {k: [p for p, _ in v] for k, v in ENTRY_POINTS.items()},
        "sources": SOURCES,
        "sinks": SINKS,
        "mitigations": MITIGATIONS,
        "controls": CONTROLS,
        "config_audit": CONFIG_AUDIT,
        "secrets": SECRETS_PATTERNS,
        "crypto": CRYPTO_PATTERNS,
        "log_sensitive": LOG_SENSITIVE_PATTERNS,
    }


__all__ = [
    "CONFIG_AUDIT",
    "CONTROLS",
    "CRYPTO_PATTERNS",
    "ENTRY_POINTS",
    "LOG_SENSITIVE_PATTERNS",
    "MITIGATIONS",
    "PATTERNS_VERSION",
    "SECRETS_PATTERNS",
    "SINKS",
    "SOURCES",
    "all_pattern_groups",
]
