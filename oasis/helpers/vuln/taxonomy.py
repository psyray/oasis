"""Vulnerability taxonomy used by the assistant validation agent.

Classifies the 25 OASIS vulnerabilities into three families so each finding is
routed to the most relevant validation helpers (flow-based tainted paths,
access-control/session checks, or config/content audit). Keeps the mapping
small and declarative so new vulnerabilities can be added without changing the
agent code itself.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Tuple


class VulnFamily(str, Enum):
    """Top-level validation strategy for a vulnerability class."""

    FLOW = "flow"
    ACCESS = "access"
    CONFIG = "config"


@dataclass(frozen=True)
class VulnDescriptor:
    """Declarative validator plan for one vulnerability type.

    - ``family``: which set of helpers will be dispatched by the LangGraph.
    - ``sink_kinds``: pattern keys in :data:`oasis.helpers.vuln.validation_patterns.SINKS` that signal
      the vulnerable operation.
    - ``source_kinds``: taint source keys to look for upstream of the sink.
    - ``mitigation_kinds``: mitigation pattern keys that, when present on the
      path, reduce the verdict severity.
    - ``required_controls``: access-control tokens whose absence between the
      entry point and the sink escalates the verdict.
    - ``cwe``: informational CWE identifiers for the report UI.
    """

    family: VulnFamily
    sink_kinds: Tuple[str, ...] = field(default_factory=tuple)
    source_kinds: Tuple[str, ...] = field(default_factory=tuple)
    mitigation_kinds: Tuple[str, ...] = field(default_factory=tuple)
    required_controls: Tuple[str, ...] = field(default_factory=tuple)
    cwe: Tuple[str, ...] = field(default_factory=tuple)
    notes: str = ""


_FLOW_HTTP_SOURCES: Tuple[str, ...] = ("http_params", "http_headers", "http_body")


_REGISTRY: Dict[str, VulnDescriptor] = {
    "SQL Injection": VulnDescriptor(
        family=VulnFamily.FLOW,
        sink_kinds=("sql_execute",),
        source_kinds=_FLOW_HTTP_SOURCES,
        mitigation_kinds=("sql_parameterized", "orm_query", "sql_escape"),
        cwe=("CWE-89",),
    ),
    "Command Injection": VulnDescriptor(
        family=VulnFamily.FLOW,
        sink_kinds=("os_exec", "shell_exec"),
        source_kinds=_FLOW_HTTP_SOURCES,
        mitigation_kinds=("arg_array_exec", "shlex_quote", "allowlist_cmd"),
        cwe=("CWE-77", "CWE-78"),
    ),
    "Remote Code Execution": VulnDescriptor(
        family=VulnFamily.FLOW,
        sink_kinds=("eval_exec", "dynamic_import"),
        source_kinds=_FLOW_HTTP_SOURCES,
        mitigation_kinds=("ast_literal", "allowlist_cmd"),
        cwe=("CWE-94",),
    ),
    "Cross-Site Scripting (XSS)": VulnDescriptor(
        family=VulnFamily.FLOW,
        sink_kinds=("html_render", "innerHTML_write", "template_mark_safe"),
        source_kinds=_FLOW_HTTP_SOURCES,
        mitigation_kinds=("html_escape", "bleach_clean", "autoescape_on"),
        cwe=("CWE-79",),
    ),
    "Path Traversal": VulnDescriptor(
        family=VulnFamily.FLOW,
        sink_kinds=("file_open", "path_join"),
        source_kinds=_FLOW_HTTP_SOURCES,
        mitigation_kinds=("safe_join", "path_normalize", "basename_only"),
        cwe=("CWE-22",),
    ),
    "Local File Inclusion": VulnDescriptor(
        family=VulnFamily.FLOW,
        sink_kinds=("file_include", "file_open"),
        source_kinds=_FLOW_HTTP_SOURCES,
        mitigation_kinds=("safe_join", "allowlist_file", "basename_only"),
        cwe=("CWE-98",),
    ),
    "Remote File Inclusion": VulnDescriptor(
        family=VulnFamily.FLOW,
        sink_kinds=("url_fetch", "file_include"),
        source_kinds=_FLOW_HTTP_SOURCES,
        mitigation_kinds=("url_allowlist", "scheme_check"),
        cwe=("CWE-98",),
    ),
    "Server-Side Request Forgery": VulnDescriptor(
        family=VulnFamily.FLOW,
        sink_kinds=("url_fetch",),
        source_kinds=_FLOW_HTTP_SOURCES,
        mitigation_kinds=("url_allowlist", "ip_block_private", "scheme_check"),
        cwe=("CWE-918",),
    ),
    "Open Redirect": VulnDescriptor(
        family=VulnFamily.FLOW,
        sink_kinds=("redirect_call",),
        source_kinds=_FLOW_HTTP_SOURCES,
        mitigation_kinds=("url_allowlist", "same_origin_check"),
        cwe=("CWE-601",),
    ),
    "Insufficient Input Validation": VulnDescriptor(
        family=VulnFamily.FLOW,
        sink_kinds=(
            "sql_execute",
            "os_exec",
            "file_open",
            "url_fetch",
            "html_render",
        ),
        source_kinds=_FLOW_HTTP_SOURCES,
        mitigation_kinds=("schema_validate", "regex_validate", "length_check"),
        cwe=("CWE-20",),
    ),
    "File Upload Vulnerabilities": VulnDescriptor(
        family=VulnFamily.FLOW,
        sink_kinds=("file_write", "file_open"),
        source_kinds=("http_file_upload",),
        mitigation_kinds=("mime_check", "extension_allowlist", "size_limit"),
        cwe=("CWE-434",),
    ),
    "XML External Entity Injection": VulnDescriptor(
        family=VulnFamily.FLOW,
        sink_kinds=("xml_parse",),
        source_kinds=_FLOW_HTTP_SOURCES,
        mitigation_kinds=("defusedxml", "disable_entity_loader"),
        cwe=("CWE-611",),
    ),
    "Insecure Deserialization": VulnDescriptor(
        family=VulnFamily.FLOW,
        sink_kinds=("deserialize_call",),
        source_kinds=_FLOW_HTTP_SOURCES,
        mitigation_kinds=("safe_loader", "signed_token", "schema_validate"),
        cwe=("CWE-502",),
    ),
    "Insecure Direct Object Reference": VulnDescriptor(
        family=VulnFamily.ACCESS,
        sink_kinds=("db_get_by_id", "object_lookup"),
        source_kinds=_FLOW_HTTP_SOURCES,
        required_controls=("login_required", "ownership_check"),
        cwe=("CWE-639",),
    ),
    "Cross-Site Request Forgery": VulnDescriptor(
        family=VulnFamily.ACCESS,
        sink_kinds=("state_change",),
        required_controls=("csrf_protection",),
        cwe=("CWE-352",),
    ),
    "Authentication Issues": VulnDescriptor(
        family=VulnFamily.ACCESS,
        sink_kinds=("auth_check",),
        required_controls=("login_required", "password_hashing"),
        cwe=("CWE-287",),
    ),
    "Session Management Issues": VulnDescriptor(
        family=VulnFamily.ACCESS,
        required_controls=("session_secure", "session_httponly", "session_samesite"),
        cwe=("CWE-384", "CWE-613"),
    ),
    "JWT Implementation Flaws": VulnDescriptor(
        family=VulnFamily.ACCESS,
        required_controls=("jwt_verify", "jwt_algorithm_pinned"),
        cwe=("CWE-347",),
    ),
    "CORS Misconfiguration": VulnDescriptor(
        family=VulnFamily.ACCESS,
        required_controls=("cors_origin_allowlist", "cors_credentials_scoped"),
        cwe=("CWE-346",),
    ),
    "Security Misconfiguration": VulnDescriptor(
        family=VulnFamily.CONFIG,
        sink_kinds=("config_flag",),
        mitigation_kinds=("env_prod_flag",),
        cwe=("CWE-16",),
    ),
    "Sensitive Data Exposure": VulnDescriptor(
        family=VulnFamily.CONFIG,
        sink_kinds=("http_response", "log_write"),
        mitigation_kinds=("mask_pii", "tls_required"),
        cwe=("CWE-200",),
    ),
    "Debug Information Exposure": VulnDescriptor(
        family=VulnFamily.CONFIG,
        sink_kinds=("debug_flag", "stack_trace_render"),
        mitigation_kinds=("env_prod_flag",),
        cwe=("CWE-489",),
    ),
    "Insecure Cryptographic Usage": VulnDescriptor(
        family=VulnFamily.CONFIG,
        sink_kinds=("crypto_call",),
        mitigation_kinds=("strong_algo",),
        cwe=("CWE-327", "CWE-328"),
    ),
    "Sensitive Data Logging": VulnDescriptor(
        family=VulnFamily.CONFIG,
        sink_kinds=("log_write",),
        mitigation_kinds=("mask_pii",),
        cwe=("CWE-532",),
    ),
    "Hardcoded Secrets": VulnDescriptor(
        family=VulnFamily.CONFIG,
        sink_kinds=("secret_literal",),
        mitigation_kinds=("env_lookup", "vault_lookup"),
        cwe=("CWE-798", "CWE-259"),
    ),
}


ALL_VULN_NAMES: FrozenSet[str] = frozenset(_REGISTRY.keys())


def get_descriptor(vulnerability_name: str) -> Optional[VulnDescriptor]:
    """Return the validator descriptor for a vulnerability display name."""
    if not isinstance(vulnerability_name, str):
        return None
    return _REGISTRY.get(vulnerability_name.strip())


def family_for(vulnerability_name: str) -> Optional[VulnFamily]:
    """Return the family for a vulnerability name, if registered."""
    descriptor = get_descriptor(vulnerability_name)
    return descriptor.family if descriptor else None


def list_by_family(family: VulnFamily) -> List[str]:
    """List vulnerability names registered under *family*."""
    return sorted(name for name, desc in _REGISTRY.items() if desc.family is family)


def descriptors() -> Dict[str, VulnDescriptor]:
    """Return a shallow copy of the descriptor registry (callers should not mutate)."""
    return dict(_REGISTRY)


__all__ = [
    "ALL_VULN_NAMES",
    "VulnDescriptor",
    "VulnFamily",
    "descriptors",
    "family_for",
    "get_descriptor",
    "list_by_family",
]
