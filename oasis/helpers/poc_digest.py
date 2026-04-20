"""Build and size-limit PoC-assist JSON digests while keeping valid JSON."""

from __future__ import annotations

import copy
import json
from typing import Any, Dict, List


def build_compact_findings_digest(all_results: Dict[str, Any]) -> Dict[str, Any]:
    """Structured summary of ``all_results`` for PoC prompts (nested dicts/lists only)."""
    compact: Dict[str, Any] = {}
    for vuln_name, rows in (all_results or {}).items():
        if not isinstance(rows, list):
            continue
        per_vuln: List[Dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            fp = row.get("file_path") or ""
            chunks = row.get("structured_chunks") or []
            chunk_summaries: List[Dict[str, Any]] = []
            for ch in chunks:
                if not isinstance(ch, dict):
                    continue
                findings = ch.get("findings") or []
                slim_findings: List[Dict[str, Any]] = [
                    {
                        "title": (fn.get("title") or "")[:400],
                        "vulnerable_code": (fn.get("vulnerable_code") or "")[
                            :1200
                        ],
                        "explanation": (fn.get("explanation") or "")[:800],
                        "example_payloads": (fn.get("example_payloads") or [])[
                            :5
                        ],
                        "exploitation_steps": (
                            fn.get("exploitation_steps") or []
                        )[:8],
                        "entry_point": (fn.get("entry_point") or "")[:400],
                    }
                    for fn in findings
                    if isinstance(fn, dict)
                ]
                chunk_summaries.append(
                    {
                        "chunk_lines": [ch.get("start_line"), ch.get("end_line")],
                        "findings": slim_findings,
                    }
                )
            per_vuln.append({"file_path": fp, "chunks": chunk_summaries})
        compact[vuln_name] = per_vuln
    return compact


def pop_last_findings_digest_leaf(compact: Dict[str, Any]) -> bool:
    """
    Remove one leaf finding (or empty container) from the digest tree.

    Returns False when nothing remains to remove.
    """
    if not compact:
        return False
    for vn in sorted(compact.keys(), reverse=True):
        return pop_last_digest_leaf_for_vuln(compact, vn)
    return False


def pop_last_digest_leaf_for_vuln(compact, vn):
    rows = compact.get(vn)
    if not isinstance(rows, list) or not rows:
        del compact[vn]
        return True
    row = rows[-1]
    if not isinstance(row, dict):
        rows.pop()
        return True
    chunks = row.get("chunks") if isinstance(row.get("chunks"), list) else []
    if chunks:
        ch = chunks[-1]
        if isinstance(ch, dict):
            findings = ch.get("findings")
            if isinstance(findings, list) and findings:
                findings.pop()
                return True
        chunks.pop()
        return True
    rows.pop()
    return True


def finalize_poc_digest_json(compact: Dict[str, Any], max_chars: int) -> str:
    """
    Return a JSON string <= ``max_chars`` that is always valid JSON.

    Wraps digest metadata so the LLM knows when rows were dropped for budget reasons.
    """
    trimmed = copy.deepcopy(compact)
    orig_len = len(json.dumps(trimmed, ensure_ascii=False))
    truncated = False

    while len(json.dumps(trimmed, ensure_ascii=False)) > max_chars:
        truncated = True
        if not pop_last_findings_digest_leaf(trimmed):
            trimmed = {}
            break

    envelope: Dict[str, Any] = {
        "truncated_for_llm_prompt_budget": truncated,
        "original_approx_json_chars": orig_len,
        "budget_chars": max_chars,
        "findings_digest": trimmed,
    }
    raw = json.dumps(envelope, ensure_ascii=False)
    if len(raw) <= max_chars:
        return raw

    envelope = {
        "truncated_for_llm_prompt_budget": True,
        "original_approx_json_chars": orig_len,
        "budget_chars": max_chars,
        "note": (
            "Digest still exceeded the JSON character budget after dropping leaf findings; "
            "increase OASIS_POC_DIGEST_JSON_MAX_CHARS if you need more context."
        ),
        "findings_digest": {},
    }
    raw = json.dumps(envelope, ensure_ascii=False)
    if len(raw) <= max_chars:
        return raw
    return json.dumps({"truncated_for_llm_prompt_budget": True, "findings_digest": {}}, ensure_ascii=False)
