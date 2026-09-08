#!/usr/bin/env python3
"""E2E fixture check: run OASIS against the realistic fixtures with a live LLM backend.

Not part of the unittest suite — it needs a running LLM server (Ollama or any
OpenAI-compatible endpoint). For each fixture language directory it runs the
``oasis`` CLI on a reduced vulnerability set (default: the Injection family —
SQL Injection, Command Injection, Cross-Site Scripting (XSS)), then checks the
canonical JSON reports for the expected detections and scan-time verdicts.

Examples:
    python scripts/e2e_fixture_scan.py \
        --provider openai --api-base https://llm.example.com/v1 \
        --model Qwen/Qwen2.5-Coder-32B-Instruct --embed-model nomic-embed-text

    python scripts/e2e_fixture_scan.py --model qwen2.5-coder:32b --embed-model nomic-embed-text

Exit code is 0 when every expectation passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

DEFAULT_VULNS = [
    "SQL Injection",
    "Command Injection",
    "Cross-Site Scripting (XSS)",
]
DEFAULT_LANGUAGES = ["csharp", "java", "js", "php", "python"]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="E2E check of OASIS detection quality on the realistic fixtures."
    )
    parser.add_argument("--provider", choices=["ollama", "openai"], default="openai")
    parser.add_argument(
        "--api-base", default=None, help="OpenAI-compatible base URL (required with --provider openai)"
    )
    parser.add_argument("--api-key", default=None, help="Optional API key (never logged)")
    parser.add_argument("--model", required=True, help="Deep/scan model id served by the backend")
    parser.add_argument("--embed-model", required=True, help="Embedding model id served by the backend")
    parser.add_argument(
        "--fixtures-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "test_files" / "realistic_app",
    )
    parser.add_argument(
        "--languages",
        nargs="*",
        default=DEFAULT_LANGUAGES,
        help="Fixture subdirectories to scan (default: all)",
    )
    parser.add_argument("--vulns", nargs="*", default=DEFAULT_VULNS)
    parser.add_argument(
        "--timeout", type=int, default=1800, help="Per-language scan timeout in seconds (default: 1800)"
    )
    parser.add_argument(
        "--output-dir", type=Path, default=None, help="Directory holding the run outputs (default: a temp dir)"
    )
    return parser.parse_args()


def build_cli_command(args: argparse.Namespace, fixture_dir: Path) -> List[str]:
    command = [
        "oasis",
        "-i", str(fixture_dir),
        "-m", args.model,
        "-em", args.embed_model,
        "-of", "json",
        "-pn", "e2e-fixtures",
        "--validate-findings",
    ]
    if args.provider == "openai":
        command += ["--provider", "openai"]
        if args.api_base:
            command += ["--api-base", args.api_base]
        if args.api_key:
            command += ["--api-key", args.api_key]
    return command


def run_scan_for_language(args: argparse.Namespace, language: str, run_root: Path) -> Dict[str, Any]:
    """Run one fixture scan; return {"ok": bool, "detail": str}."""
    fixture_dir = args.fixtures_dir / language
    if not fixture_dir.is_dir():
        return {"ok": False, "detail": f"fixture directory missing: {fixture_dir}"}

    workdir = run_root / language
    workdir.mkdir(parents=True, exist_ok=True)
    command = build_cli_command(args, fixture_dir)

    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=args.timeout,
            check=False,
        )
    except FileNotFoundError:
        return {"ok": False, "detail": "oasis CLI not found on PATH (pipx install -e .)"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "detail": f"scan timed out after {args.timeout}s"}
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-5:]
        return {"ok": False, "detail": f"exit {proc.returncode}: {' | '.join(tail)}"}
    return {"ok": True, "detail": f"done in {time.monotonic() - started:.0f}s"}


def collect_results(run_root: Path, languages: List[str], vulns: List[str]) -> List[Dict[str, Any]]:
    """Flatten canonical JSON findings per (language, vulnerability)."""
    collected: List[Dict[str, Any]] = []
    for language in languages:
        language_root = run_root / language
        docs = list(language_root.rglob("json/*.json")) if language_root.is_dir() else []
        per_vuln: Dict[str, Dict[str, Any]] = {
            vuln: {"findings": 0, "statuses": Counter()} for vuln in vulns
        }
        for doc_path in docs:
            try:
                doc = json.loads(doc_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if str(doc.get("report_type") or "") != "vulnerability":
                continue
            vuln_name = str(doc.get("vulnerability_name") or "")
            if vuln_name not in per_vuln:
                continue
            for file_entry in doc.get("files") or []:
                if not isinstance(file_entry, dict):
                    continue
                for chunk in file_entry.get("chunk_analyses") or []:
                    if not isinstance(chunk, dict):
                        continue
                    for finding in chunk.get("findings") or []:
                        if not isinstance(finding, dict):
                            continue
                        per_vuln[vuln_name]["findings"] += 1
                        validation = finding.get("validation")
                        if isinstance(validation, dict):
                            per_vuln[vuln_name]["statuses"][
                                str(validation.get("status") or "?")
                            ] += 1
        for vuln in vulns:
            collected.append({"language": language, "vuln": vuln, **per_vuln[vuln]})
    return collected


def print_report(rows: List[Dict[str, Any]]) -> bool:
    all_pass = True
    print("\n=== E2E fixture check ===")
    print(f"{'language':<10} {'vulnerability':<28} {'findings':>8}  scan-time verdicts")
    for row in rows:
        detected = row["findings"] > 0
        all_pass = all_pass and detected
        status_text = ", ".join(f"{k}x{v}" for k, v in sorted(row["statuses"].items())) or "-"
        marker = "PASS" if detected else "FAIL"
        print(
            f"{row['language']:<10} {row['vuln']:<28} {row['findings']:>8}  {status_text}  [{marker}]"
        )
    print(f"\nResult: {'ALL PASS' if all_pass else 'FAILURES PRESENT'}")
    return all_pass


def main() -> int:
    args = parse_args()
    if args.provider == "openai" and not args.api_base:
        print("--api-base is required with --provider openai", file=sys.stderr)
        return 1
    if args.output_dir:
        run_root = args.output_dir
        run_root.mkdir(parents=True, exist_ok=True)
    else:
        run_root = Path(tempfile.mkdtemp(prefix="oasis-e2e-"))
    print(f"Run outputs: {run_root}")

    scan_errors: List[str] = []
    for language in args.languages:
        print(f"\n--- scanning fixture: {language} ---")
        outcome = run_scan_for_language(args, language, run_root)
        print(f"    {outcome['detail']}")
        if not outcome["ok"]:
            scan_errors.append(f"{language}: {outcome['detail']}")

    rows = collect_results(run_root, args.languages, args.vulns)
    all_pass = print_report(rows)
    if scan_errors:
        print("\nScan errors:")
        for failure in scan_errors:
            print(f"  - {failure}")
        return 1
    print(f"(outputs kept for inspection: {run_root})")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())