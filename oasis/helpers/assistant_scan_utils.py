"""Shared filesystem scanning primitives for assistant validation helpers.

Each validation helper (entry points, mitigations, authz, config audit, ...)
needs to walk a project tree and apply a set of compiled regex patterns. This
module centralises: guarded roots, source-file filtering, size limits, and an
optional ripgrep (``rg``) fast path with a deterministic Python fallback. No
helper here persists state on its own; caches live next to the helper that
uses them.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from oasis.helpers.path_containment import is_path_within_root


# Conservative allow-list: cover the languages documented in vulnerability/.
DEFAULT_EXTENSIONS: Tuple[str, ...] = (
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".java",
    ".kt",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".vb",
    ".razor",
    ".cshtml",
    ".vbhtml",
    ".scala",
    ".rs",
    ".html",
    ".htm",
    ".jinja",
    ".j2",
    ".twig",
    ".ejs",
    ".vue",
    ".svelte",
    ".erb",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".properties",
    ".xml",
)

DEFAULT_IGNORES: Tuple[str, ...] = (
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".oasis_cache",
    "__pycache__",
)

MAX_FILE_BYTES = 1024 * 1024  # 1 MiB — skip generated bundles and large assets
MAX_SCAN_FILES = 5000  # upper bound to keep latency predictable per call


@dataclass(frozen=True)
class PatternMatch:
    """Raw match result emitted by :func:`scan_patterns`."""

    pattern_key: str
    file_path: Path
    line_number: int
    line_text: str


def iter_source_files(
    root: Path,
    *,
    extensions: Sequence[str] = DEFAULT_EXTENSIONS,
    ignores: Sequence[str] = DEFAULT_IGNORES,
    max_files: int = MAX_SCAN_FILES,
) -> Iterator[Path]:
    """Yield source files under *root* respecting containment and size limits."""
    if not root.exists() or not root.is_dir():
        return
    ignore_set = {name.lower() for name in ignores}
    ext_set = {ext.lower() for ext in extensions}
    resolved_root = root.resolve()
    seen = 0
    for current_dir, dir_names, file_names in os.walk(resolved_root):
        dir_names[:] = [d for d in dir_names if d.lower() not in ignore_set]
        current_path = Path(current_dir)
        for name in file_names:
            full_path = current_path / name
            if full_path.suffix.lower() not in ext_set:
                continue
            if not is_path_within_root(full_path, resolved_root):
                continue
            try:
                if full_path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield full_path
            seen += 1
            if seen >= max_files:
                return


def read_text_safely(path: Path) -> Optional[str]:
    """Read *path* as UTF-8 text with replacement, tolerating malformed bytes."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return None


def compile_groups(groups: Dict[str, Sequence[str]]) -> Dict[str, List[re.Pattern[str]]]:
    """Compile a mapping ``{key: [regex, ...]}`` into compiled patterns."""
    compiled: Dict[str, List[re.Pattern[str]]] = {}
    for key, patterns in groups.items():
        compiled[key] = [re.compile(p) for p in patterns]
    return compiled


def scan_patterns(
    root: Path,
    compiled: Dict[str, List[re.Pattern[str]]],
    *,
    extensions: Sequence[str] = DEFAULT_EXTENSIONS,
    max_files: int = MAX_SCAN_FILES,
    max_hits: int = 2000,
) -> List[PatternMatch]:
    """Scan every source file under *root* and return all pattern matches.

    Uses the bundled Python scanner unconditionally; callers that want the
    ripgrep fast path should call :func:`scan_with_ripgrep` directly.
    """
    hits: List[PatternMatch] = []
    for path in iter_source_files(root, extensions=extensions, max_files=max_files):
        text = read_text_safely(path)
        if text is None:
            continue
        for line_index, line in enumerate(text.splitlines(), start=1):
            for key, patterns in compiled.items():
                for pat in patterns:
                    if pat.search(line):
                        hits.append(
                            PatternMatch(
                                pattern_key=key,
                                file_path=path,
                                line_number=line_index,
                                line_text=line.rstrip(),
                            )
                        )
                        if len(hits) >= max_hits:
                            return hits
                        break
    return hits


def ripgrep_available() -> bool:
    """Return True when the ``rg`` executable is available on PATH."""
    return shutil.which("rg") is not None


def scan_with_ripgrep(
    root: Path,
    compiled: Dict[str, List[re.Pattern[str]]],
    *,
    extensions: Sequence[str] = DEFAULT_EXTENSIONS,
    max_hits: int = 2000,
    timeout_sec: float = 10.0,
) -> Optional[List[PatternMatch]]:
    """Try to scan via ripgrep for speed; return None when unavailable/error.

    Uses ``rg --no-heading --line-number --no-config`` with every pattern fed
    as ``-e``. Falls back to returning ``None`` on any failure so callers can
    transparently use :func:`scan_patterns`.
    """
    if not ripgrep_available():
        return None
    if not root.exists() or not root.is_dir():
        return []

    patterns: List[Tuple[str, str]] = []
    for key, pats in compiled.items():
        patterns.extend((key, pat.pattern) for pat in pats)
    if not patterns:
        return []

    cmd: List[str] = [
        "rg",
        "--no-heading",
        "--line-number",
        "--no-config",
        "--color=never",
        "--max-count",
        str(max_hits),
    ]
    for ext in extensions:
        cmd.extend(["-g", f"*{ext}"])
    for pat in patterns:
        cmd.extend(["-e", pat[1]])
    cmd.append(str(root.resolve()))

    try:
        completed = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout_sec,
        )
    except (subprocess.SubprocessError, OSError):
        return None

    hits: List[PatternMatch] = []
    pattern_compiled: List[Tuple[str, re.Pattern[str]]] = [
        (key, re.compile(pat)) for key, pat in patterns
    ]
    resolved_root = root.resolve()
    for raw_line in completed.stdout.decode("utf-8", errors="replace").splitlines():
        parts = raw_line.split(":", 2)
        if len(parts) != 3:
            continue
        file_str, line_str, content = parts
        try:
            line_no = int(line_str)
        except ValueError:
            continue
        file_path = Path(file_str)
        if not is_path_within_root(file_path, resolved_root):
            continue
        for key, pat in pattern_compiled:
            if pat.search(content):
                hits.append(
                    PatternMatch(
                        pattern_key=key,
                        file_path=file_path,
                        line_number=line_no,
                        line_text=content.rstrip(),
                    )
                )
                break
        if len(hits) >= max_hits:
            break
    return hits


def scan_patterns_best_effort(
    root: Path,
    compiled: Dict[str, List[re.Pattern[str]]],
    *,
    extensions: Sequence[str] = DEFAULT_EXTENSIONS,
    max_hits: int = 2000,
) -> List[PatternMatch]:
    """Prefer ripgrep when available; otherwise fall back to the Python scanner."""
    rg_hits = scan_with_ripgrep(root, compiled, extensions=extensions, max_hits=max_hits)
    if rg_hits is not None:
        return rg_hits
    return scan_patterns(root, compiled, extensions=extensions, max_hits=max_hits)


def citation_from_match(match: PatternMatch, *, context: int = 0) -> Dict[str, object]:
    """Build a dict suitable for :class:`oasis.schemas.analysis.Citation`."""
    start = max(1, match.line_number - context)
    end = match.line_number + context
    return {
        "file_path": str(match.file_path),
        "start_line": start,
        "end_line": end,
        "snippet": match.line_text,
    }


def unique_hits(hits: Iterable[PatternMatch]) -> List[PatternMatch]:
    """Deduplicate hits by (pattern_key, file, line)."""
    seen: set[Tuple[str, str, int]] = set()
    out: List[PatternMatch] = []
    for hit in hits:
        key = (hit.pattern_key, str(hit.file_path), hit.line_number)
        if key in seen:
            continue
        seen.add(key)
        out.append(hit)
    return out
