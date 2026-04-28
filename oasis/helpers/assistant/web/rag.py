"""
Embedding-cache assisted retrieval for the dashboard assistant (file-level similarity).
"""

from __future__ import annotations

import hashlib
import json
import math
import pickle
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from oasis.helpers.analysis_root_path import resolve_assistant_cache_root
from oasis.tools import calculate_similarity, create_cache_dir, logger, sanitize_name

RAGStats = Dict[str, int]

# Reject obviously corrupted vectors (pickle / API) before numpy in calculate_similarity.
_MAX_L2_NORM = 1e12


def _finite_embedding_vector(seq: Sequence[Any]) -> Optional[list[float]]:
    """Coerce to finite floats; reject empty, zero-norm, or excessive L2 norm."""
    try:
        out = [float(x) for x in seq]
    except (TypeError, ValueError):
        return None
    if not out:
        return None
    for v in out:
        if not math.isfinite(v):
            return None
    sq_sum = 0.0
    for v in out:
        sq_sum += v * v
    if not math.isfinite(sq_sum) or sq_sum <= 0.0:
        return None
    return None if math.sqrt(sq_sum) > _MAX_L2_NORM else out


def embedding_cache_file_path(
    input_path: Path | str,
    embed_model: str,
    project_name: str | None = None,
) -> Path:
    """Same layout as EmbeddingManager._setup_cache."""
    input_path = Path(input_path).resolve()
    cache_dir = create_cache_dir(input_path, project_name=project_name)
    path_id = hashlib.sha1(str(input_path).encode("utf-8")).hexdigest()[:16]
    return cache_dir / f"{path_id}_{sanitize_name(embed_model)}.cache"


def load_embedding_code_base(cache_path: Path) -> Optional[Dict[str, Any]]:
    """Load pickle cache produced by EmbeddingManager; return None on failure."""
    if not cache_path.is_file():
        return None
    try:
        with open(cache_path, "rb") as handle:
            data = pickle.load(handle)
        if isinstance(data, dict):
            return data
    except OSError as exc:
        logger.debug("Embedding cache read failed %s: %s", cache_path, exc)
    return None


def _normalize_report_path_key(path: str) -> str:
    return path.replace("\\", "/")


def _match_cache_key(cache_keys: Sequence[str], report_path: str) -> Optional[str]:
    """Resolve a report file_path to a key in code_base."""
    norm = _normalize_report_path_key(report_path.strip())
    if norm in cache_keys:
        return norm
    for key in cache_keys:
        if _normalize_report_path_key(key).endswith(norm) or norm.endswith(
            _normalize_report_path_key(key)
        ):
            return key
    base = Path(norm).name
    return next(
        (
            key
            for key in cache_keys
            if Path(_normalize_report_path_key(key)).name == base
        ),
        None,
    )


def _merged_unique_paths(
    primary: Sequence[str],
    extra: Optional[Sequence[str]],
) -> List[str]:
    seen: set[str] = set()
    ordered: List[str] = []
    for seq in (primary, extra or []):
        for fp in seq:
            if isinstance(fp, str):
                key = fp.strip()
                if key and key not in seen:
                    seen.add(key)
                    ordered.append(key)
    return ordered


def _publish_rag_stats(stats_out: Optional[RAGStats], stats: RAGStats) -> None:
    """Copy ``stats`` into optional caller-owned dict for observability."""
    if stats_out is not None:
        stats_out.clear()
        stats_out.update(stats)


def _rag_candidate_keys(
    code_base: Dict[str, Any],
    *,
    expand_project_wide: bool,
    report_file_paths: Sequence[str],
    extra_report_file_paths: Optional[Sequence[str]],
) -> List[str]:
    if expand_project_wide:
        return list(code_base.keys())
    cache_keys = list(code_base.keys())
    matched: List[str] = []
    for fp in _merged_unique_paths(report_file_paths, extra_report_file_paths):
        if key := _match_cache_key(cache_keys, fp):
            matched.append(key)
    return matched


def _score_rag_candidates(
    code_base: Dict[str, Any],
    candidates: Sequence[str],
    q_vec: list[float],
    stats: RAGStats,
) -> List[Tuple[float, str]]:
    scored: List[Tuple[float, str]] = []
    for key in candidates:
        entry = code_base.get(key)
        if not isinstance(entry, dict):
            continue
        emb = entry.get("embedding")
        if not isinstance(emb, list) or not emb:
            stats["skipped_invalid_embedding"] += 1
            continue
        emb_vec = _finite_embedding_vector(emb)
        if emb_vec is None:
            stats["skipped_invalid_embedding"] += 1
            continue
        if len(emb_vec) != len(q_vec):
            stats["skipped_dimension_mismatch"] += 1
            continue
        try:
            sim = calculate_similarity(q_vec, emb_vec)
        except Exception:
            stats["skipped_similarity_error"] += 1
            continue
        if not math.isfinite(sim):
            stats["skipped_similarity_error"] += 1
            continue
        scored.append((sim, key))
    return scored


def _maybe_warn_rag_dimension_mismatch(
    scored: Sequence[Tuple[float, str]],
    candidates: Sequence[str],
    stats: RAGStats,
    *,
    cache_path: Optional[Path],
    embed_model: str,
) -> None:
    if (
        scored
        or not candidates
        or stats["skipped_dimension_mismatch"] <= 0
        or stats["query_dimension"] <= 0
    ):
        return
    logger.warning(
        "RAG skipped every cached embedding (%s dimension mismatches vs query_dim=%s); "
        "embedding cache likely built with a different model or schema.",
        stats["skipped_dimension_mismatch"],
        stats["query_dimension"],
        extra={
            "cache_path": str(cache_path) if cache_path else "",
            "embed_model": embed_model or "",
        },
    )


def _format_rag_snippet_blocks(
    code_base: Dict[str, Any],
    scored_sorted: Sequence[Tuple[float, str]],
    *,
    top_k: int,
    max_chars_per_file: int,
) -> List[str]:
    parts: List[str] = []
    for sim, key in scored_sorted[: max(1, top_k)]:
        entry = code_base.get(key)
        if not isinstance(entry, dict):
            continue
        content = entry.get("content")
        if not isinstance(content, str) or not content.strip():
            continue
        body = content.strip()
        if len(body) > max_chars_per_file:
            body = body[: max_chars_per_file] + "\n…(truncated)…"
        parts.append(f"### File: {key} (similarity {sim:.3f})\n```\n{body}\n```")
    return parts


def retrieve_relevant_snippets(
    *,
    code_base: Dict[str, Any],
    report_file_paths: Sequence[str],
    query_embedding: Sequence[float],
    top_k: int = 5,
    max_chars_per_file: int = 6000,
    expand_project_wide: bool = False,
    extra_report_file_paths: Optional[Sequence[str]] = None,
    stats_out: Optional[RAGStats] = None,
    cache_path: Optional[Path] = None,
    embed_model: str = "",
) -> str:
    """
    Rank files by cosine similarity of file-level embedding to query; return text snippets.

    When expand_project_wide is False, only ``report_file_paths`` (plus optional
    ``extra_report_file_paths``) are considered for cache key matching.
    """
    stats: RAGStats = {
        "query_dimension": 0,
        "candidates_considered": 0,
        "skipped_dimension_mismatch": 0,
        "skipped_invalid_embedding": 0,
        "skipped_similarity_error": 0,
        "scored_count": 0,
    }

    if not code_base:
        _publish_rag_stats(stats_out, stats)
        return ""
    q_vec = _finite_embedding_vector(query_embedding)
    if q_vec is None:
        _publish_rag_stats(stats_out, stats)
        return ""
    stats["query_dimension"] = len(q_vec)

    candidates = _rag_candidate_keys(
        code_base,
        expand_project_wide=expand_project_wide,
        report_file_paths=report_file_paths,
        extra_report_file_paths=extra_report_file_paths,
    )
    stats["candidates_considered"] = len(candidates)

    scored = _score_rag_candidates(code_base, candidates, q_vec, stats)
    _maybe_warn_rag_dimension_mismatch(
        scored,
        candidates,
        stats,
        cache_path=cache_path,
        embed_model=embed_model,
    )

    if not scored:
        _publish_rag_stats(stats_out, stats)
        return ""

    scored.sort(key=lambda t: t[0], reverse=True)
    stats["scored_count"] = len(scored)
    parts = _format_rag_snippet_blocks(
        code_base,
        scored,
        top_k=top_k,
        max_chars_per_file=max_chars_per_file,
    )
    _publish_rag_stats(stats_out, stats)
    return "\n\n".join(parts)


def json_finding_slice(
    payload: Dict[str, Any],
    file_index: Optional[int],
    chunk_index: Optional[int],
    finding_index: Optional[int],
    *,
    max_chars: int = 12000,
) -> str:
    """Extract a compact JSON excerpt for assistant context."""
    cap: int = max(0, max_chars)

    try:
        files = payload.get("files") or []
        if file_index is None or file_index < 0 or file_index >= len(files):
            return ""
        fentry = files[file_index]
        chunks = fentry.get("chunk_analyses") or []
        if chunk_index is None or chunk_index < 0 or chunk_index >= len(chunks):
            return ""
        chunk = chunks[chunk_index]
        findings = chunk.get("findings") or []
        if finding_index is None or finding_index < 0 or finding_index >= len(findings):
            return ""
        raw = json.dumps(findings[finding_index], indent=2)
        if cap <= 0:
            return ""
        return raw[:cap] + "\n…(truncated)…" if len(raw) > cap else raw
    except (TypeError, KeyError, ValueError):
        return ""
