from pathlib import Path
from typing import Dict, Optional, Set, Union
from datetime import datetime
import hashlib
import pickle
import tempfile

from .enums import AnalysisMode
from .schemas.analysis import ANALYSIS_SCHEMA_VERSION
from .tools import create_cache_dir, sanitize_name, logger

# In-memory stores: source file path -> stable chunk cache key -> cached analysis text.
ChunkCacheEntries = Dict[str, str]
ChunkCacheTable = Dict[str, ChunkCacheEntries]

_legacy_adaptive_graph_dirs_warned: Set[Path] = set()


def _maybe_warn_legacy_adaptive_graph_cache(model_cache_dir: Path, scan_model_cache_dir: Path) -> None:
    """Log once per distinct path when an old ``graph/adaptive`` directory is still on disk."""
    candidates = (
        model_cache_dir / "graph" / "adaptive",
        scan_model_cache_dir / "graph" / "adaptive",
    )
    for path in candidates:
        if path in _legacy_adaptive_graph_dirs_warned:
            continue
        try:
            if not path.is_dir():
                continue
        except OSError:
            continue
        _legacy_adaptive_graph_dirs_warned.add(path)
        logger.info(
            "Legacy adaptive-analysis cache directory is present and unused by the current LangGraph layout: %s. "
            "Chunk caches are only read from graph/deep and graph/scan; remove this folder manually if you need disk space.",
            path,
        )


class CacheManager:
    """Pickle-backed chunk caches for LangGraph analysis (scan + deep lanes per model)."""

    @staticmethod
    def _atomic_pickle_write(target_path: Path, payload) -> None:
        """Write pickle payload atomically to avoid partial file corruption."""
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=target_path.parent,
            delete=False,
            prefix=f".{target_path.name}.",
            suffix=".tmp",
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
            pickle.dump(payload, tmp_file)
        tmp_path.replace(target_path)

    def __init__(
        self,
        input_path: Union[str, Path],
        llm_model: str,
        scan_model: str,
        cache_days: int,
        project_name: str | None = None,
    ):
        """
        Initialize the cache manager.

        Args:
            input_path: Path to the input being analyzed
            llm_model: Main model name
            scan_model: Scanning model name
            cache_days: Number of days to keep cache files
            project_name: Optional explicit project alias (same source as report naming)
        """
        self.cache_days = cache_days

        self.cache_dir = create_cache_dir(input_path, project_name=project_name)

        self.model_cache_dir = self.cache_dir / sanitize_name(llm_model)
        self.model_cache_dir.mkdir(exist_ok=True)

        if scan_model != llm_model:
            self.scan_model_cache_dir = self.cache_dir / sanitize_name(scan_model)
            self.scan_model_cache_dir.mkdir(exist_ok=True)
        else:
            self.scan_model_cache_dir = self.model_cache_dir

        # LangGraph-only layout: ``.../<model>/graph/deep`` and ``.../<scan_model>/graph/scan``
        self.graph_cache_dir = {
            AnalysisMode.DEEP: self.model_cache_dir / "graph" / "deep",
            AnalysisMode.SCAN: self.scan_model_cache_dir / "graph" / "scan",
        }

        for directory in self.graph_cache_dir.values():
            directory.mkdir(parents=True, exist_ok=True)

        _maybe_warn_legacy_adaptive_graph_cache(self.model_cache_dir, self.scan_model_cache_dir)

        self.chunk_cache: ChunkCacheTable = {}
        self.scan_chunk_cache: ChunkCacheTable = {}

        self._cleanup_marker_file = self.cache_dir / f".schema_cleanup_v{ANALYSIS_SCHEMA_VERSION}.done"
        self._run_schema_cleanup_once()
        self.validate_cache_expiration()

    def _run_schema_cleanup_once(self) -> None:
        """Run schema cleanup once per cache directory/version."""
        if self._cleanup_marker_file.exists():
            return
        self.cleanup_stale_schema_entries()
        try:
            self._cleanup_marker_file.write_text(datetime.now().isoformat(), encoding="utf-8")
        except OSError as exc:
            logger.warning(f"Unable to persist schema cleanup marker {self._cleanup_marker_file}: {exc}")

    def cleanup_stale_schema_entries(self) -> None:
        """Remove stale schema-versioned keys from OASIS cache payloads only."""
        version_prefix = f"v{ANALYSIS_SCHEMA_VERSION}_"
        try:
            removed_keys = 0
            for cache_dir in self.graph_cache_dir.values():
                if not cache_dir.exists():
                    continue
                for cache_file in cache_dir.glob("*.cache"):
                    try:
                        if (datetime.now().timestamp() - cache_file.stat().st_mtime) < 5:
                            continue
                    except OSError:
                        continue
                    try:
                        with open(cache_file, "rb") as cache_handle:
                            payload = pickle.load(cache_handle)
                    except Exception:
                        continue

                    if not isinstance(payload, dict):
                        continue

                    stale_keys = [
                        key
                        for key in payload
                        if isinstance(key, str) and key.startswith("v") and not key.startswith(version_prefix)
                    ]
                    if not stale_keys:
                        continue

                    for stale_key in stale_keys:
                        payload.pop(stale_key, None)
                    removed_keys += len(stale_keys)

                    try:
                        if payload:
                            self._atomic_pickle_write(cache_file, payload)
                        else:
                            cache_file.unlink()
                    except OSError as exc:
                        logger.warning(f"Failed to update stale cache entry {cache_file}: {exc}")
            if removed_keys:
                logger.info(f"Removed {removed_keys} stale cache keys from previous schema versions")
        except Exception as exc:
            logger.warning(f"Error during stale cache cleanup: {exc}")

    def get_cache_path(self, file_path: str, mode: AnalysisMode) -> Path:
        """Path to the on-disk cache file for ``file_path`` and ``mode``."""
        sanitized_file_name = sanitize_name(file_path)
        return self.graph_cache_dir[mode] / f"{sanitized_file_name}.cache"

    def get_cache_dict(self, mode: AnalysisMode) -> ChunkCacheTable:
        """In-memory dict for the given mode (scan vs deep)."""
        return self.scan_chunk_cache if mode == AnalysisMode.SCAN else self.chunk_cache

    def process_cache(self, action: str, file_path: str, mode: AnalysisMode):
        """Load or save the pickle cache for ``file_path``."""
        cache_path = self.get_cache_path(file_path, mode)
        cache_dict = self.get_cache_dict(mode)

        if action == "load":
            if file_path in cache_dict:
                return cache_dict[file_path]

            if not cache_path.exists():
                cache_dict[file_path] = {}
                return {}

            try:
                with open(cache_path, "rb") as f:
                    cache_dict[file_path] = pickle.load(f)
                    logger.debug(
                        "Loaded %s chunk cache for %s: %s entries",
                        mode.value,
                        file_path,
                        len(cache_dict[file_path]),
                    )
                    return cache_dict[file_path]
            except Exception as e:
                logger.exception("Error loading %s chunk cache: %s", mode.value, str(e))
                cache_dict[file_path] = {}
                return {}

        elif action == "save":
            if file_path not in cache_dict:
                return

            try:
                self._atomic_pickle_write(cache_path, cache_dict[file_path])
                logger.debug(
                    "Saved %s chunk cache for %s: %s entries",
                    mode.value,
                    file_path,
                    len(cache_dict[file_path]),
                )
            except Exception as e:
                logger.exception("Error saving %s chunk cache: %s", mode.value, str(e))

    def load_chunk_cache(self, file_path: str, mode: AnalysisMode = AnalysisMode.DEEP) -> ChunkCacheEntries:
        """Load chunk cache for a file."""
        return self.process_cache("load", file_path, mode)

    def save_chunk_cache(self, file_path: str, mode: AnalysisMode = AnalysisMode.DEEP):
        """Persist chunk cache for a file."""
        self.process_cache("save", file_path, mode)

    def has_caching_info(self, file_path: str, chunk: str, vuln_name: str) -> bool:
        """Whether we have enough inputs to key a cache entry."""
        return bool(file_path and chunk and vuln_name)

    def get_cached_analysis(
        self,
        file_path: str,
        chunk: str,
        vuln_name: str,
        prompt: str,
        mode: AnalysisMode = AnalysisMode.DEEP,
    ) -> Optional[str]:
        """Return cached analysis string or None."""
        cache_dict = self.get_cache_dict(mode)
        if file_path not in cache_dict:
            self.load_chunk_cache(file_path, mode)

        chunk_key = self.generate_cache_key(chunk, prompt, vuln_name)
        return cache_dict[file_path].get(chunk_key)

    def store_analysis(
        self,
        file_path: str,
        chunk: str,
        vuln_name: str,
        prompt: str,
        result: str,
        mode: AnalysisMode,
    ):
        """Store analysis result and flush to disk."""
        if not self.has_caching_info(file_path, chunk, vuln_name):
            return

        cache_dict = self.get_cache_dict(mode)
        if file_path not in cache_dict:
            cache_dict[file_path] = {}

        chunk_key = self.generate_cache_key(chunk, prompt, vuln_name)
        cache_dict[file_path][chunk_key] = result

        self.save_chunk_cache(file_path, mode)

    def generate_cache_key(self, chunk: str, prompt: str, vuln_name: str) -> str:
        """Stable key for chunk + prompt + vulnerability name."""
        chunk_hash = hashlib.md5(chunk.encode()).hexdigest()
        prompt_hash = hashlib.md5(prompt.encode()).hexdigest()
        return f"v{ANALYSIS_SCHEMA_VERSION}_{chunk_hash}_{prompt_hash}_{sanitize_name(vuln_name)}"

    def clear_scan_cache(self) -> None:
        """Remove all ``*.cache`` files under graph scan/deep dirs and reset in-memory dicts."""
        try:
            cache_dirs = list(self.graph_cache_dir.values())
            files_count = 0
            for cache_dir in cache_dirs:
                if cache_dir.exists():
                    for cache_file in cache_dir.glob("*.cache"):
                        cache_file.unlink()
                        files_count += 1

            self.chunk_cache.clear()
            self.scan_chunk_cache.clear()

            # Drop schema cleanup markers so the next CacheManager run re-runs key pruning for
            # ANALYSIS_SCHEMA_VERSION instead of trusting a stale marker after on-disk wipes.
            for marker in self.cache_dir.glob(".schema_cleanup_v*.done"):
                try:
                    marker.unlink()
                except OSError as exc:
                    logger.warning(
                        "Unable to remove schema cleanup marker %s after cache clear: %s",
                        marker,
                        exc,
                    )

            logger.info(f"Cleared {files_count} scan cache files")

        except Exception as e:
            logger.exception(f"Error clearing scan cache: {str(e)}")

    def validate_cache_expiration(self):
        """Remove expired ``*.cache`` files based on ``cache_days``."""
        now = datetime.now()
        expired_count = 0

        for cache_dir in self.graph_cache_dir.values():
            try:
                if not cache_dir.exists():
                    continue
            except OSError as exc:
                logger.warning("Could not access cache directory %s: %s", cache_dir, exc)
                continue

            try:
                cache_files = list(cache_dir.glob("*.cache"))
            except OSError as exc:
                logger.warning("Could not list cache files in %s: %s", cache_dir, exc)
                continue

            for cache_file in cache_files:
                try:
                    mod_time = datetime.fromtimestamp(cache_file.stat().st_mtime)
                    cache_age = now - mod_time
                    if cache_age.days > self.cache_days:
                        cache_file.unlink()
                        expired_count += 1
                except (OSError, OverflowError) as exc:
                    logger.warning(
                        "Could not process or remove expired cache file %s: %s",
                        cache_file,
                        exc,
                    )

        if expired_count > 0:
            logger.info(
                "Removed %s expired cache files older than %s days",
                expired_count,
                self.cache_days,
            )
