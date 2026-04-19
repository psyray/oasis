"""Tests for CacheManager paths, keys, and scan cache clearing."""

import pickle
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.cache import CacheManager
from oasis.enums import AnalysisMode, AnalysisType
from oasis.schemas.analysis import ANALYSIS_SCHEMA_VERSION


class TestCacheManager(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.mkdtemp()
        self.base = Path(self._td)
        self.proj = self.base / "demo_proj"
        self.proj.mkdir()
        self.target_file = self.proj / "main.py"
        self.target_file.write_text("print('hi')\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self._td, ignore_errors=True)

    def test_get_cache_path_standard_scan(self):
        cm = CacheManager(self.target_file, "MainModel", "ScanModel", cache_days=365)
        p = cm.get_cache_path("nest/main.py", AnalysisMode.SCAN, AnalysisType.STANDARD)
        self.assertEqual(p.parent, cm.standard_cache_dir[AnalysisMode.SCAN])
        self.assertTrue(str(p.name).endswith(".cache"))

    def test_generate_cache_key_includes_schema_version_and_hashes(self):
        cm = CacheManager(self.target_file, "m1", "m2", cache_days=365)
        key = cm.generate_cache_key('print("x")', "prompt text", "SQL Injection")
        self.assertTrue(key.startswith(f"v{ANALYSIS_SCHEMA_VERSION}_"))

    def test_clear_scan_cache_removes_cache_files(self):
        cm = CacheManager(self.target_file, "m1", "m2", cache_days=365)
        scan_dir = cm.standard_cache_dir[AnalysisMode.SCAN]
        dummy = scan_dir / "dummy.cache"
        dummy.write_bytes(pickle.dumps({"payload": True}))

        cm.clear_scan_cache(AnalysisType.STANDARD)

        self.assertFalse(dummy.exists())

    def test_process_cache_save_then_load_roundtrip(self):
        cm = CacheManager(self.target_file, "m1", "m2", cache_days=365)
        fp = "src/module.py"
        payload = {"chunk_key": {"result": "cached"}}
        cm.chunk_cache[AnalysisType.STANDARD][fp] = payload

        cm.process_cache("save", fp, AnalysisMode.DEEP, AnalysisType.STANDARD)

        cm.chunk_cache[AnalysisType.STANDARD] = {}
        loaded = cm.process_cache("load", fp, AnalysisMode.DEEP, AnalysisType.STANDARD)

        self.assertEqual(loaded, payload)


if __name__ == "__main__":
    unittest.main()
