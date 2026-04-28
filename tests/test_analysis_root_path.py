"""Tests for ``analysis_root`` encoding and resolution under ``security_reports``."""

import os
import tempfile
import unittest
from pathlib import Path

from oasis.helpers.analysis_root_path import (
    codebase_access_state,
    encode_analysis_root_for_storage,
    resolve_analysis_root_from_storage,
    resolve_first_existing_scan_root,
)


class TestAnalysisRootPath(unittest.TestCase):
    def test_encode_roundtrip_relative(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td).resolve()
            sec = td_path / "security_reports"
            proj = td_path / "myapp"
            sec.mkdir(parents=True, exist_ok=True)
            proj.mkdir(parents=True, exist_ok=True)
            rel = encode_analysis_root_for_storage(proj, sec)
            resolved = resolve_analysis_root_from_storage(rel, sec)
            self.assertIsNotNone(resolved)
            assert resolved is not None
            self.assertEqual(resolved.resolve(), proj.resolve())

    def test_resolve_absolute_existing(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td).resolve() / "code"
            proj.mkdir()
            sec = Path(td).resolve() / "security_reports"
            sec.mkdir()
            out = resolve_analysis_root_from_storage(str(proj), sec)
            self.assertEqual(out, proj.resolve())

    def test_codebase_access_state_readable(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td).resolve() / "x"
            proj.mkdir()
            sec = Path(td).resolve() / "security_reports"
            sec.mkdir()
            rel = encode_analysis_root_for_storage(proj, sec)
            rp, ok = codebase_access_state(stored_raw=rel, security_reports_root=sec)
            self.assertTrue(ok)
            self.assertIsNotNone(rp)

    def test_resolve_first_existing_prefers_first_good_candidate(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td).resolve() / "src"
            proj.mkdir()
            sec = Path(td).resolve() / "security_reports"
            sec.mkdir()
            rel = encode_analysis_root_for_storage(proj, sec)
            first = resolve_first_existing_scan_root(
                ["/nonexistent/abs/path", rel],
                sec,
            )
            self.assertEqual(first, proj.resolve())

    def test_resolve_relative_rejects_escape_outside_layout_parent(self):
        """Relative analysis_root must not resolve outside the layout parent directory."""
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td).resolve()
            sec = td_path / "security_reports"
            sec.mkdir(parents=True, exist_ok=True)
            # Sibling folder under the same layout parent remains valid.
            outside = td_path / "outside"
            outside.mkdir()
            resolved_out = resolve_analysis_root_from_storage("../outside", sec)
            self.assertIsNotNone(resolved_out)
            assert resolved_out is not None
            self.assertEqual(resolved_out.resolve(), outside.resolve())
            # Crafted relative path to a system dir must not resolve outside td_path.
            try:
                evil_rel = os.path.relpath("/etc", str(sec))
            except ValueError:  # pragma: no cover - same volume on POSIX
                return
            self.assertIsNone(
                resolve_analysis_root_from_storage(evil_rel, sec),
                "resolved path must stay under the layout parent",
            )


if __name__ == "__main__":
    unittest.main()
