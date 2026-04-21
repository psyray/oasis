"""Tests for small path helpers on the report module."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


try:
    from oasis.report import executive_summary_progress_sidecar_path, is_executive_summary_progress_sidecar
except ImportError:
    executive_summary_progress_sidecar_path = None
    is_executive_summary_progress_sidecar = None


@unittest.skipIf(
    executive_summary_progress_sidecar_path is None,
    "oasis.report dependencies are unavailable",
)
class TestReportPathHelpers(unittest.TestCase):
    def test_executive_summary_progress_sidecar_suffix(self):
        base = Path("/runs/m/json/_executive_summary.json")
        sidecar = executive_summary_progress_sidecar_path(base)
        self.assertEqual(sidecar.name, "_executive_summary.progress.json")
        self.assertEqual(sidecar.parent, base.parent)

    def test_is_executive_summary_progress_sidecar_true(self):
        p = Path("/x/json/_executive_summary.progress.json")
        self.assertTrue(is_executive_summary_progress_sidecar(p))

    def test_is_executive_summary_progress_sidecar_false_for_main(self):
        p = Path("/x/json/_executive_summary.json")
        self.assertFalse(is_executive_summary_progress_sidecar(p))


if __name__ == "__main__":
    unittest.main()
