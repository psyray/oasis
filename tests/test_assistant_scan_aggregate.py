"""Tests for scan-wide assistant aggregate JSON assembly."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from oasis.helpers.assistant.scan.scan_aggregate import build_aggregate_assistant_document


class TestBuildAggregateAssistantDocument(unittest.TestCase):
    def test_aggregate_respects_total_budget_across_files(self) -> None:
        """Per-segment bodies must sum to no more than the budget minus wrapper estimate."""
        with tempfile.TemporaryDirectory() as td:
            security_root = Path(td)
            json_dir = security_root / "run" / "m" / "json"
            json_dir.mkdir(parents=True)
            large = {"report_type": "vulnerability", "id": "x", "files": []}
            text = json.dumps(large, ensure_ascii=False)
            p1 = json_dir / "a.json"
            p2 = json_dir / "b.json"
            p1.write_text(text, encoding="utf-8")
            p2.write_text(text, encoding="utf-8")

            total_budget = 800
            agg, meta = build_aggregate_assistant_document([p1, p2], security_root, total_char_budget=total_budget)
            segments = agg.get("segments") or []
            wrapper_estimate = 256 + 2 * 64
            content_cap = max(0, total_budget - wrapper_estimate)
            used = sum(len(s.get("payload_json") or "") for s in segments if isinstance(s, dict))
            self.assertLessEqual(used, content_cap)
            self.assertEqual(len(segments), 2)

    def test_aggregate_truncation_suffix_counts_toward_segment_budget(self) -> None:
        """Truncation suffix must not push a single segment past its share of the remaining budget."""
        with tempfile.TemporaryDirectory() as td:
            security_root = Path(td)
            json_dir = security_root / "run" / "m" / "json"
            json_dir.mkdir(parents=True)
            p = json_dir / "only.json"
            p.write_text("x" * 10_000, encoding="utf-8")

            total_budget = 600
            agg, _meta = build_aggregate_assistant_document([p], security_root, total_char_budget=total_budget)
            segments = agg.get("segments") or []
            self.assertEqual(len(segments), 1)
            body = segments[0].get("payload_json") or ""
            wrapper_estimate = 256 + 64
            cap = max(0, total_budget - wrapper_estimate)
            self.assertLessEqual(len(body), cap)
            self.assertIn("truncated", body)


if __name__ == "__main__":
    unittest.main()
