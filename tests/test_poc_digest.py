"""Tests for PoC-assist digest JSON budgeting (always valid JSON)."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.helpers.poc_digest import (
    build_compact_findings_digest,
    finalize_poc_digest_json,
    pop_last_findings_digest_leaf,
)


class TestPocDigestJson(unittest.TestCase):
    def test_finalize_always_valid_json_and_under_budget(self) -> None:
        all_results = {
            "XSS": [
                {
                    "file_path": "/a.py",
                    "structured_chunks": [{"findings": [{"title": "t" * 300}]}],
                }
            ]
        }
        compact = build_compact_findings_digest(all_results)
        raw = finalize_poc_digest_json(compact, max_chars=1200)
        parsed = json.loads(raw)
        self.assertIn("findings_digest", parsed)
        self.assertLessEqual(len(raw), 1200)

    def test_finalize_envelope_documents_truncation(self) -> None:
        findings = [{"title": "x", "vulnerable_code": "y" * 4000}]
        all_results = {
            "VN": [
                {
                    "file_path": "/f.py",
                    "structured_chunks": [{"findings": findings}],
                }
            ]
        }
        compact = build_compact_findings_digest(all_results)
        raw = finalize_poc_digest_json(compact, max_chars=280)
        parsed = json.loads(raw)
        self.assertTrue(parsed.get("truncated_for_llm_prompt_budget"))

    def test_pop_last_removes_leaf(self) -> None:
        compact: dict = {"VN": [{"file_path": "/a", "chunks": [{"findings": [{"title": "1"}]}]}]}
        self.assertTrue(pop_last_findings_digest_leaf(compact))
        self.assertEqual(compact["VN"][0]["chunks"][0]["findings"], [])


if __name__ == "__main__":
    unittest.main()
