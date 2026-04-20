"""Unit tests for LangGraph vulnerability-type count helpers."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.helpers.langgraph_counts import deep_payload_vuln_types_total, embedding_tasks_vuln_types_total
from oasis.helpers.poc_pipeline import build_poc_hints_markdown


class TestLanggraphCounts(unittest.TestCase):
    def test_embedding_tasks_empty(self):
        self.assertEqual(embedding_tasks_vuln_types_total([]), 1)

    def test_embedding_tasks_distinct_names(self):
        tasks = [
            {"vuln": {"name": "XSS"}, "file_path": "a.cs"},
            {"vuln": {"name": "SQL"}, "file_path": "b.cs"},
            {"vuln": {"name": "XSS"}, "file_path": "c.cs"},
        ]
        self.assertEqual(embedding_tasks_vuln_types_total(tasks), 2)

    def test_embedding_tasks_malformed_still_counts_one(self):
        tasks = [{"file_path": "a.cs"}, {"vuln": "not-a-dict"}]
        self.assertEqual(embedding_tasks_vuln_types_total(tasks), 1)

    def test_deep_payload_non_dict(self):
        self.assertEqual(deep_payload_vuln_types_total(None), 1)

    def test_deep_payload_keys(self):
        self.assertEqual(deep_payload_vuln_types_total({"A": {}, "B": {}}), 2)


class TestPocHintsMarkdown(unittest.TestCase):
    def test_build_poc_hints_markdown_respects_char_cap(self):
        finding = {
            "title": "Some finding title",
            "exploitation_steps": ["Do the thing"],
            "example_payloads": ["<payload>"],
        }
        row = {
            "file_path": "/proj/App.cs",
            "structured_chunks": [{"findings": [finding]}],
        }
        all_results = {"XSS": [row] * 400}
        md = build_poc_hints_markdown(all_results, max_chars=1200)
        self.assertLessEqual(len(md), 1300)


if __name__ == "__main__":
    unittest.main()
