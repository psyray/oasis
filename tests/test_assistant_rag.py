"""Tests for dashboard assistant embedding-cache retrieval."""

import unittest

from oasis.helpers.assistant_rag import retrieve_relevant_snippets


class TestAssistantRag(unittest.TestCase):
    def test_empty_scored_returns_immediately(self):
        code_base = {
            "f.py": {"embedding": [float("nan")], "content": "body"},
        }
        out = retrieve_relevant_snippets(
            code_base=code_base,
            report_file_paths=["f.py"],
            query_embedding=[1.0],
            top_k=3,
        )
        self.assertEqual(out, "")

    def test_invalid_query_embedding(self):
        out = retrieve_relevant_snippets(
            code_base={"f.py": {"embedding": [1.0, 0.0], "content": "ok"}},
            report_file_paths=["f.py"],
            query_embedding=[float("nan"), 0.0],
        )
        self.assertEqual(out, "")

    def test_oversized_vector_norm_skipped(self):
        huge = [1e13, 0.0, 0.0]
        out = retrieve_relevant_snippets(
            code_base={"x": {"embedding": huge, "content": "nope"}},
            report_file_paths=["x"],
            query_embedding=[1.0, 0.0, 0.0],
        )
        self.assertEqual(out, "")

    def test_dimension_mismatch_skipped(self):
        out = retrieve_relevant_snippets(
            code_base={"x": {"embedding": [1.0], "content": "a"}},
            report_file_paths=["x"],
            query_embedding=[1.0, 0.0],
        )
        self.assertEqual(out, "")

    def test_retrieves_snippet(self):
        code_base = {
            "src/a.js": {
                "embedding": [1.0, 0.0, 0.0],
                "content": "function foo() {}",
            },
        }
        out = retrieve_relevant_snippets(
            code_base=code_base,
            report_file_paths=["src/a.js"],
            query_embedding=[1.0, 0.0, 0.0],
            top_k=2,
        )
        self.assertIn("src/a.js", out)
        self.assertIn("function foo()", out)
        self.assertTrue(any(c.isdigit() for c in out))


if __name__ == "__main__":
    unittest.main()
