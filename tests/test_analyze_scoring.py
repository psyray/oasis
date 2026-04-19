"""Unit tests for SecurityAnalyzer embedding similarity paths (no LLM)."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from oasis.analyze import SecurityAnalyzer
except ImportError:
    SecurityAnalyzer = None


@unittest.skipIf(SecurityAnalyzer is None, "oasis.analyze dependencies are unavailable")
class TestSecurityAnalyzerScoring(unittest.TestCase):
    def test_process_functions_appends_when_similarity_meets_threshold(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        results = []
        data = {
            "functions": {
                "fn_a": {"embedding": [1.0, 0.0, 0.0]},
                "fn_b": {"embedding": [0.0, 1.0, 0.0]},
            }
        }
        analyzer._process_functions("f.py", data, [1.0, 0.0, 0.0], 0.9, results)
        self.assertEqual(results, [("fn_a", 1.0)])

    def test_process_functions_skips_missing_embeddings(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        results = []
        data = {"functions": {"fn_a": {}}}
        analyzer._process_functions("f.py", data, [1.0, 0.0], 0.5, results)
        self.assertEqual(results, [])

    def test_process_file_single_vector_branch(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        results = []
        data = {"embedding": [1.0, 0.0]}
        analyzer._process_file("app.py", data, [1.0, 0.0], 0.99, results)
        self.assertEqual(results, [("app.py", 1.0)])

    def test_process_file_chunked_vectors_branch(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        results = []
        data = {"embedding": [[1.0, 0.0], [0.0, 1.0]]}
        analyzer._process_file("chunked.py", data, [1.0, 0.0], 0.99, results)
        self.assertEqual(results, [("chunked.py", 1.0)])

    def test_process_file_below_threshold_no_append(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        results = []
        data = {"embedding": [1.0, 0.0]}
        analyzer._process_file("low.py", data, [0.0, 1.0], 0.99, results)
        self.assertEqual(results, [])


if __name__ == "__main__":
    unittest.main()
