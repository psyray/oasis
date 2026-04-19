"""Pure-function tests for embedding helpers (no Ollama / network)."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.config import EMBEDDING_THRESHOLDS
from oasis.embedding import build_vulnerability_embedding_prompt, generate_content_embedding

try:
    from oasis.analyze import EmbeddingAnalyzer
except ImportError:
    EmbeddingAnalyzer = None


class TestEmbeddingPure(unittest.TestCase):
    def test_build_prompt_from_dict_includes_core_fields(self):
        vuln = {
            "name": "SQL Injection",
            "description": "Untrusted input reaches queries.",
            "patterns": ["SELECT", "execute("],
            "impact": "Data breach",
            "mitigation": "Use parameterized queries.",
        }
        prompt = build_vulnerability_embedding_prompt(vuln)
        self.assertIn("SQL Injection", prompt)
        self.assertIn("Untrusted input reaches queries.", prompt)
        self.assertIn("SELECT", prompt)
        self.assertIn("Data breach", prompt)
        self.assertIn("parameterized queries", prompt)

    def test_build_prompt_from_string_is_identity(self):
        self.assertEqual(build_vulnerability_embedding_prompt("XSS"), "XSS")

    def test_generate_content_embedding_requires_manager(self):
        with self.assertRaises(ValueError):
            generate_content_embedding("hello", "model", ollama_manager=None)


@unittest.skipIf(EmbeddingAnalyzer is None, "oasis.analyze dependencies are unavailable")
class TestEmbeddingAnalyzerStats(unittest.TestCase):
    def setUp(self):
        self.analyzer = EmbeddingAnalyzer.__new__(EmbeddingAnalyzer)

    def test_generate_threshold_analysis_empty_results(self):
        self.assertEqual(self.analyzer.generate_threshold_analysis([]), [])

    def test_generate_threshold_analysis_default_thresholds_match_config(self):
        rows = [{"similarity_score": 0.95}, {"similarity_score": 0.25}]
        out = self.analyzer.generate_threshold_analysis(rows)
        self.assertEqual(len(out), len(EMBEDDING_THRESHOLDS))
        self.assertEqual(out[0]["threshold"], EMBEDDING_THRESHOLDS[0])

    def test_generate_threshold_analysis_custom_thresholds(self):
        rows = [{"similarity_score": 0.6}]
        out = self.analyzer.generate_threshold_analysis(rows, thresholds=[0.5, 0.9])
        self.assertEqual(
            out,
            [
                {"threshold": 0.5, "matching_items": 1, "percentage": 100.0},
                {"threshold": 0.9, "matching_items": 0, "percentage": 0.0},
            ],
        )

    def test_calculate_statistics_empty_results(self):
        stats = self.analyzer.calculate_statistics([])
        self.assertEqual(stats["avg_score"], 0)
        self.assertEqual(stats["median_score"], 0)

    def test_calculate_statistics_median_index_not_statistical_median(self):
        """Regression guard: implementation uses sorted(scores)[len//2] (upper-middle for even n)."""
        rows = [
            {"similarity_score": 0.1},
            {"similarity_score": 0.2},
            {"similarity_score": 0.3},
            {"similarity_score": 0.4},
        ]
        stats = self.analyzer.calculate_statistics(rows)
        self.assertEqual(stats["median_score"], 0.3)
        self.assertEqual(stats["count"], 4)


if __name__ == "__main__":
    unittest.main()
