"""Pure-function tests for embedding helpers (no Ollama / network)."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

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

    def test_generate_content_embedding_retries_with_smaller_chunks_on_context_error(self):
        class FakeClient:
            def __init__(self):
                self.calls = []

            def embeddings(self, model, prompt):
                self.calls.append(prompt)
                if len(prompt) > 512:
                    raise RuntimeError("the input length exceeds the context length (status code: 500)")
                return {"embedding": [1.0, 2.0]}

        fake_client = FakeClient()
        fake_manager = SimpleNamespace(get_client=lambda: fake_client)
        large_content = "a" * 600

        embedding = generate_content_embedding(
            large_content,
            "embed-model",
            chunk_size=1024,
            ollama_manager=fake_manager,
        )

        self.assertEqual(embedding, [1.0, 2.0])
        self.assertGreaterEqual(len(fake_client.calls), 2)

    def test_generate_content_embedding_retries_on_alternate_context_error_message(self):
        """Alternate provider wording (e.g. 'too many tokens') still triggers chunked retry."""

        class FakeClient:
            def __init__(self):
                self.calls = []

            def embeddings(self, model, prompt):
                self.calls.append(prompt)
                if len(prompt) > 512:
                    raise RuntimeError("model runner: too many tokens in prompt")
                return {"embedding": [1.0, 2.0]}

        fake_client = FakeClient()
        fake_manager = SimpleNamespace(get_client=lambda: fake_client)
        large_content = "a" * 600

        embedding = generate_content_embedding(
            large_content,
            "embed-model",
            chunk_size=1024,
            ollama_manager=fake_manager,
        )

        self.assertEqual(embedding, [1.0, 2.0])
        self.assertGreaterEqual(len(fake_client.calls), 2)

    def test_generate_content_embedding_chunk_aggregation_single_average(self):
        class FakeClient:
            def embeddings(self, model, prompt):
                if prompt == "aaaa":
                    return {"embedding": [2.0, 4.0]}
                if prompt == "bbbb":
                    return {"embedding": [6.0, 8.0]}
                return {"embedding": [0.0, 0.0]}

        fake_manager = SimpleNamespace(get_client=lambda: FakeClient())
        content = "aaaa\nbbbb"

        embedding = generate_content_embedding(
            content,
            "embed-model",
            chunk_size=5,
            ollama_manager=fake_manager,
        )

        self.assertEqual(embedding, [4.0, 6.0])

    def test_generate_content_embedding_chunk_aggregation_skips_empty_embeddings(self):
        class FakeClient:
            def embeddings(self, model, prompt):
                if prompt == "aaaa":
                    return {"embedding": [2.0, 4.0]}
                if prompt == "bbbb":
                    return {"embedding": []}
                return {"embedding": [0.0, 0.0]}

        fake_manager = SimpleNamespace(get_client=lambda: FakeClient())
        content = "aaaa\nbbbb"

        embedding = generate_content_embedding(
            content,
            "embed-model",
            chunk_size=5,
            ollama_manager=fake_manager,
        )

        self.assertEqual(embedding, [2.0, 4.0])

    def test_generate_content_embedding_chunk_aggregation_skips_mismatched_dimensions(self):
        class FakeClient:
            def embeddings(self, model, prompt):
                if prompt == "aaaa":
                    return {"embedding": [1.0, 3.0]}
                if prompt == "bbbb":
                    return {"embedding": [2.0, 4.0, 6.0]}
                if prompt == "cccc":
                    return {"embedding": [3.0, 5.0]}
                return {"embedding": [0.0, 0.0]}

        fake_manager = SimpleNamespace(get_client=lambda: FakeClient())
        content = "aaaa\nbbbb\ncccc"

        embedding = generate_content_embedding(
            content,
            "embed-model",
            chunk_size=5,
            ollama_manager=fake_manager,
        )

        self.assertIsNone(embedding)

    def test_generate_content_embedding_uses_configurable_fallback_min_chunk_size(self):
        class FakeClient:
            def __init__(self):
                self.calls = []

            def embeddings(self, model, prompt):
                self.calls.append(prompt)
                if len(prompt) > 220:
                    raise RuntimeError("the input length exceeds the context length (status code: 500)")
                return {"embedding": [1.0, 2.0]}

        fake_client = FakeClient()
        fake_manager = SimpleNamespace(get_client=lambda: fake_client)
        content = "a" * 280

        with patch("oasis.embedding.EMBEDDING_FALLBACK_MIN_CHUNK_SIZE", 192):
            embedding = generate_content_embedding(
                content,
                "embed-model",
                chunk_size=300,
                ollama_manager=fake_manager,
            )

        self.assertEqual(embedding, [1.0, 2.0])
        self.assertEqual(len(fake_client.calls[1]), 192)


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


@unittest.skipIf(EmbeddingAnalyzer is None, "oasis.analyze dependencies are unavailable")
class TestEmbeddingSilentProgress(unittest.TestCase):
    def test_embedding_analyzer_parallel_progress_is_disabled_in_silent_mode(self):
        analyzer = EmbeddingAnalyzer.__new__(EmbeddingAnalyzer)
        analyzer.silent = True

        class DummyTqdm:
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs
                self.n = 0

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def update(self, inc):
                self.n += inc

        class DummyPool:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def imap(self, _fn, _iterable):
                return iter([{"item_id": "f.py", "similarity_score": 0.9}])

        with patch("oasis.analyze.tqdm", side_effect=DummyTqdm) as tqdm_mock, patch(
            "oasis.analyze.Pool", side_effect=DummyPool
        ), patch("oasis.analyze.cpu_count", return_value=1):
            out = analyzer._execute_parallel_analysis([object()])

        self.assertEqual(len(out), 1)
        self.assertTrue(tqdm_mock.call_args.kwargs.get("disable"))

    def test_embedding_manager_progress_is_disabled_in_silent_mode(self):
        from oasis.embedding import EmbeddingManager

        manager = EmbeddingManager.__new__(EmbeddingManager)
        manager.analyze_by_function = False
        manager.embedding_model = "embed-model"
        manager.chunk_size = 128
        manager.ollama_manager = SimpleNamespace(api_url="http://localhost:11434")
        manager.code_base = {}
        manager.silent = True
        manager.save_cache = MagicMock()

        class DummyTqdm:
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs
                self.n = 0

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def update(self, inc):
                self.n += inc

        class DummyPool:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def imap_unordered(self, _fn, _iterable):
                return iter(
                    [
                        (
                            "f.py",
                            "print('ok')",
                            [0.1, 0.2],
                            False,
                            None,
                        )
                    ]
                )

        with patch("oasis.embedding.tqdm", side_effect=DummyTqdm) as tqdm_mock, patch(
            "oasis.embedding.Pool", side_effect=DummyPool
        ), patch("oasis.embedding.cpu_count", return_value=1):
            manager.index_code_files([Path("f.py")])

        self.assertTrue(tqdm_mock.call_args.kwargs.get("disable"))
        self.assertIn("f.py", manager.code_base)
        manager.save_cache.assert_called_once()


if __name__ == "__main__":
    unittest.main()
