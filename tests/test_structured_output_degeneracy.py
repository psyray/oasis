"""Tests for degenerate structured-output detection."""

import json
import unittest

from oasis.helpers.structured_output_degeneracy import structured_deep_raw_looks_degenerate


class StructuredOutputDegeneracyTests(unittest.TestCase):
    def test_short_input_never_degenerate(self) -> None:
        self.assertFalse(structured_deep_raw_looks_degenerate(""))
        self.assertFalse(structured_deep_raw_looks_degenerate('{"findings":[]}'))

    def test_repeated_substring_flags(self) -> None:
        block = "l'inclusion " * 600
        raw = '{"findings":[{"explanation":"' + block + '"'
        self.assertTrue(structured_deep_raw_looks_degenerate(raw))

    def test_typical_small_json_not_degenerate(self) -> None:
        payload = {
            "findings": [
                {
                    "title": "Example",
                    "explanation": "Short text.",
                    "severity": "Medium",
                }
            ],
            "notes": None,
        }
        raw = json.dumps(payload, ensure_ascii=True)
        self.assertFalse(structured_deep_raw_looks_degenerate(raw))

    def test_high_entropy_json_not_degenerate(self) -> None:
        # Long but varied text should not match zlib threshold or repeat regex.
        varied = json.dumps(
            {
                "findings": [
                    {
                        "title": "t" * 80,
                        "explanation": " ".join(f"word_{i}" for i in range(400)),
                    }
                ]
            },
            ensure_ascii=True,
        )
        self.assertGreater(len(varied), 2000)
        self.assertFalse(structured_deep_raw_looks_degenerate(varied))


if __name__ == "__main__":
    unittest.main()
