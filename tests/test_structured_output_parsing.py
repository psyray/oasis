"""Tests for structured output normalization and retry behavior."""

import importlib.util
import json
import random
import sys
import unittest
from pathlib import Path

from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from oasis.schemas.analysis import ChunkDeepAnalysis
except ModuleNotFoundError:
    _spec = importlib.util.spec_from_file_location(
        "oasis_schemas_analysis",
        ROOT / "oasis" / "schemas" / "analysis.py",
    )
    _analysis = importlib.util.module_from_spec(_spec)
    assert _spec and _spec.loader is not None
    _spec.loader.exec_module(_analysis)
    ChunkDeepAnalysis = _analysis.ChunkDeepAnalysis

try:
    from oasis.structured_output.deep import (
        apply_normalizer_by_path,
        chunk_deep_normalization_change_samples,
    )
except ImportError:
    apply_normalizer_by_path = None
    chunk_deep_normalization_change_samples = None

try:
    from oasis.structured_output.json_repair import (
        fix_invalid_json_string_escapes,
        scan_open_delimiter_stack_outside_strings,
        strip_code_fences,
    )
except ImportError:
    fix_invalid_json_string_escapes = None
    scan_open_delimiter_stack_outside_strings = None
    strip_code_fences = None

try:
    from oasis.analyze import SecurityAnalyzer, _get_structured_deep_instructions
except ImportError:
    SecurityAnalyzer = None
    _get_structured_deep_instructions = None


@unittest.skipIf(
    strip_code_fences is None,
    "oasis.structured_output.json_repair is unavailable",
)
class TestStripCodeFences(unittest.TestCase):
    def test_strips_outer_fences_only(self):
        raw = '```json\n{"a": 1}\n```\n'
        self.assertEqual(strip_code_fences(raw).strip(), '{"a": 1}')

    def test_preserves_fence_line_inside_json_string_at_line_start(self):
        # Inner `` ``` `` at column 0 after a newline must not be treated as closing fence.
        inner = '{"notes": "line1\n```\nline2"}'
        wrapped = "```json\n" + inner + "\n```"
        out = strip_code_fences(wrapped)
        self.assertIn("```", out)
        self.assertIn("line1", out)
        self.assertIn("line2", out)


@unittest.skipIf(
    scan_open_delimiter_stack_outside_strings is None,
    "oasis.structured_output.json_repair is unavailable",
)
class TestScanOpenDelimiterStack(unittest.TestCase):
    def test_truncated_object_returns_open_brace(self):
        self.assertEqual(scan_open_delimiter_stack_outside_strings('{"a":1'), ["{"])

    def test_balanced_returns_empty_stack(self):
        self.assertEqual(scan_open_delimiter_stack_outside_strings('{"a":1}'), [])

    def test_mismatch_returns_none(self):
        self.assertIsNone(scan_open_delimiter_stack_outside_strings("{]"))

    def test_truncated_inside_string_returns_none(self):
        self.assertIsNone(scan_open_delimiter_stack_outside_strings('{"x":"'))

    def test_nested_brackets_with_closers_inside_string_literals(self):
        # ``]`` and ``}`` inside the string value must not pop the stack; outer object is truncated.
        s = '{"a":[{"b":"x]y"}]'
        self.assertEqual(scan_open_delimiter_stack_outside_strings(s), ["{"])


@unittest.skipIf(
    fix_invalid_json_string_escapes is None,
    "oasis.structured_output.json_repair is unavailable",
)
class TestFixInvalidJsonStringEscapes(unittest.TestCase):
    def test_invalid_escape_doubles_backslash(self):
        raw = r'{"k":"\x"}'
        fixed = fix_invalid_json_string_escapes(raw)
        self.assertEqual(json.loads(fixed)["k"], r"\x")

    def test_valid_unicode_escape_unchanged(self):
        raw = r'{"k":"\u0041"}'
        fixed = fix_invalid_json_string_escapes(raw)
        self.assertEqual(json.loads(fixed)["k"], "A")

    def test_already_escaped_backslash_not_modified(self):
        raw = r'{"k":"\\x"}'
        fixed = fix_invalid_json_string_escapes(raw)
        self.assertEqual(json.loads(fixed)["k"], r"\x")

    def test_invalid_partial_unicode_escape_is_repairable(self):
        raw = r'{"k":"\u12"}'
        fixed = fix_invalid_json_string_escapes(raw)
        parsed = json.loads(fixed)
        self.assertIn("k", parsed)
        self.assertIsInstance(parsed["k"], str)


@unittest.skipIf(
    apply_normalizer_by_path is None,
    "oasis.structured_output.deep is unavailable",
)
class TestWildcardNormalizerPath(unittest.TestCase):
    def test_star_skips_non_dict_list_elements(self):
        payload = {
            "findings": [
                {"tags": ["a", "b"]},
                "not-a-dict",
                {"tags": ["c"]},
            ]
        }

        def _norm(v: list) -> list:
            return v + ["seen"]

        changed = apply_normalizer_by_path(
            payload,
            ("findings", "*", "tags"),
            _norm,
        )
        self.assertTrue(changed)
        self.assertEqual(payload["findings"][0]["tags"], ["a", "b", "seen"])
        self.assertEqual(payload["findings"][1], "not-a-dict")
        self.assertEqual(payload["findings"][2]["tags"], ["c", "seen"])

    def test_star_on_non_list_container_is_no_op(self):
        payload = {"findings": {"0": {"tags": []}}}
        changed = apply_normalizer_by_path(
            payload,
            ("findings", "*", "tags"),
            lambda v: v,
        )
        self.assertFalse(changed)


@unittest.skipIf(
    chunk_deep_normalization_change_samples is None,
    "oasis.structured_output.deep is unavailable",
)
class TestNormalizationChangeSamples(unittest.TestCase):
    def test_reports_before_after_for_changed_finding_field(self):
        before = {
            "findings": [
                {"exploitation_conditions": ["a", "b"], "severity": "Low"},
            ]
        }
        after = {
            "findings": [
                {"exploitation_conditions": "a; b", "severity": "Low"},
            ]
        }
        samples = chunk_deep_normalization_change_samples(before, after, max_items=5)
        cond = next(
            s for s in samples if s["path"] == "findings[0].exploitation_conditions"
        )
        self.assertEqual(cond["before"], ["a", "b"])
        self.assertEqual(cond["after"], "a; b")

    def test_multiple_findings_only_changed_fields_included(self):
        before = {
            "findings": [
                {
                    "exploitation_conditions": ["a", "b"],
                    "severity": "Low",
                    "title": "Finding 1",
                },
                {
                    "exploitation_conditions": ["x"],
                    "severity": "High",
                    "title": "Finding 2",
                },
            ]
        }
        after = {
            "findings": [
                {
                    "exploitation_conditions": "a; b",
                    "severity": "Low",
                    "title": "Finding 1",
                },
                {
                    "exploitation_conditions": ["x"],
                    "severity": "Critical",
                    "title": "Finding 2",
                },
            ]
        }

        samples = chunk_deep_normalization_change_samples(before, after, max_items=10)
        paths = {s["path"] for s in samples}
        expected_changed_paths = {
            "findings[0].exploitation_conditions",
            "findings[1].severity",
        }
        self.assertEqual(paths, expected_changed_paths)

        cond_0 = next(
            s for s in samples if s["path"] == "findings[0].exploitation_conditions"
        )
        self.assertEqual(cond_0["before"], ["a", "b"])
        self.assertEqual(cond_0["after"], "a; b")

        sev_1 = next(s for s in samples if s["path"] == "findings[1].severity")
        self.assertEqual(sev_1["before"], "High")
        self.assertEqual(sev_1["after"], "Critical")


@unittest.skipIf(SecurityAnalyzer is None, "oasis.analyze dependencies are unavailable")
class TestStructuredOutputParsing(unittest.TestCase):
    def test_parse_normalizes_exploitation_conditions_list(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        raw = json.dumps(
            {
                "findings": [
                    {
                        "title": "SQL interpolation",
                        "vulnerable_code": "query = f\"SELECT * FROM users WHERE id={user_id}\"",
                        "explanation": "Input reaches SQL query without parameterization.",
                        "severity": "High",
                        "impact": "Data leakage",
                        "entry_point": "GET /users",
                        "exploitation_conditions": [
                            "Attacker can reach endpoint",
                            "Input is unsanitized",
                        ],
                    }
                ]
            }
        )

        normalized = analyzer._parse_structured_output_response(
            raw=raw,
            response_model=ChunkDeepAnalysis,
            model_display="test-model",
        )
        parsed = json.loads(normalized)
        self.assertEqual(
            parsed["findings"][0]["exploitation_conditions"],
            "Attacker can reach endpoint; Input is unsanitized",
        )

    def test_retryable_error_detects_known_string_type_mismatch(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        with self.assertRaises(ValidationError) as ctx:
            ChunkDeepAnalysis.model_validate(
                {
                    "findings": [
                        {
                            "vulnerable_code": "a",
                            "explanation": "b",
                            "severity": "Low",
                            "exploitation_conditions": ["bad"],
                        }
                    ]
                }
            )
        self.assertTrue(analyzer._is_retryable_structured_error(ChunkDeepAnalysis, ctx.exception))

    def test_retryable_error_ignores_non_exploitation_conditions_errors(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        with self.assertRaises(ValidationError) as ctx:
            ChunkDeepAnalysis.model_validate(
                {
                    "findings": [
                        {
                            "vulnerable_code": "a",
                            "explanation": "b",
                            "severity": "NotAValidSeverity",
                            "exploitation_conditions": (
                                "Attacker can reach endpoint; Input is unsanitized"
                            ),
                        }
                    ]
                }
            )
        self.assertFalse(
            analyzer._is_retryable_structured_error(ChunkDeepAnalysis, ctx.exception)
        )

    def test_deep_prompt_contains_type_guardrails_for_conditions(self):
        prompt = _get_structured_deep_instructions("SQL Injection")
        self.assertIn("exploitation_conditions MUST be a single string sentence (not list).", prompt)
        self.assertIn("Valid vs invalid typing examples:", prompt)
        self.assertIn("Escape any `\\\"` characters inside string values", prompt)
        self.assertIn(
            'return a minimal object like {"findings": [], "notes": "Unable to produce confident structured output"',
            prompt,
        )
        self.assertIn(
            "Do NOT include markdown code fences (``` or similar) anywhere inside field values.",
            prompt,
        )

    def test_repair_structured_json_raw_closes_unbalanced_payload(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        raw = (
            '{"findings":[{"title":"X","vulnerable_code":"a","explanation":"b","severity":"Low",'
            '"exploitation_conditions":"c"}'
        )
        repaired = analyzer._repair_structured_json_raw(
            raw=raw,
            response_model=ChunkDeepAnalysis,
            model_display="test-model",
        )
        parsed = ChunkDeepAnalysis.model_validate_json(repaired)
        self.assertEqual(len(parsed.findings), 1)

    def test_repair_structured_json_raw_removes_control_chars(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        raw = '{"findings":[],"notes":"hello\x01world"}'
        repaired = analyzer._repair_structured_json_raw(
            raw=raw,
            response_model=ChunkDeepAnalysis,
            model_display="test-model",
        )
        parsed = ChunkDeepAnalysis.model_validate_json(repaired)
        self.assertIn("helloworld", parsed.notes or "")

    def test_repair_structured_json_raw_uses_minimal_fallback_on_unrecoverable_payload(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        raw = 'garbage-prefix {"findings": [INVALID JSON!!!] missing-quotes-and-braces'
        repaired = analyzer._repair_structured_json_raw(
            raw=raw,
            response_model=ChunkDeepAnalysis,
            model_display="test-model",
        )
        parsed = ChunkDeepAnalysis.model_validate_json(repaired)
        self.assertIsInstance(parsed, ChunkDeepAnalysis)
        self.assertEqual(parsed.findings, [])
        self.assertTrue(parsed.validation_error)
        self.assertTrue(parsed.potential_vulnerabilities)

    def test_repair_structured_json_raw_preserves_valid_json_with_escaped_content(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        raw_payload = {
            "findings": [],
            "notes": 'Contains braces { } and brackets [ ] and comma , and escaped quote \\" and backslash \\\\',
        }
        raw = json.dumps(raw_payload)
        repaired = analyzer._repair_structured_json_raw(
            raw=raw,
            response_model=ChunkDeepAnalysis,
            model_display="test-model",
        )
        parsed = ChunkDeepAnalysis.model_validate_json(repaired)
        self.assertEqual(parsed.notes, raw_payload["notes"])

    def test_repair_structured_json_raw_randomized_notes_are_stable(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        charset = list('abc{}[],: "\\\\\n\t')
        for _ in range(20):
            note = "".join(random.choice(charset) for _ in range(40))
            raw = json.dumps({"findings": [], "notes": note})
            repaired = analyzer._repair_structured_json_raw(
                raw=raw,
                response_model=ChunkDeepAnalysis,
                model_display="test-model",
            )
            parsed = ChunkDeepAnalysis.model_validate_json(repaired)
            self.assertEqual(parsed.notes, note)

    def test_build_safe_minimal_chunk_json_returns_valid_payload(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        broken = '{"findings": [], "notes": "incomplete'
        safe = analyzer._build_safe_minimal_chunk_json(broken)
        self.assertIsNotNone(safe)
        parsed = ChunkDeepAnalysis.model_validate_json(safe)
        self.assertTrue(parsed.validation_error)
        self.assertTrue(parsed.potential_vulnerabilities)

    def test_repair_structured_json_raw_strips_trailing_garbage_after_object(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        core = {"findings": [], "notes": "ok", "validation_error": False}
        raw = json.dumps(core) + "\n\nExtra prose after JSON that breaks json.loads."
        repaired = analyzer._repair_structured_json_raw(
            raw=raw,
            response_model=ChunkDeepAnalysis,
            model_display="test-model",
        )
        parsed = ChunkDeepAnalysis.model_validate_json(repaired)
        self.assertEqual(parsed.notes, "ok")
        self.assertEqual(parsed.findings, [])

    def test_repair_structured_json_raw_fixes_invalid_escapes_in_strings(self):
        analyzer = SecurityAnalyzer.__new__(SecurityAnalyzer)
        # \\x is not a valid JSON escape; model often emits shell/Python-like snippets.
        raw = r'{"findings":[],"notes":"bad \x escape"}'
        repaired = analyzer._repair_structured_json_raw(
            raw=raw,
            response_model=ChunkDeepAnalysis,
            model_display="test-model",
        )
        parsed = ChunkDeepAnalysis.model_validate_json(repaired)
        self.assertEqual(parsed.notes, r"bad \x escape")


if __name__ == "__main__":
    unittest.main()
