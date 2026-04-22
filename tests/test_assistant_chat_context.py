"""Unit tests for verdict-first assistant prompt assembly and context budget."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from oasis.helpers.assistant.prompt.chat_context import (
    FINDING_VALIDATION_LABEL,
    REPORT_SUMMARY_LABEL,
    RETRIEVAL_CONTEXT_LABEL,
    SELECTED_FINDING_LABEL,
    USER_NOTES_LABEL,
    assemble_verdict_first_prompt,
    compact_validation_for_chat,
    compute_verdict_first_subbudgets,
)
from oasis.helpers.assistant.verdict.verdict_validation import _fit_validation_to_budget
from oasis.helpers.assistant.prompt.context_budget import (
    assistant_total_system_budget_chars,
)
from oasis.helpers.assistant.prompt.report_excerpt import compact_report_excerpt


class AssembleVerdictFirstPromptTests(unittest.TestCase):
    INTRO = "SYSTEM INTRO.\n"
    VALIDATION = {
        "status": "confirmed_exploitable",
        "confidence": 0.85,
        "summary": "The controls are missing.",
    }
    SELECTED = '{"file_path": "a.py", "findings": []}'
    RAG = "--- snippet from file a.py ---\nprint('rag')\n"
    SUMMARY = "# REPORT SUMMARY\n- Title: t\n"
    LABELS = "User considers this an auth bypass."

    def _assemble(self, total_budget: int, **overrides):
        kwargs = {
            "system_intro": self.INTRO,
            "finding_validation": self.VALIDATION,
            "selected_finding_json": self.SELECTED,
            "rag_block": self.RAG,
            "report_summary": self.SUMMARY,
            "user_labels": self.LABELS,
            "total_budget": total_budget,
        } | overrides
        return assemble_verdict_first_prompt(**kwargs)

    def test_verdict_precedes_selected_finding_and_summary(self):
        body, lengths = self._assemble(total_budget=100_000)
        idx_validation = body.index(FINDING_VALIDATION_LABEL)
        idx_selected = body.index(SELECTED_FINDING_LABEL)
        idx_rag = body.index(RETRIEVAL_CONTEXT_LABEL)
        idx_summary = body.index(REPORT_SUMMARY_LABEL)
        idx_labels = body.index(USER_NOTES_LABEL)

        self.assertTrue(body.startswith(self.INTRO))
        self.assertLess(idx_validation, idx_selected)
        self.assertLess(idx_selected, idx_rag)
        self.assertLess(idx_rag, idx_summary)
        self.assertLess(idx_summary, idx_labels)

        self.assertEqual(lengths["intro"], len(self.INTRO))
        self.assertGreater(lengths["validation"], 0)
        self.assertEqual(lengths["total"], len(body))

    def test_without_validation_marker_absent_but_rest_preserved(self):
        body, lengths = self._assemble(total_budget=100_000, finding_validation=None)
        self.assertNotIn(FINDING_VALIDATION_LABEL, body)
        self.assertIn(SELECTED_FINDING_LABEL, body)
        self.assertEqual(lengths["validation"], 0)

    def test_user_labels_are_dropped_first_when_over_budget(self):
        body, lengths = self._assemble(total_budget=320)
        self.assertIn(FINDING_VALIDATION_LABEL, body)
        self.assertEqual(lengths["user_labels"], 0)

    def test_user_labels_are_truncated_with_marker_when_slightly_over_budget(self):
        """When the overflow is small, labels must shrink with the truncation
        suffix instead of being silently dropped, so the UI/debug logs can see
        that user notes were preserved — partially."""
        long_labels = "U" * 400
        body_without_labels, _ = self._assemble(
            total_budget=10_000,
            user_labels="",
        )
        # Pick a budget that forces an overflow small enough to shrink (not drop):
        # keep enough headroom for the labels section header + a marker remainder.
        total_budget = len(body_without_labels) + 100
        body, lengths = self._assemble(
            total_budget=total_budget,
            user_labels=long_labels,
        )
        self.assertIn(USER_NOTES_LABEL, body)
        self.assertGreater(lengths["user_labels"], 0)
        self.assertLess(lengths["user_labels"], len(long_labels))
        self.assertIn("…(truncated)…", body)
        self.assertLessEqual(lengths["total"], total_budget)

    def test_summary_trimmed_before_rag(self):
        summary = "S" * 2000
        rag = "R" * 2000
        body, lengths = self._assemble(
            total_budget=4100,
            report_summary=summary,
            rag_block=rag,
            user_labels="",
        )
        self.assertIn(FINDING_VALIDATION_LABEL, body)
        self.assertLess(lengths["report_summary"], len(summary))
        self.assertEqual(lengths["rag"], len(rag))

    def test_rag_trimmed_before_selected_finding(self):
        selected = "F" * 1500
        rag = "R" * 1500
        body, lengths = self._assemble(
            total_budget=2800,
            selected_finding_json=selected,
            rag_block=rag,
            report_summary="",
            user_labels="",
        )
        self.assertLess(lengths["rag"], len(rag))
        self.assertEqual(lengths["selected_finding"], len(selected))

    def test_validation_preserves_authoritative_verdict_fields(self):
        """Validation may be *compacted* (or in degenerate cases hard-capped) but
        its authoritative verdict fields (``status``, ``summary``) must survive
        the shrink cascade so the downstream model still receives a usable
        verdict. See the compaction contract documented in
        :func:`assemble_verdict_first_prompt` and :func:`_fit_validation_to_budget`.
        """
        very_long_validation = {"status": "confirmed_exploitable", "summary": "X" * 4000}
        body, lengths = self._assemble(
            total_budget=500,
            finding_validation=very_long_validation,
            selected_finding_json="",
            rag_block="",
            report_summary="",
            user_labels="",
        )
        self.assertIn(FINDING_VALIDATION_LABEL, body)
        self.assertIn("confirmed_exploitable", body)
        self.assertIn("summary", body)
        self.assertGreater(lengths["validation"], 0)
        # Compaction is allowed: the validation block may be smaller than the
        # full JSON dump of ``very_long_validation`` once budget pressure hits.
        # The contract is that key verdict fields remain, not that length is
        # preserved verbatim.
        self.assertLessEqual(lengths["total"], 500)

    def test_hard_cap_cuts_on_section_boundary_not_mid_label(self):
        """When the body still exceeds the budget after every compaction pass,
        the hard-cap must trim at a section-label boundary (or a paragraph
        break) so the resulting prompt never exposes a half label (e.g.
        ``FINDING_VALIDATION_JS…``) or a truncated JSON object to the model.
        """
        bloated_validation = {
            "status": "confirmed_exploitable",
            "summary": "X" * 50_000,
        }
        huge_finding = '{"file_path": "a.py", "details": "' + "d" * 50_000 + '"}'
        body, lengths = self._assemble(
            total_budget=200,
            finding_validation=bloated_validation,
            selected_finding_json=huge_finding,
            rag_block="",
            report_summary="",
            user_labels="",
        )
        self.assertLessEqual(lengths["total"], 200)
        # Every label that remains in the body must be intact; a cut inside a
        # label would leave a stray "FINDING_VALIDATION_JS" (no terminating ":").
        for label in (
            FINDING_VALIDATION_LABEL,
            SELECTED_FINDING_LABEL,
        ):
            idx = body.find(label[:-1])
            if idx >= 0:
                # The label either appears in full or not at all; never partial.
                self.assertEqual(
                    body[idx : idx + len(label)],
                    label,
                    f"Partial label detected near index {idx}: {body[idx:idx + len(label) + 5]!r}",
                )
        self.assertTrue(
            body.rstrip().endswith("…(truncated)…") or body == "",
            f"hard-capped body must end with the canonical suffix, got: {body[-40:]!r}",
        )

    def test_subbudgets_sum_respects_total(self):
        sub = compute_verdict_first_subbudgets(100_000)
        self.assertEqual(sub["selected_finding"], 30_000)
        self.assertEqual(sub["rag"], 25_000)
        self.assertEqual(sub["report_summary"], 15_000)
        self.assertEqual(sub["user_labels"], 5_000)

    def test_huge_validation_does_not_starve_other_sections(self):
        """Regression test — a 200k-char validation must not crowd out finding + RAG.

        This reproduces the production log scenario where an unclipped validation
        (394 entry_points) consumed ~63k tokens and caused attention collapse. The
        chat compaction must keep validation ≤ 50% of the budget and preserve
        room for the selected finding and RAG blocks.
        """
        bloated_validation = {
            "status": "confirmed_exploitable",
            "confidence": 0.85,
            "family": "access",
            "vulnerability_name": "Authentication Issues",
            "summary": "Controls missing.",
            "scope": {"scan_root": "/tmp", "sink_line": 10},
            "entry_points": [
                {
                    "framework": "wpf",
                    "label": "mvvm_command",
                    "citation": {
                        "file_path": f"/long/path/file_{i}.cs",
                        "start_line": i,
                        "end_line": i,
                        "snippet": f"public ICommand Cmd{i} " + ("x" * 500),
                    },
                }
                for i in range(400)
            ],
            "citations": [
                {"file_path": f"/long/path/cite_{i}.cs", "start_line": i}
                for i in range(400)
            ],
            "execution_paths": [],
            "taint_flows": [],
            "mitigations": [],
            "authz_checks": [],
            "control_checks": [
                {"kind": "login_required", "present": False},
                {"kind": "password_hashing", "present": False},
            ],
            "config_findings": [],
            "budget_exhausted": False,
            "errors": [],
            "validation_backend": "graph",
            "schema_version": 4,
        }

        body, lengths = self._assemble(
            total_budget=64_000,
            finding_validation=bloated_validation,
            selected_finding_json="F" * 10_000,
            rag_block="R" * 8_000,
            report_summary="S" * 4_000,
            user_labels="labels",
        )

        self.assertLessEqual(lengths["total"], 64_000)
        self.assertLessEqual(lengths["validation"], 32_000)
        self.assertGreater(lengths["selected_finding"], 0)
        self.assertGreater(lengths["rag"], 0)
        self.assertIn("confirmed_exploitable", body)
        self.assertIn("Authentication Issues", body)
        self.assertIn(FINDING_VALIDATION_LABEL, body)
        self.assertIn(SELECTED_FINDING_LABEL, body)
        self.assertIn(RETRIEVAL_CONTEXT_LABEL, body)
        self.assertNotIn("validation_backend", body)
        self.assertNotIn("schema_version", body)


class CompactValidationForChatTests(unittest.TestCase):
    def _fixture(self):
        return {
            "schema_version": 4,
            "validation_backend": "graph",
            "status": "confirmed_exploitable",
            "confidence": 0.85,
            "family": "access",
            "vulnerability_name": "Authentication Issues",
            "summary": "Controls missing.",
            "scope": {"scan_root": "/tmp"},
            "entry_points": [{"label": f"ep_{i}"} for i in range(30)],
            "citations": [{"file_path": f"/a/{i}.py"} for i in range(30)],
            "execution_paths": [],
            "taint_flows": [],
            "mitigations": [],
            "authz_checks": [],
            "control_checks": [
                {"kind": "login_required", "present": False},
                {"kind": "password_hashing", "present": False},
            ],
            "config_findings": [],
            "budget_exhausted": False,
            "errors": [],
        }

    def test_authoritative_fields_preserved(self):
        out = compact_validation_for_chat(self._fixture())
        for key in ("status", "confidence", "family", "vulnerability_name", "summary", "scope"):
            self.assertIn(key, out)
        self.assertEqual(out["status"], "confirmed_exploitable")

    def test_lists_are_clipped_to_chat_caps(self):
        out = compact_validation_for_chat(self._fixture())
        self.assertLessEqual(len(out["entry_points"]), 9)
        self.assertLessEqual(len(out["citations"]), 11)
        self.assertEqual(out["entry_points"][-1].get("_truncated"), True)
        self.assertEqual(out["citations"][-1].get("_truncated"), True)

    def test_empty_and_redundant_fields_dropped(self):
        out = compact_validation_for_chat(self._fixture())
        self.assertNotIn("execution_paths", out)
        self.assertNotIn("taint_flows", out)
        self.assertNotIn("mitigations", out)
        self.assertNotIn("authz_checks", out)
        self.assertNotIn("config_findings", out)
        self.assertNotIn("errors", out)
        self.assertNotIn("budget_exhausted", out)
        self.assertNotIn("schema_version", out)
        self.assertNotIn("validation_backend", out)

    def test_budget_exhausted_true_is_kept(self):
        src = self._fixture()
        src["budget_exhausted"] = True
        out = compact_validation_for_chat(src)
        self.assertIs(out.get("budget_exhausted"), True)

    def test_errors_non_empty_are_kept(self):
        src = self._fixture()
        src["errors"] = [{"reason": "timeout"}]
        out = compact_validation_for_chat(src)
        self.assertEqual(out.get("errors"), [{"reason": "timeout"}])

    def test_input_not_mutated(self):
        src = self._fixture()
        original_entry_count = len(src["entry_points"])
        compact_validation_for_chat(src)
        self.assertEqual(len(src["entry_points"]), original_entry_count)
        self.assertIn("schema_version", src)

    def test_none_input_returns_none(self):
        self.assertIsNone(compact_validation_for_chat(None))
        self.assertIsNone(compact_validation_for_chat("not-a-dict"))


class FitValidationToBudgetTests(unittest.TestCase):
    def test_evidence_list_keeps_prefix_before_marker_in_drop_pass(self):
        validation = {
            "status": "confirmed_exploitable",
            "summary": "s",
            "errors": [{"id": i} for i in range(8)],
            "debug_rows": [{"id": i} for i in range(8)],
        }
        # Force pass-2 compaction: too small for initial/halved, but enough to
        # retain status+summary and a compacted list representation.
        text, stats = _fit_validation_to_budget(validation, max_chars=140)
        self.assertIn(stats["validation_fit_pass"], {"dropped_lists", "core_only", "hard_cap"})
        # If pass-2 is reached and errors remains, it must keep a qualitative prefix.
        if '"errors":' in text:
            self.assertIn('"errors":[{"id":0},{"id":1},{"id":2},{"_truncated":true', text)

    def test_non_evidence_list_collapses_to_single_marker_in_drop_pass(self):
        validation = {
            "status": "confirmed_exploitable",
            "summary": "s",
            "metrics": [{"m": i} for i in range(8)],
        }
        text, _stats = _fit_validation_to_budget(validation, max_chars=120)
        if '"metrics":' in text:
            self.assertIn('"metrics":[{"_truncated":true,"_omitted_count":', text)


class AssistantTotalSystemBudgetCharsTests(unittest.TestCase):
    CHAT_MODEL = "any-model"

    def test_fallback_when_no_manager(self):
        budget, meta = assistant_total_system_budget_chars(
            fallback_total=42_000,
            ollama_manager=None,
            chat_model=self.CHAT_MODEL,
            approx_message_chars_in_request=100,
        )
        self.assertEqual(budget, 42_000)
        self.assertEqual(meta["source"], "fallback")

    def test_ps_source_takes_priority(self):
        manager = MagicMock()
        manager.get_effective_context_token_count_with_source.return_value = (64_000, "ps")
        budget, meta = assistant_total_system_budget_chars(
            fallback_total=42_000,
            ollama_manager=manager,
            chat_model=self.CHAT_MODEL,
            approx_message_chars_in_request=0,
        )
        self.assertEqual(meta["context_source"], "ps")
        self.assertEqual(meta["context_tokens"], 64_000)
        self.assertEqual(meta["source"], "ollama_context")
        self.assertLessEqual(budget, 256_000)

    def test_clamps_to_maximum(self):
        manager = MagicMock()
        manager.get_effective_context_token_count_with_source.return_value = (500_000, "modelinfo")
        budget, _meta = assistant_total_system_budget_chars(
            fallback_total=42_000,
            ollama_manager=manager,
            chat_model=self.CHAT_MODEL,
            approx_message_chars_in_request=0,
        )
        self.assertEqual(budget, 256_000)


class CompactReportExcerptTests(unittest.TestCase):
    def _payload(self):
        return {
            "report_type": "vulnerability",
            "title": "Auth Issues",
            "generated_at": "2026-04-22",
            "model_name": "chat-q4",
            "vulnerability_name": "Authentication Issues",
            "analysis_root": "/tmp/code",
            "language": "en",
            "stats": {
                "total_findings": 3,
                "high_risk": 1,
                "medium_risk": 1,
                "low_risk": 1,
                "files_analyzed": 2,
            },
            "files": [
                {
                    "file_path": "src/a.py",
                    "chunk_analyses": [
                        {
                            "start_line": 10,
                            "findings": [
                                {"title": "SQL injection", "severity": "High", "snippet_start_line": 12},
                                {"title": "Info leak", "severity": "Low"},
                            ],
                        }
                    ],
                },
                {
                    "file_path": "src/b.py",
                    "chunk_analyses": [
                        {
                            "start_line": 5,
                            "findings": [
                                {"title": "CSRF", "severity": "Medium"},
                            ],
                        }
                    ],
                },
            ],
        }

    def test_contains_essential_header_fields(self):
        text = compact_report_excerpt(self._payload(), max_chars=5000)
        self.assertIn("REPORT SUMMARY", text)
        self.assertIn("Auth Issues", text)
        self.assertIn("Authentication Issues", text)
        self.assertIn("chat-q4", text)

    def test_top_findings_sorted_by_severity(self):
        text = compact_report_excerpt(self._payload(), max_chars=5000)
        idx_high = text.index("SQL injection")
        idx_medium = text.index("CSRF")
        idx_low = text.index("Info leak")
        self.assertLess(idx_high, idx_medium)
        self.assertLess(idx_medium, idx_low)

    def test_budget_is_honored(self):
        text = compact_report_excerpt(self._payload(), max_chars=120)
        self.assertLessEqual(len(text), 120)
        self.assertTrue(text.endswith("…(truncated)…") or len(text) == 120)

    def test_aggregate_summary_branch(self):
        aggregate = {
            "assistant_aggregate": True,
            "included_relative_paths": ["run/json/a.json", "run/json/b.json"],
            "truncated": True,
        }
        text = compact_report_excerpt(aggregate, max_chars=5000)
        self.assertIn("AGGREGATE REPORT SUMMARY", text)
        self.assertIn("run/json/a.json", text)
        self.assertIn("truncated", text)

    def test_empty_budget_returns_empty_string(self):
        self.assertEqual(compact_report_excerpt(self._payload(), max_chars=0), "")

    def test_stats_line_includes_zero_risk_bucket(self):
        """Zero counts must appear in the stats line, not be dropped as falsy."""
        payload = {
            "title": "T",
            "stats": {
                "total_findings": 2,
                "critical_risk": 0,
                "high_risk": 1,
                "medium_risk": 0,
                "low_risk": 1,
                "files_analyzed": 3,
            },
            "files": [],
        }
        text = compact_report_excerpt(payload, max_chars=5000)
        self.assertIn("critical=0", text)
        self.assertIn("medium=0", text)


if __name__ == "__main__":
    unittest.main()
