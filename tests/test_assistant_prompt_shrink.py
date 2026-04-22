"""Unit tests for label-boundary hard cap helpers."""

from __future__ import annotations

import logging
import unittest

from oasis.helpers.assistant_prompt_shrink import (
    VerdictPromptHardCapConfig,
    find_safe_cut_boundary,
    hard_cap_verdict_prompt_if_needed,
)


class AssistantPromptShrinkTests(unittest.TestCase):
    def test_find_safe_cut_prefers_label_boundary(self):
        labels = ("FINDING_VALIDATION_JSON:", "REPORT_SUMMARY:")
        body = "HEAD\n\nFINDING_VALIDATION_JSON:\n{}\n\nREPORT_SUMMARY:\n" + "Z" * 30
        sec_start = body.index("\n\nREPORT_SUMMARY:")
        raw_limit = len(body) - 3
        cut = find_safe_cut_boundary(body, raw_limit, labels)
        self.assertEqual(cut, sec_start)

    def test_hard_cap_respects_total_budget(self):
        log = logging.getLogger("test_hard_cap")
        cfg = VerdictPromptHardCapConfig(
            trunc_suffix="\n…(truncated)…",
            section_label_prefixes=("FINDING_VALIDATION_JSON:",),
        )
        long = "A" * 200
        out = hard_cap_verdict_prompt_if_needed(
            long, total_budget=80, validation_len=0, config=cfg, logger=log
        )
        self.assertLessEqual(len(out), 80)
        self.assertTrue(out.endswith("\n…(truncated)…"))


if __name__ == "__main__":
    unittest.main()
