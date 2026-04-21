"""Tests for assistant think-block parsing."""

import unittest

from oasis.helpers.assistant_think_parse import (
    enrich_assistant_message_dict,
    enrich_messages_for_response,
    parse_assistant_think,
)


class TestAssistantThinkParse(unittest.TestCase):
    def test_plain_text(self):
        split = parse_assistant_think("Hello world")
        self.assertEqual(split.visible_markdown, "Hello world")
        self.assertEqual(split.thought_segments, [])

    def test_redacted_reasoning_removed(self):
        raw = "<think>secret plan</think>\nAnswer: yes."
        split = parse_assistant_think(raw)
        self.assertEqual(split.thought_segments, ["secret plan"])
        self.assertEqual(split.visible_markdown, "Answer: yes.")

    def test_redacted_reasoning_attributes(self):
        raw = '<redacted_thinking reason="foo"> inner </think>Visible.'
        split = parse_assistant_think(raw)
        self.assertEqual(split.thought_segments, ["inner"])
        self.assertEqual(split.visible_markdown, "Visible.")

    def test_redacted_short_closing_think_tag(self):
        # Short closing tag name ``think`` (see ``_THINK_BLOCK_PATTERNS``).
        raw = '<redacted_thinking>plan B</think>\nVisible.'
        split = parse_assistant_think(raw)
        self.assertEqual(split.thought_segments, ["plan B"])
        self.assertEqual(split.visible_markdown, "Visible.")

    def test_think_tags(self):
        raw = "Intro <think>hint</think> Tail"
        split = parse_assistant_think(raw)
        self.assertEqual(split.thought_segments, ["hint"])
        self.assertEqual(split.visible_markdown, "Intro  Tail")

    def test_enrich_user_unchanged(self):
        msg = enrich_assistant_message_dict({"role": "user", "content": "Hi"})
        self.assertNotIn("visible_markdown", msg)

    def test_enrich_assistant(self):
        msg = enrich_assistant_message_dict(
            {"role": "assistant", "content": "<think>t</think>\nOk"}
        )
        self.assertEqual(msg["visible_markdown"], "Ok")
        self.assertEqual(msg["thought_segments"], ["t"])

    def test_enrich_messages_list(self):
        out = enrich_messages_for_response(
            [
                {"role": "user", "content": "q"},
                {"role": "assistant", "content": "<think>x</think> y"},
            ]
        )
        self.assertEqual(len(out), 2)
        self.assertEqual(out[1]["visible_markdown"], "y")

    def test_channel_thought_delimiter(self):
        raw = (
            "<|channel>thought <channel|>Based on the report, IDOR.\n\n"
            "## Answer\n\nThe issue is valid."
        )
        split = parse_assistant_think(raw)
        self.assertEqual(split.thought_segments, ["Based on the report, IDOR."])
        self.assertEqual(split.visible_markdown, "## Answer\n\nThe issue is valid.")

    def test_channel_thought_only(self):
        raw = "<|channel>thought <channel|>Only thinking text here."
        split = parse_assistant_think(raw)
        self.assertEqual(split.thought_segments, ["Only thinking text here."])
        self.assertEqual(split.visible_markdown, "")


if __name__ == "__main__":
    unittest.main()
