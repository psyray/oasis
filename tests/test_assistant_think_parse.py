"""Tests for assistant think-block parsing."""

import unittest

from oasis.helpers.assistant.think.think_parse import (
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

    def test_channel_thought_double_word_opener(self):
        raw = (
            "<|channel>thought thought <channel|>Dup token opener.\n\n"
            "## Answer\n\nDone."
        )
        split = parse_assistant_think(raw)
        self.assertEqual(split.thought_segments, ["Dup token opener."])
        self.assertEqual(split.visible_markdown, "## Answer\n\nDone.")

    def test_channel_thought_symmetric_close_tag(self):
        raw = "<|channel>thought <|channel|>Symmetric close.\n\n## A\n\nB."
        split = parse_assistant_think(raw)
        self.assertEqual(split.thought_segments, ["Symmetric close."])
        self.assertEqual(split.visible_markdown, "## A\n\nB.")

    def test_channel_thought_two_blocks_back_to_back(self):
        raw = (
            "<|channel>thought <channel|>First block."
            "<|channel>thought <channel|>Second block.\n\n"
            "## Reply\n\nOK."
        )
        split = parse_assistant_think(raw)
        self.assertEqual(split.thought_segments, ["First block.", "Second block."])
        self.assertEqual(split.visible_markdown, "## Reply\n\nOK.")

    def test_channel_thought_two_blocks_then_reply(self):
        raw = (
            "<|channel>thought <channel|>One.\n\n"
            "<|channel>thought <channel|>Two.\n\n"
            "## Final\n\nText."
        )
        split = parse_assistant_think(raw)
        self.assertEqual(split.thought_segments, ["One.", "Two."])
        self.assertEqual(split.visible_markdown, "## Final\n\nText.")

    def test_channel_thought_prefers_earliest_boundary(self):
        raw = (
            "<|channel>thought <channel|>reasoning notes.\n\n"
            "Visible reply starts here."
            "<|channel>thought <channel|>later block."
        )
        split = parse_assistant_think(raw)
        self.assertEqual(split.thought_segments, ["reasoning notes.", "later block."])
        self.assertEqual(split.visible_markdown, "Visible reply starts here.")

    def test_channel_thought_stray_angle_bracket_token(self):
        # Streaming tokenization sometimes emits a lone ``>`` between the opener
        # and the label (observed with gpt-oss).
        raw = (
            "<|channel>>thought <channel|>Reasoning body.\n\n"
            "Final answer here."
        )
        split = parse_assistant_think(raw)
        self.assertEqual(split.thought_segments, ["Reasoning body."])
        self.assertEqual(split.visible_markdown, "Final answer here.")

    def test_channel_thought_prefixed_label(self):
        # Some runs prefix the label (``most_thought``/``deep_thought``).
        raw = (
            "<|channel> most_thought <channel|>Deep reasoning.\n\n"
            "Visible reply."
        )
        split = parse_assistant_think(raw)
        self.assertEqual(split.thought_segments, ["Deep reasoning."])
        self.assertEqual(split.visible_markdown, "Visible reply.")

    def test_channel_analysis_symmetric_harmony(self):
        # Full harmony form: ``<|channel|>analysis<|message|>`` terminated by ``<|end|>``.
        raw = (
            "<|channel|>analysis<|message|>Internal steps...<|end|>"
            "<|start|>assistant<|channel|>final<|message|>Actual reply."
        )
        split = parse_assistant_think(raw)
        self.assertEqual(split.thought_segments, ["Internal steps..."])
        # Stray harmony tokens (``<|start|>``/``<|channel|>``/``final``/``<|message|>``)
        # survive structured extraction but are stripped by the final safety net.
        self.assertNotIn("<|", split.visible_markdown)
        self.assertIn("Actual reply.", split.visible_markdown)

    def test_channel_commentary_label(self):
        raw = "<|channel>commentary <channel|>meta notes.\n\nReply text."
        split = parse_assistant_think(raw)
        self.assertEqual(split.thought_segments, ["meta notes."])
        self.assertEqual(split.visible_markdown, "Reply text.")

    def test_stray_harmony_tokens_stripped_from_visible(self):
        # Partial tokens (truncated streams) should not leak into the UI.
        raw = "<|channel|>Hello<|end|>world"
        split = parse_assistant_think(raw)
        # ``<|channel|>`` without a reasoning label doesn't match the structured
        # opener, but the stray-token filter still removes it.
        self.assertNotIn("<|channel|>", split.visible_markdown)
        self.assertNotIn("<|end|>", split.visible_markdown)


if __name__ == "__main__":
    unittest.main()
