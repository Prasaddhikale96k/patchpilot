"""Tests for strip_reasoning (prompt 00a): leaked chain-of-thought removal."""

from __future__ import annotations

from agents.llm_router import strip_reasoning


class TestStripReasoning:
    def test_think_block_removed(self):
        text = "<think>secret plan</think>{\"a\": 1}"
        assert strip_reasoning(text) == '{"a": 1}'

    def test_multiline_think_block_removed(self):
        text = "Hello\n<think>\nline1\nline2\n</think>\nWorld"
        assert strip_reasoning(text) == "Hello\n\nWorld"

    def test_think_tag_case_insensitive(self):
        assert strip_reasoning("<THINK>x</THINK>ok") == "ok"

    def test_leading_thinking_preamble_removed(self):
        text = "Thinking: the user wants a patch.\n\nHere is the fix."
        assert strip_reasoning(text) == "Here is the fix."

    def test_let_me_think_preamble_removed(self):
        text = "Let me think about this.\n\n{\"a\": 1}"
        assert strip_reasoning(text) == '{"a": 1}'

    def test_body_mentioning_thinking_is_kept(self):
        text = "The fix stops attackers thinking about injection."
        assert strip_reasoning(text) == text

    def test_plain_text_untouched(self):
        assert strip_reasoning('{"a": 1}') == '{"a": 1}'

    def test_non_string_passes_through(self):
        assert strip_reasoning(None) is None
