from __future__ import annotations

from scripts.common.text_utils import strip_ansi, strip_markdown_fences


def test_strip_ansi_removes_color_codes():
    assert strip_ansi("\x1b[31mERROR\x1b[0m") == "ERROR"


def test_strip_ansi_noop_on_clean_text():
    assert strip_ansi("hello world") == "hello world"


def test_strip_ansi_empty_string():
    assert strip_ansi("") == ""


def test_strip_markdown_fences():
    text = "```json\n{\"key\": \"value\"}\n```"
    assert strip_markdown_fences(text) == '{"key": "value"}'


def test_strip_markdown_fences_no_fences():
    text = "plain text"
    assert strip_markdown_fences(text) == "plain text"
