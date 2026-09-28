#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Defensive response extraction and gated OpenAI-compatible calls."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
from inference_gate import inference_slot

@dataclass(frozen=True)
class LlmTextResult:
    text: str
    finish_reason: str
    truncated: bool
    error: str | None
    usage_prompt_tokens: int | None = None
    usage_completion_tokens: int | None = None


def extract_llm_text(response: Any) -> LlmTextResult:
    choices = getattr(response, "choices", None)
    if not choices:
        return LlmTextResult("", "", False, "empty_choices")
    choice = choices[0]
    message = getattr(choice, "message", None)
    finish = str(getattr(choice, "finish_reason", "") or "")
    if message is None:
        return LlmTextResult("", finish, finish == "length", "missing_message")
    content = getattr(message, "content", None)
    if content is None:
        return LlmTextResult("", finish, finish == "length", "missing_content")
    if not isinstance(content, str):
        content = str(content)
    text = content.strip()
    usage = getattr(response, "usage", None)
    prompt_tokens = getattr(usage, "prompt_tokens", None) if usage is not None else None
    completion_tokens = getattr(usage, "completion_tokens", None) if usage is not None else None
    err = None if text else "empty_content"
    return LlmTextResult(text, finish, finish == "length", err, prompt_tokens, completion_tokens)


def extract_llm_message(response: Any) -> tuple[Any | None, str | None]:
    """Return the first assistant message without assuming OpenAI response shape.

    Tool-calling responses may legitimately have ``content=None`` while still
    carrying tool_calls, therefore this helper validates only choices/message.
    Text extraction remains the responsibility of :func:`extract_llm_text`.
    """
    choices = getattr(response, "choices", None)
    if not choices:
        return None, "empty_choices"
    message = getattr(choices[0], "message", None)
    if message is None:
        return None, "missing_message"
    return message, None


def create_chat_completion(client: Any, **kwargs: Any) -> Any:
    with inference_slot():
        return client.chat.completions.create(**kwargs)
