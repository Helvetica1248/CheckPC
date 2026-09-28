#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prompt boundary helpers for untrusted evidence and tool output.

Boundary markers are control-plane text.  Raw evidence, analyst-supplied
context, and tool output must not be able to reproduce those markers verbatim,
because doing so would let untrusted data visually close or reopen a boundary
inside the model prompt.
"""
from __future__ import annotations

from typing import Iterable

EVIDENCE_BEGIN = "<BEGIN_UNTRUSTED_EVIDENCE>"
EVIDENCE_END = "<END_UNTRUSTED_EVIDENCE>"
ANALYST_CONTEXT_BEGIN = "<BEGIN_ANALYST_CONTEXT>"
ANALYST_CONTEXT_END = "<END_ANALYST_CONTEXT>"
TOOL_RESULT_BEGIN = "<BEGIN_UNTRUSTED_TOOL_RESULT>"
TOOL_RESULT_END = "<END_UNTRUSTED_TOOL_RESULT>"

RESERVED_BOUNDARY_TOKENS = (
    EVIDENCE_BEGIN,
    EVIDENCE_END,
    ANALYST_CONTEXT_BEGIN,
    ANALYST_CONTEXT_END,
    TOOL_RESULT_BEGIN,
    TOOL_RESULT_END,
)


def _neutral_form(token: str) -> str:
    """Return a human-readable form that cannot be parsed as the reserved tag."""
    return token.replace("<", "＜").replace(">", "＞")


def neutralize_prompt_boundaries(value: object,
                                 tokens: Iterable[str] = RESERVED_BOUNDARY_TOKENS) -> str:
    """Neutralize every reserved prompt-boundary literal in untrusted text.

    The transformation is deterministic and length-preserving enough for logs,
    while making the control marker visibly distinct.  Replacement is applied
    before the outer boundary is added, so the final prompt contains exactly
    one opening and one closing marker for that boundary type.
    """
    text = str(value or "")
    for token in sorted(set(tokens), key=len, reverse=True):
        text = text.replace(token, _neutral_form(token))
    return text


def wrap_untrusted_evidence(value: object) -> str:
    body = neutralize_prompt_boundaries(value)
    return f"{EVIDENCE_BEGIN}\n{body}\n{EVIDENCE_END}"


def wrap_analyst_context(value: object) -> str:
    body = neutralize_prompt_boundaries(value)
    return f"{ANALYST_CONTEXT_BEGIN}\n{body}\n{ANALYST_CONTEXT_END}"


def wrap_untrusted_tool_result(value: object) -> str:
    body = neutralize_prompt_boundaries(value)
    return f"{TOOL_RESULT_BEGIN}\n{body}\n{TOOL_RESULT_END}"
