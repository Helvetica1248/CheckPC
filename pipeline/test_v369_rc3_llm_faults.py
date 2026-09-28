#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 deterministic LLM response/fault-injection regressions."""
from __future__ import annotations
import json

PASS = FAIL = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1; print(f"  [OK]  {name}")
    else:
        FAIL += 1; print(f"  [FAIL] {name}" + (f": {detail}" if detail else ""))

def response(*, choices=None, content="{}", finish="stop", message=True, usage=True):
    if choices is not None:
        ch = choices
    elif not message:
        ch = [type("C", (), {"message": None, "finish_reason": finish})()]
    else:
        msg = type("M", (), {"content": content})()
        ch = [type("C", (), {"message": msg, "finish_reason": finish})()]
    obj = type("R", (), {"choices": ch, "system_fingerprint": "fp"})()
    obj.usage = type("U", (), {"prompt_tokens": 12, "completion_tokens": 34})() if usage else None
    return obj

from llm_runtime import extract_llm_text, extract_llm_message
r = extract_llm_text(response(choices=[]))
check("L1 empty choices", r.error == "empty_choices")
r = extract_llm_text(response(message=False))
check("L2 missing message", r.error == "missing_message")
r = extract_llm_text(response(content=None))
check("L3 missing content", r.error == "missing_content")
r = extract_llm_text(response(content="   "))
check("L4 empty content", r.error == "empty_content")
r = extract_llm_text(response(content=123, finish="length"))
check("L5 non-string normalized", r.text == "123")
check("L6 length marked truncated", r.truncated and r.finish_reason == "length")
check("L7 usage extracted", r.usage_prompt_tokens == 12 and r.usage_completion_tokens == 34)
msg, err = extract_llm_message(response(content=None))
check("L8 tool-style message allowed", msg is not None and err is None)

import analyze_section as az
check("L9 first complete JSON ignores suffix", az.extract_first_json_object('x {"a":"}"} trailing {bad') == '{"a":"}"}')
check("L10 incomplete JSON rejected", az.extract_first_json_object('{"a":1') is None)
salvaged = az._salvage_truncated_entries('{"entries":[{"source_index":0,"score":"HIGH"},{"source_index":1')
check("L11 truncated entry salvage", len(salvaged) == 1 and salvaged[0].get("source_index") == 0, salvaged)

class Completion:
    def __init__(self, result=None, error=None): self.result=result; self.error=error; self.calls=0; self.kwargs=None
    def create(self, **kwargs):
        self.calls += 1; self.kwargs=kwargs
        if self.error: raise self.error
        return self.result
class Client:
    def __init__(self, comp): self.chat=type("Chat", (), {"completions":comp})()

comp = Completion(error=TimeoutError("timeout"))
out = az.call_llm(Client(comp), "m", "netstat", 1, "x")
check("L12 timeout becomes structured error", "timeout" in out.get("error", "") and out.get("section") == "netstat", out)
comp = Completion(error=RuntimeError("maximum context length exceeded"))
out = az.call_llm(Client(comp), "m", "netstat", 1, "x")
check("L13 context-length classified", out.get("context_length_exceeded") is True, out)
comp = Completion(result=response(choices=[]))
out = az.call_llm(Client(comp), "m", "netstat", 1, "x")
check("L14 empty response parse error", out.get("parse_error") and out.get("error") == "empty_choices", out)
comp = Completion(result=response(content="prefix not-json suffix"))
out = az.call_llm(Client(comp), "m", "netstat", 1, "x")
check("L15 malformed JSON retained as raw", out.get("parse_error") and "not-json" in out.get("raw_response", ""), out)
valid = {"section":"netstat", "entries":[{"source_index":0,"score":"HIGH","identifier":"x"}], "section_summary":"x"}
comp = Completion(result=response(content=json.dumps(valid) + " trailing garbage", finish="length"))
out = az.call_llm(Client(comp), "m", "netstat", 1, "x")
check("L16 complete JSON recovered despite suffix", len(out.get("entries", [])) == 1, out)
check("L17 finish_reason retained", out.get("_finish_reason") == "length" and out.get("_truncated") is True, out)
check("L18 evidence boundary sent", "<BEGIN_UNTRUSTED_EVIDENCE>" in comp.kwargs["messages"][1]["content"])

# Coverage verification: duplicate/out-of-range source_index must not be accepted as coverage.
orig_call = az.call_llm
orig_split = az.COVERAGE_MAX_SPLIT_DEPTH
try:
    az.COVERAGE_MAX_SPLIT_DEPTH = 0
    az.call_llm = lambda *a, **k: {"entries": [
        {"source_index": 0, "score": "HIGH", "identifier": "first"},
        {"source_index": 0, "score": "HIGH", "identifier": "duplicate"},
        {"source_index": 99, "score": "HIGH", "identifier": "outside"},
    ]}
    entries = [{"proto":"TCP","local":"1","remote":"2"}, {"proto":"TCP","local":"3","remote":"4"}]
    got, _, errors, _ = az.call_llm_chunked(object(), "m", "netstat", 1, entries, lean=False,
        chunk_plan={"specs":[az.ChunkSpec(entries, [10,11], max_tokens=512)]})
    check("L19 duplicate/out-of-range rejected", len(got) == 1, got)
    check("L20 missing coverage marked unevaluated", bool(errors and errors[0].get("selected_unevaluated")), errors)
    check("L21 raw source index preserved", got[0].get("_raw_source_index") == 10, got)
finally:
    az.call_llm = orig_call
    az.COVERAGE_MAX_SPLIT_DEPTH = orig_split

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(1 if FAIL else 0)
