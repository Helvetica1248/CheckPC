#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70: Claude review findings A/B/C regression tests."""
from __future__ import annotations
import json

import analyze_section as az
import chat_tools as ct
import compare_analyzed as cmp
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION

PASS = FAIL = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [OK]  {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else ""))

def section(name):
    print("\n" + "-" * 60 + f"\n  {name}\n" + "-" * 60)

def doc(entry):
    return {"sections": {"directory": {"entries": [entry]}}, "meta": {}}

def ent(source_id=None, score="HIGH"):
    e = {
        "identifier": r"C:\\Temp\\evil.exe",
        "datetime": "2026-07-18 12:34:56",
        "score": score,
        "reason": "same evidence",
        "iocs": [r"C:\\Temp\\evil.exe"],
    }
    if source_id is not None:
        e["source_id"] = source_id
    return e

section("V1 release version")
check("V1-1 pipeline version", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("V1-2 schema version", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)

section("V2 compare_analyzed mixed-schema matching")
old = doc(ent())
new = doc(ent("directory:abc123"))
check("V2-1 mixed old/new uses two-stage mode",
      cmp.comparison_key_mode(old, new) == "source_id_then_canonical",
      cmp.comparison_key_mode(old, new))
fatal, adjud, matrix = cmp.compare(old, new, strict=False)
check("V2-2 same evidence with source_id on one side is matched",
      not fatal and not adjud and matrix[("HIGH", "HIGH")] == 1,
      f"fatal={fatal} adjud={adjud} matrix={dict(matrix)}")

new_a = doc(ent("directory:abc123"))
new_b = doc(ent("directory:abc123"))
check("V2-3 complete new/new comparison uses two-stage mode",
      cmp.comparison_key_mode(new_a, new_b) == "source_id_then_canonical")
fatal2, adjud2, matrix2 = cmp.compare(new_a, new_b, strict=False)
check("V2-4 new/new identical source_id matches",
      not fatal2 and not adjud2 and matrix2[("HIGH", "HIGH")] == 1)

partial = {"sections": {"directory": {"entries": [ent("directory:abc123"), ent()]}}}
check("V2-5 partial source_id artifact stays two-stage",
      cmp.comparison_key_mode(partial, new_b) == "source_id_then_canonical")

section("V3 defensive chat response extraction")
class EmptyChoicesResponse:
    choices = []

class EmptyChoicesCompletions:
    def create(self, **kwargs):
        return EmptyChoicesResponse()

class EmptyChoicesClient:
    chat = type("Chat", (), {"completions": EmptyChoicesCompletions()})()

try:
    ct.run_chat_turn(EmptyChoicesClient(), "model", [{"role": "user", "content": "x"}],
                     object(), lv2_enabled=False, mode="simple")
    raised = False
except RuntimeError as exc:
    raised = "empty_choices" in str(exc)
check("V3-1 simple chat rejects choices=[] deterministically", raised)

fallback, _elapsed = ct._wrapup_final_call(
    EmptyChoicesClient(), "model", [], "wrap up", "fallback answer")
check("V3-2 wrap-up returns fallback on choices=[]", fallback == "fallback answer", fallback)

class MissingMessageResponse:
    choices = [type("Choice", (), {"message": None, "finish_reason": "stop"})()]

class MissingMessageCompletions:
    def create(self, **kwargs):
        return MissingMessageResponse()

class MissingMessageClient:
    chat = type("Chat", (), {"completions": MissingMessageCompletions()})()

try:
    ct.run_chat_turn(MissingMessageClient(), "model", [{"role": "user", "content": "x"}],
                     object(), lv2_enabled=False, mode="standard")
    raised_missing = False
except RuntimeError as exc:
    raised_missing = "missing_message" in str(exc)
check("V3-3 tool-capable chat rejects missing message", raised_missing)

section("V4 entries_to_text numeric size defense")
try:
    directory_text = az.entries_to_text("directory", [
        {"date": "2026/07/18 12:00", "size": 1234, "path": r"C:\\Temp\\a.exe"}
    ])
    startup_text = az.entries_to_text("startup_folder", [
        {"date": "2026/07/18 12:00", "size": 5678, "source": "user", "path": r"C:\\a.lnk"}
    ])
    size_ok = "1234" in directory_text and "5678" in startup_text
except Exception as exc:
    size_ok = False
    directory_text = startup_text = repr(exc)
check("V4-1 numeric size values do not raise AttributeError", size_ok,
      f"directory={directory_text!r} startup={startup_text!r}")

print(f"\n{'=' * 60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS + FAIL}")
print(f"{'=' * 60}")
raise SystemExit(1 if FAIL else 0)
