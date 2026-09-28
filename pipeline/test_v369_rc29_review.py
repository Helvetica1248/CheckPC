#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 deterministic Windows path binding-variance regressions."""
from __future__ import annotations

import analyze_section as a
import section_prompts as sp
from analyze_section import ChunkSpec
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION, BUDGET_PROFILE_DEFAULT

PASS = FAIL = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [OK]  {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}: {detail}")

check("pipeline", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("schema", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("profile", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)

prompt = sp.get_prompt("com_persistence", 1, lean=True)
check("prompt explains decoded binding value",
      "外側引用符やJSONエスケープを重ねない" in prompt, prompt[:800])

expected = r"%SystemRoot%\system32\SearchFolder.dll"
check("SystemRoot and C Windows are equivalent",
      a._binding_identifier_matches(expected, r"C:\Windows\system32\SearchFolder.dll"))
check("windir alias is equivalent",
      a._binding_identifier_matches(expected, r"%windir%\system32\SearchFolder.dll"))
check("SystemRoot namespace alias is equivalent",
      a._binding_identifier_matches(expected, r"\SystemRoot\system32\SearchFolder.dll"))
check("one additional backslash escape layer is equivalent",
      a._binding_identifier_matches(expected, r"%SystemRoot%\\system32\\SearchFolder.dll"))
check("CommonProgramFiles expansion is equivalent",
      a._binding_identifier_matches(
          r"%CommonProgramFiles%\System\wab32.dll",
          r"C:\Program Files\Common Files\System\wab32.dll"))
check("different DLL remains mismatch",
      not a._binding_identifier_matches(
          r"%SystemRoot%\system32\SearchFolder.dll",
          r"C:\Windows\system32\zipfldr.dll"))
check("different registry evidence remains mismatch",
      not a._binding_identifier_matches(
          r"HKEY_CLASSES_ROOT\CLSID\{A}\InprocServer32",
          r"HKEY_CLASSES_ROOT\CLSID\{B}\InprocServer32"))

row_a = {
    "source_id": "com_persistence:a", "category": "com_persistence",
    "reg_key": r"HKEY_CLASSES_ROOT\CLSID\{A}\InprocServer32",
    "value_name": "(Default)", "value_type": "REG_EXPAND_SZ",
    "value_data": r"%SystemRoot%\system32\SearchFolder.dll",
}
row_b = {
    "source_id": "com_persistence:b", "category": "com_persistence",
    "reg_key": r"HKEY_CLASSES_ROOT\CLSID\{B}\InprocServer32",
    "value_name": "(Default)", "value_type": "REG_EXPAND_SZ",
    "value_data": r"%SystemRoot%\system32\zipfldr.dll",
}

orig_call = a._call_llm_score_checked
orig_depth = a.COVERAGE_MAX_SPLIT_DEPTH

try:
    def expanded(client, model, section, depth, data_text, verbose=False,
                 context="", lean=None, max_tokens_override=None):
        return {"section": section, "entries": [
            {"source_index": 0, "source_id": "com_persistence:a",
             "identifier": r"C:\Windows\system32\SearchFolder.dll",
             "score": "CLEAN", "reason": "expanded A"},
            {"source_index": 1, "source_id": "com_persistence:b",
             "identifier": r"C:\Windows\system32\zipfldr.dll",
             "score": "CLEAN", "reason": "expanded B"},
        ]}
    a._call_llm_score_checked = expanded
    spec = ChunkSpec([row_a, row_b], [10, 11], max_tokens=1024)
    out, _, errors, _ = a.call_llm_chunked(
        None, "m", "com_persistence", 1, [row_a, row_b], lean=True,
        chunk_plan={"specs": [spec]}, source_indices=[10, 11])
    check("equivalent paths accepted without retry error", len(out) == 2 and not errors, (out, errors))
    check("final identifiers come from raw evidence",
          [e.get("identifier") for e in out] == [row_a["value_data"], row_b["value_data"]], out)
    check("raw source indices remain correct",
          [e.get("_raw_source_index") for e in out] == [10, 11], out)
finally:
    a._call_llm_score_checked = orig_call

try:
    a.COVERAGE_MAX_SPLIT_DEPTH = 3
    def swapped(client, model, section, depth, data_text, verbose=False,
                context="", lean=None, max_tokens_override=None):
        has_a = "com_persistence:a" in data_text
        has_b = "com_persistence:b" in data_text
        entries = []
        if has_a:
            entries.append({"source_index": 0, "source_id": "com_persistence:a",
                            "identifier": row_b["value_data"], "score": "LOW", "reason": "swapped A"})
        if has_b:
            entries.append({"source_index": 1 if has_a else 0, "source_id": "com_persistence:b",
                            "identifier": row_a["value_data"], "score": "LOW", "reason": "swapped B"})
        return {"section": section, "entries": entries}
    a._call_llm_score_checked = swapped
    spec = ChunkSpec([row_a, row_b], [10, 11], max_tokens=1024)
    out, _, errors, _ = a.call_llm_chunked(
        None, "m", "com_persistence", 1, [row_a, row_b], lean=True,
        chunk_plan={"specs": [spec]}, source_indices=[10, 11])
    check("different neighbour paths remain rejected", out == [], out)
    reasons = (errors[0].get("rejection_reasons") if errors else {}) or {}
    check("identifier mismatch remains audited", reasons.get("identifier_index_mismatch", 0) > 0, reasons)
finally:
    a._call_llm_score_checked = orig_call
    a.COVERAGE_MAX_SPLIT_DEPTH = orig_depth

try:
    def wrong_sid(client, model, section, depth, data_text, verbose=False,
                  context="", lean=None, max_tokens_override=None):
        return {"section": section, "entries": [{
            "source_index": 0, "source_id": "com_persistence:wrong",
            "identifier": r"C:\Windows\system32\SearchFolder.dll",
            "score": "CLEAN", "reason": "wrong source id"}]}
    a._call_llm_score_checked = wrong_sid
    spec = ChunkSpec([row_a], [10], max_tokens=512)
    out, _, errors, _ = a.call_llm_chunked(
        None, "m", "com_persistence", 1, [row_a], lean=True,
        chunk_plan={"specs": [spec]}, source_indices=[10])
    check("wrong source_id remains rejected", out == [], out)
    reasons = (errors[0].get("rejection_reasons") if errors else {}) or {}
    check("wrong source_id rejection is audited", reasons.get("source_id_index_mismatch", 0) > 0, reasons)
finally:
    a._call_llm_score_checked = orig_call

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
