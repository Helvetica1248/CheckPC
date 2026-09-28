#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 real-model binding/provenance completeness regressions."""
from __future__ import annotations

import json

import analyze_section as a
import section_prompts as sp
from analyze_section import ChunkSpec
from validate_run_provenance import validate as validate_provenance
from validate_binding_smoke import validate as validate_smoke
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

rows = [
    {"source_id": "netstat:a", "proto": "TCP", "local": "10.0.0.1:1234",
     "remote": "8.8.8.8:443", "state": "ESTABLISHED", "pid": "1"},
    {"source_id": "netstat:b", "proto": "TCP", "local": "10.0.0.1:1235",
     "remote": "1.1.1.1:443", "state": "ESTABLISHED", "pid": "2"},
]
text = a.entries_to_text("netstat", rows)
check("binding identifier is explicit for row 0",
      'binding_identifier: "10.0.0.1:1234 → 8.8.8.8:443"' in text, text)
check("binding identifier is explicit for row 1",
      'binding_identifier: "10.0.0.1:1235 → 1.1.1.1:443"' in text, text)
check("legacy first-line source header retained",
      text.splitlines()[0].startswith("[#0][source_id=netstat:a] TCP "), text.splitlines()[0])

full_prompt = sp.get_prompt("netstat", 1, lean=False)
lean_prompt = sp.get_prompt("netstat", 1, lean=True)
check("FULL prompt points identifier to binding_identifier", "binding_identifier" in full_prompt)
check("FULL prompt forbids identifier inference", "証拠本文から推測しない" in full_prompt)
check("LEAN prompt points identifier to binding_identifier", "binding_identifier" in lean_prompt)

# Multi-entry chunks remain strict: valid index/source_id with a neighbour's
# identifier must not be accepted, even after coverage splitting.
orig_call = a._call_llm_score_checked
orig_depth = a.COVERAGE_MAX_SPLIT_DEPTH
try:
    a.COVERAGE_MAX_SPLIT_DEPTH = 1
    def swapped(client, model, section, depth, data_text, verbose=False,
                context="", lean=None, max_tokens_override=None):
        present_a = "netstat:a" in data_text
        present_b = "netstat:b" in data_text
        entries = []
        if present_a:
            entries.append({"source_index": 0, "source_id": "netstat:a",
                            "identifier": "10.0.0.1:1235 → 1.1.1.1:443",
                            "score": "LOW", "reason": "swapped"})
        if present_b:
            entries.append({"source_index": 1 if present_a else 0,
                            "source_id": "netstat:b",
                            "identifier": "10.0.0.1:1234 → 8.8.8.8:443",
                            "score": "LOW", "reason": "swapped"})
        return {"section": section, "entries": entries}
    a._call_llm_score_checked = swapped
    spec = ChunkSpec(rows, [100, 101], max_tokens=1024)
    out, _, errors, _ = a.call_llm_chunked(
        None, "m", "netstat", 1, rows, lean=True,
        chunk_plan={"specs": [spec]}, source_indices=[100, 101])
    check("neighbour identifier mixture rejected", out == [], out)
    reasons = (errors[0].get("rejection_reasons") if errors else {}) or {}
    check("rejection reason is audited", reasons.get("identifier_index_mismatch", 0) > 0, reasons)
finally:
    a._call_llm_score_checked = orig_call
    a.COVERAGE_MAX_SPLIT_DEPTH = orig_depth

# A singleton may recover an omitted identifier only when the stable source_id
# matches. A non-empty mismatching identifier remains fail-closed.
try:
    def omitted(client, model, section, depth, data_text, verbose=False,
                context="", lean=None, max_tokens_override=None):
        return {"section": section, "entries": [{
            "source_index": 0, "source_id": "netstat:a",
            "score": "LOW", "reason": "identifier omitted"}]}
    a._call_llm_score_checked = omitted
    spec = ChunkSpec([rows[0]], [100], max_tokens=512)
    out, _, errors, _ = a.call_llm_chunked(
        None, "m", "netstat", 1, [rows[0]], lean=True,
        chunk_plan={"specs": [spec]}, source_indices=[100])
    check("singleton matching source_id recovers omitted identifier",
          len(out) == 1 and out[0].get("identifier") == a._canonical_identifier("netstat", rows[0]), out)
    check("singleton omission recovery has no chunk error", not errors, errors)
finally:
    a._call_llm_score_checked = orig_call

# D1 deterministic aggregates are validated against the pre-LLM plan rather
# than forced through one-source-id/one-identifier binding.
class NoLLM:
    class Chat:
        class Completions:
            @staticmethod
            def create(**kwargs):
                raise AssertionError("LLM must not be called for deterministic-only fixture")
        completions = Completions()
    chat = Chat()

net_raw = [
    {"source_id": "netstat:ephemeral", "proto": "TCP", "local": "0.0.0.0:50001",
     "remote": "0.0.0.0:0", "state": "LISTENING", "pid": "10"},
    {"source_id": "netstat:loopback", "proto": "TCP", "local": "127.0.0.1:1234",
     "remote": "0.0.0.0:0", "state": "LISTENING", "pid": "11"},
]
parsed = {"meta": {"hostname": "T", "collection_id": "fixture"},
          "sections": {"netstat": net_raw, "tasklist": []}, "event_logs": {}}
result = a.analyze(parsed, 1, NoLLM(), "stub", target_sections=["netstat"], lean=True)
net = result["sections"]["netstat"]
check("D1 deterministic aggregate provenance complete",
      net["_provenance"].get("provenance_complete") is True, net["_provenance"])
check("D1 deterministic aggregate has no attribution errors",
      net["_provenance"].get("attribution_error_count") == 0, net["_provenance"])
check("D1 deterministic aggregate covers both raw rows",
      net["_selection_stats"].get("deterministic") == 2, net["_selection_stats"])
check("D1 aggregate method is plan-based",
      all(e.get("_source_attribution_method") == "deterministic_plan_aggregate"
          for e in net.get("entries", [])), net.get("entries"))

# Normal validation keeps partial-result accounting available; release-strict
# rejects unevaluated evidence and unresolved chunk errors.
parsed_v = {"sections": {"fixture": [{"source_id": "fixture:a"}]}, "event_logs": {}}
prov = {
    "raw_count": 1, "provenance_complete": True, "attribution_error_count": 0,
    "stages": {
        "selected": {"applicable": True, "count": 1},
        "evaluated": {"applicable": True, "count": 0},
        "unevaluated": {"applicable": True, "count": 1},
    },
}
analyzed_v = {"sections": {"fixture": {"entries": [], "_provenance": prov,
                                         "_chunk_errors": [{"coverage": True}]}}}
normal_errors = validate_provenance(parsed_v, analyzed_v)
strict_errors = validate_provenance(parsed_v, analyzed_v, release_strict=True)
check("normal validator permits auditable partial result", not normal_errors, normal_errors)
check("release-strict rejects unevaluated", any("unevaluated=1" in x for x in strict_errors), strict_errors)
check("release-strict rejects chunk errors", any("chunk_errors=1" in x for x in strict_errors), strict_errors)

# Section-limited smoke validator applies the same zero-unevaluated gate without
# requiring unrelated parsed sections to be present.
smoke_reject = validate_smoke(analyzed_v, ["fixture"])
smoke_accept_doc = {"sections": {"fixture": {
    "entries": [{"source_id": "fixture:a", "identifier": "a"}],
    "_provenance": {
        "raw_count": 1, "provenance_complete": True, "attribution_error_count": 0,
        "stages": {
            "selected": {"applicable": True, "count": 1},
            "evaluated": {"applicable": True, "count": 1},
            "unevaluated": {"applicable": True, "count": 0},
        },
    },
    "_chunk_errors": [],
}}}
smoke_accept = validate_smoke(smoke_accept_doc, ["fixture"])
check("binding smoke rejects partial section", smoke_reject["status"] == "REJECT", smoke_reject)
check("binding smoke accepts complete section", smoke_accept["status"] == "ACCEPT", smoke_accept)

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
