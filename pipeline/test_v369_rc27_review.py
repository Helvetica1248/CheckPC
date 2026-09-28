#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 semantic source-binding and comparison audit regressions."""
from __future__ import annotations

import copy
import json

import analyze_section
from analyze_section import ChunkSpec
from compare_analyzed import two_stage_entry_multisets
from compare_runs import _aggregate_issues
from comparison_approval import validate_result_object, COMPARISON_APPROVAL_SCHEMA
from validate_semantic_binding import validate as validate_semantic_binding
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
check("approval schema v2", COMPARISON_APPROVAL_SCHEMA == 2, COMPARISON_APPROVAL_SCHEMA)

# Every formerly-fallback list section must be independently numbered and source-bound.
registry_rows = [
    {
        "source_id": "active_setup:aaaaaaaaaaaaaaaaaaaaaaaa",
        "reg_key": r"HKEY_LOCAL_MACHINE\\A",
        "value_name": "StubPath",
        "value_type": "REG_SZ",
        "value_data": r"C:\\Windows\\System32\\a.dll",
    },
    {
        "source_id": "active_setup:bbbbbbbbbbbbbbbbbbbbbbbb",
        "reg_key": r"HKEY_LOCAL_MACHINE\\B",
        "value_name": "StubPath",
        "value_type": "REG_SZ",
        "value_data": r"C:\\Windows\\System32\\b.dll",
    },
]
text = analyze_section.entries_to_text("active_setup", registry_rows)
check("fallback section numbered #0", "[#0]" in text, text[:300])
check("fallback section numbered #1", "[#1]" in text, text[:300])
check("fallback section source_id A", registry_rows[0]["source_id"] in text, text[:300])
check("fallback section source_id B", registry_rows[1]["source_id"] in text, text[:300])
check(
    "active_setup canonical identifier",
    analyze_section._canonical_identifier("active_setup", registry_rows[0])
    == registry_rows[0]["value_data"],
)

recent = {
    "source_id": "recent_behavior:cccccccccccccccccccccccc",
    "category": "TypedPaths",
    "reg_key": r"HKEY_CURRENT_USER\\Software\\Recent",
    "value_name": "url1",
    "value_data": r"C:\\Users\\example\\AppData\\Local\\Programs\\Ollama",
}
check(
    "recent_behavior canonical identifier",
    analyze_section._canonical_identifier("recent_behavior", recent) == recent["value_data"],
)

wmi = {
    "source_id": "wmi:dddddddddddddddddddddddd",
    "Name": "WMI_ActiveScriptEventConsumer",
    "ScriptText": "test",
}
check("wmi canonical identifier", analyze_section._canonical_identifier("wmi", wmi) == wmi["Name"])

# Direct raw-index provenance must not pass if source_id/identifier point elsewhere.
raw_rows = copy.deepcopy(registry_rows)
wrong = {
    "_raw_source_index": 0,
    "source_id": raw_rows[0]["source_id"],
    "identifier": raw_rows[1]["value_data"],
    "score": "MEDIUM",
}
indices, method = analyze_section._result_entry_raw_indices("active_setup", raw_rows, wrong)
check("raw binding rejects swapped identifier", not indices and method == "raw_index_identifier_mismatch", (indices, method))

wrong_sid = dict(wrong)
wrong_sid["identifier"] = raw_rows[0]["value_data"]
wrong_sid["source_id"] = raw_rows[1]["source_id"]
indices, method = analyze_section._result_entry_raw_indices("active_setup", raw_rows, wrong_sid)
check("raw binding rejects swapped source_id", not indices and method == "raw_index_source_id_mismatch", (indices, method))

correct = dict(wrong)
correct["identifier"] = raw_rows[0]["value_data"]
indices, method = analyze_section._result_entry_raw_indices("active_setup", raw_rows, correct)
check("raw binding accepts consistent triple", indices == {0} and method == "raw_index_source_id_identifier", (indices, method))

check(
    "binding normalization handles whitespace and arrow",
    analyze_section._binding_identifier_matches(
        "  10.0.0.1:1→10.0.0.2:2  ",
        "10.0.0.1:1   →   10.0.0.2:2",
    ),
)

semantic_parsed = {"sections": {"active_setup": raw_rows}, "event_logs": {}}
semantic_good = {"sections": {"active_setup": {"entries": [{
    **correct, "_source_attribution_method": "source_index_triple",
}]}}}
semantic_bad = {"sections": {"active_setup": {"entries": [{
    **wrong, "_source_attribution_method": "source_index_triple",
}]}}}
check(
    "external semantic validator accepts consistent binding",
    validate_semantic_binding(semantic_parsed, semantic_good)["status"] == "ACCEPT",
    validate_semantic_binding(semantic_parsed, semantic_good),
)
check(
    "external semantic validator rejects swapped binding",
    validate_semantic_binding(semantic_parsed, semantic_bad)["status"] == "REJECT",
    validate_semantic_binding(semantic_parsed, semantic_bad),
)

# End-to-end negative control: valid index/source_id with the neighbouring raw
# identifier must be rejected even after coverage splitting.
original_call = analyze_section._call_llm_score_checked
original_depth = analyze_section.COVERAGE_MAX_SPLIT_DEPTH
try:
    analyze_section.COVERAGE_MAX_SPLIT_DEPTH = 2

    def swapped_response(client, model, section, depth, data_text, verbose=False,
                         context="", lean=None, max_tokens_override=None):
        # Use whichever source IDs are visible in the current prompt, but always
        # attach the other fixture identifier. Singleton retries therefore also
        # fail closed instead of silently overwriting the mismatch.
        present_a = registry_rows[0]["source_id"] in data_text
        present_b = registry_rows[1]["source_id"] in data_text
        entries = []
        if present_a:
            entries.append({
                "source_index": 0,
                "source_id": registry_rows[0]["source_id"],
                "identifier": registry_rows[1]["value_data"],
                "score": "MEDIUM",
                "reason": "swapped",
                "mitre": [], "iocs": [], "decoded": None, "lolbas": None,
            })
        if present_b:
            entries.append({
                "source_index": 1 if present_a else 0,
                "source_id": registry_rows[1]["source_id"],
                "identifier": registry_rows[0]["value_data"],
                "score": "MEDIUM",
                "reason": "swapped",
                "mitre": [], "iocs": [], "decoded": None, "lolbas": None,
            })
        return {"section": section, "entries": entries}

    analyze_section._call_llm_score_checked = swapped_response
    spec = ChunkSpec(registry_rows, [100, 101], max_tokens=1024)
    rows, _, errors, timings = analyze_section.call_llm_chunked(
        None, "m", "active_setup", 1, registry_rows,
        lean=False, chunk_plan={"specs": [spec]}, source_indices=[100, 101],
    )
    check("permuted semantic rows not accepted", rows == [], rows)
    check("permuted semantic rows become unevaluated", bool(errors) and errors[0].get("coverage"), errors)
    check("coverage retry attempted", any(t.get("retry") for t in timings), timings)
finally:
    analyze_section._call_llm_score_checked = original_call
    analyze_section.COVERAGE_MAX_SPLIT_DEPTH = original_depth

# Comparator must preserve unmatched source IDs instead of collapsing empty identifiers.
a_doc = {
    "meta": {"source_id_algorithm_version": "1"},
    "sections": {"fixture": {"entries": [
        {"source_id": "fixture:a", "identifier": "", "score": "CLEAN", "reason": "a"},
        {"source_id": "fixture:b", "identifier": "", "score": "CLEAN", "reason": "b"},
    ]}},
}
b_doc = {
    "meta": {"source_id_algorithm_version": "1"},
    "sections": {"fixture": {"entries": []}},
}
ma, _, mb, _ = two_stage_entry_multisets(a_doc, b_doc)
keys = sorted(str(key[1]) for key in ma)
check("unmatched source IDs retained", keys == ["source_id:fixture:a#0", "source_id:fixture:b#0"], keys)
check("no B residuals", not mb, mb)

# Identical issues are represented once with an occurrence count and unique ID.
duplicate = {
    "severity": "REVIEW", "kind": "analyzed_entry_removed",
    "section": "fixture", "identity": "", "score": "CLEAN",
    "id": "ignored",
}
aggregated = _aggregate_issues([duplicate, duplicate, duplicate])
check("duplicate issue aggregated", len(aggregated) == 1, aggregated)
check("duplicate occurrence count", aggregated[0].get("occurrence_count") == 3, aggregated)
check("aggregated issue has ID", str(aggregated[0].get("id", "")).startswith("cmp-"), aggregated)

# Approval validator rejects duplicate issue/review IDs before set conversion.
invalid_result = {
    "comparison_result_schema": 1,
    "mode": "depth1-depth2",
    "status": "REVIEW",
    "issues": [
        {"id": "cmp-x", "severity": "REVIEW"},
        {"id": "cmp-x", "severity": "REVIEW"},
    ],
    "unresolved_review_ids": ["cmp-x", "cmp-x"],
    "artifacts": {
        "a": {"parsed_sha256": "a" * 64, "analyzed_sha256": "b" * 64,
              "meta": {"pipeline_version": PIPELINE_VERSION}},
        "b": {"parsed_sha256": "c" * 64, "analyzed_sha256": "d" * 64,
              "meta": {"pipeline_version": PIPELINE_VERSION}},
    },
    "result_id": "invalid",
}
errors = validate_result_object(invalid_result)
check("duplicate review IDs rejected", any("unique" in error for error in errors), errors)

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
