#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 regressions: generalized evidence policy and closed schemas."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import analyze_section
import correlate
import depth2_select
import report_gen
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION, BUDGET_PROFILE_DEFAULT

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}")
        PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else ""))
        FAIL += 1


print("\n--- RC18 identity ---")
check("pipeline version", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("schema version", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("profile version", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)


print("\n--- production policy is product/IP agnostic ---")
production_text = "\n".join(
    (HERE / name).read_text(encoding="utf-8")
    for name in ("analyze_section.py", "depth2_select.py", "compare_analyzed.py")
)
for forbidden in ("CodeSetup", "OllamaSetup", "119.3.160.204"):
    check(f"production logic excludes {forbidden}", forbidden not in production_text)

ctx = depth2_select.empty_ctx()
paths = [
    r"C:\Users\u\AppData\Local\Temp\VendorASetup.exe",
    r"C:\Users\u\AppData\Local\Temp\random-name.exe",
    r"C:\Users\u\AppData\Local\Temp\UnrelatedTool.exe",
]
scores = [depth2_select.section_selection_score("appcompat_cache", {"path": p}, ctx)[:2]
          for p in paths]
check("basename changes do not alter selection tier/score", len(set(scores)) == 1, scores)
check("generic classifier recognizes all user-writable executables",
      all(depth2_select.is_user_writable_execution_artifact({"path": p}) for p in paths))
check("non-executable temp file is not execution artifact",
      not depth2_select.is_user_writable_execution_artifact(
          {"path": r"C:\Users\u\AppData\Local\Temp\VendorASetup.tmp"}))

for i, path in enumerate(paths):
    entry = {"identifier": path, "score": "LOW", "reason": "x", "mitre": [], "iocs": [path]}
    out = analyze_section._apply_post_filter("appcompat_cache", {"entries": [entry]}, [])["entries"][0]
    check(f"generic MEDIUM floor {i}", out["score"] == "MEDIUM", out)
    check(f"generic floor audit {i}", out.get("_floor") == "user_writable_execution_artifact", out)

high = {"identifier": paths[0], "score": "HIGH", "reason": "x", "mitre": [], "iocs": [paths[0]]}
high_out = analyze_section._apply_post_filter("appcompat_cache", {"entries": [high]}, [])["entries"][0]
check("generic floor is not a HIGH ceiling", high_out["score"] == "HIGH", high_out)


print("\n--- netstat source identity and generic MEDIUM floor ---")
raw = [{
    "source_id": "netstat:generic-1",
    "local": "10.0.0.5:50000",
    "remote": "93.184.216.34:45678",
    "state": "ESTABLISHED",
    "_proc_hint": "N/A",
}]
result_entry = {
    "source_id": "netstat:generic-1", "_raw_source_index": 999,
    "identifier": "10.0.0.5:50000 → 93.184.216.34:45678",
    "score": "LOW", "reason": "x", "mitre": [], "iocs": ["93.184.216.34"],
}
out = analyze_section._apply_post_filter("netstat", {"entries": [result_entry]}, raw)["entries"][0]
check("raw evidence resolves by source_id before invalid index", out["score"] == "MEDIUM", out)
check("generic netstat floor is MEDIUM", out.get("_floor") == "netstat_external_nonstandard_unattributed_medium", out)
raw_attributed = [dict(raw[0], _proc_hint="pid=42 (browser.exe)")]
out2 = analyze_section._apply_post_filter("netstat", {"entries": [dict(result_entry, score="LOW")]}, raw_attributed)["entries"][0]
check("attributed process does not receive unattributed floor", out2["score"] == "LOW", out2)


print("\n--- score schema retry and safe recovery ---")
old_call = analyze_section.call_llm
try:
    calls = []
    def first_bad_then_good(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            return {"entries": [{"source_index": 0, "identifier": "x", "score": "LOGBAS", "reason": "x"}]}
        return {"entries": [{"source_index": 0, "identifier": "x", "score": "MEDIUM", "reason": "x"}]}
    analyze_section.call_llm = first_bad_then_good
    retried = analyze_section._call_llm_score_checked(None, "m", "active_setup", 2, "x")
    check("invalid score triggers one retry", len(calls) == 2, len(calls))
    check("valid retry is accepted", retried["entries"][0]["score"] == "MEDIUM", retried)
    check("schema retry audit succeeds", retried.get("_schema_retry_succeeded") is True, retried)

    calls.clear()
    def always_bad(*args, **kwargs):
        calls.append(1)
        return {"entries": [{"source_index": 0, "identifier": "x", "score": "LOGBAS", "reason": "x"}]}
    analyze_section.call_llm = always_bad
    bad = analyze_section._call_llm_score_checked(None, "m", "active_setup", 2, "x")
    recovered = analyze_section._normalise_score_schema({"section": "active_setup", "entries": bad["entries"]})
    e = recovered["entries"][0]
    check("retry failure preserves evidence", len(calls) == 2 and len(recovered["entries"]) == 1, recovered)
    check("invalid score safely normalizes to MEDIUM", e["score"] == "MEDIUM", e)
    check("raw score is preserved", e.get("score_raw") == "LOGBAS", e)
    check("schema warning is preserved", e.get("score_normalization_warning") == "invalid_score", e)
    check("section is marked schema_degraded", recovered.get("schema_degraded") is True, recovered)
    md = report_gen.section_entries_md("active_setup", recovered, full=True)
    check("report surfaces schema recovery", "score schema recovery" in md, md[:300])
    filtered = correlate.extract_high_medium({"sections": {"active_setup": recovered}})
    check("correlation retains recovered MEDIUM evidence",
          filtered["active_setup"]["entries"][0]["score"] == "MEDIUM", filtered)
finally:
    analyze_section.call_llm = old_call


print("\n--- planner maximality and deterministic backfill ---")
class FakeProfile:
    d2_output_token_budget = 100
    d2_min_rep = 1
    novelty_min_rep = 0
    novelty_section_cap = 0
    sig_max_d2 = 100
    risk_ratio = 1.0
    fair_ratio = 0.0
    def tok_per_entry(self, sec): return 10
    def section_cap(self, sec): return 20

old_profile = depth2_select.active_profile
old_plan = analyze_section.resolve_chunk_plan
try:
    depth2_select.active_profile = lambda: FakeProfile()
    analyze_section.resolve_chunk_plan = lambda sec, entries, depth, **kwargs: {
        "planned_output_tokens": len(entries) * 20 + (10 if entries else 0),
        "chunk_overhead_tokens": 10 if entries else 0,
    }
    pool = {"appcompat_cache": [
        (i, {"path": rf"C:\Users\u\AppData\Local\Temp\artifact-{i}.exe"})
        for i in range(8)
    ]}
    plan = depth2_select.plan_depth2_selection(
        pool, depth2_select.empty_ctx(), ["appcompat_cache"], novelty_pools={})
    info = plan["appcompat_cache"]
    check("plan remains within global budget",
          info["global_planned_output_tokens"] <= info["global_budget"], info)
    check("over-trim is repaired by backfill", info["planner_backfill_added"] > 0, info)
    check("final plan is maximal", info["plan_is_maximal"] is True, info)
    check("maximality has no addable candidates", not info["maximality_addable_candidates"], info)
    check("unused budget is audited", info["unused_budget_tokens"] == 10, info)
finally:
    depth2_select.active_profile = old_profile
    analyze_section.resolve_chunk_plan = old_plan


print("\n--- compare schema and depth semantics ---")
def doc(depth, entries):
    return {"meta": {"depth": depth}, "sections": {"x": {"entries": entries}}}

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    a = td / "a.json"; b = td / "b.json"
    # same-depth non-HIGH disappearance is now a provenance regression.
    a.write_text(json.dumps(doc(2, [{"source_id": "x:1", "identifier": "x", "score": "LOW", "reason": "x"}])), encoding="utf-8")
    b.write_text(json.dumps(doc(2, [])), encoding="utf-8")
    cp = subprocess.run([sys.executable, str(HERE / "compare_analyzed.py"), str(a), str(b)], capture_output=True, text=True)
    check("same-depth evidence disappearance is fatal", cp.returncode == 1, cp.stdout + cp.stderr)

    # Invalid raw score is never silently omitted.
    a.write_text(json.dumps(doc(2, [{"source_id": "x:1", "identifier": "x", "score": "LOGBAS", "reason": "x"}])), encoding="utf-8")
    b.write_text(json.dumps(doc(2, [{"source_id": "x:1", "identifier": "x", "score": "MEDIUM", "reason": "x"}])), encoding="utf-8")
    cp = subprocess.run([sys.executable, str(HERE / "compare_analyzed.py"), str(a), str(b)], capture_output=True, text=True)
    check("invalid score makes comparison fail", cp.returncode == 1 and "invalid_score" in cp.stdout, cp.stdout + cp.stderr)

    # Cross-depth deterministic HIGH to MEDIUM is fatal.
    a.write_text(json.dumps(doc(1, [{"source_id": "x:1", "identifier": "x", "score": "HIGH", "reason": "[deterministic floor: HIGH] x"}])), encoding="utf-8")
    b.write_text(json.dumps(doc(2, [{"source_id": "x:1", "identifier": "x", "score": "MEDIUM", "reason": "x"}])), encoding="utf-8")
    cp = subprocess.run([sys.executable, str(HERE / "compare_analyzed.py"), str(a), str(b)], capture_output=True, text=True)
    check("cross-depth deterministic HIGH downgrade is fatal", cp.returncode == 1, cp.stdout + cp.stderr)

print(f"\nRESULT: PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
