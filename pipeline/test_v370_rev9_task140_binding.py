#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 rev9: task_140 binding/accounting/parser/comparison regression."""
from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

import analyze_section as a
import compare_runs as cr
import parse_checkpc as p
import validate_semantic_binding as v
from source_id import assign_source_ids

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail="") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [OK]  {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}: {detail}")


def raw_event(idx: int, dt: str, *, indent: str = "", colon: str = ":", body="stable") -> str:
    return (
        f"{indent}Event[{idx}]{colon}\n"
        "  Log Name: Microsoft-Windows-TaskScheduler/Operational\n"
        f"  Date: {dt}\n"
        "  Event ID: 140\n"
        "  User: S-1-5-18\n"
        "  Computer: PC1\n"
        "  Description:\n"
        f"  {body}\n"
    )


print("[1] real parser header variants + empty task_name")
text = "".join([
    raw_event(0, "2026-08-10T09:00:00Z", indent="", colon=""),
    raw_event(1, "2026-08-10T09:01:00Z", indent="  ", colon=":"),
    raw_event(2, "2026-08-10T09:02:00Z", indent="\t", colon="："),
    raw_event(3, "2026-08-10T09:03:00Z", indent=" ", colon=""),
])
rows = p.parse_task_event_text(text, "140")
check("parser splits four header variants", len(rows) == 4, len(rows))
check("task_name may be empty on all parsed rows", sum(not r.get("task_name") for r in rows) == 4, rows)
assign_source_ids("rev9-empty-task", "task_140", rows)
reps, info = a.aggregate_task140_depth1(rows, list(range(4)))
check("empty-task semantic equivalents collapse", len(reps) == 1 and info.get("collapsed_count") == 3, info)

print("\n[2] representative identifier + all-member digest/source-id binding")
result = {
    "source_id": reps[0]["source_id"],
    "identifier": a._canonical_identifier("task_140", reps[0]),
    "score": "LOW",
    "reason": "test",
    "_raw_source_index": 0,
}
a._expand_task140_aggregation_results([result], info)
indices, method = a._result_entry_raw_indices("task_140", rows, result)
check("empty task_name group binds all raw rows", indices == {0, 1, 2, 3}, (indices, method))
check("semantic group method returned", method == "task140_semantic_group", method)

parsed = {"sections": {}, "event_logs": {"task_140": rows}}
sids = [r["source_id"] for r in rows]
analyzed = {
    "meta": {"section_raw_evidence": {"task_140": {"count": 4}}},
    "sections": {"task_140": {"entries": [result], "_provenance": {"stages": {
        "evaluated": {"count": 4, "source_ids": sids},
        "deterministic": {"count": 0, "source_ids": []},
    }}}},
}
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    pp, ap = td / "parsed.json", td / "analyzed.json"
    pp.write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    ap.write_text(json.dumps(analyzed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    gate = v.validate_files(pp, ap)
check("streamed validator accepts empty-task semantic group", gate.get("status") == "ACCEPT", gate)

for label, mutator, expected in [
    ("representative identifier", lambda x: x.__setitem__("identifier", "tampered"), "task140_group_identifier_mismatch"),
    ("nonrepresentative source_id", lambda x: x["_source_ids"].__setitem__(2, "tampered"), "task140_group_source_id_mismatch"),
    ("semantic digest", lambda x: x.__setitem__("_task140_semantic_group_sha256", "0" * 64), "task140_group_semantic_digest_mismatch"),
    ("occurrence_count", lambda x: x.__setitem__("occurrence_count", 3), "task140_group_occurrence_count_mismatch"),
]:
    bad = copy.deepcopy(result)
    mutator(bad)
    got, why = a._result_entry_raw_indices("task_140", rows, bad)
    check(f"mutation {label} rejects", not got and why == expected, why)

bad_order = copy.deepcopy(result)
bad_order["_raw_source_indices"][1], bad_order["_raw_source_indices"][2] = bad_order["_raw_source_indices"][2], bad_order["_raw_source_indices"][1]
got, why = a._result_entry_raw_indices("task_140", rows, bad_order)
check("raw index order mutation rejects", not got and why == "task140_group_raw_indices_not_strictly_increasing", why)

print("\n[3] Description evidence remains semantic")
left = p.parse_task_event_text(raw_event(10, "2026-08-10T10:00:00Z", body="Date: ALPHA"), "140")[0]
right = p.parse_task_event_text(raw_event(11, "2026-08-10T11:00:00Z", body="Date: BRAVO"), "140")[0]
assign_source_ids("rev9-desc", "task_140", [left, right])
desc_reps, _ = a.aggregate_task140_depth1([left, right], [0, 1])
check("Description Date line prevents false merge", len(desc_reps) == 2, desc_reps)

print("\n[4] raw unevaluated accounting")
groups = {"raw_count": 10, "groups": [
    {"raw_indices": list(range(0, 7)), "occurrence_count": 7},
    {"raw_indices": list(range(7, 10)), "occurrence_count": 3},
]}
check("known failed representative expands exactly", a._task140_raw_unevaluated_count({"unevaluated_indices": [0]}, groups) == 7)
check("two failed representatives sum raw occurrences", a._task140_raw_unevaluated_count({"unevaluated_indices": [0, 7]}, groups) == 10)
check("unknown representative uses conservative raw_count", a._task140_raw_unevaluated_count({"unevaluated_indices": [999]}, groups) == 10)
source = Path(a.__file__).read_text(encoding="utf-8")
for marker in (
    '"error": "call_llm returned no result (falsy)"',
    '"error": result["error"]',
    '"parse_error": True',
):
    positions = []
    start = 0
    while True:
        pos = source.find(marker, start)
        if pos < 0:
            break
        positions.append(pos)
        start = pos + 1
    windows = [source[max(0, pos - 600):pos + 400] for pos in positions]
    ok = any('"unevaluated_indices": list(spec.source_indices)' in w for w in windows)
    check(f"hard-failure diag carries source indices near {marker[:22]}", ok,
          windows[-1][-500:] if windows else "marker not found")

print("\n[5] comparison occurrence_count semantics")
def run(label: str, occ: int):
    analyzed_doc = {"meta": {"source_id_algorithm_version": "1"}, "sections": {"task_140": {"entries": [{
        "source_id": "task_140:abc", "identifier": "same", "score": "LOW", "reason": "same",
        "occurrence_count": occ,
    }]}}}
    return cr.RunArtifacts(label, Path("."), Path("p"), Path("a"), {}, analyzed_doc)
issues = []
cr._compare_entries("reproducibility", run("A", 7), run("B", 8), issues, False)
check("occurrence_count difference is REVIEW-visible",
      any(x.get("kind") == "task140_occurrence_count_difference" and x.get("severity") == "REVIEW" for x in issues), issues)
issues_same = []
cr._compare_entries("reproducibility", run("A", 7), run("B", 7), issues_same, False)
check("equal occurrence_count adds no comparison noise",
      not any(x.get("kind") == "task140_occurrence_count_difference" for x in issues_same), issues_same)

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
