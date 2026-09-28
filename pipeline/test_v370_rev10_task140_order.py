#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 rev10: canonical task_140 group ordering and failure-reason regression."""
from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

import analyze_section as a
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


def raw_event(idx: int, dt: str) -> str:
    return (
        f"Event[{idx}]:\n"
        "  Log Name: Microsoft-Windows-TaskScheduler/Operational\n"
        f"  Date: {dt}\n"
        "  Event ID: 140\n"
        "  User: S-1-5-18\n"
        "  Computer: PC1\n"
        "  Description:\n"
        "  stable\n"
    )


def build():
    text = "".join(raw_event(i, f"2026-08-10T09:{i:02d}:00Z") for i in range(4))
    rows = p.parse_task_event_text(text, "140")
    assign_source_ids("rev10-order", "task_140", rows)
    reps, info = a.aggregate_task140_depth1(rows, list(range(len(rows))))
    result = {
        "source_id": reps[0]["source_id"],
        "identifier": a._canonical_identifier("task_140", reps[0]),
        "score": "LOW",
        "reason": "test",
        "_raw_source_index": 0,
    }
    a._expand_task140_aggregation_results([result], info)
    return rows, result


def streamed(rows, result):
    parsed = {"sections": {}, "event_logs": {"task_140": rows}}
    sids = [r["source_id"] for r in rows]
    analyzed = {
        "meta": {"section_raw_evidence": {"task_140": {"count": len(rows)}}},
        "sections": {"task_140": {"entries": [result], "_provenance": {"stages": {
            "evaluated": {"count": len(sids), "source_ids": sids},
            "deterministic": {"count": 0, "source_ids": []},
        }}}},
    }
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        pp, ap = td / "parsed.json", td / "analyzed.json"
        pp.write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        ap.write_text(json.dumps(analyzed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return v.validate_files(pp, ap)


rows, result = build()
indices, method = a._result_entry_raw_indices("task_140", rows, result)
check("normal semantic group analyzer ACCEPT", indices == {0, 1, 2, 3} and method == "task140_semantic_group", (indices, method))
check("normal semantic group streamed ACCEPT", streamed(rows, result).get("status") == "ACCEPT")
check("normal raw indices strictly increasing", result["_raw_source_indices"] == sorted(result["_raw_source_indices"]))
check("representative source ID is first member", result["source_id"] == result["_source_ids"][0])

cases = []

bad = copy.deepcopy(result)
bad["_raw_source_indices"][1], bad["_raw_source_indices"][2] = bad["_raw_source_indices"][2], bad["_raw_source_indices"][1]
cases.append(("raw index only swap", bad))

bad = copy.deepcopy(result)
for key in ("_raw_source_indices", "_source_ids"):
    bad[key][1], bad[key][2] = bad[key][2], bad[key][1]
cases.append(("raw index + source_id simultaneous swap", bad))

bad = copy.deepcopy(result)
bad["_raw_source_indices"][2] = bad["_raw_source_indices"][1]
bad["_source_ids"][2] = bad["_source_ids"][1]
cases.append(("duplicate raw index", bad))

bad = copy.deepcopy(result)
bad["_raw_source_indices"] = bad["_raw_source_indices"][1:] + bad["_raw_source_indices"][:1]
bad["_source_ids"] = bad["_source_ids"][1:] + bad["_source_ids"][:1]
cases.append(("representative moved away from first", bad))

for label, candidate in cases:
    got, why = a._result_entry_raw_indices("task_140", rows, candidate)
    check(f"analyzer rejects {label}", not got, why)
    gate = streamed(rows, candidate)
    check(f"streamed validator rejects {label}", gate.get("status") == "REJECT", gate)

# P2 non-regression: final coverage diagnostics retain original transport/parse cause.
source = Path(a.__file__).read_text(encoding="utf-8")
check("coverage diagnostic preserves failure_reason field", 'diag["failure_reason"]' in source)
check("hard failure source_indices preserved", source.count('"source_indices": list(spec.source_indices)') >= 4)
check("hard failure unevaluated_indices preserved", source.count('"unevaluated_indices": list(spec.source_indices)') >= 4)

# Execute a real chunk-failure path: one representative stands for seven raw events.
rows7 = p.parse_task_event_text(
    "".join(raw_event(i, f"2026-08-10T10:{i:02d}:00Z") for i in range(7)), "140")
assign_source_ids("rev10-failure", "task_140", rows7)
reps7, info7 = a.aggregate_task140_depth1(rows7, list(range(7)))
old_call = a._call_llm_score_checked
a._call_llm_score_checked = lambda *args, **kwargs: {"parse_error": True, "raw_response": "truncated"}
try:
    _, _, errors7, _ = a.call_llm_chunked(
        None, "stub", "task_140", 1, reps7, lean=True, source_indices=[0])
finally:
    a._call_llm_score_checked = old_call
check("parse_error final diagnostic retains source_indices",
      len(errors7) == 1 and errors7[0].get("source_indices") == [0], errors7)
check("parse_error final diagnostic retains failure_reason",
      len(errors7) == 1 and "parse_error" in str(errors7[0].get("failure_reason") or ""), errors7)
check("one failed representative is counted as raw seven",
      len(errors7) == 1 and a._task140_raw_unevaluated_count(errors7[0], info7) == 7, errors7)

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
