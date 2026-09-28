#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 rev8: task_140 semantic-group binding hardening regression."""
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


def evt(idx: int, dt: str, task: str = r"\Task\Same", *,
        desc_label: str = "Description", desc_line: str = "stable") -> dict:
    raw = (
        f"  Event[{idx}]:\n"
        "  Log Name: Microsoft-Windows-TaskScheduler/Operational\n"
        f"  Date: {dt}\n"
        "  Event ID: 140\n"
        "  User: S-1-5-18\n"
        "  Computer: PC1\n"
        f"  {desc_label}:\n"
        f"  {desc_line}\n"
    )
    return {
        "event_id": "140",
        "datetime": dt,
        "task_name": task,
        "user": "S-1-5-18",
        "raw": raw,
    }


print("[1] Event header / Description locale boundary")
colon_rows = [evt(i, f"2026-08-10T09:{i:02d}:00Z") for i in range(10)]
assign_source_ids("rev8-colon", "task_140", colon_rows)
colon_reps, colon_info = a.aggregate_task140_depth1(colon_rows, list(range(10)))
check("indented Event[n]: headers collapse", len(colon_reps) == 1, colon_info)
check("colon-header collapse count exact", colon_info.get("collapsed_count") == 9, colon_info)

for label in ("説明", "描述"):
    left = evt(20, "2026-08-10T10:00:00Z", desc_label=label, desc_line="日時: ALPHA")
    right = evt(21, "2026-08-10T11:00:00Z", desc_label=label, desc_line="日時: BRAVO")
    assign_source_ids(f"rev8-{label}", "task_140", [left, right])
    reps, _ = a.aggregate_task140_depth1([left, right], [0, 1])
    check(f"{label}: body 日時 line remains semantic", len(reps) == 2, [x.get("raw") for x in reps])


print("\n[2] explicit one-to-many source binding")
rows = [evt(i, f"2026-08-10T12:{i:02d}:00Z") for i in range(5)]
assign_source_ids("rev8-binding", "task_140", rows)
reps, info = a.aggregate_task140_depth1(rows, list(range(5)))
result = {
    "source_id": reps[0]["source_id"],
    "identifier": a._canonical_identifier("task_140", reps[0]),
    "score": "LOW",
    "reason": "test",
    "_raw_source_index": 0,
}
a._expand_task140_aggregation_results([result], info)
indices, method = a._result_entry_raw_indices("task_140", rows, result)
check("all five raw indices resolve", indices == set(range(5)), (indices, method, result))
check("binding method is semantic group", method == "task140_semantic_group", method)
check("source-id vector has exact cardinality", len(result.get("_source_ids") or []) == 5, result)
check("semantic digest is recorded", len(result.get("_task140_semantic_group_sha256") or "") == 64, result)

parsed = {"sections": {}, "event_logs": {"task_140": rows}}
analyzed = {
    "meta": {"section_raw_evidence": {"task_140": {"count": 5}}},
    "sections": {
        "task_140": {
            "entries": [result],
            "_provenance": {
                "stages": {
                    "evaluated": {"count": 5, "source_ids": [x["source_id"] for x in rows]},
                    "deterministic": {"count": 0, "source_ids": []},
                }
            },
        }
    },
}
mem = v.validate(parsed, analyzed)
check("in-memory semantic validator ACCEPT", mem.get("status") == "ACCEPT", mem)

with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    parsed_path = td / "parsed.json"
    analyzed_path = td / "analyzed.json"
    parsed_path.write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    analyzed_path.write_text(json.dumps(analyzed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    streamed = v.validate_files(parsed_path, analyzed_path)
check("streamed semantic validator ACCEPT", streamed.get("status") == "ACCEPT", streamed)

partial_provenance = copy.deepcopy(analyzed)
partial_provenance["sections"]["task_140"]["_provenance"]["stages"]["evaluated"]["source_ids"] = [
    x["source_id"] for x in rows[1:]
]
partial_provenance["sections"]["task_140"]["_provenance"]["stages"]["evaluated"]["count"] = 4
partial_gate = v.validate(parsed, partial_provenance)
# validate() is intentionally provenance-light; the strict file validator owns
# evaluated-stage membership checks. Exercise that path below.
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    parsed_path = td / "parsed.json"
    analyzed_path = td / "analyzed.json"
    parsed_path.write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    analyzed_path.write_text(json.dumps(partial_provenance, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    partial_streamed = v.validate_files(parsed_path, analyzed_path)
check("partial evaluated source-id group is REJECT",
      partial_streamed.get("status") == "REJECT"
      and any(e.get("detail") == "task140_group_evaluated_source_ids_incomplete"
              for e in partial_streamed.get("errors", [])), partial_streamed)

for field, mutate in (
    ("source_ids", lambda x: x["_source_ids"].__setitem__(2, "src:tampered")),
    ("digest", lambda x: x.__setitem__("_task140_semantic_group_sha256", "0" * 64)),
    ("identifier", lambda x: x.__setitem__("identifier", "different-task")),
    ("occurrence_count", lambda x: x.__setitem__("occurrence_count", 4)),
):
    bad = copy.deepcopy(result)
    mutate(bad)
    bad_indices, bad_method = a._result_entry_raw_indices("task_140", rows, bad)
    check(f"mutation {field} fails closed", not bad_indices, bad_method)


print("\n[3] legacy date-spacing stability")
dir_text = (
    " C:\\Temp のディレクトリ\n"
    "2026/08/10 09:16             1 one.exe\n"
    "2026/08/10   09:17             2 three.exe\n"
    "2026/08/10\t09:18             3 tab.exe\n"
    "2026/08/10 月  09:19             4 weekday.exe\n"
)
dir_rows = p.parse_directory(dir_text)
check("legacy separator forms remain accepted", len(dir_rows) == 4, dir_rows)
check("one-space separator preserved", dir_rows[0]["date"] == "2026/08/10 09:16", dir_rows[0])
check("three-space separator preserved", dir_rows[1]["date"] == "2026/08/10   09:17", dir_rows[1])
check("tab separator preserved", dir_rows[2]["date"] == "2026/08/10\t09:18", repr(dir_rows[2]["date"]))
check("weekday token removed canonically", dir_rows[3]["date"] == "2026/08/10  09:19", dir_rows[3])
check("one-digit hour remains rejected as pre-rev7", not p.parse_directory(" C:\\Temp のディレクトリ\n2026/08/10  9:16 1 x.exe\n"))


print("\n[4] failed representative count expands to raw occurrence count")
# Two representative groups with 7 and 3 raw observations. If representative
# raw index 0 fails, the user-facing maximum unevaluated count must be 7, not 1.
groups = {
    "groups": [
        {"raw_indices": list(range(0, 7)), "occurrence_count": 7},
        {"raw_indices": list(range(7, 10)), "occurrence_count": 3},
    ]
}
count = a._task140_raw_unevaluated_count({"unevaluated_indices": [0]}, groups)
check("failed representative maps to seven raw observations", count == 7, count)

source = Path(a.__file__).read_text(encoding="utf-8")
check("dead _aggregation_source_indices field removed", "_aggregation_source_indices" not in source)

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
