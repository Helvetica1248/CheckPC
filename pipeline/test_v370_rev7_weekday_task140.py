#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 rev7: CheckPC 6.11.2 weekday dir compatibility + D1 task_140 aggregation."""
from __future__ import annotations

from pathlib import Path

import analyze_section as a
import parse_checkpc as p
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


print("[1] Japanese dir weekday compatibility")
base = """ C:\\Users\\Public のディレクトリ
2026/08/10  09:16            12,288 plain.exe
2026/08/10 月  09:17             1,234 weekday.vbe
2026/08/10 (月) 09:18               555 paren.cmd
2026/08/10 月曜日 09:19              42 longweekday.ps1
"""
rows = p.parse_directory(base)
check("weekday-less and weekday forms all parse", len(rows) == 4, rows)
check("weekday token is normalized out of date", [x["date"] for x in rows] == [
    "2026/08/10  09:16", "2026/08/10  09:17",
    "2026/08/10  09:18", "2026/08/10  09:19",
], [x["date"] for x in rows])
check("file names remain intact", [x["name"] for x in rows] == [
    "plain.exe", "weekday.vbe", "paren.cmd", "longweekday.ps1"
], rows)

startup = """  C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup のディレクトリ
2026/08/10 月  09:17             1,234 run.vbe
2026/08/10  09:18             2,000 normal.lnk
"""
startup_rows = p.parse_startup_folder(startup)
check("startup parser accepts weekday and legacy forms", len(startup_rows) == 2, startup_rows)
check("startup weekday entry remains suspicious", startup_rows[0]["suspicious"] is True, startup_rows[0])


print("\n[2] task_140 semantic aggregation")

def evt(idx: int, dt: str, task: str, actor: str = "S-1-5-18", message_suffix: str = "updated") -> dict:
    raw = (
        f"Event[{idx}]\n"
        "  Log Name: Microsoft-Windows-TaskScheduler/Operational\n"
        "  Source: Microsoft-Windows-TaskScheduler\n"
        f"  Date: {dt}\n"
        "  Event ID: 140\n"
        "  Task: Task registration updated\n"
        f"  User: {actor}\n"
        "  Computer: PC1\n"
        "  Description:\n"
        f"actor={actor} task={task} {message_suffix}\n"
    )
    return {
        "event_id": "140",
        "datetime": dt,
        "task_name": task,
        "user": actor,
        "raw": raw,
    }

entries = [
    evt(0, "2026-08-01T00:00:00Z", r"\\Microsoft\\Windows\\X"),
    evt(1, "2026-08-02T00:00:00Z", r"\\Microsoft\\Windows\\X"),
    evt(2, "2026-08-03T00:00:00Z", r"\\Microsoft\\Windows\\X"),
    evt(3, "2026-08-01T01:00:00Z", r"\\Microsoft\\Windows\\Y"),
    evt(4, "2026-08-01T02:00:00Z", r"\\Microsoft\\Windows\\X", actor="S-1-5-21"),
    evt(5, "2026-08-01T03:00:00Z", r"\\Microsoft\\Windows\\X", message_suffix="different-message"),
]
assign_source_ids("rev7-test", "task_140", entries)
reps, info = a.aggregate_task140_depth1(entries, list(range(len(entries))))
check("only timestamp/event-index duplicates collapse", len(reps) == 4, info)
check("collapsed count is exact", info["collapsed_count"] == 2, info)
first = info["groups"][0]
check("occurrence count preserved", first["occurrence_count"] == 3, first)
check("first_seen preserved", first["first_seen"] == "2026-08-01T00:00:00Z", first)
check("last_seen preserved", first["last_seen"] == "2026-08-03T00:00:00Z", first)
check("all raw indices preserved", first["raw_indices"] == [0, 1, 2], first)
check("all source IDs preserved", len(first["source_ids"]) == 3 and len(set(first["source_ids"])) == 3, first)
check("representative exposes audit window to LLM", reps[0].get("occurrence_count") == 3 and reps[0].get("first_seen") and reps[0].get("last_seen"), reps[0])

# Simulate the binding fields returned from the representative LLM evaluation.
result = {
    "source_id": reps[0]["source_id"],
    "identifier": a._canonical_identifier("task_140", reps[0]),
    "score": "LOW",
    "reason": "test",
    "_raw_source_index": 0,
}
a._expand_task140_aggregation_results([result], info)
indices, method = a._result_entry_raw_indices("task_140", entries, result)
check("aggregated result resolves back to every raw event", indices == {0, 1, 2}, (indices, method, result))
check("aggregated result uses explicit semantic-group attribution", method == "task140_semantic_group", method)
check("single-record raw index is replaced by full raw-index vector",
      "_raw_source_index" not in result and result.get("_raw_source_indices") == [0, 1, 2], result)

# Description is semantic evidence even when a line looks like header metadata.
desc_a = evt(10, "2026-08-01T04:00:00Z", r"\Task\Z")
desc_b = evt(11, "2026-08-02T04:00:00Z", r"\Task\Z")
desc_a["raw"] += "Date: semantic-marker-A\n"
desc_b["raw"] += "Date: semantic-marker-B\n"
assign_source_ids("rev7-description", "task_140", [desc_a, desc_b])
desc_reps, _desc_info = a.aggregate_task140_depth1([desc_a, desc_b], [0, 1])
check("Date-like lines inside Description remain semantic", len(desc_reps) == 2, [x.get("raw") for x in desc_reps])

# A result that cannot bind to the representative must not inherit the group.
unbound = {"identifier": "unknown", "score": "LOW", "reason": "test"}
a._expand_task140_aggregation_results([unbound], info)
unbound_indices, _unbound_method = a._result_entry_raw_indices("task_140", entries, unbound)
check("unbound representative result fails closed", not unbound_indices, (_unbound_method, unbound))


print("\n[3] D1-only integration and bounded chunk count")
# 1,000 records across 44 semantic groups.  The D1 fixed chunk size remains 6,
# so aggregation must reduce 167 chunks to 8 without dropping any source IDs.
large = []
for i in range(1000):
    group = i % 44
    large.append(evt(i, f"2026-08-{1 + (i % 9):02d}T{i % 24:02d}:00:00Z", rf"\\Task\\G{group:02d}"))
assign_source_ids("rev7-large", "task_140", large)
large_reps, large_info = a.aggregate_task140_depth1(large, list(range(1000)))
plan = a.resolve_chunk_plan(
    "task_140", large_reps, 1, lean=True, context="",
    source_indices=[g["raw_indices"][0] for g in large_info["groups"]],
)
check("1000 raw events become 44 semantic groups", len(large_reps) == 44, large_info["group_count"])
check("all 1000 source IDs remain represented", sum(len(g["source_ids"]) for g in large_info["groups"]) == 1000)
check("D1 task_140 becomes 8 chunks at size 6", len(plan["specs"]) == 8 and max(len(x.entries) for x in plan["specs"]) <= 6,
      [len(x.entries) for x in plan["specs"]])

source = Path(a.__file__).read_text(encoding="utf-8")
check("aggregation is gated to depth=1 task_140",
      'depth == 1 and sec == "task_140"' in source)
check("no Microsoft/task-name allowlist introduced",
      "UpdateOrchestrator" not in source and "SvcRestartTask" not in source and "OneSettings" not in source)



print("\n[4] report multiplicity preservation")
import report_gen as rg
low_rows = rg._aggregate_low_entries([
    {"identifier": "Task A", "score": "LOW", "occurrence_count": 7},
    {"identifier": "Task B", "score": "LOW", "occurrence_count": 3},
], "task_140")
check("task140 LOW report counts raw observations", any("| 10 |" in row for row in low_rows), low_rows)
check("task140 LOW representative shows multiplicity", any("×7件" in row for row in low_rows), low_rows)
check("task140 MEDIUM is excluded from generic display aggregation", "task_140" in rg._MED_AGG_EXCLUDE_SECTIONS, rg._MED_AGG_EXCLUDE_SECTIONS)
check("task140 individual identifier shows multiplicity", rg._display_identifier({"identifier": "Task A", "occurrence_count": 5}, "task_140").endswith("×5件）"))

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
