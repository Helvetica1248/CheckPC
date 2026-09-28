#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rev10 LLM-free real-data gate for weekday parsing and task_140 binding/order."""
from __future__ import annotations

import argparse
import copy
import json
import tempfile
from pathlib import Path

import analyze_section as a
import parse_checkpc as p
import validate_semantic_binding as v
from source_id import assign_source_ids


def one(root: Path, pattern: str) -> Path:
    rows = sorted(root.glob(pattern))
    if len(rows) != 1:
        raise SystemExit(f"expected exactly one {pattern}: {rows}")
    return rows[0]


def streamed_gate(events, results):
    parsed = {"sections": {}, "event_logs": {"task_140": events}}
    all_sids = [str(e.get("source_id") or "") for e in events]
    analyzed = {
        "meta": {"section_raw_evidence": {"task_140": {"count": len(events)}}},
        "sections": {"task_140": {"entries": results, "_provenance": {"stages": {
            "evaluated": {"count": len(all_sids), "source_ids": all_sids},
            "deterministic": {"count": 0, "source_ids": []},
        }}}},
    }
    with tempfile.TemporaryDirectory(prefix="checkpc_rev10_realdata_") as td:
        td = Path(td)
        pp, ap = td / "parsed.json", td / "analyzed.json"
        pp.write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        ap.write_text(json.dumps(analyzed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return v.validate_files(pp, ap)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("extracted_dir")
    args = ap.parse_args()
    root = Path(args.extracted_dir).resolve()
    checkpc = one(root, "CheckPC_*.txt")
    task140 = one(root, "Eventlog_TaskScheduler_Operational_140_*.txt")

    text = p.read_file(str(checkpc))
    sections = p.split_sections(text)
    directory = p.parse_directory(sections.get("directory", ""))
    startup = p.parse_startup_folder(sections.get("startup_folder", ""))

    task_text = p.read_file(str(task140))
    first_headers = [
        line.strip() for line in task_text.replace("\r\n", "\n").split("\n")
        if line.lstrip().startswith("Event[")
    ][:5]
    events = p.parse_task_event_text(task_text, "140")
    assign_source_ids("rev10-realdata-validation", "task_140", events)
    task_name_empty = sum(1 for e in events if not str(e.get("task_name") or ""))

    reps, info = a.aggregate_task140_depth1(events, list(range(len(events))))
    rep_indices = [g["raw_indices"][0] for g in info["groups"]]
    plan = a.resolve_chunk_plan(
        "task_140", reps, 1, lean=True, context="", source_indices=rep_indices
    )

    results = []
    for rep, group in zip(reps, info["groups"]):
        result = {
            "source_id": rep.get("source_id", ""),
            "identifier": a._canonical_identifier("task_140", rep),
            "score": "LOW",
            "reason": "rev10 real-data binding probe",
            "_raw_source_index": group["raw_indices"][0],
        }
        results.append(result)
    a._expand_task140_aggregation_results(results, info)

    bound = set()
    methods = {}
    failures = []
    for result in results:
        indices, method = a._result_entry_raw_indices("task_140", events, result)
        methods[method] = methods.get(method, 0) + 1
        if not indices:
            failures.append(method)
        bound.update(indices)

    semantic_gate = streamed_gate(events, results)
    order_ok = all(
        isinstance(g.get("raw_indices"), list)
        and g["raw_indices"] == sorted(g["raw_indices"])
        and len(g["raw_indices"]) == len(set(g["raw_indices"]))
        for g in info["groups"]
    )

    # Real-data mutation: swap non-representative raw indices and matching source IDs.
    mut_index = next((i for i, r in enumerate(results) if len(r.get("_raw_source_indices") or []) >= 3), None)
    swap_analyzer_reject = False
    swap_streamed_reject = False
    swap_detail = "no group with >=3 members"
    if mut_index is not None:
        mutated = copy.deepcopy(results)
        row = mutated[mut_index]
        for key in ("_raw_source_indices", "_source_ids"):
            row[key][1], row[key][2] = row[key][2], row[key][1]
        got, why = a._result_entry_raw_indices("task_140", events, row)
        swap_analyzer_reject = not got
        swap_detail = why
        swap_gate = streamed_gate(events, mutated)
        swap_streamed_reject = swap_gate.get("status") == "REJECT"

    checks = {
        "directory_681268": len(directory) == 681268,
        "startup_2": len(startup) == 2,
        "startup_webapi": any(str(x.get("path", "")).lower().endswith("webapi.lnk") for x in startup),
        "task140_raw_1000": len(events) == 1000,
        "task140_task_name_empty_1000": task_name_empty == 1000,
        "task140_groups_44": len(reps) == 44,
        "task140_collapsed_956": info.get("collapsed_count") == 956,
        "task140_chunks_8": len(plan.get("specs") or []) == 8,
        "task140_chunk_sizes": [len(x.entries) for x in plan.get("specs") or []] == [6, 6, 6, 6, 6, 6, 6, 2],
        "task140_source_ids_1000": sum(len(g["source_ids"]) for g in info["groups"]) == 1000,
        "task140_raw_indices_1000": sum(len(g["raw_indices"]) for g in info["groups"]) == 1000,
        "task140_raw_indices_canonical_order": order_ok,
        "task140_group_digests_present": all(len(str(g.get("semantic_key_sha256") or "")) == 64 for g in info["groups"]),
        "task140_bound_raw_1000": bound == set(range(len(events))),
        "task140_binding_mismatch_0": not failures,
        "task140_binding_method": methods == {"task140_semantic_group": 44},
        "streamed_semantic_binding_accept": semantic_gate.get("status") == "ACCEPT",
        "simultaneous_swap_analyzer_reject": swap_analyzer_reject,
        "simultaneous_swap_streamed_reject": swap_streamed_reject,
    }

    print(f"CHECKPC={checkpc}")
    print(f"TASK140={task140}")
    print(f"directory={len(directory)}")
    print(f"startup={len(startup)}")
    print(f"task140_event_headers={first_headers}")
    print(f"task140_raw={len(events)}")
    print(f"task140_task_name_empty={task_name_empty}")
    print(f"task140_groups={len(reps)}")
    print(f"task140_collapsed={info.get('collapsed_count')}")
    print(f"task140_chunks={len(plan.get('specs') or [])}")
    print(f"task140_chunk_sizes={[len(x.entries) for x in plan.get('specs') or []]}")
    print(f"task140_bound_raw={len(bound)}")
    print(f"task140_binding_methods={methods}")
    print(f"semantic_binding_status={semantic_gate.get('status')}")
    print(f"simultaneous_swap_analyzer={swap_detail}")
    print(f"simultaneous_swap_streamed_reject={swap_streamed_reject}")
    for name, ok in checks.items():
        print(("PASS" if ok else "REJECT") + f": {name}")
    ok = all(checks.values())
    print("REV10_REALDATA_GATE=" + ("PASS" if ok else "REJECT"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
