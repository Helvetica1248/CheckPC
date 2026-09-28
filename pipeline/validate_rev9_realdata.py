#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rev9 real-data gate for CheckPC 6.11.2 weekday/task_140 compatibility.

This validator is LLM-free.  It proves parser counts, semantic aggregation,
explicit one-to-many binding, the streamed semantic-binding gate, and the D1
chunk plan against an extracted CAB directory.
"""
from __future__ import annotations

import argparse
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
    first_event_headers = [
        line.strip() for line in task_text.replace("\r\n", "\n").split("\n")
        if line.lstrip().startswith("Event[")
    ][:5]
    events = p.parse_task_event_text(task_text, "140")
    assign_source_ids("rev9-realdata-validation", "task_140", events)
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
            "reason": "rev9 real-data binding probe",
            "_raw_source_index": group["raw_indices"][0],
        }
        results.append(result)
    a._expand_task140_aggregation_results(results, info)

    bound = set()
    binding_methods = {}
    binding_failures = []
    for result in results:
        indices, method = a._result_entry_raw_indices("task_140", events, result)
        binding_methods[method] = binding_methods.get(method, 0) + 1
        if not indices:
            binding_failures.append(method)
        bound.update(indices)

    parsed = {"sections": {}, "event_logs": {"task_140": events}}
    all_sids = [str(e.get("source_id") or "") for e in events]
    analyzed = {
        "meta": {"section_raw_evidence": {"task_140": {"count": len(events)}}},
        "sections": {
            "task_140": {
                "entries": results,
                "_provenance": {
                    "stages": {
                        "evaluated": {"count": len(all_sids), "source_ids": all_sids},
                        "deterministic": {"count": 0, "source_ids": []},
                    }
                },
            }
        },
    }
    with tempfile.TemporaryDirectory(prefix="checkpc_rev9_realdata_") as td:
        td = Path(td)
        parsed_path = td / "parsed.json"
        analyzed_path = td / "analyzed.json"
        parsed_path.write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        analyzed_path.write_text(json.dumps(analyzed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        semantic_gate = v.validate_files(parsed_path, analyzed_path)

    checks = {
        "directory_681268": len(directory) == 681268,
        "startup_2": len(startup) == 2,
        "startup_webapi": any(str(x.get("path", "")).lower().endswith("webapi.lnk") for x in startup),
        "task140_raw_1000": len(events) == 1000,
        "task140_task_name_empty_1000": task_name_empty == 1000,
        "task140_groups_44": len(reps) == 44,
        "task140_collapsed_956": info.get("collapsed_count") == 956,
        "task140_chunks_8": len(plan.get("specs") or []) == 8,
        "task140_source_ids_1000": sum(len(g["source_ids"]) for g in info["groups"]) == 1000,
        "task140_raw_indices_1000": sum(len(g["raw_indices"]) for g in info["groups"]) == 1000,
        "task140_group_digests_present": all(
            len(str(g.get("semantic_key_sha256") or "")) == 64 for g in info["groups"]
        ),
        "task140_bound_raw_1000": bound == set(range(len(events))),
        "task140_binding_mismatch_0": not binding_failures,
        "task140_binding_method": binding_methods == {"task140_semantic_group": 44},
        "streamed_semantic_binding_accept": semantic_gate.get("status") == "ACCEPT",
    }

    print(f"CHECKPC={checkpc}")
    print(f"TASK140={task140}")
    print(f"directory={len(directory)}")
    print(f"startup={len(startup)}")
    print(f"task140_event_headers={first_event_headers}")
    print(f"task140_raw={len(events)}")
    print(f"task140_task_name_empty={task_name_empty}")
    print(f"task140_groups={len(reps)}")
    print(f"task140_collapsed={info.get('collapsed_count')}")
    print(f"task140_chunks={len(plan.get('specs') or [])}")
    print(f"task140_chunk_sizes={[len(x.entries) for x in plan.get('specs') or []]}")
    print(f"task140_source_ids={sum(len(g['source_ids']) for g in info['groups'])}")
    print(f"task140_bound_raw={len(bound)}")
    print(f"task140_binding_methods={binding_methods}")
    print(f"semantic_binding_status={semantic_gate.get('status')}")
    if semantic_gate.get("errors"):
        print("semantic_binding_errors=" + json.dumps(semantic_gate.get("errors"), ensure_ascii=False))

    for name, ok in checks.items():
        print(("PASS" if ok else "REJECT") + f": {name}")
    ok = all(checks.values())
    print("REV9_REALDATA_GATE=" + ("PASS" if ok else "REJECT"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
