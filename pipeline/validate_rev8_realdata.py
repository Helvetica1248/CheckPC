#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Manual rev8 validation against an extracted CheckPC 6.11.2 CAB directory."""
from __future__ import annotations

import argparse
from pathlib import Path

import analyze_section as a
import parse_checkpc as p
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
    assign_source_ids("rev8-realdata-validation", "task_140", events)
    reps, info = a.aggregate_task140_depth1(events, list(range(len(events))))
    rep_indices = [g["raw_indices"][0] for g in info["groups"]]
    plan = a.resolve_chunk_plan(
        "task_140", reps, 1, lean=True, context="", source_indices=rep_indices
    )

    checks = {
        "directory_681268": len(directory) == 681268,
        "startup_2": len(startup) == 2,
        "startup_webapi": any(str(x.get("path", "")).lower().endswith("webapi.lnk") for x in startup),
        "task140_raw_1000": len(events) == 1000,
        "task140_groups_44": len(reps) == 44,
        "task140_collapsed_956": info.get("collapsed_count") == 956,
        "task140_chunks_8": len(plan.get("specs") or []) == 8,
        "task140_source_ids_1000": sum(len(g["source_ids"]) for g in info["groups"]) == 1000,
        "task140_raw_indices_1000": sum(len(g["raw_indices"]) for g in info["groups"]) == 1000,
        "task140_group_digests_present": all(
            len(str(g.get("semantic_key_sha256") or "")) == 64 for g in info["groups"]
        ),
    }

    print(f"CHECKPC={checkpc}")
    print(f"TASK140={task140}")
    print(f"directory={len(directory)}")
    print(f"startup={len(startup)}")
    print(f"task140_event_headers={first_event_headers}")
    print(f"task140_raw={len(events)}")
    print(f"task140_groups={len(reps)}")
    print(f"task140_collapsed={info.get('collapsed_count')}")
    print(f"task140_chunks={len(plan.get('specs') or [])}")
    print(f"task140_chunk_sizes={[len(x.entries) for x in plan.get('specs') or []]}")
    print(f"task140_source_ids={sum(len(g['source_ids']) for g in info['groups'])}")

    for name, ok in checks.items():
        print(("PASS" if ok else "REJECT") + f": {name}")
    ok = all(checks.values())
    print("REV8_REALDATA_GATE=" + ("PASS" if ok else "REJECT"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
