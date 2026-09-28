#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 all-raw rule provenance and coverage checker regressions."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import analyze_section
from atomic_io import atomic_write_json
from compare_runs import compare_runs, load_run
from comparison_release_gate import current_package_manifest_sha256
from comparison_provenance import (
    COMPARISON_PROVENANCE_SCHEMA_VERSION,
    annotate_parsed_document,
    missing_raw_backed_provenance_sections,
    sha256_file,
    stage_indices,
    validate_section_provenance,
)
from source_id import SOURCE_ID_ALGORITHM_VERSION, assign_source_ids
from version import (
    ANALYSIS_SCHEMA_VERSION,
    BUDGET_PROFILE_DEFAULT,
    PIPELINE_VERSION,
)

PASS = FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [OK]  {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}: {detail}")


def fixture(*, empty: bool = False) -> dict:
    userassist = [] if empty else [
        {
            "path": r"C:\Users\fixture\Downloads\sample.exe",
            "last_run": "2026-07-27 12:00:00",
            "run_count": 2,
        },
        {
            "path": r"C:\Windows\System32\notepad.exe",
            "last_run": "2026-07-27 12:01:00",
            "run_count": 4,
        },
        {
            "path": "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App",
            "last_run": "2026-07-27 12:02:00",
            "run_count": 1,
        },
    ]
    task_141 = [] if empty else [
        {
            "identifier": "EventID 141: FixtureTask",
            "task_name": "FixtureTask",
            "datetime": "2026-07-27 12:03:00",
        }
    ]
    rdp_inbound = [] if empty else [
        {
            "event_id": 1149,
            "source_ip": "203.0.113.10",
            "user": "fixture",
            "datetime": "2026-07-27 12:04:00",
        },
        {
            "event_id": 21,
            "source_ip": "192.168.1.10",
            "user": "fixture",
            "datetime": "2026-07-27 12:05:00",
        },
    ]
    parsed = {
        "meta": {
            "hostname": "HOST-REF-11-RC24-FIXTURE",
            "datestamp": "20260727120500",
            "input_sha256": "a" * 64,
            "collection_id": "b" * 64,
            "parser_version": ANALYSIS_SCHEMA_VERSION,
            "pipeline_version": PIPELINE_VERSION,
            "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
            "package_manifest_sha256": current_package_manifest_sha256(),
        },
        "sections": {"userassist": userassist},
        "event_logs": {
            "task_141": task_141,
            "rdp_inbound": rdp_inbound,
        },
        "evidence_quality": {
            "task_141": {"evidence_state": "EMPTY_UNVERIFIED" if empty else "OBSERVED"}
        },
    }
    for section, rows in parsed["sections"].items():
        assign_source_ids(parsed["meta"]["collection_id"], section, rows)
    for section, rows in parsed["event_logs"].items():
        assign_source_ids(parsed["meta"]["collection_id"], section, rows)
    annotate_parsed_document(parsed)
    return parsed


def run_rules(parsed: dict, *, depth: int, lean: bool) -> dict:
    return analyze_section.analyze(
        parsed,
        depth,
        object(),
        "qwen25-coder-32b-q3",
        target_sections=["task_141", "rdp_inbound", "userassist"],
        lean=lean,
    )


def make_run(root: Path, name: str, parsed: dict, analyzed: dict) -> Path:
    run = root / name
    run.mkdir()
    parsed_path = run / "parsed_HOST-REF-11-RC24-FIXTURE_20260727120500.json"
    analyzed_path = run / "analyzed_HOST-REF-11-RC24-FIXTURE_20260727120500.json"
    atomic_write_json(parsed_path, parsed)
    analyzed = copy.deepcopy(analyzed)
    analyzed["meta"]["parsed_artifact_sha256"] = sha256_file(parsed_path)
    atomic_write_json(analyzed_path, analyzed)
    return run


def assert_rule_provenance(label: str, result: dict, raw_count: int, reason: str):
    provenance = result.get("_provenance")
    check(f"{label}: provenance present", isinstance(provenance, dict), provenance)
    if not isinstance(provenance, dict):
        return
    check(f"{label}: provenance validates", validate_section_provenance(provenance) == [],
          validate_section_provenance(provenance))
    check(f"{label}: raw_count", provenance.get("raw_count") == raw_count, provenance)
    check(f"{label}: all raw deterministic",
          stage_indices(provenance, "deterministic") == set(range(raw_count)), provenance)
    check(f"{label}: selected/evaluated/unevaluated empty",
          stage_indices(provenance, "selected") == set()
          and stage_indices(provenance, "evaluated") == set()
          and stage_indices(provenance, "unevaluated") == set(), provenance)
    check(f"{label}: complete and attribution clean",
          provenance.get("provenance_complete") is True
          and provenance.get("attribution_error_count") == 0, provenance)
    det = provenance["stages"]["deterministic"]
    check(f"{label}: deterministic source ID coverage",
          det.get("source_ids_complete") is True
          and len(det.get("source_ids") or []) == raw_count, det)
    check(f"{label}: deterministic reason",
          reason in (provenance.get("reasons") or {}).get("deterministic", {}), provenance)
    stats = result.get("_selection_stats")
    check(f"{label}: selection stats",
          isinstance(stats, dict)
          and stats.get("raw") == raw_count
          and stats.get("deterministic") == raw_count
          and stats.get("selected") == 0
          and stats.get("evaluated") == 0
          and stats.get("selected_unevaluated") == 0
          and stats.get("provenance_complete") is True, stats)


print("\n--- rc24 identity and unchanged provenance schema ---")
check("pipeline version", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("analysis schema", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("budget profile", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)
check("comparison provenance schema remains 1",
      COMPARISON_PROVENANCE_SCHEMA_VERSION == "1", COMPARISON_PROVENANCE_SCHEMA_VERSION)
check("source ID algorithm remains 1", SOURCE_ID_ALGORITHM_VERSION == "1",
      SOURCE_ID_ALGORITHM_VERSION)

print("\n--- all-raw rule sections across Depth1/Depth2 and FULL/LEAN ---")
parsed = fixture(empty=False)
outputs = {}
for depth in (1, 2):
    for lean in (False, True):
        key = f"d{depth}-{'lean' if lean else 'full'}"
        out = run_rules(copy.deepcopy(parsed), depth=depth, lean=lean)
        outputs[key] = out
        sections = out["sections"]
        assert_rule_provenance(f"{key} task_141", sections["task_141"], 1,
                               "task_deleted_rule")
        assert_rule_provenance(f"{key} rdp_inbound", sections["rdp_inbound"], 2,
                               "rdp_inbound_rule")
        assert_rule_provenance(f"{key} userassist", sections["userassist"], 3,
                               "userassist_rule")
        check(f"{key}: userassist display filtering unchanged",
              len(sections["userassist"].get("entries") or []) == 1,
              sections["userassist"].get("entries"))

print("\n--- empty raw sections retain complete empty provenance ---")
empty_parsed = fixture(empty=True)
empty_out = run_rules(empty_parsed, depth=2, lean=True)
for section, reason in (
    ("task_141", "task_deleted_rule"),
    ("rdp_inbound", "rdp_inbound_rule"),
    ("userassist", "userassist_rule"),
):
    assert_rule_provenance(f"empty {section}", empty_out["sections"][section], 0, reason)

print("\n--- coverage helper and official self comparison ---")
representative = outputs["d2-lean"]
check("no raw-backed provenance missing",
      missing_raw_backed_provenance_sections(parsed, representative) == [],
      missing_raw_backed_provenance_sections(parsed, representative))
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    good = make_run(root, "good", parsed, representative)
    a = load_run(str(good), "A")
    b = load_run(str(good), "B")
    try:
        comparison = compare_runs("reproducibility", a, b)
    finally:
        a.close(); b.close()
    check("complete self comparison PASS", comparison.get("status") == "PASS", comparison)
    check("complete self comparison exit 0", comparison.get("exit_code") == 0, comparison)

    broken_analyzed = copy.deepcopy(representative)
    broken_analyzed["sections"]["userassist"].pop("_provenance", None)
    broken = make_run(root, "broken", parsed, broken_analyzed)
    check("coverage helper finds userassist",
          missing_raw_backed_provenance_sections(parsed, broken_analyzed) == ["userassist"],
          missing_raw_backed_provenance_sections(parsed, broken_analyzed))
    a = load_run(str(broken), "A")
    b = load_run(str(broken), "B")
    try:
        rejected = compare_runs("reproducibility", a, b)
    finally:
        a.close(); b.close()
    missing_issues = [
        row for row in rejected.get("issues", [])
        if row.get("kind") == "section_provenance_missing"
        and row.get("section") == "userassist"
    ]
    check("official comparison rejects missing provenance",
          rejected.get("status") == "INPUT_ERROR" and rejected.get("exit_code") == 2,
          rejected)
    check("official comparison reports both sides", len(missing_issues) == 2, missing_issues)

    parsed_path = broken / "parsed_HOST-REF-11-RC24-FIXTURE_20260727120500.json"
    analyzed_path = broken / "analyzed_HOST-REF-11-RC24-FIXTURE_20260727120500.json"
    proc = subprocess.run(
        [sys.executable, str(HERE / "validate_run_provenance.py"),
         str(parsed_path), str(analyzed_path)],
        cwd=HERE, capture_output=True, text=True,
    )
    check("lightweight checker fails closed", proc.returncode == 1, proc.stdout + proc.stderr)
    check("lightweight checker names userassist", '"userassist"' in proc.stdout, proc.stdout)

print("\n--- prior secret-free logging remains present ---")
source = (HERE / "vt_post.py").read_text(encoding="utf-8")
check(".env logger remains key-only", "loaded_keys = sorted(loaded)" in source,
      "key-only logger missing")
check("loaded values are not formatted", "→ {loaded}" not in source and "→ {masked}" not in source,
      "unsafe mapping formatting remains")

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(1 if FAIL else 0)
