#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 Defender deterministic provenance regressions."""
from __future__ import annotations

import json
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


def fixture(raw):
    parsed = {
        "meta": {
            "hostname": "HOST-REF-11-FIXTURE",
            "datestamp": "20260727120001",
            "input_sha256": "a" * 64,
            "collection_id": "b" * 64,
            "parser_version": ANALYSIS_SCHEMA_VERSION,
            "pipeline_version": PIPELINE_VERSION,
            "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
            "package_manifest_sha256": current_package_manifest_sha256(),
        },
        "sections": {"defender_quarantine": raw},
        "event_logs": {},
        "evidence_quality": {},
    }
    assign_source_ids(parsed["meta"]["collection_id"], "defender_quarantine", raw)
    annotate_parsed_document(parsed)
    return parsed


def run_defender(parsed, *, lean):
    return analyze_section.analyze(
        parsed,
        2,
        object(),
        "qwen25-coder-32b-q3",
        target_sections=["defender_quarantine"],
        lean=lean,
    )


def make_run(root: Path, name: str, parsed: dict, analyzed: dict) -> Path:
    run = root / name
    run.mkdir()
    parsed_path = run / "parsed_HOST-REF-11-FIXTURE_20260727120001.json"
    atomic_write_json(parsed_path, parsed)
    analyzed = json.loads(json.dumps(analyzed, ensure_ascii=False))
    analyzed["meta"]["parsed_artifact_sha256"] = sha256_file(parsed_path)
    atomic_write_json(run / "analyzed_HOST-REF-11-FIXTURE_20260727120001.json", analyzed)
    return run


print("\n--- rc23 identity and unchanged comparison schema ---")
check("pipeline version", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("analysis schema", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("budget profile", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)
check("comparison provenance schema remains 1",
      COMPARISON_PROVENANCE_SCHEMA_VERSION == "1", COMPARISON_PROVENANCE_SCHEMA_VERSION)
check("source ID algorithm remains 1", SOURCE_ID_ALGORITHM_VERSION == "1", SOURCE_ID_ALGORITHM_VERSION)

print("\n--- empty Defender section has complete provenance ---")
empty_parsed = fixture([])
empty_out = run_defender(empty_parsed, lean=True)
empty_result = empty_out["sections"]["defender_quarantine"]
empty_prov = empty_result["_provenance"]
check("empty provenance validates", validate_section_provenance(empty_prov) == [],
      validate_section_provenance(empty_prov))
check("empty raw_count is zero", empty_prov.get("raw_count") == 0, empty_prov)
check("empty provenance complete", empty_prov.get("provenance_complete") is True, empty_prov)
check("empty deterministic set", stage_indices(empty_prov, "deterministic") == set(), empty_prov)
check("empty selected/evaluated/unevaluated",
      stage_indices(empty_prov, "selected") == set()
      and stage_indices(empty_prov, "evaluated") == set()
      and stage_indices(empty_prov, "unevaluated") == set(), empty_prov)
for stage_name in ("mandatory", "deterministic", "selected", "evaluated", "unevaluated"):
    row = empty_prov["stages"][stage_name]
    check(f"empty {stage_name} source IDs complete",
          row.get("source_ids_complete") is True and row.get("source_ids") == [], row)

print("\n--- HOST-REF-11-like records retain entries and complete raw provenance ---")
sha1 = "A" * 40
raw = [
    {
        "threat_name": "Trojan:Win32/Fixture.A",
        "path": r"C:\Users\fixture\malware.exe",
        "datetime": "2026-06-23T20:19:36Z",
        "source": "defender_eventlog",
    },
    {
        "threat_name": "",
        "path": rf"C:\ProgramData\Microsoft\Windows Defender\Quarantine\ResourceData\AA\{sha1}",
        "datetime": "2026-06-23T20:20:00Z",
        "source": "directory_scan",
    },
    {
        "threat_name": "",
        "path": rf"C:\ProgramData\Microsoft\Windows Defender\Quarantine\Resources\AA\{sha1}",
        "datetime": "2026-06-23T20:21:00Z",
        "source": "directory_scan",
    },
]
parsed = fixture(raw)
lean_out = run_defender(parsed, lean=True)
full_out = run_defender(parsed, lean=False)
result = lean_out["sections"]["defender_quarantine"]
prov = result["_provenance"]
stats = result["_selection_stats"]
check("duplicate SHA-1 display entries remain grouped", len(result.get("entries") or []) == 2,
      result.get("entries"))
check("all three raw records deterministic", stage_indices(prov, "deterministic") == {0, 1, 2}, prov)
check("raw_count preserves parsed evidence", prov.get("raw_count") == 3, prov)
check("selected/evaluated/unevaluated remain empty",
      stage_indices(prov, "selected") == set()
      and stage_indices(prov, "evaluated") == set()
      and stage_indices(prov, "unevaluated") == set(), prov)
check("provenance validates", validate_section_provenance(prov) == [],
      validate_section_provenance(prov))
check("provenance complete and attribution clean",
      prov.get("provenance_complete") is True
      and prov.get("attribution_error_count") == 0
      and prov.get("attribution_errors") == [], prov)
det_row = prov["stages"]["deterministic"]
check("deterministic source ID coverage complete",
      det_row.get("source_ids_complete") is True
      and len(det_row.get("source_ids") or []) == 3, det_row)
check("selection stats measured and complete", stats == {
    "raw": 3,
    "selected": 0,
    "deterministic": 3,
    "deferred": 0,
    "deferred_by_policy": 0,
    "evaluated": 0,
    "selected_unevaluated": 0,
    "selected_coverage_pct": 100.0,
    "provenance_complete": True,
    "attribution_error_count": 0,
}, stats)
check("FULL and LEAN Defender provenance identical",
      full_out["sections"]["defender_quarantine"]["_provenance"] == prov,
      full_out["sections"]["defender_quarantine"]["_provenance"])

print("\n--- self comparison accepts complete Defender provenance ---")
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    run = make_run(root, "run", parsed, lean_out)
    a = load_run(str(run), "A")
    b = load_run(str(run), "B")
    try:
        comparison = compare_runs("reproducibility", a, b)
    finally:
        a.close()
        b.close()
    check("self comparison PASS", comparison.get("status") == "PASS", comparison)
    check("self comparison exit 0", comparison.get("exit_code") == 0, comparison)

print("\n--- rc22 secret-free logging remains present ---")
source = (HERE / "vt_post.py").read_text(encoding="utf-8")
check(".env logger remains key-only", "loaded_keys = sorted(loaded)" in source, "key-only logger missing")
check("loaded values are not formatted", "→ {loaded}" not in source and "→ {masked}" not in source,
      "unsafe mapping formatting remains")

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(1 if FAIL else 0)
