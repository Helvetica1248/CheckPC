#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 Depth1 attribution, measured coverage and release-gate regressions."""
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
from comparison_approval import compute_result_id, create_approval
from comparison_provenance import (
    annotate_parsed_document, build_section_provenance, sha256_file,
    stage_indices,
)
from comparison_release_gate import current_package_manifest_sha256, evaluate_release_gate
from compare_runs import COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION as CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION
from source_id import assign_source_ids
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION, BUDGET_PROFILE_DEFAULT

PASS = FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [OK]  {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}: {detail}")


def parsed_fixture(raw):
    parsed = {
        "meta": {
            "hostname": "H", "datestamp": "20260725010101",
            "input_sha256": "b" * 64, "collection_id": "b" * 64,
            "parser_version": ANALYSIS_SCHEMA_VERSION,
            "pipeline_version": PIPELINE_VERSION,
            "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
            "package_manifest_sha256": current_package_manifest_sha256(),
        },
        "sections": {"appcompat_cache": raw},
        "event_logs": {}, "evidence_quality": {},
    }
    assign_source_ids(parsed["meta"]["collection_id"], "appcompat_cache", raw)
    annotate_parsed_document(parsed)
    return parsed


def run_depth(parsed, depth, fake_chunk):
    old = analyze_section.call_llm_chunked
    try:
        analyze_section.call_llm_chunked = fake_chunk
        return analyze_section.analyze(
            parsed, depth, object(), "model-a",
            target_sections=["appcompat_cache"], lean=True,
        )
    finally:
        analyze_section.call_llm_chunked = old


def make_run(root: Path, name: str):
    run = root / name
    run.mkdir()
    raw = [
        {"path": r"C:\Temp\a.exe", "suspicious": True},
        {"path": r"C:\Temp\b.exe", "suspicious": True},
    ]
    parsed = parsed_fixture(raw)
    parsed_path = run / "parsed_H_20260725010101.json"
    atomic_write_json(parsed_path, parsed)
    prov = build_section_provenance(
        "appcompat_cache", raw,
        selected={0, 1}, deterministic=set(), deferred=set(),
        evaluated={0, 1}, unevaluated=set(),
        mandatory=set(), mandatory_applicable=False,
        selected_reasons={"depth1_selected": {0, 1}},
    )
    meta = dict(parsed["meta"])
    meta.update({
        "analysis_mode": "LEAN", "depth": 1, "model": "model-a",
        "budget_profile": BUDGET_PROFILE_DEFAULT,
        "budget_profile_fingerprint": "f" * 64,
        "max_inflight_llm": 9, "pipeline_max_workers": 2,
        "runtime_fingerprint": "r" * 64,
        "package_manifest_sha256": current_package_manifest_sha256(),
        "parsed_artifact_sha256": sha256_file(parsed_path),
    })
    analyzed = {
        "meta": meta, "depth": 1,
        "sections": {"appcompat_cache": {
            "section": "appcompat_cache",
            "entries": [
                {"identifier": raw[0]["path"], "source_id": raw[0]["source_id"],
                 "_raw_source_index": 0, "score": "MEDIUM", "reason": "r", "iocs": []},
                {"identifier": raw[1]["path"], "source_id": raw[1]["source_id"],
                 "_raw_source_index": 1, "score": "LOW", "reason": "r", "iocs": []},
            ],
            "section_summary": "fixture", "_provenance": prov,
        }},
    }
    atomic_write_json(run / "analyzed_H_20260725010101.json", analyzed)
    return run


def valid_result(mode: str, status="PASS", review_ids=()):
    row = {
        "comparison_result_schema": 1,
        "generated_at": "2026-07-25T00:00:00+00:00",
        "mode": mode, "strict_llm": False,
        "comparison_implementation": {"evidence_version": CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION,
            "compare_runs_sha256": sha256_file(HERE / "compare_runs.py")},
        "status": status, "exit_code": 3 if status == "REVIEW" else 0,
        "summary": {"input_error": 0, "fail": 0, "review": len(review_ids)},
        "artifacts": {
            "a": {"parsed_sha256": "a" * 64, "analyzed_sha256": "b" * 64,
                  "meta": {"pipeline_version": PIPELINE_VERSION,
                           "package_manifest_sha256": current_package_manifest_sha256(),
                           "source_id_algorithm_version": "1"},
                  "parsed_meta": {"pipeline_version": PIPELINE_VERSION,
                                  "package_manifest_sha256": current_package_manifest_sha256(),
                                  "source_id_algorithm_version": "1"}},
            "b": {"parsed_sha256": "c" * 64, "analyzed_sha256": "d" * 64,
                  "meta": {"pipeline_version": PIPELINE_VERSION,
                           "package_manifest_sha256": current_package_manifest_sha256(),
                           "source_id_algorithm_version": "1"},
                  "parsed_meta": {"pipeline_version": PIPELINE_VERSION,
                                  "package_manifest_sha256": current_package_manifest_sha256(),
                                  "source_id_algorithm_version": "1"}},
        },
        "identity_matching": {},
        "issues": [
            {"id": rid, "severity": "REVIEW", "kind": "fixture_review",
             "section": "fixture", "occurrence_count": 1}
            for rid in review_ids
        ],
        "unresolved_review_ids": list(review_ids),
        "unresolved_review_occurrence_count": len(review_ids),
    }
    row["result_id"] = compute_result_id(row)
    return row


print("\n--- rc21 identity ---")
check("pipeline version", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("schema version", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("profile version", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)

print("\n--- Depth1 free-form reason and source attribution ---")
raw = [
    {"path": r"C:\Temp\a.exe", "suspicious": True},
    {"path": r"C:\Temp\b.exe", "suspicious": True},
    {"path": r"C:\Windows\notepad.exe", "suspicious": False},
]
parsed = parsed_fixture(raw)

def fake_missing_index(client, model, sec, depth, entries, verbose, context, **kwargs):
    return [
        {"identifier": entries[0]["path"], "source_id": entries[0]["source_id"],
         "score": "HIGH", "reason": "ルールベースの検出パターンに合致", "iocs": []},
        {"identifier": entries[1]["path"], "source_id": entries[1]["source_id"],
         "score": "MEDIUM", "reason": "fixture", "iocs": []},
    ], "ok", [], []

out = run_depth(parsed, 1, fake_missing_index)
prov = out["sections"]["appcompat_cache"]["_provenance"]
check("reason text does not make deterministic", stage_indices(prov, "deterministic") == set(), prov)
check("source_id fallback restores selected", stage_indices(prov, "selected") == {0, 1}, prov)
check("source_id fallback marks evaluated", stage_indices(prov, "evaluated") == {0, 1}, prov)
check("Depth1 provenance complete", prov.get("provenance_complete") is True, prov)

print("\n--- unresolved Depth1 attribution is fail-closed ---")
parsed = parsed_fixture([{"path": r"C:\Temp\a.exe", "suspicious": True}])
def fake_unresolved(*args, **kwargs):
    return [{"identifier": "changed-by-model", "score": "HIGH", "reason": "r", "iocs": []}], "ok", [], []
out = run_depth(parsed, 1, fake_unresolved)
prov = out["sections"]["appcompat_cache"]["_provenance"]
check("unresolved attribution does not become deferred", stage_indices(prov, "selected") == {0}, prov)
check("unresolved attribution becomes unevaluated", stage_indices(prov, "unevaluated") == {0}, prov)
check("provenance incomplete flag", prov.get("provenance_complete") is False, prov)
check("attribution error counted", prov.get("attribution_error_count") == 1, prov)

print("\n--- Depth2 evaluated is measured, not asserted ---")
parsed = parsed_fixture([
    {"path": r"C:\Temp\a.exe", "suspicious": True},
    {"path": r"C:\Temp\b.exe", "suspicious": True},
])
def fake_partial_depth2(client, model, sec, depth, entries, verbose, context, **kwargs):
    raw_indices = kwargs.get("source_indices") or [0]
    return [{"identifier": entries[0]["path"], "source_id": entries[0]["source_id"],
             "_raw_source_index": raw_indices[0], "score": "MEDIUM", "reason": "r", "iocs": []}], "ok", [], []
out = run_depth(parsed, 2, fake_partial_depth2)
prov = out["sections"]["appcompat_cache"]["_provenance"]
check("Depth2 selected has two", stage_indices(prov, "selected") == {0, 1}, prov)
check("Depth2 evaluated has actual one", stage_indices(prov, "evaluated") == {0}, prov)
check("Depth2 unevaluated catches silent omission", stage_indices(prov, "unevaluated") == {1}, prov)

print("\n--- source ID coverage cannot pass silently ---")
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    a_dir, b_dir = make_run(root, "a"), make_run(root, "b")
    analyzed_b = next(b_dir.glob("analyzed_*.json"))
    data = json.loads(analyzed_b.read_text(encoding="utf-8"))
    data["sections"]["appcompat_cache"]["entries"][0].pop("source_id", None)
    atomic_write_json(analyzed_b, data)
    a, b = load_run(str(a_dir), "A"), load_run(str(b_dir), "B")
    result = compare_runs("reproducibility", a, b)
    check("analyzed source_id loss is REVIEW not PASS",
          result["status"] == "REVIEW" and any(x["kind"] == "analyzed_source_id_missing" for x in result["issues"]), result)
    a.close(); b.close()

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    a_dir, b_dir = make_run(root, "a"), make_run(root, "b")
    analyzed_b = next(b_dir.glob("analyzed_*.json"))
    data = json.loads(analyzed_b.read_text(encoding="utf-8"))
    stage = data["sections"]["appcompat_cache"]["_provenance"]["stages"]["selected"]
    stage["source_ids"] = []
    atomic_write_json(analyzed_b, data)
    a, b = load_run(str(a_dir), "A"), load_run(str(b_dir), "B")
    result = compare_runs("reproducibility", a, b)
    check("exact stage source_id coverage loss is INPUT_ERROR",
          result["status"] == "INPUT_ERROR" and any(x["kind"] == "stage_source_id_coverage_incomplete" for x in result["issues"]), result)
    a.close(); b.close()

print("\n--- release gate rejects malformed or unknown results ---")
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    for mode in ("reproducibility", "cross-version", "full-lean", "depth1-depth2"):
        row = valid_result(mode)
        atomic_write_json(root / f"comparison_result_{mode}.json", row)
    check("valid four-mode results are eligible", evaluate_release_gate(root)["eligible"], evaluate_release_gate(root))
    bad = json.loads((root / "comparison_result_reproducibility.json").read_text(encoding="utf-8"))
    bad.pop("comparison_result_schema", None)
    atomic_write_json(root / "comparison_result_reproducibility.json", bad)
    check("missing result schema blocks release", not evaluate_release_gate(root)["eligible"], evaluate_release_gate(root))

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    for mode in ("reproducibility", "cross-version", "full-lean", "depth1-depth2"):
        row = valid_result(mode)
        if mode == "full-lean":
            row["status"] = "UNKNOWN"
            row["result_id"] = compute_result_id(row)
        atomic_write_json(root / f"comparison_result_{mode}.json", row)
    check("unknown status blocks release", not evaluate_release_gate(root)["eligible"], evaluate_release_gate(root))

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    for mode in ("reproducibility", "cross-version", "full-lean", "depth1-depth2"):
        row = valid_result(mode, "REVIEW" if mode == "full-lean" else "PASS",
                           ["review-1"] if mode == "full-lean" else [])
        rp = root / f"comparison_result_{mode}.json"
        atomic_write_json(rp, row)
        if mode == "full-lean":
            create_approval(rp, root / "comparison_approval_full-lean.json",
                            approver="analyst", reason="expected", review_ids=["review-1"])
    check("approved REVIEW remains eligible", evaluate_release_gate(root)["eligible"], evaluate_release_gate(root))
    row = json.loads((root / "comparison_result_depth1-depth2.json").read_text(encoding="utf-8"))
    row["artifacts"]["a"]["parsed_sha256"] = "not-a-sha"
    row["result_id"] = compute_result_id(row)
    atomic_write_json(root / "comparison_result_depth1-depth2.json", row)
    check("invalid artifact SHA blocks release", not evaluate_release_gate(root)["eligible"], evaluate_release_gate(root))

print(f"\nRESULT: PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
