#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 comparison/provenance/release-gate regressions."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import analyze_section
from atomic_io import atomic_write_json
from compare_runs import compare_runs, load_run
from comparison_approval import compute_result_id, create_approval
from comparison_provenance import (
    annotate_parsed_document, build_section_provenance, sha256_file,
    stage_indices, validate_section_provenance,
)
from comparison_release_gate import current_package_manifest_sha256, evaluate_release_gate
from compare_runs import COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION as CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION
from source_id import assign_source_ids
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION, BUDGET_PROFILE_DEFAULT

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}")
        PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else ""))
        FAIL += 1


def make_run(root: Path, name: str, *, version=PIPELINE_VERSION, schema=ANALYSIS_SCHEMA_VERSION,
             mode="LEAN", depth=2, selected=(0, 1), deterministic=(), deferred=(),
             scores=("MEDIUM", "LOW"), deterministic_high=False, input_sha="a" * 64,
             model="model-a", profile="profile-a", profile_fp="f" * 64):
    run = root / name
    run.mkdir()
    raw = [
        {"path": r"C:\Temp\a.exe", "suspicious": True},
        {"path": r"C:\Temp\b.exe", "suspicious": True},
    ]
    assign_source_ids(input_sha, "appcompat_cache", raw)
    parsed = {
        "meta": {
            "hostname": "HOST", "datestamp": "20260725000000",
            "input_sha256": input_sha, "collection_id": input_sha,
            "pipeline_version": version, "analysis_schema_version": schema,
            "parser_version": schema,
            "package_manifest_sha256": (current_package_manifest_sha256() if version == PIPELINE_VERSION else "9" * 64),
        },
        "sections": {"appcompat_cache": raw}, "event_logs": {},
    }
    annotate_parsed_document(parsed)
    parsed_path = run / "parsed_HOST_20260725000000.json"
    atomic_write_json(parsed_path, parsed)
    parsed_sha = sha256_file(parsed_path)
    selected_set, deterministic_set, deferred_set = map(set, (selected, deterministic, deferred))
    if not deferred_set:
        deferred_set = set(range(len(raw))) - selected_set - deterministic_set
    prov = build_section_provenance(
        "appcompat_cache", raw,
        selected=selected_set, deterministic=deterministic_set, deferred=deferred_set,
        evaluated=selected_set, unevaluated=(), mandatory=(), mandatory_applicable=False,
        selected_reasons={"risk_selected": selected_set} if selected_set else {},
        deterministic_reasons={"rule": deterministic_set} if deterministic_set else {},
        deferred_reasons={"over_global_budget": deferred_set} if deferred_set else {},
    )
    entries = []
    for idx, score in enumerate(scores):
        if idx >= len(raw):
            break
        entries.append({
            "identifier": raw[idx]["path"], "source_id": raw[idx]["source_id"],
            "score": score, "reason": "r", "iocs": [raw[idx]["path"]],
            "_raw_source_index": idx,
            **({"deterministic_origin": "fixture_rule"} if deterministic_high and score == "HIGH" else {}),
        })
    meta = dict(parsed["meta"])
    meta.update({
        "pipeline_version": version, "analysis_schema_version": schema,
        "analysis_mode": mode, "depth": depth, "model": model,
        "budget_profile": profile, "budget_profile_fingerprint": profile_fp,
        "max_inflight_llm": 9, "pipeline_max_workers": 2,
        "runtime_fingerprint": "runtime-" + mode + str(depth),
        "package_manifest_sha256": (
            current_package_manifest_sha256() if version == PIPELINE_VERSION else "9" * 64
        ),
        "parsed_artifact_sha256": parsed_sha,
    })
    analyzed = {"meta": meta, "depth": depth, "sections": {
        "appcompat_cache": {"section": "appcompat_cache", "entries": entries,
                            "section_summary": "fixture", "_provenance": prov}
    }}
    analyzed_path = run / "analyzed_HOST_20260725000000.json"
    atomic_write_json(analyzed_path, analyzed)
    return run


print("\n--- rc20 identity ---")
check("pipeline version", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("schema version", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("profile version", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)

print("\n--- compact provenance schema ---")
raw = [{"source_id": "s0", "x": 0}, {"source_id": "s1", "x": 1}, {"source_id": "s2", "x": 2}]
prov = build_section_provenance(
    "x", raw, selected={0}, deterministic={1}, deferred={2},
    evaluated={0}, unevaluated=set(), mandatory=set(), mandatory_applicable=False,
)
check("provenance partition valid", not validate_section_provenance(prov), validate_section_provenance(prov))
check("mandatory applicability explicit", stage_indices(prov, "mandatory") is None, prov)
check("selected exact", stage_indices(prov, "selected") == {0}, prov)
check("deferred source IDs omitted", "source_ids" not in prov["stages"]["deferred"], prov)

print("\n--- Depth1 provenance is emitted and complete ---")
parsed = {
    "meta": {"hostname": "H", "input_sha256": "b" * 64, "collection_id": "b" * 64,
             "parser_version": ANALYSIS_SCHEMA_VERSION,
             "pipeline_version": PIPELINE_VERSION,
             "analysis_schema_version": ANALYSIS_SCHEMA_VERSION},
    "sections": {"appcompat_cache": [
        {"path": r"C:\Users\u\AppData\Local\Temp\a.exe", "suspicious": True},
        {"path": r"C:\Windows\System32\notepad.exe", "suspicious": False},
    ]}, "event_logs": {}, "evidence_quality": {},
}
assign_source_ids(parsed["meta"]["collection_id"], "appcompat_cache", parsed["sections"]["appcompat_cache"])
annotate_parsed_document(parsed)
old_chunk = analyze_section.call_llm_chunked
try:
    def fake_chunk(client, model, sec, depth, entries, verbose, context, **kwargs):
        indices = kwargs.get("source_indices") or list(range(len(entries)))
        out = []
        for pos, entry in enumerate(entries):
            out.append({"identifier": entry["path"], "source_id": entry["source_id"],
                        "score": "MEDIUM", "reason": "fixture", "iocs": [entry["path"]],
                        "_raw_source_index": indices[pos]})
        return out, "ok", [], []
    analyze_section.call_llm_chunked = fake_chunk
    analyzed = analyze_section.analyze(parsed, 1, object(), "model-a",
                                       target_sections=["appcompat_cache"], lean=True)
    p = analyzed["sections"]["appcompat_cache"].get("_provenance")
    check("Depth1 provenance exists", isinstance(p, dict), p)
    check("Depth1 partition valid", isinstance(p, dict) and not validate_section_provenance(p),
          validate_section_provenance(p) if isinstance(p, dict) else p)
    check("Depth1 mandatory is not applicable", isinstance(p, dict) and stage_indices(p, "mandatory") is None, p)
    check("metadata fail-closed fields present",
          all(analyzed["meta"].get(k) not in (None, "") for k in (
              "runtime_fingerprint", "comparison_provenance_schema_version",
              "source_id_algorithm_version", "budget_profile_fingerprint")), analyzed["meta"])
finally:
    analyze_section.call_llm_chunked = old_chunk

print("\n--- four comparison modes ---")
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    a_dir = make_run(root, "repro_a")
    b_dir = make_run(root, "repro_b")
    a = load_run(str(a_dir), "A"); b = load_run(str(b_dir), "B")
    result = compare_runs("reproducibility", a, b)
    check("reproducibility identical PASS", result["status"] == "PASS", result)
    a.close(); b.close()

    bad_dir = make_run(root, "repro_bad", input_sha="c" * 64)
    a = load_run(str(a_dir), "A"); b = load_run(str(bad_dir), "B")
    result = compare_runs("reproducibility", a, b)
    check("repro metadata mismatch INPUT_ERROR", result["status"] == "INPUT_ERROR", result)
    a.close(); b.close()

    cv_a_dir = make_run(root, "cv_a", version="3.69-rc19", schema="2.0-rc19",
                        profile="old", profile_fp="1" * 64, selected=(0, 1), scores=("MEDIUM", "LOW"))
    cv_b_dir = make_run(root, "cv_b", selected=(0,), scores=("MEDIUM",))
    a = load_run(str(cv_a_dir), "A"); b = load_run(str(cv_b_dir), "B")
    result = compare_runs("cross-version", a, b)
    check("cross-version non-HIGH selection difference REVIEW",
          result["status"] == "REVIEW" and result["summary"]["fail"] == 0, result)
    a.close(); b.close()

    full_dir = make_run(root, "full", mode="FULL", selected=(0, 1), scores=("MEDIUM", "LOW"))
    lean_dir = make_run(root, "lean", mode="LEAN", selected=(0,), scores=("MEDIUM",))
    a = load_run(str(full_dir), "A"); b = load_run(str(lean_dir), "B")
    result = compare_runs("full-lean", a, b)
    check("FULL/LEAN selected difference is REVIEW not FAIL",
          result["status"] == "REVIEW" and result["summary"]["fail"] == 0, result)
    a.close(); b.close()

    d1_dir = make_run(root, "d1", depth=1, selected=(), deterministic=(0,), scores=("HIGH",),
                      deterministic_high=True)
    d2_dir = make_run(root, "d2", depth=2, selected=(0,), deterministic=(), scores=("MEDIUM",))
    a = load_run(str(d1_dir), "A"); b = load_run(str(d2_dir), "B")
    result = compare_runs("depth1-depth2", a, b)
    check("deterministic HIGH to MEDIUM is FAIL", result["status"] == "FAIL" and any(
        x["kind"] == "deterministic_high_to_medium" for x in result["issues"]), result)
    a.close(); b.close()

print("\n--- approval and formal release gate ---")
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    for mode in ("reproducibility", "cross-version", "full-lean", "depth1-depth2"):
        result = {
            "comparison_result_schema": 1, "result_id": f"result-{mode}", "mode": mode,
            "comparison_implementation": {"evidence_version": CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION,
                "compare_runs_sha256": sha256_file(HERE / "compare_runs.py")},
            "status": "REVIEW" if mode == "full-lean" else "PASS",
            "unresolved_review_ids": ["review-1"] if mode == "full-lean" else [],
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
        }
        result["result_id"] = compute_result_id(result)
        rp = root / f"comparison_result_{mode}.json"
        atomic_write_json(rp, result)
        if mode == "full-lean":
            create_approval(rp, root / "comparison_approval_review.json",
                            approver="analyst", reason="expected selected-set difference",
                            review_ids=["review-1"])
    gate = evaluate_release_gate(root)
    check("all four approved modes make release gate eligible", gate["eligible"], gate)
    (root / "comparison_approval_review.json").unlink()
    gate = evaluate_release_gate(root)
    check("unapproved review blocks release gate", not gate["eligible"], gate)

print(f"\nRESULT: PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
