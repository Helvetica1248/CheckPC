#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 semantic comparison and evidence binding regressions."""
from __future__ import annotations

import copy
import json
import tarfile
import tempfile
from pathlib import Path

from build_reproducibility_bundle import build_bundle
from compare_runs import RunArtifacts, compare_runs
from comparison_provenance import document_raw_evidence_fingerprint
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

check("pipeline", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("schema", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("profile", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)

meta = {
    "input_sha256": "x", "model": "m", "pipeline_version": PIPELINE_VERSION,
    "analysis_schema_version": ANALYSIS_SCHEMA_VERSION, "depth": 1,
    "analysis_mode": "LEAN", "budget_profile": BUDGET_PROFILE_DEFAULT,
    "budget_profile_fingerprint": "f", "max_inflight_llm": 1,
    "pipeline_max_workers": 1, "runtime_fingerprint": "r",
    "comparison_provenance_schema_version": "1",
    "source_id_algorithm_version": "1", "parsed_artifact_sha256": "",
    "raw_evidence_fingerprint": "", "section_raw_evidence": {},
    "package_manifest_sha256": "p" * 64,
}

def artifacts(root: Path, label: str, entry: dict) -> RunArtifacts:
    parsed = {"meta": dict(meta), "sections": {}, "event_logs": {}}
    raw_fp = document_raw_evidence_fingerprint(parsed)
    parsed["meta"]["raw_evidence_fingerprint"] = raw_fp
    analyzed = {"meta": dict(meta), "sections": {
        "fixture": {"entries": [entry]}
    }}
    analyzed["meta"]["raw_evidence_fingerprint"] = raw_fp
    pp = root / f"parsed_{label}.json"
    ap = root / f"analyzed_{label}.json"
    pp.write_text(json.dumps(parsed), encoding="utf-8")
    import hashlib
    sha = hashlib.sha256(pp.read_bytes()).hexdigest()
    analyzed["meta"]["parsed_artifact_sha256"] = sha
    ap.write_text(json.dumps(analyzed), encoding="utf-8")
    return RunArtifacts(label, root, pp, ap, parsed, analyzed)

base = {
    "source_id": "fixture:1", "identifier": "A", "score": "CLEAN",
    "reason": "same", "iocs": ["a", "b"], "mitre": "T0001",
    "lolbas": "tool.exe", "decoded": "decoded",
}
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    for field, changed in (
        ("identifier", "B"), ("reason", "different"),
        ("iocs", ["a", "c"]), ("mitre", "T0002"),
        ("lolbas", "other.exe"), ("decoded", "other"),
    ):
        a_entry = copy.deepcopy(base)
        b_entry = copy.deepcopy(base)
        b_entry[field] = changed
        a = artifacts(root, "a", a_entry)
        b = artifacts(root, "b", b_entry)
        strict = compare_runs("reproducibility", a, b, strict_llm=True)
        issues = [x for x in strict["issues"] if x["kind"] == "llm_content_difference"]
        check(f"strict detects {field}", strict["status"] == "FAIL" and
              len(issues) == 1 and issues[0].get("fields") == [field], issues)
        relaxed = compare_runs("reproducibility", a, b, strict_llm=False)
        relaxed_issues = [x for x in relaxed["issues"] if x["kind"] == "llm_content_difference"]
        check(f"relaxed reviews {field}", relaxed["status"] == "REVIEW" and
              len(relaxed_issues) == 1 and relaxed_issues[0]["severity"] == "REVIEW",
              relaxed_issues)

    # IOC ordering alone must remain equivalent.
    a = artifacts(root, "order_a", base)
    order_b = copy.deepcopy(base)
    order_b["iocs"] = ["b", "a"]
    b = artifacts(root, "order_b", order_b)
    result = compare_runs("reproducibility", a, b, strict_llm=True)
    check("IOC order normalized", not any(
        x["kind"] == "llm_content_difference" for x in result["issues"]
    ), result["issues"])

print("--- comparison result bundle binding ---")
with tempfile.TemporaryDirectory() as td:
    root = Path(td) / "run"
    root.mkdir()
    for name in ("parsed_FIX.json", "analyzed_FIX.json", "correlation_FIX.json",
                 "report_FIX.md", "ingest_manifest.json"):
        (root / name).write_text("{}\n", encoding="utf-8")
    comparison = Path(td) / "comparison_result_reproducibility.json"
    comparison.write_text(json.dumps({
        "result_id": "abc", "mode": "reproducibility", "status": "PASS"
    }), encoding="utf-8")
    out = Path(td) / "bundle.tar.gz"
    result = build_bundle(root, out, comparison)
    included = result["scope"]["bundle_included"]
    check("comparison JSON listed",
          "comparisons/comparison_result_reproducibility.json" in included, included)
    check("comparison included flag",
          result["scope"]["comparison_result_included"] is True, result["scope"])
    with tarfile.open(out, "r:gz") as tf:
        names = tf.getnames()
    check("comparison JSON archived",
          "comparisons/comparison_result_reproducibility.json" in names, names)

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
