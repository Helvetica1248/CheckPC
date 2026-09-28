#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 rev10: comparator evidence v2 producer -> gate -> promotion E2E."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import shutil
import tempfile
from pathlib import Path

import compare_runs as cr
import promote_to_formal as promo
from atomic_io import atomic_write_json
from comparison_approval import compute_result_id, create_approval
from comparison_provenance import document_raw_evidence_fingerprint, sha256_file
from comparison_release_gate import (
    CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION,
    REQUIRED_MODES,
    current_package_manifest_sha256,
    evaluate_release_gate,
)

PASS = 0
FAIL = 0
OLD_REV8_COMPARE_SHA256 = "2204dd10d0551f8b548c1b6272de8c085072e92525e8c3c288c72ccb69ae5741"


def check(name: str, condition: bool, detail="") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [OK]  {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}: {detail}")


def write_run(root: Path, name: str, *, version="3.70", mode="LEAN", depth=1,
              profile="v370", profile_fp="fp370", package_manifest_sha256: str | None = None) -> Path:
    d = root / name
    d.mkdir()
    manifest_value = (
        package_manifest_sha256
        if package_manifest_sha256 is not None
        else (current_package_manifest_sha256() if version == "3.70" else "9" * 64)
    )
    parsed = {
        "meta": {
            "pipeline_version": version,
            "source_id_algorithm_version": "1",
            "package_manifest_sha256": manifest_value,
        },
        "sections": {}, "event_logs": {},
    }
    pp = d / "parsed_host.json"
    pp.write_text(json.dumps(parsed, sort_keys=True), encoding="utf-8")
    meta = {
        "pipeline_version": version,
        "analysis_schema_version": "2.1",
        "analysis_mode": mode,
        "depth": depth,
        "model": "rev10-e2e-model",
        "input_sha256": "a" * 64,
        "budget_profile": profile,
        "budget_profile_fingerprint": profile_fp,
        "max_inflight_llm": 1,
        "pipeline_max_workers": 1,
        "runtime_fingerprint": "rev10-e2e-runtime",
        "source_id_algorithm_version": "1",
        "comparison_provenance_schema_version": "1",
        "parsed_artifact_sha256": sha256_file(pp),
        "raw_evidence_fingerprint": document_raw_evidence_fingerprint(parsed),
        "package_manifest_sha256": manifest_value,
    }
    ap = d / "analyzed_host.json"
    ap.write_text(json.dumps({"meta": meta, "sections": {}}, sort_keys=True), encoding="utf-8")
    return d


def build_actual_comparisons(base: Path) -> tuple[Path, dict]:
    runs = base / "runs"
    runs.mkdir()
    r1 = write_run(runs, "d1lean1")
    r2 = write_run(runs, "d1lean2")
    old = write_run(runs, "old", version="3.69", profile="v369", profile_fp="fp369")
    full = write_run(runs, "d1full", mode="FULL")
    d2 = write_run(runs, "d2lean", depth=2)
    combos = {
        "reproducibility": (r1, r2),
        "cross-version": (old, r1),
        "full-lean": (full, r1),
        "depth1-depth2": (r1, d2),
    }
    gate_dir = base / "gate"
    gate_dir.mkdir()
    for mode, (left, right) in combos.items():
        out = gate_dir / f"comparison_result_{mode}.json"
        rc = cr.main(["--mode", mode, str(left), str(right), "--output", str(out)])
        if rc != 0:
            raise AssertionError(f"compare_runs {mode} rc={rc}")
        doc = json.loads(out.read_text(encoding="utf-8"))
        if doc.get("status") != "PASS":
            raise AssertionError(f"compare_runs {mode} status={doc.get('status')}")
    gate = evaluate_release_gate(gate_dir)
    atomic_write_json(gate_dir / "comparison_release_gate.json", gate)
    return gate_dir, gate


def write_package(root: Path, gate_dir: Path, gate: dict) -> None:
    root.mkdir()
    (root / "version.py").write_text(
        'PIPELINE_VERSION = "3.70"\n'
        'ANALYSIS_SCHEMA_VERSION = "2.1"\n'
        'RELEASE_STATUS = "validation-pending"\n'
        'BUDGET_PROFILE_DEFAULT = "v370"\n', encoding="utf-8")
    (root / "budget_profile.py").write_text(
        'PROFILES = {"v369": {"name": "v369", "n": 1, "provisional": False, "validated": True}, '
        '"v370": {"name": "v370", "n": 1, "provisional": False, "validated": True}}\n',
        encoding="utf-8")
    shutil.copy2(Path(cr.__file__), root / "compare_runs.py")
    shutil.copy2(Path(cr.__file__).resolve().parent / "SHA256SUMS.txt", root / "SHA256SUMS.txt")
    (root / "baseline.json").write_text("{}\n", encoding="utf-8")
    summary = {
        "summary_schema": 1,
        "release_mode": True,
        "formal_release_eligible": True,
        "environment_label": "base117",
        "new_fail": 0,
        "known_fail": 0,
        "error": 0,
        "skip": 0,
        "comparison_gate": {"required": True, "directory": str(gate_dir.resolve()), **copy.deepcopy(gate)},
    }
    atomic_write_json(root / "test_results.json", summary)


def promotion_dry_run(package: Path, gate_dir: Path) -> tuple[int, str]:
    old_here = promo.HERE
    old_runtime = promo.check_runtime_baseline
    old_budget = promo.check_numeric_budget
    old_argv = list(__import__('sys').argv)
    import sys
    promo.HERE = package
    promo.check_runtime_baseline = lambda baseline, errors: None
    promo.check_numeric_budget = lambda errors: None
    sys.argv = [
        "promote_to_formal.py", "--runtime-baseline", str(package / "baseline.json"),
        "--source-package-sha256", "e" * 64,
        "--comparison-gate-dir", str(gate_dir), "--dry-run",
    ]
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = promo.main()
    finally:
        promo.HERE = old_here
        promo.check_runtime_baseline = old_runtime
        promo.check_numeric_budget = old_budget
        sys.argv = old_argv
    return rc, buf.getvalue()


with tempfile.TemporaryDirectory(prefix="checkpc_rev10_cmp_") as td:
    base = Path(td)
    gate_dir, gate = build_actual_comparisons(base)
    current_sha = sha256_file(Path(cr.__file__))
    check("producer evidence version is current v2",
          cr.COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION == 2
          and CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION == 2)
    check("actual four-mode gate eligible", gate.get("eligible") is True, gate)
    check("actual gate has exactly four modes", {x.get("mode") for x in gate.get("modes", [])} == set(REQUIRED_MODES), gate)
    check("gate binds current comparator SHA+version pair",
          all(x.get("compare_runs_sha256") == current_sha
              and x.get("comparison_implementation_evidence_version") == 2
              for x in gate.get("modes", [])), gate)

    package = base / "package"
    write_package(package, gate_dir, gate)
    rc, out = promotion_dry_run(package, gate_dir)
    check("promotion dry-run accepts actual v2 artifacts", rc == 0 and "DRY-RUN" in out, out)

    # Build a cryptographically self-consistent old-rev8-style result + approval.
    legacy = base / "legacy_gate"
    shutil.copytree(gate_dir, legacy)
    result_path = legacy / "comparison_result_reproducibility.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["comparison_implementation"] = {
        "evidence_version": 1,
        "compare_runs_sha256": OLD_REV8_COMPARE_SHA256,
    }
    issue = {
        "id": "cmp-rev8-legacy-review",
        "severity": "REVIEW",
        "kind": "legacy_evidence_probe",
        "section": "task_140",
        "evidence_digest": "1" * 64,
        "samples": ["legacy"],
    }
    result["status"] = "REVIEW"
    result["exit_code"] = 3
    result["issues"] = [issue]
    result["unresolved_review_ids"] = [issue["id"]]
    result["unresolved_review_occurrence_count"] = 1
    result["summary"] = {"input_error": 0, "fail": 0, "review": 1, "review_occurrences": 1}
    result["result_id"] = compute_result_id(result)
    atomic_write_json(result_path, result)
    approval_path = legacy / "comparison_approval_reproducibility.json"
    create_approval(result_path, approval_path, approver="legacy-reviewer",
                    reason="legacy approval must not enable reuse", review_ids=[issue["id"]])
    legacy_gate = evaluate_release_gate(legacy)
    check("old rev8 result+approval cannot be reused", legacy_gate.get("eligible") is False, legacy_gate)
    errors = " | ".join(map(str, legacy_gate.get("errors") or []))
    check("legacy rejection cites evidence version/SHA pair",
          "evidence version mismatch" in errors and "SHA mismatch" in errors, errors)

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
