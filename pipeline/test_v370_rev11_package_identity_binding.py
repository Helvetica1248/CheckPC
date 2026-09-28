#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 rev11: current-package manifest identity binds 4-mode artifacts."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path

import compare_runs as cr
import promote_to_formal as promo
from atomic_io import atomic_write_json
from comparison_approval import compute_result_id, create_approval
from comparison_provenance import document_raw_evidence_fingerprint, sha256_file
from comparison_release_gate import (
    REQUIRED_MODES,
    current_package_manifest_sha256,
    evaluate_release_gate,
)

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


def write_run(root: Path, name: str, *, version="3.70", mode="LEAN", depth=1,
              profile="v370", profile_fp="fp370", manifest_sha: str,
              runtime_fingerprint="rev11-current-runtime") -> Path:
    d = root / name
    d.mkdir()
    parsed = {
        "meta": {
            "pipeline_version": version,
            "source_id_algorithm_version": "1",
            "package_manifest_sha256": manifest_sha,
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
        "model": "rev11-e2e-model",
        "input_sha256": "a" * 64,
        "budget_profile": profile,
        "budget_profile_fingerprint": profile_fp,
        "max_inflight_llm": 1,
        "pipeline_max_workers": 1,
        "runtime_fingerprint": runtime_fingerprint,
        "source_id_algorithm_version": "1",
        "comparison_provenance_schema_version": "1",
        "parsed_artifact_sha256": sha256_file(pp),
        "raw_evidence_fingerprint": document_raw_evidence_fingerprint(parsed),
        "package_manifest_sha256": manifest_sha,
    }
    ap = d / "analyzed_host.json"
    ap.write_text(json.dumps({"meta": meta, "sections": {}}, sort_keys=True), encoding="utf-8")
    return d


def build_comparisons(base: Path, current_manifest: str, *, old_current_manifest: bool = False, approved_review: bool = False):
    runs = base / "runs"
    runs.mkdir(parents=True)
    used = ("7" * 64) if old_current_manifest else current_manifest
    runtime = "rev9-old-runtime" if old_current_manifest else "rev11-current-runtime"
    r1 = write_run(runs, "d1lean1", manifest_sha=used, runtime_fingerprint=runtime)
    r2 = write_run(runs, "d1lean2", manifest_sha=used, runtime_fingerprint=runtime)
    old = write_run(
        runs, "old", version="3.69", profile="v369", profile_fp="fp369",
        manifest_sha="6" * 64, runtime_fingerprint="formal-v369-runtime",
    )
    full = write_run(runs, "d1full", mode="FULL", manifest_sha=used, runtime_fingerprint=runtime)
    d2 = write_run(runs, "d2lean", depth=2, manifest_sha=used, runtime_fingerprint=runtime)
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
    if approved_review:
        result_path = gate_dir / "comparison_result_reproducibility.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        issue = {
            "id": "cmp-rev11-old-package-approved-review",
            "severity": "REVIEW",
            "kind": "parsed_field_transition",
            "section": "startup_folder",
            "count": 1,
            "transitions_digest": "1" * 32,
            "samples": [{"identity": "fixture", "fields": {"suspicious": {"a": False, "b": True}}}],
        }
        result["status"] = "REVIEW"
        result["exit_code"] = 3
        result["summary"] = {"input_error": 0, "fail": 0, "review": 1, "review_occurrences": 1}
        result["issues"] = [issue]
        result["unresolved_review_ids"] = [issue["id"]]
        result["unresolved_review_occurrence_count"] = 1
        result["result_id"] = compute_result_id(result)
        atomic_write_json(result_path, result)
        create_approval(
            result_path, gate_dir / "comparison_approval_reproducibility.json",
            approver="rev11-negative-e2e", reason="fresh approval must not bypass package identity",
            review_ids=[issue["id"]],
        )
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


def run_promotion(package: Path, gate_dir: Path, *, dry_run: bool) -> tuple[int, str]:
    old_here = promo.HERE
    old_runtime = promo.check_runtime_baseline
    old_budget = promo.check_numeric_budget
    old_argv = list(sys.argv)
    promo.HERE = package
    promo.check_runtime_baseline = lambda baseline, errors: None
    promo.check_numeric_budget = lambda errors: None
    sys.argv = [
        "promote_to_formal.py", "--runtime-baseline", str(package / "baseline.json"),
        "--source-package-sha256", "e" * 64,
        "--comparison-gate-dir", str(gate_dir),
    ] + (["--dry-run"] if dry_run else [])
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


current_manifest = current_package_manifest_sha256()
check("current package manifest identity is SHA-256", len(current_manifest) == 64, current_manifest)

with tempfile.TemporaryDirectory(prefix="checkpc_rev11_pkgid_") as td:
    base = Path(td)

    # Positive: every current-v3.70 side was generated by this exact package manifest.
    good_dir, good_gate = build_comparisons(base / "good", current_manifest)
    check("current-package four-mode gate eligible", good_gate.get("eligible") is True, good_gate)
    check("gate records current package manifest identity",
          good_gate.get("current_package_manifest_sha256") == current_manifest, good_gate)
    mode_rows = good_gate.get("modes") or []
    check("all current artifact identities are recorded and match",
          len(mode_rows) == 4 and all(
              row.get("current_artifacts")
              and all(x.get("package_manifest_sha256") == current_manifest
                      for x in row.get("current_artifacts") or [])
              for row in mode_rows), mode_rows)
    cross = next(row for row in mode_rows if row.get("mode") == "cross-version")
    check("cross-version binds only the current v3.70 side",
          len(cross.get("current_artifacts") or []) == 1
          and (cross.get("current_artifacts") or [{}])[0].get("pipeline_version") == "3.70", cross)

    package = base / "package"
    write_package(package, good_dir, good_gate)
    rc, out = run_promotion(package, good_dir, dry_run=True)
    check("promotion dry-run accepts current-package artifacts", rc == 0 and "DRY-RUN" in out, out)
    rc, out = run_promotion(package, good_dir, dry_run=False)
    check("promotion apply accepts current-package artifacts", rc == 0 and "PROMOTED" in out, out)
    promotion = json.loads((package / "formal_promotion.json").read_text(encoding="utf-8"))
    check("formal promotion records current package manifest identity",
          promotion.get("current_package_manifest_sha256") == current_manifest, promotion)
    check("formal promotion records per-mode current artifact identities",
          all(row.get("current_artifacts") for row in promotion.get("comparison_modes") or []),
          promotion.get("comparison_modes"))

    # Negative: rev9-like v3.70 artifacts, then regenerated by current comparator.
    bad_dir, bad_gate = build_comparisons(
        base / "old4", current_manifest, old_current_manifest=True, approved_review=True
    )
    check("old-package artifacts are rejected by release gate", bad_gate.get("eligible") is False, bad_gate)
    errors = " | ".join(map(str, bad_gate.get("errors") or []))
    check("old-package rejection cites package manifest mismatch",
          "package manifest mismatch" in errors, errors)
    check("fresh approval exists but cannot bypass package identity",
          (bad_dir / "comparison_approval_reproducibility.json").is_file(), bad_dir)
    bad_package = base / "bad_package"
    write_package(bad_package, bad_dir, bad_gate)
    rc, out = run_promotion(bad_package, bad_dir, dry_run=True)
    check("promotion dry-run rejects old-package artifacts", rc == 1 and "BLOCKED" in out, out)

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
