#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 rev12: run-lineage binding and requested GUI/report regressions."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path

import analyze_section as a
import compare_runs as cr
import directory_policy as dp
import promote_to_formal as promo
import report_gen
from atomic_io import atomic_write_json
from comparison_approval import compute_result_id, create_approval
from comparison_provenance import document_raw_evidence_fingerprint, sha256_file
from comparison_release_gate import current_package_manifest_sha256, evaluate_release_gate

HERE = Path(__file__).resolve().parent
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
              analyzed_manifest_sha: str | None = None,
              include_ingest: bool = True) -> Path:
    d = root / name
    d.mkdir(parents=True)
    parsed_meta = {
        "pipeline_version": version,
        "analysis_schema_version": "2.1",
        "source_id_algorithm_version": "1",
        "comparison_provenance_schema_version": "1",
        "package_manifest_sha256": manifest_sha,
    }
    parsed = {"meta": parsed_meta, "sections": {}, "event_logs": {}}
    pp = d / "parsed_host.json"
    pp.write_text(json.dumps(parsed, sort_keys=True), encoding="utf-8")
    psha = sha256_file(pp)
    analyzed_manifest_sha = analyzed_manifest_sha or manifest_sha
    meta = {
        "pipeline_version": version,
        "analysis_schema_version": "2.1",
        "analysis_mode": mode,
        "depth": depth,
        "model": "rev12-e2e-model",
        "input_sha256": "a" * 64,
        "budget_profile": profile,
        "budget_profile_fingerprint": profile_fp,
        "max_inflight_llm": 1,
        "pipeline_max_workers": 1,
        "runtime_fingerprint": "rev12-e2e-runtime",
        "source_id_algorithm_version": "1",
        "comparison_provenance_schema_version": "1",
        "parsed_artifact_sha256": psha,
        "raw_evidence_fingerprint": document_raw_evidence_fingerprint(parsed),
        "package_manifest_sha256": analyzed_manifest_sha,
    }
    ap = d / "analyzed_host.json"
    ap.write_text(json.dumps({"meta": meta, "sections": {}}, sort_keys=True), encoding="utf-8")
    if include_ingest:
        ingest = {
            "pipeline_version": version,
            "analysis_schema_version": "2.1",
            "analysis_mode": mode,
            "depth": depth,
            "model": "rev12-e2e-model",
            "input_sha256": "a" * 64,
            "budget_profile": profile,
            "budget_profile_fingerprint": profile_fp,
            "max_inflight_llm": 1,
            "pipeline_max_workers": 1,
            "source_id_algorithm_version": "1",
            "comparison_provenance_schema_version": "1",
            "parsed_artifact_sha256": psha,
            "raw_evidence_fingerprint": document_raw_evidence_fingerprint(parsed),
            "package_manifest_sha256": manifest_sha,
        }
        (d / "ingest_manifest.json").write_text(json.dumps(ingest, sort_keys=True), encoding="utf-8")
    return d


def build_four(base: Path, manifest_sha: str) -> tuple[Path, dict]:
    runs = base / "runs"
    runs.mkdir(parents=True)
    r1 = write_run(runs, "d1lean1", manifest_sha=manifest_sha)
    r2 = write_run(runs, "d1lean2", manifest_sha=manifest_sha)
    old = write_run(runs, "old", version="3.69", profile="v369", profile_fp="fp369", manifest_sha="6" * 64)
    full = write_run(runs, "d1full", mode="FULL", manifest_sha=manifest_sha)
    d2 = write_run(runs, "d2lean", depth=2, manifest_sha=manifest_sha)
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
            raise AssertionError(f"compare {mode} rc={rc}")
    gate = evaluate_release_gate(gate_dir)
    atomic_write_json(gate_dir / "comparison_release_gate.json", gate)
    return gate_dir, gate


def write_package(root: Path, gate_dir: Path, gate: dict) -> None:
    root.mkdir()
    (root / "version.py").write_text(
        'PIPELINE_VERSION = "3.70"\nANALYSIS_SCHEMA_VERSION = "2.1"\n'
        'RELEASE_STATUS = "validation-pending"\nBUDGET_PROFILE_DEFAULT = "v370"\n', encoding="utf-8")
    (root / "budget_profile.py").write_text(
        'PROFILES={"v369":{"name":"v369","n":1,"provisional":False,"validated":True},'
        '"v370":{"name":"v370","n":1,"provisional":False,"validated":True}}\n', encoding="utf-8")
    shutil.copy2(HERE / "compare_runs.py", root / "compare_runs.py")
    shutil.copy2(HERE / "SHA256SUMS.txt", root / "SHA256SUMS.txt")
    (root / "baseline.json").write_text("{}\n", encoding="utf-8")
    atomic_write_json(root / "test_results.json", {
        "summary_schema": 1, "release_mode": True, "formal_release_eligible": True,
        "environment_label": "base117", "new_fail": 0, "known_fail": 0,
        "error": 0, "skip": 0,
        "comparison_gate": {"required": True, "directory": str(gate_dir.resolve()), **copy.deepcopy(gate)},
    })


def promotion_dry_run(package: Path, gate_dir: Path) -> tuple[int, str]:
    old_here, old_runtime, old_budget, old_argv = promo.HERE, promo.check_runtime_baseline, promo.check_numeric_budget, list(sys.argv)
    promo.HERE = package
    promo.check_runtime_baseline = lambda baseline, errors: None
    promo.check_numeric_budget = lambda errors: None
    sys.argv = ["promote_to_formal.py", "--runtime-baseline", str(package / "baseline.json"),
                "--source-package-sha256", "e" * 64,
                "--comparison-gate-dir", str(gate_dir), "--dry-run"]
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = promo.main()
    finally:
        promo.HERE, promo.check_runtime_baseline, promo.check_numeric_budget, sys.argv = old_here, old_runtime, old_budget, old_argv
    return rc, buf.getvalue()


print("[1] parsed/analyzed/ingest run lineage")
current = current_package_manifest_sha256()
with tempfile.TemporaryDirectory(prefix="checkpc_rev12_") as td:
    base = Path(td)
    good_a = write_run(base, "good_a", manifest_sha=current)
    good_b = write_run(base, "good_b", manifest_sha=current)
    out = base / "good.json"
    rc = cr.main(["--mode", "reproducibility", str(good_a), str(good_b), "--output", str(out)])
    good_doc = json.loads(out.read_text(encoding="utf-8"))
    check("current parsed/analyzed/ingest lineage ACCEPT", rc == 0 and good_doc.get("status") == "PASS", good_doc.get("issues"))
    art = good_doc["artifacts"]["a"]
    check("comparison evidence records parsed/analyzed/ingest SHA",
          all(art.get(k) for k in ("parsed_sha256", "analyzed_sha256", "ingest_manifest_sha256")), art)
    check("comparison evidence records parsed package identity",
          art.get("parsed_meta", {}).get("package_manifest_sha256") == current, art.get("parsed_meta"))
    check("comparison evidence records ingest package identity",
          art.get("ingest_manifest_identity", {}).get("package_manifest_sha256") == current, art.get("ingest_manifest_identity"))

    # Required negative B: parsed OLD, analyzed CURRENT.
    bad_a = write_run(base, "bad_a", manifest_sha="7" * 64, analyzed_manifest_sha=current)
    bad_b = write_run(base, "bad_b", manifest_sha="7" * 64, analyzed_manifest_sha=current)
    bad_out = base / "bad.json"
    rc = cr.main(["--mode", "reproducibility", str(bad_a), str(bad_b), "--output", str(bad_out)])
    bad_doc = json.loads(bad_out.read_text(encoding="utf-8"))
    kinds = {x.get("kind") for x in bad_doc.get("issues") or []}
    check("parsed OLD / analyzed CURRENT is INPUT_ERROR",
          rc == cr.EXIT_INPUT and bad_doc.get("status") == "INPUT_ERROR"
          and "parsed_analyzed_run_identity_mismatch" in kinds, bad_doc.get("issues"))

    # Positive four-mode gate and promotion.
    gate_dir, gate = build_four(base / "positive", current)
    check("current lineage four-mode gate eligible", gate.get("eligible") is True, gate.get("errors"))
    package = base / "package"
    write_package(package, gate_dir, gate)
    prc, pout = promotion_dry_run(package, gate_dir)
    check("current lineage promotion dry-run PASS", prc == 0 and "DRY-RUN" in pout, pout)

    # Negative C: mutate only result analyzed meta to CURRENT, leave parsed_meta OLD.
    old_dir, old_gate = build_four(base / "old", "7" * 64)
    for result_path in old_dir.glob("comparison_result_*.json"):
        doc = json.loads(result_path.read_text(encoding="utf-8"))
        for side in ("a", "b"):
            artifact = (doc.get("artifacts") or {}).get(side) or {}
            if (artifact.get("meta") or {}).get("pipeline_version") == "3.70":
                artifact["meta"]["package_manifest_sha256"] = current
        if doc.get("mode") == "reproducibility":
            issue = {
                "id": "cmp-rev12-retag-approved-review",
                "severity": "REVIEW", "kind": "parsed_field_transition",
                "section": "startup_folder", "count": 1,
                "transitions_digest": "2" * 32,
                "samples": [{"identity": "fixture", "fields": {"suspicious": {"a": False, "b": True}}}],
            }
            doc["status"] = "REVIEW"
            doc["exit_code"] = 3
            doc["summary"] = {"input_error": 0, "fail": 0, "review": 1, "review_occurrences": 1}
            doc["issues"] = [issue]
            doc["unresolved_review_ids"] = [issue["id"]]
            doc["unresolved_review_occurrence_count"] = 1
        doc["result_id"] = compute_result_id(doc)
        atomic_write_json(result_path, doc)
        if doc.get("mode") == "reproducibility":
            create_approval(
                result_path, old_dir / "comparison_approval_reproducibility.json",
                approver="rev12-negative-e2e",
                reason="fresh approval must not bypass parsed/analyzed lineage mismatch",
                review_ids=doc["unresolved_review_ids"],
            )
    retag_gate = evaluate_release_gate(old_dir)
    atomic_write_json(old_dir / "comparison_release_gate.json", retag_gate)
    errs = " | ".join(map(str, retag_gate.get("errors") or []))
    check("fresh approval exists for retagged result",
          (old_dir / "comparison_approval_reproducibility.json").is_file())
    check("result-only package retag is rejected by gate",
          retag_gate.get("eligible") is False and "parsed/analyzed package manifest mismatch" in errs, errs)
    bad_pkg = base / "retag_package"
    write_package(bad_pkg, old_dir, retag_gate)
    prc, pout = promotion_dry_run(bad_pkg, old_dir)
    check("result-only package retag promotion dry-run REJECT", prc == 1 and "BLOCKED" in pout, pout)

print("\n[2] Directory OS-managed root files")
def ent(path: str) -> dict:
    parent, _, name = path.rpartition("\\")
    return {"path": path, "dir": parent, "name": name, "size": "1", "date": "2026/08/10  10:00"}
for name in ("hiberfil.sys", "pagefile.sys", "swapfile.sys"):
    e = ent("C:\\" + name)
    check(f"C root {name} recognized as OS-managed", dp.is_root_os_managed_file(e))
    check(f"C root {name} excluded from Level1", not a.entry_matches_level1("directory", e))
    check(f"C root {name} has no floor", a._floor_rule(e["path"]) is None)
normal = ent(r"C:\payload.sys")
check("other C-root sys remains admitted", a.entry_matches_level1("directory", normal))
check("other C-root sys still has floor", a._floor_rule(normal["path"]) is not None)
raw = [ent(r"C:\hiberfil.sys"), normal]
filtered = a.apply_level1_filter("directory", raw)
check("OS-managed exclusion does not delete raw evidence", len(raw) == 2 and raw[0]["name"] == "hiberfil.sys")
check("only triage candidate is removed", len(filtered) == 1 and filtered[0]["name"] == "payload.sys", filtered)

print("\n[3] report/UI simplification")
policy = {
    "tier_total": {"M0": 0, "M1": 46, "R": 88},
    "tier_selected": {"M0": 0, "M1": 46, "R": 0},
    "deferred_reason_counts": {"signature_diversity": 88},
    "coverage_degraded": True,
}
analyzed = {
    "meta": {"hostname": "HOST", "pipeline_version": "3.70", "analysis_schema_version": "2.1"},
    "depth": 1,
    "sections": {
        "directory": {
            "entries": [{"identifier": "⚠ directory: 同型パターン88件を代表3件/型に集約（raw_directory退避）", "score": "MEDIUM", "reason": "x"}],
            "_directory_policy": policy,
            "evidence_state": "UNKNOWN",
            "section_summary": "directory test",
        },
        "dns_cache": {"entries": [], "evidence_state": "UNKNOWN", "section_summary": "not collected"},
    },
}
notice = "\n".join(report_gen._directory_coverage_notice(analyzed))
md = report_gen.generate_report(analyzed, {}, full=False)
check("directory coverage counts remain visible", "候補 134件中" in notice and "未個別評価 88件" in notice, notice)
check("signature_diversity wording removed from coverage notice", "signature_diversity" not in notice, notice)
check("signature synthetic warning hidden from final report", "同型パターン88件" not in md, md[-1200:])
check("collection quality section removed", "収集品質・解析制約" not in md, md[:2000])
server_text = (HERE / "server.py").read_text(encoding="utf-8")
check("report modal body has stable id", 'id="reportModalBody"' in server_text)
check("report open resets scrollTop before and after opening",
      'reportBody.scrollTop = 0;' in server_text and 'requestAnimationFrame(() => { reportBody.scrollTop = 0; });' in server_text)

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
