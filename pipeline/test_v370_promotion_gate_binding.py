#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 rev2: formal promotion must bind the exact new comparison gate."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import promote_to_formal as promo  # noqa: E402
from atomic_io import atomic_write_json  # noqa: E402
from comparison_approval import compute_result_id, create_approval  # noqa: E402
from comparison_release_gate import (  # noqa: E402
    CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION,
    REQUIRED_MODES,
    current_package_manifest_sha256,
    evaluate_release_gate,
)
from comparison_provenance import sha256_file  # noqa: E402
from version import PIPELINE_VERSION  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}" + (f": {detail}" if detail else ""))


def result_for(mode: str, marker: str = "base") -> dict:
    issue = {
        "id": f"cmp-{mode}-{marker}",
        "severity": "REVIEW",
        "kind": "parsed_field_transition",
        "section": "startup_folder",
        "count": 1,
        "fields": ["suspicious"],
        "transitions_digest": (marker.encode("utf-8").hex() + "0" * 32)[:32],
        "samples": [{
            "identity": f"startup_folder:{marker}:0",
            "fields": {"suspicious": {"a": False, "b": True}},
        }],
    }
    row = {
        "comparison_result_schema": 1,
        "generated_at": "2026-08-05T00:00:00+00:00",
        "mode": mode,
        "strict_llm": False,
        "comparison_implementation": {
            "evidence_version": CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION,
            "compare_runs_sha256": sha256_file(Path(__file__).resolve().parent / "compare_runs.py"),
        },
        "comparison_scope": {"included": [], "excluded": []},
        "status": "REVIEW",
        "exit_code": 1,
        "summary": {"input_error": 0, "fail": 0, "review": 1,
                    "review_occurrences": 1},
        "artifacts": {
            "a": {
                "parsed_sha256": "a" * 64,
                "analyzed_sha256": "b" * 64,
                "parsed_meta": {"pipeline_version": PIPELINE_VERSION,
                                "source_id_algorithm_version": "1",
                                "package_manifest_sha256": current_package_manifest_sha256()},
                "ingest_manifest_sha256": None,
                "ingest_manifest_identity": None,
                "meta": {"pipeline_version": PIPELINE_VERSION,
                         "source_id_algorithm_version": "1",
                         "package_manifest_sha256": current_package_manifest_sha256()},
            },
            "b": {
                "parsed_sha256": "c" * 64,
                "analyzed_sha256": "d" * 64,
                "parsed_meta": {"pipeline_version": PIPELINE_VERSION,
                                "source_id_algorithm_version": "1",
                                "package_manifest_sha256": current_package_manifest_sha256()},
                "ingest_manifest_sha256": None,
                "ingest_manifest_identity": None,
                "meta": {"pipeline_version": PIPELINE_VERSION,
                         "source_id_algorithm_version": "1",
                         "package_manifest_sha256": current_package_manifest_sha256()},
            },
        },
        "identity_matching": {},
        "issues": [issue],
        "unresolved_review_ids": [issue["id"]],
        "unresolved_review_occurrence_count": 1,
    }
    row["result_id"] = compute_result_id(row)
    return row


def create_gate(root: Path, marker: str = "base") -> dict:
    root.mkdir(parents=True, exist_ok=True)
    for mode in REQUIRED_MODES:
        result_path = root / f"comparison_result_{mode}.json"
        approval_path = root / f"comparison_approval_{mode}.json"
        result = result_for(mode, f"{marker}-{mode}")
        atomic_write_json(result_path, result)
        create_approval(
            result_path,
            approval_path,
            approver="tester",
            reason="manual regression approval",
            review_ids=result["unresolved_review_ids"],
        )
    gate = evaluate_release_gate(root)
    atomic_write_json(root / "comparison_release_gate.json", gate)
    return gate


def write_package(root: Path, gate_dir: Path, gate: dict) -> None:
    (root / "version.py").write_text(
        'PIPELINE_VERSION = "3.70"\n'
        'ANALYSIS_SCHEMA_VERSION = "2.1"\n'
        'RELEASE_STATUS = "validation-pending"\n'
        'BUDGET_PROFILE_DEFAULT = "v370"\n',
        encoding="utf-8",
    )
    (root / "budget_profile.py").write_text(
        'PROFILES = {"v369": {"name": "v369", "n": 1, '
        '"provisional": False, "validated": True}, '
        '"v370": {"name": "v370", "n": 1, '
        '"provisional": False, "validated": True}}\n',
        encoding="utf-8",
    )
    shutil.copy2(Path(__file__).resolve().parent / "compare_runs.py",
                 root / "compare_runs.py")
    shutil.copy2(Path(__file__).resolve().parent / "SHA256SUMS.txt",
                 root / "SHA256SUMS.txt")
    (root / "verify_analysis_runtime_unchanged.py").write_text(
        "raise SystemExit(0)\n", encoding="utf-8"
    )
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
        "comparison_gate": {
            "required": True,
            "directory": str(gate_dir.resolve()),
            **copy.deepcopy(gate),
        },
    }
    atomic_write_json(root / "test_results.json", summary)


def snapshots(root: Path) -> dict[str, bytes | None]:
    return {
        name: (root / name).read_bytes() if (root / name).exists() else None
        for name in ("version.py", "budget_profile.py", "formal_promotion.json")
    }


def run_promotion(root: Path, gate_dir: Path | None, *, dry_run: bool = False) -> tuple[int, str]:
    old_here = promo.HERE
    old_runtime = promo.check_runtime_baseline
    old_budget = promo.check_numeric_budget
    old_argv = list(sys.argv)
    promo.HERE = root
    promo.check_runtime_baseline = lambda baseline, errors: None
    promo.check_numeric_budget = lambda errors: None
    argv = ["promote_to_formal.py", "--runtime-baseline", str(root / "baseline.json"),
            "--source-package-sha256", "e" * 64]
    if gate_dir is not None:
        argv += ["--comparison-gate-dir", str(gate_dir)]
    if dry_run:
        argv.append("--dry-run")
    sys.argv = argv
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            try:
                rc = promo.main()
            except SystemExit as exc:
                rc = int(exc.code or 0)
    finally:
        promo.HERE = old_here
        promo.check_runtime_baseline = old_runtime
        promo.check_numeric_budget = old_budget
        sys.argv = old_argv
    return rc, buf.getvalue()


with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    package = base / "package"
    package.mkdir()
    gate1 = base / "gate1"
    gate1_doc = create_gate(gate1)
    write_package(package, gate1, gate1_doc)

    # 1. Exact bound gate promotes and records four result/approval SHA sets.
    rc, out = run_promotion(package, gate1)
    check("matching gate and test_results promote", rc == 0, out)
    promotion = json.loads((package / "formal_promotion.json").read_text(encoding="utf-8"))
    check("promotion records schema 2", promotion.get("schema") == 2, repr(promotion))
    check("promotion records exact gate directory",
          promotion.get("comparison_gate_directory") == str(gate1.resolve()))
    check("promotion records gate JSON SHA",
          promotion.get("comparison_gate_json_sha256") == sha256_file(
              gate1 / "comparison_release_gate.json"))
    modes = promotion.get("comparison_modes") or []
    check("promotion records all four modes", {row.get("mode") for row in modes} == set(REQUIRED_MODES))
    check("every mode records one result SHA and one approval SHA",
          all(len(row.get("result_sha256", "")) == 64
              and len(row.get("approval_files") or []) == 1
              and len((row.get("approval_files") or [{}])[0].get("sha256", "")) == 64
              for row in modes), repr(modes))
    check("comparisons_regenerated is evidence-derived true",
          promotion.get("comparisons_regenerated") is True)

    # Reset package for blocking cases.
    package2 = base / "package2"
    package2.mkdir()
    write_package(package2, gate1, gate1_doc)

    # 2/5. Embedded old gate directory versus new supplied gate directory blocks.
    gate2 = base / "gate2"
    gate2_doc = create_gate(gate2, "new")
    before = snapshots(package2)
    rc, out = run_promotion(package2, gate2)
    check("old embedded gate versus new argument blocks", rc == 1, out)
    check("directory mismatch block modifies no files", snapshots(package2) == before)

    # 3. Embedded result SHA mismatch blocks even when directory is equal.
    summary = json.loads((package2 / "test_results.json").read_text(encoding="utf-8"))
    summary["comparison_gate"] = {"required": True, "directory": str(gate1.resolve()),
                                  **copy.deepcopy(gate1_doc)}
    summary["comparison_gate"]["modes"][0]["result_sha256"] = "0" * 64
    atomic_write_json(package2 / "test_results.json", summary)
    before = snapshots(package2)
    rc, out = run_promotion(package2, gate1)
    check("embedded result SHA mismatch blocks", rc == 1, out)
    check("result SHA mismatch modifies no files", snapshots(package2) == before)

    # Restore exact summary.
    write_package(package2, gate1, gate1_doc)

    # 4. Approval changed to an old result ID blocks direct gate evaluation.
    approval_path = gate1 / "comparison_approval_reproducibility.json"
    original_approval = approval_path.read_bytes()
    approval = json.loads(original_approval.decode("utf-8"))
    approval["comparison_result_id"] = "old-result-id"
    atomic_write_json(approval_path, approval)
    before = snapshots(package2)
    rc, out = run_promotion(package2, gate1)
    check("approval for old result ID blocks", rc == 1, out)
    check("old approval block modifies no files", snapshots(package2) == before)
    approval_path.write_bytes(original_approval)
    atomic_write_json(gate1 / "comparison_release_gate.json", evaluate_release_gate(gate1))
    gate1_doc = evaluate_release_gate(gate1)
    write_package(package2, gate1, gate1_doc)

    # Gate file tampering is independently detected.
    tampered = json.loads((gate1 / "comparison_release_gate.json").read_text(encoding="utf-8"))
    tampered["eligible"] = False
    atomic_write_json(gate1 / "comparison_release_gate.json", tampered)
    before = snapshots(package2)
    rc, out = run_promotion(package2, gate1)
    check("tampered gate JSON blocks", rc == 1, out)
    check("tampered gate block modifies no files", snapshots(package2) == before)
    atomic_write_json(gate1 / "comparison_release_gate.json", evaluate_release_gate(gate1))

    # 6. Gate argument is mandatory and argparse exits before writes.
    before = snapshots(package2)
    rc, out = run_promotion(package2, None)
    check("missing comparison gate argument is rejected", rc == 2, out)
    check("missing argument modifies no files", snapshots(package2) == before)

    # Dry-run validates but never writes.
    gate1_doc = evaluate_release_gate(gate1)
    write_package(package2, gate1, gate1_doc)
    before = snapshots(package2)
    rc, out = run_promotion(package2, gate1, dry_run=True)
    check("dry-run succeeds with exact evidence", rc == 0, out)
    check("dry-run modifies no files", snapshots(package2) == before)

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(1 if FAIL else 0)
