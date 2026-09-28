#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Promote v3.70 metadata only when base117 evidence is cryptographically bound.

Promotion is fail-closed and metadata-only.  The script re-evaluates the exact
comparison directory supplied on the command line, validates its immutable
results and approvals, verifies that ``test_results.json`` embeds the same gate
evidence, proves the analysis runtime is unchanged, and verifies that v370's
numeric budget is identical to formal v369.  No file is modified until every
precondition succeeds.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from comparison_approval import load_result, validate_approval
from comparison_provenance import sha256_file
from comparison_release_gate import (
    CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION,
    REQUIRED_MODES,
    current_package_manifest_sha256,
    evaluate_release_gate,
)

HERE = Path(__file__).resolve().parent
FORMAL_RELEASE_STATUS = "release"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST32_RE = re.compile(r"^[0-9a-f]{32}$")


def _fail(errors: list[str], message: str) -> None:
    errors.append(message)


def _load_json(path: Path, errors: list[str], label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        _fail(errors, f"{label}: cannot read {path}: {exc}")
        return None


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _gate_core(value: dict[str, Any]) -> dict[str, Any]:
    """Return the stable evidence fields shared by gate file and test summary."""
    modes = []
    for row in value.get("modes") or []:
        if not isinstance(row, dict):
            continue
        approvals = []
        for approval in row.get("approvals") or []:
            if isinstance(approval, dict):
                approvals.append({
                    "file": str(approval.get("file") or ""),
                    "sha256": str(approval.get("sha256") or ""),
                    "approved_review_ids": sorted(
                        map(str, approval.get("approved_review_ids") or [])
                    ),
                    "approved_review_count": int(
                        approval.get("approved_review_count", 0) or 0
                    ),
                    "approved_review_occurrence_count": int(
                        approval.get("approved_review_occurrence_count", 0) or 0
                    ),
                })
        approvals.sort(key=lambda item: (item["file"], item["sha256"]))
        current_artifacts = []
        for artifact in row.get("current_artifacts") or []:
            if isinstance(artifact, dict):
                current_artifacts.append({
                    "side": str(artifact.get("side") or ""),
                    "pipeline_version": str(artifact.get("pipeline_version") or ""),
                    "package_manifest_sha256": str(artifact.get("package_manifest_sha256") or ""),
                    "source_id_algorithm_version": str(artifact.get("source_id_algorithm_version") or ""),
                    "parsed_pipeline_version": str(artifact.get("parsed_pipeline_version") or ""),
                    "parsed_package_manifest_sha256": str(artifact.get("parsed_package_manifest_sha256") or ""),
                    "parsed_source_id_algorithm_version": str(artifact.get("parsed_source_id_algorithm_version") or ""),
                    "parsed_sha256": str(artifact.get("parsed_sha256") or ""),
                    "analyzed_sha256": str(artifact.get("analyzed_sha256") or ""),
                    "ingest_manifest_sha256": str(artifact.get("ingest_manifest_sha256") or ""),
                    "ingest_pipeline_version": str(artifact.get("ingest_pipeline_version") or ""),
                    "ingest_package_manifest_sha256": str(artifact.get("ingest_package_manifest_sha256") or ""),
                    "ingest_source_id_algorithm_version": str(artifact.get("ingest_source_id_algorithm_version") or ""),
                })
        current_artifacts.sort(key=lambda item: item["side"])
        modes.append({
            "mode": str(row.get("mode") or ""),
            "result": str(row.get("result") or ""),
            "result_id": str(row.get("result_id") or ""),
            "result_sha256": str(row.get("result_sha256") or ""),
            "compare_runs_sha256": str(row.get("compare_runs_sha256") or ""),
            "comparison_implementation_evidence_version": int(
                row.get("comparison_implementation_evidence_version", 0) or 0
            ),
            "current_artifacts": current_artifacts,
            "status": str(row.get("status") or ""),
            "review_count": int(row.get("review_count", 0) or 0),
            "review_occurrence_count": int(
                row.get("review_occurrence_count", 0) or 0
            ),
            "approved_review_count": int(
                row.get("approved_review_count", 0) or 0
            ),
            "approved_review_occurrence_count": int(
                row.get("approved_review_occurrence_count", 0) or 0
            ),
            "approvals": approvals,
            "approval_count": len(approvals),
            "approval_sha256s": [item["sha256"] for item in approvals],
        })
    modes.sort(key=lambda item: item["mode"])
    return {
        "comparison_release_gate_schema": value.get("comparison_release_gate_schema"),
        "pipeline_version": value.get("pipeline_version"),
        "upgraded_from_version": value.get("upgraded_from_version"),
        "current_package_manifest_sha256": str(value.get("current_package_manifest_sha256") or ""),
        "eligible": bool(value.get("eligible")),
        "required_modes": list(map(str, value.get("required_modes") or [])),
        "modes": modes,
        "errors": list(map(str, value.get("errors") or [])),
    }


def check_test_results(errors: list[str]) -> dict[str, Any]:
    data = _load_json(HERE / "test_results.json", errors, "test_results")
    if not isinstance(data, dict):
        return {}
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else data
    if not isinstance(summary, dict):
        _fail(errors, "test_results: summary object missing")
        return {}

    if not summary.get("release_mode"):
        _fail(errors, "test_results: release_mode is not true")
    if not summary.get("formal_release_eligible"):
        _fail(errors, "test_results: formal_release_eligible is not true")
    if str(summary.get("environment_label", "")) != "base117":
        _fail(errors, "test_results: environment_label must be 'base117', got "
                      f"{summary.get('environment_label')!r}")
    for key in ("new_fail", "known_fail", "error", "skip"):
        value = summary.get(key)
        if value is None:
            _fail(errors, f"test_results: missing {key}")
        else:
            try:
                nonzero = int(value) != 0
            except (TypeError, ValueError):
                nonzero = True
            if nonzero:
                _fail(errors, f"test_results: {key}={value!r}, formal release requires 0")
    return summary


def check_runtime_baseline(baseline: Path, errors: list[str]) -> None:
    if not baseline.is_file():
        _fail(errors, f"runtime baseline not found: {baseline}")
        return
    proc = subprocess.run(
        [sys.executable, str(HERE / "verify_analysis_runtime_unchanged.py"),
         "--baseline", str(baseline)],
        capture_output=True, text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if proc.returncode != 0:
        tail = (proc.stdout + proc.stderr).strip().splitlines()[-8:]
        _fail(errors, "analysis runtime changed since the 4-mode baseline: "
                      + " | ".join(tail))


def check_numeric_budget(errors: list[str]) -> None:
    sys.path.insert(0, str(HERE))
    try:
        import budget_profile
    except Exception as exc:
        _fail(errors, f"budget_profile import failed: {exc}")
        return
    metadata = {"name", "note", "provisional", "validated", "warning"}
    v370 = budget_profile.PROFILES.get("v370") or {}
    v369 = budget_profile.PROFILES.get("v369") or {}
    diff = sorted(
        key for key in set(v370) | set(v369)
        if key not in metadata and v370.get(key) != v369.get(key)
    )
    if diff:
        _fail(errors, "budget_profile: v370 numeric fields differ from formal "
                      f"v369: {diff}")


def _digest_complete(result: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    stage_names = {"mandatory", "deterministic", "selected", "deferred", "evaluated", "unevaluated"}
    for issue in result.get("issues") or []:
        if not isinstance(issue, dict) or issue.get("severity") != "REVIEW":
            continue
        kind = str(issue.get("kind") or "")
        field = ""
        if kind == "parsed_field_transition":
            field = "transitions_digest"
        elif kind == "raw_evidence_added":
            field = "evidence_digest"
        else:
            for stage in stage_names:
                if kind in {f"{stage}_added", f"{stage}_set_difference"}:
                    field = "evidence_digest"
                    break
        if field and not _DIGEST32_RE.fullmatch(str(issue.get(field) or "")):
            errors.append(f"{kind}:{issue.get('id')}: missing valid {field}")
    return errors


def check_comparison_gate(directory: Path, summary: dict[str, Any],
                          errors: list[str]) -> dict[str, Any]:
    root = directory.resolve()
    if not root.is_dir():
        _fail(errors, f"comparison gate directory missing: {root}")
        return {}

    embedded = summary.get("comparison_gate") or {}
    if not isinstance(embedded, dict):
        _fail(errors, "test_results: comparison_gate must be an object")
        return {}
    embedded_dir = str(embedded.get("directory") or "")
    if not embedded_dir:
        _fail(errors, "test_results: comparison_gate.directory missing")
    else:
        try:
            if Path(embedded_dir).resolve() != root:
                _fail(errors, "test_results: comparison_gate.directory does not match "
                              f"--comparison-gate-dir: {embedded_dir!r} != {str(root)!r}")
        except Exception as exc:
            _fail(errors, f"test_results: invalid comparison gate directory: {exc}")

    direct = evaluate_release_gate(root, package_dir=HERE)
    if not direct.get("eligible") or direct.get("errors"):
        _fail(errors, "comparison gate direct evaluation failed: "
                      + "; ".join(map(str, direct.get("errors") or [])))

    try:
        expected_package_manifest_sha = current_package_manifest_sha256(HERE)
    except Exception as exc:
        expected_package_manifest_sha = ""
        _fail(errors, f"current package manifest identity unavailable during promotion: {exc}")
    if str(direct.get("current_package_manifest_sha256") or "") != expected_package_manifest_sha:
        _fail(errors, "comparison gate current package manifest identity differs from promotion package")

    gate_path = root / "comparison_release_gate.json"
    gate_file = _load_json(gate_path, errors, "comparison gate JSON")
    if isinstance(gate_file, dict):
        if _canonical_json(_gate_core(gate_file)) != _canonical_json(_gate_core(direct)):
            _fail(errors, "comparison_release_gate.json does not match direct evaluation")
    else:
        gate_file = {}

    if _canonical_json(_gate_core(embedded)) != _canonical_json(_gate_core(direct)):
        _fail(errors, "test_results comparison_gate does not match direct evaluation")

    mode_rows = {str(row.get("mode") or ""): row for row in direct.get("modes") or []}
    if set(mode_rows) != set(REQUIRED_MODES):
        _fail(errors, "comparison gate does not contain exactly the four required modes")

    records: list[dict[str, Any]] = []
    all_digest_complete = True
    all_current_implementation = True
    expected_compare_sha = sha256_file(HERE / "compare_runs.py")
    for mode in REQUIRED_MODES:
        row = mode_rows.get(mode)
        if not isinstance(row, dict):
            continue
        result_path = root / str(row.get("result") or "")
        try:
            result = load_result(result_path)
        except Exception as exc:
            _fail(errors, f"mode {mode}: result revalidation failed: {exc}")
            continue
        actual_result_sha = sha256_file(result_path)
        if actual_result_sha != row.get("result_sha256"):
            _fail(errors, f"mode {mode}: result SHA differs from gate")
        if str(result.get("result_id") or "") != str(row.get("result_id") or ""):
            _fail(errors, f"mode {mode}: result ID differs from gate")
        implementation = result.get("comparison_implementation") or {}
        implementation_sha = str(implementation.get("compare_runs_sha256") or "")
        implementation_version = implementation.get("evidence_version")
        if (implementation_version != CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION
                or implementation_sha != expected_compare_sha):
            all_current_implementation = False
            _fail(
                errors,
                f"mode {mode}: result was not produced by the current comparator implementation "
                f"(expected evidence_version={CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION}, "
                f"sha256={expected_compare_sha}; actual evidence_version={implementation_version!r}, "
                f"sha256={implementation_sha})",
            )
        if str(row.get("compare_runs_sha256") or "") != implementation_sha:
            _fail(errors, f"mode {mode}: comparator SHA differs from gate")
        if int(row.get("comparison_implementation_evidence_version", 0) or 0) != int(
                implementation_version or 0):
            _fail(errors, f"mode {mode}: comparator evidence version differs from gate")

        current_artifacts: list[dict[str, Any]] = []
        artifacts = result.get("artifacts") or {}
        current_pipeline_version = str(direct.get("pipeline_version") or "")
        for side in ("a", "b"):
            artifact = artifacts.get(side) or {}
            meta = artifact.get("meta") if isinstance(artifact, dict) else {}
            parsed_meta = artifact.get("parsed_meta") if isinstance(artifact, dict) else {}
            ingest_identity = artifact.get("ingest_manifest_identity") if isinstance(artifact, dict) else None
            if not isinstance(meta, dict):
                meta = {}
            if not isinstance(parsed_meta, dict):
                parsed_meta = {}
            if ingest_identity is not None and not isinstance(ingest_identity, dict):
                ingest_identity = {}
            pipeline_version = str(meta.get("pipeline_version") or "")
            if pipeline_version != current_pipeline_version:
                continue
            artifact_manifest_sha = str(meta.get("package_manifest_sha256") or "").lower()
            parsed_pipeline_version = str(parsed_meta.get("pipeline_version") or "")
            parsed_manifest_sha = str(parsed_meta.get("package_manifest_sha256") or "").lower()
            analyzed_source_algo = str(meta.get("source_id_algorithm_version") or "")
            parsed_source_algo = str(parsed_meta.get("source_id_algorithm_version") or "")
            ingest_manifest_sha = (str((ingest_identity or {}).get("package_manifest_sha256") or "").lower()
                                   if ingest_identity is not None else "")
            ingest_pipeline_version = (str((ingest_identity or {}).get("pipeline_version") or "")
                                       if ingest_identity is not None else "")
            ingest_source_algo = (str((ingest_identity or {}).get("source_id_algorithm_version") or "")
                                  if ingest_identity is not None else "")
            current_artifacts.append({
                "side": side,
                "pipeline_version": pipeline_version,
                "package_manifest_sha256": artifact_manifest_sha,
                "source_id_algorithm_version": analyzed_source_algo,
                "parsed_pipeline_version": parsed_pipeline_version,
                "parsed_package_manifest_sha256": parsed_manifest_sha,
                "parsed_source_id_algorithm_version": parsed_source_algo,
                "parsed_sha256": str(artifact.get("parsed_sha256") or ""),
                "analyzed_sha256": str(artifact.get("analyzed_sha256") or ""),
                "ingest_manifest_sha256": str(artifact.get("ingest_manifest_sha256") or ""),
                "ingest_pipeline_version": ingest_pipeline_version,
                "ingest_package_manifest_sha256": ingest_manifest_sha,
                "ingest_source_id_algorithm_version": ingest_source_algo,
            })
            if artifact_manifest_sha != expected_package_manifest_sha:
                _fail(errors, f"mode {mode}: current artifact side {side} package manifest mismatch during promotion")
            if parsed_pipeline_version != pipeline_version or parsed_manifest_sha != artifact_manifest_sha or parsed_source_algo != analyzed_source_algo:
                _fail(errors, f"mode {mode}: current artifact side {side} parsed/analyzed run identity mismatch during promotion")
            if ingest_identity is not None and (ingest_pipeline_version != pipeline_version or ingest_manifest_sha != artifact_manifest_sha or ingest_source_algo != analyzed_source_algo):
                _fail(errors, f"mode {mode}: current artifact side {side} ingest/analyzed run identity mismatch during promotion")
        current_artifacts.sort(key=lambda item: item["side"])
        gate_current_artifacts = sorted(
            [
                {
                    "side": str(item.get("side") or ""),
                    "pipeline_version": str(item.get("pipeline_version") or ""),
                    "package_manifest_sha256": str(item.get("package_manifest_sha256") or ""),
                    "source_id_algorithm_version": str(item.get("source_id_algorithm_version") or ""),
                    "parsed_pipeline_version": str(item.get("parsed_pipeline_version") or ""),
                    "parsed_package_manifest_sha256": str(item.get("parsed_package_manifest_sha256") or ""),
                    "parsed_source_id_algorithm_version": str(item.get("parsed_source_id_algorithm_version") or ""),
                    "parsed_sha256": str(item.get("parsed_sha256") or ""),
                    "analyzed_sha256": str(item.get("analyzed_sha256") or ""),
                    "ingest_manifest_sha256": str(item.get("ingest_manifest_sha256") or ""),
                    "ingest_pipeline_version": str(item.get("ingest_pipeline_version") or ""),
                    "ingest_package_manifest_sha256": str(item.get("ingest_package_manifest_sha256") or ""),
                    "ingest_source_id_algorithm_version": str(item.get("ingest_source_id_algorithm_version") or ""),
                }
                for item in (row.get("current_artifacts") or [])
                if isinstance(item, dict)
            ],
            key=lambda item: item["side"],
        )
        if current_artifacts != gate_current_artifacts:
            _fail(errors, f"mode {mode}: current artifact package identities differ from gate")

        digest_errors = _digest_complete(result)
        if digest_errors:
            all_digest_complete = False
            for message in digest_errors:
                _fail(errors, f"mode {mode}: {message}")

        approval_records = []
        for approval in row.get("approvals") or []:
            if not isinstance(approval, dict):
                _fail(errors, f"mode {mode}: malformed approval evidence")
                continue
            approval_path = root / str(approval.get("file") or "")
            approval_errors = validate_approval(result_path, approval_path)
            if approval_errors:
                _fail(errors, f"mode {mode}: approval revalidation failed: "
                              + "; ".join(approval_errors))
                continue
            actual_approval_sha = sha256_file(approval_path)
            if actual_approval_sha != approval.get("sha256"):
                _fail(errors, f"mode {mode}: approval SHA differs from gate")
            approval_records.append({
                "file": approval_path.name,
                "sha256": actual_approval_sha,
            })

        if int(row.get("review_count", 0) or 0) > 0 and not approval_records:
            _fail(errors, f"mode {mode}: REVIEW result has no bound approval")
        records.append({
            "mode": mode,
            "result_file": result_path.name,
            "result_id": str(result.get("result_id") or ""),
            "result_sha256": actual_result_sha,
            "compare_runs_sha256": implementation_sha,
            "comparison_implementation_evidence_version": int(implementation_version or 0),
            "current_artifacts": current_artifacts,
            "approval_files": approval_records,
        })

    evidence = {
        "directory": str(root),
        "gate_file": gate_path.name,
        "current_package_manifest_sha256": expected_package_manifest_sha,
        "gate_json_sha256": sha256_file(gate_path) if gate_path.is_file() else "",
        "eligible": bool(direct.get("eligible")),
        "errors": list(direct.get("errors") or []),
        "modes": records,
        "comparisons_regenerated": bool(
            direct.get("eligible")
            and not direct.get("errors")
            and len(records) == len(REQUIRED_MODES)
            and all_digest_complete
            and all_current_implementation
        ),
    }
    if not evidence["comparisons_regenerated"]:
        _fail(errors, "comparison evidence does not prove regenerated digest-aware results")
    return evidence


def _updated_version_text() -> tuple[str, str]:
    path = HERE / "version.py"
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(r'^RELEASE_STATUS\s*=\s*"[^"]*"', re.M)
    if not pattern.search(text):
        raise RuntimeError("version.py: RELEASE_STATUS assignment not found")
    updated = pattern.sub(f'RELEASE_STATUS = "{FORMAL_RELEASE_STATUS}"', text, count=1)
    return updated, f'RELEASE_STATUS -> "{FORMAL_RELEASE_STATUS}"'


def _updated_budget_text() -> tuple[str, list[str]]:
    path = HERE / "budget_profile.py"
    text = path.read_text(encoding="utf-8")
    changes: list[str] = []
    replacements = (
        (r'PROFILES\["v370"\]\["provisional"\]\s*=\s*True',
         'PROFILES["v370"]["provisional"] = False', 'provisional -> False'),
        (r'PROFILES\["v370"\]\["validated"\]\s*=\s*False',
         'PROFILES["v370"]["validated"] = True', 'validated -> True'),
    )
    updated = text
    for pattern, replacement, label in replacements:
        new = re.sub(pattern, replacement, updated, count=1)
        if new != updated:
            changes.append(label)
            updated = new
    return updated, changes or ["budget metadata already formal"]


def _promotion_payload(source_sha256: str, summary: dict[str, Any],
                       evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": 2,
        "promoted_at": datetime.now(timezone.utc).isoformat(),
        "promoted_from_package_sha256": source_sha256,
        "release_status": FORMAL_RELEASE_STATUS,
        "environment_label": summary.get("environment_label"),
        "release_mode": bool(summary.get("release_mode")),
        "formal_release_eligible": bool(summary.get("formal_release_eligible")),
        "four_mode_artifacts": "current-package-analysis-artifacts",
        "current_package_manifest_sha256": evidence.get("current_package_manifest_sha256"),
        "comparisons_regenerated": bool(evidence.get("comparisons_regenerated")),
        "comparison_gate_directory": evidence.get("directory"),
        "comparison_gate_file": evidence.get("gate_file"),
        "comparison_gate_json_sha256": evidence.get("gate_json_sha256"),
        "comparison_modes": evidence.get("modes") or [],
        "compare_runs_sha256": sha256_file(HERE / "compare_runs.py"),
        "note": (
            "Four analysis-mode artifacts were generated by the exact current "
            "candidate package manifest recorded here. Runtime invariance alone "
            "does not authorize artifact reuse. Comparisons were regenerated with "
            "the current comparator, approvals were recreated, and package identity "
            "plus exact gate evidence embedded in test_results.json were revalidated."
        ),
    }


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    temp = path.with_name(path.name + ".promotion-tmp")
    with temp.open("wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def _commit(updates: dict[Path, bytes]) -> None:
    originals: dict[Path, bytes | None] = {
        path: path.read_bytes() if path.exists() else None for path in updates
    }
    written: list[Path] = []
    try:
        for path, data in updates.items():
            _atomic_write_bytes(path, data)
            written.append(path)
    except Exception:
        for path in reversed(written):
            original = originals[path]
            if original is None:
                path.unlink(missing_ok=True)
            else:
                _atomic_write_bytes(path, original)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-baseline", required=True,
                        help="baseline JSON from verify_analysis_runtime_unchanged.py")
    parser.add_argument("--source-package-sha256", required=True,
                        help="SHA-256 of the finalized candidate distribution package that produced the current 4-mode artifacts")
    parser.add_argument("--comparison-gate-dir", required=True,
                        help="new comparison result/approval directory used by release-mode tests")
    parser.add_argument("--dry-run", action="store_true",
                        help="check preconditions and print the plan only")
    args = parser.parse_args()

    source_sha = str(args.source_package_sha256 or "").lower()
    if not _SHA256_RE.fullmatch(source_sha):
        print("INPUT ERROR: --source-package-sha256 must be 64 hex characters")
        return 2

    errors: list[str] = []
    summary = check_test_results(errors)
    baseline = Path(args.runtime_baseline).resolve()
    check_runtime_baseline(baseline, errors)
    check_numeric_budget(errors)
    evidence = check_comparison_gate(Path(args.comparison_gate_dir), summary, errors)

    print("=" * 64)
    print("  v3.70 formal promotion preconditions")
    print("=" * 64)
    if errors:
        for row in errors:
            print(f"  [BLOCK] {row}")
        print("\nRESULT: BLOCKED - no files were modified.")
        return 1

    print("  [OK] formal release-mode test results (base117)")
    print("  [OK] exact comparison gate directory bound to test_results.json")
    print("  [OK] four result SHA/ID sets and approval SHA sets revalidated")
    print("  [OK] digest-aware comparisons verified as regenerated")
    print("  [OK] current v3.70 artifacts bound to current package manifest identity")
    print("  [OK] analysis runtime unchanged")
    print("  [OK] v370 numeric budget identical to formal v369")

    version_text, version_action = _updated_version_text()
    budget_text, budget_actions = _updated_budget_text()
    payload = _promotion_payload(source_sha, summary, evidence)
    promotion_bytes = (json.dumps(
        payload, ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n").encode("utf-8")

    actions = [version_action, *budget_actions,
               f"formal_promotion.json <- gate {payload['comparison_gate_json_sha256'][:16]}…"]
    print("\n  planned changes:" if args.dry_run else "\n  applied changes:")
    for row in actions:
        print(f"    - {row}")
    if args.dry_run:
        print("\nRESULT: DRY-RUN - nothing written.")
        return 0

    try:
        _commit({
            HERE / "version.py": version_text.encode("utf-8"),
            HERE / "budget_profile.py": budget_text.encode("utf-8"),
            HERE / "formal_promotion.json": promotion_bytes,
        })
    except Exception as exc:
        print(f"\nRESULT: ERROR - promotion transaction rolled back: {exc}")
        return 1

    print("\nRESULT: PROMOTED. Next:")
    print("    PYTHONDONTWRITEBYTECODE=1 python3 generate_release_manifest.py")
    print("    PYTHONDONTWRITEBYTECODE=1 python3 verify_release_package.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
