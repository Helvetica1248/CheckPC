#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate the four approved comparison modes required for formal release.

The returned gate object is also an immutable evidence index.  In addition to
result SHA-256 values it records every valid approval file that contributes to
an approved REVIEW set.  ``run_all_tests.py --release`` embeds this object in
``test_results.json``; ``promote_to_formal.py`` re-evaluates the directory and
requires the embedded evidence to match byte-for-byte before promotion.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from atomic_io import atomic_write_json
from comparison_approval import load_result, validate_approval
from compare_runs import (
    COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION as CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION,
)
from comparison_provenance import sha256_file
from version import PIPELINE_VERSION, UPGRADED_FROM_VERSION

REQUIRED_MODES = ("reproducibility", "cross-version", "full-lean", "depth1-depth2")


def current_package_manifest_sha256(package_dir: str | Path | None = None) -> str:
    """SHA-256 identity of the current package's SHA256SUMS.txt file."""
    root = Path(package_dir).resolve() if package_dir is not None else Path(__file__).resolve().parent
    manifest = root / "SHA256SUMS.txt"
    if not manifest.is_file():
        raise FileNotFoundError(f"current package manifest missing: {manifest}")
    return sha256_file(manifest)


def _load_approvals(root: Path, errors: list[str]) -> list[tuple[Path, dict[str, Any]]]:
    rows: list[tuple[Path, dict[str, Any]]] = []
    for approval_path in sorted(root.glob("comparison_approval*.json")):
        try:
            value = json.loads(approval_path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("object required")
        except Exception as exc:
            errors.append(f"invalid approval {approval_path.name}: {exc}")
            continue
        rows.append((approval_path, value))
    return rows


def evaluate_release_gate(directory: str | Path, *, required_modes=REQUIRED_MODES, package_dir: str | Path | None = None) -> dict[str, Any]:
    root = Path(directory)
    errors: list[str] = []
    rows: list[dict[str, Any]] = []
    try:
        current_manifest_sha = current_package_manifest_sha256(package_dir)
    except Exception as exc:
        current_manifest_sha = ""
        errors.append(f"current package manifest identity unavailable: {exc}")
    if not root.is_dir():
        return {
            "comparison_release_gate_schema": 1,
            "pipeline_version": PIPELINE_VERSION,
            "upgraded_from_version": UPGRADED_FROM_VERSION,
            "current_package_manifest_sha256": current_manifest_sha,
            "eligible": False,
            "errors": [f"comparison gate directory missing: {root}"],
            "required_modes": list(required_modes),
            "modes": [],
        }

    approvals = _load_approvals(root, errors)
    results: dict[str, list[tuple[Path, dict[str, Any]]]] = {
        mode: [] for mode in required_modes
    }
    for path in sorted(root.glob("comparison_result*.json")):
        try:
            value = load_result(path)
        except Exception as exc:
            errors.append(f"invalid result {path.name}: {exc}")
            continue
        mode = str(value.get("mode") or "")
        if mode in results:
            results[mode].append((path, value))

    for mode in required_modes:
        candidates = results.get(mode) or []
        if len(candidates) != 1:
            errors.append(f"mode {mode}: expected one result, found {len(candidates)}")
            continue

        result_path, result = candidates[0]
        status = str(result.get("status") or "")
        if status not in {"PASS", "REVIEW"}:
            errors.append(f"mode {mode}: non-releasable status={status}")
        artifact_rows = result.get("artifacts") or {}
        versions = {
            str((artifact_rows.get(side) or {}).get("meta", {}).get("pipeline_version") or "")
            for side in ("a", "b")
        }
        if PIPELINE_VERSION not in versions:
            errors.append(f"mode {mode}: current pipeline version {PIPELINE_VERSION} absent")

        current_artifacts: list[dict[str, Any]] = []
        for side in ("a", "b"):
            artifact = artifact_rows.get(side) or {}
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
            if pipeline_version != PIPELINE_VERSION:
                continue
            artifact_manifest_sha = str(meta.get("package_manifest_sha256") or "").lower()
            parsed_pipeline_version = str(parsed_meta.get("pipeline_version") or "")
            parsed_manifest_sha = str(parsed_meta.get("package_manifest_sha256") or "").lower()
            analyzed_source_algo = str(meta.get("source_id_algorithm_version") or "")
            parsed_source_algo = str(parsed_meta.get("source_id_algorithm_version") or "")
            ingest_manifest_sha = (
                str((ingest_identity or {}).get("package_manifest_sha256") or "").lower()
                if ingest_identity is not None else ""
            )
            ingest_pipeline_version = (
                str((ingest_identity or {}).get("pipeline_version") or "")
                if ingest_identity is not None else ""
            )
            ingest_source_algo = (
                str((ingest_identity or {}).get("source_id_algorithm_version") or "")
                if ingest_identity is not None else ""
            )
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
            if artifact_manifest_sha != current_manifest_sha:
                errors.append(
                    f"mode {mode}: current artifact side {side} package manifest mismatch: "
                    f"expected={current_manifest_sha or '<unavailable>'} "
                    f"actual={artifact_manifest_sha or '<missing>'}"
                )
            if parsed_pipeline_version != pipeline_version:
                errors.append(f"mode {mode}: current artifact side {side} parsed/analyzed pipeline version mismatch")
            if parsed_manifest_sha != artifact_manifest_sha:
                errors.append(f"mode {mode}: current artifact side {side} parsed/analyzed package manifest mismatch")
            if parsed_source_algo != analyzed_source_algo:
                errors.append(f"mode {mode}: current artifact side {side} parsed/analyzed source-id algorithm mismatch")
            if ingest_identity is not None:
                if ingest_pipeline_version != pipeline_version:
                    errors.append(f"mode {mode}: current artifact side {side} ingest/analyzed pipeline version mismatch")
                if ingest_manifest_sha != artifact_manifest_sha:
                    errors.append(f"mode {mode}: current artifact side {side} ingest/analyzed package manifest mismatch")
                if ingest_source_algo != analyzed_source_algo:
                    errors.append(f"mode {mode}: current artifact side {side} ingest/analyzed source-id algorithm mismatch")

        expected_compare_sha = sha256_file(Path(__file__).with_name("compare_runs.py"))
        implementation = result.get("comparison_implementation") or {}
        if implementation.get("evidence_version") != CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION:
            errors.append(
                f"mode {mode}: comparison implementation evidence version mismatch: "
                f"expected={CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION} "
                f"actual={implementation.get('evidence_version')!r}"
            )
        if implementation.get("compare_runs_sha256") != expected_compare_sha:
            errors.append(f"mode {mode}: comparison implementation SHA mismatch")

        review_id_list = list(map(str, result.get("unresolved_review_ids") or []))
        review_ids = set(review_id_list)
        approved: set[str] = set()
        approval_evidence: list[dict[str, Any]] = []

        for approval_path, approval in approvals:
            if approval.get("comparison_result_id") != result.get("result_id"):
                continue
            approval_errors = validate_approval(result_path, approval_path)
            if approval_errors:
                errors.append(f"{approval_path.name}: {'; '.join(approval_errors)}")
                continue
            approved_ids = sorted(map(str, approval.get("approved_review_ids") or []))
            approved.update(approved_ids)
            approval_evidence.append({
                "file": approval_path.name,
                "sha256": sha256_file(approval_path),
                "approved_review_ids": approved_ids,
                "approved_review_count": int(
                    approval.get("approved_review_count", len(approved_ids)) or 0
                ),
                "approved_review_occurrence_count": int(
                    approval.get("approved_review_occurrence_count", 0) or 0
                ),
            })

        missing = sorted(review_ids - approved)
        if missing:
            errors.append(f"mode {mode}: unapproved reviews: {', '.join(missing[:8])}")

        issue_by_id = {
            str(issue.get("id")): issue
            for issue in result.get("issues", [])
            if isinstance(issue, dict) and issue.get("severity") == "REVIEW"
        }
        review_occurrences = sum(
            int(issue_by_id[review_id].get("occurrence_count", 1) or 1)
            for review_id in review_id_list
            if review_id in issue_by_id
        )
        approved_occurrences = sum(
            int(issue_by_id[review_id].get("occurrence_count", 1) or 1)
            for review_id in (review_ids & approved)
            if review_id in issue_by_id
        )
        approval_evidence.sort(key=lambda row: (row["file"], row["sha256"]))

        rows.append({
            "mode": mode,
            "result": result_path.name,
            "result_id": str(result.get("result_id") or ""),
            "result_sha256": sha256_file(result_path),
            "compare_runs_sha256": str(implementation.get("compare_runs_sha256") or ""),
            "comparison_implementation_evidence_version": int(
                implementation.get("evidence_version", 0) or 0
            ),
            "current_artifacts": current_artifacts,
            "status": status,
            "review_count": len(review_ids),
            "review_occurrence_count": review_occurrences,
            "approved_review_count": len(review_ids & approved),
            "approved_review_occurrence_count": approved_occurrences,
            "approvals": approval_evidence,
            "approval_count": len(approval_evidence),
            "approval_sha256s": [row["sha256"] for row in approval_evidence],
        })

    return {
        "comparison_release_gate_schema": 1,
        "pipeline_version": PIPELINE_VERSION,
        "upgraded_from_version": UPGRADED_FROM_VERSION,
        "current_package_manifest_sha256": current_manifest_sha,
        "eligible": not errors,
        "required_modes": list(required_modes),
        "modes": rows,
        "errors": errors,
    }


def build_index(directory: str | Path, output: str | Path) -> dict[str, Any]:
    summary = evaluate_release_gate(directory)
    atomic_write_json(output, summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    parser.add_argument("--json-out")
    args = parser.parse_args()
    summary = evaluate_release_gate(args.directory)
    if args.json_out:
        atomic_write_json(args.json_out, summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary.get("eligible") else 1


if __name__ == "__main__":
    raise SystemExit(main())
