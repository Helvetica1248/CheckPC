#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Create and validate immutable approvals for comparison REVIEW items."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from atomic_io import atomic_write_json
from comparison_provenance import sha256_file

COMPARISON_RESULT_SCHEMA = 1
COMPARISON_APPROVAL_SCHEMA = 2
ALLOWED_RESULT_STATUSES = frozenset({"PASS", "REVIEW", "FAIL", "INPUT_ERROR"})
ALLOWED_RESULT_MODES = frozenset({
    "reproducibility", "cross-version", "full-lean", "depth1-depth2",
})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _stable_result_payload(value: Mapping[str, Any]) -> dict[str, Any]:
    stable = dict(value)
    stable.pop("generated_at", None)
    stable.pop("result_id", None)
    return stable


def compute_result_id(value: Mapping[str, Any]) -> str:
    raw = json.dumps(
        _stable_result_payload(value), ensure_ascii=False,
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def validate_result_object(value: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["comparison result must be an object"]
    if value.get("comparison_result_schema") != COMPARISON_RESULT_SCHEMA:
        errors.append("unsupported comparison result schema")
    mode = str(value.get("mode") or "")
    if mode not in ALLOWED_RESULT_MODES:
        errors.append(f"unsupported comparison mode: {mode or '<missing>'}")
    status = str(value.get("status") or "")
    if status not in ALLOWED_RESULT_STATUSES:
        errors.append(f"unsupported comparison status: {status or '<missing>'}")
    review_ids = value.get("unresolved_review_ids")
    if not isinstance(review_ids, list) or any(not isinstance(x, str) or not x for x in review_ids):
        errors.append("unresolved_review_ids must be a list of non-empty strings")
    elif len(review_ids) != len(set(review_ids)):
        errors.append("unresolved_review_ids must be unique")
    issues = value.get("issues")
    if issues is not None and not isinstance(issues, list):
        errors.append("issues must be a list when present")
    elif isinstance(issues, list):
        issue_ids = [str(x.get("id") or "") for x in issues if isinstance(x, Mapping)]
        if any(not x for x in issue_ids):
            errors.append("every issue must have a non-empty id")
        elif len(issue_ids) != len(set(issue_ids)):
            errors.append("issue ids must be unique")
        expected_review_ids = [
            str(x.get("id")) for x in issues
            if isinstance(x, Mapping) and x.get("severity") == "REVIEW"
        ]
        if isinstance(review_ids, list) and review_ids != expected_review_ids:
            errors.append("unresolved_review_ids must exactly match REVIEW issue order")
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, Mapping):
        errors.append("artifacts object missing")
    else:
        for side in ("a", "b"):
            artifact = artifacts.get(side)
            if not isinstance(artifact, Mapping):
                errors.append(f"artifacts.{side} missing")
                continue
            for field in ("parsed_sha256", "analyzed_sha256"):
                digest = str(artifact.get(field) or "").lower()
                if not _SHA256_RE.fullmatch(digest):
                    errors.append(f"artifacts.{side}.{field} must be 64 lowercase hex characters")
            meta = artifact.get("meta")
            if not isinstance(meta, Mapping) or not str(meta.get("pipeline_version") or ""):
                errors.append(f"artifacts.{side}.meta.pipeline_version missing")
    actual_id = str(value.get("result_id") or "")
    expected_id = compute_result_id(value)
    if actual_id != expected_id:
        errors.append("comparison result id mismatch")
    return errors


def load_result(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    errors = validate_result_object(value)
    if errors:
        raise ValueError("; ".join(errors))
    return value


def create_approval(result_path: str | Path, output_path: str | Path, *,
                    approver: str, reason: str, review_ids: list[str]) -> dict[str, Any]:
    result = load_result(result_path)
    unresolved = set(map(str, result.get("unresolved_review_ids") or []))
    requested = set(map(str, review_ids))
    if not requested:
        raise ValueError("at least one review id is required")
    unknown = sorted(requested - unresolved)
    if unknown:
        raise ValueError(f"unknown review ids: {', '.join(unknown)}")
    if not str(approver).strip() or not str(reason).strip():
        raise ValueError("approver and reason are required")
    approval = {
        "comparison_approval_schema": COMPARISON_APPROVAL_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "comparison_result_sha256": sha256_file(result_path),
        "comparison_result_id": result.get("result_id"),
        "mode": result.get("mode"),
        "approved_review_ids": sorted(requested),
        "approved_review_count": len(requested),
        "approved_review_occurrence_count": sum(
            int(issue.get("occurrence_count", 1) or 1)
            for issue in result.get("issues", [])
            if isinstance(issue, Mapping) and issue.get("id") in requested
        ),
        "approver": str(approver).strip(),
        "reason": str(reason).strip(),
    }
    atomic_write_json(output_path, approval)
    return approval


def validate_approval(result_path: str | Path, approval_path: str | Path) -> list[str]:
    errors: list[str] = []
    try:
        result = load_result(result_path)
    except Exception as exc:
        return [f"invalid comparison result: {exc}"]
    approval = json.loads(Path(approval_path).read_text(encoding="utf-8"))
    if not isinstance(approval, dict) or approval.get("comparison_approval_schema") != COMPARISON_APPROVAL_SCHEMA:
        return ["unsupported approval schema"]
    actual_sha = sha256_file(result_path)
    if approval.get("comparison_result_sha256") != actual_sha:
        errors.append("comparison result sha256 mismatch")
    if approval.get("comparison_result_id") != result.get("result_id"):
        errors.append("comparison result id mismatch")
    if approval.get("mode") != result.get("mode"):
        errors.append("comparison mode mismatch")
    unresolved = set(map(str, result.get("unresolved_review_ids") or []))
    approved = set(map(str, approval.get("approved_review_ids") or []))
    if not approved <= unresolved:
        errors.append("approval contains unknown review ids")
    if not str(approval.get("approver") or "").strip():
        errors.append("approver missing")
    if not str(approval.get("reason") or "").strip():
        errors.append("reason missing")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("result")
    create.add_argument("--output", required=True)
    create.add_argument("--approver", required=True)
    create.add_argument("--reason", required=True)
    create.add_argument("--review-id", action="append", default=[])
    validate = sub.add_parser("validate")
    validate.add_argument("result")
    validate.add_argument("approval")
    args = parser.parse_args()
    try:
        if args.command == "create":
            approval = create_approval(args.result, args.output, approver=args.approver,
                                       reason=args.reason, review_ids=args.review_id)
            print(json.dumps(approval, ensure_ascii=False, indent=2))
            return 0
        errors = validate_approval(args.result, args.approval)
        if errors:
            print(json.dumps({"valid": False, "errors": errors}, ensure_ascii=False, indent=2))
            return 1
        print(json.dumps({"valid": True}, ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(f"[ERROR] {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
