#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate release_manifest.json and SHA256SUMS.txt deterministically."""
from __future__ import annotations
import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from atomic_io import atomic_write_json, atomic_write_text
from budget_profile import active_profile
from version import (PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION, RELEASE_STATUS,
                     UPGRADED_FROM_VERSION)

ROOT = Path(__file__).resolve().parent
EXCLUDE_NAMES = {"SHA256SUMS.txt", "release_manifest.json"}
EXCLUDE_PARTS = {"__pycache__", ".git", ".pytest_cache"}
FORBIDDEN_SECRET_NAMES = {".env", ".env.local", ".env.example"}
FORBIDDEN_PACKAGE_PARTS = {"__pycache__", ".git", ".pytest_cache"}
FORBIDDEN_PACKAGE_SUFFIXES = {".pyc", ".pyo"}


def assert_no_forbidden_secret_files() -> None:
    found = [
        path.relative_to(ROOT).as_posix()
        for path in ROOT.rglob("*")
        if path.is_file() and path.name in FORBIDDEN_SECRET_NAMES
    ]
    if found:
        raise RuntimeError(
            "forbidden secret configuration in package: " + ", ".join(sorted(found)))


def forbidden_package_artifacts() -> list[str]:
    """Return cache/build artifacts that must never be shipped.

    These files used to be silently excluded from the release manifest, which
    allowed unverified ``__pycache__/*.pyc`` content to remain inside the ZIP.
    Packaging now fails closed instead of claiming integrity for only a subset
    of the delivered files.
    """
    found: list[str] = []
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        if any(part in FORBIDDEN_PACKAGE_PARTS for part in rel.parts):
            found.append(rel.as_posix())
            continue
        if path.is_file() and path.suffix.lower() in FORBIDDEN_PACKAGE_SUFFIXES:
            found.append(rel.as_posix())
    return sorted(set(found))


def assert_no_forbidden_package_artifacts() -> None:
    found = forbidden_package_artifacts()
    if found:
        preview = ", ".join(found[:20])
        if len(found) > 20:
            preview += f", ... (+{len(found) - 20})"
        raise RuntimeError("forbidden package artifacts: " + preview)


def included_files():
    for path in sorted(ROOT.rglob("*"), key=lambda p: p.relative_to(ROOT).as_posix()):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if rel.name in EXCLUDE_NAMES or any(part in EXCLUDE_PARTS for part in rel.parts):
            continue
        if rel.suffix in {".pyc", ".zip"}:
            continue
        yield rel, path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_test_summary(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(
            f"test summary not found: {path}; run run_all_tests.py --summary-json {path.name}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    required = {
        "summary_schema", "release_mode", "pass", "new_fail", "known_fail",
        "skip", "error", "release_blocked", "skipped_tests", "shards",
        "generated_at", "python", "host", "environment_label",
    }
    missing = sorted(required - set(raw))
    if missing:
        raise ValueError(f"test summary missing fields: {', '.join(missing)}")
    shards = raw.get("shards")
    if not isinstance(shards, list) or not shards:
        raise ValueError("test summary shards must be a non-empty list")
    numeric = ("pass", "new_fail", "known_fail", "skip", "error")
    shard_totals = {key: sum(int(row.get(key, 0)) for row in shards) for key in numeric}
    for key in numeric:
        if shard_totals[key] != int(raw[key]):
            raise ValueError(
                f"test summary shard total mismatch: {key}={shard_totals[key]} total={raw[key]}")
    skipped_tests = sorted(str(x) for x in raw.get("skipped_tests", []))
    if len(skipped_tests) != int(raw["skip"]):
        raise ValueError(
            f"skipped_tests count mismatch: names={len(skipped_tests)} skip={raw['skip']}")
    comparison_gate = raw.get("comparison_gate") or {
        "directory": "", "eligible": False, "errors": [],
        "required": bool(raw.get("release_mode")),
    }
    formal_eligible = bool(
        raw.get("release_mode")
        and not raw.get("release_blocked")
        and all(int(raw[key]) == 0 for key in ("new_fail", "known_fail", "skip", "error"))
        and str(raw.get("environment_label", "")) == "base117"
        and comparison_gate.get("eligible", False)
    )
    return {
        "summary_schema": int(raw["summary_schema"]),
        "release_mode": bool(raw["release_mode"]),
        "pass": int(raw["pass"]),
        "new_fail": int(raw["new_fail"]),
        "known_fail": int(raw["known_fail"]),
        "error": int(raw["error"]),
        "skip": int(raw["skip"]),
        "skipped_test_files": int(raw["skip"]),
        "skipped_tests": skipped_tests,
        "release_blocked": bool(raw["release_blocked"]),
        "formal_release_eligible": formal_eligible,
        "comparison_gate": comparison_gate,
        "shards": shards,
        "generated_at": str(raw["generated_at"]),
        "python": str(raw["python"]),
        "host": str(raw["host"]),
        "environment_label": str(raw["environment_label"]),
        "formal_release_required": "base117 run_all_tests.py --release",
        "verification_scope": (
            "cross-file consistency; does not prove that tests were executed"),
    }


def main() -> int:
    assert_no_forbidden_secret_files()
    assert_no_forbidden_package_artifacts()
    parser = argparse.ArgumentParser()
    parser.add_argument("--test-summary-json", default="test_results.json")
    args = parser.parse_args()
    summary_path = Path(args.test_summary_json)
    if not summary_path.is_absolute():
        summary_path = ROOT / summary_path
    test_summary = _load_test_summary(summary_path)

    files = {rel.as_posix(): sha256(path) for rel, path in included_files()}
    profile = active_profile().to_dict()
    manifest = {
        "pipeline_version": PIPELINE_VERSION,
        "upgraded_from_version": UPGRADED_FROM_VERSION,
        "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
        "release_status": RELEASE_STATUS,
        "budget_profile": profile,
        "test_summary": test_summary,
        "file_count_excluding_manifests": len(files),
        "files": files,
    }
    atomic_write_json(ROOT / "release_manifest.json", manifest, indent=2)

    sum_files = list(included_files()) + [(Path("release_manifest.json"), ROOT / "release_manifest.json")]
    unique = {rel.as_posix(): path for rel, path in sum_files}
    lines = [f"{sha256(unique[name])}  {name}" for name in sorted(unique)]
    atomic_write_text(ROOT / "SHA256SUMS.txt", "\n".join(lines) + "\n")
    print(f"generated: release_manifest.json ({len(files)} files)")
    print(f"generated: SHA256SUMS.txt ({len(lines)} entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
