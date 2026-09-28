#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prove that the analysis runtime is byte-identical to a reference package.

Reusing an existing 4-mode comparison set is only sound when every file that can
influence parsing, selection, scoring, provenance or source-ID generation is
unchanged.  This tool makes that claim machine-checkable instead of relying on a
reviewer reading a diff.

Usage
-----
    # record the allowlist SHA-256 of the package that produced the 4-mode set
    python3 verify_analysis_runtime_unchanged.py --emit baseline.json

    # later, prove a candidate package did not touch the analysis runtime
    python3 verify_analysis_runtime_unchanged.py --baseline baseline.json

Exit codes
----------
    0  every allowlisted file matches the baseline
    1  at least one allowlisted file differs, is missing or is unreadable
    2  usage / input error

The allowlist below is intentionally explicit.  A file that is not listed is not
covered, so adding a new analysis-runtime module requires adding it here as
well; ``--selftest`` checks that the listed files all exist.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

# Importing budget_profile/version below must not leave __pycache__ behind:
# the release manifest generator fails closed on any cache artifact.
sys.dont_write_bytecode = True

HERE = os.path.dirname(os.path.abspath(__file__))

# Files whose contents can change analysis output.  Chat, reporting, comparison
# and packaging modules are deliberately excluded: they cannot alter parsed or
# analyzed artifacts, so changing them does not invalidate a 4-mode set.
ANALYSIS_RUNTIME_FILES = (
    "analyze_section.py",
    "directory_policy.py",
    "depth2_select.py",
    "parse_checkpc.py",
    "correlate.py",
    "source_id.py",
    "provenance.py",
    "token_budget.py",
    "section_prompts.py",
    "budget_profile.py",
    "inference_gate.py",
    "llm_runtime.py",
    "prompt_safety.py",
    "evidence_meta.py",
    "ioc_utils.py",
    "known_infra.py",
    "path_safety.py",
    "collector_profile.py",
    "ingest_manifest.py",
    "timeline.py",
    "version.py",
)

# ``budget_profile.py`` and ``version.py`` legitimately change at promotion:
# only validation metadata moves, never a numeric budget or a schema version.
# They are therefore compared through a normalized view as well as raw SHA-256,
# and a raw-only difference is reported as METADATA rather than CHANGED.
PROMOTION_METADATA_FILES = {
    "budget_profile.py": (
        'PROFILES["v370"]["provisional"]',
        'PROFILES["v370"]["validated"]',
        'PROFILES["v370"]["note"]',
    ),
    "version.py": (
        "RELEASE_STATUS",
    ),
}


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def numeric_budget_fingerprint() -> dict:
    """Fingerprint every numeric budget field, independent of file bytes.

    Promotion must not move a single budget number.  Comparing this fingerprint
    catches a numeric edit even if it were smuggled in alongside a metadata-only
    diff.
    """
    sys.path.insert(0, HERE)
    import budget_profile  # noqa: E402  (import after sys.path setup)

    metadata_keys = {"name", "note", "provisional", "validated", "warning",
                     "fingerprint"}
    out = {}
    for name, profile in sorted(budget_profile.PROFILES.items()):
        numeric = {
            key: value for key, value in sorted(profile.items())
            if key not in metadata_keys
        }
        payload = json.dumps(numeric, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), default=str)
        out[name] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return out


def schema_identity() -> dict:
    sys.path.insert(0, HERE)
    import version  # noqa: E402
    from source_id import SOURCE_ID_ALGORITHM_VERSION  # noqa: E402
    from comparison_provenance import (  # noqa: E402
        COMPARISON_PROVENANCE_SCHEMA_VERSION)
    return {
        "pipeline_version": version.PIPELINE_VERSION,
        "analysis_schema_version": version.ANALYSIS_SCHEMA_VERSION,
        "budget_profile_default": version.BUDGET_PROFILE_DEFAULT,
        "source_id_algorithm_version": SOURCE_ID_ALGORITHM_VERSION,
        "comparison_provenance_schema_version": (
            COMPARISON_PROVENANCE_SCHEMA_VERSION),
    }


def collect() -> dict:
    files = {}
    missing = []
    for name in ANALYSIS_RUNTIME_FILES:
        path = os.path.join(HERE, name)
        if not os.path.isfile(path):
            missing.append(name)
            continue
        files[name] = sha256_file(path)
    return {
        "allowlist_schema": 1,
        "files": files,
        "missing": missing,
        "numeric_budget_fingerprint": numeric_budget_fingerprint(),
        "schema_identity": schema_identity(),
    }


def compare(baseline: dict, actual: dict) -> tuple[list, list, list]:
    changed, metadata_only, problems = [], [], []
    base_files = baseline.get("files") or {}
    act_files = actual.get("files") or {}

    for name in sorted(set(base_files) | set(act_files)):
        want, got = base_files.get(name), act_files.get(name)
        if want is None:
            problems.append(f"{name}: not in baseline allowlist")
            continue
        if got is None:
            problems.append(f"{name}: missing from candidate package")
            continue
        if want == got:
            continue
        if name in PROMOTION_METADATA_FILES:
            metadata_only.append(f"{name}: {want[:12]} -> {got[:12]}")
        else:
            changed.append(f"{name}: {want[:12]} -> {got[:12]}")

    if actual.get("missing"):
        problems.append("missing allowlisted files: "
                        + ", ".join(actual["missing"]))

    base_num = baseline.get("numeric_budget_fingerprint") or {}
    act_num = actual.get("numeric_budget_fingerprint") or {}
    for profile in sorted(set(base_num) | set(act_num)):
        if base_num.get(profile) != act_num.get(profile):
            changed.append(f"numeric budget changed: profile {profile}")

    base_id = baseline.get("schema_identity") or {}
    act_id = actual.get("schema_identity") or {}
    for key in sorted(set(base_id) | set(act_id)):
        # RELEASE_STATUS is not part of schema_identity, so any difference here
        # is a real schema or algorithm change and invalidates reuse.
        if base_id.get(key) != act_id.get(key):
            changed.append(
                f"schema identity changed: {key} "
                f"{base_id.get(key)!r} -> {act_id.get(key)!r}")

    return changed, metadata_only, problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--emit", metavar="PATH",
                    help="write the current allowlist fingerprint as a baseline")
    ap.add_argument("--baseline", metavar="PATH",
                    help="verify the current package against a baseline file")
    ap.add_argument("--selftest", action="store_true",
                    help="check that every allowlisted file exists")
    args = ap.parse_args()

    actual = collect()

    if args.selftest:
        if actual["missing"]:
            print("SELFTEST FAIL: missing " + ", ".join(actual["missing"]))
            return 1
        print(f"SELFTEST OK: {len(actual['files'])} analysis runtime files present")
        return 0

    if args.emit:
        tmp = args.emit + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(actual, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, args.emit)
        print(f"baseline written: {args.emit} ({len(actual['files'])} files)")
        return 0

    if not args.baseline:
        ap.print_help()
        return 2

    try:
        with open(args.baseline, encoding="utf-8") as fh:
            baseline = json.load(fh)
    except Exception as exc:
        print(f"INPUT ERROR: cannot read baseline: {exc}")
        return 2

    changed, metadata_only, problems = compare(baseline, actual)

    print("=" * 60)
    print("  analysis runtime invariance")
    print("=" * 60)
    print(f"  allowlisted files      : {len(actual['files'])}")
    print(f"  changed (blocking)     : {len(changed)}")
    print(f"  metadata-only (allowed): {len(metadata_only)}")
    print(f"  problems               : {len(problems)}")
    for row in metadata_only:
        print(f"    [METADATA] {row}")
    for row in changed:
        print(f"    [CHANGED ] {row}")
    for row in problems:
        print(f"    [PROBLEM ] {row}")

    if changed or problems:
        print("\nRESULT: FAIL - existing 4-mode artifacts must NOT be reused; "
              "re-run all four comparison modes.")
        return 1
    print("\nRESULT: PASS - analysis runtime unchanged. This result alone does NOT authorize reuse of existing 4-mode artifacts; "
          "formal release also requires exact current package manifest identity binding "
          "for every current-version artifact, followed by regenerated comparisons and fresh approvals.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
