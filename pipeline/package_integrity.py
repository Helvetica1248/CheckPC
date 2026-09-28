#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fail-closed installed-package integrity verification for CheckPC."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from pipeline_errors import ConfigurationError

MANIFEST_NAME = "SHA256SUMS.txt"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_package_integrity(package_dir: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    root = Path(package_dir or Path(__file__).resolve().parent).resolve()
    manifest = root / MANIFEST_NAME
    errors: list[str] = []
    checked = 0
    expected_paths: set[str] = set()
    if not manifest.is_file() or manifest.is_symlink():
        return {
            "valid": False,
            "package_dir": str(root),
            "manifest": str(manifest),
            "package_manifest_sha256": "",
            "checked_files": 0,
            "errors": [f"{MANIFEST_NAME} is missing or not a regular file"],
        }

    for line_no, raw in enumerate(manifest.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            expected, rel_text = raw.split("  ", 1)
        except ValueError:
            errors.append(f"line {line_no}: invalid manifest row")
            continue
        rel = Path(rel_text)
        expected_paths.add(rel.as_posix())
        if rel.is_absolute() or ".." in rel.parts or rel_text in {"", "."}:
            errors.append(f"line {line_no}: unsafe path {rel_text!r}")
            continue
        candidate = root / rel
        cursor = root
        symlinked = False
        for part in rel.parts:
            cursor = cursor / part
            if cursor.is_symlink():
                symlinked = True
                break
        target = candidate.resolve(strict=False)
        try:
            target.relative_to(root)
        except ValueError:
            errors.append(f"line {line_no}: path escapes package {rel_text!r}")
            continue
        if symlinked or not candidate.is_file():
            errors.append(f"missing/non-regular/symlink: {rel_text}")
            continue
        actual = _sha256(target)
        checked += 1
        if actual != expected.lower():
            errors.append(f"sha256 mismatch: {rel_text}")

    # Reject unlisted package content. Python/test caches are explicitly
    # operational and excluded from the release manifest; everything else
    # must be listed so an added module, .env, symlink, or executable cannot
    # silently change the runtime build identity.
    ignored_parts = {"__pycache__", ".pytest_cache", ".git"}
    for candidate in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
        rel = candidate.relative_to(root)
        rel_text = rel.as_posix()
        if rel_text == MANIFEST_NAME:
            continue
        if any(part in ignored_parts for part in rel.parts) or rel.suffix == ".pyc":
            continue
        if candidate.is_symlink():
            errors.append(f"unlisted symlink: {rel_text}")
            continue
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            errors.append(f"unlisted non-regular file: {rel_text}")
            continue
        if rel_text not in expected_paths:
            errors.append(f"unlisted file: {rel_text}")

    return {
        "valid": not errors,
        "package_dir": str(root),
        "manifest": str(manifest),
        "package_manifest_sha256": _sha256(manifest),
        "checked_files": checked,
        "errors": errors,
    }


def assert_package_integrity(package_dir: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    result = verify_package_integrity(package_dir)
    if not result["valid"]:
        raise ConfigurationError(
            "runtime package SHA256SUMS verification failed; clean deploy required: "
            + "; ".join(result["errors"][:8])
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package_dir", nargs="?", default=str(Path(__file__).resolve().parent))
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    result = verify_package_integrity(args.package_dir)
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    print(text)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(text + "\n", encoding="utf-8")
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
