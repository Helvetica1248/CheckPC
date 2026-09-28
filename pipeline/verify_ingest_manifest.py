#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify hashes and sizes recorded in ingest_manifest.json."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from ingest_manifest import sha256_file


def verify(manifest_path: str) -> dict:
    mp = Path(manifest_path).resolve()
    data = json.loads(mp.read_text(encoding="utf-8"))
    records = []

    def one(kind, expected_path, expected_hash, expected_size=None, name=""):
        p = Path(expected_path) if expected_path else Path()
        if expected_path and not p.is_file() and name:
            candidate = mp.parent / name
            if candidate.is_file():
                p = candidate
        if not expected_path or not p.is_file():
            return {"kind": kind, "name": name or str(expected_path), "status": "MISSING"}
        actual_size = p.stat().st_size
        actual_hash = sha256_file(p)
        ok = actual_hash == expected_hash and (expected_size is None or actual_size == expected_size)
        return {
            "kind": kind, "name": name or p.name, "path": str(p),
            "expected_sha256": expected_hash, "actual_sha256": actual_hash,
            "expected_size": expected_size, "actual_size": actual_size,
            "status": "PASS" if ok else "MISMATCH",
        }

    records.append(one("input", data.get("input_path"), data.get("input_sha256", ""), name="input"))
    for rec in data.get("files") or []:
        if isinstance(rec, dict):
            records.append(one("artifact", rec.get("path"), rec.get("sha256", ""), rec.get("size"), rec.get("name", "")))
    return {
        "manifest": str(mp), "records": records,
        "pass": all(r["status"] == "PASS" for r in records),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest")
    ap.add_argument("--json", dest="json_path", default="")
    args = ap.parse_args()
    try:
        result = verify(args.manifest)
    except Exception as exc:
        print(f"[FAIL] manifest error: {exc}")
        return 2
    for rec in result["records"]:
        print(f"[{rec['status']}] {rec['kind']} {rec['name']}")
    if args.json_path:
        Path(args.json_path).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
