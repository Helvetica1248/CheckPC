#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build a safe reproducibility evidence bundle including downstream artifacts."""
from __future__ import annotations
import argparse, gzip, hashlib, io, json, tarfile
from pathlib import Path

INCLUDED_PATTERNS = ("parsed_*.json", "analyzed_*.json", "correlation_*.json", "report_*.md")
REQUIRED_PATTERNS = ("parsed_*.json", "analyzed_*.json")


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def collect_run_files(run_dir: Path) -> list[tuple[str, Path]]:
    root = run_dir.resolve()
    if not root.is_dir():
        raise ValueError(f"run directory not found: {root}")
    found: list[Path] = []
    for pattern in INCLUDED_PATTERNS:
        for path in sorted(root.glob(pattern)):
            if path.name.endswith("_vt.json") and path.name.startswith("analyzed_"):
                continue
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"non-regular artifact: {path}")
            path.resolve().relative_to(root)
            found.append(path)
    ingest = root / "ingest_manifest.json"
    if ingest.exists():
        if ingest.is_symlink() or not ingest.is_file():
            raise ValueError(f"non-regular artifact: {ingest}")
        found.append(ingest)
    unique = {path.name: path for path in found}
    for pattern in REQUIRED_PATTERNS:
        matches = [path for path in unique.values() if path.match(pattern)]
        if len(matches) != 1:
            raise ValueError(
                f"required pattern must match exactly once: {pattern} ({len(matches)})"
            )
    return [(name, unique[name]) for name in sorted(unique)]


def _comparison_record(path: Path) -> tuple[str, Path]:
    candidate = path.resolve()
    if path.is_symlink() or not candidate.is_file():
        raise ValueError(f"comparison result is not a regular file: {path}")
    if not candidate.name.startswith("comparison_result_") or candidate.suffix != ".json":
        raise ValueError(f"unexpected comparison result filename: {candidate.name}")
    value = json.loads(candidate.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not value.get("result_id") or not value.get("mode"):
        raise ValueError("comparison result is not a valid result object")
    return f"comparisons/{candidate.name}", candidate


def build_bundle(
    run_dir: Path,
    output: Path,
    comparison_result: Path | None = None,
) -> dict:
    root = run_dir.resolve()
    files = collect_run_files(root)
    if comparison_result is not None:
        files.append(_comparison_record(comparison_result))
    arc_names = [name for name, _ in files]
    if len(arc_names) != len(set(arc_names)):
        raise ValueError("duplicate bundle archive name")
    records = [
        {"name": name, "sha256": _sha(path), "size": path.stat().st_size}
        for name, path in files
    ]
    manifest = {
        "schema_version": 1,
        "scope": {
            "comparison_included": ["parsed_*.json", "analyzed_*.json"],
            "comparison_excluded": [
                "correlation_*.json", "report_*.md", "ingest_manifest.json"
            ],
            "comparison_result_included": comparison_result is not None,
            "bundle_included": [row["name"] for row in records],
        },
        "files": records,
    }
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw, gzip.GzipFile(
        filename="", mode="wb", fileobj=raw, mtime=0
    ) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tf:
            for arc_name, path in files:
                info = tf.gettarinfo(str(path), arcname=arc_name)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                info.mode = 0o600
                with path.open("rb") as fh:
                    tf.addfile(info, fh)
            payload = (
                json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            info = tarfile.TarInfo("reproducibility_bundle_manifest.json")
            info.size = len(payload)
            info.uid = info.gid = 0
            info.mtime = 0
            info.mode = 0o600
            tf.addfile(info, io.BytesIO(payload))
    return {**manifest, "bundle": str(output), "bundle_sha256": _sha(output)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--comparison-result", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    result = build_bundle(args.run_dir, args.output, args.comparison_result)
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    print(text)
    if args.json_out:
        args.json_out.write_text(text + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
