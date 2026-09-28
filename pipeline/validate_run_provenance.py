#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lightweight fail-closed provenance coverage checker for parsed/analyzed JSON.

This checker deliberately avoids expanding compact raw-index ranges.  It is
suitable for multi-million-entry CheckPC artifacts where a full set-based
external checker would consume excessive memory.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from comparison_provenance import (
    missing_analyzed_raw_sections,
    missing_raw_backed_provenance_sections,
    raw_sections,
)


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be object: {path}")
    return value


def _stage_count(provenance: Mapping[str, Any], name: str) -> int | None:
    stages = provenance.get("stages")
    if not isinstance(stages, Mapping):
        return None
    row = stages.get(name)
    if not isinstance(row, Mapping) or row.get("applicable") is False:
        return None
    try:
        return int(row.get("count", -1))
    except (TypeError, ValueError):
        return -1


def validate(parsed: Mapping[str, Any], analyzed: Mapping[str, Any], *, release_strict: bool = False) -> list[str]:
    errors: list[str] = []
    raw = raw_sections(parsed)
    analyzed_sections = analyzed.get("sections", {})
    if not isinstance(analyzed_sections, Mapping):
        return ["analyzed.sections is missing"]

    for section in missing_analyzed_raw_sections(parsed, analyzed):
        errors.append(f"{section}: analyzed section missing")
    for section in missing_raw_backed_provenance_sections(parsed, analyzed):
        errors.append(f"{section}: provenance missing")

    for section, result in analyzed_sections.items():
        name = str(section)
        if not isinstance(result, Mapping):
            continue
        provenance = result.get("_provenance")
        if name not in raw:
            if not isinstance(provenance, Mapping):
                continue
            from comparison_provenance import validate_section_provenance
            for detail in validate_section_provenance(provenance):
                errors.append(f"{name}: derived provenance invalid: {detail}")
            if provenance.get("provenance_complete") is not True:
                errors.append(f"{name}: derived provenance_complete is not true")
            for entry_index, entry in enumerate(result.get("entries") or []):
                if isinstance(entry, Mapping) and not str(entry.get("source_id") or ""):
                    errors.append(f"{name}: derived entry source_id missing index={entry_index}")
            stages = provenance.get("stages") or {}
            if isinstance(stages, Mapping):
                for stage_name in ("mandatory", "deterministic", "selected", "evaluated", "unevaluated"):
                    row = stages.get(stage_name)
                    if not isinstance(row, Mapping) or row.get("applicable") is False:
                        continue
                    count = int(row.get("count", -1))
                    ids = row.get("source_ids")
                    if row.get("source_ids_complete") is not True or not isinstance(ids, list) or len(ids) != count:
                        errors.append(f"{name}: derived stage source_id coverage incomplete stage={stage_name}")
            continue
        if not isinstance(provenance, Mapping):
            continue
        expected_raw = len(raw[name])
        try:
            actual_raw = int(provenance.get("raw_count", -1))
        except (TypeError, ValueError):
            actual_raw = -1
        if actual_raw != expected_raw:
            errors.append(
                f"{name}: raw_count mismatch expected={expected_raw} actual={actual_raw}"
            )
        if provenance.get("provenance_complete") is not True:
            errors.append(f"{name}: provenance_complete is not true")
        try:
            attr = int(provenance.get("attribution_error_count", 0) or 0)
        except (TypeError, ValueError):
            attr = -1
        if attr != 0:
            errors.append(f"{name}: attribution_error_count={attr}")
        selected = _stage_count(provenance, "selected")
        evaluated = _stage_count(provenance, "evaluated")
        unevaluated = _stage_count(provenance, "unevaluated")
        if None not in (selected, evaluated, unevaluated):
            if selected != evaluated + unevaluated:
                errors.append(
                    f"{name}: selected closure mismatch "
                    f"selected={selected} evaluated={evaluated} unevaluated={unevaluated}"
                )
            if release_strict and unevaluated != 0:
                errors.append(f"{name}: release-strict unevaluated={unevaluated}")
            if release_strict and evaluated != selected:
                errors.append(
                    f"{name}: release-strict evaluated mismatch selected={selected} evaluated={evaluated}"
                )
        if release_strict:
            chunk_errors = result.get("_chunk_errors") or []
            if not isinstance(chunk_errors, list):
                errors.append(f"{name}: release-strict _chunk_errors is not a list")
            elif chunk_errors:
                errors.append(f"{name}: release-strict chunk_errors={len(chunk_errors)}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("parsed", type=Path)
    parser.add_argument("analyzed", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument(
        "--release-strict", action="store_true",
        help="require selected==evaluated, unevaluated=0 and chunk_errors=0",
    )
    args = parser.parse_args()

    parsed = _load(args.parsed)
    analyzed = _load(args.analyzed)
    errors = validate(parsed, analyzed, release_strict=args.release_strict)
    raw = raw_sections(parsed)
    analyzed_sections = analyzed.get("sections", {})
    checked = 0
    if isinstance(analyzed_sections, Mapping):
        checked = sum(
            1 for section, result in analyzed_sections.items()
            if str(section) in raw and isinstance(result, Mapping)
        )
    result = {
        "status": "ACCEPT" if not errors else "REJECT",
        "release_strict": bool(args.release_strict),
        "raw_backed_sections_checked": checked,
        "missing_analyzed_sections": missing_analyzed_raw_sections(parsed, analyzed),
        "missing_provenance_sections": missing_raw_backed_provenance_sections(
            parsed, analyzed
        ),
        "errors": errors,
    }
    if args.json_out:
        args.json_out.write_text(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
