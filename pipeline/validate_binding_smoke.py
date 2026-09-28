#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validate evaluation completeness for a section-limited rc28 LLM smoke run."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping


def _count_stage(prov: Mapping[str, Any], name: str) -> int:
    stage = (prov.get("stages") or {}).get(name) or {}
    if stage.get("applicable") is False:
        return 0
    try:
        return int(stage.get("count", 0) or 0)
    except (TypeError, ValueError):
        return -1


def validate(doc: Mapping[str, Any], sections: list[str]) -> dict[str, Any]:
    analyzed = doc.get("sections") or {}
    errors: list[str] = []
    rows: list[dict[str, Any]] = []
    totals = Counter()

    for name in sections:
        result = analyzed.get(name)
        if not isinstance(result, Mapping):
            errors.append(f"{name}: analyzed section missing")
            continue
        prov = result.get("_provenance") or {}
        selected = _count_stage(prov, "selected")
        evaluated = _count_stage(prov, "evaluated")
        unevaluated = _count_stage(prov, "unevaluated")
        chunk_errors = result.get("_chunk_errors") or []
        attribution = int(prov.get("attribution_error_count", 0) or 0)
        complete = prov.get("provenance_complete") is True
        rejection_reasons = Counter()
        if isinstance(chunk_errors, list):
            for item in chunk_errors:
                if not isinstance(item, Mapping):
                    continue
                for key, value in (item.get("rejection_reasons") or {}).items():
                    try:
                        rejection_reasons[str(key)] += int(value)
                    except (TypeError, ValueError):
                        pass
        else:
            errors.append(f"{name}: _chunk_errors is not a list")
            chunk_errors = []

        row = {
            "section": name,
            "selected": selected,
            "evaluated": evaluated,
            "unevaluated": unevaluated,
            "chunk_errors": len(chunk_errors),
            "attribution_errors": attribution,
            "provenance_complete": complete,
            "rejection_reasons": dict(sorted(rejection_reasons.items())),
        }
        rows.append(row)
        for key in ("selected", "evaluated", "unevaluated", "chunk_errors", "attribution_errors"):
            totals[key] += int(row[key])

        if selected < 0 or evaluated < 0 or unevaluated < 0:
            errors.append(f"{name}: invalid provenance stage count")
        if selected != evaluated:
            errors.append(f"{name}: selected={selected} evaluated={evaluated}")
        if unevaluated != 0:
            errors.append(f"{name}: unevaluated={unevaluated}")
        if chunk_errors:
            errors.append(f"{name}: chunk_errors={len(chunk_errors)}")
        if attribution != 0:
            errors.append(f"{name}: attribution_errors={attribution}")
        if not complete:
            errors.append(f"{name}: provenance_complete is not true")

    return {
        "schema_version": 1,
        "status": "ACCEPT" if not errors else "REJECT",
        "sections": rows,
        "totals": dict(totals),
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analyzed", type=Path)
    parser.add_argument("--section", action="append", dest="sections", required=True)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    doc = json.loads(args.analyzed.read_text(encoding="utf-8"))
    result = validate(doc, args.sections)
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if result["status"] == "ACCEPT" else 1


if __name__ == "__main__":
    raise SystemExit(main())
