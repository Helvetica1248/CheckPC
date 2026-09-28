#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

from compare_runs import (
    RunArtifacts,
    _compare_cross_version_derived_fields,
    _compare_raw,
    _cross_version_analyzed_view,
    _stage_identities,
)

PASS = 0
FAIL = 0


def check(name, cond, detail=None):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}: {detail!r}")


def make_run(root: Path, label: str, suspicious: bool, source_id: str) -> RunArtifacts:
    row = {
        "path": "Ollama.lnk",
        "date": "2026/06/18  15:54",
        "size": "736",
        "source": "windows_startup",
        "suspicious": suspicious,
        "source_id": source_id,
    }
    parsed = {
        "meta": {},
        "sections": {"startup_folder": [copy.deepcopy(row)]},
    }
    provenance = {
        "raw_count": 1,
        "selected_ranges": [[0, 0]],
        "deterministic_ranges": [],
        "deferred_ranges": [],
        "evaluated_ranges": [[0, 0]],
        "selected_unevaluated_ranges": [],
    }
    analyzed = {
        "meta": {"source_id_algorithm_version": "1"},
        "sections": {
            "startup_folder": {
                "entries": [{
                    "source_id": source_id,
                    "identifier": "Ollama.lnk",
                    "score": "MEDIUM",
                    "reason": "same",
                    "iocs": [],
                }],
                "_provenance": provenance,
            }
        },
    }
    parsed_path = root / f"parsed_{label}.json"
    analyzed_path = root / f"analyzed_{label}.json"
    parsed_path.write_text(json.dumps(parsed), encoding="utf-8")
    analyzed_path.write_text(json.dumps(analyzed), encoding="utf-8")
    return RunArtifacts(
        label=label,
        root=root,
        parsed_path=parsed_path,
        analyzed_path=analyzed_path,
        parsed=parsed,
        analyzed=analyzed,
    )


with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    old = make_run(root, "old", False, "startup_folder:old")
    new = make_run(root, "new", True, "startup_folder:new")

    issues = []
    _compare_raw("cross-version", old, new, issues)
    check(
        "cross-version derived flag does not emit raw removal/addition",
        not any(row.get("kind") in {"raw_evidence_removed", "raw_evidence_added"} for row in issues),
        issues,
    )

    strict_issues = []
    _compare_raw("reproducibility", old, new, strict_issues)
    check(
        "same-version comparison remains strict",
        {row.get("kind") for row in strict_issues}
        == {"raw_evidence_removed", "raw_evidence_added"},
        strict_issues,
    )

    derived = []
    _compare_cross_version_derived_fields(old, new, derived)
    check(
        "derived field transition is REVIEW",
        len(derived) == 1
        and derived[0].get("severity") == "REVIEW"
        and derived[0].get("kind") == "parsed_field_transition"
        and derived[0].get("count") == 1,
        derived,
    )

    selected_old = _stage_identities(old, "startup_folder", "selected", "cross-version")
    selected_new = _stage_identities(new, "startup_folder", "selected", "cross-version")
    check(
        "cross-version stage identity survives source-id change",
        selected_old == selected_new,
        (selected_old, selected_new),
    )

    old_view = _cross_version_analyzed_view(old)
    new_view = _cross_version_analyzed_view(new)
    old_sid = old_view["sections"]["startup_folder"]["entries"][0]["source_id"]
    new_sid = new_view["sections"]["startup_folder"]["entries"][0]["source_id"]
    check(
        "analyzed source IDs normalize to the same physical identity",
        old_sid == new_sid and old_sid.startswith("cross-version:startup_folder:"),
        (old_sid, new_sid),
    )

print(f"PASS={PASS} FAIL={FAIL}")
raise SystemExit(1 if FAIL else 0)
