#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 formal-promotion regression: REVIEW evidence completeness.

Approval records are keyed by comparison issue ID.  Before this change the ID
for a truncated-sample issue covered only ``count`` plus the first N samples,
so two different evidence sets could share an ID and a previously approved ID
could silently come to mean something else.  These tests pin the fixed
behaviour, and also re-pin the cross-version derived-field normalization so it
cannot quietly widen.
"""
from __future__ import annotations

import collections
import os
import random
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import compare_runs as cr  # noqa: E402

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}" + (f": {detail}" if detail else ""))


def transition(index: int, a: object = False, b: object = True) -> dict:
    return {"identity": f"startup_folder:d{index}:0",
            "fields": {"suspicious": {"a": a, "b": b}}}


def digest(rows: list) -> str:
    return cr._evidence_digest(cr._sorted_transitions(rows))


def issue_id(rows: list, count: int) -> str:
    ordered = cr._sorted_transitions(rows)
    payload = {
        "severity": "REVIEW", "kind": "parsed_field_transition",
        "section": "startup_folder", "count": count,
        "fields": ["suspicious"],
        "transitions_digest": cr._evidence_digest(ordered),
        "samples": ordered[:8],
    }
    return cr._issue_id("cmp", payload)


def startup_row(path: str, suspicious: bool, date: str = "2026/06/18  15:54",
                size: str = "736") -> dict:
    return {"path": path, "date": date, "size": size,
            "source": "windows_startup", "suspicious": suspicious,
            "source_id": f"startup_folder:{path}"}


# ── 1. transition 20件で9件目以降のみ変更するとREVIEW IDが変わる ──────────
base_20 = [transition(i) for i in range(20)]
tail_changed = [transition(i) for i in range(8)] + [transition(i + 100) for i in range(12)]
check("tail-only change alters the REVIEW ID",
      issue_id(base_20, 20) != issue_id(tail_changed, 20))
check("tail-only change alters the evidence digest",
      digest(base_20) != digest(tail_changed))

# ── 2. transitionのa/b値だけ変更してもREVIEW IDが変わる ──────────────────
value_changed = [transition(i, a=True, b=False) for i in range(20)]
check("a/b value-only change alters the REVIEW ID",
      issue_id(base_20, 20) != issue_id(value_changed, 20))
check("a/b value-only change alters the evidence digest",
      digest(base_20) != digest(value_changed))

# A change in only one of the twenty rows must still move the ID.
single_value_changed = [transition(i) for i in range(19)] + [transition(19, a=None, b=True)]
check("single-row value change alters the REVIEW ID",
      issue_id(base_20, 20) != issue_id(single_value_changed, 20))

# ── 3. 完全同一transitionでIDが安定する ─────────────────────────────────
same_rows = list(base_20)
random.Random(20260805).shuffle(same_rows)
check("identical transition set keeps a stable REVIEW ID",
      issue_id(base_20, 20) == issue_id(same_rows, 20))
check("evidence digest is input-order independent",
      digest(base_20) == digest(same_rows))

# ── 4. 実raw削除は引き続きFAIL ──────────────────────────────────────────
rows_a = [startup_row(f"C:\\SF\\f{i}.lnk", False) for i in range(6)]
rows_b_removed = [startup_row(f"C:\\SF\\f{i}.lnk", False) for i in range(2)]
run_a = SimpleNamespace(parsed={"sections": {"startup_folder": rows_a}},
                        analyzed={"sections": {}})
run_removed = SimpleNamespace(parsed={"sections": {"startup_folder": rows_b_removed}},
                              analyzed={"sections": {}})
issues: list = []
cr._compare_raw("cross-version", run_a, run_removed, issues)
removal = [row for row in issues
           if row.get("kind") == "raw_evidence_removed" and row.get("severity") == "FAIL"]
check("real raw removal still FAILs under cross-version",
      len(removal) == 1 and removal[0].get("count") == 4, repr(issues))

# Removal combined with a derived-field change must still FAIL.
rows_b_mixed = [startup_row(f"C:\\SF\\f{i}.lnk", True) for i in range(2)]
run_mixed = SimpleNamespace(parsed={"sections": {"startup_folder": rows_b_mixed}},
                            analyzed={"sections": {}})
issues_mixed: list = []
cr._compare_raw("cross-version", run_a, run_mixed, issues_mixed)
check("removal plus derived-field change still FAILs",
      any(row.get("kind") == "raw_evidence_removed" and row.get("severity") == "FAIL"
          and row.get("count") == 4 for row in issues_mixed),
      repr(issues_mixed))

# ── 5. cross-version以外ではsuspicious差分を検出 ────────────────────────
rows_b_derived = [startup_row(f"C:\\SF\\f{i}.lnk", i < 4) for i in range(6)]
for mode in ("reproducibility", "full-lean", "depth1-depth2"):
    ids_a = cr._comparison_raw_identity_multiset(mode, "startup_folder", rows_a)
    ids_b = cr._comparison_raw_identity_multiset(mode, "startup_folder", rows_b_derived)
    diff = collections.Counter(ids_a) - collections.Counter(ids_b)
    check(f"{mode} still detects the derived-field difference",
          sum(diff.values()) == 4, repr(diff))

ids_a_cv = cr._comparison_raw_identity_multiset("cross-version", "startup_folder", rows_a)
ids_b_cv = cr._comparison_raw_identity_multiset("cross-version", "startup_folder", rows_b_derived)
check("cross-version treats the derived-field change as identical physical evidence",
      collections.Counter(ids_a_cv) == collections.Counter(ids_b_cv))

# ── 6. derived-field allowlistの固定 ────────────────────────────────────
actual_allowlist = {str(section): set(fields)
                    for section, fields in cr._CROSS_VERSION_DERIVED_RAW_FIELDS.items()}
check("derived-field allowlist is pinned to the approved single entry",
      actual_allowlist == {"startup_folder": {"suspicious"}},
      repr(actual_allowlist))

for section in ("persistence_reg", "directory", "task_scheduler", "service"):
    ids_x = cr._comparison_raw_identity_multiset("cross-version", section, rows_a)
    ids_y = cr._comparison_raw_identity_multiset("cross-version", section, rows_b_derived)
    check(f"{section} is not normalized under cross-version",
          collections.Counter(ids_x) != collections.Counter(ids_y))

# ── 7. parsed_field_transition が transitions_digest を持つ ─────────────
run_derived = SimpleNamespace(parsed={"sections": {"startup_folder": rows_b_derived}},
                              analyzed={"sections": {}})
derived_issues: list = []
cr._compare_cross_version_derived_fields(run_a, run_derived, derived_issues)
check("derived-field transition is reported as REVIEW with a digest",
      len(derived_issues) == 1
      and derived_issues[0]["severity"] == "REVIEW"
      and derived_issues[0]["kind"] == "parsed_field_transition"
      and derived_issues[0]["count"] == 4
      and len(derived_issues[0].get("transitions_digest", "")) == 32,
      repr(derived_issues))

# ── 8. 他のtruncated-sample REVIEWにも全証拠digestが付く ────────────────
rows_added = rows_a + [startup_row(f"C:\\SF\\new{i}.lnk", False) for i in range(12)]
run_added = SimpleNamespace(parsed={"sections": {"startup_folder": rows_added}},
                            analyzed={"sections": {}})
issues_added: list = []
cr._compare_raw("cross-version", run_a, run_added, issues_added)
added = [row for row in issues_added if row.get("kind") == "raw_evidence_added"]
check("raw_evidence_added carries a full-evidence digest",
      len(added) == 1 and len(added[0].get("evidence_digest", "")) == 32,
      repr(issues_added))

rows_added_other = rows_a + [startup_row(f"C:\\SF\\other{i}.lnk", False) for i in range(12)]
run_added_other = SimpleNamespace(parsed={"sections": {"startup_folder": rows_added_other}},
                                  analyzed={"sections": {}})
issues_added_other: list = []
cr._compare_raw("cross-version", run_a, run_added_other, issues_added_other)
added_other = [row for row in issues_added_other if row.get("kind") == "raw_evidence_added"]
check("raw_evidence_added ID reacts to evidence beyond the first eight samples",
      len(added_other) == 1 and added[0]["id"] != added_other[0]["id"],
      f"{added[0]['id']} vs {added_other[0]['id']}")

# ── 9. source ID / provenance の恒久仕様は不変 ──────────────────────────
from source_id import SOURCE_ID_ALGORITHM_VERSION  # noqa: E402
from comparison_provenance import COMPARISON_PROVENANCE_SCHEMA_VERSION  # noqa: E402

check("source ID algorithm version is unchanged", SOURCE_ID_ALGORITHM_VERSION == "1")
check("comparison provenance schema is unchanged",
      COMPARISON_PROVENANCE_SCHEMA_VERSION == "1")

print(f"\nPASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
