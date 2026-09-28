#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 rev14: depth1-depth2 signature-diversity comparison regressions.

The comparator may downgrade a D1 HIGH removal from FAIL to REVIEW only when
D2 proves that the exact raw row still exists, was deferred solely for
signature_diversity, and an exact same planner-signature representative was
selected, evaluated and source-id-bound in analyzed output.  Planner behavior
itself is unchanged.
"""
from __future__ import annotations

from pathlib import Path

import compare_runs as cr
from comparison_provenance import build_section_provenance

PASS = FAIL = 0
SECTION = "system_7045"


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [OK]  {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}: {detail}")


def raw_row(index: int, *, family: str = "iac") -> dict:
    exe = "iAC_Clp_64x.exe" if family == "iac" else "other.exe"
    service = "TMiACUninstallSvc" if family == "iac" else "OtherSvc"
    return {
        "source_id": f"system_7045:sid{index}",
        "service_name": service,
        "image_path": rf"c:\\temp\\fixture\\{exe}",
    }


def entry(row: dict, score: str, *, deterministic=False) -> dict:
    out = {
        "source_id": row["source_id"],
        "identifier": row["service_name"],
        "score": score,
        "reason": f"fixture {score}",
    }
    if deterministic:
        out["deterministic_origin"] = "fixture_floor"
    return out


def make_run(raw, entries, *, selected, deferred, evaluated,
             deferred_reason="signature_diversity", label="run"):
    reasons = {deferred_reason: set(deferred)} if deferred and deferred_reason else {}
    prov = build_section_provenance(
        SECTION,
        raw,
        selected=set(selected),
        deterministic=set(),
        deferred=set(deferred),
        evaluated=set(evaluated),
        unevaluated=set(selected) - set(evaluated),
        deferred_reasons=reasons,
        selected_reasons={"fixture_selected": set(selected)} if selected else {},
    )
    parsed = {"sections": {}, "event_logs": {SECTION: raw}}
    analyzed = {"meta": {"source_id_algorithm_version": "1"}, "sections": {SECTION: {"entries": entries, "_provenance": prov}}}
    return cr.RunArtifacts(
        label=label,
        root=Path("."),
        parsed_path=Path("parsed.json"),
        analyzed_path=Path("analyzed.json"),
        parsed=parsed,
        analyzed=analyzed,
    )


def compare_entries(a, b, mode="depth1-depth2"):
    issues = []
    cr._compare_entries(mode, a, b, issues, strict_llm=False)
    return issues


def issue_for_sid(issues, sid):
    return [x for x in issues if x.get("removed_source_id") == sid or sid in str(x.get("identity", ""))]


RAW = [raw_row(i) for i in range(6)]
D1_ENTRIES = [entry(row, "HIGH") for row in RAW]
D1 = make_run(RAW, D1_ENTRIES, selected=range(6), deferred=(), evaluated=range(6), label="D1")

# Baseline real-world shape: D1 HIGH x6, D2 MEDIUM representatives x3,
# signature-diversity deferred x3.  No FAIL may remain for the deferred rows.
D2_MEDIUM = make_run(
    RAW,
    [entry(RAW[i], "MEDIUM") for i in range(3)],
    selected=range(3), deferred=range(3, 6), evaluated=range(3), label="D2-medium",
)
issues = compare_entries(D1, D2_MEDIUM)
fails = [x for x in issues if x.get("severity") == "FAIL"]
sig_reviews = [x for x in issues if x.get("kind") == "signature_diversity_high_to_medium"]
check("real fixture D1 HIGH x6 / D2 MEDIUM x3 + deferred x3 -> FAIL=0", len(fails) == 0, fails)
check("three deferred HIGH rows become signature-aware REVIEW", len(sig_reviews) == 3, sig_reviews)
check("signature REVIEW retains complete representative evidence",
      all(x.get("deferred_reason") == "signature_diversity"
          and x.get("planner_signature") == "iac_clp_64x.exe"
          and x.get("representative_best_score") == "MEDIUM"
          and len(x.get("representative_source_ids") or []) == 3
          and len(x.get("representative_raw_indices") or []) == 3
          and x.get("representative_scores") == ["MEDIUM", "MEDIUM", "MEDIUM"]
          for x in sig_reviews), sig_reviews)

# HIGH representative is still REVIEW, not PASS, because an exact source_id was omitted.
D2_HIGH = make_run(
    RAW,
    [entry(RAW[i], "HIGH") for i in range(3)],
    selected=range(3), deferred=range(3, 6), evaluated=range(3), label="D2-high",
)
issues = compare_entries(D1, D2_HIGH)
check("signature_diversity with HIGH representative -> REVIEW",
      len([x for x in issues if x.get("kind") == "signature_diversity_high_represented"]) == 3
      and not [x for x in issues if x.get("severity") == "FAIL"], issues)

# Deterministic HIGH must not be weakened to REVIEW by MEDIUM representatives.
det_entries = [entry(row, "HIGH", deterministic=(i >= 3)) for i, row in enumerate(RAW)]
D1_DET = make_run(RAW, det_entries, selected=range(6), deferred=(), evaluated=range(6), label="D1-det")
issues = compare_entries(D1_DET, D2_MEDIUM)
for i in range(3, 6):
    rows = issue_for_sid(issues, RAW[i]["source_id"])
    check(f"deterministic HIGH deferred row {i} remains FAIL",
          any(x.get("severity") == "FAIL" and x.get("kind") == "analyzed_entry_removed" for x in rows), rows)

# LOW/CLEAN representatives cannot cover a D1 HIGH omission.
for representative_score in ("LOW", "CLEAN"):
    d2 = make_run(
        RAW,
        [entry(RAW[i], representative_score) for i in range(3)],
        selected=range(3), deferred=range(3, 6), evaluated=range(3),
        label=f"D2-{representative_score.lower()}",
    )
    issues = compare_entries(D1, d2)
    check(f"{representative_score} representatives keep deferred D1 HIGH as FAIL",
          any(x.get("severity") == "FAIL" and x.get("kind") == "analyzed_entry_removed"
              and x.get("score") == "HIGH" for x in issues), issues)

# Wrong deferred reason must not unlock the rev14 resolution.
D2_BUDGET = make_run(
    RAW,
    [entry(RAW[i], "MEDIUM") for i in range(3)],
    selected=range(3), deferred=range(3, 6), evaluated=range(3),
    deferred_reason="over_global_budget", label="D2-budget",
)
issues = compare_entries(D1, D2_BUDGET)
check("over_global_budget deferred HIGH remains FAIL",
      len([x for x in issues if x.get("kind") == "analyzed_entry_removed" and x.get("severity") == "FAIL"]) == 3,
      issues)

# A same-source raw row whose planner signature differs from representatives remains FAIL.
RAW_SIG_MISMATCH = [dict(row) for row in RAW]
for i in range(3, 6):
    RAW_SIG_MISMATCH[i]["image_path"] = rf"c:\\temp\\fixture\\different{i}.exe"
D2_SIG_MISMATCH = make_run(
    RAW_SIG_MISMATCH,
    [entry(RAW_SIG_MISMATCH[i], "MEDIUM") for i in range(3)],
    selected=range(3), deferred=range(3, 6), evaluated=range(3), label="D2-sig-mismatch",
)
issues = compare_entries(D1, D2_SIG_MISMATCH)
check("planner signature mismatch remains FAIL",
      len([x for x in issues if x.get("kind") == "analyzed_entry_removed" and x.get("severity") == "FAIL"]) == 3,
      issues)

# No evaluated representative -> FAIL.
D2_NO_REP = make_run(
    RAW, [], selected=(), deferred=range(6), evaluated=(), label="D2-no-rep",
)
issues = compare_entries(D1, D2_NO_REP)
check("signature_diversity without representative remains FAIL",
      len([x for x in issues if x.get("kind") == "analyzed_entry_removed" and x.get("severity") == "FAIL"]) == 6,
      issues)


# Multiple deferred reasons are not equivalent to exact signature_diversity.
D2_MULTI_REASON = make_run(
    RAW,
    [entry(RAW[i], "MEDIUM") for i in range(3)],
    selected=range(3), deferred=range(3, 6), evaluated=range(3), label="D2-multi-reason",
)
prov_multi = D2_MULTI_REASON.analyzed["sections"][SECTION]["_provenance"]
prov_multi["reasons"]["deferred"]["over_global_budget"] = prov_multi["reasons"]["deferred"]["signature_diversity"]
prov_multi["deferred_reasons"]["over_global_budget"] = prov_multi["deferred_reasons"]["signature_diversity"]
issues = compare_entries(D1, D2_MULTI_REASON)
check("multiple deferred reasons do not unlock exception",
      len([x for x in issues if x.get("kind") == "analyzed_entry_removed" and x.get("severity") == "FAIL"]) == 3,
      issues)

# Selected but not evaluated same-signature rows do not count as representatives.
D2_UNEVALUATED_REP = make_run(
    RAW, [], selected=range(3), deferred=range(3, 6), evaluated=(), label="D2-unevaluated-rep",
)
issues = compare_entries(D1, D2_UNEVALUATED_REP)
check("selected but unevaluated representative does not cover D1 HIGH",
      len([x for x in issues if x.get("kind") == "analyzed_entry_removed" and x.get("severity") == "FAIL"]) == 6,
      issues)

# Ambiguous representative source binding (duplicate analyzed source_id) fails closed.
D2_DUP_BIND = make_run(
    RAW,
    [entry(RAW[i], "MEDIUM") for i in range(3)] + [entry(RAW[0], "MEDIUM")],
    selected=range(3), deferred=range(3, 6), evaluated=range(3), label="D2-dup-bind",
)
issues = compare_entries(D1, D2_DUP_BIND)
check("duplicate representative source binding fails closed",
      len([x for x in issues if x.get("kind") == "analyzed_entry_removed" and x.get("severity") == "FAIL"]) >= 3
      and not [x for x in issues if str(x.get("kind", "")).startswith("signature_diversity_")],
      issues)

# The exception is strictly depth1-depth2; other modes keep the legacy removal kind.
issues = compare_entries(D1, D2_MEDIUM, mode="reproducibility")
check("reproducibility does not use signature-diversity exception",
      not [x for x in issues if str(x.get("kind", "")).startswith("signature_diversity_")]
      and len([x for x in issues if x.get("kind") == "analyzed_entry_removed" and x.get("severity") == "FAIL"]) == 3,
      issues)
issues = compare_entries(D1, D2_MEDIUM, mode="full-lean")
check("full-lean does not use signature-diversity exception",
      not [x for x in issues if str(x.get("kind", "")).startswith("signature_diversity_")], issues)
issues = compare_entries(D1, D2_MEDIUM, mode="cross-version")
check("cross-version does not use signature-diversity exception",
      not [x for x in issues if str(x.get("kind", "")).startswith("signature_diversity_")], issues)

# Raw evidence removal remains a hard FAIL independent of analyzed matching.
RAW_REMOVED = RAW[:-1]
D2_RAW_REMOVED = make_run(
    RAW_REMOVED,
    [entry(RAW_REMOVED[i], "MEDIUM") for i in range(3)],
    selected=range(3), deferred=range(3, 5), evaluated=range(3), label="D2-raw-removed",
)
raw_issues = []
cr._compare_raw("depth1-depth2", D1, D2_RAW_REMOVED, raw_issues)
check("raw evidence removal remains FAIL",
      any(x.get("severity") == "FAIL" and x.get("kind") == "raw_evidence_removed" for x in raw_issues),
      raw_issues)

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
