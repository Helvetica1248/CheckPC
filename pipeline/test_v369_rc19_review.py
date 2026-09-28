#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 regressions: bounded/cancellable Step 4B planner."""
from __future__ import annotations

import time
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import analyze_section
import depth2_select
from pipeline_errors import PipelineCancelled
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION, BUDGET_PROFILE_DEFAULT

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}")
        PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else ""))
        FAIL += 1


print("\n--- RC19 identity ---")
check("pipeline version", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("schema version", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("profile version", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)


class FakeProfile:
    d2_output_token_budget = 100
    d2_min_rep = 1
    novelty_min_rep = 0
    novelty_section_cap = 0
    sig_max_d2 = 200000
    risk_ratio = 1.0
    fair_ratio = 0.0
    planner_trim_batch_max = 8
    planner_frontier_reserve_per_section = 16
    planner_candidate_probe_limit = 64
    planner_replan_limit = 64
    planner_cancel_check_interval = 128
    planner_progress_interval = 1024
    planner_trim_iteration_limit = 64
    def tok_per_entry(self, sec): return 10
    def section_cap(self, sec): return 200


print("\n--- bounded policy frontier on large cap-underfilled pool ---")
old_profile = depth2_select.active_profile
old_plan = analyze_section.resolve_chunk_plan
try:
    depth2_select.active_profile = lambda: FakeProfile()
    plan_calls = []
    def fake_plan(sec, entries, depth, **kwargs):
        plan_calls.append((sec, len(entries)))
        return {
            "planned_output_tokens": len(entries) * 20 + (10 if entries else 0),
            "chunk_overhead_tokens": 10 if entries else 0,
        }
    analyze_section.resolve_chunk_plan = fake_plan
    # The selected set remains below the section cap while almost every candidate
    # is ineligible under the nearly-full global budget: the rc18 worst path.
    pool_size = 100_000
    pool = {"directory": [
        (i, {"path": rf"C:\\Users\\u\\AppData\\Local\\Temp\\artifact-{i:06d}.exe"})
        for i in range(pool_size)
    ]}
    events = []
    started = time.monotonic()
    result = depth2_select.plan_depth2_selection(
        pool, depth2_select.empty_ctx(), ["directory"], novelty_pools={},
        progress_callback=lambda payload: events.append(dict(payload)))
    elapsed = time.monotonic() - started
    info = result["directory"]
    check("large pool completes in bounded time", elapsed < 20.0, f"elapsed={elapsed:.3f}s")
    check("selected remains below section cap", len(info["selected"]) < FakeProfile().section_cap("directory"), len(info["selected"]))
    check("frontier is bounded independently of raw size",
          info["candidate_frontier_size"] <= 32,
          info["candidate_frontier_size"])
    check("candidate probes respect configured limit",
          info["backfill_candidates_examined"] <= FakeProfile.planner_candidate_probe_limit,
          info["backfill_candidates_examined"])
    check("replans respect configured limit",
          info["planner_replan_count"] <= FakeProfile.planner_replan_limit,
          info["planner_replan_count"])
    check("resolve_chunk_plan is not called per raw candidate",
          len(plan_calls) < 100, len(plan_calls))
    check("policy frontier maximality is explicit",
          info["plan_is_policy_frontier_maximal"] is True, info)
    check("global maximality is not claimed",
          info["global_maximality_not_claimed"] is True, info)
    phases = {e.get("phase") for e in events}
    for phase in ("candidate_scoring", "initial_plan", "budget_trim", "backfill",
                  "frontier_audit", "deferred_accounting"):
        check(f"progress emits {phase}", phase in phases, sorted(phases))
finally:
    depth2_select.active_profile = old_profile
    analyze_section.resolve_chunk_plan = old_plan


print("\n--- operation-limit fail-closed audit ---")
class TightProfile(FakeProfile):
    planner_candidate_probe_limit = 1
    planner_replan_limit = 1
    planner_frontier_reserve_per_section = 16

try:
    depth2_select.active_profile = lambda: TightProfile()
    analyze_section.resolve_chunk_plan = lambda sec, entries, depth, **kwargs: {
        "planned_output_tokens": len(entries) * 20 + (10 if entries else 0),
        "chunk_overhead_tokens": 10 if entries else 0,
    }
    pool = {"directory": [(i, {"path": rf"C:\\Temp\\x{i}.exe"}) for i in range(20)]}
    info = depth2_select.plan_depth2_selection(
        pool, depth2_select.empty_ctx(), ["directory"], novelty_pools={})["directory"]
    check("operation-limit hit is audited",
          info["planner_probe_limit_hit"] is True or info["planner_replan_limit_hit"] is True, info)
    check("limit hit prevents maximality claim",
          info["plan_is_policy_frontier_maximal"] is False, info)
finally:
    depth2_select.active_profile = old_profile
    analyze_section.resolve_chunk_plan = old_plan


print("\n--- Step 4B cooperative cancellation ---")
try:
    depth2_select.active_profile = lambda: FakeProfile()
    analyze_section.resolve_chunk_plan = lambda sec, entries, depth, **kwargs: {
        "planned_output_tokens": len(entries) * 20 + (10 if entries else 0),
        "chunk_overhead_tokens": 10 if entries else 0,
    }
    calls = {"n": 0}
    def cancel_check():
        calls["n"] += 1
        return calls["n"] >= 3
    cancelled = False
    try:
        depth2_select.plan_depth2_selection(
            {"directory": [(i, {"path": rf"C:\\Temp\\c{i}.exe"}) for i in range(10_000)]},
            depth2_select.empty_ctx(), ["directory"], novelty_pools={},
            cancel_check=cancel_check)
    except PipelineCancelled:
        cancelled = True
    check("planner raises typed PipelineCancelled", cancelled)
    check("cancellation is checked during Step 4B", calls["n"] >= 3, calls)
finally:
    depth2_select.active_profile = old_profile
    analyze_section.resolve_chunk_plan = old_plan


print("\n--- production code has no unbounded candidate_order pass ---")
production = (HERE / "depth2_select.py").read_text(encoding="utf-8")
check("legacy full candidate_order helper removed", "def candidate_order()" not in production)
check("bounded frontier helper present", "def _bounded_frontier()" in production)
check("policy-frontier audit field present", "plan_is_policy_frontier_maximal" in production)
check("planner cancellation wired", "cancel_check" in production and "PipelineCancelled" in production)

print(f"\nRESULT: PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
