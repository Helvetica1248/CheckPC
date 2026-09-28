#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 regressions: Depth2 mandatory/floor preservation and deferred reporting."""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import analyze_section
import depth2_select
import report_gen
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


print("\n--- RC17 identity ---")
check("pipeline version", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("schema version", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("profile version", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)


print("\n--- deterministic Office startup mandatory classification ---")
zotero = {
    "path": r"C:\Users\u\AppData\Roaming\Microsoft\Word\STARTUP\Zotero.dotm",
    "source": "office_startup", "suspicious": True,
}
lock = dict(zotero, path=r"C:\Users\u\AppData\Roaming\Microsoft\Word\STARTUP\~$Zotero.dotm")
normal = dict(zotero, path=r"C:\Users\u\AppData\Roaming\Microsoft\Word\STARTUP\normal.txt")
windows = dict(zotero, source="windows_startup")
check("Zotero.dotm is mandatory",
      depth2_select.deterministic_mandatory_reason("startup_folder", zotero)
      == "office_startup_macro_suspicious")
check("Office lock file excluded",
      depth2_select.deterministic_mandatory_reason("startup_folder", lock) == "")
check("non-macro extension excluded",
      depth2_select.deterministic_mandatory_reason("startup_folder", normal) == "")
check("windows startup excluded from Office rule",
      depth2_select.deterministic_mandatory_reason("startup_folder", windows) == "")
check("mandatory is unioned into Level1 allow-set",
      depth2_select.include_mandatory_indices("startup_folder", [normal, zotero], {0}) == {0, 1})
class _MustNotIterate:
    def __iter__(self):
        raise AssertionError("non-startup raw_entries must not be scanned")

check("unrelated sections avoid raw rescanning",
      depth2_select.include_mandatory_indices("netstat", _MustNotIterate(), {7}) == {7})
_m1_dir = {"path": r"C:\Users\Public\Music\sample.vbe"}
check("directory M1 is unioned before bounded selection",
      depth2_select.include_mandatory_indices("directory", [_m1_dir], set()) == {0})

xih_6 = [
    {"path": r"C:\Users\fixture-user-01\AppData\Roaming\Microsoft\Word\STARTUP\Zotero.dotm",
     "source": "office_startup", "suspicious": True,
     "source_id": "startup_folder:ee1d692b3dcbcd061833eb83"},
    {"path": r"C:\Users\fixture-user-01\AppData\Roaming\Microsoft\Word\STARTUP\~$Zotero.dotm",
     "source": "office_startup", "suspicious": True},
    {"path": r"C:\Users\fixture-user-01\AppData\Roaming\Microsoft\Excel\XLSTART\Book.xltx",
     "source": "office_startup", "suspicious": False},
    {"path": r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini",
     "source": "windows_startup", "suspicious": False},
    {"path": r"C:\Users\fixture-user-01\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini",
     "source": "windows_startup", "suspicious": False},
    {"path": r"C:\Users\fixture-user-01\AppData\Roaming\Microsoft\Word\STARTUP\readme.txt",
     "source": "office_startup", "suspicious": False},
]
mandatory_xih = depth2_select.include_mandatory_indices("startup_folder", xih_6, set())
check("HOST-REF-11 six-entry fixture retains only Zotero.dotm as mandatory",
      mandatory_xih == {0}, mandatory_xih)

ctx = depth2_select.empty_ctx()
tier, score, _ = depth2_select.section_selection_score("startup_folder", zotero, ctx)
check("startup macro receives tier0", tier == 0, (tier, score))
tier_lock, _, _ = depth2_select.section_selection_score("startup_folder", lock, ctx)
check("lock file is not tier0", tier_lock != 0, tier_lock)


print("\n--- Depth2 planner floor preservation and batch trim ---")
class FakeProfile:
    d2_output_token_budget = 100
    d2_min_rep = 1
    novelty_min_rep = 0
    novelty_section_cap = 0
    sig_max_d2 = 100
    risk_ratio = 1.0
    fair_ratio = 0.0
    def tok_per_entry(self, sec):
        return 10
    def section_cap(self, sec):
        return 20

old_profile = depth2_select.active_profile
old_plan = analyze_section.resolve_chunk_plan
try:
    depth2_select.active_profile = lambda: FakeProfile()

    def fake_plan(sec, entries, depth, **kwargs):
        # A selected section carries fixed chunk overhead. Two floor-only sections
        # therefore exceed the 100-token budget and must remain as explicit overrun.
        return {
            "planned_output_tokens": 60 if entries else 0,
            "chunk_overhead_tokens": 50 if entries else 0,
        }

    analyze_section.resolve_chunk_plan = fake_plan
    pools = {
        "startup_folder": [(0, zotero), (1, normal)],
        "hosts": [(0, {"ip": "1.2.3.4", "hostname": "a.example"})],
    }
    plan = depth2_select.plan_depth2_selection(
        pools, depth2_select.empty_ctx(), ["startup_folder", "hosts"],
        lean=False, context="", novelty_pools={})
    startup_indices = [i for i, _ in plan["startup_folder"]["selected"]]
    hosts_indices = [i for i, _ in plan["hosts"]["selected"]]
    check("mandatory Zotero survives", 0 in startup_indices, plan["startup_folder"])
    check("small section floor survives", hosts_indices == [0], plan["hosts"])
    check("protected floors may report explicit overrun",
          plan["startup_folder"]["global_budget_overrun"] is True, plan)
    check("section floor target recorded",
          plan["hosts"]["section_floor_target"] == 1, plan["hosts"])
    check("section floor selected recorded",
          plan["hosts"]["section_floor_selected"] == 1, plan["hosts"])
    check("batch trim telemetry recorded",
          isinstance(plan["hosts"]["planner_trim_iterations"], int), plan["hosts"])
finally:
    depth2_select.active_profile = old_profile
    analyze_section.resolve_chunk_plan = old_plan


print("\n--- startup deterministic HIGH/CLEAN floor ---")
raw = [zotero, lock]
section = {"entries": [
    {"_raw_source_index": 0, "identifier": "Zotero.dotm", "score": "LOW",
     "reason": "LLM provisional", "mitre": [], "iocs": []},
    {"_raw_source_index": 1, "identifier": "~$Zotero.dotm", "score": "HIGH",
     "reason": "LLM provisional", "mitre": ["T1137.001"], "iocs": []},
]}
out = analyze_section._apply_post_filter("startup_folder", section, raw)["entries"]
check("Zotero LOW is raised to HIGH", out[0]["score"] == "HIGH", out[0])
check("Zotero floor reason recorded",
      out[0].get("depth2_mandatory_reason") == "office_startup_macro_suspicious", out[0])
check("Zotero technique retained", "T1137.001" in out[0].get("mitre", []), out[0])
check("lock HIGH is lowered to CLEAN", out[1]["score"] == "CLEAN", out[1])
check("lock technique removed", out[1].get("mitre") == [], out[1])


print("\n--- netstat and generic user-writable evidence calibration ---")
net_raw = [{
    "remote": "203.0.113.7:45678", "local": "192.0.2.5:55578",
    "state": "ESTABLISHED", "_proc_hint": "unknown",
    "source_id": "netstat:generic-unattributed",
}]
net_sec = {"entries": [{
    "_raw_source_index": 99,
    "source_id": "netstat:generic-unattributed",
    "identifier": "192.0.2.5:55578 → 203.0.113.7:45678",
    "score": "LOW", "reason": "LLM provisional", "mitre": [], "iocs": ["203.0.113.7"],
}]}
net_out = analyze_section._apply_post_filter("netstat", net_sec, net_raw)["entries"][0]
check("unattributed external nonstandard connection receives MEDIUM floor",
      net_out.get("score") == "MEDIUM", net_out)
check("netstat raw evidence resolves by stable source_id",
      net_out.get("_floor") == "netstat_external_nonstandard_unattributed_medium", net_out)
net_known = [dict(net_raw[0], _proc_hint="pid=1 (browser.exe)")]
net_known_out = analyze_section._apply_post_filter("netstat", {"entries": [{
    "source_id": "netstat:generic-unattributed", "identifier": net_sec["entries"][0]["identifier"],
    "score": "LOW", "reason": "x", "mitre": [], "iocs": [],
}]}, net_known)["entries"][0]
check("attributed connection is not floor-raised", net_known_out.get("score") == "LOW", net_known_out)

for idx, path in enumerate([
    r"C:\Users\u\AppData\Local\Temp\VendorASetup.exe",
    r"C:\Users\u\Downloads\random-name.dll",
    r"C:\Windows\Temp\payload.ps1",
]):
    app = {"entries": [{"identifier": path, "score": "LOW",
                         "reason": "LLM provisional", "mitre": [], "iocs": [path]}]}
    app_out = analyze_section._apply_post_filter("appcompat_cache", app, [])["entries"][0]
    check(f"generic user-writable executable {idx} receives MEDIUM floor",
          app_out.get("score") == "MEDIUM", app_out)
    check(f"generic floor id {idx}",
          app_out.get("_floor") == "user_writable_execution_artifact", app_out)

high_path = r"C:\Users\u\AppData\Local\Temp\VendorBUpdate.exe"
high_out = analyze_section._apply_post_filter("appcompat_cache", {"entries": [{
    "identifier": high_path, "score": "HIGH", "reason": "x", "mitre": [], "iocs": [high_path],
}]}, [])["entries"][0]
check("generic MEDIUM floor never downgrades HIGH", high_out.get("score") == "HIGH", high_out)
check("non-executable temp artifact is not name-calibrated",
      analyze_section._apply_post_filter("appcompat_cache", {"entries": [{
          "identifier": r"C:\Users\u\AppData\Local\Temp\VendorASetup.tmp", "score": "LOW",
          "reason": "x", "mitre": [], "iocs": [r"C:\Users\u\AppData\Local\Temp\VendorASetup.tmp"],
      }]}, [])["entries"][0]["score"] == "LOW")


print("\n--- all-deferred report visibility ---")
sec_data = {
    "section": "startup_folder",
    "entries": [],
    "section_summary": "depth2選抜後のLLM送付対象なし",
    "_selection_stats": {
        "raw": 6, "selected": 0, "deterministic": 0, "deferred": 6,
        "deferred_by_policy": 6,
        "by_reason": {"deferred:over_global_budget": 6},
        "global_planned_output_tokens": 74848,
        "global_budget": 75000,
    },
}
md = report_gen.section_entries_md("startup_folder", sec_data)
check("all-deferred heading is explicit", "全件繰延・未評価" in md, md)
check("all-deferred warning says not safe", "安全確認済みを意味しません" in md, md)
check("deferred reason shown", "over_global_budget=6" in md, md)
check("does not use empty-section class", 'class="sec-empty"' not in md, md)

normal_empty = report_gen.section_entries_md("startup_folder", {
    "section": "startup_folder", "entries": [], "section_summary": "対象なし",
})
check("genuinely empty section remains 所見なし", "所見なし" in normal_empty, normal_empty)

print(f"\nRESULT: PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
