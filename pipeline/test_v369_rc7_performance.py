#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 Depth2 performance, progress and PDF diagnostics regression."""
from __future__ import annotations

import re
import sys
import time

import analyze_section as az
import depth2_select as d2
from section_prompts import get_level1_filters
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION, BUDGET_PROFILE_DEFAULT

PASS = FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [OK]  {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else ""))


def section(name):
    print("\n" + "-" * 60 + f"\n  {name}\n" + "-" * 60)


section("V1 rc9 identity")
check("V1-1 pipeline", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("V1-2 schema", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("V1-3 profile", BUDGET_PROFILE_DEFAULT == "v370",
      BUDGET_PROFILE_DEFAULT)


section("V2 exact O(N^2) replacement")
normal = set(range(0, 20))
novelty = set(range(20, 40))
chosen = {0, 20}
sig = [22, 1, 21, 2]  # intentionally unsorted: rc6 preserved insertion order
actual = d2._build_deferred_reasons(normal, novelty, chosen, sig, True)
legacy_sig = list(sig)
legacy = {"signature_diversity": list(legacy_sig)}
for gi in sorted((normal | novelty) - chosen):
    if gi in legacy["signature_diversity"]:
        continue
    legacy.setdefault("over_section_cap", []).append(gi)
check("V2-1 selected/deferred reason sets preserved",
      {k: set(v) for k, v in actual.items()} == {k: set(v) for k, v in legacy.items()},
      str(actual))
check("V2-2 order difference is explicit", actual["signature_diversity"] != legacy_sig)
check("V2-3 rc9 canonical order sorted", actual["signature_diversity"] == sorted(sig))


section("V3 Level1 predicate compatibility")
def legacy_match(section_name, entry):
    pats = [re.compile(x, re.I) for x in get_level1_filters(section_name)]
    if not pats:
        return True
    if isinstance(entry, str):
        return any(p.search(entry) for p in pats)
    if isinstance(entry, dict):
        return any(p.search(v) for v in entry.values() if isinstance(v, str) for p in pats)
    return False

examples = [
    {"path": r"C:\Users\Public\drop.exe", "name": "drop.exe", "size": "1"},
    {"path": r"C:\Windows\System32\kernel32.dll", "name": "kernel32.dll", "size": "0"},
    {"path": r"D:\tools\x.dll", "name": "x.dll", "source_id": "directory:7abc.tmp"},
    {"path": r"C:\Data\invoice.pdf.exe", "name": "invoice.pdf.exe"},
    "TCP 10.0.0.1:1 1.1.1.1:443 ESTABLISHED",
]
for sec in ("directory", "netstat"):
    for i, item in enumerate(examples):
        check(f"V3 {sec} example {i}",
              az.entry_matches_level1(sec, item) == legacy_match(sec, item))


section("V4 planner scalability without selection drift")
n = 100_000
pool = []
for i in range(n):
    family = i // 4
    pool.append((i, {
        "path": rf"C:\Users\u\AppData\Local\Temp\family{family:08d}.exe",
        "name": f"family{family:08d}.exe",
        "source_id": f"directory:{i:09d}",
        "size": str(100 + i % 17),
    }))
t0 = time.perf_counter()
planned = d2.plan_depth2_selection(
    {"directory": pool}, d2.empty_ctx(), ["directory"],
    novelty_pools={"directory": []})["directory"]
elapsed = time.perf_counter() - t0
counts = {k: len(v) for k, v in planned["deferred_reasons"].items()}
check("V4-1 completes under 10 seconds", elapsed < 10.0, f"{elapsed:.3f}s")
check("V4-2 M1 parent bound", len(planned["selected"]) == 8,
      len(planned["selected"]))
check("V4-3 signature classification exact", counts.get("signature_diversity") == 2,
      str(counts))
check("V4-4 M1 policy classification exact", counts.get("m1_policy_bound") == 99_990,
      str(counts))


section("V5 structured GUI progress")
events = []
parsed_rule = {
    "meta": {"hostname": "RC7-PROGRESS"},
    "sections": {"userassist": [{"path": r"C:\Temp\x.exe", "run_count": 1}]},
    "event_logs": {},
}
result = az.analyze(parsed_rule, 2, None, "stub",
                    target_sections=["userassist"], progress_callback=events.append)
stages = [e.get("stage") for e in events if isinstance(e, dict)]
check("V5-1 selection prepare event", "selection_prepare" in stages, str(stages))
check("V5-2 selection plan event", "selection_plan" in stages, str(stages))
check("V5-3 section progress event", "section_analysis" in stages, str(stages))
check("V5-4 output produced", "userassist" in result.get("sections", {}))


section("V6 compact provenance and unevaluated failure path")
raw = [{"path": r"C:\Users\Public\drop.exe", "name": "drop.exe",
        "source_id": "directory:000000"}]
raw.extend({"path": rf"C:\Windows\System32\normal{i}.mui", "name": f"normal{i}.mui",
            "source_id": f"directory:{i+1:06d}"} for i in range(200))
parsed = {"meta": {"hostname": "RC7-PROV"}, "sections": {"directory": raw},
          "event_logs": {}}
orig = az.call_llm_chunked
try:
    az.call_llm_chunked = lambda *a, **k: (
        [], "stub", [{"unevaluated_indices": [0], "error": "forced"}], [])
    out = az.analyze(parsed, 2, None, "stub", target_sections=["directory"])
finally:
    az.call_llm_chunked = orig
sec = out["sections"]["directory"]
prov = sec.get("_provenance", {})
check("V6-1 compact source IDs",
      prov.get("source_ids_scope") == "mandatory_deterministic_selected_evaluated_unevaluated",
      str(prov.keys()))
check("V6-2 raw count retained", prov.get("raw_count") == len(raw), prov.get("raw_count"))
check("V6-3 deferred IDs omitted explicitly", prov.get("deferred_source_ids_omitted", 0) > 0,
      prov.get("deferred_source_ids_omitted"))
check("V6-4 no missing to_dict crash", "selected_unevaluated_ranges" in prov, str(prov.keys()))


section("V7 PDF runtime import")
try:
    import reportlab
    import pdf_export
    ok = True
    detail = f"python={sys.executable} reportlab={reportlab.__version__} pdf={pdf_export.__file__}"
except Exception as exc:
    ok = False
    detail = f"{type(exc).__name__}: {exc}"
check("V7-1 reportlab/pdf_export import", ok, detail)

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
