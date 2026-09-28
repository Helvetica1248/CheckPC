#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 progress, comparison, provenance and correlation regressions."""
from __future__ import annotations

from types import SimpleNamespace

import analyze_section as az
import compare_analyzed as cmp
import correlate as corr
import depth2_select as d2
import ioc_utils as iu
from provenance import DispositionLedger, PlannedItem

PASS = FAIL = 0

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"[PASS] {name}")
    else:
        FAIL += 1; print(f"[FAIL] {name}" + (f" :: {detail}" if detail else ""))

# A1: unsorted signature list: reason sets match but order is intentionally canonicalized.
normal, novelty, chosen = set(range(20)), set(range(20, 40)), {0, 20}
sig = [22, 1, 21, 2]
actual = d2._build_deferred_reasons(normal, novelty, chosen, sig, True)
legacy = {"signature_diversity": list(sig)}
for gi in sorted((normal | novelty) - chosen):
    if gi not in legacy["signature_diversity"]:
        legacy.setdefault("over_section_cap", []).append(gi)
check("F1 unsorted signature reason sets match",
      {k:set(v) for k,v in actual.items()} == {k:set(v) for k,v in legacy.items()})
check("F2 signature order not claimed identical", actual["signature_diversity"] != sig)

# PlannedItem: mutation after ledger.add cannot alter audit state; all values normalize to int.
src = [0, "1", 2]
item = PlannedItem({}, 0, src, "selected", "risk_selected")
ledger = DispositionLedger(3)
ledger.add(item)
src[0] = 99; src.append(100)
audit = item.to_audit()
check("F3 PlannedItem no shared mutable list", audit["source_index_ranges"] == [[0,2]], audit)
check("F4 PlannedItem count normalized", audit["source_count"] == 3, audit)
check("F5 ledger selection immutable", ledger.selected == {0,1,2}, ledger.selected)

# Deferred duplicate guard after global budget adjustment.
pool = []
for i in range(3000):
    pool.append((i, {"path": rf"C:\\Temp\\x{i}.exe", "name":f"x{i}.exe", "source_id":f"directory:{i}"}))
plan = d2.plan_depth2_selection({"directory":pool}, d2.empty_ctx(), ["directory"], novelty_pools={"directory":[]})["directory"]
for reason, indices in plan["deferred_reasons"].items():
    check(f"F6 deferred unique {reason}", len(indices) == len(set(indices)))
selected = {i for i,_ in plan["selected"]}
deferred = set().union(*(set(v) for v in plan["deferred_reasons"].values()))
check("F7 selected and deferred disjoint", not (selected & deferred))

# A5: cancellation emits terminal accounting for every target.
events = []
checks = {"n": 0}
def cancel_check():
    checks["n"] += 1
    return checks["n"] > 1
parsed = {
    "meta":{"hostname":"CANCEL"},
    "sections":{
        "userassist":[{"path":r"C:\\Temp\\a.exe","run_count":1}],
        "known_tools":[],
        "defender_quarantine":[],
    },
    "event_logs":{},
}
out = az.analyze(parsed, 2, None, "stub",
                 target_sections=["userassist","known_tools","defender_quarantine"],
                 cancel_check=cancel_check, progress_callback=events.append)
finals = [e for e in events if isinstance(e,dict) and e.get("event") == "final"]
check("F8 cancellation final event exists", len(finals) == 1, finals)
if finals:
    f = finals[0]
    check("F9 terminal count equals total", f.get("terminal") == f.get("total") == 3, f)
    check("F10 completed+cancelled+failed=total",
          f.get("completed",0)+f.get("cancelled",0)+f.get("failed",0) == 3, f)
    check("F11 active empty at final", f.get("active_sections") == [], f)

# A6: normal concurrent progress is monotonic and terminal sections are unique.
events2=[]
parsed2={"meta":{"hostname":"PROGRESS"},"sections":{
    "userassist":[{"path":r"C:\\Temp\\a.exe","run_count":1}],
    "known_tools":[],"defender_quarantine":[],"rdp_inbound":[]},"event_logs":{}}
az.analyze(parsed2,2,None,"stub",
           target_sections=["userassist","known_tools","defender_quarantine","rdp_inbound"],
           progress_callback=events2.append)
sec_events=[e for e in events2 if isinstance(e,dict) and e.get("stage")=="section_analysis"]
term=[e.get("terminal",0) for e in sec_events]
check("F12 progress terminal monotonic", term == sorted(term), term)
terminal_names=[e.get("last_completed") or e.get("last_cancelled") or e.get("last_failed")
                for e in sec_events if e.get("event") in {"complete","cancel","fail"}]
check("F13 terminal sections not duplicated", len(terminal_names)==len(set(terminal_names)), terminal_names)

# Two-stage compare: shared source_id must win even if canonical fields differ.
a={"sections":{"directory":{"entries":[
    {"source_id":"directory:abc","identifier":"C:/OLD.exe","score":"HIGH","reason":"a","iocs":[]},
    {"identifier":"legacy.exe","datetime":"","score":"LOW","reason":"legacy","iocs":[]},
]}}}
b={"sections":{"directory":{"entries":[
    {"source_id":"directory:abc","identifier":"C:/NEW.exe","score":"HIGH","reason":"b","iocs":[]},
    {"identifier":"legacy.exe","datetime":"","score":"LOW","reason":"legacy","iocs":[]},
]}}}
fatal, adjud, matrix = cmp.compare(a,b,False)
check("F14 two-stage compare avoids false disappearance", not fatal and not adjud, (fatal,adjud))
check("F15 two-stage mode label", cmp.comparison_key_mode(a,b)=="source_id_then_canonical")

# Correlation compact retry and finish_reason preservation.
responses=[
    SimpleNamespace(text='{"infection_suspicion":"HIGH",', error=None, finish_reason="length"),
    SimpleNamespace(text='{"infection_suspicion":"HIGH","infection_summary":"x","malware_family":"Unknown","correlated_iocs":[],"timeline":[],"mitre_ttps":[],"recommended_actions":[]}', error=None, finish_reason="stop"),
]
orig_create, orig_extract = corr.create_chat_completion, corr.extract_llm_text
try:
    corr.create_chat_completion=lambda *a,**k: responses.pop(0)
    corr.extract_llm_text=lambda x: x
    doc={"meta":{"hostname":"CORR"},"sections":{"directory":{"entries":[
        {"identifier":"x","score":"HIGH","reason":"r","iocs":[]}
    ]}}}
    result=corr.correlate(doc,2,object(),"stub")
finally:
    corr.create_chat_completion, corr.extract_llm_text = orig_create, orig_extract
check("F16 compact retry succeeds", result.get("_correlate_retry",{}).get("succeeded") is True, result)
check("F17 successful finish_reason retained", result.get("finish_reason") == "stop", result)
check("F18 deterministic suspicion retained", result.get("infection_suspicion") == "HIGH", result)


# IOC representation is stable across output modes without losing full paths.
e={"iocs":["170.205.43.80:1058", "ABCDEF0123456789ABCDEF0123456789", "EXAMPLE.COM.",
           '"C:/Program Files/App/app.exe" --silent', "170.205.43.80"]}
iu.normalize_entry_iocs(e)
check("F19 IP port separated", e["iocs"].count("170.205.43.80") == 1 and e.get("ioc_ports") == [1058], e)
check("F20 hash normalized lowercase", "abcdef0123456789abcdef0123456789" in e["iocs"], e)
check("F21 FQDN normalized lowercase", "example.com" in e["iocs"], e)
check("F22 command line reduced to full path", r"C:\Program Files\App\app.exe" in e["iocs"], e)

print(f"PASS={PASS} FAIL={FAIL}")
raise SystemExit(1 if FAIL else 0)
