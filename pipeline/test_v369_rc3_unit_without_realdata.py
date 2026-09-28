#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Run synthetic/unit portions that legacy mixed real-data tests otherwise skip."""
from __future__ import annotations
import json
import tempfile
from datetime import datetime
from pathlib import Path

PASS = FAIL = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1; print(f"  [OK]  {name}")
    else:
        FAIL += 1; print(f"  [FAIL] {name}" + (f": {detail}" if detail else ""))

def section(name):
    print("\n" + "-"*60 + f"\n  {name}\n" + "-"*60)

section("U1 timeline synthetic coverage")
import timeline as tl
for value in (
    "2026/06/25  22:38", "2026/06/25 22:38:01",
    "2026-06-25 22:38:01", "2022-12-29T13:39:08.353",
    "2026-06-25 22:38",
):
    check(f"U1 parse {value}", tl._parse_ts(value) is not None)
check("U1 invalid timestamp rejected", tl._parse_ts("not a date") is None)
for value in ("0.0.0.0", "3389", r"C:\Program"):
    check(f"U1 generic finding {value}", tl._is_generic_finding(value))
for value in ("mimikatz.exe", "evil.example.com", r"C:\Users\u\Temp\bad.exe"):
    check(f"U1 specific finding {value}", not tl._is_generic_finding(value))

def ev(ts, sec, sev, suspicious=False):
    return {"datetime": datetime.strptime(ts, "%Y-%m-%d %H:%M:%S"), "ts": ts,
            "section": sec, "severity": sev, "phase": "x", "summary": sec,
            "mitre": [], "suspicious": suspicious}

events = [ev("2026-06-20 09:00:00", "userassist", "LOW"),
          ev("2026-06-20 14:00:00", "defender_quarantine", "HIGH"),
          ev("2026-06-20 14:20:00", "userassist", "LOW")]
shown, suppressed = tl._filter_events_for_display(events, None, full=False)
check("U1 near-anchor LOW retained", any(x["ts"] == "2026-06-20 14:20:00" for x in shown))
check("U1 distant LOW suppressed", suppressed == 1, suppressed)

section("U2 deterministic report fallback")
import report_gen as rg
analyzed = {"sections": {"defender_quarantine": {"entries": [
    {"score": "HIGH", "identifier": "Trojan:Win32/Bearfoos.A!ml"}]}}}
corr = {"infection_suspicion": None, "malware_family": "Unknown"}
rg.apply_deterministic_fallback(corr, analyzed)
check("U2 suspicion floor", corr.get("infection_suspicion") == "HIGH", corr)
check("U2 family fallback", "Bearfoos.A" in corr.get("malware_family", ""), corr)
check("U2 provenance flags", bool(corr.get("_meta_flags", {}).get("suspicion_fallback")))
snapshot = json.dumps(corr, sort_keys=True, ensure_ascii=False)
rg.apply_deterministic_fallback(corr, analyzed)
check("U2 fallback idempotent", snapshot == json.dumps(corr, sort_keys=True, ensure_ascii=False))

section("U3 VT downgrade unit coverage")
import vt_post as vt

def run_vt(identifier, ioc, verdict=None, section_name="system_7045", score="HIGH"):
    entry = {"identifier": identifier, "score": score, "iocs": [ioc], "reason": "orig"}
    if verdict is not None:
        entry["_vt_results"] = [{"verdict": verdict, "ioc": ioc}]
    doc = {"sections": {section_name: {"entries": [entry]}}}
    count = vt.apply_peruser_high_downgrade(doc)
    return entry["score"], count

score, count = run_vt("HWiNFO Kernel Driver", r"C:\Users\u\AppData\Local\Temp\HWiNFO_x64.sys", "clean")
check("U3 allowlisted clean downgraded", score == "MEDIUM" and count == 1)
score, _ = run_vt("HWiNFO Kernel Driver", r"C:\Users\u\AppData\Local\Temp\HWiNFO_x64.sys", "malicious")
check("U3 malicious remains HIGH", score == "HIGH")
score, _ = run_vt("EvilSvc", r"C:\Users\u\AppData\Roaming\Evil\backdoor.exe", "clean")
check("U3 unknown vendor remains HIGH", score == "HIGH")
score, _ = run_vt("HWiNFO Kernel Driver", r"C:\Users\u\AppData\Local\Temp\HWiNFO_x64.sys", None)
check("U3 unqueried remains HIGH", score == "HIGH")

section("U4 ChatContext synthetic coverage")
import chat_tools as ct
with tempfile.TemporaryDirectory() as td:
    run_dir = Path(td) / "job" / "output" / "HOST_20260719"
    run_dir.mkdir(parents=True)
    analyzed_doc = {"sections": {
        "startup_folder": {"entries": [
            {"score": "HIGH", "identifier": "Zotero.dotm", "reason": "office add-in", "iocs": [r"C:\Zotero.dotm"]},
            {"score": "LOW", "identifier": "normal.lnk", "reason": "normal", "iocs": []},
        ]},
        "netstat": {"entries": [{"score": "MEDIUM", "identifier": "evil.example:443", "reason": "external", "iocs": ["evil.example"]}]},
    }}
    parsed_doc = {"sections": {"directory": [
        {"dir": r"C:\Program Files\Demo", "name": "a.exe", "size": 1},
        {"dir": r"C:\Program Files\Demo\sub", "name": "b.dll", "size": 2},
    ]}}
    (run_dir / "analyzed_HOST.json").write_text(json.dumps(analyzed_doc), encoding="utf-8")
    (run_dir / "parsed_HOST.json").write_text(json.dumps(parsed_doc), encoding="utf-8")
    (run_dir / "correlation_HOST.json").write_text(json.dumps({"infection_suspicion":"HIGH"}), encoding="utf-8")
    ctx = ct.ChatContext(run_dir, Path(td), vt_key="")
    check("U4 get section", len(ctx.tool_get_section("startup_folder").get("entries", [])) == 2)
    check("U4 missing section reports candidates", "available_sections" in ctx.tool_get_section("missing"))
    check("U4 entry detail searches IOC/reason", len(ctx.tool_get_entry_detail("startup_folder", "zotero").get("matches", [])) == 1)
    hm = ctx.tool_list_high_medium()
    check("U4 HIGH/MEDIUM only", hm.get("count") == 2 and all(e.get("score") in {"HIGH", "MEDIUM"} for e in hm.get("entries", [])), hm)
    directory = ctx.tool_list_directory_files(r"C:\Program Files\Demo", max_results=10)
    check("U4 directory recursive listing", directory.get("total") == 2, directory)
    check("U4 VT guard without key", "error" in ctx.tool_vt_lookup("evil.example"))

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(1 if FAIL else 0)
