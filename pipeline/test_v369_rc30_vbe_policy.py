#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 VBE/M0-M1-Tier-R/chat raw fallback regressions."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import analyze_section as a
import depth2_select as d2
import directory_policy as dp
from chat_tools import ChatContext

PASS = FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [OK]  {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}: {detail}")


def entry(path, index=0):
    p = str(path)
    parent, _, name = p.rpartition("\\")
    return {
        "date": "2026/07/15  10:09",
        "size": "371",
        "name": name,
        "path": p,
        "dir": parent,
        "source_id": f"directory:{index:06d}",
    }


wef = entry(r"C:\Users\Public\Music\wef.vbe", 1)
check("wef.vbe is M1", dp.evidence_tier(wef) == "M1", dp.evidence_tier(wef))
check("wef.vbe Level1 match", a.entry_matches_level1("directory", wef))
cls = a._classify_dir_entry(wef)
check("wef.vbe score uses real path fields", a._dir_anomaly_score(wef, cls) >= 120,
      a._dir_anomaly_score(wef, cls))
check("wef.vbe MEDIUM floor", a._floor_rule(wef["path"]) is not None,
      a._floor_rule(wef["path"]))

for ext in (".vbe", ".cmd", ".jse", ".wsf", ".msi", ".msp"):
    e = entry(rf"C:\Users\Public\Music\sample{ext}")
    check(f"canonical Level1 {ext}", a.entry_matches_level1("directory", e))
    check(f"canonical floor {ext}", a._floor_rule(e["path"]) is not None)
    check(f"Depth2 M1 {ext}", d2.is_user_writable_execution_artifact(e))

# M0 selection guarantee after duplicate-pattern suppression.
m0 = [entry(rf"C:\Users\u\Desktop\invoice{i:03d}.pdf.exe", i) for i in range(10)]
scored_m0 = [(a._dir_anomaly_score(e, "A"), "A", e) for e in m0]
selected, overflow, info = a._select_dir_llm_entries(scored_m0, max_llm=2, sig_max=3)
check("M0 may exceed normal budget but duplicate family is bounded", len(selected) == 3,
      (len(selected), info))
check("M0 overrun audited", info["normal_budget_overrun_by_m0"] == 1, info)

# 200 differently named Public files cannot occupy all 200 slots: same parent=8.
m1 = [entry(rf"C:\Users\Public\Music\junk_{i:03d}_name{i}.exe", i) for i in range(200)]
def alpha_name(i):
    alphabet = "ghijklmnopqrstuvwxyz"
    chars = []
    n = i
    for _ in range(4):
        chars.append(alphabet[n % len(alphabet)])
        n //= len(alphabet)
    return "risk_" + "".join(chars)

r = [entry(rf"C:\Users\u\Downloads\{alpha_name(i)}.exe", 1000+i) for i in range(220)]
scored = [(a._dir_anomaly_score(e, "B"), "B", e) for e in m1 + r]
selected, overflow, info = a._select_dir_llm_entries(scored, max_llm=200, sig_max=3)
check("directory total remains normal cap without M0", len(selected) == 200, len(selected))
check("same Public parent bounded to 8", info["tier_selected"]["M1"] == 8, info)
check("Tier R has no fixed 100 maximum", info["tier_selected"]["R"] == 192, info)
check("M1 coverage degradation is explicit", info["coverage_degraded"], info)

# Deep AppData/browser-style JS remains Tier R, not M1.
deep = entry(r"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Extensions\abc\1.0\worker.js")
check("deep AppData JS is Tier R", dp.evidence_tier(deep) == "R", dp.evidence_tier(deep))

# Chat fallback: analyzed has no hit, parsed raw contains wef.vbe.
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    (root / "analyzed_HOST.json").write_text(
        json.dumps({"sections": {"directory": {"entries": []}}}, ensure_ascii=False),
        encoding="utf-8")
    (root / "parsed_HOST.json").write_text(
        json.dumps({"sections": {"directory": [wef]}}, ensure_ascii=False),
        encoding="utf-8")
    ctx = ChatContext(root, root)
    got = ctx.tool_search_keyword("wef.vbe")
    check("chat raw fallback finds wef.vbe", got.get("count") == 1 and got.get("raw_fallback_searched"), got)
    check("chat reports raw scope", got.get("scope") in {"parsed_directory_raw", "parsed_directory_raw_index"}, got)
    missing = ctx.tool_search_keyword("definitely-not-present.xyz")
    check("chat missing result is scope-qualified", "絶対的な不存在" in missing.get("note", ""), missing)

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
