#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70: input integrity, provenance and runtime hardening tests."""
from __future__ import annotations
import base64
import json
import os
import tempfile
from pathlib import Path

import parse_checkpc as pc
from source_id import assign_source_ids
from evidence_meta import classify_event_text
from llm_runtime import extract_llm_text
from provenance import DispositionLedger, PlannedItem
from vt_post import apply_vt_score
from correlate import _apply_ioc_category_fallback
from budget_profile import active_profile
import depth2_select as d2
from atomic_io import atomic_write_json, load_json_with_recovery
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION

PASS = FAIL = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1; print(f"  [OK]  {name}")
    else:
        FAIL += 1; print(f"  [FAIL] {name}" + (f": {detail}" if detail else ""))

def section(name):
    print("\n" + "-"*60 + f"\n  {name}\n" + "-"*60)

section("V1 version/profile")
check("V1-1 pipeline version", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("V1-2 schema version", ANALYSIS_SCHEMA_VERSION == "2.1")
prof = active_profile()
check("V1-3 provisional profile", prof.name == "v370", prof.name)
check("V1-4 ratios sum to 1", abs(prof.risk_ratio + prof.fair_ratio + prof.novelty_ratio - 1) < 1e-9)

section("V2 physical section split")
text = """1. Check Environment\nCOMPUTERNAME=HOST\n4. Check Association of EXE\nA\n5. Check UAC Bypass\nB\n15. Check Directory\nD\n17. Check Tasklist\nT\nXX. Check Others\nO\n16. Check Netstat\nN\n"""
secs, meta = pc.split_sections(text, return_meta=True)
check("V2-1 association independent", secs.get("association_exe", "").endswith("\nA") and "5. Check" not in secs.get("association_exe", ""))
check("V2-2 uac independent", secs.get("uac_bypass", "").endswith("\nB") and "15. Check" not in secs.get("uac_bypass", ""))
check("V2-3 directory not polluted", secs.get("directory", "").endswith("\nD") and "17. Check" not in secs.get("directory", ""))
check("V2-4 netstat after others", secs.get("netstat", "").strip().endswith("N") and "XX. Check" not in secs.get("netstat", ""))
check("V2-5 physical order recorded", meta.get("section_order", [])[-2:] == ["XX", "16"], str(meta))

section("V3 multi-position encoding")
with tempfile.TemporaryDirectory() as td:
    p = Path(td)/"mixed.txt"
    raw = b"A"*(1024*1024+123) + "15. Check Directory\r\n C:\\Temp のディレクトリ\r\n".encode("cp932")
    p.write_bytes(raw)
    decoded, info = pc.read_file_with_info(str(p))
    check("V3-1 late cp932 marker survives", "のディレクトリ" in decoded, str(info))
    check("V3-2 encoding metadata", info.get("encoding") in ("cp932", "shift_jis"), str(info))

section("V4 evidence quality")
q0 = classify_event_text("", max_records=1000)
q1000 = classify_event_text("\n".join(f"Event[{i}]" for i in range(1000)), max_records=1000)
check("V4-1 empty is unverified", q0.get("evidence_state") == "EMPTY_UNVERIFIED", str(q0))
check("V4-2 1000 is possibly truncated", q1000.get("possibly_truncated") is True, str(q1000))

section("V5 companion association")
with tempfile.TemporaryDirectory() as td:
    d = Path(td)
    (d/"Eventlog_System_7045_HOST_20260717120000.txt").write_text("one", encoding="utf-8")
    (d/"Eventlog_System_7045_HOST_20260718120000.txt").write_text("two", encoding="utf-8")
    path, by, candidates = pc._select_companion_file(str(d), "Eventlog_System_7045_HOST_", "20260718120000")
    check("V5-1 exact timestamp", Path(path).name.endswith("20260718120000.txt"), path)
    check("V5-2 association reason", by == "hostname_timestamp_exact", by)
    path2, by2, _ = pc._select_companion_file(str(d), "Eventlog_System_7045_HOST_", "20260719120000")
    check("V5-3 ambiguous candidates not selected", not path2 and by2 == "ambiguous_candidates", by2)

section("V6 stable source IDs")
entries1 = [{"path":"C:\\Temp\\a.exe", "size":"1"}, {"path":"C:\\Temp\\a.exe", "size":"1"}]
entries2 = json.loads(json.dumps(entries1))
assign_source_ids("collection", "directory", entries1)
assign_source_ids("collection", "directory", entries2)
check("V6-1 deterministic", [e["source_id"] for e in entries1] == [e["source_id"] for e in entries2])
check("V6-2 duplicates distinct", entries1[0]["source_id"] != entries1[1]["source_id"])

section("V7 provenance unevaluated")
ledger = DispositionLedger(3)
for i in range(3): ledger.add(PlannedItem({}, i, [i], "selected", "representative_selected"))
ledger.mark_unevaluated([1,2])
check("V7-1 list marking", ledger.stats()["selected_unevaluated"] == 2)
check("V7-2 coverage", ledger.stats()["selected_coverage_pct"] < 100)

section("V8 novelty selection")
ctx = d2.empty_ctx()
pools = {"directory": [(0, {"path":"C:\\Windows\\normal.dll"})]}
novelty = {"directory": [(1, {"path":"C:\\Users\\Public\\odd.ps1"}), (2, {"path":"C:\\Temp\\blob.js"})]}
res = d2.plan_depth2_selection(pools, ctx, ["directory"], novelty_pools=novelty)
reasons = res["directory"].get("selected_reasons", {})
check("V8-1 novelty selected", any(v == "novelty_selected" for v in reasons.values()), str(reasons))
check("V8-2 provenance exact signature reason", "signature_diversity" in res["directory"].get("deferred_reasons", {}))

section("V9 LLM defensive extraction")
class R: pass
r=R(); r.choices=[]
check("V9-1 empty choices", extract_llm_text(r).error == "empty_choices")
r2=R(); c=R(); m=R(); m.content=None; c.message=m; c.finish_reason="stop"; r2.choices=[c]
check("V9-2 none content", extract_llm_text(r2).error == "missing_content")

section("V10 VT clean does not downgrade")
score, changed, note = apply_vt_score("MEDIUM", {"verdict":"clean","positives":0,"total":70}, "fqdn")
check("V10-1 score remains MEDIUM", score == "MEDIUM" and not changed, f"{score}/{changed}")
check("V10-2 note explains", "スコアは維持" in note, note)

section("V11 private IOC category")
doc={"correlated_iocs":[{"ioc":"192.168.1.5","significance":""}]}
_apply_ioc_category_fallback(doc)
check("V11-1 private is internal_unclear", doc["correlated_iocs"][0]["category"] == "internal_unclear")

section("V12 atomic recovery")
with tempfile.TemporaryDirectory() as td:
    p=Path(td)/"x.json"
    atomic_write_json(p,{"ok":1})
    check("V12-1 atomic JSON read", load_json_with_recovery(p,{}) == {"ok":1})
    p.write_text("{broken", encoding="utf-8")
    check("V12-2 corrupt recovery", load_json_with_recovery(p,{"fallback":1}) == {"fallback":1})
    check("V12-3 corrupt file retained", any(x.name.startswith("x.json.corrupt") for x in Path(td).iterdir()))

section("V13 HTTP Basic PBKDF2")
import base64, hashlib, os
with tempfile.TemporaryDirectory() as td:
    os.environ["PIPELINE_JOBS_DIR"] = td
    os.environ.pop("PIPELINE_API_KEY", None)
    salt = b"v369-fixed-test-salt"
    digest = hashlib.pbkdf2_hmac("sha256", b"correct-password", salt, 120000)
    os.environ["PIPELINE_AUTH_USER"] = "analyst"
    os.environ["PIPELINE_AUTH_PBKDF2"] = (
        "120000$" + base64.b64encode(salt).decode() + "$" +
        base64.b64encode(digest).decode()
    )
    import importlib
    sv = importlib.import_module("server")
    class Req:
        def __init__(self, value): self.headers={"Authorization": value}
    def basic(user, password):
        token=base64.b64encode(f"{user}:{password}".encode()).decode()
        return "Basic " + token
    check("V13-1 correct credentials", sv._verify_basic_auth(Req(basic("analyst", "correct-password"))))
    check("V13-2 wrong password denied", not sv._verify_basic_auth(Req(basic("analyst", "wrong"))))
    check("V13-3 wrong user denied", not sv._verify_basic_auth(Req(basic("other", "correct-password"))))

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(1 if FAIL else 0)
