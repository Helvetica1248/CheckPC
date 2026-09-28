# -*- coding: utf-8 -*-
"""T-TL4（timeline配線）/ T-TL5（LOW抑制）/ R-3・R-4移植 の回帰テスト。

scripts/ 配下のモジュールを対象に検証する。実データはCHECKPC_TEST_EXTRACTで指定する。
"""
import os
import sys, glob, json, importlib.util
from datetime import datetime

for _c in (os.environ.get("CHECKPC_SCRIPTS", ""), os.path.dirname(os.path.abspath(__file__)),
           os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
           "/opt/llm/analysis", "/home/claude/scripts"):
    if _c and os.path.exists(os.path.join(_c, "analyze_section.py")):
        SCRIPTS = _c
        break
else:
    print("analyze_section.py が見つかりません"); sys.exit(2)
sys.path.insert(0, SCRIPTS)
def _mod(name):
    spec = importlib.util.spec_from_file_location(name, f"{SCRIPTS}/{name}.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
tl = _mod("timeline")
rg = _mod("report_gen")

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: print(f"  [OK]  {name}"); PASS += 1
    else: print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1
def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

def _ev(ts, section, sev, suspicious=False):
    return {"datetime": datetime.strptime(ts, "%Y-%m-%d %H:%M:%S"), "ts": ts,
            "section": section, "severity": sev, "phase": "x",
            "summary": f"{section} ev", "mitre": [], "suspicious": suspicious}

# ════════════════════════════════════════════════════════════
sec("T-TL5: LOW実行痕跡の判定とアンカー近接抑制")
check("userassist LOW 非不審 → 抑制対象",
      tl._is_low_exec_noise(_ev("2026-06-20 10:00:00", "userassist", "LOW")))
check("prefetch LOW 非不審 → 抑制対象",
      tl._is_low_exec_noise(_ev("2026-06-20 10:00:00", "prefetch", "LOW")))
check("userassist LOW だが不審(*) → 抑制対象外",
      not tl._is_low_exec_noise(_ev("2026-06-20 10:00:00", "userassist", "LOW", True)))
check("rdp_1024 LOW（実行痕跡でない）→ 抑制対象外",
      not tl._is_low_exec_noise(_ev("2026-06-20 10:00:00", "rdp_1024", "LOW")))
check("HIGH severity → 抑制対象外",
      not tl._is_low_exec_noise(_ev("2026-06-20 10:00:00", "userassist", "HIGH")))

# アンカー近接: HIGH の ±30分内の LOW exec は残す / 遠いものは抑制
events = [
    _ev("2026-06-20 09:00:00", "userassist", "LOW"),   # アンカーから遠い → 抑制
    _ev("2026-06-20 14:00:00", "defender_quarantine", "HIGH"),  # アンカー
    _ev("2026-06-20 14:20:00", "userassist", "LOW"),   # アンカー+20分 → 残す
    _ev("2026-06-20 18:00:00", "prefetch", "LOW"),     # アンカーから遠い → 抑制
]
shown, supp = tl._filter_events_for_display(events, None, full=False)
check("アンカー±30分内のLOW実行痕跡は保持", any(e["ts"]=="2026-06-20 14:20:00" for e in shown))
check("アンカーから遠いLOW実行痕跡は抑制（2件）", supp == 2, f"supp={supp}")
check("HIGHアンカー自体は常に保持", any(e["severity"]=="HIGH" for e in shown))

shown_full, supp_full = tl._filter_events_for_display(events, None, full=True)
check("full=True では抑制ゼロ・全件表示", supp_full == 0 and len(shown_full) == 4)

# ════════════════════════════════════════════════════════════
sec("T-TL5: build_timeline_markdown / render の full 引数")
secs = {"userassist": [
    {"last_run": "2026-06-20 09:00:00", "path": "a.exe"},
    {"last_run": "2026-06-20 09:05:00", "path": "b.exe"},
]}
md_supp = tl.build_timeline_markdown(secs, findings=[], full=False)
md_full = tl.build_timeline_markdown(secs, findings=[], full=True)
check("抑制版: アンカー無し→LOW実行痕跡が全抑制され注記表示",
      "LOW実行痕跡" in md_supp and "抑制: 2件" in md_supp, md_supp)
check("全件版: 抑制注記が出ない", "抑制:" not in md_full)

# ════════════════════════════════════════════════════════════
sec("R-3/R-4移植: apply_deterministic_fallback の来歴フラグ・冪等性")
a3 = {"sections": {"defender_quarantine": {"entries": [
    {"score": "HIGH", "identifier": "Trojan:Win32/Bearfoos.A!ml"}]}}}
r = {"infection_suspicion": None, "malware_family": "Unknown"}
rg.apply_deterministic_fallback(r, a3)
check("suspicion None→補完＋フラグ", r["infection_suspicion"] == "HIGH"
      and r["_meta_flags"].get("suspicion_fallback"))
check("family Unknown→Bearfoos.A＋フラグ", "Bearfoos.A" in r["malware_family"]
      and r["_meta_flags"].get("family_fallback"))
snap = (r["infection_suspicion"], r["malware_family"])
rg.apply_deterministic_fallback(r, a3)  # 再適用
check("冪等: 再適用で値・フラグ不変",
      (r["infection_suspicion"], r["malware_family"]) == snap)

# 有効値は上書きしない & フラグ立たない
r2 = {"infection_suspicion": "LOW", "malware_family": "Emotet"}
rg.apply_deterministic_fallback(r2, a3)
check("有効値は非上書き", r2["infection_suspicion"] == "LOW" and r2["malware_family"] == "Emotet")
check("有効値時はフラグ無し", not r2.get("_meta_flags", {}).get("suspicion_fallback"))

# ════════════════════════════════════════════════════════════
sec("移植後: report_gen が来歴フラグから注記を表示する")
# correlate が既に MEDIUM へ補完済み＋フラグ付きの correlation を想定
a_med = {"sections": {"x": {"entries": [{"score": "MEDIUM"}] * 5}}}
corr = {"infection_suspicion": "MEDIUM", "malware_family": "Unknown",
        "_meta_flags": {"suspicion_fallback": True}}
md = rg.generate_report(a_med, corr)
check("補完済み値でも注記（決定論フォールバック）が出る",
      "決定論フォールバック" in md, "注記なし")
check("呼び出し側 correlation は副作用で変化しない（浅いコピー）",
      corr["infection_suspicion"] == "MEDIUM")

# ════════════════════════════════════════════════════════════
sec("実データ統合: T-TL4配線で着信RDPが年表に出る（WIN）")
def real(host, vt=False):
    hd = glob.glob(os.path.join(os.environ["CHECKPC_TEST_EXTRACT"], f"{host}_*"))[0]
    p = json.load(open(glob.glob(f"{hd}/parsed_*.json")[0], encoding="utf-8"))
    a = json.load(open([x for x in glob.glob(f"{hd}/analyzed_*.json") if ("_vt" in x)==vt][0], encoding="utf-8"))
    return p, a
p, a = real("HOST-REF-10")
fnd = tl.extract_findings_from_results(a)
md = tl.build_timeline_markdown(p.get("sections", {}), fnd, p.get("event_logs"))
check("配線出力に着信RDPが含まれる", "着信RDP" in md)
res = tl.build_timeline(p["sections"], fnd, p.get("event_logs"))
shown, supp = tl._filter_events_for_display(res["events"], res.get("suspicious_window"), False)
hm_full = sum(1 for e in res["events"] if e["severity"] in ("HIGH","MEDIUM") or e["suspicious"])
hm_shown = sum(1 for e in shown if e["severity"] in ("HIGH","MEDIUM") or e["suspicious"])
check("抑制後も重要イベントは100%保持", hm_full == hm_shown, f"{hm_full}→{hm_shown}")
check("抑制が実際に効いている（>0件）", supp > 0, f"supp={supp}")

# ════════════════════════════════════════════════════════════
print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
