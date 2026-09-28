# -*- coding: utf-8 -*-
"""test_v368_select_entries.py — v3.68 depth2 選抜・予算配分・保存則の回帰テスト。"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _c in (os.environ.get("CHECKPC_SCRIPTS", ""), HERE,
           os.path.dirname(HERE), "/opt/llm/analysis", "/home/claude/scripts"):
    if _c and os.path.exists(os.path.join(_c, "depth2_select.py")):
        SCRIPTS = _c
        break
else:
    print("depth2_select.py が見つかりません"); sys.exit(2)
sys.path.insert(0, SCRIPTS)

spec = importlib.util.spec_from_file_location("a", f"{SCRIPTS}/analyze_section.py")
a = importlib.util.module_from_spec(spec); sys.modules["a"] = a
sys.modules["analyze_section"] = a; spec.loader.exec_module(a)
import depth2_select as d2
import budget_profile as bp
from provenance import DispositionLedger, PlannedItem

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}"); PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1


def sec(t):
    print(f"\n{'-' * 60}\n  {t}\n{'-' * 60}")


prof = bp.active_profile()


# ════════════════════════════════════════════════════════════
sec("SE-provenance: 保存則（S/D/F 相互排他・網羅）")
led = DispositionLedger(10)
led.add(PlannedItem({}, 0, [0, 1], "selected"))       # 0,1 = selected
led.add(PlannedItem({}, 2, [2], "deterministic", "netstat_private"))
# 集約: 代表3 + メンバー4,5 が deferred
led.add(PlannedItem({}, 3, [3], "selected"))
for i in (4, 5, 6, 7, 8, 9):
    led.add(PlannedItem({}, i, [i], "deferred", "over_global_budget"))
check("SE-1: 保存則 verify() が通る（3分類相互排他・網羅）", led.verify())
check("SE-1b: selected 集合", led.selected == {0, 1, 3})
check("SE-1c: deterministic 集合", led.deterministic == {2})
check("SE-1d: deferred 集合", led.deferred == {4, 5, 6, 7, 8, 9})

sec("SE-provenance2: 二重分類の検出")
led2 = DispositionLedger(3)
led2.add(PlannedItem({}, 0, [0], "selected"))
try:
    led2.add(PlannedItem({}, 0, [0], "deferred", "over_global_budget"))
    check("SE-2: 二重分類で例外", False)
except ValueError:
    check("SE-2: 二重分類を検出して例外", True)

sec("SE-provenance3: 網羅違反の検出")
led3 = DispositionLedger(5)
led3.add(PlannedItem({}, 0, [0], "selected"))
try:
    led3.verify()
    check("SE-3: 網羅違反で例外", False)
except AssertionError:
    check("SE-3: 網羅違反(欠落)を検出", True)

sec("SE-selected_unevaluated: 未評価の追跡")
led4 = DispositionLedger(3)
for i in range(3):
    led4.add(PlannedItem({}, i, [i], "selected"))
led4.mark_unevaluated(2, "coverage_missing")
st = led4.stats()
check("SE-4: selected_unevaluated が数えられる", st["selected_unevaluated"] == 1)
check("SE-4b: selected_coverage_pct < 100", st["selected_coverage_pct"] < 100)

sec("SE-23/24: グローバル予算・mandatory 超過")
ctx = d2.empty_ctx()
ctx["file_basenames"]["defender"].add("evil.exe")
pools = {
    "directory": [(i, {"path": f"C:\\Temp\\f{i}.exe", "name": f"f{i}.exe", "iocs": []})
                  for i in range(500)],
    "netstat": [(i, {"remote": f"{1+i%200}.{2+i%50}.{3}.4:{4000+i}",
                     "state": "ESTABLISHED", "local": "0.0.0.0:1", "iocs": []})
                for i in range(400)],
    "ps_history": [(0, "powershell -enc AAAA FromBase64String"),
                   (1, "Get-ChildItem")],
    "service": [(0, {"identifier": "s0", "name": "evil.exe", "image_path": "C:\\x", "iocs": []})],
}
order = ["directory", "netstat", "ps_history", "service"]
res = d2.plan_depth2_selection(pools, ctx, order)
total = sum(res[s]["plan"]["planned_output_tokens"] for s in order if res[s]["plan"])
check("SE-23: 合計 planned_output_tokens <= 予算",
      total <= prof.d2_output_token_budget, f"{total} > {prof.d2_output_token_budget}")
# mandatory: defender 一致の service, ps_history -enc は必ず選抜
ps_sel = {gi for gi, _ in res["ps_history"]["selected"]}
svc_sel = {gi for gi, _ in res["service"]["selected"]}
check("SE-24: ps_history mandatory(-enc) が選抜される", 0 in ps_sel)
check("SE-24b: service mandatory(defender一致) が選抜される", 0 in svc_sel)

sec("SE-25: 最低代表枠")
# directory は cap 200 だが、予算次第。最低 min(D2_MIN_REP, cap) は確保される想定
check("SE-25: directory floor is fulfilled up to bounded eligible candidates",
      res["directory"]["section_floor_selected"]
      == min(res["directory"]["section_floor_target"], len(res["directory"]["selected"])),
      str(res["directory"]))

sec("SE-26: cap を超えない（mandatory除く）")
check("SE-26: directory <= cap", len(res["directory"]["selected"]) <= prof.section_cap("directory"))

sec("SE-29: 決定論（同一入力・同一予算 → 同一選抜）")
res2 = d2.plan_depth2_selection(pools, ctx, order)
same = all({g for g, _ in res[s]["selected"]} == {g for g, _ in res2[s]["selected"]}
           for s in order)
check("SE-29: 選抜が決定論的", same)

sec("SE-26b: ファイル先頭N件切り出しにならない（末尾も選ばれうる）")
# 全件同スコアだと raw_index 昇順になるが、スコア差があれば末尾が選ばれる
pools_score = {"dns_cache": [
    (i, {"fqdn": ("evil-random-xkjqmz.xyz" if i == 499 else "normal.example.com"),
         "iocs": []}) for i in range(500)]}
res3 = d2.plan_depth2_selection(pools_score, d2.empty_ctx(), ["dns_cache"])
sel_idx = {gi for gi, _ in res3["dns_cache"]["selected"]}
check("SE-26b: 末尾の高スコアエントリ(499)が選抜される（先頭N件切り出しでない）",
      499 in sel_idx, f"selected={sorted(sel_idx)[:5]}...")

sec("SE-27: 同型シグネチャの多様性（sig_max）")
# 同一 /24 に大量 → sig_max=3 で代表化され、全部は選抜されない
pools_sig = {"netstat": [
    (i, {"remote": f"5.5.5.{i}:443", "state": "ESTABLISHED",
         "local": "0.0.0.0:1", "iocs": []}) for i in range(100)]}
res4 = d2.plan_depth2_selection(pools_sig, d2.empty_ctx(), ["netstat"])
check("SE-27: 同一/24の大量接続は sig_max で代表化（全100件は選ばれない）",
      len(res4["netstat"]["selected"]) < 100, str(len(res4["netstat"]["selected"])))

sec("SE-score: mandatory は狭く定義（tier=0）")
ctx0 = d2.empty_ctx()
# 外部IP+非標準ポートだけでは mandatory でない（tier1）
t, s, tbk = d2.section_selection_score(
    "netstat", {"remote": "1.2.3.4:8080", "state": "ESTABLISHED", "iocs": []}, ctx0)
check("SE-score: 外部IP+非標準ポートだけは mandatory でない（tier=1）", t == 1)
# ps -enc は mandatory
t2, _, _ = d2.section_selection_score("ps_history", "powershell -enc AAAA", ctx0)
check("SE-score: ps -enc は mandatory（tier=0）", t2 == 0)


print(f"\n{'=' * 60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS + FAIL}")
print(f"{'=' * 60}")
print(f"PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
