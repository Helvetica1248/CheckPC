# -*- coding: utf-8 -*-
"""test_v368_correlate_order.py — v3.68 correlate 決定論・予算・HIGH表現の回帰テスト。"""
import hashlib
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _c in (os.environ.get("CHECKPC_SCRIPTS", ""), HERE,
           os.path.dirname(HERE), "/opt/llm/analysis", "/home/claude/scripts"):
    if _c and os.path.exists(os.path.join(_c, "correlate.py")):
        SCRIPTS = _c
        break
else:
    print("correlate.py が見つかりません"); sys.exit(2)
sys.path.insert(0, SCRIPTS)

spec = importlib.util.spec_from_file_location("a", f"{SCRIPTS}/analyze_section.py")
a = importlib.util.module_from_spec(spec); sys.modules["a"] = a
sys.modules["analyze_section"] = a; spec.loader.exec_module(a)
spec2 = importlib.util.spec_from_file_location("c", f"{SCRIPTS}/correlate.py")
c = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(c)

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}"); PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1


def sec(t):
    print(f"\n{'-' * 60}\n  {t}\n{'-' * 60}")


def mk(order, n_high=1, n_med=1):
    secs = {}
    for s in order:
        ents = []
        for i in range(n_high):
            ents.append({"score": "HIGH", "identifier": f"{s}-h{i}",
                         "reason": "悪性の疑い", "iocs": [f"1.2.3.{i}"]})
        for i in range(n_med):
            ents.append({"score": "MEDIUM", "identifier": f"{s}-m{i}",
                         "reason": "要確認", "iocs": []})
        secs[s] = {"entries": ents, "section_summary": f"{s} サマリ"}
    return {"sections": secs, "meta": {"hostname": "T"}}


order = ["directory", "netstat", "ps_history", "dns_cache"]

# ════════════════════════════════════════════════════════════
sec("CO-1: sections 挿入順を変えても入力テキストが同一")
f1 = c.extract_high_medium(mk(order))
f2 = c.extract_high_medium(mk(list(reversed(order))))
t1, s1 = c.build_correlate_text(f1, 2, 13000)
t2, s2 = c.build_correlate_text(f2, 2, 13000)
h1 = hashlib.sha256(t1.encode()).hexdigest()
h2 = hashlib.sha256(t2.encode()).hexdigest()
check("CO-1: 挿入順非依存（SHA-256 一致）", h1 == h2, f"{h1[:8]} vs {h2[:8]}")

sec("CO-2/3b/3c: 3回実行で入力・統計・source集合が一致")
runs = [c.build_correlate_text(c.extract_high_medium(mk(order)), 2, 13000)
        for _ in range(3)]
hashes = [hashlib.sha256(t.encode()).hexdigest() for t, _ in runs]
check("CO-3b: 入力テキスト SHA-256 が3回一致", len(set(hashes)) == 1)
stats_json = [str(sorted(st.items())) for _, st in runs]
check("CO-3c: 統計が3回一致", len(set(stats_json)) == 1)

sec("CO-5: 12000文字の単純切断が存在しない")
# 大量 HIGH でも「...(省略)」による char 切断ではなく token 予算で縮退
big = mk(order, n_high=50, n_med=50)
t, st = c.build_correlate_text(c.extract_high_medium(big), 2, 2000)
check("CO-5: 旧 12000文字切断マーカーがない", "...(省略)" not in t)

sec("CO-9/20: どの compression_level でも high_unrepresented == 0")
for budget in (100000, 5000, 2000, 500, 100, 50):
    t, st = c.build_correlate_text(c.extract_high_medium(big), 2, budget)
    check(f"CO-9: budget={budget} で high_unrepresented==0 (level={st['compression_level']})",
          st["high_unrepresented"] == 0, str(st))

sec("CO-19: HIGH 表現の4指標が整合")
t, st = c.build_correlate_text(c.extract_high_medium(big), 2, 500)
check("CO-19: individual + aggregated + unrepresented == source_total",
      st["high_individual_included"] + st["high_aggregated_source_count"]
      + st["high_unrepresented"] == st["high_source_total"], str(st))

sec("CO-7/8: 予算縮小で compression_level が上がる")
_, st_big = c.build_correlate_text(c.extract_high_medium(big), 2, 100000)
_, st_small = c.build_correlate_text(c.extract_high_medium(big), 2, 200)
check("CO-7: 予算を絞ると compression_level が上がる",
      st_small["compression_level"] >= st_big["compression_level"],
      f"{st_big['compression_level']} -> {st_small['compression_level']}")

sec("CO-15/17: 統計整合")
t, st = c.build_correlate_text(c.extract_high_medium(mk(order)), 2, 13000)
check("CO-15: included + omitted == input_total",
      st["included"] + st["omitted"] == st["input_total"], str(st))
check("CO-17: used_tokens <= budget_tokens",
      st["used_tokens"] <= st["budget_tokens"], str(st))

sec("CO-18: HIGH/MEDIUM 0件はスキップ（NONE返却）")
empty = {"sections": {"x": {"entries": [{"score": "CLEAN", "identifier": "a"}]}},
         "meta": {"hostname": "T"}}
f = c.extract_high_medium(empty)
check("CO-18: CLEAN のみは filtered が空", f == {})

sec("CO-16: correlate() が _correlate_input を記録（スキップ経路）")
r = c.correlate({"sections": {}, "meta": {"hostname": "T"}}, 2, None, "m")
check("CO-16: スキップ時も _correlate_input を持つ", "_correlate_input" in r)


print(f"\n{'=' * 60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS + FAIL}")
print(f"{'=' * 60}")
print(f"PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
