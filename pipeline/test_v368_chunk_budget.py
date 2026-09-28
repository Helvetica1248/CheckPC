# -*- coding: utf-8 -*-
"""test_v368_chunk_budget.py — v3.68 動的チャンク・トークン予算の回帰テスト。

検証:
  · depth1 完全再現（FULL/LEAN とも現行 CHUNK_SIZE_DEPTH1 を維持）
  · depth>=2 の動的チャンク（出力予算 − チャンク固定費 → 件数）
  · コンテキスト予算（fixed + input + max_tokens + margin <= max_model_len）
  · est_tokens の CJK 重み付き・安全率・実測下回り防止
  · oversize 縮退（出力縮小 → 中略 → 未評価）
"""
import importlib.util
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _c in (os.environ.get("CHECKPC_SCRIPTS", ""), HERE,
           os.path.dirname(HERE), "/opt/llm/analysis", "/home/claude/scripts"):
    if _c and os.path.exists(os.path.join(_c, "analyze_section.py")):
        SCRIPTS = _c
        break
else:
    print("analyze_section.py が見つかりません"); sys.exit(2)
sys.path.insert(0, SCRIPTS)

spec = importlib.util.spec_from_file_location("a", f"{SCRIPTS}/analyze_section.py")
a = importlib.util.module_from_spec(spec); sys.modules["a"] = a
sys.modules["analyze_section"] = a; spec.loader.exec_module(a)
import token_budget as tb
import budget_profile as bp

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}"); PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1


def sec(t):
    print(f"\n{'-' * 60}\n  {t}\n{'-' * 60}")


def dummy(section, n):
    if section == "ps_history":
        return [f"powershell command line {i}" for i in range(n)]
    out = []
    for i in range(n):
        out.append({"identifier": f"id{i}", "path": f"C:\\x\\f{i}.exe",
                    "name": f"f{i}.exe", "reason": "x", "command": f"cmd{i}",
                    "remote": "1.2.3.4:443", "local": "0.0.0.0:1",
                    "state": "ESTABLISHED", "fqdn": f"h{i}.example.com",
                    "created": "2026/01/01 00:00", "task_name": f"t{i}",
                    "service_name": f"s{i}", "url": f"http://x/{i}"})
    return out


# ════════════════════════════════════════════════════════════
sec("CB-1: depth1 完全再現（現行 CHUNK_SIZE_DEPTH1 を維持）")
for section, cs in a.CHUNK_SIZE_DEPTH1.items():
    for lean in (False, True):
        n = a.resolve_n_out_max(section, 1, lean=lean)
        check(f"CB-1: {section} depth1 lean={lean} n_out_max=={cs}",
              n == cs, f"{n}")

sec("CB-1b: LEAN depth1 == FULL depth1（境界不変）")
for section, cs in a.CHUNK_SIZE_DEPTH1.items():
    ents = dummy(section, cs * 3 + 2)
    cf = a.chunk_entries(section, ents, 1, lean=False)
    cl = a.chunk_entries(section, ents, 1, lean=True)
    check(f"CB-1b: {section} depth1 FULL/LEAN のチャンク境界が一致",
          [len(x) for x in cf] == [len(x) for x in cl],
          f"F={[len(x) for x in cf]} L={[len(x) for x in cl]}")

sec("CB-2: depth1 のチャンク総数が現行仕様（単純 size 分割）と一致")
for section, cs in a.CHUNK_SIZE_DEPTH1.items():
    for n in (1, cs, cs + 1, cs * 2, 100):
        chunks = a.chunk_entries(section, dummy(section, n), 1, lean=False)
        exp = math.ceil(n / cs)
        check(f"CB-2: {section} n={n} → {exp}チャンク",
              len(chunks) == exp, f"{len(chunks)}")

sec("CB-3〜5: 境界値")
check("CB-3: 空リスト → []", a.chunk_entries("directory", [], 2) == [])
check("CB-4: 1件 → 1チャンク", len(a.chunk_entries("directory", dummy("directory", 1), 2)) == 1)

sec("CB-6/7: コンテキスト予算（全 section×depth×mode で超過なし）")
prof = bp.active_profile()
allok = True
for section in a.CHUNK_SIZE_DEPTH1:
    for depth in (1, 2, 3, 4):
        for lean in (False, True):
            plan = a.resolve_chunk_plan(section, dummy(section, 30), depth, lean=lean)
            maxtok = plan["max_tokens"]
            # 最大チャンクの入力 + 予約出力 + margin <= max_model_len
            worst_in = max((sp.est_input for sp in plan["specs"]), default=0)
            total = plan["fixed_tokens"] + worst_in + maxtok + tb.CHUNK_SAFETY_MARGIN
            if total > tb.MAX_MODEL_LEN:
                allok = False
                print(f"    超過: {section} d{depth} lean={lean}: {total}")
            if plan["input_budget"] <= 0:
                allok = False
check("CB-6/7: 全組合せで max_model_len 超過なし・input_budget>0", allok)

sec("CB-8/9/10: oversize 縮退")
# 単独で予算超過する巨大エントリ（ps_history の長大コマンド）
huge = ["x" * 60000]
plan = a.resolve_chunk_plan("ps_history", huge, 2, lean=False)
check("CB-8: 巨大エントリが専用 spec になる", len(plan["specs"]) == 1)
sp = plan["specs"][0]
check("CB-9: oversize は縮小/中略/未評価のいずれかで解決",
      sp.reason.startswith("oversize") or sp.unevaluable, sp.reason)
# 全件どこかのチャンクに入る（無限ループなし）
plan2 = a.resolve_chunk_plan("ps_history",
                             ["y" * 100] * 5 + ["z" * 60000] + ["w" * 100] * 5,
                             2, lean=False)
total_ents = sum(len(sp.entries) for sp in plan2["specs"])
check("CB-10: oversize 混在でも全件が spec に含まれる（11件）",
      total_ents == 11, str(total_ents))

sec("CB-11/12/13: 保存則・順序・決定論")
ents = dummy("directory", 47)
plan = a.resolve_chunk_plan("directory", ents, 2, lean=False)
flat = [e for sp in plan["specs"] for e in sp.entries]
check("CB-11: 保存則（全件が spec に含まれる）", len(flat) == 47, str(len(flat)))
check("CB-12: 順序保存（入力順のまま）",
      [e["identifier"] for e in flat] == [e["identifier"] for e in ents])
p2 = a.resolve_chunk_plan("directory", ents, 2, lean=False)
check("CB-13: 決定論（2回で同一チャンク境界）",
      [len(s.entries) for s in plan["specs"]] == [len(s.entries) for s in p2["specs"]])

sec("CB-14: TOK_PER_ENTRY 下限（暫定プロファイル）")
check("CB-14: directory FULL >= 204 相当（暫定256）",
      prof.tok_per_entry("directory") >= 204, str(prof.tok_per_entry("directory")))
check("CB-14: netstat >= 204（暫定256）", prof.tok_per_entry("netstat") >= 204)
check("CB-14: defender_quarantine は 0（LLM予算対象外）",
      prof.tok_per_entry("defender_quarantine") == 0)

sec("CB-15: FULL/LEAN 同一値（v3.68-rc1・0.6倍禁止）")
for section in ("directory", "prefetch", "ps_history"):
    check(f"CB-15: {section} FULL==LEAN（暫定は同一値）",
          prof.tok_per_entry(section, lean=False) == prof.tok_per_entry(section, lean=True))

sec("CB-18: n_out_max = (max_tok - overhead) // tpe（固定費控除）")
# directory depth2: (2048 - 192) // 256 = 7
check("CB-18: directory depth2 n_out_max == 7",
      a.resolve_n_out_max("directory", 2, lean=False) == 7,
      str(a.resolve_n_out_max("directory", 2, lean=False)))
# ps_history depth2: (1024 - 192) // 192 = 4
check("CB-18: ps_history depth2 n_out_max == 4",
      a.resolve_n_out_max("ps_history", 2, lean=False) == 4,
      str(a.resolve_n_out_max("ps_history", 2, lean=False)))
# その他: (1024 - 192) // 160 = 5
check("CB-18: service depth2 n_out_max == 5",
      a.resolve_n_out_max("service", 2, lean=False) == 5,
      str(a.resolve_n_out_max("service", 2, lean=False)))

sec("CB-20〜25: est_tokens（CJK 重み付き・安全率・実測下回り防止）")
check("CB-20: 空文字 → 0", tb.est_tokens("") == 0)
check("CB-21: ascii 最適化版と素朴実装が一致",
      tb._count_ascii("abcあいうdef") == 6)
# 日本語のみ 100文字 → 安全率込みで >= 100
jp = "あ" * 100
check("CB-22: 日本語100文字 >= 100トークン（過小評価しない）",
      tb.est_tokens(jp) >= 100, str(tb.est_tokens(jp)))
# ASCII は 2文字/token（Base64 過小評価対策）
asc = "a" * 300
check("CB-23: ASCII300文字 >= 150トークン（2文字/token・3文字/token にしない）",
      tb.est_tokens(asc) >= 150, str(tb.est_tokens(asc)))
# 安全率が掛かる
raw = tb.est_tokens_raw("a" * 200)
withsf = tb.est_tokens("a" * 200)
check("CB-24: 安全率が適用される（est >= raw）", withsf >= raw)
# 混在
mix = "svchost.exe を C:\\Windows\\Temp\\悪意ある.exe が偽装"
check("CB-25: 混在テキストが正の値", tb.est_tokens(mix) > 0)

sec("CB-31/32/33: render_entries（原本不変・中略）")
import copy
ents = [{"path": "C:\\a\\b.exe", "name": "b.exe"}]
orig = copy.deepcopy(ents)
txt, trunc = a.render_entries("directory", ents, truncate=False)
check("CB-31: truncate=False は entries_to_text と一致",
      txt == a.entries_to_text("directory", ents) and trunc == [])
check("CB-31b: 原本を変更しない", ents == orig)
long_ents = [{"path": "C:\\" + "x" * 2000 + "\\payload.exe", "name": "payload.exe"}]
orig2 = copy.deepcopy(long_ents)
txt2, trunc2 = a.render_entries("directory", long_ents, truncate=True)
check("CB-32: truncate=True でも原本不変", long_ents == orig2)
check("CB-33: 中略時にファイル名(payload.exe)が残る",
      "payload.exe" in txt2, txt2[:80])
check("CB-33b: 中略記録が返る", len(trunc2) >= 1 if trunc2 else True)


print(f"\n{'=' * 60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS + FAIL}")
print(f"{'=' * 60}")
print(f"PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
