# -*- coding: utf-8 -*-
"""v3.65 の回帰テスト。

対象:
  · 提案8: 可視性フロア — dns_cache の CLEAN 禁止（最低LOW）/
    netstat LISTENING の CLEAN 禁止（最低LOW）。confabulation
    （根拠を創作した無害断定。第3回A/Bの online.autotranshub.com で実観測）
    による可視性喪失の決定論防止
  · 提案7: compare_analyzed.py のエントリ単位裁定枠組み
    （突合・遷移マトリクス・降格/昇格リスト・HIGH→LOW/CLEAN 自動不合格）
"""
import sys, os, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
for _c in (os.environ.get("CHECKPC_SCRIPTS", ""), HERE,
           os.path.dirname(HERE), "/home/claude/scripts"):
    if _c and os.path.exists(os.path.join(_c, "analyze_section.py")):
        SCRIPTS = _c
        break
else:
    print("analyze_section.py が見つかりません"); sys.exit(2)
sys.path.insert(0, SCRIPTS)
def _mod(name):
    spec = importlib.util.spec_from_file_location(name, f"{SCRIPTS}/{name}.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
a  = _mod("analyze_section")
ca = _mod("compare_analyzed")

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: print(f"  [OK]  {name}"); PASS += 1
    else: print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1
def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

def one(section, score, ident, reason="一般的なサービスドメイン"):
    r = {"entries": [{"identifier": ident, "score": score,
                      "reason": reason, "iocs": [ident], "mitre": []}]}
    a._apply_post_filter(section, r)
    return r["entries"][0]

# ════════════════════════════════════════════════════════════
sec("V8-1: dns_cache 可視性フロア（CLEAN禁止・最低LOW）")
e = one("dns_cache", "CLEAN", "online.autotranshub.com")
check("V8-1: confabulation型CLEAN → LOW（実観測ケースの再現防止）",
      e["score"] == "LOW", str(e))
check("V8-1: [フロア]注記＋元reasonを保持",
      "[フロア]" in e["reason"] and e["reason"].startswith("一般的なサービスドメイン"),
      e["reason"])
check("V8-1: 監査用 _floor=dns_visibility", e.get("_floor") == "dns_visibility")
check("V8-1: MEDIUM は不変", one("dns_cache", "MEDIUM", "x.test")["score"] == "MEDIUM")
check("V8-1: LOW は不変（注記も付かない）",
      "[フロア]" not in one("dns_cache", "LOW", "y.test")["reason"])
check("V8-1: HIGH は不変", one("dns_cache", "HIGH", "c2.evil")["score"] == "HIGH")
r = {"entries": [{"identifier": "z.test", "score": "CLEAN", "reason": "r", "iocs": []}]}
a._apply_post_filter("dns_cache", r); a._apply_post_filter("dns_cache", r)
check("V8-1: 冪等（注記は1回のみ）", r["entries"][0]["reason"].count("[フロア]") == 1)

# ════════════════════════════════════════════════════════════
sec("V8-2: netstat LISTENING 可視性フロア")
check("V8-2: 待受CLEAN → LOW（0.0.0.0:0宛）",
      one("netstat", "CLEAN", "0.0.0.0:30193 → 0.0.0.0:0",
          "AVCore.exe が使用")["score"] == "LOW")
check("V8-2: 待受CLEAN → LOW（[::]:0宛）",
      one("netstat", "CLEAN", "[::]:7680 → [::]:0")["score"] == "LOW")
check("V8-2: 外向き接続の CLEAN は不変（ルールベースCLEAN固定と整合）",
      one("netstat", "CLEAN", "192.168.11.9:49758 → 3.173.238.60:443")["score"] == "CLEAN")
check("V8-2: 待受の LOW は不変（T-29 LOW固定と整合）",
      "[フロア]" not in one("netstat", "LOW", "0.0.0.0:60000 → 0.0.0.0:0")["reason"])
check("V8-2: 待受の MEDIUM/HIGH は不変",
      one("netstat", "MEDIUM", "0.0.0.0:22331 → 0.0.0.0:0")["score"] == "MEDIUM"
      and one("netstat", "HIGH", "0.0.0.0:4444 → 0.0.0.0:0")["score"] == "HIGH")
check("V8-2: 監査用 _floor=netstat_listen_visibility",
      one("netstat", "CLEAN", "0.0.0.0:8080 → 0.0.0.0:0").get("_floor")
      == "netstat_listen_visibility")

# ════════════════════════════════════════════════════════════
sec("V7: compare_analyzed エントリ単位裁定枠組み")
def doc(entries_by_sec):
    return {"sections": {s_: {"entries": es} for s_, es in entries_by_sec.items()}}
def ent(ident, score, reason="r"):
    return {"identifier": ident, "score": score, "reason": reason, "iocs": []}

A = doc({"x": [ent("a", "HIGH"), ent("b", "MEDIUM"), ent("c", "LOW"),
               ent("d", "CLEAN"), ent("dup", "LOW"), ent("dup", "MEDIUM"),
               ent("⚠ 可視化", "MEDIUM")],
         "y": [ent("e", "HIGH")]})
B = doc({"x": [ent("a", "MEDIUM"), ent("b", "MEDIUM"), ent("c", "CLEAN"),
               ent("d", "CLEAN"), ent("dup", "MEDIUM"),
               ent("⚠ 可視化", "MEDIUM")],
         "y": [ent("e", "CLEAN"), ent("new", "LOW")]})
# ════════════════════════════════════════════════════════════
sec("V7: compare_analyzed マルチセット比較（v3.68 / C12・D-3）")
def doc(entries_by_sec, chunk_errors=None):
    secs = {}
    for s_, es in entries_by_sec.items():
        sr = {"entries": es}
        if chunk_errors and s_ in chunk_errors:
            sr["_chunk_errors"] = chunk_errors[s_]
        secs[s_] = sr
    return {"sections": secs, "meta": {}}
def ent(ident, score, reason="r"):
    return {"identifier": ident, "score": score, "reason": reason, "iocs": []}

A = doc({"x": [ent("a", "HIGH"), ent("b", "MEDIUM"), ent("c", "LOW"),
               ent("d", "CLEAN"), ent("dup", "LOW"), ent("dup", "MEDIUM"),
               ent("⚠ 可視化", "MEDIUM")],
         "y": [ent("e", "HIGH")]})
B = doc({"x": [ent("a", "MEDIUM"), ent("b", "MEDIUM"), ent("c", "CLEAN"),
               ent("d", "CLEAN"), ent("dup", "MEDIUM"),
               ent("⚠ 可視化", "MEDIUM")],
         "y": [ent("e", "CLEAN"), ent("new", "LOW")]})

# ⚠エントリ除外
ms_a, _ = ca.entry_multiset(A)
check("V7: entry_multiset が ⚠エントリを除外する",
      not any("⚠" in k[1] for k in ms_a))
# 重複 identifier を畳まない（マルチセット）
check("V7: 同一 identifier の複数イベントを畳まない（dup が2件）",
      sum(ms_a[k].total() for k in ms_a if k[1] == "dup") == 2,
      str([(k, dict(ms_a[k])) for k in ms_a if k[1] == "dup"]))

# 通常比較: HIGH→CLEAN(e) は自動不合格 → 終了コード1
fatal, adjud, matrix = ca.compare(A, B, strict=False)
tags = [f[0] for f in fatal]
check("V7: HIGH→LOW/CLEAN を自動不合格に検出（e）",
      any("HIGH→LOW/CLEAN" in t for t in tags), str(tags))
check("V7: HIGH→MEDIUM(a) は通常比較で要裁定（自動不合格でない）",
      any("HIGH->MEDIUM" in x[0] for x in adjud)
      and not any("HIGH->MEDIUM" in t for t in tags), str(adjud))

# strict-regression: HIGH→MEDIUM も不合格
fatal_s, adjud_s, _ = ca.compare(A, B, strict=True)
check("V7: strict では HIGH→MEDIUM(a) も自動不合格",
      any("HIGH->MEDIUM" in f[0] for f in fatal_s), str([f[0] for f in fatal_s]))

# tot_b 修正: B のみに存在するセクションも合計される
A_t = {"sections": {"x": {"entries": [ent("a", "LOW")],
                          "_chunk_timings": [{"elapsed_sec": 10.0}]}}, "meta": {}}
B_t = {"sections": {"x": {"entries": [ent("a", "LOW")],
                          "_chunk_timings": [{"elapsed_sec": 5.0}]},
                    "z": {"entries": [ent("q", "LOW")],
                          "_chunk_timings": [{"elapsed_sec": 7.0}]}}, "meta": {}}
tb = ca.timings(B_t)
check("V7: timings が B のみのセクション(z)も含む（tot_b=sum(values)修正）",
      sum(tb.values()) == 12.0, str(tb))

# chunk_errors / 未評価 の自動不合格化（間接: compare は fatal に加える）
A_e = doc({"x": [ent("a", "LOW")]})
B_e = doc({"x": [ent("a", "LOW")]},
          chunk_errors={"x": [{"selected_unevaluated": True, "n_entries": 3,
                               "n_salvaged": 0}]})
check("V7: n_unevaluated が B の未評価を数える",
      ca.n_unevaluated(B_e) == 3, str(ca.n_unevaluated(B_e)))
check("V7: n_chunk_errors が B の chunk_errors を数える",
      ca.n_chunk_errors(B_e) == 1, str(ca.n_chunk_errors(B_e)))

print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
