# -*- coding: utf-8 -*-
"""timeline.py TL-A〜TL-E 修正の回帰テスト。

合成データ＋実データ（提供アーカイブ）で各修正を検証する。
test_pipeline.py と同じ軽量 check() 方式。
"""
import os
import sys, glob, json, importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = Path(os.environ.get("CHECKPC_SCRIPTS", str(HERE))).expanduser().resolve()
REALDATA_ROOT = Path(os.environ["CHECKPC_TEST_EXTRACT"]).expanduser().resolve()
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("timeline", str(SCRIPTS / "timeline.py"))
tl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tl)

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}"); PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1

def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

# ════════════════════════════════════════════════════════════
sec("TL-B: 時刻フォーマット（スラッシュ・ダブルスペース・秒なし）")
cases = {
    "2026/06/25  22:38":    True,   # スラッシュ＋ダブルスペース＋秒なし（prefetch実形式）
    "2026/06/25 22:38:01":  True,   # スラッシュ＋秒あり
    "2020/10/18  09:10":    True,   # defender directory_scan 実形式
    "2026-06-25 22:38:01":  True,   # 従来ダッシュ形式（回帰）
    "2022-12-29T13:39:08.353": True,# ISO＋ミリ秒（着信RDP実形式）
    "2026-06-25 22:38":     True,   # ダッシュ＋秒なし
    "":                     False,
    "not a date":           False,
}
for s, ok in cases.items():
    got = tl._parse_ts(s) is not None
    check(f"_parse_ts({s!r}) → {'解析可' if ok else '解析不可'}", got == ok,
          f"got={got}")

# ════════════════════════════════════════════════════════════
sec("TL-C: findings ガード（汎用トークン除外・固有所見保持）")
generic = ["0.0.0.0", "3389", "127.0.0.1", "C:\\Program", "c:\\windows",
           "0.0.0.0:3389", "[::]:8020", "623"]
for g in generic:
    check(f"汎用 {g!r} は除外", tl._is_generic_finding(g))
specific = ["rustdesk.exe", "mimikatz.exe", "evil.example.com",
            "C:\\Users\\u\\AppData\\Local\\Temp\\x.exe", "Ollama.lnk"]
for s in specific:
    check(f"固有 {s!r} は保持", not tl._is_generic_finding(s))

# _normalize_findings がガードを通すこと
norm = tl._normalize_findings(["0.0.0.0", "C:\\Program", "rustdesk.exe", "3389"])
check("_normalize_findings: 汚染除去後 rustdesk.exe のみ残る",
      norm == ["rustdesk.exe"], str(norm))

# 完全パス抽出（空白を含むパスが切れないこと）
fake = {"sections": {"directory": {"entries": [
    {"score": "HIGH", "identifier": "C:\\Program Files\\Evil App\\bad.exe",
     "iocs": []}]}}}
fnd = tl.extract_findings_from_results(fake)
check("空白入り完全パスが切れずに抽出される",
      any("bad.exe" in f.lower() for f in fnd), str(fnd))
check("切れ端 'C:\\Program' 単体は突合キーに残らない",
      "c:\\program" not in tl._normalize_findings(fnd), str(tl._normalize_findings(fnd)))

# ════════════════════════════════════════════════════════════
sec("TL-D: BITS ジョブ名（display キー）／TL-E: run_count 表示")
bits_cfg = tl.EVENT_SOURCES["bits_jobs"]
e_bits = {"creation_time": "2026-06-20 14:00:00", "display": "WindowsUpdater",
          "url": "http://evil.test/x.dll", "local_file": "C:\\Temp\\x.dll"}
s = bits_cfg["fmt"](e_bits)
check("BITS: display が表示される", "WindowsUpdater" in s, s)
check("BITS: URL/保存先が併記される", "evil.test" in s, s)
e_bits_noname = {"creation_time": "2026-06-20 14:00:00"}
check("BITS: 名前なしでも (無名) で落ちない",
      "(無名)" in bits_cfg["fmt"](e_bits_noname))

ua_cfg = tl.EVENT_SOURCES["userassist"]
check("UA: run_count=0 は回数非表示",
      "回" not in ua_cfg["fmt"]({"last_run": "x", "path": "a.exe", "run_count": "0"}))
check("UA: run_count=5 は (実行5回) 表示",
      "実行5回" in ua_cfg["fmt"]({"last_run": "x", "path": "a.exe", "run_count": "5"}))
check("UA: 旧 (x0) 形式が出ない",
      "(x0)" not in ua_cfg["fmt"]({"last_run": "x", "path": "a.exe", "run_count": "0"}))

# ════════════════════════════════════════════════════════════
sec("TL-A: event_logs マージ（実データ）")
base = str(REALDATA_ROOT)
def real(host):
    hd = glob.glob(f"{base}/{host}_*")[0]
    parsed = json.load(open(glob.glob(f"{hd}/parsed_*.json")[0], encoding="utf-8"))
    an = [x for x in glob.glob(f"{hd}/analyzed_*.json") if "_vt" not in x][0]
    analyzed = json.load(open(an, encoding="utf-8"))
    return parsed, analyzed

# HOST-REF-10: 着信RDP（event_logs配下）が年表に出ること
p, a = real("HOST-REF-10")
fnd = tl.extract_findings_from_results(a)
res_new = tl.build_timeline(p["sections"], fnd, p.get("event_logs"))
res_old = tl.build_timeline(p["sections"], fnd)  # event_logs を渡さない＝旧挙動
srcs_new = res_new["sources"]; srcs_old = res_old["sources"]
check("TL-A: 旧挙動では rdp_inbound が0件（再現）",
      "rdp_inbound" not in srcs_old, str(srcs_old))
check("TL-A: 新挙動で rdp_inbound が取得される",
      srcs_new.get("rdp_inbound", 0) >= 1, str(srcs_new))
check("TL-A: 新挙動で system_7045 が取得される",
      srcs_new.get("system_7045", 0) >= 1, str(srcs_new))
# 着信RDPイベントが横展開/初期侵入フェーズで存在
rdp_evs = [e for e in res_new["events"] if e["section"] == "rdp_inbound"]
check("TL-A: 着信RDPが横展開/初期侵入フェーズで年表化",
      rdp_evs and all(e["phase"] == "横展開/初期侵入" for e in rdp_evs),
      f"{len(rdp_evs)}件")

# HOST-REF-02（クリーン）: TL-B 効果で prefetch が除外されないこと
p2, a2 = real("HOST-REF-02")
res2 = tl.build_timeline(p2["sections"],
                         tl.extract_findings_from_results(a2),
                         p2.get("event_logs"))
check("TL-B: prefetch が時刻解析できて取得される",
      res2["sources"].get("prefetch", 0) >= 1, str(res2["sources"]))
check("TL-A+B: 除外件数が旧208件から大幅減（<50）",
      res2["skipped"] < 50, f"skipped={res2['skipped']}")

# ════════════════════════════════════════════════════════════
print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
