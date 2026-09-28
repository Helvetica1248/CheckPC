# -*- coding: utf-8 -*-
"""[2] VT必須条件付き HIGH→MEDIUM 降格（提案A）の回帰テスト。

方針:
  · 既知ベンダ per-user/Temp サービス・Office アドインの HIGH を、
    VT実行済み かつ malicious でない場合のみ MEDIUM 降格。
  · VT malicious / VT未照合 / allowlist非該当 は HIGH 維持（取りこぼし防止）。
  · VT-clean を積極証拠にせず、malicious を降格拒否ゲートにのみ使用。
"""
import os
import sys, importlib.util

for _c in (os.environ.get("CHECKPC_SCRIPTS", ""), os.path.dirname(os.path.abspath(__file__)),
           os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
           "/opt/llm/analysis", "/home/claude/scripts"):
    if _c and os.path.exists(os.path.join(_c, "analyze_section.py")):
        SCRIPTS = _c
        break
else:
    print("analyze_section.py が見つかりません"); sys.exit(2)
sys.path.insert(0, SCRIPTS)
spec = importlib.util.spec_from_file_location("vt_post", f"{SCRIPTS}/vt_post.py")
vt = importlib.util.module_from_spec(spec); spec.loader.exec_module(vt)

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: print(f"  [OK]  {name}"); PASS += 1
    else: print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1
def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

def build(section, ident, ioc, vt_verdict=None, score="HIGH"):
    e = {"identifier": ident, "score": score, "iocs": [ioc], "reason": "orig"}
    if vt_verdict is not None:
        e["_vt_results"] = [{"verdict": vt_verdict, "ioc": ioc}]
    return {"sections": {section: {"entries": [e]}}}

def run(section, ident, ioc, vt_verdict=None, score="HIGH"):
    r = build(section, ident, ioc, vt_verdict, score)
    n = vt.apply_peruser_high_downgrade(r)
    return r["sections"][section]["entries"][0]["score"], n

# ════════════════════════════════════════════════════════════
sec("降格される（allowlist一致 かつ VT-not-malicious かつ VT照合済み）")
s, _ = run("system_7045", "HWiNFO Kernel Driver",
           r"C:\Users\u\AppData\Local\Temp\HWiNFO_x64_206.sys", "clean")
check("HWiNFO(Temp) + VTクリーン → MEDIUM", s == "MEDIUM")
s, _ = run("system_7045", "BaiduNetdiskUtility",
           r"C:\Users\u\AppData\Roaming\baidu\BaiduNetdisk\YunUtilityService.exe", "unknown")
check("Baidu(AppData) + VT未登録 → MEDIUM", s == "MEDIUM")
s, _ = run("system_7045", "WsNativePush",
           r"C:\Users\u\AppData\Local\Wondershare\WsNativePushService.exe", "clean")
check("Wondershare(AppData) + VTクリーン → MEDIUM", s == "MEDIUM")
s, _ = run("startup_folder", r"...\Word\STARTUP\Zotero.dotm",
           r"C:\Users\u\AppData\Roaming\Microsoft\Word\STARTUP\Zotero.dotm", "clean")
check("Zotero(office_startup) + VTクリーン → MEDIUM", s == "MEDIUM")

# ════════════════════════════════════════════════════════════
sec("降格しない（取りこぼし防止のゲート）")
s, _ = run("system_7045", "HWiNFO Kernel Driver",
           r"C:\Users\u\AppData\Local\Temp\HWiNFO_x64_206.sys", "malicious")
check("VT malicious → HIGH維持（HWiNFO BYOVD 等の実害を取りこぼさない）", s == "HIGH")
s, _ = run("system_7045", "BaiduNetdiskUtility",
           r"C:\Users\u\AppData\Roaming\baidu\x.exe", None)   # _vt_results なし
check("VT未照合(_vt_results無し) → HIGH維持", s == "HIGH")
s, _ = run("system_7045", "EvilSvc",
           r"C:\Users\u\AppData\Roaming\Evil\backdoor.exe", "clean")
check("allowlist非該当の未知ベンダ → HIGH維持", s == "HIGH")
s, _ = run("startup_folder", r"...\Word\STARTUP\evil.dotm",
           r"C:\Users\u\AppData\Roaming\Microsoft\Word\STARTUP\evil.dotm", "clean")
check("office_startupだが未知アドイン → HIGH維持", s == "HIGH")

# ════════════════════════════════════════════════════════════
sec("スコープ・境界")
# 降格幅は MEDIUM 止まり（CLEAN/LOW まで落とさない）
s, _ = run("system_7045", "HWiNFO Kernel Driver",
           r"C:\Users\u\AppData\Local\Temp\HWiNFO_x64_206.sys", "clean")
check("降格幅は MEDIUM 止まり（LOW/CLEANにしない）", s == "MEDIUM")
# HIGH以外は対象外（MEDIUMを触らない）
s, _ = run("system_7045", "HWiNFO Kernel Driver",
           r"C:\Users\u\AppData\Local\Temp\HWiNFO_x64_206.sys", "clean", score="MEDIUM")
check("元がMEDIUMなら変更しない", s == "MEDIUM")
# 対象外セクションは触らない
r = {"sections": {"service": {"entries": [
    {"identifier": "x", "score": "HIGH", "iocs": [r"C:\Users\u\AppData\Roaming\baidu\x.exe"],
     "_vt_results": [{"verdict": "clean"}]}]}}}
vt.apply_peruser_high_downgrade(r)
check("対象外セクション(service)は降格対象にしない",
      r["sections"]["service"]["entries"][0]["score"] == "HIGH")
# 件数の戻り値
r = build("system_7045", "HWiNFO", r"C:\Users\u\AppData\Local\Temp\HWiNFO.sys", "clean")
check("戻り値が降格件数を返す", vt.apply_peruser_high_downgrade(r) == 1)

# ════════════════════════════════════════════════════════════
sec("実データ（HOST-REF-04 の HIGH5件相当）")
import json, glob
a = json.load(open(glob.glob(os.path.join(os.environ["CHECKPC_TEST_EXTRACT"], "HOST-REF-04_*/analyzed_*.json"))[0], encoding="utf-8"))
# VT結果を模擬付与（clean）してから降格を適用
import copy
r = copy.deepcopy(a)
for sn in ("system_7045", "startup_folder"):
    for e in r["sections"].get(sn, {}).get("entries", []):
        if e.get("score") == "HIGH":
            e["_vt_results"] = [{"verdict": "clean", "ioc": (e.get("iocs") or [""])[0]}]
before = sum(1 for sn in ("system_7045", "startup_folder")
             for e in r["sections"].get(sn, {}).get("entries", []) if e.get("score") == "HIGH")
n = vt.apply_peruser_high_downgrade(r)
after = sum(1 for sn in ("system_7045", "startup_folder")
            for e in r["sections"].get(sn, {}).get("entries", []) if e.get("score") == "HIGH")
check(f"HIGH{before}件中 allowlist該当が降格（降格={n}, 残HIGH={after}）",
      n >= 3 and after < before, f"before={before} n={n} after={after}")

# ════════════════════════════════════════════════════════════
sec("IOC抽出段階（_classify_ioc / extract_iocs_from_analyzed）— Officeアドイン拡張子")
# 実運用バグ: apply_peruser_high_downgrade 自体は正しくても、
# vt_enrich が呼ぶ extract_iocs_from_analyzed が Office アドイン拡張子を
# 対象外にしていると _vt_results が一生populateされず C3(VT照合済み)を
# 満たせないため、Zotero等のOfficeアドイン降格が実運用で発動しない。
for ext, ok in ((".dotm", True), (".dot", True), (".xlam", True),
                (".xla", True), (".ppam", True), (".xlsm", True),
                (".dotx", False), (".txt", False)):
    p = r"C:\Users\u\AppData\Roaming\Microsoft\Word\STARTUP\Zotero" + ext
    got = vt._classify_ioc(p)
    want = "filepath" if ok else None
    check(f"_classify_ioc: Officeアドイン{ext} → {want}", got == want, f"got={got}")

# extract_iocs_from_analyzed を通した end-to-end 確認（実データ）
a2 = json.load(open(glob.glob(os.path.join(os.environ["CHECKPC_TEST_EXTRACT"], "HOST-REF-04_*/analyzed_*.json"))[0], encoding="utf-8"))
ioc_map = vt.extract_iocs_from_analyzed(a2, min_score="MEDIUM")
zotero_hit = [k for k in ioc_map if "zotero" in k.lower()]
check("extract_iocs_from_analyzed: Zotero.dotm がVT照合対象IOCに含まれる（実データ）",
      len(zotero_hit) == 1, f"hit={zotero_hit}")

print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
