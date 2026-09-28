# -*- coding: utf-8 -*-
"""提案5: 決定論 MEDIUM フロア（v3.64）の回帰テスト。

背景: LEAN A/B 実測（HOST-REF-08・2回）で、LLM 判定の揺らぎにより実害級の
エントリ（Public\\Libraries\\x64.exe、Temp\\wmic.exe 等）が HIGH→CLEAN/LOW へ
落ちる事象が再現。配置だけで疑わしいパターンは LLM 判定に依存させず、
ルールで MEDIUM 未満へ落とさない（昇格フロア）。FULL/LEAN 両モードで有効。
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
spec = importlib.util.spec_from_file_location("a", f"{SCRIPTS}/analyze_section.py")
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: print(f"  [OK]  {name}"); PASS += 1
    else: print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1
def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

def one(section, score, ioc, reason="元の根拠"):
    r = {"entries": [{"identifier": ioc, "score": score,
                      "reason": reason, "iocs": [ioc], "mitre": []}]}
    a._apply_post_filter(section, r)
    return r["entries"][0]

# ════════════════════════════════════════════════════════════
sec("F1: (i) 既知不審配置の実行ファイル → MEDIUMフロア")
e = one("directory", "CLEAN", r"C:\Users\Public\Libraries\x64.exe")
check("F1: Public\\Libraries\\x64.exe CLEAN→MEDIUM（A/Bで再現した実害級消失の対策）",
      e["score"] == "MEDIUM", str(e))
check("F1: reason に [フロア] 注記＋元の根拠を保持",
      "[フロア]" in e["reason"] and e["reason"].startswith("元の根拠"), e["reason"])
check("F1: 監査用 _floor=susp_dir が付く", e.get("_floor") == "susp_dir")
for path, want in [
    (r"C:\PerfLogs\stage.dll",                 "MEDIUM"),
    (r"C:\$Recycle.Bin\S-1-5-21\payload.dll",  "MEDIUM"),
    (r"C:\Windows\Help\backdoor.exe",          "MEDIUM"),
    (r"C:\Windows\Fonts\svc.exe",              "MEDIUM"),
    (r"C:\Windows\Debug\x.bat",                "MEDIUM"),
    (r"C:\Windows\Tracing\y.ps1",              "MEDIUM"),
    (r"C:\Users\Public\Libraries\readme.txt",  "CLEAN"),   # 非実行ファイルは対象外
    (r"C:\Users\Public\Desktop\app.lnk",       "CLEAN"),   # 対象ディレクトリ外
    (r"C:\Program Files\Vendor\tool.exe",      "CLEAN"),   # 通常配置
]:
    got = one("directory", "CLEAN", path)["score"]
    check(f"F1: {path[:44]:44} → {want}", got == want, f"got={got}")

# ════════════════════════════════════════════════════════════
sec("F2: (ii) OSバイナリ名のシステム配置外 → MEDIUMフロア")
e = one("appcompat_cache", "LOW", r"C:\Users\fixture-user-02\AppData\Local\Temp\wmic.exe")
check("F2: Temp\\wmic.exe LOW→MEDIUM（v1 A/Bで消失した実害級の対策）",
      e["score"] == "MEDIUM", str(e))
check("F2: 注記にバイナリ名と偽装疑いが明記される",
      "wmic.exe" in e["reason"] and "偽装" in e["reason"], e["reason"])
for path, want in [
    (r"C:\Users\u\Downloads\svchost.exe",       "MEDIUM"),
    (r"C:\Temp\rundll32.exe",                   "MEDIUM"),
    (r"C:\Users\u\Downloads\explorer.exe",      "MEDIUM"),
    (r"C:\Windows\System32\wbem\wmic.exe",      "CLEAN"),   # 正規配置
    (r"C:\Windows\System32\svchost.exe",        "CLEAN"),
    (r"C:\Windows\SysWOW64\rundll32.exe",       "CLEAN"),
    (r"C:\Windows\WinSxS\amd64_x\conhost.exe",  "CLEAN"),
    (r"C:\Windows\explorer.exe",                "CLEAN"),   # explorer は Windows 直下が正規
    (r"C:\Users\u\Downloads\myapp.exe",         "MEDIUM"),  # rc18: 汎用user-writable実行痕跡
]:
    got = one("appcompat_cache", "CLEAN", path)["score"]
    check(f"F2: {path[:44]:44} → {want}", got == want, f"got={got}")

# ════════════════════════════════════════════════════════════
sec("F3: スコープ・境界・冪等性")
check("F3: HIGH は不変（フロアは昇格のみ）",
      one("directory", "HIGH", r"C:\Users\Public\Libraries\evil.exe")["score"] == "HIGH")
check("F3: MEDIUM は不変（注記も付かない）",
      "[フロア]" not in one("directory", "MEDIUM",
                            r"C:\Users\Public\Libraries\e.exe")["reason"])
check("F3: 対象外セクション(netstat)には作用しない",
      one("netstat", "CLEAN", r"C:\Users\Public\Libraries\x.exe")["score"] == "CLEAN")
check("F3: 対象外セクション(prefetch: パス情報なし)には作用しない",
      one("prefetch", "CLEAN", "WMIC.EXE-2088EB2D.pf")["score"] == "CLEAN")
# 冪等性: 再適用で注記が二重にならない
r = {"entries": [{"identifier": r"C:\PerfLogs\a.exe", "score": "CLEAN",
                  "reason": "r", "iocs": [r"C:\PerfLogs\a.exe"], "mitre": []}]}
a._apply_post_filter("directory", r)
a._apply_post_filter("directory", r)
check("F3: 冪等（[フロア]注記は1回のみ）",
      r["entries"][0]["reason"].count("[フロア]") == 1, r["entries"][0]["reason"])
# iocs が空でも identifier で判定できる
e = one("directory", "CLEAN", "")
r2 = {"entries": [{"identifier": r"C:\PerfLogs\b.exe", "score": "CLEAN",
                   "reason": "r", "iocs": [], "mitre": []}]}
a._apply_post_filter("directory", r2)
check("F3: iocs 空時は identifier で判定", r2["entries"][0]["score"] == "MEDIUM")
# 大文字小文字・スラッシュ混在
check("F3: 大文字小文字/スラッシュ混在も検出",
      one("directory", "CLEAN", "c:/users/PUBLIC/Libraries/X64.EXE")["score"] == "MEDIUM")

# ════════════════════════════════════════════════════════════
sec("F4: 既存降格ロジックとの共存（回帰）")
# rc18: Windows Temp配下の実行体は製品名に関係なくuser-writable execution
# artifactとしてMEDIUM未満へ落とさない。親ディレクトリ名が.tmpでも同じ。
e = one("directory", "CLEAN", r"C:\Windows\TEMP\CR_9F3A.tmp\setup.exe")
check("F4: Windows Temp配下の実行体は汎用MEDIUMフロア",
      e["score"] == "MEDIUM" and e.get("_floor") == "user_writable_execution_artifact",
      str(e))

print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
