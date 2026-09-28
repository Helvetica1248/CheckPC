# -*- coding: utf-8 -*-
"""提案B: filepath whitelist 照合エンジン・降格の回帰テスト。"""
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
spec = importlib.util.spec_from_file_location("fw", f"{SCRIPTS}/filepath_whitelist.py")
fw = importlib.util.module_from_spec(spec); spec.loader.exec_module(fw)

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: print(f"  [OK]  {name}"); PASS += 1
    else: print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1
def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

# ════════════════════════════════════════════════════════════
sec("パターン変換ユニット")
check("_clean_pattern: ラベル除去",
      fw._clean_pattern(r":\Windows\a.exe << label << 20200713") == r":\Windows\a.exe")
check("_clean_pattern: コメント行→空", fw._clean_pattern("# comment") == "")
check("_normalize: 小文字・/→\\",
      fw._normalize("C:/Windows/A.EXE") == r"c:\windows\a.exe")

# ════════════════════════════════════════════════════════════
sec("照合エンジン（同梱 master whitelist）")
wl = fw.get_whitelist()
check("WL がロードされている", wl.stats()["loaded"])
check("env/ワイルド/ドライブ非依存パターンがコンパイル済み", wl.stats()["regex_groups"] >= 1)

check("ドライブ非依存 :\\ 一致（別ドライブ）",
      wl.is_whitelisted(r"D:\Windows\system32\FlashPlayerInstaller.exe"))
check("ワイルド * 展開一致（ユーザー名可変）",
      wl.is_whitelisted(r"C:\Users\alice\AppData\Local\Line\bin\current\LINE.exe"))
check("env/ワイルド複合一致（CR_*.tmp\\setup.exe）",
      wl.is_whitelisted(r"C:\Windows\TEMP\CR_9F3A.tmp\setup.exe"))
check("大文字小文字無視", wl.is_whitelisted(r"d:\WINDOWS\SYSTEM32\flashplayerinstaller.EXE"))

check("非該当: ユーザーDLの無関係exe",
      not wl.is_whitelisted(r"C:\Users\bob\Downloads\evil.exe"))
check("非該当: Temp のバックドア",
      not wl.is_whitelisted(r"C:\Temp\backdoor.exe"))
check("空文字は False", not wl.is_whitelisted(""))

# ════════════════════════════════════════════════════════════
sec("ファイル未在時は安全に無効化（loaded=False, 常に False）")
wl_missing = fw.FilepathWhitelist(path="/nonexistent/does_not_exist.txt")
check("未在 → loaded=False", not wl_missing.loaded)
check("未在 → is_whitelisted 常に False",
      not wl_missing.is_whitelisted(r"C:\Windows\explorer.exe"))
check("未在 → 降格 0 件",
      fw.apply_whitelist_downgrade({"sections": {"directory": {"entries": [
          {"score": "MEDIUM", "iocs": [r"D:\Windows\system32\FlashPlayerInstaller.exe"]}]}}},
          wl_missing) == 0)

# ════════════════════════════════════════════════════════════
sec("Phase2 降格ポリシー（HIGH不変・対象セクション限定）")
def one(section, score, ioc):
    a = {"sections": {section: {"entries": [
        {"identifier": ioc, "score": score, "iocs": [ioc], "reason": "o"}]}}}
    fw.apply_whitelist_downgrade(a, wl)
    return a["sections"][section]["entries"][0]["score"]

wl_ioc = r"D:\Windows\system32\FlashPlayerInstaller.exe"
check("directory: WL一致MEDIUM → CLEAN", one("directory", "MEDIUM", wl_ioc) == "CLEAN")
check("prefetch: WL一致LOW → CLEAN", one("prefetch", "LOW", wl_ioc) == "CLEAN")
check("directory: WL一致でもHIGHは不変（正の悪性シグナル優先）",
      one("directory", "HIGH", wl_ioc) == "HIGH")
check("非該当パスのMEDIUMは維持",
      one("directory", "MEDIUM", r"C:\Temp\evil.exe") == "MEDIUM")
check("対象外セクション(netstat)は触らない",
      one("netstat", "MEDIUM", wl_ioc) == "MEDIUM")

# 降格件数の戻り値
a = {"sections": {"directory": {"entries": [
    {"score": "MEDIUM", "iocs": [wl_ioc]},
    {"score": "LOW", "iocs": [wl_ioc]},
    {"score": "HIGH", "iocs": [wl_ioc]},
]}}}
check("降格件数=2（MEDIUM+LOWのみ、HIGH除く）",
      fw.apply_whitelist_downgrade(a, wl) == 2)

# ════════════════════════════════════════════════════════════
sec("実運用バグの再現・修正確認: task_scheduler対応＋環境変数プレースホルダ解決")
# 実運用で発覚: task_schedulerセクションが_WL_TARGET_SECTIONSに含まれて
# おらず、pla.dll/calluxxprovider.vbs等（既にWL登録済みだった）のCLEAN
# 降格が一切適用されていなかった。また、task_schedulerのIOCは
# %systemroot%\...のような未解決プレースホルダのままのため、
# WLパターン側の「解決済みドライブレターパス」を期待する正規表現とも
# 一致しなかった（二重の原因）。

check("_resolve_env_placeholders: %systemroot%を解決済みパスに変換する",
      fw._resolve_env_placeholders(r"%systemroot%\system32\pla.dll")
      == r"c:\windows\system32\pla.dll")
check("_resolve_env_placeholders: %windir%も同じ解決先になる",
      fw._resolve_env_placeholders(r"%windir%\system32\pla.dll")
      == fw._resolve_env_placeholders(r"%systemroot%\system32\pla.dll"))

check("task_scheduler が _WL_TARGET_SECTIONS に含まれる",
      "task_scheduler" in fw._WL_TARGET_SECTIONS)

_ts_wl_cases = [
    (r"%systemroot%\system32\pla.dll", "pla.dll"),
    (r"%systemroot%\system32\calluxxprovider.vbs", "calluxxprovider.vbs"),
    (r"%windir%\system32\gatherNetworkInfo.vbs", "gatherNetworkInfo.vbs"),
    (r"%windir%\system32\acproxy.dll", "acproxy.dll"),
    (r"%windir%\system32\AppxDeploymentClient.dll", "AppxDeploymentClient.dll"),
    (r"%windir%\system32\pcrpf.dll", "pcrpf.dll（新規追加）"),
    (r"%windir%\system32\Startupscan.dll", "Startupscan.dll"),
    (r"%windir%\system32\Windows.Storage.ApplicationData.dll",
     "Windows.Storage.ApplicationData.dll"),
]
for path, label in _ts_wl_cases:
    check(f"WL一致: {label}", wl.is_whitelisted(path), f"path={path}")

# task_scheduler の実運用相当データで、8件がCLEAN降格されHIGHは不変であることを確認
_ts_entries = [
    {"score": "MEDIUM", "identifier": "\\Microsoft\\Windows\\PLA\\Server Manager Performance Monitor",
     "iocs": [r"%systemroot%\system32\pla.dll"], "reason": "実行パスが PLA.dll を参照しているが、タスク名が不一致"},
    {"score": "MEDIUM", "identifier": "\\Microsoft\\Windows\\Server Manager\\CleanupOldPerfLogs",
     "iocs": [r"%systemroot%\system32\calluxxprovider.vbs"], "reason": "cscript.exe が System32 外のスクリプトを実行"},
    {"score": "HIGH", "identifier": "本物の不審タスク",
     "iocs": [r"C:\Users\Public\evil.exe"], "reason": "検証用"},
]
_ts_analyzed = {"sections": {"task_scheduler": {"entries": _ts_entries}}}
_ts_n = fw.apply_whitelist_downgrade(_ts_analyzed, wl)
check("task_scheduler: 既知正規ファイル2件がCLEANへ降格される", _ts_n == 2, f"n={_ts_n}")
check("task_scheduler: 降格後、pla.dllエントリはCLEANになる",
      _ts_entries[0]["score"] == "CLEAN", f"entries={_ts_entries}")
check("task_scheduler: 降格後のreasonに[WL: CLEAN降格]の注記が付く"
      "（従来の事実誤認を含む理由文は前面に出ない）",
      "[WL: CLEAN降格]" in _ts_entries[0]["reason"], f"reason={_ts_entries[0]['reason']}")
check("task_scheduler: HIGHエントリ(本物の不審タスク)は降格されず維持される",
      _ts_entries[2]["score"] == "HIGH", f"entries={_ts_entries}")

print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
