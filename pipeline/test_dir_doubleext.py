# -*- coding: utf-8 -*-
"""directory A分類: 二重拡張子パターンの誤爆是正（Q2）の回帰テスト。

正規の名前空間DLL（信頼配置の *.pdf.dll 等）を A から除外しつつ、
文書偽装（*.pdf.exe/.scr、信頼配置外の *.pdf.dll）は A を維持する。
"""
import sys, os, importlib.util

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
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: print(f"  [OK]  {name}"); PASS += 1
    else: print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1
def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

def cls(path):
    parts = path.split("\\")
    return a._classify_dir_entry(
        {"path": path, "name": parts[-1], "dir": "\\".join(parts[:-1])})

# ════════════════════════════════════════════════════════════
sec("誤爆是正: 信頼配置の名前空間DLLは A ではない")
check("System32\\Windows.Data.Pdf.dll → 非A",
      cls(r"C:\WINDOWS\System32\Windows.Data.Pdf.dll") != "A")
check("SysWOW64\\Windows.Data.Pdf.dll → 非A",
      cls(r"C:\WINDOWS\SysWOW64\Windows.Data.Pdf.dll") != "A")
check("Program Files 配下の *.Docx.dll → 非A",
      cls(r"C:\Program Files\WDATP\x\Microsoft.Ceres.DocParsing.FormatHandlers.Docx.dll") != "A")
check("WinSxS 配下の *.Pdf.dll → 非A",
      cls(r"C:\Windows\WinSxS\amd64_x\Something.Pdf.dll") != "A")
check("バレ名のみ Windows.Data.Pdf.dll（パス区切りなし）→ 非A",
      cls(r"Windows.Data.Pdf.dll") != "A")

# ════════════════════════════════════════════════════════════
sec("検出維持（取りこぼし防止）: 偽装・非信頼配置は A")
check("Temp の invoice.pdf.dll → A（側読み込み偽装疑い）",
      cls(r"C:\Users\u\AppData\Local\Temp\invoice.pdf.dll") == "A")
check("Downloads の report.pdf.exe → A（二重拡張子exe）",
      cls(r"C:\Users\u\Downloads\report.pdf.exe") == "A")
check("Downloads の report.pdf.scr → A（二重拡張子scr）",
      cls(r"C:\Users\u\Downloads\report.pdf.scr") == "A")
check("System32 の invoice.pdf.exe → A（exeは信頼配置でも偽装として維持）",
      cls(r"C:\Windows\System32\invoice.pdf.exe") == "A")
check("ユーザー領域の資料.xlsx.exe → A",
      cls(r"C:\Users\u\Desktop\資料.xlsx.exe") == "A")

# ════════════════════════════════════════════════════════════
sec("他の A パターンに副作用がないこと（回帰）")
check("mimikatz.exe → A", cls(r"C:\tools\mimikatz.exe") == "A")
check("Windows\\Temp\\x.exe → A", cls(r"C:\Windows\Temp\x.exe") == "A")
check("Windows\\Tasks\\x.job → A", cls(r"C:\Windows\Tasks\evil.job") == "A")
check("sysprep\\cryptbase.dll → A（DLL探索順ハイジャック）",
      cls(r"C:\Users\u\AppData\Local\Temp\sysprep\cryptbase.dll") == "A")
# 通常の正規DLLはA以外
check("通常の System32\\kernel32.dll → 非A",
      cls(r"C:\Windows\System32\kernel32.dll") != "A")

print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
