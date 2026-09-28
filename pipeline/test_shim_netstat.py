# -*- coding: utf-8 -*-
"""ShimCacheParser 照合是正（ロケール曜日文字対応）／ netstat 案A の回帰テスト。"""
import sys, os, re, importlib.util, tempfile, shutil
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
for _c in (os.environ.get("CHECKPC_SCRIPTS", ""), HERE,
           os.path.dirname(HERE), "/opt/llm/analysis", "/home/claude/scripts"):
    if _c and os.path.exists(os.path.join(_c, "analyze_section.py")):
        SCRIPTS = _c
        break
else:
    print("analyze_section.py が見つかりません"); sys.exit(2)
sys.path.insert(0, SCRIPTS)

# run_analysis は openai import を伴うため、_shim_match_key だけ抽出して評価する
_src = open(f"{SCRIPTS}/run_analysis.py", encoding="utf-8").read()
_m = re.search(r"def _shim_match_key.*?\n\n\ndef run_shimcache", _src, re.S)
_ns = {"re": re}
exec(_m.group(0).replace("\n\n\ndef run_shimcache", ""), _ns)
shim_key = _ns["_shim_match_key"]

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: print(f"  [OK]  {name}"); PASS += 1
    else: print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1
def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

# ════════════════════════════════════════════════════════════
sec("_shim_match_key: 安定キー生成")
check("非ASCII(周三)を除去",
      shim_key("HOST_20260701周三17502091.txt") == "host_2026070117502091.txt")
check("U+FFFD置換文字を除去",
      shim_key("HOST_20260701\ufffd\ufffd17502091.txt") == "host_2026070117502091.txt")
check("? 置換文字を除去",
      shim_key("HOST_20260701??17502091.txt") == "host_2026070117502091.txt")
check("ASCII曜日(Tue)は保持（両ファイル同一なので問題なし）",
      shim_key("HOST_06302026Tue15203650.txt") == "host_06302026tue15203650.txt")
check("大文字小文字を無視", shim_key("HOST_ABC.TXT") == shim_key("host_abc.txt"))

# ════════════════════════════════════════════════════════════
sec("CheckPC↔AppCompatCache 照合（化け方の食い違いを吸収）")
def match(cp_suffix, ac_suffix):
    return shim_key(cp_suffix) == shim_key(ac_suffix)
# 中国語曜日が両者で異なる化け方をしても一致する
check("U+FFFD vs 半角カナ化 → 一致",
      match("H_20260701\ufffd\ufffd17502091.txt", "H_20260701\uff96\uff9c17502091.txt"))
check("原文保持 vs ?置換 → 一致",
      match("H_20260701周三17502091.txt", "H_20260701??17502091.txt"))
check("曜日あり vs 曜日欠落 → 一致",
      match("H_20260701周三17502091.txt", "H_2026070117502091.txt"))
check("ASCII曜日(Tue)同士 → 一致（回帰）",
      match("H_06302026Tue15203650.txt", "H_06302026Tue15203650.txt"))
# 別ホストは誤一致しない
check("別ホスト名は一致しない",
      not match("HOSTA_2026070117502091.txt", "HOSTB_2026070117502091.txt"))
check("別日時は一致しない",
      not match("H_20260701周三17502091.txt", "H_20260702周三17502091.txt"))

# ════════════════════════════════════════════════════════════
sec("実CAB4種: 展開→照合が全て成功する")
import subprocess
_UPLOAD = os.environ.get("CHECKPC_TEST_UPLOADS", "").strip()
cabs = ([f for f in os.listdir(_UPLOAD) if f.endswith(".cab")]
        if os.path.isdir(_UPLOAD) else [])
work_root = Path(os.environ.get("CHECKPC_TEST_WORKDIR", tempfile.gettempdir())).expanduser().resolve()
work_root.mkdir(parents=True, exist_ok=True)
for cab in sorted(cabs):
    ed = work_root / f"cabtest_rt_{re.sub(r'[^A-Za-z0-9]', '_', cab)[:16]}"
    shutil.rmtree(ed, ignore_errors=True)
    ed.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cabextract", "-e", "SJIS", os.path.join(_UPLOAD, cab), "-d", ed],
                   capture_output=True)
    files = os.listdir(ed)
    cp = [f for f in files if f.lower().startswith("checkpc") and f.lower().endswith(".txt")]
    matched = False
    if cp:
        suffix = re.sub(r"^checkpc_", "", cp[0], flags=re.I)
        for f in files:
            if re.match(r"^AppCompatCache_", f, re.I) and f.lower().endswith(".txt"):
                fs = re.sub(r"^AppCompatCache_", "", f, flags=re.I)
                if shim_key(fs) == shim_key(suffix):
                    matched = True
    check(f"{cab[:34]:34} → AppCompatCache照合成功", matched)

# ════════════════════════════════════════════════════════════
sec("netstat 案A: max_tokens/chunk_size 設定")
spec = importlib.util.spec_from_file_location("a", f"{SCRIPTS}/analyze_section.py")
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
mt = a.MAX_TOKENS["netstat"][1]
cs = a.CHUNK_SIZE_DEPTH1["netstat"]
check("netstat depth1 max_tokens=2048", mt == 2048, f"={mt}")
check("netstat depth1 chunk_size=10", cs == 10, f"={cs}")
check("トークン余裕 >=192tok/entry（directory同等）", mt // cs >= 192, f"={mt//cs}")

# ════════════════════════════════════════════════════════════
sec("文字化けファイル名のASCII安全化（python2.7/nkf入出力パス対策）")
def safe_stem(base):
    return re.sub(r'[?<>:"|*]','',re.sub(r'[^\x00-\x7f]','',base))
check("化けた曜日文字を除去してASCII化",
      safe_stem("CheckPC_H_20260701\uff96\uff9c\ufffd17.txt") == "CheckPC_H_2026070117.txt")
check("Windows禁止文字を除去",
      safe_stem("CheckPC_H_2026??07.txt") == "CheckPC_H_202607.txt")
check("ASCII名は不変",
      safe_stem("CheckPC_HOST-REF-05_06302026Tue15.txt") == "CheckPC_HOST-REF-05_06302026Tue15.txt")
_ss = safe_stem("CheckPC_H_20260701\uff96\ufffd17.txt")
check("生成される安全stemはASCIIのみ", _ss.isascii())
check("out_csv名もASCII安全",
      re.sub(r'^checkpc_','ParsedAppCompatCache_',_ss,flags=re.I).replace('.txt','.csv').isascii())


print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
