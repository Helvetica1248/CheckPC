# -*- coding: utf-8 -*-
"""report_gen.py R-3 / R-4 決定論フォールバックの回帰テスト。"""
import os
import sys, glob, json, importlib.util
from pathlib import Path

for _c in (os.environ.get("CHECKPC_SCRIPTS", ""), os.path.dirname(os.path.abspath(__file__)),
           os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
           "/opt/llm/analysis", "/home/claude/scripts"):
    if _c and os.path.exists(os.path.join(_c, "analyze_section.py")):
        SCRIPTS = _c
        break
else:
    print("analyze_section.py が見つかりません"); sys.exit(2)
sys.path.insert(0, SCRIPTS)  # SECTION_LABELS 等の依存
REALDATA_ROOT = Path(os.environ["CHECKPC_TEST_EXTRACT"]).expanduser().resolve()
spec = importlib.util.spec_from_file_location("report_gen", str(Path(SCRIPTS) / "report_gen.py"))
rg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rg)

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}"); PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1
def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

# ════════════════════════════════════════════════════════════
sec("R-3: derive_malware_family（Defender検知名→ファミリー）")
# 検知名パターンの抽出
samples = {
    "Trojan:MSIL/Darkvigil.NWA!MTB": "Darkvigil.NWA",
    "Adware:Win32/Tnega":            "Tnega",
    "Trojan:Win32/Cerdigent.A!dha":  "Cerdigent.A",
    "Program:Script/Wacapew.A!ml":   "Wacapew.A",
    "Trojan:Win32/Kepavll!rfn":      "Kepavll",
}
for ident, fam in samples.items():
    m = rg._DEFENDER_NAME_RE.match(ident)
    check(f"{ident} → {fam}", bool(m) and m.group(1) == fam,
          f"got={m.group(1) if m else None}")

# HIGH のみ採用・頻度順
fake = {"sections": {"defender_quarantine": {"entries": [
    {"score": "HIGH", "identifier": "Trojan:Win32/Ravartar!rfn"},
    {"score": "HIGH", "identifier": "Trojan:Win32/Ravartar!rfn"},
    {"score": "HIGH", "identifier": "Adware:Win32/Tnega"},
    {"score": "MEDIUM", "identifier": "Trojan:Win32/ShouldBeIgnored"},
]}}}
fam = rg.derive_malware_family(fake)
check("頻度順で Ravartar が先頭", fam.startswith("Ravartar"), fam)
check("MEDIUM のエントリは無視", "ShouldBeIgnored" not in fam, fam)

# 検知なし → 空文字（捏造しない）
check("Defender HIGH なし → 空文字",
      rg.derive_malware_family({"sections": {}}) == "")

# ════════════════════════════════════════════════════════════
sec("R-4: derive_suspicion_floor（所見件数→床）")
def mk(h, m, l):
    ents = ([{"score": "HIGH"}] * h + [{"score": "MEDIUM"}] * m + [{"score": "LOW"}] * l)
    return {"sections": {"x": {"entries": ents}}}
check("HIGH>0 → HIGH",   rg.derive_suspicion_floor(mk(1, 0, 0)) == "HIGH")
check("MEDIUMのみ → MEDIUM", rg.derive_suspicion_floor(mk(0, 5, 0)) == "MEDIUM")
check("LOWのみ → LOW",   rg.derive_suspicion_floor(mk(0, 0, 3)) == "LOW")
check("所見なし → NONE", rg.derive_suspicion_floor(mk(0, 0, 0)) == "NONE")

# ════════════════════════════════════════════════════════════
sec("generate_report: フォールバック作動条件と有効値の非上書き")
# None suspicion → 床で補完＋注記
a = mk(0, 3, 0)
c = {"infection_suspicion": None, "malware_family": "Unknown"}
md = rg.generate_report(a, c)
check("None → MEDIUM 補完＋注記表示",
      "MEDIUM（決定論フォールバック" in md, "見出し未補完")
check("見出しに 'None' が出ない", ": None" not in md)

# 有効な suspicion は上書きしない
c2 = {"infection_suspicion": "LOW", "malware_family": "Emotet"}
md2 = rg.generate_report(mk(5, 0, 0), c2)  # HIGH=5 でも LLM値 LOW を尊重
check("有効な LLM 値 LOW は床(HIGH)で上書きされない",
      "感染嫌疑評価: LOW" in md2, "上書きされた")
check("有効な family Emotet は上書きされない", "Emotet" in md2)
check("有効値のとき フォールバック注記は出ない",
      "決定論フォールバック" not in md2 and "決定論抽出" not in md2)

# family Unknown かつ Defender検知あり → 補完
a3 = {"sections": {"defender_quarantine": {"entries": [
    {"score": "HIGH", "identifier": "Trojan:Win32/Bearfoos.A!ml"}]}}}
md3 = rg.generate_report(a3, {"infection_suspicion": "HIGH", "malware_family": "Unknown"})
check("family Unknown → Bearfoos.A 補完＋注記",
      "Bearfoos.A" in md3 and "Defender検知名から決定論抽出" in md3)

# ════════════════════════════════════════════════════════════
sec("実データ（提供アーカイブ）での確認")
def load(p): return json.load(open(p, encoding="utf-8"))
def files(host, vt):
    hd = glob.glob(str(REALDATA_ROOT / f"{host}_*"))[0]
    a = [x for x in glob.glob(f"{hd}/analyzed_{host}_*.json") if ("_vt" in x) == vt][0]
    c = [x for x in glob.glob(f"{hd}/correlation_{host}_*.json") if ("_vt" in x) == vt][0]
    return load(a), load(c)

a, c = files("HOST-REF-09", False)  # VT前で None だった版
md = rg.generate_report(a, c)
check("R-4実: TANAKALAB(VT前) で None が消える", ": None" not in md)
check("R-4実: TANAKALAB が MEDIUM で描画", "感染嫌疑評価: MEDIUM" in md)

a, c = files("HOST-REF-08", True)
md = rg.generate_report(a, c)
check("R-3実: LOAE family が実検知名に補完(Ravartar等)",
      "Ravartar" in md or "Tnega" in md or "Kepavll" in md)

# ════════════════════════════════════════════════════════════
print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
