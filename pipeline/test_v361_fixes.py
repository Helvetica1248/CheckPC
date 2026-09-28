# -*- coding: utf-8 -*-
"""v3.61 の回帰テスト。

対象:
  · report_gen: M-1 MEDIUM集約からの永続化系セクション除外
    （実害事例: HOST-REF-08 の "Micorsoft" タイポスクワット永続化タスクが集約で埋没）
  · analyze_section._apply_post_filter: rdp_1024 GUID接続先への決定論注記
  · server.py: /result?format=all（全件版レポートのGUI表示・旧ジョブフォールバック）
"""
import sys, os, re, importlib.util

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
rg = _mod("report_gen")
a  = _mod("analyze_section")

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: print(f"  [OK]  {name}"); PASS += 1
    else: print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1
def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

# ════════════════════════════════════════════════════════════
sec("V1: M-1 永続化系セクションは MEDIUM を集約しない")
# 実データ相当: HOST-REF-08 の task_scheduler MEDIUM 4件（同一シグネチャ）
_ts = {"entries": [
    {"identifier": r"\Micorsoft Visual Host Sync Update", "score": "MEDIUM",
     "reason": "タスク名が \\Microsoft\\Windows\\ 配下でない。", "iocs": [], "mitre": []},
    {"identifier": r"\Micorsoft Visual Host Update", "score": "MEDIUM",
     "reason": "タスク名が \\Microsoft\\Windows\\ 配下でない。", "iocs": [], "mitre": []},
    {"identifier": r"\Micorsoft Visual Studio Host Update", "score": "MEDIUM",
     "reason": "タスク名が \\Microsoft\\Windows\\ 配下でない。", "iocs": [], "mitre": []},
    {"identifier": r"\ZoomUpdateTaskUser-S-1-5-21", "score": "MEDIUM",
     "reason": "タスク名が \\Microsoft\\Windows\\ 配下でない。", "iocs": [], "mitre": []},
], "section_summary": "s"}
md = rg.section_entries_md("task_scheduler", _ts, full=False)
check("V1: task_scheduler 標準版で集約行が出ない", "（集約）" not in md, md)
check("V1: タイポスクワット永続化タスクが個別行で見える",
      "Micorsoft Visual Host Sync Update" in md, md[:300])
check("V1: 4件全てが個別展開される",
      all(e["identifier"] in md for e in _ts["entries"]))
# 除外セクションの網羅
for sname in ("task_scheduler", "startup_folder", "service",
              "persistence_reg", "system_7045", "bits_jobs"):
    check(f"V1: {sname} が除外セットに含まれる",
          sname in rg._MED_AGG_EXCLUDE_SECTIONS)
# 非永続化セクションは従来通り集約される（回帰）
md_dq = rg.section_entries_md("defender_quarantine",
    {"entries": [dict(e, identifier=f"x{i}") for i, e in enumerate(_ts["entries"])],
     "section_summary": "s"}, full=False)
check("V1: 非永続化セクション(defender_quarantine)は従来通り集約（回帰）",
      "（集約）" in md_dq, md_dq)
# _all 版は従来通り全展開（回帰）
md_all = rg.section_entries_md("task_scheduler", _ts, full=True)
check("V1: _all版も全展開（回帰・変化なし）", "（集約）" not in md_all)

# ════════════════════════════════════════════════════════════
sec("V2: rdp_1024 GUID接続先の決定論注記")
GUID = "7EE8D767-08EB-4322-BFD0-52551E83ACEF"
def _rdp(ident, score="MEDIUM", reason="外部RDP接続の可能性。"):
    return {"entries": [{"identifier": ident, "score": score,
                         "reason": reason, "iocs": [ident], "mitre": []}],
            "section_summary": "s"}
r = a._apply_post_filter("rdp_1024", _rdp(GUID))
e = r["entries"][0]
check("V2: GUID識別子に注記が付く", "[注記] 接続先がGUID形式" in e["reason"], e["reason"])
check("V2: Hyper-V可能性とログ未記録の説明を含む",
      "Hyper-V" in e["reason"] and "記録されない" in e["reason"], e["reason"])
check("V2: スコアは不変（注記のみ・降格なし）", e["score"] == "MEDIUM")
check("V2: 元のreasonが保持される", e["reason"].startswith("外部RDP接続の可能性。"))
# 冪等性
r2 = a._apply_post_filter("rdp_1024", r)
check("V2: 再適用しても二重付与されない",
      r2["entries"][0]["reason"].count("[注記]") == 1)
# 非GUID識別子は不変
r3 = a._apply_post_filter("rdp_1024", _rdp("192.168.1.50"))
check("V2: IPアドレス識別子には注記しない", "[注記]" not in r3["entries"][0]["reason"])
r4 = a._apply_post_filter("rdp_1024", _rdp("fileserver01"))
check("V2: ホスト名識別子には注記しない", "[注記]" not in r4["entries"][0]["reason"])
# 波括弧付きGUIDも対象
r5 = a._apply_post_filter("rdp_1024", _rdp("{" + GUID + "}"))
check("V2: {GUID} 形式も注記対象", "[注記]" in r5["entries"][0]["reason"])
# 他セクションへの副作用なし
r6 = a._apply_post_filter("dns_cache", _rdp(GUID))
check("V2: 他セクション(dns_cache)には作用しない",
      "[注記]" not in r6["entries"][0]["reason"])

# ════════════════════════════════════════════════════════════
sec("V3: server /result?format=all（全件版のGUI表示）")
client = None
try:
    # 環境整備（fastapi/uvicorn/python-multipart 必須）。未整備の環境では
    # SKIP とし、整備済み環境ではアサーション失敗を隠さない構造にする。
    from fastapi.testclient import TestClient
    sv = _mod("server")
    client = TestClient(sv.app)
except Exception as ex:
    print(f"  [SKIP] serverテスト環境が未整備のためスキップ: {ex}")
if client:
    import pathlib
    td1 = sv.JOBS_DIR / "t1"
    td1.mkdir(parents=True, exist_ok=True)
    rp  = td1 / "report_H_1.md"
    rap = td1 / "report_H_1_all.md"
    rp.write_text("# 標準版", encoding="utf-8")
    rap.write_text("# 全件版レポート", encoding="utf-8")

    sv._jobs["t1"] = {"status": "done", "report_path": str(rp),
                      "report_all_path": str(rap)}
    res = client.get("/result/t1?format=all")
    check("V3: format=all で全件版が返る",
          res.status_code == 200 and "全件版レポート" in res.text,
          f"{res.status_code}")
    # 旧ジョブ（report_all_path 無し）→ 命名規則フォールバック
    td2 = sv.JOBS_DIR / "t2"
    td2.mkdir(parents=True, exist_ok=True)
    rp2 = td2 / "report_H_1.md"
    rap2 = td2 / "report_H_1_all.md"
    rp2.write_text("# 標準版", encoding="utf-8")
    rap2.write_text("# 全件版レポート", encoding="utf-8")
    sv._jobs["t2"] = {"status": "done", "report_path": str(rp2)}
    res2 = client.get("/result/t2?format=all")
    check("V3: 旧ジョブでも report_path から _all 版を導出できる",
          res2.status_code == 200 and "全件版レポート" in res2.text,
          f"{res2.status_code}")
    # 標準版の既存動作（回帰）
    res3 = client.get("/result/t1?format=md")
    check("V3: format=md は従来通り標準版（回帰）",
          res3.status_code == 200 and "標準版" in res3.text)
    # GUIに全件版ボタンが含まれる
    html = client.get("/").text
    check("V3: GUIに『全件版』ボタンがある", "全件版" in html)
    check("V3: viewReport が format 引数対応", "fmt = 'md'" in html or "fmt='md'" in html)

print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
