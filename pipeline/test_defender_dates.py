# -*- coding: utf-8 -*-
"""Defender検知日付の記載（v3.60）の回帰テスト。

対象:
  · analyze_section.analyze_defender_quarantine_rule_based — datetime 保持・
    directory_scan 出所区別・SHA-1集約時の全日時保持
  · report_gen.section_entries_md — 日時(JST)列の独立表示・範囲表示・
    出所併記・日時なしセクションの不変（回帰）
  · defender_dir_report.build_defender_dir_report — 検知日時範囲の追記行
  · call_llm_chunked（depth>=2 パス）— source_index 経由の datetime 付与
"""
import sys, os, re, json, importlib.util

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
rg = _mod("report_gen")
dd = _mod("defender_dir_report")

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: print(f"  [OK]  {name}"); PASS += 1
    else: print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1
def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

Q = r"C:\ProgramData\Microsoft\Windows Defender\Quarantine\ResourceData\5B"
SHA = "5B" + "A" * 38

# ════════════════════════════════════════════════════════════
sec("D-1: ルールベース評価が datetime を保持する")
raw = [
    # defender_eventlog 由来（検知日時・UTC ISO）
    {"source": "defender_eventlog", "threat_name": "Trojan:Win32/Kepavll!rfn",
     "path": r"C:\Users\u\INetCache\dnscfg[1].dll",
     "datetime": "2026-04-04T20:14:00.0060000Z"},
    # 同一 SHA-1 の隔離検体が2イベント（ResourceData/Resources 重複相当）
    {"source": "defender_eventlog", "threat_name": "",
     "path": Q + "\\" + SHA, "datetime": "2026-04-04T20:14:02.3830000Z"},
    {"source": "defender_eventlog", "threat_name": "",
     "path": Q.replace("ResourceData", "Resources") + "\\" + SHA,
     "datetime": "2026-04-06T01:00:00.0000000Z"},
    # directory_scan 由来（ファイル更新日時・検知日時ではない）
    {"source": "directory_scan", "threat_name": "",
     "path": r"C:\ProgramData\ESET\Quarantine\abc.nqf",
     "datetime": "2020/10/18  09:10"},
]
r = a.analyze_defender_quarantine_rule_based(raw)
ents = r["entries"]
check("D-1: エントリ数=3（SHA-1重複は集約）", len(ents) == 3, f"={len(ents)}")
e_threat = ents[0]
check("D-1: 脅威名HIGHに datetime が乗る",
      e_threat.get("datetime") == "2026-04-04T20:14:00.0060000Z", str(e_threat))
check("D-1: defender_eventlog 由来は kind=検知",
      e_threat.get("datetime_kind") == "検知", str(e_threat.get("datetime_kind")))
e_sha = [e for e in ents if SHA in (e.get("iocs") or [""])[0]][0]
check("D-1: SHA-1集約エントリが両イベントの日時を保持（datetime_all=2件）",
      len(e_sha.get("datetime_all", [])) == 2, str(e_sha.get("datetime_all")))
check("D-1: datetime_all は昇順（初回〜最終の範囲表示用）",
      e_sha.get("datetime_all") == sorted(e_sha.get("datetime_all", [])))
e_dir = [e for e in ents if e.get("identifier", "").endswith(".nqf")][0]
check("D-1: directory_scan 由来は kind=更新（出所区別）",
      e_dir.get("datetime_kind") == "更新", str(e_dir))
# 日時なし入力の後退がないこと
r0 = a.analyze_defender_quarantine_rule_based(
    [{"source": "defender_eventlog", "threat_name": "T:X/Y", "path": r"C:\x.dll"}])
check("D-1: 日時なし入力でも従来どおり評価される（datetime キー無し）",
      r0["entries"] and "datetime" not in r0["entries"][0])

# ════════════════════════════════════════════════════════════
sec("D-2: レポートに日時(JST)列が独立表示される")
md = rg.section_entries_md("defender_quarantine",
                           {"entries": ents, "section_summary": "s"}, full=True)
check("D-2: ヘッダに 日時(JST) 列が追加される", "| 日時(JST) |" in md, md[:200])
check("D-2: UTC(Z)がJSTへ変換される（20:14Z → 翌05:14）",
      "2026-04-05 05:14" in md, md)
check("D-2: SHA-1集約行は初回〜最終の範囲＋件数表示",
      re.search(r"2026-04-05 05:14 〜 2026-04-06 10:00（2件）", md), md)
check("D-2: directory_scan 由来は（ファイル更新日時）を併記",
      "（ファイル更新日時）" in md, md)
check("D-2: マーカー無しローカル時刻は無変換（2020-10-18 09:10）",
      "2020-10-18 09:10" in md, md)
# 表の桁が全行で一致していること（Markdown崩れ防止）
rows = [l for l in md.splitlines() if l.startswith("|")]
ncols = {l.count("|") for l in rows}
check("D-2: 全テーブル行のセル数が一致", len(ncols) == 1, str(ncols))

# 日時を持たないセクションは従来と完全一致（回帰）
plain = {"entries": [{"identifier": "x", "score": "HIGH", "reason": "r",
                      "iocs": [], "mitre": []}], "section_summary": ""}
md_p = rg.section_entries_md("service", plain, full=True)
check("D-2: 日時なしセクションに 日時(JST) 列は出ない（回帰）",
      "日時(JST)" not in md_p, md_p[:120])

# ════════════════════════════════════════════════════════════
sec("D-3: M-1 MEDIUM集約行にも範囲の日時セルが付く")
med = [{"identifier": f"C:\\q\\{i}.bin", "score": "MEDIUM",
        "reason": "脅威名不明。隔離フォルダ内に存在（要VT照合）。",
        "iocs": [], "mitre": [],
        "datetime": f"2026-04-0{i}T00:00:00Z"} for i in range(1, 6)]  # 5件>=閾値4
md3 = rg.section_entries_md("defender_quarantine",
                            {"entries": med, "section_summary": "s"}, full=False)
check("D-3: 集約行が生成される", "（集約）" in md3, md3)
agg_line = [l for l in md3.splitlines() if "（集約）" in l][0]
check("D-3: 集約行の日時セルが初回〜最終の範囲",
      re.search(r"2026-04-01 09:00 〜 2026-04-05 09:00", agg_line), agg_line)
rows3 = [l for l in md3.splitlines() if l.startswith("|")]
check("D-3: 集約表でもセル数が全行一致",
      len({l.count("|") for l in rows3}) == 1,
      str({l.count("|") for l in rows3}))

# ════════════════════════════════════════════════════════════
sec("D-4: 16-D 集約表示に検知日時の範囲が追記される")
parsed = {"meta": {"hostname": "TESTHOST"}, "sections": {
    "defender_quarantine": [
        {"source": "defender_eventlog", "threat_name": "T:X/Y",
         "path": r"C:\Users\u\Temp\evil.dll",
         "datetime": "2026-04-04T20:14:00.0060000Z"},
        {"source": "defender_eventlog", "threat_name": "T:X/Y",
         "path": r"C:\Users\u\Temp\evil.dll",
         "datetime": "2026-04-06T01:00:00.0000000Z"},
        {"source": "defender_eventlog", "threat_name": "T:Z/W",
         "path": r"C:\Users\u\Temp\single.dll",
         "datetime": "2026-04-05T00:00:00.0000000Z",
         "process_name": r"C:\Windows\System32\rundll32.exe"},
        {"source": "defender_eventlog", "threat_name": "T:N/D",
         "path": r"C:\Users\u\Temp\nodate.dll"},
    ],
    "directory": [],
}}
md4 = dd.build_defender_dir_report(parsed)
lines4 = md4.splitlines()
check("D-4: パス行そのものは従来と不変（追記行方式）",
      r"C:\Users\u\Temp\evil.dll" in lines4, "")
i_evil = lines4.index(r"C:\Users\u\Temp\evil.dll")
check("D-4: 複数検知は直下に初回〜最終の範囲＋件数",
      re.search(r"└ 検知: 2026-04-05 05:14 〜 2026-04-06 10:00 \(JST・2件\)",
                lines4[i_evil + 1]), lines4[i_evil + 1])
i_single = lines4.index(r"C:\Users\u\Temp\single.dll")
check("D-4: 単一検知は日時のみ",
      "検知: 2026-04-05 09:00 (JST)" in lines4[i_single + 1], lines4[i_single + 1])
i_nodate = lines4.index(r"C:\Users\u\Temp\nodate.dll")
check("D-4: 日時なしイベントには追記行を出さない",
      "検知:" not in lines4[i_nodate + 1], lines4[i_nodate + 1])
i_proc = lines4.index(r"C:\Windows\System32\rundll32.exe")
check("D-4: コマンド（Process Name由来）にも検知日時が付く",
      "検知: 2026-04-05 09:00" in lines4[i_proc + 1], lines4[i_proc + 1])

# ════════════════════════════════════════════════════════════
sec("D-5: depth>=2 LLMパスでも datetime が元データから付与される")
def _ok_json(user_msg):
    idxs = [int(m) for m in re.findall(r"^\[#(\d+)\]", user_msg, re.M)]
    es = [{"source_index": i, "identifier": f"e{i}", "score": "HIGH",
           "reason": "ok", "mitre": [], "iocs": []} for i in idxs]
    return json.dumps({"section": "defender_quarantine", "entries": es},
                      ensure_ascii=False)
class _Cli:
    calls = []
    class chat:
        class completions:
            @staticmethod
            def create(**kw):
                user = [m for m in kw["messages"] if m["role"] == "user"][0]["content"]
                _Cli.calls.append(user)
                class R: pass
                r = R(); r.choices = [R()]; r.choices[0].message = R()
                r.choices[0].message.content = _ok_json(user)
                return r
chunk = [{"source": "defender_eventlog", "threat_name": "T:A/B",
          "path": r"C:\x\a.dll", "datetime": "2026-04-04T20:14:00Z"},
         {"source": "directory_scan", "threat_name": "",
          "path": r"C:\q\b.nqf", "datetime": "2020/10/18  09:10"}]
res5, _, errs5, _ = a.call_llm_chunked(_Cli, "dummy", "defender_quarantine", 2, chunk)
check("D-5: chunk_errorsなし", errs5 == [], str(errs5))
d5 = {e.get("datetime"): e for e in res5}
check("D-5: defender_eventlog 由来の datetime が付与される",
      "2026-04-04T20:14:00Z" in d5, str(res5))
check("D-5: directory_scan 由来は kind=更新 も付与される",
      d5.get("2020/10/18  09:10", {}).get("datetime_kind") == "更新", str(res5))

print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
