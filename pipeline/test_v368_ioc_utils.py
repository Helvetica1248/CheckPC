# -*- coding: utf-8 -*-
"""test_v368_ioc_utils.py — v3.68 IOC 共通化（D-1）の回帰テスト。

移設前後の挙動同一（golden fixture）と、証拠抽出/VT判定の責務分離を検証する。
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _c in (os.environ.get("CHECKPC_SCRIPTS", ""), HERE,
           os.path.dirname(HERE), "/opt/llm/analysis", "/home/claude/scripts"):
    if _c and os.path.exists(os.path.join(_c, "ioc_utils.py")):
        SCRIPTS = _c
        break
else:
    print("ioc_utils.py が見つかりません"); sys.exit(2)
sys.path.insert(0, SCRIPTS)

import ioc_utils as iu

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}"); PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1


def sec(t):
    print(f"\n{'-' * 60}\n  {t}\n{'-' * 60}")


# ════════════════════════════════════════════════════════════
sec("IU-1: 移設前後の分類が一致（golden fixture）")
# golden fixture をコード内に固定（移設前の vt_post._classify_ioc の期待値）
GOLDEN = {
    "d41d8cd98f00b204e9800998ecf8427e": "hash",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709": "hash",
    "1.2.3.4": "ip", "8.8.8.8": "ip", "10.0.0.1": None, "192.168.1.1": None,
    "172.16.0.1": None, "172.31.255.255": None, "172.32.0.1": "ip",
    "127.0.0.1": None, "169.254.1.1": None, "100.64.0.1": None,
    "1.2.3.4:443": "ip", "999.1.1.1": None,
    "example.com": "fqdn", "evil.example.com": "fqdn",
    "www.microsoft.com": None, "dns.google": None, "localhost": None,
    "server.corp.local": None, "foo.bar": None,
    "vipns4.queniudns.com": "fqdn", "github.com": None,
    "C:\\Windows\\System32\\svchost.exe": None,
    "C:\\Users\\a\\AppData\\Local\\Temp\\x64.exe": "filepath",
    "svchost.exe": None, "x64.exe": None, "Zotero.dotm": None, "report.pdf": None,
}
for val, exp in GOLDEN.items():
    got = iu.classify_ioc(val)
    check(f"IU-1: classify_ioc({val[:36]}) == {exp}", got == exp, f"got={got}")

sec("IU-2/3/4: Windows パス/ファイル名/内部FQDN を FQDN 誤認しない")
check("IU-2: Windows パスは fqdn にならない",
      iu.classify_syntactic("C:\\Windows\\System32\\svchost.exe") != "fqdn")
check("IU-3: ファイル名 svchost.exe は fqdn にならない",
      iu.classify_syntactic("svchost.exe") != "fqdn")
check("IU-4: server.corp.local は fqdn にならない（TLD検証）",
      iu.classify_syntactic("server.corp.local") != "fqdn")

sec("IU-5: プライベートIP判定")
check("IU-5: 1.2.3.4 は private でない", not iu.is_private_ip("1.2.3.4"))
check("IU-5: 10.0.0.1 は private", iu.is_private_ip("10.0.0.1"))
check("IU-5: 100.64.0.1(CGNAT) は private 扱い", iu.is_private_ip("100.64.0.1"))

sec("IU-6/7: メール抽出")
recs = iu.extract_evidence_iocs("連絡先は user@contoso.com です", "reason")
check("IU-6: メールを証拠抽出", any(r["type"] == "email" for r in recs))
recs2 = iu.extract_evidence_iocs("a@b というのは TLD なし", "reason")
check("IU-7: TLDなし a@b はメール誤検出しない",
      not any(r["value"] == "a@b" for r in recs2))

sec("IU-8: ハッシュ検出")
recs = iu.extract_evidence_iocs("SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709", "threat")
check("IU-8: SHA-1 を証拠抽出", any(r["type"] == "hash" for r in recs))

sec("IU-9: 証拠に source_field / excerpt / フラグ")
recs = iu.extract_evidence_iocs("外部 1.2.3.4 と MS の update.microsoft.com へ接続", "path")
ips = [r for r in recs if r["type"] == "ip"]
check("IU-9: source_field が保持される", all(r["source_field"] == "path" for r in recs))
check("IU-9: 外部IP は private=False", any(not r["private"] for r in ips) if ips else True)
fqdns = [r for r in recs if r["type"] == "fqdn"]
check("IU-9: 既知インフラ(MS)は削除せず known_infra=True で保持",
      any(r.get("known_infra") for r in fqdns), str(fqdns))

sec("IU-10: Defender 脅威名から IOC を出さない")
recs = iu.extract_evidence_iocs("Trojan:Win32/Emotet.A!ml", "threat_name")
check("IU-10: 脅威名文字列から偽IOCを出さない",
      not any(r["type"] in ("ip", "fqdn") for r in recs), str(recs))

sec("IU-11/12/14: 決定論・重複排除")
r1 = iu.extract_evidence_iocs("1.2.3.4 1.2.3.4 evil.com evil.com", "x")
check("IU-12: 重複排除（大小無視で一意）",
      sum(1 for r in r1 if r["value"] == "1.2.3.4") == 1)
r2 = iu.extract_evidence_iocs("1.2.3.4 1.2.3.4 evil.com evil.com", "x")
check("IU-14: 決定論（同一入力→同一出力）",
      [r["value"] for r in r1] == [r["value"] for r in r2])

sec("IU-VT: should_query_vt の責務分離")
check("VT: 外部IP は照合対象", iu.should_query_vt("1.2.3.4")[0] is True)
check("VT: private IP は照合しない", iu.should_query_vt("10.0.0.1")[0] is False)
check("VT: 既知インフラ FQDN は照合しない",
      iu.should_query_vt("update.microsoft.com")[0] is False)
check("VT: 未知 FQDN は照合対象", iu.should_query_vt("evil.example.com")[0] is True)
check("VT: メールは照合対象外", iu.should_query_vt("a@b.com")[0] is False)

sec("IU-URL: URL から host 抽出")
check("URL: host 抽出", iu.url_host("http://evil.com/a.php") == "evil.com")
recs = iu.extract_evidence_iocs("http://evil.example.com/x への接続", "cmd")
check("URL: URL と host(fqdn) の両方を証拠化",
      any(r["type"] == "url" for r in recs) and any(r["type"] == "fqdn" for r in recs))

sec("IU-13: vt_post 後方互換の別名")
try:
    spec = importlib.util.spec_from_file_location("vt_post", f"{SCRIPTS}/vt_post.py")
    vt = importlib.util.module_from_spec(spec); spec.loader.exec_module(vt)
    check("IU-13: vt_post._classify_ioc 別名が動く",
          vt._classify_ioc("1.2.3.4") == "ip")
except Exception as e:
    check("IU-13: vt_post import", False, str(e))


print(f"\n{'=' * 60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS + FAIL}")
print(f"{'=' * 60}")
print(f"PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
