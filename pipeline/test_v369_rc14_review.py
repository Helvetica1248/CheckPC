#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 regressions: VT truthfulness and Defender threat-name stability."""

import copy
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import ioc_utils as iu
import correlate
import report_gen
import vt_post
from pdf_export import md_to_pdf
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION, BUDGET_PROFILE_DEFAULT

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}")
        PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else ""))
        FAIL += 1


def sec(title):
    print(f"\n{'-' * 64}\n  {title}\n{'-' * 64}")


sec("RC14 version")
check("RC14 pipeline", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("RC14 schema", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("RC14 profile", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)


sec("Defender threat names remain literal evidence")
threats = [
    "Trojan:MSIL/Darkvigil.NWA!MTB",
    "Program:Script/Wacapew.A!ml",
    "Trojan:Win32/ComHijackTypeLibScript.A",
    "Behavior:Win32/Persistence.A!ml",
]
for threat in threats:
    norm, port = iu.normalize_evidence_ioc(threat)
    detail = iu.normalize_evidence_ioc_detail(threat)
    check(f"literal preserved: {threat}", norm == threat and port is None, repr((norm, port)))
    check(f"dedicated kind: {threat}",
          detail.get("ioc") == threat
          and detail.get("ioc_normalization_kind") == "defender_threat_name"
          and detail.get("ioc_port") is None, repr(detail))
    check(f"not VT filepath: {threat}", iu.classify_ioc(threat) is None,
          repr(iu.classify_ioc(threat)))
    check(f"syntactic malware_name: {threat}", iu.classify_syntactic(threat) == "malware_name",
          repr(iu.classify_syntactic(threat)))

check("malware_name never queried",
      iu.should_query_vt(threats[0]) == (False, "malware_name_not_vt_target"),
      repr(iu.should_query_vt(threats[0])))
check("ordinary Windows path still normalizes separators",
      iu.normalize_evidence_ioc("C:/Temp/evil.exe")[0] == r"C:\Temp\evil.exe")
check("URL normalization unaffected",
      iu.normalize_evidence_ioc("HTTP://Example.COM/A/B")[0] == "http://example.com/A/B")

corr = {
    "correlated_iocs": [
        {"ioc": t, "found_in": ["defender_quarantine"], "significance": "Defender detection"}
        for t in threats
    ]
}
correlate._normalize_correlation_iocs(corr)
check("correlation retains all threat names",
      [x.get("ioc") for x in corr["correlated_iocs"]] == threats,
      repr(corr["correlated_iocs"]))
check("correlation marks dedicated kind",
      all(x.get("ioc_normalization_kind") == "defender_threat_name"
          for x in corr["correlated_iocs"]), repr(corr["correlated_iocs"]))
check("correlation never rewrites slash",
      all("\\" not in x.get("ioc", "") for x in corr["correlated_iocs"]),
      repr(corr["correlated_iocs"]))


sec("VT entry state is conservative")
check("no results = not_queried", report_gen._vt_entry_status([]) == "not_queried")
check("clean only = clean",
      report_gen._vt_entry_status([{"verdict": "clean"}]) == "clean")
check("unknown = unknown",
      report_gen._vt_entry_status([{"verdict": "unknown"}]) == "unknown")
check("error beats clean",
      report_gen._vt_entry_status([{"verdict": "clean"}, {"verdict": "error"}]) == "error")
check("fmt_vt error beats clean",
      "エラー" in report_gen.fmt_vt([
          {"verdict": "clean", "total": 70},
          {"verdict": "error", "vt_error": "proxy_error"},
      ]))
check("suspicious beats error",
      report_gen._vt_entry_status([{"verdict": "error"}, {"verdict": "suspicious"}]) == "suspicious")
check("fmt_vt no result explicitly says 未照合", "未照合" in report_gen.fmt_vt([]))


def low(identifier, results=None):
    e = {"score": "LOW", "identifier": identifier, "reason": "network evidence"}
    if results is not None:
        e["_vt_results"] = results
    return e

entries = [
    low("10.0.0.1:50000 → 8.8.8.8:443", [{"verdict": "clean"}]),
    low("10.0.0.1:50001 → 1.1.1.1:443", [{"verdict": "error", "vt_error": "proxy_error"}]),
    low("10.0.0.1:50002 → 9.9.9.9:443", [{"verdict": "unknown"}]),
    low("10.0.0.1:50003 → 4.4.4.4:443"),
    low("10.0.0.1:50004 → 5.5.5.5:80", [{"verdict": "clean"}, {"verdict": "error"}]),
]
agg = "\n".join(report_gen._aggregate_low_entries(entries, "netstat"))
check("aggregate identifies clean", "クリーン" in agg, agg)
check("aggregate identifies error", "エラー／未確認" in agg, agg)
check("aggregate identifies not_found", "未登録" in agg, agg)
check("aggregate identifies not_queried", "未照合" in agg, agg)
check("legacy false label removed", "外部 HTTPS (443) — VT クリーン" not in agg, agg)
check("mixed clean/error is not represented as clean group",
      "外部 HTTP (80) | `5.5.5.5` | 1 | ⚠ エラー／未確認" in agg, agg)


sec("VT unique-target summary")
original_lookup = vt_post.lookup_ioc
try:
    verdicts = {
        "1.1.1.1": "clean",
        "2.2.2.2": "malicious",
        "3.3.3.3": "suspicious",
        "4.4.4.4": "unknown",
        "5.5.5.5": "error",
        "6.6.6.6": "skipped",
    }

    def fake_lookup(value, api_key, proxies=None, rate_delay=0, ioc_type=None, timeout=0):
        verdict = verdicts[value]
        if verdict == "skipped":
            return {"ioc": value, "ioc_type": ioc_type, "skipped": True}
        return {
            "ioc": value, "ioc_type": ioc_type, "verdict": verdict,
            "positives": 5 if verdict == "malicious" else 1 if verdict == "suspicious" else 0,
            "total": 70, "vt_names": [], "vt_url": "", "vt_error": "proxy_error" if verdict == "error" else "",
        }

    vt_post.lookup_ioc = fake_lookup
    analyzed = {
        "meta": {"hostname": "TEST", "pipeline_version": PIPELINE_VERSION,
                 "analysis_schema_version": ANALYSIS_SCHEMA_VERSION},
        "depth": 1,
        "sections": {
            "netstat": {
                "entries": [
                    {"score": "MEDIUM", "identifier": f"x{i}", "reason": "x", "iocs": [ip]}
                    for i, ip in enumerate(verdicts, 1)
                ]
            }
        },
    }
    enriched = vt_post.vt_enrich(copy.deepcopy(analyzed), api_key="dummy",
                                 rate_delay=0, max_workers=1, verbose=False)
    counts = enriched.get("_vt_summary", {}).get("status_counts", {})
    check("status_counts clean", counts.get("clean") == 1, repr(counts))
    check("status_counts malicious", counts.get("malicious") == 1, repr(counts))
    check("status_counts suspicious", counts.get("suspicious") == 1, repr(counts))
    check("status_counts not_found", counts.get("not_found") == 1, repr(counts))
    check("status_counts error", counts.get("error") == 1, repr(counts))
    check("status_counts not_queried", counts.get("not_queried") == 1, repr(counts))
    summary_text = report_gen._fmt_vt_summary(enriched["_vt_summary"])
    check("summary reports exact scope", "正確IOC照合" in summary_text, summary_text)
    check("summary reports completed count", "判定完了 4 件" in summary_text, summary_text)
    check("summary reports error count", "エラー 1 件" in summary_text, summary_text)
    check("summary reports not queried count", "未照合 1 件" in summary_text, summary_text)
finally:
    vt_post.lookup_ioc = original_lookup

legacy = report_gen._fmt_vt_summary({"total_iocs": 109, "errors": 36,
                                     "filepath_searched": 73})
check("legacy summary does not infer clean", "クリーン" not in legacy, legacy)
check("legacy summary flags incomplete error floor", "エラー 36 件以上" in legacy, legacy)


sec("Report/PDF path does not claim VT clean on errors")
analyzed_report = {
    "meta": {"hostname": "TEST", "pipeline_version": PIPELINE_VERSION,
             "analysis_schema_version": ANALYSIS_SCHEMA_VERSION},
    "depth": 1,
    "_vt_summary": {
        "total_iocs": 1,
        "status_counts": {"malicious": 0, "suspicious": 0, "clean": 0,
                          "not_found": 0, "error": 1, "not_queried": 0},
    },
    "sections": {
        "netstat": {
            "entries": [low("10.0.0.1:50001 → 1.1.1.1:443",
                            [{"verdict": "error", "vt_error": "proxy_error"}])],
            "section_summary": "network",
        }
    },
}
correlation = {"infection_suspicion": "LOW", "infection_summary": "test",
               "malware_family": "Unknown", "correlated_iocs": [],
               "timeline": [], "mitre_ttps": [], "recommended_actions": []}
md = report_gen.generate_report(analyzed_report, correlation, full=False)
check("report header shows VT error", "エラー 1 件" in md, md[:1200])
check("report body shows VT error/unconfirmed", "エラー／未確認" in md, md)
check("report does not claim VT clean", "VT クリーン" not in md, md)
pdf = md_to_pdf(md, title="rc14 VT report")
check("PDF export completes", pdf.startswith(b"%PDF") and len(pdf) > 1000, str(len(pdf)))

print(f"\n{'=' * 64}")
print(f"PASS={PASS} FAIL={FAIL}")
print(f"{'=' * 64}")
sys.exit(1 if FAIL else 0)
