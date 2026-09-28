#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 regressions: service evidence fidelity and VT scope separation."""

import copy
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import analyze_section
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
    print(f"\n{'-' * 68}\n  {title}\n{'-' * 68}")


sec("RC15 version")
check("RC15 pipeline", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("RC15 schema", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("RC15 profile", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)


sec("VT candidate overflow is not not_found")


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


orig_get = vt_post.requests.get
try:
    vt_post.requests.get = lambda *a, **k: FakeResponse(
        200, {"meta": {"count": 501}, "data": [{"id": "x", "attributes": {}}]}
    )
    overflow = vt_post._vt_search_by_name("common.exe", "dummy", None)
    check("overflow verdict", overflow.get("verdict") == "too_many_hits", repr(overflow))
    check("overflow retains hit count", overflow.get("total_hits") == 501, repr(overflow))
    check("overflow is not unknown", overflow.get("verdict") != "unknown", repr(overflow))

    vt_post.requests.get = lambda *a, **k: FakeResponse(
        200, {"meta": {"count": 0}, "data": []}
    )
    no_results = vt_post._vt_search_by_name("missing.exe", "dummy", None)
    check("no result remains unknown", no_results.get("verdict") == "unknown", repr(no_results))
    check("no result reason", no_results.get("vt_error") == "no_results", repr(no_results))
finally:
    vt_post.requests.get = orig_get

score, changed, note = vt_post.apply_vt_score(
    "MEDIUM",
    {"verdict": "too_many_hits", "total_hits": 1234, "vt_error": "hits=1234>max(500)"},
    ioc_type="filepath",
)
check("overflow never changes score", score == "MEDIUM" and not changed, repr((score, changed)))
check("overflow note is explicit", "候補過多" in note and "判定不能" in note, note)
check("report status preserves overflow",
      report_gen._vt_entry_status([{"verdict": "too_many_hits"}]) == "too_many_hits")
check("overflow beats clean",
      report_gen._vt_entry_status([
          {"verdict": "clean"}, {"verdict": "too_many_hits"}
      ]) == "too_many_hits")
check("error beats overflow",
      report_gen._vt_entry_status([
          {"verdict": "too_many_hits"}, {"verdict": "error"}
      ]) == "error")
check("fmt_vt labels overflow",
      "候補過多" in report_gen.fmt_vt([
          {"verdict": "too_many_hits", "ioc_type": "filepath", "total_hits": 777}
      ]))


sec("VT exact/reference scopes remain separate")
orig_lookup = vt_post.lookup_ioc
try:
    verdicts = {
        "1.1.1.1": ("malicious", "ip"),
        "2.2.2.2": ("clean", "ip"),
        "3.3.3.3": ("unknown", "ip"),
        "4.4.4.4": ("error", "ip"),
        "a.exe": ("malicious", "filepath"),
        "b.exe": ("suspicious", "filepath"),
        "c.exe": ("clean", "filepath"),
        "d.exe": ("unknown", "filepath"),
        "e.exe": ("too_many_hits", "filepath"),
        "f.exe": ("error", "filepath"),
    }

    def fake_lookup(value, api_key, proxies=None, rate_delay=0, ioc_type=None, timeout=0):
        verdict, expected_type = verdicts[value]
        return {
            "ioc": value,
            "ioc_type": expected_type,
            "verdict": verdict,
            "positives": 7 if verdict == "malicious" else 1 if verdict == "suspicious" else 0,
            "total": 70,
            "total_hits": 900 if verdict == "too_many_hits" else 1,
            "vt_names": [],
            "vt_url": "",
            "vt_error": (
                "hits=900>max(500)" if verdict == "too_many_hits"
                else "no_results" if verdict == "unknown" and expected_type == "filepath"
                else "proxy_error" if verdict == "error"
                else "VT未登録" if verdict == "unknown"
                else ""
            ),
        }

    vt_post.lookup_ioc = fake_lookup
    entries = []
    for value in ("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"):
        entries.append({"score": "MEDIUM", "identifier": value, "reason": "x", "iocs": [value]})
    for name in ("a.exe", "b.exe", "c.exe", "d.exe", "e.exe", "f.exe"):
        entries.append({
            "score": "MEDIUM", "identifier": name, "reason": "x",
            "iocs": [rf"C:\\Temp\\{name}"],
        })
    analyzed = {
        "meta": {"hostname": "TEST", "pipeline_version": PIPELINE_VERSION,
                 "analysis_schema_version": ANALYSIS_SCHEMA_VERSION},
        "depth": 1,
        "sections": {"directory": {"entries": entries}},
    }
    enriched = vt_post.vt_enrich(copy.deepcopy(analyzed), api_key="dummy",
                                 rate_delay=0, max_workers=1)
    summ = enriched["_vt_summary"]
    exact = summ["exact_status_counts"]
    fp = summ["filepath_status_counts"]
    combined = summ["status_counts"]
    check("exact target count", summ.get("exact_total_iocs") == 4, repr(summ))
    check("filepath target count", summ.get("filepath_total_iocs") == 6, repr(summ))
    check("exact malicious only exact", exact.get("malicious") == 1, repr(exact))
    check("filepath malicious separate", fp.get("malicious") == 1, repr(fp))
    check("filepath suspicious separate", fp.get("suspicious") == 1, repr(fp))
    check("filepath overflow separate", fp.get("too_many_hits") == 1, repr(fp))
    check("combined overflow retained", combined.get("too_many_hits") == 1, repr(combined))
    check("overflow counter", summ.get("filepath_too_many_hits") == 1, repr(summ))
    check("no_results only not_found", fp.get("not_found") == 1, repr(fp))
    text = report_gen._fmt_vt_summary(summ)
    check("summary names exact scope", "正確IOC照合" in text, text)
    check("summary names filepath scope", "filepath参考検索" in text, text)
    check("exact malicious shown", "正確IOC照合: 対象 4 件" in text and "悪性 1 件" in text, text)
    check("filepath malicious qualified", "同名悪性 1 件" in text, text)
    check("overflow shown separately", "候補過多 1 件" in text, text)
    check("summary has line break", "<br>" in text, text)
finally:
    vt_post.lookup_ioc = orig_lookup

corr = {
    "infection_suspicion": "NONE",
    "infection_summary": "test",
    "malware_family": "Unknown",
    "correlated_iocs": [],
    "timeline": [],
    "mitre_ttps": [],
    "recommended_actions": [],
}
md = report_gen.generate_report(enriched, corr, full=False)
check("report separates exact VT scope", "正確IOC照合" in md, md[:500])
check("report separates filepath reference scope", "filepath参考検索" in md, md[:500])
check("report explains overflow is not unregistered",
      "候補過多による照合不能" in md, md[-2000:])
with tempfile.TemporaryDirectory() as td:
    pdf_path = os.path.join(td, "rc15.pdf")
    try:
        pdf_bytes = md_to_pdf(md, "rc15")
        with open(pdf_path, "wb") as f:
            f.write(pdf_bytes)
        pdf_ok = os.path.isfile(pdf_path) and os.path.getsize(pdf_path) > 0
    except Exception as exc:
        pdf_ok = False
        pdf_detail = repr(exc)
    else:
        pdf_detail = os.path.getsize(pdf_path)
    check("split VT summary exports to PDF", pdf_ok, pdf_detail)


sec("system_7045 raw evidence is authoritative")
base = r"C:\Program Files\WindowsApps\Microsoft.GamingServices_35.112.23002.0_x64__8wekyb3d8bbwe"
raw_gaming = [
    {"service_name": "GamingServicesNet", "image_path": base + r"\GamingServicesNet.exe",
     "account_name": "LocalSystem", "datetime": "2026-05-09T00:00:00Z"},
    {"service_name": "GamingServices", "image_path": base + r"\GamingServices.exe",
     "account_name": "LocalSystem", "datetime": "2026-06-02T00:00:00Z"},
]
sec_result = {
    "entries": [
        {"source_index": 0, "identifier": "RustDesk Service", "score": "HIGH",
         "reason": "ImagePath is AppData RustDesk", "mitre": ["T1219"],
         "iocs": [r"C:\Users\x\AppData\RustDesk.exe"]},
        {"source_index": 1, "identifier": "RustDesk Service", "score": "LOW",
         "reason": "RustDesk", "mitre": ["T1219"], "iocs": []},
    ],
    "section_summary": "RustDesk services in AppData",
}
out = analyze_section._apply_post_filter("system_7045", copy.deepcopy(sec_result), raw_gaming)
entries = out["entries"]
check("GamingServices names restored",
      [e.get("identifier") for e in entries] == ["GamingServicesNet", "GamingServices"], repr(entries))
check("GamingServices deterministic CLEAN",
      all(e.get("score") == "CLEAN" for e in entries), repr(entries))
check("GamingServices strict identity kind",
      all(e.get("service_identity_kind") == "microsoft_gaming_services" for e in entries), repr(entries))
check("GamingServices executable restored",
      entries[0].get("service_executable", "").endswith("GamingServicesNet.exe")
      and entries[1].get("service_executable", "").endswith("GamingServices.exe"), repr(entries))
check("GamingServices T1219 removed",
      all("T1219" not in (e.get("mitre") or []) for e in entries), repr(entries))
check("LLM identifiers retained only for audit",
      all(e.get("llm_identifier_raw") == "RustDesk Service" for e in entries), repr(entries))
check("reconciliation warning recorded",
      all(e.get("evidence_reconciled") is True for e in entries), repr(entries))
check("summary no false RustDesk", "RustDesk" not in out.get("section_summary", ""), out.get("section_summary"))
check("summary reflects clean count", "CLEAN=2" in out.get("section_summary", ""), out.get("section_summary"))
check("summary lists raw service names",
      "GamingServicesNet" in out.get("section_summary", "")
      and "GamingServices" in out.get("section_summary", ""), out.get("section_summary"))

crossed = analyze_section._apply_post_filter("system_7045", {
    "entries": [{"source_index": 0, "identifier": "RustDesk Service", "score": "LOW",
                 "reason": "x", "mitre": ["T1219"], "iocs": []}],
}, [{"service_name": "GamingServices",
     "image_path": base + r"\GamingServicesNet.exe"}])["entries"][0]
check("GamingServices name/executable mismatch is not CLEAN",
      crossed.get("score") != "CLEAN", repr(crossed))

raw_rustdesk = [{
    "service_name": "RustDesk Service",
    "image_path": r'"C:\Program Files\RustDesk\RustDesk.exe" --service',
    "account_name": "LocalSystem",
}]
rust_in = {"entries": [{
    "source_index": 0, "identifier": "GamingServices", "score": "LOW",
    "reason": "wrong", "mitre": [], "iocs": [],
}]}
rust = analyze_section._apply_post_filter("system_7045", copy.deepcopy(rust_in), raw_rustdesk)["entries"][0]
check("raw RustDesk name wins", rust.get("identifier") == "RustDesk Service", repr(rust))
check("real RustDesk Program Files MEDIUM", rust.get("score") == "MEDIUM", repr(rust))
check("real RustDesk retains T1219", "T1219" in rust.get("mitre", []), repr(rust))
check("real RustDesk executable", rust.get("service_executable") == r"C:\Program Files\RustDesk\RustDesk.exe", repr(rust))

# Reproduce the rc14 failure mode: filtered position points at GamingServices,
# while stable source_id identifies the actual RustDesk event.
raw_reordered = [
    {"source_id": "gaming", "service_name": "GamingServicesNet",
     "image_path": base + r"\GamingServicesNet.exe"},
    {"source_id": "rust", "service_name": "RustDesk Service",
     "image_path": r'"C:\Program Files\RustDesk\RustDesk.exe" --service'},
]
reordered = analyze_section._apply_post_filter("system_7045", {
    "entries": [{"source_index": 0, "_raw_source_index": 0, "source_id": "rust",
                 "identifier": "RustDesk Service", "score": "LOW", "reason": "x",
                 "mitre": [], "iocs": []}],
}, raw_reordered)["entries"][0]
check("source_id wins over stale raw index", reordered.get("service_executable") == r"C:\Program Files\RustDesk\RustDesk.exe", repr(reordered))
check("stale index cannot create GamingServices mismatch", reordered.get("identifier") == "RustDesk Service" and reordered.get("score") == "MEDIUM", repr(reordered))

raw_user = [{
    "service_name": "RustDesk Service",
    "image_path": r"C:\Users\x\AppData\Local\RustDesk\RustDesk.exe --service",
}]
user = analyze_section._apply_post_filter("system_7045", copy.deepcopy(rust_in), raw_user)["entries"][0]
check("real RustDesk user-write HIGH", user.get("score") == "HIGH", repr(user))

raw_unknown = [{
    "service_name": "Acme Update Service",
    "image_path": r"C:\Program Files\Acme\updater.exe",
}]
unknown_in = {"entries": [{
    "source_index": 0, "identifier": "RustDesk Service", "score": "HIGH",
    "reason": "hallucinated remote tool", "mitre": ["T1219"], "iocs": [],
}]}
unknown = analyze_section._apply_post_filter(
    "system_7045", copy.deepcopy(unknown_in), raw_unknown
)["entries"][0]
check("unknown raw name replaces hallucination", unknown.get("identifier") == "Acme Update Service", repr(unknown))
check("unknown safe path converges MEDIUM", unknown.get("score") == "MEDIUM", repr(unknown))
check("hallucinated T1219 removed", "T1219" not in unknown.get("mitre", []), repr(unknown))
check("service creation technique retained", "T1543.003" in unknown.get("mitre", []), repr(unknown))
check("original reason retained for audit", unknown.get("llm_reason_raw") == "hallucinated remote tool", repr(unknown))

raw_unknown_user = [{
    "service_name": "Acme Update Service",
    "image_path": r"C:\Users\Public\acme.exe",
}]
unknown_user = analyze_section._apply_post_filter(
    "system_7045", copy.deepcopy(unknown_in), raw_unknown_user
)["entries"][0]
check("mismatched user-write path HIGH", unknown_user.get("score") == "HIGH", repr(unknown_user))

# Backward compatibility: raw evidence unavailable in isolated historical fixtures.
legacy = analyze_section._apply_post_filter("system_7045", {
    "entries": [{"identifier": "RustDesk Service", "score": "LOW", "reason": "",
                 "iocs": [r"C:\Program Files\RustDesk\RustDesk.exe"]}]
}, None)["entries"][0]
check("legacy fixture fallback retained", legacy.get("score") == "MEDIUM", repr(legacy))

print(f"\nRESULT: PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
