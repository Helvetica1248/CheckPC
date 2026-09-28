#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 Claude follow-up regressions: correlation, IOC, ledger, release."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

import compare_analyzed as cmp
import correlate as corr
import ioc_utils as iu
from budget_profile import active_profile
from generate_release_manifest import _load_test_summary
from provenance import DispositionLedger, PlannedItem
from report_gen import generate_report
from section_prompts import get_prompt, get_system_prompt
from token_budget import MAX_MODEL_LEN
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}" + (f" :: {detail}" if detail else ""))


def doc_one():
    return {"meta": {"hostname": "RC10"}, "sections": {"directory": {"entries": [
        {"identifier": r"C:\\Temp\\x.exe", "score": "HIGH", "reason": "r", "iocs": []},
        {"identifier": r"C:\\Temp\\y.exe", "score": "MEDIUM", "reason": "m", "iocs": []},
    ]}}}


check("R1 pipeline version", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("R2 schema version", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("R3 profile version", active_profile().name == "v370", active_profile().name)

# Token allocation: initial and retry include system + chat overhead and never exceed context.
for depth in (1, 2, 3, 4):
    desired = {1: 2048, 2: 2048, 3: 2048, 4: 4096}[depth]
    initial_budget = corr._data_budget_for_output(get_prompt("correlate", depth), desired)
    data, _ = corr.build_correlate_text(corr.extract_high_medium(doc_one()), depth, initial_budget)
    initial_msg = get_prompt("correlate", depth).replace("{data}", data)
    initial = corr._available_output_tokens(initial_msg, desired)
    retry_budget = corr._data_budget_for_output(
        corr._compact_retry_user_message("{data}"), corr.CORRELATE_RETRY_MAX_TOKENS)
    retry_data, _ = corr.build_correlate_text(
        corr.extract_high_medium(doc_one()), depth, retry_budget)
    retry = corr._available_output_tokens(
        corr._compact_retry_user_message(retry_data), corr.CORRELATE_RETRY_MAX_TOKENS)
    check(f"R4 depth{depth} initial allocation bounded",
          initial["estimated_total_tokens"] <= MAX_MODEL_LEN, initial)
    check(f"R5 depth{depth} retry allocation bounded",
          retry["estimated_total_tokens"] <= MAX_MODEL_LEN, retry)
    check(f"R6 depth{depth} retry max >= initial max",
          retry["max_tokens"] >= initial["max_tokens"], (initial, retry))

# First length -> second length + malformed JSON: fallback is explicit and calls stop at two.
responses = [
    SimpleNamespace(text='{"infection_suspicion":"HIGH",', error=None, finish_reason="length"),
    SimpleNamespace(text='{"infection_suspicion":"HIGH",', error=None, finish_reason="length"),
]
calls = []
orig_create, orig_extract = corr.create_chat_completion, corr.extract_llm_text
try:
    def fake_create(*args, **kwargs):
        calls.append(kwargs)
        return responses.pop(0)
    corr.create_chat_completion = fake_create
    corr.extract_llm_text = lambda x: x
    twice = corr.correlate(doc_one(), 2, object(), "stub")
finally:
    corr.create_chat_completion, corr.extract_llm_text = orig_create, orig_extract
retry = twice.get("_correlate_retry", {})
check("R7 double truncation falls back", retry.get("fallback_applied") is True, twice)
check("R8 double truncation recorded", retry.get("truncated_twice") is True, retry)
check("R9 LLM is called at most twice", len(calls) == 2, len(calls))
check("R10 fallback keeps deterministic suspicion", twice.get("infection_suspicion") == "HIGH", twice)

# Retry build failure is contained and audited.
real_build = corr.build_correlate_text
count = {"n": 0}
try:
    def flaky_build(*args, **kwargs):
        count["n"] += 1
        if count["n"] == 2:
            raise ValueError("synthetic retry build failure")
        return real_build(*args, **kwargs)
    corr.build_correlate_text = flaky_build
    corr.create_chat_completion = lambda *a, **k: SimpleNamespace(
        text='{"infection_suspicion":"HIGH",', error=None, finish_reason="length")
    corr.extract_llm_text = lambda x: x
    build_fail = corr.correlate(doc_one(), 2, object(), "stub")
finally:
    corr.build_correlate_text = real_build
    corr.create_chat_completion, corr.extract_llm_text = orig_create, orig_extract
check("R11 retry build error recorded",
      "synthetic retry build failure" in build_fail.get("_correlate_retry", {}).get("retry_build_error", ""), build_fail)
check("R12 retry build error applies fallback",
      build_fail.get("_correlate_retry", {}).get("fallback_applied") is True, build_fail)

# Retry LLM exception is contained.
step = {"n": 0}
try:
    def retry_raises(*args, **kwargs):
        step["n"] += 1
        if step["n"] == 1:
            return SimpleNamespace(text='{"infection_suspicion":"HIGH",', error=None, finish_reason="length")
        raise RuntimeError("retry transport failure")
    corr.create_chat_completion = retry_raises
    corr.extract_llm_text = lambda x: x
    retry_fail = corr.correlate(doc_one(), 2, object(), "stub")
finally:
    corr.create_chat_completion, corr.extract_llm_text = orig_create, orig_extract
check("R13 retry exception recorded",
      "retry transport failure" in retry_fail.get("_correlate_retry", {}).get("retry_error", ""), retry_fail)
check("R14 retry exception does not escape",
      retry_fail.get("_correlate_retry", {}).get("fallback_applied") is True, retry_fail)

# Parseable JSON with length is retained and visibly marked.
parseable = {
    "infection_suspicion": "HIGH", "infection_summary": "x", "malware_family": "Unknown",
    "correlated_iocs": [], "timeline": [], "mitre_ttps": [], "recommended_actions": [],
}
try:
    corr.create_chat_completion = lambda *a, **k: SimpleNamespace(
        text=json.dumps(parseable), error=None, finish_reason="length")
    corr.extract_llm_text = lambda x: x
    retained = corr.correlate(doc_one(), 2, object(), "stub")
finally:
    corr.create_chat_completion, corr.extract_llm_text = orig_create, orig_extract
check("R15 parseable length result retained", retained.get("infection_summary") == "x", retained)
check("R16 parseable length marked truncated", retained.get("output_truncated") is True, retained)
report = generate_report(doc_one(), retained)
check("R17 report warns about truncation", "横断相関出力の制限" in report, report[:500])

# Correlation IOC normalization, raw preservation and report port rendering.
raw_corr = {
    "infection_suspicion": "HIGH", "infection_summary": "x", "malware_family": "Unknown",
    "correlated_iocs": [
        {"ioc": "1.2.3.4:443", "found_in": ["netstat"], "significance": "x"},
        {"ioc": "[2001:DB8::1]:8443", "found_in": ["netstat"], "significance": "v6"},
        {"ioc": "::ffff:192.168.0.1", "found_in": ["netstat"], "significance": "mapped"},
        {"ioc": "ABCDEF0123456789ABCDEF0123456789", "found_in": ["directory"], "significance": "hash"},
        {"ioc": "EXAMPLE.COM.", "found_in": ["dns_cache"], "significance": "fqdn"},
        {"ioc": "HTTP://Example.COM/Path/File.EXE?Token=AbC", "found_in": ["ps_history"], "significance": "url"},
        {"ioc": "192.168.0.1:99999", "found_in": ["netstat"], "significance": "bad"},
    ], "timeline": [], "mitre_ttps": [], "recommended_actions": [],
}
final = corr._finalize_correlation(raw_corr, {"hostname": "IOC"}, 2, doc_one(), {}, "stop")
by_raw = {x.get("ioc_raw", x.get("ioc")): x for x in final["correlated_iocs"]}
check("R18 IPv4 port separated", by_raw["1.2.3.4:443"].get("ioc") == "1.2.3.4" and by_raw["1.2.3.4:443"].get("ioc_port") == 443, by_raw)
check("R19 IPv6 port separated", by_raw["[2001:DB8::1]:8443"].get("ioc") == "2001:db8::1" and by_raw["[2001:DB8::1]:8443"].get("ioc_port") == 8443, by_raw)
check("R20 IPv4-mapped IPv6 dotted form", any(x.get("ioc") == "::ffff:192.168.0.1" for x in final["correlated_iocs"]), final)
check("R21 hash lowercase", any(x.get("ioc") == "abcdef0123456789abcdef0123456789" for x in final["correlated_iocs"]), final)
check("R22 FQDN normalized", any(x.get("ioc") == "example.com" for x in final["correlated_iocs"]), final)
check("R23 URL scheme/host only normalized", any(x.get("ioc") == "http://example.com/Path/File.EXE?Token=AbC" for x in final["correlated_iocs"]), final)
check("R24 invalid port retained and warned", by_raw["192.168.0.1:99999"].get("ioc_normalization_warning") == "invalid_port", by_raw)
ioc_report = generate_report(doc_one(), final)
check("R25 report renders IPv4 port", "`1.2.3.4:443`" in ioc_report, ioc_report)
check("R26 report renders bracketed IPv6 port", "`[2001:db8::1]:8443`" in ioc_report, ioc_report)

# Ledger add is atomic and freeze is complete before first yield.
ledger = DispositionLedger(5)
ledger.add(PlannedItem({}, 0, [0, 1], "selected", "r"))
_ = ledger.selected  # populate cache
bad = PlannedItem({}, 2, [2, 3, 99], "selected", "r")
try:
    ledger.add(bad)
except ValueError:
    pass
check("R27 ledger state unchanged after range error", ledger.selected == {0, 1}, ledger.selected)
check("R28 ledger items unchanged after range error", len(ledger._items) == 1, len(ledger._items))
check("R29 ledger cache not stale after error", ledger.indices("selected") == {0, 1}, ledger._indices_cache)
item = PlannedItem({}, 0, list(range(1000)), "selected", "r")
it = item.consume_source_indices()
next(it)
check("R30 early iterator abandonment keeps full ranges", item.to_audit()["source_index_ranges"] == [[0, 999]], item.to_audit())
check("R31 freeze is idempotent", item.source_index_ranges == [[0, 999]] and item.to_audit()["source_count"] == 1000)

# Duplicate source_id is a mandatory adjudication even if score multiset is unchanged.
a = {"sections": {"netstat": {"entries": [
    {"source_id": "sid-1", "identifier": "a", "score": "HIGH", "reason": "a", "iocs": []},
    {"source_id": "sid-1", "identifier": "b", "score": "MEDIUM", "reason": "b", "iocs": []},
]}}}
b = {"sections": {"netstat": {"entries": [
    {"source_id": "sid-1", "identifier": "c", "score": "MEDIUM", "reason": "c", "iocs": []},
    {"source_id": "sid-1", "identifier": "d", "score": "HIGH", "reason": "d", "iocs": []},
]}}}
fatal, adjud, _ = cmp.compare(a, b, False)
check("R32 duplicate source_id requires adjudication", any(x[0] == "ambiguous_source_id_bundle" for x in adjud), adjud)
check("R33 duplicate source_id is not guessed as fatal", not fatal, fatal)

# Machine summary loader requires directly generated shard/name/release metadata.
summary = {
    "summary_schema": 1, "release_mode": False,
    "pass": 10, "new_fail": 0, "known_fail": 0, "skip": 1, "error": 0,
    "release_blocked": False, "formal_release_eligible": False,
    "skipped_tests": ["test_real.py"],
    "shards": [{"index": 0, "count": 1, "pass": 10, "new_fail": 0,
                "known_fail": 0, "skip": 1, "error": 0,
                "skipped_tests": ["test_real.py"]}],
    "generated_at": "2026-07-22T00:00:00Z", "python": "3.13.0",
    "host": "host", "environment_label": "",
}
with tempfile.TemporaryDirectory() as td:
    path = Path(td) / "summary.json"
    path.write_text(json.dumps(summary), encoding="utf-8")
    loaded = _load_test_summary(path)
    check("R34 release loader preserves release_mode", loaded.get("release_mode") is False, loaded)
    check("R35 release loader preserves shards", loaded.get("shards") == summary["shards"], loaded)
    broken = dict(summary)
    broken["pass"] = 11
    path.write_text(json.dumps(broken), encoding="utf-8")
    try:
        _load_test_summary(path)
        rejected = False
    except ValueError:
        rejected = True
    check("R36 release loader rejects shard mismatch", rejected)

# Additional boundary and archive low-risk regressions.
zero = iu.normalize_evidence_ioc_detail("1.2.3.4:0")
over = iu.normalize_evidence_ioc_detail("1.2.3.4:65536")
maxp = iu.normalize_evidence_ioc_detail("1.2.3.4:65535")
check("R37 port zero is not separated", zero.get("ioc_port") is None and zero.get("ioc_normalization_warning") == "invalid_port", zero)
check("R38 port 65536 is rejected", over.get("ioc_port") is None and over.get("ioc_normalization_warning") == "invalid_port", over)
check("R39 port 65535 is accepted", maxp.get("ioc") == "1.2.3.4" and maxp.get("ioc_port") == 65535, maxp)
check("R40 UNC path is not damaged", iu.normalize_evidence_ioc_detail(r"\\server\share\Tool.EXE").get("ioc") == r"\\server\share\Tool.EXE")

capped = {"correlated_iocs": [], "timeline": [],
          "mitre_ttps": [f"T{i}" for i in range(corr.CORRELATE_MAX_TTPS + 3)],
          "recommended_actions": []}
corr._cap_correlation_output(capped)
check("R41 mitre_ttps hard cap", len(capped["mitre_ttps"]) == corr.CORRELATE_MAX_TTPS, capped.get("_output_limits"))

million = PlannedItem({}, 0, list(range(1_000_000)), "selected", "bulk")
million.freeze_source_indices()
check("R42 million indices compact to one range", million.source_index_ranges == [[0, 999999]], million.source_index_ranges)
check("R43 million freeze releases caller list", million._borrowed_source_indices is None and million.to_audit()["source_count"] == 1_000_000)

from archive_manager import ArchiveManager, ArchiveRequestError
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    job_root = root / "badroot"
    output = job_root / "archives" / "inside"
    output.mkdir(parents=True)
    job = {"job_id": "badroot", "status": "done", "output_dir": str(output),
           "hostname": "H", "finished_at": 0}
    mgr = ArchiveManager(root, queue_max=1, timeout_sec=1, large_threshold_mb=1)
    called = {"collect": False}
    original_collect = mgr._collect_sources
    try:
        def should_not_collect(*args, **kwargs):
            called["collect"] = True
            return []
        mgr._collect_sources = should_not_collect
        state = mgr._new_state(job, "full", "auto")
        mgr._states[("badroot", "full")] = state
        mgr._process({"job": job, "kind": "full", "compression": "auto"})
        bad_state = mgr.status("badroot", "full")
        check("R44 archive root validation precedes source walk", called["collect"] is False, bad_state)
        check("R45 invalid archive root is recorded", bad_state.get("error_kind") == "archive_root_invalid", bad_state)
    finally:
        mgr._collect_sources = original_collect
        mgr.shutdown()

with tempfile.TemporaryDirectory() as td:
    path = Path(td) / "large.bin"
    path.write_bytes(b"x" * 1024)
    try:
        ArchiveManager._hash_file(path, 0.0)
        timed_out = False
    except ArchiveRequestError as exc:
        timed_out = exc.error_kind == "archive_build_timeout"
    check("R46 archive hash obeys build deadline", timed_out)


# rc10: initial fallback paths always emit machine-readable metadata and report warnings.
def _assert_fallback_case(label, result, expected_reason):
    info = result.get("_correlate_retry", {})
    check(f"{label} metadata", info.get("fallback_applied") is True, result)
    check(f"{label} reason", info.get("fallback_reason") == expected_reason, info)
    rep = generate_report(doc_one(), result)
    check(f"{label} report warning", "横断相関フォールバック" in rep, rep[:1200])

real_build = corr.build_correlate_text
try:
    corr.build_correlate_text = lambda *a, **k: (_ for _ in ()).throw(ValueError("initial synthetic build"))
    initial_build = corr.correlate(doc_one(), 2, object(), "stub")
finally:
    corr.build_correlate_text = real_build
_assert_fallback_case("R47 initial build failure", initial_build, "initial_build_error")

real_alloc = corr._available_output_tokens
try:
    corr._available_output_tokens = lambda *a, **k: {
        "system_tokens": 1, "user_tokens": 1, "message_overhead_tokens": 1,
        "safety_margin_tokens": 1, "available_tokens": 100,
        "desired_max_tokens": 2048, "max_tokens": 100,
        "estimated_total_tokens": 104,
    }
    initial_budget = corr.correlate(doc_one(), 2, object(), "stub")
finally:
    corr._available_output_tokens = real_alloc
_assert_fallback_case("R50 initial output budget", initial_budget, "initial_budget_exhausted")

try:
    corr.create_chat_completion = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("initial transport"))
    initial_llm = corr.correlate(doc_one(), 2, object(), "stub")
finally:
    corr.create_chat_completion = orig_create
_assert_fallback_case("R53 initial LLM failure", initial_llm, "initial_llm_error")

# First stop+invalid JSON, retry length+invalid JSON is not a double truncation.
responses = [
    SimpleNamespace(text='not-json', error=None, finish_reason="stop"),
    SimpleNamespace(text='{"infection_suspicion":"HIGH",', error=None, finish_reason="length"),
]
try:
    corr.create_chat_completion = lambda *a, **k: responses.pop(0)
    corr.extract_llm_text = lambda x: x
    one_trunc = corr.correlate(doc_one(), 2, object(), "stub")
finally:
    corr.create_chat_completion, corr.extract_llm_text = orig_create, orig_extract
one_info = one_trunc.get("_correlate_retry", {})
check("R56 first stop is not truncated", one_info.get("first_truncated") is False, one_info)
check("R57 retry length is truncated", one_info.get("retry_truncated") is True, one_info)
check("R58 one truncation is not truncated_twice", one_info.get("truncated_twice") is False, one_info)

# Successful retry identifies the effective evidence input.
responses = [
    SimpleNamespace(text='not-json', error=None, finish_reason="stop"),
    SimpleNamespace(text=json.dumps(parseable), error=None, finish_reason="stop"),
]
try:
    corr.create_chat_completion = lambda *a, **k: responses.pop(0)
    corr.extract_llm_text = lambda x: x
    retry_ok = corr.correlate(doc_one(), 2, object(), "stub")
finally:
    corr.create_chat_completion, corr.extract_llm_text = orig_create, orig_extract
check("R59 retry supersedes initial input", retry_ok.get("_correlate_input", {}).get("superseded_by_retry") is True, retry_ok)
check("R60 retry is effective input", retry_ok.get("_correlate_input", {}).get("effective_input") == "retry", retry_ok)
check("R61 retry success has no fallback", retry_ok.get("_correlate_retry", {}).get("fallback_applied") is False, retry_ok)

# Empty/deduplicated IOC losses are counted; URL port stays in URL authority.
stats_corr = {
    "correlated_iocs": [
        {"ioc": "", "found_in": []},
        {"ioc": "   ", "found_in": []},
        {"ioc": "EXAMPLE.COM.", "found_in": ["dns"], "significance": "x"},
        {"ioc": "example.com", "found_in": ["dns"], "significance": "x"},
        {"ioc": "HTTPS://EXAMPLE.COM.:8443/Path", "found_in": ["net"], "significance": "u"},
        {"ioc": "1.2.3.4:65536", "found_in": ["net"], "significance": "bad"},
    ]
}
corr._normalize_correlation_iocs(stats_corr)
ns = stats_corr.get("_ioc_normalization", {})
check("R62 empty IOC drops counted", ns.get("dropped_empty_count") == 2, ns)
check("R63 semantic duplicates counted", ns.get("deduplicated_count") == 1, ns)
check("R64 invalid ports counted", ns.get("invalid_port_count") == 1, ns)
url_item = next(x for x in stats_corr["correlated_iocs"] if str(x.get("ioc", "")).startswith("https://"))
check("R65 URL port remains in authority", url_item.get("ioc") == "https://example.com:8443/Path", url_item)
check("R66 URL does not duplicate ioc_port", "ioc_port" not in url_item, url_item)

# Fallback reason must be one of the documented stable values.
allowed_reasons = {
    "initial_build_error", "initial_budget_exhausted", "initial_llm_error",
    "retry_build_error", "retry_budget_exhausted", "retry_llm_error",
    "retry_parse_error", "retry_truncated_invalid_json",
}
for label, result in (("build", initial_build), ("budget", initial_budget),
                      ("llm", initial_llm), ("retry", twice)):
    reason = result.get("_correlate_retry", {}).get("fallback_reason")
    check(f"R67 fallback reason allowlist {label}", reason in allowed_reasons, reason)

print(f"PASS={PASS} FAIL={FAIL}")
raise SystemExit(1 if FAIL else 0)
