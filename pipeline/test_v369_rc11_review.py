#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 regressions: service adjudication, IOC structure, GUI/help, release metadata."""
import json
import os
import tempfile
from pathlib import Path

from analyze_section import _apply_post_filter, _parse_service_command
from ioc_utils import normalize_evidence_ioc_detail
from correlate import (
    _normalize_correlation_iocs, _fallback_result, FALLBACK_REASONS,
    CorrelateBudgetExhausted,
)
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION, BUDGET_PROFILE_DEFAULT
import run_all_tests
from release_check_ids import make_check_id

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"[PASS] {name}")
    else:
        FAIL += 1; print(f"[FAIL] {name} :: {detail}")

check("RC11 version", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("RC11 schema", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("RC11 profile", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)

# RustDesk 7045: FULL/LEAN source-independent deterministic adjudication.
raw_pf = [{
    "service_name": "RustDesk Service",
    "image_path": '"C:\\Program Files\\RustDesk\\RustDesk.exe" --import-config "C:\\Users\\x\\AppData\\Roaming\\RustDesk\\config\\RustDesk.toml"',
}]
full_entry = {"source_index": 0, "identifier": "RustDesk Service", "score": "HIGH",
              "reason": "ImagePath が %AppData% 配下にある",
              "iocs": [r"C:\Users\x\AppData\Roaming\RustDesk\config\RustDesk.toml"],
              "mitre": ["T1543.003"]}
lean_entry = {"source_index": 0, "identifier": "RustDesk Service", "score": "LOW",
              "reason": "ImagePath が %AppData% 配下にある",
              "iocs": [r'C:\Program Files\RustDesk\RustDesk.exe" --import-config "C:\Users\x\AppData\Roaming\RustDesk\config\RustDesk.toml'],
              "mitre": ["T1543.003"]}
full = _apply_post_filter("system_7045", {"entries": [full_entry]}, raw_pf)["entries"][0]
lean = _apply_post_filter("system_7045", {"entries": [lean_entry]}, raw_pf)["entries"][0]
check("RustDesk Program Files MEDIUM FULL", full["score"] == "MEDIUM", full)
check("RustDesk Program Files MEDIUM LEAN", lean["score"] == "MEDIUM", lean)
check("RustDesk FULL/LEAN reason stable", full["reason"] == lean["reason"], (full, lean))
check("RustDesk executable extracted", full.get("service_executable") == r"C:\Program Files\RustDesk\RustDesk.exe", full)
check("RustDesk config argument separated", full.get("service_argument_paths") == [r"C:\Users\x\AppData\Roaming\RustDesk\config\RustDesk.toml"], full)
check("RustDesk IOC is executable", full.get("iocs") == [r"C:\Program Files\RustDesk\RustDesk.exe"], full)
check("RustDesk T1219 retained", "T1219" in full.get("mitre", []), full)

raw_user = [{"service_name": "RustDesk Service",
             "image_path": '"C:\\Users\\x\\AppData\\Local\\RustDesk\\RustDesk.exe" --service'}]
user = _apply_post_filter("system_7045", {"entries": [{
    "source_index": 0, "identifier": "RustDesk Service", "score": "LOW", "reason": "", "iocs": []
}]}, raw_user)["entries"][0]
check("RustDesk user-write HIGH", user["score"] == "HIGH", user)
check("RustDesk HIGH reason consistent", "HIGHを維持" in user["reason"], user["reason"])

parsed = _parse_service_command(raw_pf[0]["image_path"])
check("service parser executable", parsed["executable"].endswith(r"RustDesk\RustDesk.exe"), parsed)
check("service parser arguments", "--import-config" in parsed["arguments"], parsed)

# Compound netstat correlation IOC.
pair_raw = "192.168.0.167:55578 → 119.3.160.204:11111"
detail = normalize_evidence_ioc_detail(pair_raw)
check("connection pair remote IOC", detail.get("ioc") == "119.3.160.204", detail)
check("connection pair remote port", detail.get("ioc_port") == 11111, detail)
check("connection pair local IP", detail.get("local_ip") == "192.168.0.167", detail)
check("connection pair local port", detail.get("local_port") == 55578, detail)
check("connection pair raw preserved", detail.get("ioc_raw") == pair_raw, detail)
check("connection pair kind", detail.get("ioc_normalization_kind") == "connection_pair", detail)

corr = {"correlated_iocs": [{"ioc": pair_raw, "found_in": ["netstat"],
                               "significance": "外部通信", "category": "external_intrusion"}]}
_normalize_correlation_iocs(corr)
ci = corr["correlated_iocs"][0]
check("correlation pair structured", ci.get("local_ip") == "192.168.0.167" and ci.get("ioc_port") == 11111, ci)
check("correlation normalization counted", corr["_ioc_normalization"]["normalized_count"] == 1, corr)

# Fallback vocabulary is production-owned; unknown values safely degrade.
expected_reasons = {
    "initial_build_error", "initial_budget_exhausted", "initial_llm_error",
    "retry_build_error", "retry_budget_exhausted", "retry_llm_error",
    "retry_parse_error", "retry_truncated_invalid_json",
    "initial_processing_error",
}
check("fallback reason vocabulary", FALLBACK_REASONS == expected_reasons, FALLBACK_REASONS)
unknown_result = _fallback_result(
    {}, 1, {"sections": {}}, {}, fallback_reason="unknown_reason")
unknown_info = unknown_result.get("_correlate_retry", {})
check("unknown fallback reason safely degraded",
      unknown_info.get("fallback_reason") == "initial_processing_error", unknown_info)
check("unknown fallback raw retained",
      unknown_info.get("fallback_reason_raw") == "unknown_reason", unknown_info)
check("budget exception dedicated", issubclass(CorrelateBudgetExhausted, ValueError))

# Check IDs are stable across rc values.
a = make_check_id("V3b", "V3b: version=3.69-rc10")
b = make_check_id("V3b", "V3b: version=3.70")
c = make_check_id("V5", "V5: profile v369-rc10-provisional")
d = make_check_id("V5", "V5: profile v370")
check("version check ID stable", a == b, (a, b))
check("profile check ID stable", c == d, (c, d))
formal_version = make_check_id("V3b", "V3b: version=3.69")
formal_schema = make_check_id("V3b", "V3b: schema=2.0")
formal_file = make_check_id("V3b", "V3b: v3.69_変更概要.md が存在")
check("formal version check ID stable", b == formal_version, (b, formal_version))
check("formal schema check ID stable",
      make_check_id("V3b", "V3b: schema=2.1") == formal_schema, formal_schema)
check("formal file check ID stable",
      make_check_id("V3b", "V3b: v3.70_変更概要.md が存在") == formal_file, formal_file)

# RC summaries always carry a non-empty environment label.
old = os.environ.pop("CHECKPC_TEST_ENV_LABEL", None)
try:
    meta = run_all_tests._summary_metadata()
finally:
    if old is not None: os.environ["CHECKPC_TEST_ENV_LABEL"] = old
check("default environment label nonempty", bool(meta.get("environment_label")), meta)
check("default environment label explicit", meta.get("environment_label") == "developer-local", meta)

# GUI/help static assertions.
import server
html = server._HTML
guide = server.GUIDE_PATH.read_text(encoding="utf-8")
svg = server.DIAGRAM_PATH.read_text(encoding="utf-8")
check("GUI archive details folded", '<details class="job-more"' in html, "details missing")
check("GUI warning not standalone row", 'archive-warning' in html and 'archive-row' in html)
check("GUI old depth warning removed", "深度2は一部データが未評価になる既知問題" not in html)
check("guide FULL LEAN", "FULL／LEAN" in guide)
check("guide archive types", "検証用ZIP" in guide and "全成果物ZIP" in guide)
check("guide fallback", "横断相関フォールバック" in guide)
check("guide system flow", "システムの仕組み" in guide and "archive worker" in guide)
check("diagram archive worker", "archive worker" in svg)
check("diagram audit", "監査ログ" in svg)

print(f"PASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
