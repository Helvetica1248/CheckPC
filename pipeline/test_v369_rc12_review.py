#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 regressions: formal check IDs, rejected pairs, safe fallback."""
from __future__ import annotations

import contextlib
import io

from correlate import FALLBACK_REASONS, _fallback_result, _normalize_correlation_iocs
from ioc_utils import normalize_evidence_ioc_detail
from release_check_ids import make_check_id, stable_check_name
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION, BUDGET_PROFILE_DEFAULT

PASS = FAIL = 0

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name} :: {detail}")

check("RC12 pipeline", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("RC12 schema", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("RC12 profile", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)

# IDs remain stable for rc -> formal and future minor RC transitions.
for label, a, b in [
    ("pipeline rc/formal", "V3b: version=3.70", "V3b: version=3.69"),
    ("schema rc/formal", "V3b: schema=2.1", "V3b: schema=2.0"),
    ("release file rc/formal", "V3b: v3.70_変更概要.md が存在", "V3b: v3.69_変更概要.md が存在"),
    ("profile rc/formal", "V5: profile v370", "V5: profile v369"),
    ("future pipeline rc/formal", "V3b: version=3.70-rc1", "V3b: version=3.70"),
    ("future schema rc/formal", "V3b: schema=2.1-rc1", "V3b: schema=2.1"),
    ("future profile rc/formal", "V5: profile v370-rc1-provisional", "V5: profile v370"),
]:
    ida = make_check_id(label.split()[0], a)
    idb = make_check_id(label.split()[0], b)
    check(f"stable ID {label}", ida == idb, (stable_check_name(a), stable_check_name(b), ida, idb))

check("version/schema logical names remain distinct",
      make_check_id("V3b", "V3b: version=3.69") != make_check_id("V3b", "V3b: schema=3.69"))

# Rejected connection pairs remain raw but are machine-auditable.
for remote_port in (0, 65536, 99999):
    raw = f"192.168.0.167:55578 → 119.3.160.204:{remote_port}"
    detail = normalize_evidence_ioc_detail(raw)
    check(f"rejected pair raw {remote_port}", detail.get("ioc") == raw, detail)
    check(f"rejected pair kind {remote_port}",
          detail.get("ioc_normalization_kind") == "connection_pair_rejected", detail)
    check(f"rejected pair warning {remote_port}",
          detail.get("ioc_normalization_warning") == "invalid_remote_port", detail)
    check(f"rejected pair no split {remote_port}",
          detail.get("ioc_port") is None and "local_ip" not in detail, detail)

valid = normalize_evidence_ioc_detail(
    "192.168.0.167:55578 → 119.3.160.204:11111")
check("valid pair unaffected", valid.get("ioc") == "119.3.160.204" and valid.get("ioc_port") == 11111, valid)

corr = {"correlated_iocs": [
    {"ioc": "192.168.0.167:55578 → 119.3.160.204:0", "found_in": ["netstat"]},
    {"ioc": "192.168.0.167:55578 → 119.3.160.204:99999", "found_in": ["netstat"]},
]}
_normalize_correlation_iocs(corr)
stats = corr.get("_ioc_normalization", {})
check("invalid pair counted", stats.get("invalid_port_count") == 2, stats)
check("rejected pair counted", stats.get("connection_pair_rejected_count") == 2, stats)
check("rejected pair not normalized", stats.get("normalized_count") == 0, stats)
check("rejected pair raw counted", stats.get("raw_preserved_count") == 2, stats)
check("normalization accounting closed",
      stats.get("output_count", 0) + stats.get("dropped_empty_count", 0)
      + stats.get("deduplicated_count", 0) == stats.get("input_count", -1), stats)

# Fallback is the last safety net: unknown/missing reason must never escape.
for reason, expected_raw in [("future_reason", "future_reason"), (None, "<missing>")]:
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        result = _fallback_result({}, 1, {"sections": {}}, {}, fallback_reason=reason)
    info = result.get("_correlate_retry", {})
    check(f"fallback safely degrades {reason}",
          info.get("fallback_reason") == "initial_processing_error", info)
    check(f"fallback raw retained {reason}",
          info.get("fallback_reason_raw") == expected_raw, info)
    check(f"fallback warning emitted {reason}", "CHECKPC_CORRELATE_WARNING" in stderr.getvalue(), stderr.getvalue())
    check(f"fallback result retained {reason}", result.get("parse_error") is True and info.get("fallback_applied") is True, result)

check("fallback vocabulary includes safe default", "initial_processing_error" in FALLBACK_REASONS, FALLBACK_REASONS)

print(f"PASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
