#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 regressions: fallback authority, report audit, check-ID policy."""
from __future__ import annotations

import contextlib
import io
from pathlib import Path

from budget_profile import active_profile
from correlate import _fallback_result
from release_check_ids import (
    find_bare_release_versions,
    find_duplicate_check_ids,
    make_check_id,
)
from report_gen import generate_report
from version import ANALYSIS_SCHEMA_VERSION, BUDGET_PROFILE_DEFAULT, PIPELINE_VERSION

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name} :: {detail}")


check("RC13 pipeline", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("RC13 schema", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("RC13 profile constant", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)
check("RC13 active profile", active_profile().name == "v370", active_profile().name)

# retry_info is untrusted diagnostic data and cannot override the validated reason.
stderr = io.StringIO()
with contextlib.redirect_stderr(stderr):
    unknown = _fallback_result(
        {}, 1, {"sections": {}}, {},
        fallback_reason="future_reason",
        retry_info={"fallback_reason": "bogus", "fallback_reason_raw": "stale"},
    )
unknown_info = unknown.get("_correlate_retry", {})
check("unknown reason overrides retry_info reason",
      unknown_info.get("fallback_reason") == "initial_processing_error", unknown_info)
check("unknown reason overrides retry_info raw",
      unknown_info.get("fallback_reason_raw") == "future_reason", unknown_info)
check("unknown reason warning retained",
      "CHECKPC_CORRELATE_WARNING" in stderr.getvalue(), stderr.getvalue())

stderr = io.StringIO()
with contextlib.redirect_stderr(stderr):
    known = _fallback_result(
        {}, 1, {"sections": {}}, {},
        fallback_reason="initial_llm_error",
        retry_info={"fallback_reason": "bogus", "fallback_reason_raw": "stale"},
    )
known_info = known.get("_correlate_retry", {})
check("known reason overrides retry_info reason",
      known_info.get("fallback_reason") == "initial_llm_error", known_info)
check("known reason removes stale raw", "fallback_reason_raw" not in known_info, known_info)
check("known reason does not warn", not stderr.getvalue(), stderr.getvalue())

stderr = io.StringIO()
with contextlib.redirect_stderr(stderr):
    missing = _fallback_result(
        {}, 1, {"sections": {}}, {},
        fallback_reason=None,
        retry_info={"fallback_reason": "bogus", "fallback_reason_raw": "stale"},
    )
missing_info = missing.get("_correlate_retry", {})
check("missing reason safely defaults",
      missing_info.get("fallback_reason") == "initial_processing_error", missing_info)
check("missing reason raw is authoritative",
      missing_info.get("fallback_reason_raw") == "<missing>", missing_info)

# The human report exposes safe-degradation provenance without allowing Markdown
# inline-code or control-character injection.
analyzed = {"meta": {"hostname": "RC13-TEST"}, "sections": {}, "depth": 1}
corr = {
    "_correlate_retry": {
        "fallback_applied": True,
        "fallback_reason": "initial_processing_error",
        "fallback_reason_raw": "future`reason\nnext\x01line",
    },
    "parse_error": True,
}
report = generate_report(analyzed, corr)
check("report shows normalized reason", "原因コード: `initial_processing_error`" in report, report[:1000])
check("report shows original reason label", "元の原因コード:" in report, report[:1000])
check("report explains safe degradation", "未認識の原因コードを安全な既定値へ縮退" in report, report[:1000])
check("report strips raw newline/control injection", "future'reason next line" in report, report[:1000])
check("report does not preserve injected backtick", "future`reason" not in report, report[:1000])

known_report = generate_report(analyzed, {
    "_correlate_retry": {
        "fallback_applied": True,
        "fallback_reason": "initial_llm_error",
    },
    "parse_error": True,
})
check("known report omits original reason line", "元の原因コード:" not in known_report, known_report[:1000])

# Typed contexts remain stable, while ambiguous bare versions are rejected by policy.
check("typed version is not bare",
      not find_bare_release_versions("V3b: version=3.70-rc1"))
check("typed schema is not bare",
      not find_bare_release_versions("V3b: schema=2.1-rc1"))
check("release filename is not bare",
      not find_bare_release_versions("V3b: v3.70-rc1_変更概要.md が存在"))
check("profile is not bare",
      not find_bare_release_versions("V5: profile v370-rc1-provisional"))
check("ordinary ratio is not a release version",
      not find_bare_release_versions("V5: risk/fair/novelty比率が1.0"))
check("bare pipeline version is detected",
      find_bare_release_versions("V3b: pipeline 3.70-rc1") == ("3.70-rc1",))
check("bare schema version is detected",
      find_bare_release_versions("V3b: analysis schema 2.1") == ("2.1",))

row_a = {"id": make_check_id("V3b", "V3b: v3.68 から v3.69 へ移行"), "name": "forward"}
row_b = {"id": make_check_id("V3b", "V3b: v3.69 から v3.68 へ移行"), "name": "reverse"}
duplicates = find_duplicate_check_ids([row_a, row_b])
check("duplicate check IDs are detected", bool(duplicates), duplicates)
check("unique check IDs pass", not find_duplicate_check_ids([
    {"id": "a", "name": "one"}, {"id": "b", "name": "two"},
]))

root = Path(__file__).resolve().parent
design = (root / "DESIGN.md").read_text(encoding="utf-8")
check("DESIGN defines pre-dedup occurrence counters",
      "dedup前の入力オカレンス数" in design)
verifier = (root / "verify_release_package.py").read_text(encoding="utf-8")
check("verifier checks bare version policy",
      "check名にラベル無し裸バージョンが無い" in verifier)
check("verifier checks ID uniqueness", "check IDが全件一意" in verifier)

print(f"PASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
