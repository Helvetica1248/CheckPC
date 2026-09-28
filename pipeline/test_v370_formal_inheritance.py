#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 must preserve security/operational policies of formal v3.69."""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

import budget_profile
import comparison_release_gate
import generate_release_manifest
import version

HERE = Path(__file__).resolve().parent
PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}: {detail}")


check("identity version", version.PIPELINE_VERSION == "3.70", version.PIPELINE_VERSION)
check("identity baseline", version.UPGRADED_FROM_VERSION == "3.69",
      getattr(version, "UPGRADED_FROM_VERSION", "<missing>"))
check("PEP440 version", 'version = "3.70.0"' in (HERE / "pyproject.toml").read_text(encoding="utf-8"))

external = HERE / "checkpc-pipeline.env.example"
check("external env template exists", external.is_file())
check("legacy package env template absent", not (HERE / ".env.example").exists())
check("package secret env absent",
      not any((HERE / name).exists() for name in (".env", ".env.local", ".env.example")))
if external.is_file():
    env_text = external.read_text(encoding="utf-8")
    check("external env selects v370", "CHECKPC_BUDGET_PROFILE=v370" in env_text)
    check("external env has no populated secret",
          not any(line.startswith(prefix) and line.split("=", 1)[1].strip()
                  for line in env_text.splitlines()
                  for prefix in ("VT_API_KEY=", "PIPELINE_API_KEY=", "PIPELINE_AUTH_PBKDF2=")))

formal = budget_profile.PROFILES["v369"]
v370 = budget_profile.PROFILES["v370"]
check("formal v369 profile is validated", formal["validated"] and not formal["provisional"])
# v3.70 was promoted after base117 real-machine end-to-end verification, so the
# profile is no longer provisional.  The numeric equality check below is what
# guarantees promotion moved metadata only.
check("v370 profile is validated after base117 E2E",
      v370["validated"] and not v370["provisional"],
      repr({k: v370.get(k) for k in ("provisional", "validated")}))
ignore = {"name", "note", "provisional", "validated"}
formal_numeric = {k: v for k, v in formal.items() if k not in ignore}
v370_numeric = {k: v for k, v in v370.items() if k not in ignore}
check("v370 numeric budget equals formal v369", formal_numeric == v370_numeric)

manifest_source = (HERE / "generate_release_manifest.py").read_text(encoding="utf-8")
check("manifest rejects package-local secrets",
      "FORBIDDEN_SECRET_NAMES" in manifest_source and "assert_no_forbidden_secret_files" in manifest_source)
check("manifest rejects cache/build artifacts",
      "assert_no_forbidden_package_artifacts" in manifest_source
      and not generate_release_manifest.forbidden_package_artifacts(),
      generate_release_manifest.forbidden_package_artifacts())
check("manifest records baseline", '"upgraded_from_version": UPGRADED_FROM_VERSION' in manifest_source)
check("comparison gate records baseline",
      comparison_release_gate.UPGRADED_FROM_VERSION == "3.69")
check("comparison gate keeps current-version requirement",
      "current pipeline version" in (HERE / "comparison_release_gate.py").read_text(encoding="utf-8"))

portable_files = [
    "run_all_tests.py", "test_chat_tools_realdata.py",
    "test_report_fallback.py", "test_timeline_fixes.py",
    "test_integration_ttl4_ttl5.py", "test_vt_downgrade.py",
    "test_shim_netstat.py",
]
portable_text = "\n".join((HERE / name).read_text(encoding="utf-8") for name in portable_files)
forbidden_test_paths = (
    "/home" + "/claude/output_check", "/home" + "/claude/desktop1r5l72q",
    "/home" + "/claude/report_gen.py", "/home" + "/claude/timeline.py",
    "/home" + "/claude/cabtest", "/home" + "/claude/extract", "/mnt" + "/user-data/uploads",
)
check("formal v3.69 real-data test paths remain portable",
      not any(x in portable_text for x in forbidden_test_paths),
      str([x for x in forbidden_test_paths if x in portable_text]))
check("formal real-data test environment controls exist",
      all(x in portable_text for x in (
          "CHECKPC_TEST_EXTRACT", "CHECKPC_TEST_WORKDIR",
          "CHECKPC_TEST_NESTED_HOST", "CHECKPC_TEST_UPLOADS")))

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    # The function is rooted at the package directory; create and remove each
    # forbidden legacy package-local secret/template name in turn.
    for forbidden_name in (".env", ".env.local", ".env.example"):
        forbidden = HERE / forbidden_name
        try:
            forbidden.write_text("SECRET=must-not-ship\n", encoding="utf-8")
            raised = False
            try:
                generate_release_manifest.assert_no_forbidden_secret_files()
            except RuntimeError:
                raised = True
            check(f"manifest guard fails closed for {forbidden_name}", raised)
        finally:
            forbidden.unlink(missing_ok=True)


with tempfile.TemporaryDirectory() as td:
    original_root = generate_release_manifest.ROOT
    try:
        temp_root = Path(td)
        generate_release_manifest.ROOT = temp_root
        cache = temp_root / "__pycache__"
        cache.mkdir()
        (cache / "injected.cpython-313.pyc").write_bytes(b"not trusted")
        raised = False
        try:
            generate_release_manifest.assert_no_forbidden_package_artifacts()
        except RuntimeError:
            raised = True
        check("manifest guard fails closed for __pycache__/pyc", raised)
    finally:
        generate_release_manifest.ROOT = original_root

# ── v3.70 formal promotion: metadata only, never a budget number ──────────
import budget_profile as _bp_formal  # noqa: E402

_METADATA_KEYS = {"name", "note", "provisional", "validated", "warning"}
_v370 = _bp_formal.PROFILES.get("v370") or {}
_v369 = _bp_formal.PROFILES.get("v369") or {}
_numeric_diff = sorted(
    key for key in set(_v370) | set(_v369)
    if key not in _METADATA_KEYS and _v370.get(key) != _v369.get(key)
)
check("v370 numeric budget is identical to formal v369", not _numeric_diff,
      repr(_numeric_diff))
check("v370 section budgets are unchanged",
      _v370.get("sec_cap_d2") == _v369.get("sec_cap_d2"))
check("v370 per-entry token table is unchanged",
      _v370.get("tok_per_entry") == _v369.get("tok_per_entry"))
check("v370 depth2 output token budget is unchanged",
      _v370.get("d2_output_token_budget") == _v369.get("d2_output_token_budget"))
check("v370 tier selection ratios are unchanged",
      all(_v370.get(key) == _v369.get(key)
          for key in ("risk_ratio", "fair_ratio", "novelty_ratio",
                      "d2_min_rep", "novelty_min_rep", "novelty_section_cap",
                      "sig_max_d2")))
check("v370 is marked validated after base117 E2E",
      _v370.get("validated") is True and _v370.get("provisional") is False,
      repr({k: _v370.get(k) for k in ("provisional", "validated")}))

_prev_active = _bp_formal._ACTIVE
try:
    _bp_formal._ACTIVE = None
    os.environ["CHECKPC_BUDGET_PROFILE"] = "v370"
    _active_dict = _bp_formal.BudgetProfile().to_dict()
finally:
    _bp_formal._ACTIVE = _prev_active
check("validated v370 emits no validation-pending warning",
      _active_dict.get("warning") == "", repr(_active_dict.get("warning")))
check("validated v370 still publishes a fingerprint",
      bool(_active_dict.get("fingerprint")))

# The promotion tooling must exist and must refuse to run without evidence.
check("analysis runtime invariance tool is present",
      os.path.isfile(os.path.join(HERE, "verify_analysis_runtime_unchanged.py")))
check("formal promotion tool is present",
      os.path.isfile(os.path.join(HERE, "promote_to_formal.py")))
_promote_text = open(os.path.join(HERE, "promote_to_formal.py"),
                     encoding="utf-8").read()
for _guard in ("release_mode", "formal_release_eligible", "base117",
               "comparison_gate", "check_runtime_baseline",
               "check_numeric_budget"):
    check(f"promotion tool enforces {_guard}", _guard in _promote_text)

_gate_text = (HERE / "comparison_release_gate.py").read_text(encoding="utf-8")
check("comparison gate records result IDs and comparator SHA",
      '"result_id"' in _gate_text and '"compare_runs_sha256"' in _gate_text)
check("comparison gate records approval SHA sets",
      '"approval_sha256s"' in _gate_text and '"approvals"' in _gate_text)
check("promotion requires an explicit comparison gate directory",
      '"--comparison-gate-dir"' in _promote_text and "required=True" in _promote_text)
check("promotion directly re-evaluates the comparison gate",
      "evaluate_release_gate" in _promote_text)
check("promotion revalidates immutable approvals",
      "validate_approval" in _promote_text and "approval SHA differs from gate" in _promote_text)
check("promotion binds test_results to the exact gate directory",
      "comparison_gate.directory does not match" in _promote_text)
check("promotion records gate/result/approval SHA evidence",
      all(token in _promote_text for token in (
          "comparison_gate_json_sha256", "result_sha256", "approval_files")))
check("promotion binding regression test exists",
      (HERE / "test_v370_promotion_gate_binding.py").is_file())

# GUI polling-state hotfix is part of the formal candidate package but remains
# outside the analysis runtime allowlist.
_server_ui_text = (HERE / "server.py").read_text(encoding="utf-8")
check("GUI polling-state regression test exists",
      (HERE / "test_v370_gui_polling_state.py").is_file())
check("GUI folder options avoid unchanged polling rebuild",
      "if (signature === _folderOptionsSignature) return;" in _server_ui_text)
check("GUI job menu state is restored after render",
      "captureOpenJobMenus" in _server_ui_text
      and "restoreOpenJobMenus" in _server_ui_text
      and 'data-job-id="${escapeHtml(String(j.job_id))}"' in _server_ui_text)
check("GUI header omits J-CRAT branding",
      '<div class="sub">Qwen2.5-Coder 32B</div>' in _server_ui_text
      and '<div class="sub">Qwen2.5-Coder 32B · J-CRAT</div>' not in _server_ui_text)

print(f"PASS={PASS} FAIL={FAIL}")
print(json.dumps({"PASS": PASS, "FAIL": FAIL}, ensure_ascii=False))
raise SystemExit(1 if FAIL else 0)
