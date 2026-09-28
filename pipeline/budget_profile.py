#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validated depth=2 output-budget profiles (v3.69-rc20).

The v3.69-rc20 profile is intentionally provisional. Its values are recorded in
all outputs and are promoted to a validated profile only after separate real-host
calibration.
"""
from __future__ import annotations
import hashlib
import json
import os
from copy import deepcopy
from pipeline_errors import ConfigurationError
from pipeline_settings import env_float, env_int
from version import BUDGET_PROFILE_DEFAULT

BUDGET_PROFILE_NAME = BUDGET_PROFILE_DEFAULT
D2_OUTPUT_TOKEN_BUDGET = 75000
D2_RISK_BUDGET_RATIO = 0.65
D2_FAIR_BUDGET_RATIO = 0.25
D2_NOVELTY_BUDGET_RATIO = 0.10
D2_MIN_REP = 10
D2_NOVELTY_MIN_REP = 3
D2_NOVELTY_SECTION_CAP = 20
SIG_MAX_D2 = 3
TOKENS_PER_CHUNK_OVERHEAD = 192
TOKEN_ESTIMATE_SAFETY_FACTOR = 1.15
SECTION_CHUNK_CAP = 20
PLANNER_TRIM_BATCH_MAX = 8
PLANNER_FRONTIER_RESERVE_PER_SECTION = 32
PLANNER_CANDIDATE_PROBE_LIMIT = 1024
PLANNER_REPLAN_LIMIT = 512
PLANNER_CANCEL_CHECK_INTERVAL = 4096
PLANNER_PROGRESS_INTERVAL = 65536
PLANNER_TRIM_ITERATION_LIMIT = 512

TOK_PER_ENTRY_PROVISIONAL = {
    "directory": 256, "netstat": 256, "ps_history": 192,
    "persistence_reg": 160, "task_scheduler": 160, "service": 160,
    "dns_cache": 160, "prefetch": 160, "appcompat_cache": 160,
    "startup_folder": 160, "hosts": 160, "system_7045": 160,
    "rdp_1024": 160, "bits_jobs": 160,
    "association_exe": 160, "uac_bypass": 160, "active_setup": 160,
    "com_persistence": 160, "wmi": 192, "task_106": 160,
    "task_140": 160, "recent_behavior": 160,
    "defender_quarantine": 0,
}
_TOK_PER_ENTRY_DEFAULT = 160

SEC_CAP_D2 = {
    "directory": 200, "netstat": 300, "appcompat_cache": 200,
    "prefetch": 150, "dns_cache": 150, "ps_history": 100,
}
_SEC_CAP_D2_DEFAULT = 10 ** 9

PROFILES = {
    "v368-rc2-provisional": {
        "provisional": True,
        "validated": False,
        "d2_output_token_budget": 75000,
        "risk_ratio": 0.75,
        "fair_ratio": 0.25,
        "novelty_ratio": 0.0,
        "d2_min_rep": 10,
        "novelty_min_rep": 0,
        "novelty_section_cap": 0,
        "sig_max_d2": 3,
        "tokens_per_chunk_overhead": 192,
        "token_estimate_safety_factor": 1.15,
        "tok_per_entry": deepcopy(TOK_PER_ENTRY_PROVISIONAL),
        "sec_cap_d2": deepcopy(SEC_CAP_D2),
        "section_chunk_cap": 20,
        "note": "v3.68-rc2 compatibility profile; unvalidated.",
    },
    "v369-rc2-provisional": {
        "provisional": True,
        "validated": False,
        "d2_output_token_budget": D2_OUTPUT_TOKEN_BUDGET,
        "risk_ratio": D2_RISK_BUDGET_RATIO,
        "fair_ratio": D2_FAIR_BUDGET_RATIO,
        "novelty_ratio": D2_NOVELTY_BUDGET_RATIO,
        "d2_min_rep": D2_MIN_REP,
        "novelty_min_rep": D2_NOVELTY_MIN_REP,
        "novelty_section_cap": D2_NOVELTY_SECTION_CAP,
        "sig_max_d2": SIG_MAX_D2,
        "tokens_per_chunk_overhead": TOKENS_PER_CHUNK_OVERHEAD,
        "token_estimate_safety_factor": TOKEN_ESTIMATE_SAFETY_FACTOR,
        "tok_per_entry": deepcopy(TOK_PER_ENTRY_PROVISIONAL),
        "sec_cap_d2": deepcopy(SEC_CAP_D2),
        "section_chunk_cap": SECTION_CHUNK_CAP,
        "note": "Unvalidated v3.69-rc2 values; calibrate before formal v3.69.",
    },
}

# rc3 retains the exact provisional values; only hardening/calibration code changed.
PROFILES["v369-rc3-provisional"] = deepcopy(PROFILES["v369-rc2-provisional"])
PROFILES["v369-rc3-provisional"]["note"] = (
    "Unvalidated v3.69-rc3 values; identical to rc2 and subject to real-host calibration.")

# rc4 retains the exact provisional values; prompt-boundary hardening does not
# change calibration constants.  Use a distinct profile name to prevent rc3/rc4
# measurements from being silently mixed.
PROFILES["v369-rc4-provisional"] = deepcopy(PROFILES["v369-rc3-provisional"])
PROFILES["v369-rc4-provisional"]["note"] = (
    "Unvalidated v3.69-rc4 values; identical to rc3 and subject to real-host calibration.")

# rc5 retains the exact provisional values; chat Lv.2 hardening does not change
# calibration constants. Use a distinct profile name to prevent rc4/rc5
# measurements from being silently mixed.
PROFILES["v369-rc5-provisional"] = deepcopy(PROFILES["v369-rc4-provisional"])
PROFILES["v369-rc5-provisional"]["note"] = (
    "Unvalidated v3.69-rc5 values; identical to rc4 and subject to real-host calibration.")

# rc6 retains the same provisional values; Claude review R1-R3 hardening changes
# only chat IOC validation/grounding/audit behavior. Keep a distinct profile name
# so rc5 and rc6 measurements cannot be silently mixed.
PROFILES["v369-rc6-provisional"] = deepcopy(PROFILES["v369-rc5-provisional"])
PROFILES["v369-rc6-provisional"]["note"] = (
    "Unvalidated v3.69-rc6 values; identical to rc5 and subject to real-host calibration.")

# rc7 preserves the rc6 selection budget and changes only the implementation
# complexity/diagnostics. Keep it for old artifact/profile compatibility.
PROFILES["v369-rc7-provisional"] = deepcopy(PROFILES["v369-rc6-provisional"])
PROFILES["v369-rc7-provisional"]["note"] = (
    "Unvalidated v3.69-rc7 values; rc6 selection semantics with quadratic "
    "Depth2 planner bug fixed. Subject to real-host calibration.")

# rc8 retains the measured rc7 planner values while fixing archive, progress,
# correlation and release-integrity defects. Calibration constants are unchanged.
PROFILES["v369-rc8-provisional"] = deepcopy(PROFILES["v369-rc7-provisional"])
PROFILES["v369-rc8-provisional"]["note"] = (
    "Unvalidated v3.69-rc8 values; identical selection budget to rc7 and "
    "subject to final base117 calibration.")

# rc9 keeps the rc8 planner/calibration values and hardens correlation retry,
# IOC normalization, provenance exception safety and release verification.
PROFILES["v369-rc9-provisional"] = deepcopy(PROFILES["v369-rc8-provisional"])
PROFILES["v369-rc9-provisional"]["note"] = (
    "Unvalidated v3.69-rc9 values; identical selection budget to rc8 and "
    "subject to final base117 calibration.")

# rc10 retains rc9 selection/calibration constants.  It changes only fallback
# observability, retry provenance, IOC audit counters and verifier diagnostics.
PROFILES["v369-rc10-provisional"] = deepcopy(PROFILES["v369-rc9-provisional"])
PROFILES["v369-rc10-provisional"]["note"] = (
    "Unvalidated v3.69-rc10 values; identical selection budget to rc9 and "
    "subject to final base117 calibration.")

# rc11 retains rc10 selection/calibration constants. It changes deterministic
# service adjudication, correlation IOC structure, GUI/help and release metadata.
PROFILES["v369-rc11-provisional"] = deepcopy(PROFILES["v369-rc10-provisional"])
PROFILES["v369-rc11-provisional"]["note"] = (
    "Unvalidated v3.69-rc11 values; identical selection budget to rc10 and "
    "subject to final base117 calibration.")

# rc12 retains rc11 selection/calibration constants. It hardens release-check
# identity, rejected connection-pair audit metadata and fallback resilience.
PROFILES["v369-rc12-provisional"] = deepcopy(PROFILES["v369-rc11-provisional"])
PROFILES["v369-rc12-provisional"]["note"] = (
    "Unvalidated v3.69-rc12 values; identical selection budget to rc11 and "
    "subject to final base117 calibration.")

# rc13 retains rc12 selection/calibration constants. It hardens fallback
# metadata authority, report observability and release-check naming audits.
PROFILES["v369-rc13-provisional"] = deepcopy(PROFILES["v369-rc12-provisional"])
PROFILES["v369-rc13-provisional"]["note"] = (
    "Unvalidated v3.69-rc13 values; identical selection budget to rc12 and "
    "subject to final base117 calibration.")

# rc14 retains rc13 selection/calibration constants. It fixes VT report-state
# truthfulness and preserves Defender threat names as non-filepath evidence.
PROFILES["v369-rc14-provisional"] = deepcopy(PROFILES["v369-rc13-provisional"])
PROFILES["v369-rc14-provisional"]["note"] = (
    "Unvalidated v3.69-rc14 values; identical selection budget to rc13 and "
    "subject to final base117 calibration.")

# rc15 retains rc14 selection/calibration constants. It reconciles system_7045
# identities with raw evidence and separates exact VT lookups from filepath
# reference searches, including a dedicated too-many-hits state.
PROFILES["v369-rc15-provisional"] = deepcopy(PROFILES["v369-rc14-provisional"])
PROFILES["v369-rc15-provisional"]["note"] = (
    "Unvalidated v3.69-rc15 values; identical selection budget to rc14 and "
    "subject to final base117 calibration.")

# rc16 retains rc15 selection/calibration constants. It hardens unbalanced
# service command parsing and runtime/archive identity checks only.
PROFILES["v369-rc16-provisional"] = deepcopy(PROFILES["v369-rc15-provisional"])
PROFILES["v369-rc16-provisional"]["note"] = (
    "Unvalidated v3.69-rc16 values; identical selection budget to rc15 and "
    "subject to final base117 calibration.")

# rc17 retains the rc16 numeric budget while protecting deterministic HIGH
# candidates and section floors. A bounded explicit overrun is permitted when
# mandatory/floor evidence cannot fit after real chunk overhead is calculated.
PROFILES["v369-rc17-provisional"] = deepcopy(PROFILES["v369-rc16-provisional"])
PROFILES["v369-rc17-provisional"]["note"] = (
    "Unvalidated v3.69-rc17 values; rc16 numeric budget with mandatory/floor "
    "preservation and subject to final base117 calibration.")

# rc18 retains the numeric envelope while replacing product-specific calibration
# with generic evidence classes and maximal feasible planning.
PROFILES["v369-rc18-provisional"] = deepcopy(PROFILES["v369-rc17-provisional"])
PROFILES["v369-rc18-provisional"]["note"] = (
    "Unvalidated v3.69-rc18 values; rc17 numeric budget with bounded trim, "
    "deterministic backfill and maximality audit.")


# rc19 retains the rc18 numeric envelope and generic evidence policies while
# bounding Step 4B planner work to a policy frontier. It explicitly does not
# claim global knapsack maximality across millions of raw candidates.
PROFILES["v369-rc20-provisional"] = deepcopy(PROFILES["v369-rc18-provisional"])
PROFILES["v369-rc20-provisional"].update({
    "planner_trim_batch_max": PLANNER_TRIM_BATCH_MAX,
    "planner_frontier_reserve_per_section": PLANNER_FRONTIER_RESERVE_PER_SECTION,
    "planner_candidate_probe_limit": PLANNER_CANDIDATE_PROBE_LIMIT,
    "planner_replan_limit": PLANNER_REPLAN_LIMIT,
    "planner_cancel_check_interval": PLANNER_CANCEL_CHECK_INTERVAL,
    "planner_progress_interval": PLANNER_PROGRESS_INTERVAL,
    "planner_trim_iteration_limit": PLANNER_TRIM_ITERATION_LIMIT,
    "note": ("Unvalidated v3.69-rc20 values; rc18 numeric budget with bounded "
             "policy-frontier trim/backfill and cancellable Step 4B planning."),
})

# rc21 changes comparison/provenance audit paths only.  The Depth2 selection
# envelope and bounded policy-frontier planner are intentionally identical to
# rc20 pending base117 calibration.
PROFILES["v369-rc21-provisional"] = deepcopy(PROFILES["v369-rc20-provisional"])
PROFILES["v369-rc21-provisional"]["note"] = (
    "Unvalidated v3.69-rc21 values; identical rc20 bounded planner budget, "
    "with Depth1 attribution and release-gate hardening only.")

# rc22 changes only .env startup logging.  Selection, planner, token budget,
# provenance and comparison semantics remain byte-for-byte equivalent to rc21.
PROFILES["v369-rc22-provisional"] = deepcopy(PROFILES["v369-rc21-provisional"])
PROFILES["v369-rc22-provisional"]["note"] = (
    "Unvalidated v3.69-rc22 values; identical rc21 planner and budget, "
    "with secret-free .env startup logging only.")

# v3.69-rc1 artifacts may explicitly request the previous provisional name.
# Keep it as an exact-value compatibility alias while the default advances to rc6.
PROFILES["v369-rc1-provisional"] = deepcopy(PROFILES["v369-rc2-provisional"])
PROFILES["v369-rc1-provisional"]["note"] = (
    "Compatibility alias for v3.69-rc1 provisional values; unvalidated.")


class BudgetProfile:
    def __init__(self, name: str | None = None):
        requested = name or os.environ.get("CHECKPC_BUDGET_PROFILE") or BUDGET_PROFILE_NAME
        if requested not in PROFILES:
            raise ConfigurationError(
                f"Unknown CHECKPC_BUDGET_PROFILE={requested!r}; available={sorted(PROFILES)}")
        base = deepcopy(PROFILES[requested])
        self.name = requested
        self.provisional = bool(base.get("provisional", True))
        self.validated = bool(base.get("validated", False))
        self.environment_overrides: dict[str, object] = {}

        self.d2_output_token_budget = self._int(
            "CHECKPC_D2_OUTPUT_TOKEN_BUDGET", base["d2_output_token_budget"], minimum=1)
        self.risk_ratio = self._float(
            "CHECKPC_D2_RISK_BUDGET_RATIO", base["risk_ratio"], minimum=0.0, maximum=1.0)
        self.fair_ratio = self._float(
            "CHECKPC_D2_FAIR_BUDGET_RATIO", base["fair_ratio"], minimum=0.0, maximum=1.0)
        self.novelty_ratio = self._float(
            "CHECKPC_D2_NOVELTY_BUDGET_RATIO", base["novelty_ratio"], minimum=0.0, maximum=1.0)
        ratio_sum = self.risk_ratio + self.fair_ratio + self.novelty_ratio
        if abs(ratio_sum - 1.0) > 1e-9:
            raise ConfigurationError(
                "CHECKPC_D2_*_BUDGET_RATIO values must sum to 1.0: "
                f"risk={self.risk_ratio}, fair={self.fair_ratio}, novelty={self.novelty_ratio}")
        self.d2_min_rep = self._int("CHECKPC_D2_MIN_REP", base["d2_min_rep"], minimum=0)
        self.novelty_min_rep = self._int(
            "CHECKPC_D2_NOVELTY_MIN_REP", base["novelty_min_rep"], minimum=0)
        self.novelty_section_cap = self._int(
            "CHECKPC_D2_NOVELTY_SECTION_CAP", base["novelty_section_cap"], minimum=0)
        self.sig_max_d2 = self._int("CHECKPC_D2_SIG_MAX", base["sig_max_d2"], minimum=1)
        self.tokens_per_chunk_overhead = self._int(
            "CHECKPC_TOKENS_PER_CHUNK_OVERHEAD", base["tokens_per_chunk_overhead"], minimum=0)
        self.token_estimate_safety_factor = self._float(
            "CHECKPC_TOKEN_ESTIMATE_SAFETY_FACTOR", base["token_estimate_safety_factor"], minimum=1.0)
        self.section_chunk_cap = int(base["section_chunk_cap"])
        if self.section_chunk_cap <= 0:
            raise ConfigurationError("section_chunk_cap must be positive")
        self.planner_trim_batch_max = self._int(
            "CHECKPC_D2_PLANNER_TRIM_BATCH_MAX",
            base.get("planner_trim_batch_max", PLANNER_TRIM_BATCH_MAX), minimum=1)
        self.planner_frontier_reserve_per_section = self._int(
            "CHECKPC_D2_PLANNER_FRONTIER_RESERVE",
            base.get("planner_frontier_reserve_per_section",
                     PLANNER_FRONTIER_RESERVE_PER_SECTION), minimum=0)
        self.planner_candidate_probe_limit = self._int(
            "CHECKPC_D2_PLANNER_PROBE_LIMIT",
            base.get("planner_candidate_probe_limit", PLANNER_CANDIDATE_PROBE_LIMIT), minimum=1)
        self.planner_replan_limit = self._int(
            "CHECKPC_D2_PLANNER_REPLAN_LIMIT",
            base.get("planner_replan_limit", PLANNER_REPLAN_LIMIT), minimum=1)
        self.planner_cancel_check_interval = self._int(
            "CHECKPC_D2_PLANNER_CANCEL_INTERVAL",
            base.get("planner_cancel_check_interval", PLANNER_CANCEL_CHECK_INTERVAL), minimum=1)
        self.planner_progress_interval = self._int(
            "CHECKPC_D2_PLANNER_PROGRESS_INTERVAL",
            base.get("planner_progress_interval", PLANNER_PROGRESS_INTERVAL), minimum=1)
        self.planner_trim_iteration_limit = self._int(
            "CHECKPC_D2_PLANNER_TRIM_ITERATION_LIMIT",
            base.get("planner_trim_iteration_limit", PLANNER_TRIM_ITERATION_LIMIT), minimum=1)

        self.tok_per_entry_table = dict(base["tok_per_entry"])
        self.sec_cap_table = dict(base["sec_cap_d2"])
        self.sec_cap_table["directory"] = self._int(
            "CHECKPC_DIR_MAX_LLM_D2", self.sec_cap_table.get("directory", 200), minimum=1)
        for sec, value in self.tok_per_entry_table.items():
            if value < 0:
                raise ConfigurationError(f"tok_per_entry[{sec}] must be >=0")
        for sec, value in self.sec_cap_table.items():
            if value < 0:
                raise ConfigurationError(f"sec_cap_d2[{sec}] must be >=0")

    def _int(self, name, default, **kwargs):
        value = env_int(name, int(default), **kwargs)
        if name in os.environ and os.environ.get(name) != "":
            self.environment_overrides[name] = value
        return value

    def _float(self, name, default, **kwargs):
        value = env_float(name, float(default), **kwargs)
        if name in os.environ and os.environ.get(name) != "":
            self.environment_overrides[name] = value
        return value

    def tok_per_entry(self, section, lean=None):
        """Return output-token estimate; ``lean`` is a compatibility no-op.

        FULL/LEAN may still produce different chunk counts because their fixed
        input prompt tokens differ.  Do not infer selected-set equality from
        this compatibility parameter.
        """
        return int(self.tok_per_entry_table.get(section, _TOK_PER_ENTRY_DEFAULT))

    def section_cap(self, section):
        return int(self.sec_cap_table.get(section, _SEC_CAP_D2_DEFAULT))

    def is_llm_budgeted(self, section):
        return self.tok_per_entry(section) > 0

    def risk_budget(self, remaining):
        return int(remaining * self.risk_ratio)

    def fair_budget(self, remaining):
        return int(remaining * self.fair_ratio)

    def novelty_budget(self, remaining):
        return int(remaining * self.novelty_ratio)

    def to_dict(self):
        data = {
            "name": self.name,
            "provisional": self.provisional,
            "validated": self.validated,
            "d2_output_token_budget": self.d2_output_token_budget,
            "ratios": {"risk": self.risk_ratio, "fair": self.fair_ratio, "novelty": self.novelty_ratio},
            "d2_min_rep": self.d2_min_rep,
            "novelty_min_rep": self.novelty_min_rep,
            "novelty_section_cap": self.novelty_section_cap,
            "sig_max_d2": self.sig_max_d2,
            "tokens_per_chunk_overhead": self.tokens_per_chunk_overhead,
            "token_estimate_safety_factor": self.token_estimate_safety_factor,
            "tok_per_entry": dict(self.tok_per_entry_table),
            "sec_cap_d2": dict(self.sec_cap_table),
            "section_chunk_cap": self.section_chunk_cap,
            "planner_trim_batch_max": self.planner_trim_batch_max,
            "planner_frontier_reserve_per_section": self.planner_frontier_reserve_per_section,
            "planner_candidate_probe_limit": self.planner_candidate_probe_limit,
            "planner_replan_limit": self.planner_replan_limit,
            "planner_cancel_check_interval": self.planner_cancel_check_interval,
            "planner_progress_interval": self.planner_progress_interval,
            "planner_trim_iteration_limit": self.planner_trim_iteration_limit,
            "environment_overrides": dict(self.environment_overrides),
            "warning": ("v3.69正式版の数値予算を継承。v3.70運用切替前にbase117実機E2Eで再検証すること。"
                        if self.provisional else ""),
        }
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        data["fingerprint"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return data

_ACTIVE = None


def active_profile():
    global _ACTIVE
    if _ACTIVE is None:
        _ACTIVE = BudgetProfile()
    return _ACTIVE


def reset_profile():
    global _ACTIVE
    _ACTIVE = None
    return active_profile()

# rc23 changes only Defender deterministic provenance completeness.  Selection,
# planner, token budget, ratios and all other profile values remain unchanged.
PROFILES["v369-rc23-provisional"] = deepcopy(PROFILES["v369-rc22-provisional"])
PROFILES["v369-rc23-provisional"]["note"] = (
    "Unvalidated v3.69-rc23 values; identical rc22 planner and budget, "
    "with Defender Depth2 provenance completeness fixed."
)

# rc24 adds complete provenance to all-raw rule-based sections only.
# Planner, token budget, ratios and numeric profile values remain unchanged.
PROFILES["v369-rc27-provisional"] = deepcopy(PROFILES["v369-rc23-provisional"])
PROFILES["v369-rc27-provisional"]["note"] = (
    "Unvalidated v3.69-rc26 values; identical rc23 planner and budget, "
    "with task_141, rdp_inbound and userassist provenance completeness fixed."
)

# rc28 keeps the rc27 numeric envelope and changes only semantic binding
# presentation, singleton omission recovery, deterministic aggregate provenance,
# and release-strict validation.  Selection and budget calibration are unchanged.
PROFILES["v369-rc29-provisional"] = deepcopy(PROFILES["v369-rc27-provisional"])
PROFILES["v369-rc29-provisional"]["note"] = (
    "Unvalidated v3.69-rc29 values; identical rc27 planner and budget, "
    "with explicit binding identifiers and validation completeness fixes."
)



# Formal v3.69 keeps the exact rc29 numeric/planner envelope and marks the
# separately measured base117 profile as validated.
PROFILES["v369"] = deepcopy(PROFILES["v369-rc29-provisional"])
PROFILES["v369"].update({
    "name": "v369",
    "provisional": False,
    "validated": True,
    "note": (
        "Formal v3.69 profile validated on base117; numeric planning and budget "
        "values are identical to v369-rc29-provisional."
    ),
})

# rc30 keeps the rc29 numeric envelope while changing directory evidence
# admission, bounded M1 stratification, Tier-R residual allocation and chat raw fallback.
PROFILES["v369-rc30-provisional"] = deepcopy(PROFILES["v369-rc29-provisional"])
PROFILES["v369-rc30-provisional"]["note"] = (
    "Unvalidated v3.69-rc30 values; rc29 numeric budget with canonical directory "
    "M0/M1/Tier-R selection and raw-search grounding fixes."
)

# v3.70 retains the formally released v3.69 numeric envelope.  This profile
# changes directory evidence completeness/visibility and not the measured
# token budget itself.  base117 end-to-end validation is still required before
# operational promotion.
PROFILES["v370"] = deepcopy(PROFILES["v369"])
PROFILES["v370"]["name"] = "v370"
# base117 end-to-end validation completed on 2026-08-05.  Only the validation
# metadata below changes at promotion; every numeric field is still inherited
# verbatim from the formal v369 profile by the deepcopy above.
PROFILES["v370"]["provisional"] = False
PROFILES["v370"]["validated"] = True
PROFILES["v370"]["note"] = (
    "v3.70 directory evidence policy; formal v3.69 numeric budget retained. "
    "Validated by base117 real-machine end-to-end verification (2026-08-05)."
)
