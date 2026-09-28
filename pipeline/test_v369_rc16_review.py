#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 regressions: malformed service commands and runtime/archive identity."""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import time
import zipfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import analyze_section
from archive_manager import ArchiveManager
from pipeline_errors import PipelineError
from runtime_identity import (
    assert_runtime_identity, assert_artifact_identity, artifact_identity,
)
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


def wait_ready(mgr, jid, kind="validation", timeout=8):
    end = time.time() + timeout
    last = {}
    while time.time() < end:
        last = mgr.status(jid, kind)
        if last.get("status") in {"ready", "error"}:
            return last
        time.sleep(0.02)
    return last


print("\n--- RC16 identity ---")
check("pipeline version", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("schema version", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("profile version", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)
identity = assert_runtime_identity()
check("runtime guard passes", identity.get("pipeline_version") == PIPELINE_VERSION, identity)

base_doc = {
    "meta": {
        "pipeline_version": PIPELINE_VERSION,
        "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
        "parser_version": ANALYSIS_SCHEMA_VERSION,
        "budget_profile": BUDGET_PROFILE_DEFAULT,
        "analysis_mode": "FULL",
    }
}
check("artifact identity extraction", artifact_identity(base_doc).get("analysis_mode") == "FULL")
check("artifact identity passes", bool(assert_artifact_identity(
    base_doc, label="test", analysis_mode="FULL", require_parser=True)))
try:
    bad = copy.deepcopy(base_doc)
    bad["meta"]["pipeline_version"] = "3.69-rc15"
    assert_artifact_identity(bad, label="stale", analysis_mode="FULL", require_parser=True)
    rejected = False
except PipelineError:
    rejected = True
check("stale artifact version rejected", rejected)
try:
    assert_artifact_identity(base_doc, label="mode", analysis_mode="LEAN", require_parser=True)
    rejected = False
except PipelineError:
    rejected = True
check("artifact mode mismatch rejected", rejected)


print("\n--- malformed Event 7045 ImagePath ---")
malformed = (
    r'C:\Program Files\RustDesk\RustDesk.exe" --import-config '
    r'"C:\Users\fixture-user-01\AppData\Roaming\RustDesk\config\RustDesk.toml'
)
parsed = analyze_section._parse_service_command(malformed)
check("orphan closing quote executable recovered",
      parsed.get("executable") == r"C:\Program Files\RustDesk\RustDesk.exe", parsed)
check("arguments recovered", parsed.get("arguments", "").startswith("--import-config"), parsed)
check("config path recovered",
      r"C:\Users\fixture-user-01\AppData\Roaming\RustDesk\config\RustDesk.toml"
      in parsed.get("argument_paths", []), parsed)
check("closing quote warning recorded",
      "unbalanced_closing_quote_after_executable" in parsed.get("warnings", []), parsed)
check("opening quote warning recorded",
      "unbalanced_opening_quote_in_arguments" in parsed.get("warnings", []), parsed)

normal = analyze_section._parse_service_command(
    r'"C:\Program Files\RustDesk\RustDesk.exe" --service')
check("normal quoted executable unaffected",
      normal.get("executable") == r"C:\Program Files\RustDesk\RustDesk.exe", normal)
check("normal command has no warning", normal.get("warnings") == [], normal)
plain = analyze_section._parse_service_command(
    r'C:\Program Files\Acme\acme.exe --service')
check("normal plain executable unaffected",
      plain.get("executable") == r"C:\Program Files\Acme\acme.exe", plain)
check("normal plain has no warning", plain.get("warnings") == [], plain)

raw = [{
    "source_id": "rust-1",
    "service_name": "RustDesk Service",
    "image_path": malformed,
    "account_name": "LocalSystem",
}]

def run_score(initial):
    section = {"entries": [{
        "source_id": "rust-1", "source_index": 0,
        "identifier": "RustDesk Service", "score": initial,
        "reason": "LLM provisional", "mitre": ["T1543.003"], "iocs": [],
    }]}
    return analyze_section._apply_post_filter("system_7045", section, raw)["entries"][0]

full = run_score("HIGH")
lean = run_score("LOW")
check("FULL malformed RustDesk converges MEDIUM", full.get("score") == "MEDIUM", full)
check("LEAN malformed RustDesk converges MEDIUM", lean.get("score") == "MEDIUM", lean)
check("FULL/LEAN executable identical",
      full.get("service_executable") == lean.get("service_executable")
      == r"C:\Program Files\RustDesk\RustDesk.exe", (full, lean))
check("FULL warning persisted", full.get("service_command_warning") ==
      "unbalanced_closing_quote_after_executable", full)
check("warning list persisted", set(full.get("service_command_warnings", [])) == {
      "unbalanced_closing_quote_after_executable",
      "unbalanced_opening_quote_in_arguments",
}, full)
check("argument path persisted", full.get("service_argument_paths") == [
      r"C:\Users\fixture-user-01\AppData\Roaming\RustDesk\config\RustDesk.toml"], full)
check("remote techniques retained",
      {"T1219", "T1543.003"}.issubset(set(full.get("mitre", []))), full)
check("raw command preserved", full.get("image_path_raw") == malformed, full)

raw_user = [{
    "source_id": "rust-user",
    "service_name": "RustDesk Service",
    "image_path": r'C:\Users\Public\RustDesk.exe" --service',
}]
user = analyze_section._apply_post_filter("system_7045", {"entries": [{
    "source_id": "rust-user", "identifier": "RustDesk Service",
    "score": "LOW", "reason": "x", "mitre": [], "iocs": [],
}]}, raw_user)["entries"][0]
check("malformed user-write RustDesk remains HIGH", user.get("score") == "HIGH", user)


print("\n--- archive mode-derived filename and identity gate ---")
with tempfile.TemporaryDirectory(prefix="rc16_archive_") as td:
    root = Path(td)

    def make_job(jid, mode):
        lean_mode = mode == "LEAN"
        run = root / jid / "output" / "HOST_20260724"
        run.mkdir(parents=True)
        meta = {
            "pipeline_version": PIPELINE_VERSION,
            "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
            "parser_version": ANALYSIS_SCHEMA_VERSION,
            "budget_profile": BUDGET_PROFILE_DEFAULT,
            "analysis_mode": mode,
        }
        (run / "analyzed_HOST.json").write_text(
            json.dumps({"meta": meta, "sections": {}}), encoding="utf-8")
        manifest = {k: meta[k] for k in (
            "pipeline_version", "analysis_schema_version", "budget_profile", "analysis_mode")}
        (run / "ingest_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (run / "correlation_HOST.json").write_text("{}", encoding="utf-8")
        (run / "report_HOST.md").write_text("# report\n", encoding="utf-8")
        return {
            "job_id": jid, "status": "done", "output_dir": str(root / jid / "output"),
            "hostname": "HOST", "lean": lean_mode,
            "pipeline_version": PIPELINE_VERSION,
            "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
            "budget_profile": BUDGET_PROFILE_DEFAULT,
        }

    mgr = ArchiveManager(root, queue_max=4, timeout_sec=10)
    try:
        lean_job = make_job("leanjob", "LEAN")
        mgr.request(lean_job, "validation", "store")
        lean_state = wait_ready(mgr, "leanjob")
        check("LEAN validation ready", lean_state.get("status") == "ready", lean_state)
        check("LEAN archive filename from artifact mode",
              Path(lean_state.get("archive_path", "")).name == "validation_LEAN.zip", lean_state)
        check("LEAN state mode", lean_state.get("analysis_mode") == "LEAN", lean_state)
        with zipfile.ZipFile(lean_state["archive_path"]) as zf:
            am = json.loads(zf.read("archive_manifest.json"))
        check("archive manifest mode", am.get("analysis_mode") == "LEAN", am)
        fh, name, _ = mgr.open_ready("leanjob", "validation")
        fh.close()
        check("download filename reflects LEAN", name == "validation_LEAN.zip", name)

        full_job = make_job("fulljob", "FULL")
        mgr.request(full_job, "validation", "store")
        full_state = wait_ready(mgr, "fulljob")
        check("FULL validation ready", full_state.get("status") == "ready", full_state)
        check("FULL archive filename from artifact mode",
              Path(full_state.get("archive_path", "")).name == "validation_FULL.zip", full_state)

        mismatch_job = make_job("mismatch", "FULL")
        mismatch_job["lean"] = True
        mgr.request(mismatch_job, "validation", "store")
        mismatch_state = wait_ready(mgr, "mismatch")
        check("job/artifact mode mismatch fails closed",
              mismatch_state.get("status") == "error"
              and mismatch_state.get("error_kind") == "job_artifact_mode_mismatch",
              mismatch_state)

        stale_job = make_job("stale", "LEAN")
        analyzed_path = next((root / "stale" / "output").rglob("analyzed_*.json"))
        stale_doc = json.loads(analyzed_path.read_text(encoding="utf-8"))
        stale_doc["meta"]["pipeline_version"] = "3.69-rc15"
        analyzed_path.write_text(json.dumps(stale_doc), encoding="utf-8")
        mgr.request(stale_job, "validation", "store")
        stale_state = wait_ready(mgr, "stale")
        check("stale artifact version blocks archive",
              stale_state.get("status") == "error"
              and stale_state.get("error_kind") == "artifact_identity_mismatch",
              stale_state)
    finally:
        mgr.shutdown()

print(f"\nRESULT: PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
