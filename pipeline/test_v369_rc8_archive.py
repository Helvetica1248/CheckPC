#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 background archive, reuse, safety and queue regressions."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import zipfile
from pathlib import Path

from archive_manager import ArchiveManager, ArchiveRequestError
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION

PASS = FAIL = 0

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"[PASS] {name}"); PASS += 1
    else:
        print(f"[FAIL] {name}" + (f" :: {detail}" if detail else "")); FAIL += 1


def wait_status(mgr, jid, kind, terminal=("ready", "error"), timeout=10):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        last = mgr.status(jid, kind)
        if last.get("status") in terminal:
            return last
        time.sleep(0.03)
    return last or {}


def mkjob(root: Path, jid: str, status="done", *, lean=True):
    job_root = root / jid
    run = job_root / "output" / "HOST_20260722"
    run.mkdir(parents=True)
    mode = "LEAN" if lean else "FULL"
    analyzed = {
        "meta": {
            "pipeline_version": PIPELINE_VERSION,
            "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
            "parser_version": ANALYSIS_SCHEMA_VERSION,
            "budget_profile": "v370",
            "analysis_mode": mode,
        },
        "sections": {},
    }
    manifest = {
        "pipeline_version": PIPELINE_VERSION,
        "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
        "budget_profile": "v370",
        "analysis_mode": mode,
    }
    (run / "analyzed_HOST_20260722.json").write_text(
        json.dumps(analyzed) + "\n", encoding="utf-8")
    (run / "ingest_manifest.json").write_text(
        json.dumps(manifest) + "\n", encoding="utf-8")
    (run / "correlation_HOST_20260722.json").write_text('{"corr":1}\n', encoding="utf-8")
    (run / "report_HOST_20260722.md").write_text('# report\n', encoding="utf-8")
    (run / "report_HOST_20260722_timeline.md").write_text('# timeline\n', encoding="utf-8")
    (run / "parsed_HOST_20260722.json").write_text('{"parsed":1}\n', encoding="utf-8")
    (run / "other.bin").write_bytes(b"x" * 4096)
    (job_root / "job.log.jsonl").write_text('{"message":"ok"}\n', encoding="utf-8")
    (job_root / "chat_tool_log.jsonl").write_text('{"tool":"vt"}\n', encoding="utf-8")
    return {
        "job_id": jid, "status": status, "output_dir": str(job_root / "output"),
        "finished_at": time.time(), "hostname": "HOST", "lean": lean,
        "pipeline_version": PIPELINE_VERSION,
        "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
        "budget_profile": "v370",
    }


check("A0 pipeline version rc9", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("A0 schema version rc9", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)

with tempfile.TemporaryDirectory(prefix="checkpc_rc8_archive_") as td:
    root = Path(td)
    job = mkjob(root, "job1")
    fb = root / "_audit_fallback" / "job1"
    fb.mkdir(parents=True)
    (fb / "chat_tool_log.jsonl").write_text('{"fallback":1}\n', encoding="utf-8")
    mgr = ArchiveManager(root, queue_max=4, timeout_sec=10, large_threshold_mb=1)

    # Invalid and non-terminal requests.
    try:
        mgr.request(job, "bad", "auto")
        check("A1 invalid kind rejected", False)
    except ArchiveRequestError as e:
        check("A1 invalid kind rejected", e.status_code == 400 and e.error_kind == "invalid_archive_kind")
    running = dict(job, job_id="running", status="running")
    try:
        mgr.request(running, "validation", "auto")
        check("A2 non-terminal rejected", False)
    except ArchiveRequestError as e:
        check("A2 non-terminal rejected", e.status_code == 409 and e.error_kind == "job_not_terminal")

    st0 = mgr.request(job, "validation", "auto")
    check("A3 request returns queued immediately", st0["status"] == "queued")
    # Same request must deduplicate, not enqueue another build.
    st_dup = mgr.request(job, "validation", "auto")
    check("A4 same job/kind request deduplicated", st_dup.get("deduplicated") is True)
    try:
        mgr.request(job, "full", "auto")
        check("A5 same job second kind blocked while active", False)
    except ArchiveRequestError as e:
        check("A5 same job second kind blocked while active", e.error_kind == "archive_job_busy")

    ready = wait_status(mgr, "job1", "validation")
    check("A6 validation ready", ready.get("status") == "ready", ready)
    check("A7 effective compression normal", ready.get("effective_compression") == "normal", ready)
    check("A8 progress reaches all files", ready.get("files_completed") == ready.get("files_total"), ready)
    check("A9 progress bytes reaches total", ready.get("bytes_processed") == ready.get("bytes_total"), ready)
    zpath = Path(ready["archive_path"])
    check("A10 ZIP exists outside output", zpath.is_file() and not str(zpath).startswith(job["output_dir"]))
    with zipfile.ZipFile(zpath) as zf:
        names = zf.namelist()
        check("A11 manifest included", names[-1] == "archive_manifest.json", names)
        check("A12 validation analyzed included", any("analyzed_" in n for n in names), names)
        check("A13 validation report timeline included", any(n.endswith("_timeline.md") for n in names), names)
        check("A14 validation job log included", "job.log.jsonl" in names, names)
        check("A15 validation chat audit included", "chat_tool_log.jsonl" in names, names)
        check("A16 validation fallback audit included", "_audit_fallback/chat_tool_log.jsonl" in names, names)
        check("A17 validation parsed excluded", not any("parsed_" in n for n in names), names)
        check("A18 validation other file excluded", not any(n.endswith("other.bin") for n in names), names)
        manifest = json.loads(zf.read("archive_manifest.json"))
        check("A19 validation provenance warning", manifest.get("provenance_recoverable") is False)
        check("A20 manifest carries version/profile", manifest.get("pipeline_version") == "3.70" and bool(manifest.get("budget_profile")), manifest)
        check("A20b manifest carries mode", manifest.get("analysis_mode") == "LEAN", manifest)

    # open_ready acquires fd before transfer.
    fh, filename, size = mgr.open_ready("job1", "validation")
    try:
        check("A21 open_ready filename", filename == "validation_LEAN.zip", filename)
        check("A22 open_ready size", size == zpath.stat().st_size)
        check("A23 open_ready readable", fh.read(2) == b"PK")
    finally:
        fh.close()

    # testzip must never be used on reuse hot path.
    original_testzip = zipfile.ZipFile.testzip
    def forbidden(*a, **k):
        raise AssertionError("testzip hot path")
    zipfile.ZipFile.testzip = forbidden
    try:
        reuse_req = mgr.request(job, "validation", "auto")
        check("A24 reuse request is asynchronous queued", reuse_req.get("status") == "queued")
        reused = wait_status(mgr, "job1", "validation")
        check("A25 ready archive reused", reused.get("status") == "ready" and reused.get("reused") is True, reused)
    finally:
        zipfile.ZipFile.testzip = original_testzip

    # Source mutation invalidates reuse and rebuilds.
    report = Path(job["output_dir"]) / "HOST_20260722" / "report_HOST_20260722.md"
    old_sha = reused.get("archive_sha256")
    report.write_text('# changed report\n', encoding="utf-8")
    os.utime(report, None)
    mgr.request(job, "validation", "auto")
    rebuilt = wait_status(mgr, "job1", "validation")
    check("A26 source change rebuilds", rebuilt.get("status") == "ready" and rebuilt.get("reused") is False, rebuilt)
    check("A27 rebuilt archive hash changes", rebuilt.get("archive_sha256") != old_sha)

    # Profile conflict with a ready archive.
    try:
        mgr.request(job, "validation", "store")
        check("A28 ready profile conflict rejected", False)
    except ArchiveRequestError as e:
        check("A28 ready profile conflict rejected", e.status_code == 409 and e.error_kind == "archive_profile_conflict")

    # Full archive includes parsed and arbitrary regular artifacts but never archives/ itself.
    full_req = mgr.request(job, "full", "store")
    check("A29 full queued", full_req.get("status") == "queued")
    full = wait_status(mgr, "job1", "full")
    check("A30 full ready", full.get("status") == "ready", full)
    check("A31 full store compression", full.get("effective_compression") == "store", full)
    with zipfile.ZipFile(full["archive_path"]) as zf:
        names = zf.namelist()
        check("A32 full parsed included", any("parsed_" in n for n in names), names)
        check("A33 full other included", any(n.endswith("other.bin") for n in names), names)
        check("A34 full self archive excluded", not any("archives/" in n for n in names), names)
        m = json.loads(zf.read("archive_manifest.json"))
        check("A35 full provenance recoverable", m.get("provenance_recoverable") is True)

    # Symlink directory and file must not escape or appear.
    outside = root / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    outroot = Path(job["output_dir"])
    try:
        (outroot / "escape_dir").symlink_to(outside, target_is_directory=True)
        (outroot / "escape_file").symlink_to(outside / "secret.txt")
        # Change source snapshot so full is rebuilt using same profile.
        (outroot / "HOST_20260722" / "new.txt").write_text("new", encoding="utf-8")
        mgr.request(job, "full", "store")
        full2 = wait_status(mgr, "job1", "full")
        with zipfile.ZipFile(full2["archive_path"]) as zf:
            names = zf.namelist()
            check("A36 directory symlink excluded", not any("escape_dir" in n for n in names), names)
            check("A37 file symlink excluded", not any("escape_file" in n for n in names), names)
            check("A38 outside secret excluded", not any("secret.txt" in n for n in names), names)
    except (OSError, NotImplementedError):
        check("A36 directory symlink excluded", True, "symlink unsupported")
        check("A37 file symlink excluded", True, "symlink unsupported")
        check("A38 outside secret excluded", True, "symlink unsupported")

    check("A39 manager inactive after builds", not mgr.is_job_active("job1"))
    mgr.forget_job("job1")
    check("A40 forget removes in-memory states", mgr.status("job1", "validation")["status"] == "none")

# Bounded queue and global one-builder behavior using a delayed builder.
with tempfile.TemporaryDirectory(prefix="checkpc_rc8_queue_") as td:
    root = Path(td)
    jobs = [mkjob(root, f"q{i}") for i in range(4)]
    mgr = ArchiveManager(root, queue_max=1, timeout_sec=10)
    original = mgr._build_zip
    gate = threading.Event()
    entered = []
    counters = {"active": 0, "max_active": 0}
    lock = threading.Lock()
    def slow(*args, **kwargs):
        with lock:
            counters["active"] += 1
            counters["max_active"] = max(counters["max_active"], counters["active"])
            entered.append(args[2]["job_id"])
        gate.wait(1.5)
        try:
            return original(*args, **kwargs)
        finally:
            with lock:
                counters["active"] -= 1
    mgr._build_zip = slow
    mgr.request(jobs[0], "validation", "auto")
    end = time.time() + 2
    while not entered and time.time() < end: time.sleep(0.01)
    mgr.request(jobs[1], "validation", "auto")
    try:
        mgr.request(jobs[2], "validation", "auto")
        check("A41 bounded queue rejects overflow", False)
    except ArchiveRequestError as e:
        check("A41 bounded queue rejects overflow", e.status_code == 429 and e.error_kind == "archive_queue_full")
    gate.set()
    s0 = wait_status(mgr, "q0", "validation")
    s1 = wait_status(mgr, "q1", "validation")
    check("A42 queued jobs complete", s0.get("status") == "ready" and s1.get("status") == "ready", (s0,s1))
    check("A43 global building maximum one", counters["max_active"] == 1, counters["max_active"])

print(f"PASS={PASS} FAIL={FAIL}")
raise SystemExit(1 if FAIL else 0)
