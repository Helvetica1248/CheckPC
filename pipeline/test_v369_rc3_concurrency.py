#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 functional two-job isolation and atomic ZIP regressions."""
from __future__ import annotations
import json
import os
import tempfile
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

PASS = FAIL = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1; print(f"  [OK]  {name}")
    else:
        FAIL += 1; print(f"  [FAIL] {name}" + (f": {detail}" if detail else ""))

with tempfile.TemporaryDirectory() as td:
    os.environ["PIPELINE_JOBS_DIR"] = td
    os.environ.pop("PIPELINE_API_KEY", None)
    os.environ.pop("PIPELINE_AUTH_USER", None)
    os.environ.pop("PIPELINE_AUTH_PBKDF2", None)
    import server as sv
    from fastapi.testclient import TestClient

    barrier = threading.Barrier(2)
    original_run = sv.run
    def fake_run(input_path, *, output_dir, context="", progress_callback=None, **kwargs):
        marker = Path(input_path).read_text(encoding="utf-8")
        run_dir = Path(output_dir) / marker
        run_dir.mkdir(parents=True, exist_ok=True)
        if progress_callback:
            progress_callback(f"marker:{marker}")
        barrier.wait(timeout=5)
        parsed = run_dir / f"parsed_{marker}.json"
        analyzed = run_dir / f"analyzed_{marker}.json"
        manifest = run_dir / "ingest_manifest.json"
        report = run_dir / f"report_{marker}.md"
        parsed.write_text(json.dumps({"meta":{"hostname":marker}}), encoding="utf-8")
        analyzed.write_text(json.dumps({
            "meta": {
                "hostname": marker,
                "pipeline_version": sv.PIPELINE_VERSION,
                "analysis_schema_version": sv.ANALYSIS_SCHEMA_VERSION,
                "parser_version": sv.ANALYSIS_SCHEMA_VERSION,
                "budget_profile": sv.BUDGET_PROFILE_DEFAULT,
                "analysis_mode": "LEAN",
            },
            "marker": marker,
        }), encoding="utf-8")
        manifest.write_text(json.dumps({
            "pipeline_version": sv.PIPELINE_VERSION,
            "analysis_schema_version": sv.ANALYSIS_SCHEMA_VERSION,
            "budget_profile": sv.BUDGET_PROFILE_DEFAULT,
            "analysis_mode": "LEAN",
        }), encoding="utf-8")
        report.write_text(f"# {marker}\n", encoding="utf-8")
        return {"run_dir":str(run_dir), "parsed":str(parsed), "analyzed":str(analyzed),
                "manifest":str(manifest), "report":str(report)}
    sv.run = fake_run
    jobs=[]
    for marker in ("JOB_A", "JOB_B"):
        job=sv._new_job(marker + ".txt")
        inp=Path(td)/job["job_id"]/"input"/job["stored_filename"]
        inp.parent.mkdir(parents=True, exist_ok=True)
        inp.write_text(marker, encoding="utf-8")
        jobs.append((job,inp,marker))
    with ThreadPoolExecutor(max_workers=2) as ex:
        futs=[ex.submit(sv._run_job, job, inp, 1, "", "", True) for job,inp,_ in jobs]
        for f in futs: f.result(timeout=10)
    sv.run = original_run

    check("C1 both jobs completed", all(sv._jobs[j["job_id"]]["status"] == "done" for j,_,_ in jobs))
    for job,_,marker in jobs:
        rec=sv._jobs[job["job_id"]]
        run_dir=Path(rec["run_dir"])
        other="JOB_B" if marker=="JOB_A" else "JOB_A"
        text="\n".join(p.read_text(encoding="utf-8") for p in run_dir.rglob("*") if p.is_file())
        check(f"C2 {marker} contains own marker", marker in text)
        check(f"C3 {marker} excludes other marker", other not in text, text)
        log=(Path(td)/job["job_id"]/"job.log.jsonl").read_text(encoding="utf-8")
        check(f"C4 {marker} log isolated", job["job_id"] in log and other not in log)

    client=TestClient(sv.app)
    jid=jobs[0][0]["job_id"]
    # A symlink planted below output must not exfiltrate external file content into ZIP.
    first_out = Path(sv._jobs[jid]["output_dir"])
    external_secret = Path(td).parent / "rc3_external_secret.txt"
    external_secret.write_text("DO_NOT_ARCHIVE", encoding="utf-8")
    link = first_out / "outside_link.txt"
    try:
        link.symlink_to(external_secret)
    except OSError:
        link = None
    legacy = client.get(f"/result/{jid}?format=zip")
    check("C5 legacy ZIP endpoint removed", legacy.status_code == 410, legacy.status_code)

    def request_zip():
        return client.post(f"/jobs/{jid}/archive", json={"kind":"validation","compression":"normal"})
    with ThreadPoolExecutor(max_workers=2) as ex:
        responses=[f.result(timeout=10) for f in [ex.submit(request_zip), ex.submit(request_zip)]]
    check("C6 concurrent archive requests accepted", all(r.status_code==202 for r in responses),
          [r.status_code for r in responses])
    import time
    status = None
    for _ in range(100):
        status = client.get(f"/jobs/{jid}/archive/status?kind=validation")
        if status.status_code == 200 and status.json().get("status") in {"ready","error"}:
            break
        time.sleep(0.05)
    check("C7 archive reaches ready", status is not None and status.json().get("status") == "ready",
          None if status is None else status.json())
    downloaded = client.get(f"/jobs/{jid}/archive/download?kind=validation")
    valid = downloaded.status_code == 200
    names=[]
    if valid:
        try:
            import io
            with zipfile.ZipFile(io.BytesIO(downloaded.content)) as zf:
                names=zf.namelist()
                valid = bool(names)
        except Exception:
            valid=False
    check("C8 archive download valid", valid, names)
    check("C9 validation excludes parsed", not any(Path(n).name.startswith("parsed_") for n in names), names)
    check("C10 validation excludes symlinked external file", "outside_link.txt" not in names, names)
    tmp_residual=list((Path(td)/jid/"archives").glob("*.tmp")) if (Path(td)/jid/"archives").exists() else []
    check("C11 no temporary ZIP residual", not tmp_residual, str(tmp_residual))
    external_secret.unlink(missing_ok=True)

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(1 if FAIL else 0)
