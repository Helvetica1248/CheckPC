#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Preflight checks for CheckPC Analysis Pipeline deployments."""
from __future__ import annotations
import argparse
import json
import os
import shutil
import socket
import ssl
import sys
import urllib.request
from pathlib import Path

from budget_profile import active_profile
from path_safety import resolved
from pipeline_settings import runtime_settings
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION


def check(name, status, detail, required=True):
    return {"name": name, "status": status, "detail": str(detail), "required": required}


def run_checks(skip_vllm=False):
    out = []
    out.append(check("python", "PASS" if sys.version_info >= (3, 10) else "FAIL", sys.version.split()[0]))
    try:
        rt = runtime_settings()
        out.append(check("runtime_settings", "PASS", rt))
    except Exception as exc:
        out.append(check("runtime_settings", "FAIL", exc))
        rt = None
    try:
        prof = active_profile().to_dict()
        out.append(check("budget_profile", "PASS", f"{prof.get('name')} {prof.get('fingerprint')}"))
    except Exception as exc:
        out.append(check("budget_profile", "FAIL", exc))

    jobs_dir = resolved(os.environ.get("PIPELINE_JOBS_DIR", "/opt/llm/jobs"))
    try:
        jobs_dir.mkdir(parents=True, exist_ok=True)
        probe = jobs_dir / ".doctor_write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        usage = shutil.disk_usage(jobs_dir)
        out.append(check("jobs_dir", "PASS", f"{jobs_dir} free={usage.free // (1024**3)}GiB"))
    except Exception as exc:
        out.append(check("jobs_dir", "FAIL", exc))

    try:
        import reportlab
        import pdf_export
        out.append(check(
            "pdf_export", "PASS",
            f"python={sys.executable} reportlab={getattr(reportlab, '__version__', '?')} "
            f"module={getattr(pdf_export, '__file__', '?')}"))
    except Exception as exc:
        out.append(check(
            "pdf_export", "FAIL",
            f"python={sys.executable} {type(exc).__name__}: {exc}"))

    for cmd, required in (("openssl", True), ("cabextract", True), ("nkf", False), ("python2.7", False)):
        found = shutil.which(cmd)
        out.append(check(f"command:{cmd}", "PASS" if found else ("FAIL" if required else "WARN"),
                         found or "not found", required=required))
    shim = Path(os.environ.get("CHECKPC_SHIMCACHE_PARSER", "/opt/llm/batchtools/ShimCacheParser.py"))
    out.append(check("ShimCacheParser", "PASS" if shim.is_file() else "WARN", shim, required=False))

    user = os.environ.get("PIPELINE_AUTH_USER", "")
    pbkdf2 = os.environ.get("PIPELINE_AUTH_PBKDF2", "")
    api_key = os.environ.get("PIPELINE_API_KEY", "")
    auth_ok = bool((user and pbkdf2) or api_key)
    out.append(check("authentication", "PASS" if auth_ok else "WARN",
                     "configured" if auth_ok else "not configured; localhost bind only", required=False))
    cert, key = os.environ.get("PIPELINE_SSL_CERT", ""), os.environ.get("PIPELINE_SSL_KEY", "")
    if bool(cert) != bool(key):
        out.append(check("tls_pair", "FAIL", "certificate/key must be set together"))
    elif cert:
        ok = Path(cert).is_file() and Path(key).is_file()
        out.append(check("tls_pair", "PASS" if ok else "FAIL", f"cert={cert} key={key}"))
    else:
        out.append(check("tls_pair", "WARN", "TLS not configured", required=False))

    if not skip_vllm:
        url = os.environ.get("VLLM_URL", "http://127.0.0.1:8000/v1").rstrip("/") + "/models"
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                body = json.loads(resp.read().decode("utf-8", "replace"))
            models = [x.get("id") for x in body.get("data", []) if isinstance(x, dict)]
            configured = os.environ.get("VLLM_MODEL", os.environ.get("CHAT_MODEL", ""))
            status = "PASS" if (not configured or configured in models) else "FAIL"
            out.append(check("vllm", status, f"url={url} models={models} configured={configured or '(auto)'}"))
        except Exception as exc:
            out.append(check("vllm", "FAIL", exc))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", dest="json_path", default="")
    ap.add_argument("--skip-vllm", action="store_true")
    args = ap.parse_args()
    checks = run_checks(args.skip_vllm)
    for item in checks:
        print(f"[{item['status']:<4}] {item['name']}: {item['detail']}")
    result = {
        "pipeline_version": PIPELINE_VERSION,
        "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
        "checks": checks,
        "pass": all(x["status"] != "FAIL" for x in checks if x["required"]),
    }
    if args.json_path:
        Path(args.json_path).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
