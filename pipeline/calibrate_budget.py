#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Aggregate calibration metrics without mixing incompatible run profiles."""
from __future__ import annotations
import argparse
import csv
import glob
import json
import os
import statistics
from collections import defaultdict
from pathlib import Path
from atomic_io import atomic_write_json

PERCENTILES = (50, 90, 95, 99)


def pct(values, p):
    if not values:
        return None
    vals = sorted(float(v) for v in values)
    k = (len(vals) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(vals) - 1)
    if lo == hi:
        return vals[lo]
    return vals[lo] + (vals[hi] - vals[lo]) * (k - lo)


def metric_summary(values):
    vals = [float(v) for v in values if isinstance(v, (int, float))]
    if not vals:
        return {"count": 0, "sum": 0, "mean": None, "max": None,
                **{f"p{p}": None for p in PERCENTILES}}
    return {
        "count": len(vals), "sum": sum(vals), "mean": statistics.mean(vals),
        "max": max(vals), **{f"p{p}": pct(vals, p) for p in PERCENTILES},
    }


def _load_manifest(analyzed_path: str) -> dict:
    p = Path(analyzed_path).resolve().parent / "ingest_manifest.json"
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _run_identity(doc: dict, manifest: dict) -> dict:
    meta = dict(doc.get("meta") or {})
    prof = doc.get("_budget_profile") or {}
    return {
        "depth": doc.get("depth", meta.get("depth", manifest.get("depth", "unknown"))),
        "analysis_mode": meta.get("analysis_mode", manifest.get("analysis_mode", "unknown")),
        "model": meta.get("model", manifest.get("model", "unknown")),
        "budget_profile": meta.get("budget_profile", prof.get("name", manifest.get("budget_profile", "unknown"))),
        "budget_profile_fingerprint": meta.get(
            "budget_profile_fingerprint", prof.get("fingerprint", manifest.get("budget_profile_fingerprint", "unknown"))),
        "pipeline_max_workers": meta.get("pipeline_max_workers", manifest.get("pipeline_max_workers", "unknown")),
        "max_inflight_llm": meta.get("max_inflight_llm", manifest.get("max_inflight_llm", "unknown")),
        "pipeline_version": meta.get("pipeline_version", manifest.get("pipeline_version", "unknown")),
    }


def _identity_key(identity: dict) -> str:
    return "|".join(str(identity[k]) for k in (
        "depth", "analysis_mode", "model", "budget_profile",
        "budget_profile_fingerprint", "pipeline_max_workers", "max_inflight_llm"))


def summarize(paths, *, allow_mixed_profiles=False):
    groups = {}
    fingerprints = set()
    invalid = []
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            invalid.append({"path": path, "error": str(exc)})
            continue
        manifest = _load_manifest(path)
        identity = _run_identity(doc, manifest)
        fp = identity["budget_profile_fingerprint"]
        if fp not in (None, "", "unknown"):
            fingerprints.add(str(fp))
        key = _identity_key(identity)
        if key not in groups:
            groups[key] = {
                "identity": identity, "files": [],
                "run_metrics": defaultdict(list),
                "sections": defaultdict(lambda: defaultdict(list)),
                "counters": defaultdict(int),
            }
        g = groups[key]
        g["files"].append(os.path.abspath(path))
        timing = doc.get("_timing_summary") or {}
        if isinstance(timing.get("total_elapsed_sec"), (int, float)):
            g["run_metrics"]["total_elapsed_sec"].append(timing["total_elapsed_sec"])
        for value_name in ("section_max_workers", "chunk_max_workers"):
            if isinstance(timing.get(value_name), (int, float)):
                g["run_metrics"][value_name].append(timing[value_name])

        for sec, sd in (doc.get("sections") or {}).items():
            if not isinstance(sd, dict):
                continue
            metrics = g["sections"][sec]
            st = sd.get("_selection_stats") or {}
            for name in ("raw", "selected", "deterministic", "deferred_by_policy",
                         "selected_unevaluated", "mandatory_selected", "risk_selected",
                         "fair_selected", "novelty_selected"):
                if isinstance(st.get(name), (int, float)):
                    metrics[name].append(st[name])
                    if name == "selected_unevaluated":
                        g["counters"]["selected_unevaluated"] += int(st[name])
            if isinstance(sd.get("_elapsed_sec"), (int, float)):
                metrics["section_elapsed_sec"].append(sd["_elapsed_sec"])
            for t in sd.get("_chunk_timings") or []:
                if not isinstance(t, dict):
                    continue
                mapping = {
                    "prompt_tokens": "actual_prompt_tokens",
                    "completion_tokens": "actual_completion_tokens",
                    "elapsed_sec": "chunk_elapsed_sec",
                    "estimated_data_tokens": "estimated_data_tokens",
                    "estimated_fixed_prompt_tokens": "estimated_fixed_prompt_tokens",
                    "estimated_total_prompt_tokens": "estimated_total_prompt_tokens",
                }
                for src, dst in mapping.items():
                    v = t.get(src)
                    if isinstance(v, (int, float)):
                        metrics[dst].append(v)
                actual = t.get("prompt_tokens")
                estimated = t.get("estimated_total_prompt_tokens")
                if isinstance(actual, (int, float)) and isinstance(estimated, (int, float)) and estimated > 0:
                    metrics["actual_estimated_prompt_ratio"].append(actual / estimated)
                if t.get("retry"):
                    g["counters"]["retry"] += 1
                    metrics["retry_count"].append(1)
                if t.get("retry_unrecovered") or t.get("unrecovered"):
                    g["counters"]["retry_unrecovered"] += 1
                if t.get("finish_reason") == "length":
                    g["counters"]["finish_reason_length"] += 1
                    metrics["finish_length_count"].append(1)
                if t.get("oversize") or t.get("context_length_exceeded"):
                    g["counters"]["oversize_or_context_limit"] += 1
                if t.get("coverage_retry") or t.get("split_depth"):
                    g["counters"]["coverage_split_or_retry"] += 1

    if len(fingerprints) > 1 and not allow_mixed_profiles:
        raise ValueError(
            "multiple budget profile fingerprints detected; rerun per profile or use --allow-mixed-profiles: "
            + ", ".join(sorted(fingerprints)))

    output_groups = []
    for key, g in sorted(groups.items()):
        output_groups.append({
            "group_key": key,
            "identity": g["identity"],
            "file_count": len(g["files"]),
            "files": g["files"],
            "run_metrics": {k: metric_summary(v) for k, v in sorted(g["run_metrics"].items())},
            "counters": dict(sorted(g["counters"].items())),
            "sections": {
                sec: {k: metric_summary(v) for k, v in sorted(metrics.items())}
                for sec, metrics in sorted(g["sections"].items())
            },
        })
    return {
        "input_file_count": len(paths),
        "valid_file_count": sum(g["file_count"] for g in output_groups),
        "invalid_files": invalid,
        "budget_profile_fingerprints": sorted(fingerprints),
        "groups": output_groups,
    }


def write_csv(path: str, result: dict) -> None:
    fields = [
        "group_key", "depth", "analysis_mode", "model", "budget_profile",
        "budget_profile_fingerprint", "pipeline_max_workers", "max_inflight_llm",
        "scope", "section", "metric", "count", "sum", "mean", "p50", "p90", "p95", "p99", "max",
    ]
    tmp = Path(path).with_suffix(Path(path).suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for group in result["groups"]:
            ident = group["identity"]
            base = {"group_key": group["group_key"], **{k: ident.get(k) for k in fields if k in ident}}
            for metric, sm in group["run_metrics"].items():
                w.writerow({**base, "scope": "run", "section": "", "metric": metric, **sm})
            for sec, metrics in group["sections"].items():
                for metric, sm in metrics.items():
                    w.writerow({**base, "scope": "section", "section": sec, "metric": metric, **sm})
            for metric, value in group["counters"].items():
                w.writerow({**base, "scope": "counter", "section": "", "metric": metric,
                            "count": 1, "sum": value, "mean": value, "max": value})
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--output", "-o", default="calibration_v369.json")
    ap.add_argument("--csv-output", default="")
    ap.add_argument("--allow-mixed-profiles", action="store_true")
    args = ap.parse_args()
    paths = []
    for item in args.inputs:
        expanded = glob.glob(item, recursive=True)
        paths.extend(expanded or [item])
    paths = sorted({p for p in paths if os.path.isfile(p)})
    try:
        result = summarize(paths, allow_mixed_profiles=args.allow_mixed_profiles)
    except ValueError as exc:
        ap.error(str(exc))
    atomic_write_json(args.output, result)
    csv_output = args.csv_output or str(Path(args.output).with_suffix(".csv"))
    write_csv(csv_output, result)
    print(f"calibration files={result['valid_file_count']} groups={len(result['groups'])} "
          f"json={args.output} csv={csv_output}")


if __name__ == "__main__":
    main()
