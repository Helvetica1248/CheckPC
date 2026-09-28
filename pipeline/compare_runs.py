#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fail-closed run/full-archive comparison gates for CheckPC v3.70.

Usage:
  python3 compare_runs.py --mode reproducibility RUN_A RUN_B --output result.json
  python3 compare_runs.py --mode cross-version RUN_A RUN_B --output result.json
  python3 compare_runs.py --mode full-lean RUN_A RUN_B --output result.json
  python3 compare_runs.py --mode depth1-depth2 RUN_DEPTH1 RUN_DEPTH2 --output result.json

Inputs must be a run directory or a full archive containing exactly one parsed
and one non-VT analyzed artifact (use --host when an archive contains many).
"""
from __future__ import annotations

import argparse
import collections
import copy
import hashlib
import json
import os
import shutil
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from atomic_io import atomic_write_json
from source_id import canonical_evidence_sha256
from comparison_approval import compute_result_id
from compare_analyzed import (
    SCORES, ORDER, canonical_key, schema_findings, two_stage_entry_multisets,
    _iter_comparable_entries,
)
from depth2_select import _sig_generic as _depth2_planner_signature
from comparison_provenance import (
    PARSED_ANALYSIS_EXEMPT_SECTIONS,
    missing_analyzed_raw_sections,
    COMPARISON_PROVENANCE_SCHEMA_VERSION,
    document_raw_evidence_fingerprint,
    raw_identity_multiset,
    sha256_file,
    expand_ranges,
    stage_indices,
    validate_section_provenance,
)

EXIT_OK, EXIT_FAIL, EXIT_INPUT, EXIT_REVIEW, EXIT_INTERNAL = 0, 1, 2, 3, 4
MODES = ("reproducibility", "cross-version", "full-lean", "depth1-depth2")
COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION = 2


# Fields that are derived during parsing and may legitimately change between
# release lines without the underlying physical evidence being added or removed.
# This normalization is intentionally scoped to cross-version comparison only;
# reproducibility and same-version comparisons remain byte-for-byte strict.
_CROSS_VERSION_DERIVED_RAW_FIELDS: dict[str, frozenset[str]] = {
    "startup_folder": frozenset({"suspicious"}),
}


def _cross_version_raw_entry(section: str, entry: Any) -> Any:
    """Return the physical-evidence view used only for cross-version matching."""
    ignored = _CROSS_VERSION_DERIVED_RAW_FIELDS.get(str(section))
    if not ignored or not isinstance(entry, Mapping):
        return entry
    return {key: value for key, value in entry.items() if str(key) not in ignored}


def _comparison_raw_identity_multiset(
    mode: str, section: str, entries: list[Any]
) -> list[str]:
    """Return raw identities, normalizing approved derived fields cross-version."""
    if mode != "cross-version" or section not in _CROSS_VERSION_DERIVED_RAW_FIELDS:
        return raw_identity_multiset(section, entries)
    counts: dict[str, int] = {}
    out: list[str] = []
    for entry in entries:
        digest = canonical_evidence_sha256(
            _cross_version_raw_entry(section, entry)
        )
        ordinal = counts.get(digest, 0)
        counts[digest] = ordinal + 1
        out.append(f"{section}:{digest}:{ordinal}")
    return out


def _cross_version_source_id_map(run: "RunArtifacts", section: str) -> dict[str, str]:
    """Map release-specific source IDs to stable cross-version physical IDs."""
    rows = _raw_sections(run.parsed).get(section, [])
    identities = _comparison_raw_identity_multiset("cross-version", section, rows)
    mapping: dict[str, str] = {}
    for row, identity in zip(rows, identities):
        if not isinstance(row, Mapping):
            continue
        source_id = str(row.get("source_id") or "")
        if source_id:
            mapping[source_id] = f"cross-version:{identity}"
    return mapping


def _cross_version_analyzed_view(run: "RunArtifacts") -> dict[str, Any]:
    """Normalize analyzed source IDs when only a parsed derived field changed."""
    view = copy.deepcopy(run.analyzed)
    sections = view.get("sections")
    if not isinstance(sections, Mapping):
        return view
    for section in _CROSS_VERSION_DERIVED_RAW_FIELDS:
        mapping = _cross_version_source_id_map(run, section)
        result = sections.get(section)
        if not isinstance(result, Mapping):
            continue
        entries = result.get("entries")
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            source_id = str(entry.get("source_id") or "")
            if source_id in mapping:
                entry["source_id"] = mapping[source_id]
    return view


def _canonical_evidence_text(value: Any) -> str:
    """Stable canonical JSON text used for evidence digests."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    )


def _evidence_digest(items: Any) -> str:
    """Digest the complete evidence set behind a truncated ``samples`` list.

    ``samples`` in an issue payload is display-only and capped at a few rows.
    Approval records are keyed by issue ID, so an ID derived from ``count`` plus
    the first N samples cannot distinguish two different evidence sets that
    happen to share their head and size.  This digest covers every element, and
    for field transitions it covers the changed field names and their a/b values
    as well as the identity, so a value-only change also changes the ID.
    """
    return hashlib.sha256(
        _canonical_evidence_text(items).encode("utf-8")
    ).hexdigest()[:32]


def _sorted_transitions(transitions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stable order for transitions regardless of raw entry ordering."""
    return sorted(
        transitions,
        key=lambda row: (
            str(row.get("identity") or ""),
            _canonical_evidence_text(row.get("fields")),
        ),
    )


def _counter_evidence(counter: "collections.Counter") -> list[list[Any]]:
    """Stable full-evidence view of an identity multiset difference."""
    return [[str(key), int(count)] for key, count in sorted(counter.items())]


def _compare_cross_version_derived_fields(
    a: "RunArtifacts", b: "RunArtifacts", issues: list[dict[str, Any]]
) -> None:
    """Report parser-derived field transitions as REVIEW, not raw removal."""
    raw_a, raw_b = _raw_sections(a.parsed), _raw_sections(b.parsed)
    for section, fields in _CROSS_VERSION_DERIVED_RAW_FIELDS.items():
        rows_a = raw_a.get(section, [])
        rows_b = raw_b.get(section, [])
        ids_a = _comparison_raw_identity_multiset("cross-version", section, rows_a)
        ids_b = _comparison_raw_identity_multiset("cross-version", section, rows_b)
        by_a: dict[str, list[Any]] = collections.defaultdict(list)
        by_b: dict[str, list[Any]] = collections.defaultdict(list)
        for identity, row in zip(ids_a, rows_a):
            by_a[identity].append(row)
        for identity, row in zip(ids_b, rows_b):
            by_b[identity].append(row)
        transitions: list[dict[str, Any]] = []
        for identity in sorted(set(by_a) & set(by_b)):
            left_rows, right_rows = by_a[identity], by_b[identity]
            for index in range(min(len(left_rows), len(right_rows))):
                left, right = left_rows[index], right_rows[index]
                if not isinstance(left, Mapping) or not isinstance(right, Mapping):
                    continue
                changed = {
                    field: {"a": left.get(field), "b": right.get(field)}
                    for field in sorted(fields)
                    if left.get(field) != right.get(field)
                }
                if changed:
                    transitions.append({
                        "identity": identity,
                        "fields": changed,
                    })
        if transitions:
            ordered = _sorted_transitions(transitions)
            _append(
                issues, "REVIEW", "parsed_field_transition",
                section=section, count=len(ordered),
                fields=sorted(fields),
                transitions_digest=_evidence_digest(ordered),
                samples=ordered[:8],
            )


@dataclass
class RunArtifacts:
    label: str
    root: Path
    parsed_path: Path
    analyzed_path: Path
    parsed: dict[str, Any]
    analyzed: dict[str, Any]
    cleanup: tempfile.TemporaryDirectory | None = None
    ingest_manifest_path: Path | None = None
    ingest_manifest: dict[str, Any] | None = None

    def close(self) -> None:
        if self.cleanup is not None:
            self.cleanup.cleanup()


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be object: {path}")
    return value


def _safe_extract(path: Path) -> tuple[Path, tempfile.TemporaryDirectory]:
    td = tempfile.TemporaryDirectory(prefix="checkpc_compare_")
    root = Path(td.name)
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            target = (root / name).resolve()
            if not str(target).startswith(str(root.resolve()) + os.sep):
                td.cleanup()
                raise ValueError(f"unsafe archive path: {info.filename}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
    return root, td


def _choose(paths: list[Path], kind: str, host: str) -> Path:
    filtered = paths
    if host:
        needle = host.casefold()
        filtered = [p for p in paths if needle in p.name.casefold() or needle in str(p.parent).casefold()]
    if len(filtered) != 1:
        sample = ", ".join(str(p) for p in filtered[:8])
        raise ValueError(f"expected exactly one {kind} artifact, found {len(filtered)}: {sample}")
    return filtered[0]


def _choose_optional(paths: list[Path], kind: str, host: str) -> Path | None:
    filtered = paths
    if host:
        needle = host.casefold()
        filtered = [p for p in paths if needle in p.name.casefold() or needle in str(p.parent).casefold()]
    if not filtered:
        return None
    if len(filtered) != 1:
        sample = ", ".join(str(p) for p in filtered[:8])
        raise ValueError(f"expected at most one {kind} artifact, found {len(filtered)}: {sample}")
    return filtered[0]


def load_run(value: str, label: str, host: str = "") -> RunArtifacts:
    source = Path(value).resolve()
    cleanup = None
    if source.is_file() and zipfile.is_zipfile(source):
        root, cleanup = _safe_extract(source)
    elif source.is_dir():
        root = source
    else:
        raise ValueError(f"input must be run directory or ZIP archive: {value}")
    parsed_paths = sorted(root.rglob("parsed_*.json"))
    analyzed_paths = sorted(
        p for p in root.rglob("analyzed_*.json")
        if not p.name.endswith("_vt.json")
    )
    parsed_path = _choose(parsed_paths, "parsed", host)
    analyzed_path = _choose(analyzed_paths, "analyzed", host)
    ingest_manifest_path = _choose_optional(sorted(root.rglob("ingest_manifest.json")), "ingest manifest", host)
    return RunArtifacts(
        label=label, root=root, parsed_path=parsed_path, analyzed_path=analyzed_path,
        parsed=_load_json(parsed_path), analyzed=_load_json(analyzed_path), cleanup=cleanup,
        ingest_manifest_path=ingest_manifest_path,
        ingest_manifest=(_load_json(ingest_manifest_path) if ingest_manifest_path else None),
    )


def _meta(run: RunArtifacts) -> dict[str, Any]:
    meta = run.analyzed.get("meta")
    return dict(meta) if isinstance(meta, Mapping) else {}


def _parsed_meta(run: RunArtifacts) -> dict[str, Any]:
    meta = run.parsed.get("meta")
    return dict(meta) if isinstance(meta, Mapping) else {}


def _ingest_meta(run: RunArtifacts) -> dict[str, Any]:
    return dict(run.ingest_manifest) if isinstance(run.ingest_manifest, Mapping) else {}


def _depth(meta: Mapping[str, Any]) -> int:
    try:
        return int(meta.get("depth", 0))
    except (TypeError, ValueError):
        return 0


def _raw_sections(parsed: Mapping[str, Any]) -> dict[str, list[Any]]:
    out: dict[str, list[Any]] = {}
    for container_name in ("sections", "event_logs"):
        container = parsed.get(container_name, {})
        if not isinstance(container, Mapping):
            continue
        for section, entries in container.items():
            if isinstance(entries, list):
                out[str(section)] = entries
    return out


def _issue_id(prefix: str, payload: Mapping[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return f"{prefix}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12]}"


def _append(rows: list[dict[str, Any]], severity: str, kind: str, **detail: Any) -> None:
    payload = {"severity": severity, "kind": kind, **detail}
    payload["id"] = _issue_id("cmp", payload)
    rows.append(payload)



def _aggregate_issues(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse byte-identical issue payloads and retain occurrence counts."""
    grouped: dict[str, tuple[dict[str, Any], int]] = {}
    order: list[str] = []
    for row in rows:
        payload = dict(row)
        payload.pop("id", None)
        payload.pop("occurrence_count", None)
        key = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if key not in grouped:
            grouped[key] = (payload, 1)
            order.append(key)
        else:
            first, count = grouped[key]
            grouped[key] = (first, count + 1)
    out = []
    for key in order:
        payload, count = grouped[key]
        if count > 1:
            payload["occurrence_count"] = count
        payload["id"] = _issue_id("cmp", payload)
        out.append(payload)
    return out


def _validate_run(run: RunArtifacts, issues: list[dict[str, Any]]) -> None:
    meta = _meta(run)
    required = (
        "pipeline_version", "analysis_schema_version", "analysis_mode", "depth",
        "model", "input_sha256", "budget_profile", "budget_profile_fingerprint",
        "max_inflight_llm", "pipeline_max_workers", "runtime_fingerprint",
        "comparison_provenance_schema_version", "source_id_algorithm_version",
        "parsed_artifact_sha256", "raw_evidence_fingerprint",
    )
    for key in required:
        if meta.get(key) in (None, ""):
            _append(issues, "INPUT_ERROR", "missing_metadata", side=run.label, field=key)
    if str(meta.get("comparison_provenance_schema_version")) != COMPARISON_PROVENANCE_SCHEMA_VERSION:
        _append(issues, "INPUT_ERROR", "unsupported_provenance_schema", side=run.label,
                value=meta.get("comparison_provenance_schema_version"))

    # rev12: bind analyzed metadata back to the actual parsed/run identity.
    # Package identity is written to parsed first and inherited by analyzed.
    # Trusting analyzed.meta alone allowed an old run to be re-tagged by changing
    # one JSON field.  Fail closed on missing/mismatched lineage fields.
    parsed_meta = _parsed_meta(run)
    lineage_fields = (
        "pipeline_version",
        "package_manifest_sha256",
        "source_id_algorithm_version",
    )
    for field in lineage_fields:
        parsed_value = parsed_meta.get(field)
        analyzed_value = meta.get(field)
        if parsed_value in (None, ""):
            _append(issues, "INPUT_ERROR", "parsed_run_identity_missing",
                    side=run.label, field=field)
        if analyzed_value in (None, ""):
            _append(issues, "INPUT_ERROR", "analyzed_run_identity_missing",
                    side=run.label, field=field)
        if (parsed_value not in (None, "") and analyzed_value not in (None, "")
                and str(parsed_value) != str(analyzed_value)):
            _append(issues, "INPUT_ERROR", "parsed_analyzed_run_identity_mismatch",
                    side=run.label, field=field, parsed=parsed_value, analyzed=analyzed_value)

    # In normal v3.70 run directories ingest_manifest.json is present.  When it
    # is available, bind it to the same lineage and to the parsed file SHA too.
    # The parsed/analyzed check above remains mandatory even for legacy inputs
    # that legitimately lack an ingest manifest.
    ingest = _ingest_meta(run)
    if ingest:
        for field in lineage_fields:
            ingest_value = ingest.get(field)
            parsed_value = parsed_meta.get(field)
            analyzed_value = meta.get(field)
            if ingest_value in (None, ""):
                _append(issues, "INPUT_ERROR", "ingest_run_identity_missing",
                        side=run.label, field=field)
            elif (parsed_value not in (None, "") and str(ingest_value) != str(parsed_value)):
                _append(issues, "INPUT_ERROR", "parsed_ingest_run_identity_mismatch",
                        side=run.label, field=field, parsed=parsed_value, ingest=ingest_value)
            elif (analyzed_value not in (None, "") and str(ingest_value) != str(analyzed_value)):
                _append(issues, "INPUT_ERROR", "analyzed_ingest_run_identity_mismatch",
                        side=run.label, field=field, analyzed=analyzed_value, ingest=ingest_value)

    actual_parsed_sha = sha256_file(run.parsed_path)
    if meta.get("parsed_artifact_sha256") and actual_parsed_sha != meta.get("parsed_artifact_sha256"):
        _append(issues, "INPUT_ERROR", "parsed_artifact_sha256_mismatch", side=run.label,
                expected=meta.get("parsed_artifact_sha256"), actual=actual_parsed_sha)
    if ingest and ingest.get("parsed_artifact_sha256"):
        if actual_parsed_sha != str(ingest.get("parsed_artifact_sha256")):
            _append(issues, "INPUT_ERROR", "ingest_parsed_artifact_sha256_mismatch",
                    side=run.label, expected=ingest.get("parsed_artifact_sha256"),
                    actual=actual_parsed_sha)
    actual_raw_fp = document_raw_evidence_fingerprint(run.parsed)
    if meta.get("raw_evidence_fingerprint") and actual_raw_fp != meta.get("raw_evidence_fingerprint"):
        _append(issues, "INPUT_ERROR", "raw_evidence_fingerprint_mismatch", side=run.label,
                expected=meta.get("raw_evidence_fingerprint"), actual=actual_raw_fp)

    raw_sections = _raw_sections(run.parsed)
    for section, raw_entries in raw_sections.items():
        for index, raw_entry in enumerate(raw_entries):
            if isinstance(raw_entry, Mapping) and not str(raw_entry.get("source_id") or ""):
                _append(issues, "INPUT_ERROR", "parsed_source_id_missing",
                        side=run.label, section=section, raw_index=index)
    analyzed_sections = run.analyzed.get("sections", {})
    if not isinstance(analyzed_sections, Mapping):
        _append(issues, "INPUT_ERROR", "sections_missing", side=run.label)
        return
    for section in missing_analyzed_raw_sections(run.parsed, run.analyzed):
        _append(issues, "INPUT_ERROR", "analyzed_section_missing",
                side=run.label, section=section)
    for section, section_result in analyzed_sections.items():
        if not isinstance(section_result, Mapping):
            continue
        raw = raw_sections.get(str(section))
        provenance = section_result.get("_provenance")
        if raw is None:
            if isinstance(provenance, Mapping):
                for error in validate_section_provenance(provenance):
                    _append(issues, "INPUT_ERROR", "derived_section_provenance_invalid",
                            side=run.label, section=section, detail=error)
                stages = provenance.get("stages") or {}
                if isinstance(stages, Mapping):
                    for stage_name in ("mandatory", "deterministic", "selected", "evaluated", "unevaluated"):
                        stage = stages.get(stage_name)
                        if not isinstance(stage, Mapping) or stage.get("applicable") is False:
                            continue
                        try:
                            stage_count = int(stage.get("count", -1))
                        except (TypeError, ValueError):
                            stage_count = -1
                        source_ids = stage.get("source_ids")
                        if not (stage.get("source_ids_complete") is True
                                and isinstance(source_ids, list)
                                and len(source_ids) == stage_count
                                and all(isinstance(x, str) and x for x in source_ids)):
                            _append(issues, "INPUT_ERROR",
                                    "derived_stage_source_id_coverage_incomplete",
                                    side=run.label, section=section, stage=stage_name)
                for entry_index, entry in enumerate(section_result.get("entries") or []):
                    if isinstance(entry, Mapping) and not str(entry.get("source_id") or ""):
                        _append(issues, "INPUT_ERROR", "derived_analyzed_source_id_missing",
                                side=run.label, section=section, entry_index=entry_index)
            continue
        if not isinstance(provenance, Mapping):
            _append(issues, "INPUT_ERROR", "section_provenance_missing",
                    side=run.label, section=section)
            continue
        for error in validate_section_provenance(provenance):
            _append(issues, "INPUT_ERROR", "section_provenance_invalid",
                    side=run.label, section=section, detail=error)
        stages = provenance.get("stages")
        if isinstance(stages, Mapping):
            for stage_name in ("mandatory", "deterministic", "selected", "evaluated", "unevaluated"):
                stage = stages.get(stage_name)
                if not isinstance(stage, Mapping) or stage.get("applicable") is False:
                    continue
                try:
                    stage_count = int(stage.get("count", -1))
                except (TypeError, ValueError):
                    stage_count = -1
                source_ids = stage.get("source_ids")
                coverage_ok = (
                    stage.get("source_ids_complete") is True
                    and isinstance(source_ids, list)
                    and len(source_ids) == stage_count
                    and all(isinstance(x, str) and x for x in source_ids)
                )
                if not coverage_ok:
                    _append(issues, "INPUT_ERROR", "stage_source_id_coverage_incomplete",
                            side=run.label, section=section, stage=stage_name,
                            count=stage_count,
                            source_id_count=len(source_ids or []) if isinstance(source_ids, list) else -1)
        if provenance.get("provenance_complete") is not True:
            _append(issues, "INPUT_ERROR", "section_provenance_incomplete",
                    side=run.label, section=section,
                    attribution_error_count=provenance.get("attribution_error_count", 0))
        try:
            attribution_error_count = int(provenance.get("attribution_error_count", 0) or 0)
        except (TypeError, ValueError):
            attribution_error_count = -1
        if attribution_error_count != 0:
            _append(issues, "INPUT_ERROR", "source_attribution_error",
                    side=run.label, section=section,
                    attribution_error_count=attribution_error_count)
        if int(provenance.get("raw_count", -1)) != len(raw):
            _append(issues, "INPUT_ERROR", "section_raw_count_mismatch", side=run.label,
                    section=section, expected=len(raw), actual=provenance.get("raw_count"))
        section_fp = provenance.get("raw_evidence_fingerprint")
        parsed_meta = run.parsed.get("meta", {}) if isinstance(run.parsed.get("meta"), Mapping) else {}
        expected_fp = ((parsed_meta.get("section_raw_evidence") or {}).get(section) or {}).get(
            "raw_evidence_fingerprint")
        if expected_fp and section_fp != expected_fp:
            _append(issues, "INPUT_ERROR", "section_raw_fingerprint_mismatch",
                    side=run.label, section=section, expected=expected_fp, actual=section_fp)
        for entry_index, entry in enumerate(section_result.get("entries") or []):
            if not isinstance(entry, Mapping):
                continue
            if str(entry.get("source_id") or ""):
                continue
            identifier = str(entry.get("identifier") or "")
            if identifier.startswith("⚠") or entry.get("_meta_only"):
                continue
            raw_index = entry.get("_raw_source_index")
            if isinstance(raw_index, int) and not isinstance(raw_index, bool):
                _append(issues, "REVIEW", "analyzed_source_id_missing",
                        side=run.label, section=section, entry_index=entry_index,
                        raw_index=raw_index, identity=identifier[:180])

    invalid, degraded = schema_findings(run.analyzed, run.label)
    for row in invalid:
        _append(issues, "FAIL", "invalid_score", side=run.label, section=row[1], detail=row[3])
    for row in degraded:
        _append(issues, "REVIEW", "schema_recovery", side=run.label, section=row[1], detail=row[3])


def _require_equal(issues: list[dict[str, Any]], ma: Mapping[str, Any], mb: Mapping[str, Any],
                   fields: tuple[str, ...], *, kind: str = "metadata_mismatch") -> None:
    for field in fields:
        if ma.get(field) != mb.get(field):
            _append(issues, "INPUT_ERROR", kind, field=field, a=ma.get(field), b=mb.get(field))


def _validate_mode(mode: str, a: RunArtifacts, b: RunArtifacts,
                   issues: list[dict[str, Any]]) -> None:
    ma, mb = _meta(a), _meta(b)
    common = ("input_sha256", "model")
    _require_equal(issues, ma, mb, common)
    da, db = _depth(ma), _depth(mb)
    mode_a, mode_b = str(ma.get("analysis_mode")), str(mb.get("analysis_mode"))
    if mode == "reproducibility":
        _require_equal(issues, ma, mb, (
            "pipeline_version", "analysis_schema_version", "input_sha256", "depth",
            "analysis_mode", "model", "budget_profile", "budget_profile_fingerprint",
            "max_inflight_llm", "pipeline_max_workers", "runtime_fingerprint",
            "source_id_algorithm_version", "package_manifest_sha256",
        ))
    elif mode == "cross-version":
        _require_equal(issues, ma, mb, ("input_sha256", "depth", "analysis_mode", "model"))
        if (ma.get("pipeline_version"), ma.get("budget_profile_fingerprint")) == (
                mb.get("pipeline_version"), mb.get("budget_profile_fingerprint")):
            _append(issues, "INPUT_ERROR", "cross_version_requires_version_or_profile_difference")
    elif mode == "full-lean":
        _require_equal(issues, ma, mb, (
            "pipeline_version", "analysis_schema_version", "input_sha256", "depth", "model",
            "budget_profile", "budget_profile_fingerprint", "source_id_algorithm_version",
            "package_manifest_sha256",
        ))
        if {mode_a, mode_b} != {"FULL", "LEAN"}:
            _append(issues, "INPUT_ERROR", "full_lean_requires_opposite_modes", a=mode_a, b=mode_b)
    elif mode == "depth1-depth2":
        _require_equal(issues, ma, mb, (
            "pipeline_version", "analysis_schema_version", "input_sha256", "analysis_mode",
            "model", "budget_profile", "budget_profile_fingerprint",
            "package_manifest_sha256",
        ))
        if (da, db) != (1, 2):
            _append(issues, "INPUT_ERROR", "depth_direction_invalid", a=da, b=db,
                    expected="A=1,B=2")


def _prov(run: RunArtifacts, section: str) -> Mapping[str, Any] | None:
    sr = (run.analyzed.get("sections") or {}).get(section)
    if isinstance(sr, Mapping) and isinstance(sr.get("_provenance"), Mapping):
        return sr.get("_provenance")
    return None


def _stage_identities(
    run: RunArtifacts, section: str, stage: str, mode: str
) -> collections.Counter | None:
    raw = _raw_sections(run.parsed).get(section)
    provenance = _prov(run, section)
    if raw is None or provenance is None:
        return None
    indices = stage_indices(provenance, stage)
    if indices is None:
        return None
    identities = _comparison_raw_identity_multiset(mode, section, raw)
    return collections.Counter(identities[index] for index in sorted(indices))


def _compare_raw(mode: str, a: RunArtifacts, b: RunArtifacts,
                 issues: list[dict[str, Any]]) -> None:
    ra, rb = _raw_sections(a.parsed), _raw_sections(b.parsed)
    for section in sorted(set(ra) | set(rb)):
        ca = collections.Counter(
            _comparison_raw_identity_multiset(mode, section, ra.get(section, []))
        )
        cb = collections.Counter(
            _comparison_raw_identity_multiset(mode, section, rb.get(section, []))
        )
        removed = ca - cb
        added = cb - ca
        if removed:
            _append(issues, "FAIL", "raw_evidence_removed", section=section,
                    count=sum(removed.values()), samples=list(removed)[:8])
        if added:
            severity = "FAIL" if mode in {"reproducibility", "depth1-depth2"} else "REVIEW"
            evidence = _counter_evidence(added)
            _append(issues, severity, "raw_evidence_added", section=section,
                    count=sum(added.values()),
                    evidence_digest=_evidence_digest(evidence),
                    samples=[row[0] for row in evidence[:8]])


def _compare_stages(mode: str, a: RunArtifacts, b: RunArtifacts,
                    issues: list[dict[str, Any]]) -> None:
    sections = sorted(set(_raw_sections(a.parsed)) | set(_raw_sections(b.parsed)))
    for section in sections:
        if mode == "depth1-depth2":
            continue
        if mode == "reproducibility":
            policies = {name: "FAIL" for name in (
                "mandatory", "deterministic", "selected", "deferred", "evaluated", "unevaluated")}
        elif mode == "full-lean":
            policies = {
                "mandatory": "FAIL", "deterministic": "FAIL",
                "selected": "REVIEW", "evaluated": "REVIEW", "unevaluated": "REVIEW",
            }
        else:  # cross-version
            policies = {
                "mandatory": "FAIL_REMOVAL", "deterministic": "FAIL_REMOVAL",
                "selected": "REVIEW", "evaluated": "REVIEW", "unevaluated": "REVIEW",
            }
        for stage, policy in policies.items():
            ca = _stage_identities(a, section, stage, mode)
            cb = _stage_identities(b, section, stage, mode)
            if ca is None and cb is None:
                continue
            if ca is None or cb is None:
                _append(issues, "INPUT_ERROR", "stage_applicability_mismatch",
                        section=section, stage=stage, a_applicable=ca is not None,
                        b_applicable=cb is not None)
                continue
            removed, added = ca - cb, cb - ca
            if not removed and not added:
                continue
            if policy == "FAIL_REMOVAL":
                if removed:
                    _append(issues, "FAIL", f"{stage}_removed", section=section,
                            count=sum(removed.values()), samples=list(removed)[:8])
                if added:
                    evidence = _counter_evidence(added)
                    _append(issues, "REVIEW", f"{stage}_added", section=section,
                            count=sum(added.values()),
                            evidence_digest=_evidence_digest(evidence),
                            samples=[row[0] for row in evidence[:8]])
            else:
                removed_evidence = _counter_evidence(removed)
                added_evidence = _counter_evidence(added)
                _append(issues, policy, f"{stage}_set_difference", section=section,
                        removed=sum(removed.values()), added=sum(added.values()),
                        evidence_digest=_evidence_digest(
                            {"removed": removed_evidence, "added": added_evidence}),
                        removed_samples=[row[0] for row in removed_evidence[:5]],
                        added_samples=[row[0] for row in added_evidence[:5]])


def _source_id_from_comparison_key(key: tuple[Any, ...]) -> str:
    """Return the exact source_id encoded by a source-id comparison key."""
    if len(key) < 2:
        return ""
    ident = str(key[1])
    if not ident.startswith("source_id:"):
        return ""
    return ident[len("source_id:"):].split("#", 1)[0]


def _provenance_reasons_for_index(
    provenance: Mapping[str, Any], disposition: str, index: int
) -> list[str]:
    """Return exact provenance reasons covering one raw index, fail-closed."""
    raw_count = int(provenance.get("raw_count", 0) or 0)
    reasons_root = provenance.get("reasons")
    reasons = None
    if isinstance(reasons_root, Mapping):
        reasons = reasons_root.get(disposition)
    if not isinstance(reasons, Mapping):
        reasons = provenance.get(f"{disposition}_reasons")
    if not isinstance(reasons, Mapping):
        return []
    out: list[str] = []
    for reason, ranges in reasons.items():
        try:
            indices = expand_ranges(ranges, raw_count=raw_count)
        except Exception:
            return []
        if index in indices:
            out.append(str(reason))
    return sorted(out)


def _depth2_signature_diversity_resolution(
    a: RunArtifacts, b: RunArtifacts, key: tuple[Any, ...]
) -> tuple[str, str, dict[str, Any]] | None:
    """Resolve a D1 HIGH removal through an actually-evaluated D2 signature family.

    This is deliberately narrow. It applies only when the exact D1 source_id raw
    still exists in the D2 parsed artifact, D2 provenance says that exact raw row
    was deferred *only* for ``signature_diversity``, and one or more rows with the
    exact same Depth2 planner signature were selected, evaluated, and have analyzed
    entries bound by source_id. It never changes the planner or source binding.

    Returns ``(severity, kind, evidence)`` only for safe REVIEW transitions.
    Any ambiguity or weaker representative score returns ``None`` so the caller
    retains the pre-rev14 FAIL behavior.
    """
    section = str(key[0]) if key else ""
    source_id = _source_id_from_comparison_key(key)
    if not section or not source_id:
        return None

    raw_b = _raw_sections(b.parsed).get(section)
    provenance = _prov(b, section)
    if not isinstance(raw_b, list) or not isinstance(provenance, Mapping):
        return None

    matches = [
        index for index, row in enumerate(raw_b)
        if isinstance(row, Mapping) and str(row.get("source_id") or "") == source_id
    ]
    if len(matches) != 1:
        return None
    removed_index = matches[0]

    deferred = stage_indices(provenance, "deferred")
    selected = stage_indices(provenance, "selected")
    evaluated = stage_indices(provenance, "evaluated")
    if deferred is None or selected is None or evaluated is None:
        return None
    if removed_index not in deferred:
        return None
    if _provenance_reasons_for_index(provenance, "deferred", removed_index) != [
        "signature_diversity"
    ]:
        return None

    try:
        planner_signature = str(_depth2_planner_signature(section, raw_b[removed_index]))
    except Exception:
        return None

    analyzed_sections = b.analyzed.get("sections")
    section_result = analyzed_sections.get(section) if isinstance(analyzed_sections, Mapping) else None
    entries = section_result.get("entries") if isinstance(section_result, Mapping) else None
    if not isinstance(entries, list):
        return None

    entries_by_source_id: dict[str, list[Mapping[str, Any]]] = collections.defaultdict(list)
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        sid = str(entry.get("source_id") or "")
        if sid:
            entries_by_source_id[sid].append(entry)

    representatives: list[dict[str, Any]] = []
    candidate_indices = sorted((selected & evaluated) - {removed_index})
    for index in candidate_indices:
        if not (0 <= index < len(raw_b)):
            return None
        row = raw_b[index]
        if not isinstance(row, Mapping):
            continue
        try:
            signature = str(_depth2_planner_signature(section, row))
        except Exception:
            return None
        if signature != planner_signature:
            continue
        sid = str(row.get("source_id") or "")
        bound_entries = entries_by_source_id.get(sid, [])
        if not sid or len(bound_entries) != 1:
            return None
        entry = bound_entries[0]
        score = str(entry.get("score") or "")
        if score not in SCORES:
            return None
        representatives.append({
            "raw_index": index,
            "source_id": sid,
            "score": score,
        })

    if not representatives:
        return None

    rank = {score: pos for pos, score in enumerate(("HIGH", "MEDIUM", "LOW", "CLEAN"))}
    best_score = min(
        (row["score"] for row in representatives),
        key=lambda score: rank.get(score, 999),
    )
    deterministic_high = _deterministic_high_key(a.analyzed, key)

    evidence = {
        "removed_source_id": source_id,
        "removed_raw_index": removed_index,
        "planner_signature": planner_signature,
        "deferred_reason": "signature_diversity",
        "representative_source_ids": [row["source_id"] for row in representatives],
        "representative_raw_indices": [row["raw_index"] for row in representatives],
        "representative_scores": [row["score"] for row in representatives],
        "representative_best_score": best_score,
        "d1_deterministic_high": bool(deterministic_high),
    }

    if best_score == "HIGH":
        return "REVIEW", "signature_diversity_high_represented", evidence
    if best_score == "MEDIUM" and not deterministic_high:
        return "REVIEW", "signature_diversity_high_to_medium", evidence
    return None


def _deterministic_high_key(doc: Mapping[str, Any], key: tuple[Any, ...]) -> bool:
    section, ident = key[0], str(key[1])
    sid = ""
    if ident.startswith("source_id:"):
        sid = ident[len("source_id:"):].split("#", 1)[0]
    for sec, entry in _iter_comparable_entries(doc):
        if sec != section:
            continue
        if sid and str(entry.get("source_id") or "") != sid:
            continue
        if not sid and canonical_key(sec, entry, use_source_id=False) != key:
            continue
        if entry.get("score") == "HIGH" and (
                entry.get("deterministic_origin") or entry.get("depth2_mandatory_reason")):
            return True
    return False


def _compare_entries(mode: str, a: RunArtifacts, b: RunArtifacts,
                     issues: list[dict[str, Any]], strict_llm: bool) -> None:
    analyzed_a = _cross_version_analyzed_view(a) if mode == "cross-version" else a.analyzed
    analyzed_b = _cross_version_analyzed_view(b) if mode == "cross-version" else b.analyzed
    ma, ra, mb, rb = two_stage_entry_multisets(analyzed_a, analyzed_b)
    severity_order = ["HIGH", "MEDIUM", "LOW", "CLEAN"]
    for key in sorted(set(ma) | set(mb), key=str):
        ca, cb = collections.Counter(ma.get(key, {})), collections.Counter(mb.get(key, {}))
        for score in severity_order:
            n = min(ca.get(score, 0), cb.get(score, 0))
            ca[score] -= n
            cb[score] -= n
        for score_a in severity_order:
            while ca.get(score_a, 0) > 0:
                score_b = next((x for x in severity_order if cb.get(x, 0) > 0), None)
                ca[score_a] -= 1
                if score_b is None:
                    if mode == "depth1-depth2" and score_a == "HIGH":
                        resolved = _depth2_signature_diversity_resolution(a, b, key)
                        if resolved is not None:
                            severity, kind, evidence = resolved
                            _append(
                                issues, severity, kind,
                                section=key[0], identity=str(key[1])[:180], score=score_a,
                                **evidence,
                            )
                            continue
                    severity = "FAIL" if score_a == "HIGH" else ("FAIL" if strict_llm else "REVIEW")
                    _append(issues, severity, "analyzed_entry_removed", section=key[0],
                            identity=str(key[1])[:180], score=score_a)
                    continue
                cb[score_b] -= 1
                if score_a == score_b:
                    continue
                if score_a == "HIGH" and score_b in {"LOW", "CLEAN"}:
                    severity, kind = "FAIL", "high_to_low_or_clean"
                elif score_a == "HIGH" and score_b == "MEDIUM":
                    if _deterministic_high_key(analyzed_a, key):
                        severity, kind = "FAIL", "deterministic_high_to_medium"
                    else:
                        severity, kind = "REVIEW", "high_to_medium"
                else:
                    severity, kind = ("FAIL" if strict_llm else "REVIEW"), "score_transition"
                _append(issues, severity, kind, section=key[0], identity=str(key[1])[:180],
                        transition=f"{score_a}->{score_b}",
                        a_reason=ra[key].get(score_a, ""), b_reason=rb[key].get(score_b, ""))
        for score_b in severity_order:
            if cb.get(score_b, 0):
                _append(issues, "FAIL" if strict_llm else "REVIEW", "analyzed_entry_added",
                        section=key[0], identity=str(key[1])[:180], score=score_b,
                        count=cb.get(score_b, 0))

    # Same-source, same-score stable semantic field changes are LLM-layer
    # differences.  Internal attribution/provenance/timing fields are excluded
    # here because they are validated by dedicated comparison stages.
    semantic_fields = (
        "identifier", "reason", "iocs", "mitre", "lolbas", "decoded",
    )

    def semantic_value(field: str, entry: Mapping[str, Any]) -> Any:
        value = entry.get(field)
        if field == "iocs":
            return sorted(map(str, value or []))
        if value is None:
            return ""
        return value

    def unique_sid(doc: Mapping[str, Any]) -> dict[tuple[str, str], Mapping[str, Any]]:
        groups: dict[tuple[str, str], list[Mapping[str, Any]]] = collections.defaultdict(list)
        for section, entry in _iter_comparable_entries(doc):
            sid = str(entry.get("source_id") or "")
            if sid:
                groups[(section, sid)].append(entry)
        return {key: rows[0] for key, rows in groups.items() if len(rows) == 1}
    ua, ub = unique_sid(analyzed_a), unique_sid(analyzed_b)
    for key in sorted(set(ua) & set(ub)):
        ea, eb = ua[key], ub[key]
        if ea.get("score") != eb.get("score"):
            continue
        fields = [
            field for field in semantic_fields
            if semantic_value(field, ea) != semantic_value(field, eb)
        ]
        if fields:
            _append(issues, "FAIL" if strict_llm else "REVIEW", "llm_content_difference",
                    section=key[0], source_id=key[1], fields=fields)

        # rev9: occurrence_count is semantic audit metadata for D1 task_140
        # groups.  Compare it only when both sides explicitly carry the field,
        # avoiding noise in D1-vs-D2 / pre-aggregation comparisons while
        # preventing same-generation multiplicity changes from disappearing.
        if key[0] == "task_140" and "occurrence_count" in ea and "occurrence_count" in eb:
            try:
                occ_a = int(ea.get("occurrence_count"))
                occ_b = int(eb.get("occurrence_count"))
            except (TypeError, ValueError):
                occ_a = occ_b = -1
            if occ_a != occ_b:
                _append(
                    issues, "FAIL" if strict_llm else "REVIEW",
                    "task140_occurrence_count_difference",
                    section=key[0], source_id=key[1],
                    a_occurrence_count=ea.get("occurrence_count"),
                    b_occurrence_count=eb.get("occurrence_count"),
                )


def compare_runs(mode: str, a: RunArtifacts, b: RunArtifacts, *, strict_llm: bool = False) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    _validate_run(a, issues)
    _validate_run(b, issues)
    _validate_mode(mode, a, b, issues)
    if not any(row["severity"] == "INPUT_ERROR" for row in issues):
        _compare_raw(mode, a, b, issues)
        if mode == "cross-version":
            _compare_cross_version_derived_fields(a, b, issues)
        _compare_stages(mode, a, b, issues)
        _compare_entries(mode, a, b, issues, strict_llm)
    issues = _aggregate_issues(issues)
    input_errors = [row for row in issues if row["severity"] == "INPUT_ERROR"]
    failures = [row for row in issues if row["severity"] == "FAIL"]
    reviews = [row for row in issues if row["severity"] == "REVIEW"]
    review_occurrences = sum(int(row.get("occurrence_count", 1) or 1) for row in reviews)
    if input_errors:
        status, exit_code = "INPUT_ERROR", EXIT_INPUT
    elif failures:
        status, exit_code = "FAIL", EXIT_FAIL
    elif reviews:
        status, exit_code = "REVIEW", EXIT_REVIEW
    else:
        status, exit_code = "PASS", EXIT_OK
    result = {
        "comparison_result_schema": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "strict_llm": bool(strict_llm),
        "comparison_implementation": {
            "evidence_version": COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION,
            "compare_runs_sha256": sha256_file(Path(__file__)),
        },
        "comparison_scope": {
            "included": ["parsed_*.json", "analyzed_*.json", "ingest_manifest.json (when present)"],
            "excluded": ["correlation_*.json", "report_*.md"],
        },
        "status": status,
        "exit_code": exit_code,
        "summary": {
            "input_error": len(input_errors), "fail": len(failures),
            "review": len(reviews), "review_occurrences": review_occurrences,
        },
        "artifacts": {
            "a": {
                "parsed_sha256": sha256_file(a.parsed_path),
                "analyzed_sha256": sha256_file(a.analyzed_path),
                "ingest_manifest_sha256": (sha256_file(a.ingest_manifest_path) if a.ingest_manifest_path else None),
                "parsed_meta": _parsed_meta(a),
                "ingest_manifest_identity": {
                    key: _ingest_meta(a).get(key) for key in (
                        "pipeline_version", "package_manifest_sha256", "source_id_algorithm_version"
                    )
                } if a.ingest_manifest else None,
                "meta": _meta(a),
            },
            "b": {
                "parsed_sha256": sha256_file(b.parsed_path),
                "analyzed_sha256": sha256_file(b.analyzed_path),
                "ingest_manifest_sha256": (sha256_file(b.ingest_manifest_path) if b.ingest_manifest_path else None),
                "parsed_meta": _parsed_meta(b),
                "ingest_manifest_identity": {
                    key: _ingest_meta(b).get(key) for key in (
                        "pipeline_version", "package_manifest_sha256", "source_id_algorithm_version"
                    )
                } if b.ingest_manifest else None,
                "meta": _meta(b),
            },
        },
        "identity_matching": {
            "source_id_algorithm_a": _meta(a).get("source_id_algorithm_version"),
            "source_id_algorithm_b": _meta(b).get("source_id_algorithm_version"),
            "canonical_fallback_available": True,
            "canonical_fallback_used": (
                _meta(a).get("source_id_algorithm_version")
                != _meta(b).get("source_id_algorithm_version")
            ),
        },
        "issues": issues,
        "unresolved_review_ids": [row["id"] for row in reviews],
        "unresolved_review_occurrence_count": review_occurrences,
    }
    result["result_id"] = compute_result_id(result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=MODES)
    parser.add_argument("a")
    parser.add_argument("b")
    parser.add_argument("--host", default="", help="multi-host full archive filter")
    parser.add_argument("--strict-llm", action="store_true")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    a = b = None
    try:
        a = load_run(args.a, "A", args.host)
        b = load_run(args.b, "B", args.host)
        result = compare_runs(args.mode, a, b, strict_llm=args.strict_llm)
        atomic_write_json(args.output, result)
        print(json.dumps({
            "mode": result["mode"], "status": result["status"],
            "summary": result["summary"], "result_id": result["result_id"],
            "output": os.path.abspath(args.output),
        }, ensure_ascii=False, indent=2))
        return int(result["exit_code"])
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(f"[INPUT ERROR] {exc}", file=sys.stderr)
        return EXIT_INPUT
    except Exception as exc:
        import traceback
        traceback.print_exc()
        print(f"[INTERNAL ERROR] {exc}", file=sys.stderr)
        return EXIT_INTERNAL
    finally:
        if a is not None:
            a.close()
        if b is not None:
            b.close()


if __name__ == "__main__":
    raise SystemExit(main())
