#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comparison provenance schema and raw-evidence fingerprints for rc20.

The compact ranges are authoritative for planner stages.  Large raw/deferred
source-id arrays are deliberately not duplicated into analyzed artifacts; they
are reconstructed from the parsed artifact in a full archive or run directory.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from source_id import (
    SOURCE_ID_ALGORITHM_VERSION,
    canonical_evidence,
    canonical_evidence_sha256,
)

COMPARISON_PROVENANCE_SCHEMA_VERSION = "1"
PARSED_ANALYSIS_EXEMPT_SECTIONS = frozenset({"tasklist"})

STAGE_NAMES = (
    "raw", "mandatory", "deterministic", "selected", "deferred",
    "evaluated", "unevaluated",
)


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def compress_indices(indices: Iterable[int]) -> list[list[int]]:
    values = sorted(set(int(x) for x in indices))
    if not values:
        return []
    out: list[list[int]] = []
    start = prev = values[0]
    for value in values[1:]:
        if value == prev + 1:
            prev = value
            continue
        out.append([start, prev])
        start = prev = value
    out.append([start, prev])
    return out


def expand_ranges(ranges: Any, *, raw_count: int | None = None) -> set[int]:
    out: set[int] = set()
    for row in ranges or []:
        if not isinstance(row, (list, tuple)) or len(row) != 2:
            raise ValueError(f"invalid range row: {row!r}")
        start, end = int(row[0]), int(row[1])
        if start < 0 or end < start:
            raise ValueError(f"invalid range bounds: {row!r}")
        if raw_count is not None and end >= raw_count:
            raise ValueError(f"range exceeds raw_count={raw_count}: {row!r}")
        out.update(range(start, end + 1))
    return out


def _entries_for_document(document: Mapping[str, Any]) -> list[tuple[str, list[Any]]]:
    rows: list[tuple[str, list[Any]]] = []
    for container_name in ("sections", "event_logs"):
        container = document.get(container_name, {})
        if not isinstance(container, Mapping):
            continue
        for section in sorted(container):
            entries = container.get(section)
            if isinstance(entries, list):
                rows.append((str(section), entries))
    return rows


def raw_sections(document: Mapping[str, Any]) -> dict[str, list[Any]]:
    """Return list-backed parsed evidence sections from both containers."""
    out: dict[str, list[Any]] = {}
    for container_name in ("sections", "event_logs"):
        container = document.get(container_name, {})
        if not isinstance(container, Mapping):
            continue
        for section, entries in container.items():
            if isinstance(entries, list):
                out[str(section)] = entries
    return out


def missing_analyzed_raw_sections(
    parsed: Mapping[str, Any], analyzed: Mapping[str, Any],
    *, exempt_sections: frozenset[str] = PARSED_ANALYSIS_EXEMPT_SECTIONS,
) -> list[str]:
    """Return list-backed parsed sections absent from analyzed output.

    Empty raw sections are still required.  Only explicitly documented helper
    inputs may be exempt; host names, record counts and source IDs are never
    used as exemptions.
    """
    raw = raw_sections(parsed)
    analyzed_sections = analyzed.get("sections", {})
    if not isinstance(analyzed_sections, Mapping):
        return sorted(name for name in raw if name not in exempt_sections)
    return sorted(
        name for name in raw
        if name not in exempt_sections and not isinstance(analyzed_sections.get(name), Mapping)
    )


def missing_raw_backed_provenance_sections(
    parsed: Mapping[str, Any], analyzed: Mapping[str, Any]
) -> list[str]:
    """Return present raw-backed analyzed sections that lack provenance."""
    raw = raw_sections(parsed)
    analyzed_sections = analyzed.get("sections", {})
    if not isinstance(analyzed_sections, Mapping):
        return []
    missing: list[str] = []
    for name in raw:
        if name in PARSED_ANALYSIS_EXEMPT_SECTIONS:
            continue
        result = analyzed_sections.get(name)
        if not isinstance(result, Mapping):
            continue
        if not isinstance(result.get("_provenance"), Mapping):
            missing.append(name)
    return sorted(missing)


def section_raw_evidence_fingerprint(section: str, entries: Iterable[Any]) -> str:
    h = hashlib.sha256()
    for index, entry in enumerate(entries):
        h.update(str(section).encode("utf-8"))
        h.update(b"\0")
        h.update(str(index).encode("ascii"))
        h.update(b"\0")
        h.update(canonical_evidence(entry).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def document_raw_evidence_fingerprint(document: Mapping[str, Any]) -> str:
    h = hashlib.sha256()
    for section, entries in _entries_for_document(document):
        h.update(section.encode("utf-8"))
        h.update(b"\0")
        h.update(str(len(entries)).encode("ascii"))
        h.update(b"\0")
        h.update(section_raw_evidence_fingerprint(section, entries).encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def raw_identity_multiset(section: str, entries: Iterable[Any]) -> list[str]:
    """Return canonical identities with duplicate ordinals, preserving multiplicity."""
    counts: dict[str, int] = {}
    out: list[str] = []
    for entry in entries:
        digest = canonical_evidence_sha256(entry)
        ordinal = counts.get(digest, 0)
        counts[digest] = ordinal + 1
        out.append(f"{section}:{digest}:{ordinal}")
    return out


def annotate_parsed_document(document: dict[str, Any]) -> dict[str, Any]:
    """Add comparison identity that is independent of path and release metadata."""
    meta = dict(document.get("meta") or {})
    per_section: dict[str, dict[str, Any]] = {}
    for section, entries in _entries_for_document(document):
        per_section[section] = {
            "raw_count": len(entries),
            "raw_evidence_fingerprint": section_raw_evidence_fingerprint(section, entries),
        }
    meta["comparison_provenance_schema_version"] = COMPARISON_PROVENANCE_SCHEMA_VERSION
    meta["source_id_algorithm_version"] = SOURCE_ID_ALGORITHM_VERSION
    meta["raw_evidence_fingerprint"] = document_raw_evidence_fingerprint(document)
    meta["section_raw_evidence"] = per_section
    document["meta"] = meta
    return document


def _source_ids(raw_entries: list[Any], indices: Iterable[int]) -> list[str]:
    out = []
    for index in sorted(set(int(x) for x in indices)):
        if 0 <= index < len(raw_entries) and isinstance(raw_entries[index], dict):
            value = str(raw_entries[index].get("source_id") or "")
            if value:
                out.append(value)
    return out


def _stage(raw_entries: list[Any], indices: Iterable[int], *, applicable: bool = True,
           exact_source_ids: bool = True) -> dict[str, Any]:
    if not applicable:
        return {"applicable": False}
    index_set = set(int(x) for x in indices)
    row: dict[str, Any] = {
        "applicable": True,
        "count": len(index_set),
        "ranges": compress_indices(index_set),
    }
    if exact_source_ids:
        source_ids = _source_ids(raw_entries, index_set)
        row["source_ids"] = source_ids
        row["source_ids_complete"] = len(source_ids) == len(index_set)
    return row


def build_section_provenance(
    section: str,
    raw_entries: list[Any],
    *,
    selected: Iterable[int] = (),
    deterministic: Iterable[int] = (),
    deferred: Iterable[int] = (),
    evaluated: Iterable[int] = (),
    unevaluated: Iterable[int] = (),
    mandatory: Iterable[int] = (),
    mandatory_applicable: bool = True,
    selected_reasons: Mapping[str, Iterable[int]] | None = None,
    deterministic_reasons: Mapping[str, Iterable[int]] | None = None,
    deferred_reasons: Mapping[str, Iterable[int]] | None = None,
    provenance_complete: bool = True,
    attribution_errors: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    raw_set = set(range(len(raw_entries)))
    selected_set = set(int(x) for x in selected)
    deterministic_set = set(int(x) for x in deterministic)
    deferred_set = set(int(x) for x in deferred)
    evaluated_set = set(int(x) for x in evaluated)
    unevaluated_set = set(int(x) for x in unevaluated)
    mandatory_set = set(int(x) for x in mandatory)
    stages = {
        "raw": _stage(raw_entries, raw_set, exact_source_ids=False),
        "mandatory": _stage(raw_entries, mandatory_set,
                            applicable=mandatory_applicable, exact_source_ids=True),
        "deterministic": _stage(raw_entries, deterministic_set),
        "selected": _stage(raw_entries, selected_set),
        "deferred": _stage(raw_entries, deferred_set, exact_source_ids=False),
        "evaluated": _stage(raw_entries, evaluated_set),
        "unevaluated": _stage(raw_entries, unevaluated_set),
    }
    attribution_rows = [dict(row) for row in attribution_errors]
    return {
        "schema_version": COMPARISON_PROVENANCE_SCHEMA_VERSION,
        "source_id_algorithm_version": SOURCE_ID_ALGORITHM_VERSION,
        "section": str(section),
        "raw_count": len(raw_entries),
        "raw_evidence_fingerprint": section_raw_evidence_fingerprint(section, raw_entries),
        "stages": stages,
        "reasons": {
            "selected": {str(k): compress_indices(v) for k, v in (selected_reasons or {}).items()},
            "deterministic": {str(k): compress_indices(v) for k, v in (deterministic_reasons or {}).items()},
            "deferred": {str(k): compress_indices(v) for k, v in (deferred_reasons or {}).items()},
        },
        # Legacy aliases retained through v3.69 for existing consumers.
        "selected_ranges": stages["selected"].get("ranges", []),
        "deterministic_ranges": stages["deterministic"].get("ranges", []),
        "deferred_ranges": stages["deferred"].get("ranges", []),
        "evaluated_ranges": stages["evaluated"].get("ranges", []),
        "selected_unevaluated_ranges": stages["unevaluated"].get("ranges", []),
        "selected_reasons": {str(k): compress_indices(v) for k, v in (selected_reasons or {}).items()},
        "deterministic_reasons": {str(k): compress_indices(v) for k, v in (deterministic_reasons or {}).items()},
        "deferred_reasons": {str(k): compress_indices(v) for k, v in (deferred_reasons or {}).items()},
        "source_ids_scope": "mandatory_deterministic_selected_evaluated_unevaluated",
        "deferred_source_ids_omitted": len(deferred_set),
        "provenance_complete": bool(provenance_complete),
        "attribution_error_count": len(attribution_rows),
        "attribution_errors": attribution_rows,
    }


def stage_indices(provenance: Mapping[str, Any], stage: str) -> set[int] | None:
    stages = provenance.get("stages")
    if isinstance(stages, Mapping) and isinstance(stages.get(stage), Mapping):
        row = stages[stage]
        if row.get("applicable") is False:
            return None
        return expand_ranges(row.get("ranges"), raw_count=int(provenance.get("raw_count", 0)))
    legacy = {
        "selected": "selected_ranges",
        "deterministic": "deterministic_ranges",
        "deferred": "deferred_ranges",
        "evaluated": "evaluated_ranges",
        "unevaluated": "selected_unevaluated_ranges",
    }.get(stage)
    if legacy and legacy in provenance:
        return expand_ranges(provenance.get(legacy), raw_count=int(provenance.get("raw_count", 0)))
    if stage == "raw" and "raw_count" in provenance:
        return set(range(int(provenance.get("raw_count", 0))))
    if stage == "mandatory":
        reasons = provenance.get("selected_reasons") or {}
        if isinstance(reasons, Mapping) and "mandatory_selected" in reasons:
            return expand_ranges(reasons.get("mandatory_selected"),
                                 raw_count=int(provenance.get("raw_count", 0)))
    return None


def validate_section_provenance(provenance: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        raw_count = int(provenance.get("raw_count", -1))
    except Exception:
        return ["raw_count is invalid"]
    if raw_count < 0:
        errors.append("raw_count is missing")
        return errors
    resolved = {name: stage_indices(provenance, name) for name in STAGE_NAMES}
    selected = resolved.get("selected") or set()
    deterministic = resolved.get("deterministic") or set()
    deferred = resolved.get("deferred") or set()
    if selected & deterministic:
        errors.append("selected intersects deterministic")
    if selected & deferred:
        errors.append("selected intersects deferred")
    if deterministic & deferred:
        errors.append("deterministic intersects deferred")
    if (selected | deterministic | deferred) != set(range(raw_count)):
        errors.append("selected/deterministic/deferred do not partition raw")
    mandatory = resolved.get("mandatory")
    if mandatory is not None and not mandatory <= selected:
        errors.append("mandatory is not a subset of selected")
    evaluated = resolved.get("evaluated")
    unevaluated = resolved.get("unevaluated")
    if evaluated is not None and unevaluated is not None:
        if evaluated & unevaluated:
            errors.append("evaluated intersects unevaluated")
        if evaluated | unevaluated != selected:
            errors.append("evaluated/unevaluated do not partition selected")
    return errors


def runtime_fingerprint(meta: Mapping[str, Any]) -> str:
    keys = (
        "model", "depth", "analysis_mode", "budget_profile",
        "budget_profile_fingerprint", "max_inflight_llm", "pipeline_max_workers",
    )
    payload = {key: meta.get(key) for key in keys}
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
