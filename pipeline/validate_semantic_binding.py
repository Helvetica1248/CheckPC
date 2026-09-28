#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fail-closed semantic source-binding validator for parsed/analyzed artifacts.

Unlike coverage-only provenance checks, this validator confirms that every
LLM-attributed analyzed row resolves back to the same raw entry by positional
index, source_id, and canonical identifier. Deterministic-only rows that were
never sent to the LLM are excluded unless they retain an LLM attribution method.

The command-line path streams the potentially multi-gigabyte parsed JSON and
materializes only raw entries referenced by analyzed rows. This avoids loading
large directory inventories into memory while retaining fail-closed behavior.
"""
from __future__ import annotations

import argparse
import json
import hashlib
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from analyze_section import (
    _binding_identifier_matches,
    _canonical_identifier,
    _result_entry_raw_indices,
    _task140_semantic_key,
)
from comparison_provenance import raw_sections

_CONTAINER_RE = re.compile(r'^  "(sections|event_logs)": \{\s*$')
_SECTION_ARRAY_RE = re.compile(
    r'^    ("(?:[^"\\]|\\.)*"): \[\s*$'
)
_CONTAINER_END_RE = re.compile(r'^  \}[,]?\s*$')
_ARRAY_END_RE = re.compile(r'^    \][,]?\s*$')
_OBJECT_VALUE_START_RE = re.compile(r'^      \{\s*$')
_OBJECT_VALUE_END_RE = re.compile(r'^      \}[,]?\s*$')
_ARRAY_VALUE_START_RE = re.compile(r'^      \[\s*$')
_ARRAY_VALUE_END_RE = re.compile(r'^      \][,]?\s*$')


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be object: {path}")
    return value


def _eligible_entries(
    analyzed: Mapping[str, Any],
) -> tuple[dict[str, list[tuple[int, Mapping[str, Any]]]], int, list[dict[str, Any]]]:
    """Return strict LLM-evaluated rows grouped by raw-backed section.

    Provenance ``evaluated.source_ids`` is authoritative when present. Pure
    deterministic rows are skipped even when later provenance attachment added
    a positional attribution method. Normal evaluated rows require one
    non-negative ``_raw_source_index``; rev8 task_140 semantic groups use an
    explicit verified one-to-many ``_raw_source_indices`` vector instead.
    """
    sections = analyzed.get("sections", {})
    raw_backed = set(
        str(name) for name in ((analyzed.get("meta") or {}).get("section_raw_evidence") or {})
    )
    grouped: dict[str, list[tuple[int, Mapping[str, Any]]]] = defaultdict(list)
    skipped_deterministic = 0
    errors: list[dict[str, Any]] = []

    if not isinstance(sections, Mapping):
        return {}, 0, [{"kind": "analyzed_sections_missing"}]

    for section, result in sections.items():
        section_name = str(section)
        if raw_backed and section_name not in raw_backed:
            continue
        if not isinstance(result, Mapping):
            continue
        result_entries = result.get("entries") or []
        if not isinstance(result_entries, list):
            errors.append({"section": section_name, "kind": "entries_not_list"})
            continue

        provenance = result.get("_provenance") or {}
        stages = provenance.get("stages") or {} if isinstance(provenance, Mapping) else {}
        evaluated_stage = stages.get("evaluated") or {} if isinstance(stages, Mapping) else {}
        deterministic_stage = stages.get("deterministic") or {} if isinstance(stages, Mapping) else {}
        evaluated_ids = {
            str(value) for value in (evaluated_stage.get("source_ids") or []) if value
        } if isinstance(evaluated_stage, Mapping) else set()
        deterministic_ids = {
            str(value) for value in (deterministic_stage.get("source_ids") or []) if value
        } if isinstance(deterministic_stage, Mapping) else set()
        evaluated_count = int(evaluated_stage.get("count", 0) or 0) \
            if isinstance(evaluated_stage, Mapping) else 0

        if evaluated_count and not evaluated_ids:
            errors.append({
                "section": section_name,
                "kind": "semantic_source_binding_invalid",
                "detail": "evaluated_source_ids_missing",
                "evaluated_count": evaluated_count,
            })

        for entry_index, entry in enumerate(result_entries):
            if not isinstance(entry, Mapping):
                continue
            identifier = str(entry.get("identifier") or "")
            if entry.get("_meta_only") or identifier.startswith("⚠"):
                continue

            source_id = str(entry.get("source_id") or "")
            is_task140_group = (
                section_name == "task_140"
                and entry.get("_source_attribution_method") == "task140_semantic_group"
            )
            group_source_ids = {
                str(value) for value in (entry.get("_source_ids") or []) if value
            } if is_task140_group else set()
            if is_task140_group and evaluated_ids and group_source_ids:
                overlap = group_source_ids & evaluated_ids
                if overlap and not group_source_ids.issubset(evaluated_ids):
                    errors.append({
                        "section": section_name,
                        "entry_index": entry_index,
                        "source_id": source_id,
                        "identifier": identifier[:300],
                        "kind": "semantic_source_binding_invalid",
                        "detail": "task140_group_evaluated_source_ids_incomplete",
                    })
                is_evaluated = bool(group_source_ids) and group_source_ids.issubset(evaluated_ids)
            else:
                is_evaluated = bool(source_id and source_id in evaluated_ids)
            is_deterministic = bool(
                entry.get("deterministic_origin")
                or (source_id and source_id in deterministic_ids and not is_evaluated)
            )
            if is_deterministic:
                skipped_deterministic += 1
                continue

            # With complete provenance, only evaluated rows are in scope. For
            # legacy/small fixtures without provenance, an explicit attribution
            # method keeps the validator fail closed.
            if evaluated_ids and not is_evaluated:
                continue
            if not evaluated_ids and not entry.get("_source_attribution_method"):
                continue

            if is_task140_group:
                raw_indices = entry.get("_raw_source_indices")
                source_ids = entry.get("_source_ids")
                digest = str(entry.get("_task140_semantic_group_sha256") or "")
                basic_ok = (
                    isinstance(raw_indices, list) and bool(raw_indices)
                    and all(isinstance(x, int) and not isinstance(x, bool) and x >= 0
                            for x in raw_indices)
                    and len(raw_indices) == len(set(raw_indices))
                    and isinstance(source_ids, list)
                    and len(source_ids) == len(raw_indices)
                    and int(entry.get("occurrence_count", 0) or 0) == len(raw_indices)
                    and bool(re.fullmatch(r"[0-9a-f]{64}", digest))
                )
                if not basic_ok:
                    errors.append({
                        "section": section_name,
                        "entry_index": entry_index,
                        "source_id": source_id,
                        "identifier": identifier[:300],
                        "kind": "semantic_source_binding_invalid",
                        "detail": "task140_semantic_group_metadata_invalid",
                    })
                    continue
                grouped[section_name].append((entry_index, entry))
                continue

            raw_index = entry.get("_raw_source_index")
            if isinstance(raw_index, bool) or not isinstance(raw_index, int) or raw_index < 0:
                errors.append({
                    "section": section_name,
                    "entry_index": entry_index,
                    "source_id": source_id,
                    "identifier": identifier[:300],
                    "kind": "semantic_source_binding_invalid",
                    "detail": "raw_source_index_missing_or_invalid",
                })
                continue
            grouped[section_name].append((entry_index, entry))

    return dict(grouped), skipped_deterministic, errors


def _strip_trailing_comma(text: str) -> str:
    value = text.rstrip()
    if value.endswith(","):
        value = value[:-1].rstrip()
    return value


def _iter_pretty_array(
    fh: Iterable[str],
) -> Iterable[tuple[int, str]]:
    """Yield ``(index, JSON text)`` from a two-space indented array.

    Parsed artifacts are emitted by ``atomic_write_json(..., indent=2)``. The
    parser deliberately requires that canonical format; malformed or minified
    input fails closed instead of silently weakening validation.
    """
    index = 0
    iterator = iter(fh)
    for line in iterator:
        if _ARRAY_END_RE.match(line):
            return
        if not line.strip():
            continue

        buffer = [line]
        if _OBJECT_VALUE_START_RE.match(line):
            for continuation in iterator:
                buffer.append(continuation)
                if _OBJECT_VALUE_END_RE.match(continuation):
                    break
            else:
                raise ValueError("unterminated object in parsed section array")
        elif _ARRAY_VALUE_START_RE.match(line):
            for continuation in iterator:
                buffer.append(continuation)
                if _ARRAY_VALUE_END_RE.match(continuation):
                    break
            else:
                raise ValueError("unterminated array in parsed section array")

        yield index, _strip_trailing_comma("".join(buffer).strip())
        index += 1

    raise ValueError("unterminated parsed section array")


def _skip_pretty_array(fh: Iterable[str]) -> None:
    for line in fh:
        if _ARRAY_END_RE.match(line):
            return
    raise ValueError("unterminated parsed section array")


def _collect_target_raw_entries(
    parsed_path: Path,
    target_indices: Mapping[str, set[int]],
) -> tuple[dict[str, dict[int, Any]], set[str]]:
    """Stream parsed JSON and collect only requested section/index entries."""
    collected: dict[str, dict[int, Any]] = defaultdict(dict)
    seen_sections: set[str] = set()
    wanted_sections = set(target_indices)

    with parsed_path.open("r", encoding="utf-8") as fh:
        iterator = iter(fh)
        in_container = False
        for line in iterator:
            if not in_container:
                if _CONTAINER_RE.match(line):
                    in_container = True
                continue

            if _CONTAINER_END_RE.match(line):
                in_container = False
                continue

            match = _SECTION_ARRAY_RE.match(line)
            if not match:
                continue

            section = json.loads(match.group(1))
            if not isinstance(section, str):
                raise ValueError("parsed section key is not a string")
            seen_sections.add(section)

            if section not in wanted_sections:
                _skip_pretty_array(iterator)
                continue

            wanted = target_indices.get(section, set())
            # Later event_logs entries intentionally overwrite an identically
            # named sections entry, matching comparison_provenance.raw_sections.
            section_values: dict[int, Any] = {}
            for raw_index, raw_text in _iter_pretty_array(iterator):
                if raw_index not in wanted:
                    continue
                try:
                    section_values[raw_index] = json.loads(raw_text)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"cannot decode parsed {section}[{raw_index}]: {exc}"
                    ) from exc
            collected[section] = section_values

    return dict(collected), seen_sections


def _target_indices_for_entry(entry: Mapping[str, Any]) -> set[int]:
    if entry.get("_source_attribution_method") == "task140_semantic_group":
        return {
            int(value) for value in (entry.get("_raw_source_indices") or [])
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        }
    value = entry.get("_raw_source_index")
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return {int(value)}
    return set()


def _validate_task140_group_streamed(
    entry: Mapping[str, Any], available: Mapping[int, Any]
) -> str | None:
    raw_indices = list(entry.get("_raw_source_indices") or [])
    source_ids = list(entry.get("_source_ids") or [])
    digest = str(entry.get("_task140_semantic_group_sha256") or "")
    identifier = str(entry.get("identifier") or "")
    representative_sid = str(entry.get("source_id") or "")
    if not raw_indices or len(source_ids) != len(raw_indices):
        return "task140_semantic_group_metadata_invalid"
    if representative_sid != str(source_ids[0] or ""):
        return "task140_group_representative_source_id_mismatch"
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0
           for value in raw_indices):
        return "task140_group_raw_index_invalid"
    if len(raw_indices) != len(set(raw_indices)):
        return "task140_group_raw_index_duplicate"
    if any(left >= right for left, right in zip(raw_indices, raw_indices[1:])):
        return "task140_group_raw_indices_not_strictly_increasing"
    if int(entry.get("occurrence_count", 0) or 0) != len(raw_indices):
        return "task140_group_occurrence_count_mismatch"
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        return "task140_group_digest_invalid"
    for position, raw_index in enumerate(raw_indices):
        raw_entry = available.get(int(raw_index))
        if not isinstance(raw_entry, Mapping):
            return "task140_group_raw_index_out_of_range_or_not_object"
        expected_sid = str(raw_entry.get("source_id") or "")
        if not expected_sid or str(source_ids[position] or "") != expected_sid:
            return "task140_group_source_id_mismatch"
        # Representative-only identifier validation mirrors the analyzer.
        # Non-representative raw-text fallback identifiers may differ solely
        # because Event[n]/Date transport metadata is volatile; their exact
        # source_id and semantic digest remain mandatory below.
        if position == 0:
            expected_identifier = _canonical_identifier("task_140", dict(raw_entry))
            if not expected_identifier or not _binding_identifier_matches(
                expected_identifier, identifier
            ):
                return "task140_group_identifier_mismatch"
        semantic = _task140_semantic_key(dict(raw_entry))
        actual_digest = hashlib.sha256(
            semantic.encode("utf-8", errors="replace")
        ).hexdigest()
        if actual_digest != digest:
            return "task140_group_semantic_digest_mismatch"
    return None


def _validate_streamed(
    grouped: Mapping[str, list[tuple[int, Mapping[str, Any]]]],
    raw_entries: Mapping[str, Mapping[int, Any]],
    seen_sections: set[str],
    *,
    skipped_deterministic: int,
    initial_errors: list[dict[str, Any]],
) -> dict[str, Any]:
    errors = list(initial_errors)
    checked = 0

    for section in sorted(grouped):
        if section not in seen_sections:
            for entry_index, entry in grouped[section]:
                errors.append({
                    "section": section,
                    "entry_index": entry_index,
                    "source_id": str(entry.get("source_id") or ""),
                    "identifier": str(entry.get("identifier") or "")[:300],
                    "kind": "semantic_source_binding_invalid",
                    "detail": "parsed_section_missing",
                })
            continue

        available = raw_entries.get(section, {})
        for entry_index, entry in grouped[section]:
            checked += 1
            if (section == "task_140"
                    and entry.get("_source_attribution_method") == "task140_semantic_group"):
                detail = _validate_task140_group_streamed(entry, available)
                if detail:
                    errors.append({
                        "section": section,
                        "entry_index": entry_index,
                        "source_id": str(entry.get("source_id") or ""),
                        "identifier": str(entry.get("identifier") or "")[:300],
                        "kind": "semantic_source_binding_invalid",
                        "detail": detail,
                    })
                continue

            raw_index = int(entry["_raw_source_index"])
            raw_entry = available.get(raw_index)
            if not isinstance(raw_entry, Mapping):
                errors.append({
                    "section": section,
                    "entry_index": entry_index,
                    "raw_source_index": raw_index,
                    "source_id": str(entry.get("source_id") or ""),
                    "identifier": str(entry.get("identifier") or "")[:300],
                    "kind": "semantic_source_binding_invalid",
                    "detail": "raw_source_index_out_of_range_or_not_object",
                })
                continue

            expected_source_id = str(raw_entry.get("source_id") or "")
            actual_source_id = str(entry.get("source_id") or "")
            if not expected_source_id or actual_source_id != expected_source_id:
                errors.append({
                    "section": section,
                    "entry_index": entry_index,
                    "raw_source_index": raw_index,
                    "source_id": actual_source_id,
                    "expected_source_id": expected_source_id,
                    "identifier": str(entry.get("identifier") or "")[:300],
                    "kind": "semantic_source_binding_invalid",
                    "detail": "raw_index_source_id_mismatch",
                })
                continue

            expected_identifier = _canonical_identifier(section, dict(raw_entry))
            actual_identifier = str(entry.get("identifier") or "")
            if not expected_identifier or not _binding_identifier_matches(
                actual_identifier, expected_identifier
            ):
                errors.append({
                    "section": section,
                    "entry_index": entry_index,
                    "raw_source_index": raw_index,
                    "source_id": actual_source_id,
                    "identifier": actual_identifier[:300],
                    "expected_identifier": expected_identifier[:300],
                    "kind": "semantic_source_binding_invalid",
                    "detail": "raw_index_identifier_mismatch",
                })

    return {
        "status": "ACCEPT" if not errors else "REJECT",
        "checked_entries": checked,
        "skipped_deterministic_entries": skipped_deterministic,
        "error_count": len(errors),
        "errors": errors,
        "parsed_loading_mode": "streamed_target_indices",
    }


def validate(parsed: Mapping[str, Any], analyzed: Mapping[str, Any]) -> dict[str, Any]:
    """In-memory validator retained for unit tests and small fixtures."""
    raw = raw_sections(parsed)
    sections = analyzed.get("sections", {})
    errors: list[dict[str, Any]] = []
    checked = 0
    skipped_deterministic = 0

    if not isinstance(sections, Mapping):
        return {
            "status": "REJECT",
            "checked_entries": 0,
            "skipped_deterministic_entries": 0,
            "error_count": 1,
            "errors": [{"kind": "analyzed_sections_missing"}],
            "parsed_loading_mode": "in_memory",
        }

    for section in sorted(raw):
        result = sections.get(section)
        if not isinstance(result, Mapping):
            continue
        result_entries = result.get("entries") or []
        if not isinstance(result_entries, list):
            errors.append({"section": section, "kind": "entries_not_list"})
            continue

        for entry_index, entry in enumerate(result_entries):
            if not isinstance(entry, Mapping):
                continue
            identifier = str(entry.get("identifier") or "")
            if entry.get("_meta_only") or identifier.startswith("⚠"):
                continue
            if entry.get("deterministic_origin") and not entry.get(
                "_source_attribution_method"
            ):
                skipped_deterministic += 1
                continue

            checked += 1
            indices, method = _result_entry_raw_indices(
                section, raw[section], dict(entry)
            )
            if not indices:
                errors.append({
                    "section": section,
                    "entry_index": entry_index,
                    "source_id": str(entry.get("source_id") or ""),
                    "identifier": identifier[:300],
                    "kind": "semantic_source_binding_invalid",
                    "detail": method,
                })

    return {
        "status": "ACCEPT" if not errors else "REJECT",
        "checked_entries": checked,
        "skipped_deterministic_entries": skipped_deterministic,
        "error_count": len(errors),
        "errors": errors,
        "parsed_loading_mode": "in_memory",
    }


def validate_files(parsed_path: Path, analyzed_path: Path) -> dict[str, Any]:
    """Memory-bounded file validator used by the CLI and overnight runner."""
    analyzed = _load(analyzed_path)
    grouped, skipped, initial_errors = _eligible_entries(analyzed)
    targets = {
        section: set().union(*(_target_indices_for_entry(entry) for _, entry in entries))
        if entries else set()
        for section, entries in grouped.items()
    }
    raw_entries, seen_sections = _collect_target_raw_entries(parsed_path, targets)
    return _validate_streamed(
        grouped,
        raw_entries,
        seen_sections,
        skipped_deterministic=skipped,
        initial_errors=initial_errors,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("parsed", type=Path)
    parser.add_argument("analyzed", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    result = validate_files(args.parsed, args.analyzed)
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    print(text)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(text + "\n", encoding="utf-8")
    return 0 if result["status"] == "ACCEPT" else 1


if __name__ == "__main__":
    raise SystemExit(main())
