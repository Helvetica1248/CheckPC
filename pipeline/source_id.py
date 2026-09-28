#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stable evidence identity independent of LLM chunk positions."""
from __future__ import annotations
import hashlib
import json
from typing import Any, Iterable

SOURCE_ID_ALGORITHM_VERSION = "1"

_VOLATILE_KEYS = {
    "source_index", "_raw_source_index", "source_id", "_source_id",
    "_proc_hint", "_vt_results", "_floor", "_whitelist_match",
}


def canonical_evidence(entry: Any) -> str:
    def clean(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {str(k): clean(v) for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))
                    if str(k) not in _VOLATILE_KEYS}
        if isinstance(obj, list):
            return [clean(v) for v in obj]
        if isinstance(obj, tuple):
            return [clean(v) for v in obj]
        return obj
    return json.dumps(clean(entry), ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def canonical_evidence_sha256(entry: Any) -> str:
    """Return the canonical raw-evidence hash independent of source_id metadata."""
    return hashlib.sha256(canonical_evidence(entry).encode("utf-8")).hexdigest()


def make_source_id(collection_id: str, section: str, entry: Any, duplicate_ordinal: int = 0) -> str:
    raw_hash = canonical_evidence_sha256(entry)
    material = f"{collection_id}\0{section}\0{raw_hash}\0{duplicate_ordinal}".encode("utf-8")
    return f"{section}:{hashlib.sha256(material).hexdigest()[:24]}"


def assign_source_ids(collection_id: str, section: str, entries: Iterable[Any]) -> list[Any]:
    counts: dict[str, int] = {}
    out = []
    for entry in entries:
        if not isinstance(entry, dict):
            out.append(entry)
            continue
        raw = canonical_evidence(entry)
        ordinal = counts.get(raw, 0)
        counts[raw] = ordinal + 1
        entry["source_id"] = make_source_id(collection_id, section, entry, ordinal)
        out.append(entry)
    return out
