#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Threat-intelligence oriented local investigation engine for CheckPC v3.71.

This module deliberately sits outside the formal analysis/provenance pipeline.
It builds a small, regenerable per-job SQLite cache from immutable analysis
artifacts and exposes deterministic search/summary/timeline primitives to the
chat layer.  Formal parsed/analyzed/correlation artifacts are read-only.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import tempfile
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Optional

import directory_index

CHAT_INDEX_SCHEMA_VERSION = "3"
NORMALIZER_VERSION = "v371-rc3"
INDEX_FILENAME = "chat_evidence_v1.sqlite"
LEDGER_FILENAME = "evidence_ledger_v1.json"
SUPPORTED_SCHEMA_PAIRS = {
    ("3.69", "2.0"),
    ("3.70", "2.1"),
    ("3.71", "2.1"),
}
MAX_SCALAR_VALUES_PER_RECORD = 96
MAX_SCALAR_LENGTH = 4096
MAX_CORE_JSON_BYTES = int(os.environ.get("CHAT_CORE_JSON_MAX_BYTES", str(64 * 1024 * 1024)))
MAX_LEDGER_ROWS = 12
DEFAULT_TIMEOUT_SEC = float(os.environ.get("CHAT_INVESTIGATE_TIMEOUT_SEC", "12"))
DEFAULT_MAX_CASE_JOBS = int(os.environ.get("CHAT_INVESTIGATE_MAX_JOBS", "200"))
DEFAULT_LIMIT = int(os.environ.get("CHAT_INVESTIGATE_DEFAULT_LIMIT", "50"))
HARD_LIMIT = int(os.environ.get("CHAT_INVESTIGATE_HARD_LIMIT", "200"))
PARSED_SCAN_MAX_RECORDS = int(os.environ.get("CHAT_PARSED_SCAN_MAX_RECORDS", "50000"))
DIRECTORY_STREAM_MAX_BYTES = int(os.environ.get("CHAT_DIRECTORY_STREAM_MAX_BYTES", str(512 * 1024 * 1024)))

_BUILD_LOCKS: dict[str, threading.Lock] = {}
_BUILD_LOCKS_GUARD = threading.Lock()

_HASH_RE = re.compile(r"(?i)^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
_FQDN_RE = re.compile(r"(?i)^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_WIN_ABS_RE = re.compile(r"(?i)^[a-z]:[\\/]")
_EXT_RE = re.compile(r"(?i)(?:^|[\\/])[^\\/]+\.[a-z0-9_+-]{1,12}$")
_TIMESTAMP_FIELD_RE = re.compile(r"(?i)(?:^|[._-])(time|date|timestamp|last_run|created|modified|written)(?:$|[._-])")
_FOLLOWUP_RE = re.compile(r"(?:その|それら|さっき|先ほど|前回|先程|those|these|previous|earlier)", re.I)
_SECTION_LIST_RE = re.compile(r'^    "([^"]+)": \[$')
_SECTION_DICT_RE = re.compile(r'^    "([^"]+)": \{$')
_SIMPLE_EXT_GLOB_RE = re.compile(r'(?i)^\*\.([A-Za-z0-9_+-]{1,12})$')
_PREVALENCE_INTENT_RE = re.compile(r'(?:何台|何ホスト|何端末|どのホスト|どの端末|案件内.{0,24}(?:見つか|存在|観測|確認)|\bprevalence\b|\bhow many\s+(?:hosts?|endpoints?)\b|\bwhich\s+(?:hosts?|endpoints?)\b)', re.I)
_HOSTNAME_INTENT_RE = re.compile(r'(?:ホスト(?:名)?|端末(?:名)?|\bhost(?:name)?\b|\bendpoint\b)', re.I)
_IDENTIFIER_TOKEN_RE = re.compile(r'(?i)^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$')
_GENERIC_SEARCH_TOKENS = {
    'service', 'services', 'process', 'processes', 'task', 'tasks', 'registry',
    'network', 'dns', 'host', 'hostname', 'endpoint', 'file', 'path', 'status',
    'high', 'medium', 'low', 'critical', 'infection_suspicion', 'summary',
}
_EXPLICIT_WIN_PATH_RE = re.compile(r'(?i)([A-Z]:[\\/][^<>"|?\r\n]*?\.[A-Za-z0-9_+-]{1,12})')
_EXPLICIT_FILELIKE_RE = re.compile(r'([^\s\\/:*?"<>|、。！？「」『』（）()\[\]{}]+?\.[A-Za-z0-9_+-]{1,12})')
_EXPLICIT_HASH_TOKEN_RE = re.compile(r'(?i)(?<![0-9a-f])(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})(?![0-9a-f])')
_EXPLICIT_IPV4_TOKEN_RE = re.compile(r'(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])')


class InvestigationDeadlineExceeded(RuntimeError):
    pass


def _check_deadline(deadline_monotonic: Optional[float]) -> None:
    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
        raise InvestigationDeadlineExceeded("investigation_deadline_exceeded")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _json_digest(value: object) -> str:
    blob = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _sha256_file(path: Path, deadline_monotonic: Optional[float] = None) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            _check_deadline(deadline_monotonic)
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _safe_job_id(value: object) -> bool:
    text = str(value or "")
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", text)) and text not in (".", "..")


def _safe_job_root(jobs_dir: Path, job_id: str) -> tuple[Optional[Path], str]:
    if not _safe_job_id(job_id):
        return None, "invalid_job_id"
    try:
        root = jobs_dir.resolve()
        candidate = jobs_dir / job_id
        if candidate.is_symlink():
            return None, "job_symlink"
        resolved = candidate.resolve()
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None, "job_outside_root"
    if not resolved.is_dir():
        return None, "job_missing"
    return resolved, "ok"


def _select_artifact(job_root: Path, prefix: str, *, prefer_vt: bool = True) -> Optional[Path]:
    output = job_root / "output"
    if not output.is_dir() or output.is_symlink():
        return None
    vt, base = [], []
    for p in output.rglob(f"{prefix}*.json"):
        if p.is_symlink() or not p.is_file():
            continue
        try:
            p.resolve().relative_to(job_root)
        except (OSError, ValueError):
            continue
        if p.name.endswith("_vt.json"):
            vt.append(p.resolve())
        else:
            base.append(p.resolve())
    if prefer_vt and vt:
        return sorted(vt)[0]
    return sorted(base)[0] if base else (sorted(vt)[0] if vt else None)


def _select_timeline(job_root: Path) -> Optional[Path]:
    output = job_root / "output"
    if not output.is_dir() or output.is_symlink():
        return None
    vt, base = [], []
    for p in output.rglob("report_*_timeline.md"):
        if p.is_symlink() or not p.is_file():
            continue
        try:
            p.resolve().relative_to(job_root)
        except (OSError, ValueError):
            continue
        if p.name.endswith("_vt_timeline.md"):
            vt.append(p.resolve())
        else:
            base.append(p.resolve())
    return sorted(vt)[0] if vt else (sorted(base)[0] if base else None)


def _select_parsed(job_root: Path) -> Optional[Path]:
    return _select_artifact(job_root, "parsed_", prefer_vt=False)


def _select_ingest(job_root: Path) -> Optional[Path]:
    output = job_root / "output"
    if not output.is_dir() or output.is_symlink():
        return None
    rows = []
    for p in output.rglob("ingest_manifest.json"):
        if p.is_symlink() or not p.is_file():
            continue
        try:
            p.resolve().relative_to(job_root)
        except (OSError, ValueError):
            continue
        rows.append(p.resolve())
    return sorted(rows)[0] if rows else None



def _load_json(path: Optional[Path]) -> dict:
    """Small helper for non-core metadata such as ingest_manifest."""
    if path is None:
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError, UnicodeError):
        return {}


def _load_json_bounded(path: Optional[Path], deadline_monotonic: Optional[float], *, role: str) -> tuple[dict, str]:
    """Load analyzed/correlation JSON with size and wall-clock guards."""
    if path is None:
        return {}, f"{role}_missing"
    try:
        size = path.stat().st_size
    except OSError:
        return {}, f"{role}_stat_error"
    if size > MAX_CORE_JSON_BYTES:
        return {}, f"{role}_artifact_too_large"
    chunks: list[bytes] = []
    total = 0
    try:
        with path.open("rb") as fh:
            while True:
                _check_deadline(deadline_monotonic)
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_CORE_JSON_BYTES:
                    return {}, f"{role}_artifact_too_large"
                chunks.append(chunk)
        _check_deadline(deadline_monotonic)
        value = json.loads(b"".join(chunks).decode("utf-8", errors="strict"))
    except InvestigationDeadlineExceeded:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}, f"{role}_invalid_json"
    if not isinstance(value, dict):
        return {}, f"{role}_invalid_shape"
    return value, "ok"

def _read_top_level_meta_streaming(path: Optional[Path], deadline_monotonic: Optional[float], *, role: str) -> tuple[dict, str]:
    """Read only the top-level pretty-printed ``meta`` object.

    CheckPC owns the JSON formatting for formal artifacts.  This helper avoids
    loading large analyzed/parsed documents merely to validate their schema
    pair for the correlation-only summary fast path.  Format drift fails
    closed instead of being guessed.
    """
    if path is None:
        return {}, f"{role}_missing"
    lines: list[str] = []
    in_meta = False
    try:
        with path.open("r", encoding="utf-8", errors="strict") as fh:
            for line in fh:
                _check_deadline(deadline_monotonic)
                if not in_meta:
                    if line == '  "meta": {\n' or line.rstrip("\r\n") == '  "meta": {':
                        in_meta = True
                        lines = ["{"]
                    continue
                if line.startswith("  },") or line.rstrip("\r\n") == "  }":
                    lines.append("}")
                    break
                lines.append(line[2:] if line.startswith("  ") else line)
                if len(lines) > 20000:
                    return {}, f"{role}_meta_too_large"
    except InvestigationDeadlineExceeded:
        raise
    except (OSError, UnicodeError):
        return {}, f"{role}_meta_read_error"
    if not lines or lines[-1] != "}":
        return {}, f"{role}_format_unsupported"
    try:
        value = json.loads("".join(lines))
    except json.JSONDecodeError:
        return {}, f"{role}_format_unsupported"
    return (value if isinstance(value, dict) else {}), "ok"


def _read_parsed_meta_streaming(parsed: Optional[Path], deadline_monotonic: Optional[float]) -> tuple[dict, str]:
    return _read_top_level_meta_streaming(parsed, deadline_monotonic, role="parsed")



def _claimed_parsed_sha(job_root: Path, analyzed: dict) -> str:
    meta = analyzed.get("meta") if isinstance(analyzed.get("meta"), dict) else {}
    candidate = str(meta.get("parsed_artifact_sha256") or "").lower()
    if re.fullmatch(r"[0-9a-f]{64}", candidate):
        return candidate
    ingest = _load_json(_select_ingest(job_root))
    candidate = str(ingest.get("parsed_artifact_sha256") or "").lower()
    return candidate if re.fullmatch(r"[0-9a-f]{64}", candidate) else ""


def _version_pair(doc: dict) -> tuple[str, str]:
    meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}
    return (
        str(meta.get("pipeline_version") or doc.get("pipeline_version") or ""),
        str(meta.get("analysis_schema_version") or doc.get("analysis_schema_version") or ""),
    )


def _artifact_state(job_root: Path, deadline_monotonic: Optional[float] = None) -> tuple[dict, dict, Optional[Path], Optional[Path], Optional[Path]]:
    _check_deadline(deadline_monotonic)
    analyzed_path = _select_artifact(job_root, "analyzed_")
    correlation_path = _select_artifact(job_root, "correlation_")
    parsed_path = _select_parsed(job_root)

    analyzed, analyzed_status = _load_json_bounded(analyzed_path, deadline_monotonic, role="analyzed")
    correlation, correlation_status = _load_json_bounded(correlation_path, deadline_monotonic, role="correlation")
    if analyzed_path is not None and analyzed_status != "ok":
        support = analyzed_status
    elif correlation_path is not None and correlation_status != "ok":
        support = correlation_status
    else:
        support = "supported"

    analyzed_pair = _version_pair(analyzed) if analyzed else ("", "")
    correlation_pair = _version_pair(correlation) if correlation else ("", "")
    formal_pairs = [pair for pair in (analyzed_pair, correlation_pair) if pair != ("", "")]
    if support == "supported":
        if analyzed_path is not None and analyzed_pair == ("", ""):
            support = "artifact_schema_mismatch"
        elif correlation_path is not None and correlation_pair == ("", ""):
            support = "artifact_schema_mismatch"
        elif not formal_pairs:
            support = "analysis_artifacts_missing"
        elif any(pair not in SUPPORTED_SCHEMA_PAIRS for pair in formal_pairs):
            support = "unsupported_schema"
        elif any(pair != formal_pairs[0] for pair in formal_pairs[1:]):
            support = "artifact_schema_mismatch"

    pipeline_version, schema_version = formal_pairs[0] if formal_pairs else ("", "")
    parsed_meta, parsed_meta_status = _read_parsed_meta_streaming(parsed_path, deadline_monotonic)
    parsed_pair = (str(parsed_meta.get("pipeline_version") or ""), str(parsed_meta.get("analysis_schema_version") or ""))
    if parsed_path is None:
        parsed_support = "parsed_missing"
    elif parsed_meta_status != "ok":
        parsed_support = parsed_meta_status
    elif parsed_pair not in SUPPORTED_SCHEMA_PAIRS:
        parsed_support = "unsupported_schema"
    elif support != "supported" or parsed_pair != (pipeline_version, schema_version):
        parsed_support = "artifact_schema_mismatch"
    else:
        parsed_support = "supported"

    claimed_parsed_sha = _claimed_parsed_sha(job_root, analyzed) if parsed_path else ""
    actual_parsed_sha = _sha256_file(parsed_path, deadline_monotonic) if parsed_path and parsed_support == "supported" else ""
    if parsed_path is not None and parsed_support == "supported":
        if not re.fullmatch(r"[0-9a-f]{64}", actual_parsed_sha):
            parsed_support = "parsed_sha_unavailable"
        elif claimed_parsed_sha and claimed_parsed_sha != actual_parsed_sha:
            parsed_support = "source_artifact_sha_mismatch"

    sources = {
        "analyzed": {"path": str(analyzed_path or ""), "sha256": _sha256_file(analyzed_path, deadline_monotonic) if analyzed_path else ""},
        "correlation": {"path": str(correlation_path or ""), "sha256": _sha256_file(correlation_path, deadline_monotonic) if correlation_path else ""},
        "parsed": {"path": str(parsed_path or ""), "sha256": actual_parsed_sha, "expected_sha256": claimed_parsed_sha},
    }
    meta = analyzed.get("meta") if isinstance(analyzed.get("meta"), dict) else {}
    identity = {
        "pipeline_version": pipeline_version,
        "analysis_schema_version": schema_version,
        "analyzed_pipeline_version": analyzed_pair[0],
        "analyzed_analysis_schema_version": analyzed_pair[1],
        "correlation_pipeline_version": correlation_pair[0],
        "correlation_analysis_schema_version": correlation_pair[1],
        "package_manifest_sha256": str(meta.get("package_manifest_sha256") or ""),
        "collection_id": str(meta.get("collection_id") or parsed_meta.get("collection_id") or ""),
        "source_id_algorithm_version": str(meta.get("source_id_algorithm_version") or parsed_meta.get("source_id_algorithm_version") or ""),
        "support_status": support,
        "parsed_support_status": parsed_support,
        "parsed_pipeline_version": parsed_pair[0],
        "parsed_analysis_schema_version": parsed_pair[1],
        "parsed_expected_sha256": claimed_parsed_sha,
        "parsed_actual_sha256": actual_parsed_sha,
        "source_set_sha256": _json_digest(sources),
        "sources": sources,
    }
    return identity, {"analyzed": analyzed, "correlation": correlation, "parsed_meta": parsed_meta}, analyzed_path, correlation_path, parsed_path

def _index_path(job_root: Path) -> Path:
    return job_root / "chat_cache" / INDEX_FILENAME


def _ledger_path(job_root: Path) -> Path:
    return job_root / "chat_cache" / LEDGER_FILENAME


def _read_meta(index_path: Path) -> dict[str, str]:
    if not index_path.is_file() or index_path.is_symlink():
        return {}
    try:
        with sqlite3.connect(index_path) as con:
            return {str(k): str(v) for k, v in con.execute("SELECT key,value FROM index_meta")}
    except sqlite3.Error:
        return {}



def _flatten_scalars(value: object, prefix: str = "", *, depth: int = 0,
                     stats: Optional[dict[str, int]] = None) -> Iterable[tuple[str, str]]:
    if stats is None:
        stats = {}
    if depth > 4:
        stats["depth_truncated"] = stats.get("depth_truncated", 0) + 1
        return
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_prefix = f"{prefix}.{key_text}" if prefix else key_text
            yield from _flatten_scalars(child, child_prefix, depth=depth + 1, stats=stats)
    elif isinstance(value, (list, tuple)):
        for idx, child in enumerate(value):
            child_prefix = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
            yield from _flatten_scalars(child, child_prefix, depth=depth + 1, stats=stats)
    elif value is not None:
        text = str(value).strip()
        if not text:
            return
        stats["scalar_seen"] = stats.get("scalar_seen", 0) + 1
        if len(text) > MAX_SCALAR_LENGTH:
            stats["oversized_scalar_skipped"] = stats.get("oversized_scalar_skipped", 0) + 1
            return
        yield prefix, text

def _entity_types(value: str, field_path: str, section: str) -> set[str]:
    text = str(value or "").strip()
    low_field = field_path.casefold()
    low_section = section.casefold()
    types = {"keyword"}
    if not text:
        return types
    if "hostname" in low_field or "safe_hostname" in low_field:
        types.add("hostname")
    if _HASH_RE.fullmatch(text):
        types.add("hash")
    try:
        ipaddress.ip_address(text.strip("[]"))
        types.add("ip")
    except ValueError:
        pass
    if _FQDN_RE.fullmatch(text.rstrip(".")):
        types.add("fqdn")
    if _WIN_ABS_RE.match(text) or text.startswith("\\\\"):
        types.add("path")
        name = re.split(r"[\\/]", text.rstrip("\\/"))[-1]
        if "." in name:
            types.add("filename")
    elif _EXT_RE.search(text) and " " not in text:
        types.add("filename")
    if low_section in {"service", "system_7045"} or "service" in low_field:
        types.add("service")
    if low_section in {"task_scheduler", "task_106", "task_140", "task_141"} or "task" in low_field:
        types.add("task")
    if "reg" in low_section or any(token in low_field for token in ("reg_key", "registry", "value_name", "value_data")):
        types.add("registry")
    if low_section in {"tasklist", "process", "netstat"} or any(token in low_field for token in ("process", "image", "cmdline", "commandline")):
        types.add("process")
    if low_section.startswith("defender") or "threat" in low_field:
        types.add("threat_name")
    return types


def _timestamp_kind(section: str, field_path: str) -> str:
    f = field_path.casefold()
    s = section.casefold()
    if s.startswith("system_") or s.startswith("task_") or "event" in s:
        return "event_occurrence"
    if "last_run" in f or s == "userassist":
        return "last_execution_observation"
    if s.startswith("defender"):
        return "detection_event"
    if s == "directory":
        return "filesystem_metadata"
    return "source_timestamp"



def _insert_record(con: sqlite3.Connection, *, section: str, origin: str,
                   source_id: str, identifier: str, score: str, reason: str,
                   raw_index: str, occurrence_count: int, payload: object,
                   hostname: str, truncation_counter: Optional[Counter] = None) -> int:
    cur = con.execute(
        "INSERT INTO evidence_record(section,origin,source_id,identifier,score,reason,raw_index,occurrence_count,hostname) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (section, origin, source_id, identifier, score, reason, raw_index, occurrence_count, hostname),
    )
    record_id = int(cur.lastrowid)
    seen: set[tuple[str, str, str]] = set()
    scalar_count = 0
    local_stats: dict[str, int] = {}
    for field_path, text in _flatten_scalars(payload, stats=local_stats):
        if scalar_count >= MAX_SCALAR_VALUES_PER_RECORD:
            local_stats["scalar_count_truncated"] = local_stats.get("scalar_count_truncated", 0) + 1
            break
        scalar_count += 1
        for typ in _entity_types(text, field_path, section):
            key = (typ, field_path, text.casefold())
            if key in seen:
                continue
            seen.add(key)
            con.execute(
                "INSERT INTO entity_occurrence(record_id,entity_type,value_raw,match_key,field_path) VALUES(?,?,?,?,?)",
                (record_id, typ, text, text.casefold(), field_path),
            )
        if _TIMESTAMP_FIELD_RE.search(field_path):
            con.execute(
                "INSERT INTO timestamp_observation(record_id,ts_raw,ts_kind,source_field,timezone_basis,precision,confidence) "
                "VALUES(?,?,?,?,?,?,?)",
                (record_id, text, _timestamp_kind(section, field_path), field_path,
                 "source_preserved", "source", "UNSPECIFIED"),
            )
    if truncation_counter is not None:
        for key in ("scalar_count_truncated", "oversized_scalar_skipped", "depth_truncated"):
            if local_stats.get(key):
                truncation_counter[key] += int(local_stats[key])
    return record_id

def _parsed_identifier(section: str, record: dict) -> str:
    for key in ("identifier", "path", "image_path", "name", "service_name", "display_name",
                "task_name", "task_path", "process_name", "exe_path", "command_line",
                "remote", "fqdn", "threat_name", "source_id"):
        value = record.get(key)
        if value not in (None, ""):
            return str(value)
    return f"{section} structured evidence"



def _iter_parsed_structured(parsed: Path, deadline_monotonic: Optional[float]) -> Iterable[tuple[str, dict]]:
    """Yield CheckPC-owned structured records under sections and event_logs.

    Only pretty-printed list/dict values are accepted. Directory remains a separate
    raw-evidence path; raw string/blob values are intentionally not interpreted.
    Shape drift fails closed instead of being guessed.
    """
    containers = {"sections", "event_logs"}
    in_container = False
    container = ""
    section = ""
    mode = ""
    in_entry = False
    entry_lines: list[str] = []
    emitted = 0
    seen_containers: set[str] = set()
    with parsed.open("r", encoding="utf-8", errors="strict") as fh:
        for line in fh:
            _check_deadline(deadline_monotonic)
            stripped = line.rstrip("\r\n")
            if not in_container:
                m_empty = re.fullmatch(r'  "([^"]+)": \{\},?', stripped)
                if m_empty and m_empty.group(1) in containers:
                    seen_containers.add(m_empty.group(1))
                    continue
                m = re.fullmatch(r'  "([^"]+)": \{', stripped)
                if m and m.group(1) in containers:
                    container = m.group(1)
                    in_container = True
                    seen_containers.add(container)
                continue

            if not section:
                if stripped in ("  }", "  },"):
                    in_container = False
                    container = ""
                    continue
                m = _SECTION_LIST_RE.match(stripped)
                if m:
                    section = m.group(1)
                    mode = "skip_list" if container == "sections" and section == "directory" else "list"
                    continue
                m = _SECTION_DICT_RE.match(stripped)
                if m:
                    section = m.group(1)
                    mode = "dict"
                    entry_lines = ["{"]
                    continue
                # Scalars/raw blobs are not structured Evidence Pivot data.
                continue

            if mode == "skip_list":
                if stripped in ("    ]", "    ],"):
                    section = mode = ""
                continue

            if mode == "list":
                if not in_entry:
                    if stripped in ("    ]", "    ],"):
                        section = mode = ""
                        continue
                    if stripped == "      {":
                        in_entry = True
                        entry_lines = ["{"]
                    continue
                if stripped in ("      }", "      },"):
                    entry_lines.append("}")
                    try:
                        value = json.loads("".join(entry_lines))
                    except json.JSONDecodeError as exc:
                        raise RuntimeError(f"parsed_structured_decode_error:{container}:{section}") from exc
                    if not isinstance(value, dict):
                        raise RuntimeError(f"parsed_structured_non_object:{container}:{section}")
                    emitted += 1
                    if emitted > PARSED_SCAN_MAX_RECORDS:
                        raise RuntimeError("parsed_structured_record_limit")
                    yield section, value
                    in_entry = False
                    entry_lines = []
                else:
                    entry_lines.append(line[6:] if line.startswith("      ") else line)
                continue

            if mode == "dict":
                if stripped in ("    }", "    },"):
                    entry_lines.append("}")
                    try:
                        value = json.loads("".join(entry_lines))
                    except json.JSONDecodeError as exc:
                        raise RuntimeError(f"parsed_structured_decode_error:{container}:{section}") from exc
                    if not isinstance(value, dict):
                        raise RuntimeError(f"parsed_structured_non_object:{container}:{section}")
                    emitted += 1
                    if emitted > PARSED_SCAN_MAX_RECORDS:
                        raise RuntimeError("parsed_structured_record_limit")
                    yield section, value
                    section = mode = ""
                    entry_lines = []
                else:
                    entry_lines.append(line[4:] if line.startswith("    ") else line)

    if in_container or section or in_entry:
        raise RuntimeError("parsed_structured_format_incomplete")
    if not containers.issubset(seen_containers):
        # Old/supported documents are expected to carry both top-level containers.
        # Missing container means the structured search universe was not fully scanned.
        missing = ",".join(sorted(containers - seen_containers))
        raise RuntimeError(f"parsed_structured_container_missing:{missing}")

def _build_index(job_root: Path, job_id: str, job_meta: dict,
                 deadline_monotonic: Optional[float] = None) -> tuple[Optional[Path], dict]:
    _check_deadline(deadline_monotonic)
    identity, docs, analyzed_path, correlation_path, parsed_path = _artifact_state(job_root, deadline_monotonic)
    if identity["support_status"] != "supported":
        return None, {"reason": identity["support_status"], **identity}
    if analyzed_path is None and correlation_path is None:
        return None, {"reason": "analysis_artifacts_missing", **identity}
    if parsed_path is None or identity.get("parsed_support_status") != "supported":
        return None, {"reason": identity.get("parsed_support_status") or "parsed_unavailable", **identity}

    analyzed = docs["analyzed"]
    correlation = docs["correlation"]
    meta = analyzed.get("meta") if isinstance(analyzed.get("meta"), dict) else {}
    parsed_meta = docs.get("parsed_meta") if isinstance(docs.get("parsed_meta"), dict) else {}
    hostname = str(meta.get("safe_hostname") or meta.get("hostname") or parsed_meta.get("hostname") or correlation.get("hostname") or "")
    target = _index_path(job_root)
    target.parent.mkdir(parents=True, exist_ok=True)

    expected = {
        "chat_index_schema_version": CHAT_INDEX_SCHEMA_VERSION,
        "normalizer_version": NORMALIZER_VERSION,
        "source_set_sha256": identity["source_set_sha256"],
    }
    existing = _read_meta(target)
    if existing and all(existing.get(k) == v for k, v in expected.items()) and existing.get("state") == "ready":
        return target, {
            "reason": "ready", "hostname": existing.get("hostname", hostname),
            "core_evidence_complete": existing.get("core_evidence_complete", "true") == "true",
            "scalar_count_truncated": int(existing.get("scalar_count_truncated", "0") or 0),
            "oversized_scalar_skipped": int(existing.get("oversized_scalar_skipped", "0") or 0),
            "depth_truncated": int(existing.get("depth_truncated", "0") or 0),
            **identity,
        }

    lock_key = str(target)
    with _BUILD_LOCKS_GUARD:
        lock = _BUILD_LOCKS.setdefault(lock_key, threading.Lock())
    if deadline_monotonic is None:
        acquired = lock.acquire()
    else:
        remaining = max(0.0, deadline_monotonic - time.monotonic())
        acquired = lock.acquire(timeout=remaining)
    if not acquired:
        raise InvestigationDeadlineExceeded("index_build_lock_timeout")
    try:
        _check_deadline(deadline_monotonic)
        existing = _read_meta(target)
        if existing and all(existing.get(k) == v for k, v in expected.items()) and existing.get("state") == "ready":
            return target, {
                "reason": "ready", "hostname": existing.get("hostname", hostname),
                "core_evidence_complete": existing.get("core_evidence_complete", "true") == "true",
                "scalar_count_truncated": int(existing.get("scalar_count_truncated", "0") or 0),
                "oversized_scalar_skipped": int(existing.get("oversized_scalar_skipped", "0") or 0),
                "depth_truncated": int(existing.get("depth_truncated", "0") or 0),
                **identity,
            }

        fd, temp_name = tempfile.mkstemp(prefix=target.name + ".", suffix=".tmp", dir=target.parent)
        os.close(fd)
        temp = Path(temp_name)
        try:
            with sqlite3.connect(temp) as con:
                con.execute("PRAGMA journal_mode=OFF")
                con.execute("PRAGMA synchronous=FULL")
                con.executescript("""
                    CREATE TABLE index_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE source_artifact (role TEXT PRIMARY KEY, path TEXT NOT NULL, sha256 TEXT NOT NULL);
                    CREATE TABLE evidence_record (
                        record_id INTEGER PRIMARY KEY,
                        section TEXT NOT NULL, origin TEXT NOT NULL, source_id TEXT NOT NULL,
                        identifier TEXT NOT NULL, score TEXT NOT NULL, reason TEXT NOT NULL,
                        raw_index TEXT NOT NULL, occurrence_count INTEGER NOT NULL, hostname TEXT NOT NULL
                    );
                    CREATE TABLE entity_occurrence (
                        entity_id INTEGER PRIMARY KEY, record_id INTEGER NOT NULL,
                        entity_type TEXT NOT NULL, value_raw TEXT NOT NULL, match_key TEXT NOT NULL,
                        field_path TEXT NOT NULL,
                        FOREIGN KEY(record_id) REFERENCES evidence_record(record_id)
                    );
                    CREATE INDEX idx_entity_match ON entity_occurrence(match_key COLLATE NOCASE);
                    CREATE INDEX idx_entity_type_match ON entity_occurrence(entity_type,match_key COLLATE NOCASE);
                    CREATE INDEX idx_record_score ON evidence_record(score);
                    CREATE TABLE timestamp_observation (
                        timestamp_id INTEGER PRIMARY KEY, record_id INTEGER NOT NULL,
                        ts_raw TEXT NOT NULL, ts_kind TEXT NOT NULL, source_field TEXT NOT NULL,
                        timezone_basis TEXT NOT NULL, precision TEXT NOT NULL, confidence TEXT NOT NULL,
                        FOREIGN KEY(record_id) REFERENCES evidence_record(record_id)
                    );
                """)
                index_meta = {
                    **expected,
                    "builder_pipeline_version": "3.71",
                    "job_id": job_id,
                    "hostname": hostname,
                    "pipeline_version": identity["pipeline_version"],
                    "analysis_schema_version": identity["analysis_schema_version"],
                    "parsed_pipeline_version": identity.get("parsed_pipeline_version", ""),
                    "parsed_analysis_schema_version": identity.get("parsed_analysis_schema_version", ""),
                    "package_manifest_sha256": identity["package_manifest_sha256"],
                    "collection_id": identity["collection_id"],
                    "source_id_algorithm_version": identity["source_id_algorithm_version"],
                    "support_status": identity["support_status"],
                    "parsed_support_status": identity.get("parsed_support_status", ""),
                    "parsed_expected_sha256": identity.get("parsed_expected_sha256", ""),
                    "parsed_actual_sha256": identity.get("parsed_actual_sha256", ""),
                    "built_at": _now_iso(),
                    "core_ready": "true",
                    "core_evidence_complete": "false",
                    "scalar_count_truncated": "0",
                    "oversized_scalar_skipped": "0",
                    "depth_truncated": "0",
                    "parsed_structured_complete": "false",
                    "directory_ready": "false",
                    "state": "building",
                }
                con.executemany("INSERT INTO index_meta(key,value) VALUES(?,?)", index_meta.items())
                for role, row in identity["sources"].items():
                    con.execute("INSERT INTO source_artifact(role,path,sha256) VALUES(?,?,?)",
                                (role, row.get("path", ""), row.get("sha256", "")))

                truncation_counter: Counter = Counter()

                # Searchable metadata is descriptive only. Folder/status remain scope/control metadata.
                metadata_payload = {
                    "job_id": job_id,
                    "hostname": hostname,
                    "pipeline_version": identity["pipeline_version"],
                    "analysis_schema_version": identity["analysis_schema_version"],
                }
                _insert_record(con, section="job_metadata", origin="metadata", source_id="",
                               identifier=hostname or job_id, score="", reason="",
                               raw_index="", occurrence_count=1, payload=metadata_payload,
                               hostname=hostname, truncation_counter=truncation_counter)

                for sec_name, sec in (analyzed.get("sections") or {}).items():
                    _check_deadline(deadline_monotonic)
                    if not isinstance(sec, dict):
                        continue
                    for entry in sec.get("entries") or []:
                        _check_deadline(deadline_monotonic)
                        if not isinstance(entry, dict):
                            continue
                        raw_index = entry.get("_raw_source_index", entry.get("source_index", ""))
                        try:
                            raw_index_text = json.dumps(raw_index, ensure_ascii=False, sort_keys=True)
                        except TypeError:
                            raw_index_text = str(raw_index)
                        try:
                            occurrence_count = max(1, int(entry.get("occurrence_count", 1) or 1))
                        except (TypeError, ValueError):
                            occurrence_count = 1
                        _insert_record(con, section=str(sec_name), origin="analyzed",
                                       source_id=str(entry.get("source_id") or ""),
                                       identifier=str(entry.get("identifier") or ""),
                                       score=str(entry.get("score") or ""),
                                       reason=str(entry.get("reason") or ""),
                                       raw_index=raw_index_text, occurrence_count=occurrence_count,
                                       payload=entry, hostname=hostname, truncation_counter=truncation_counter)

                if correlation:
                    corr_payload = {
                        "infection_suspicion": correlation.get("infection_suspicion"),
                        "malware_family": correlation.get("malware_family"),
                        "correlated_iocs": correlation.get("correlated_iocs"),
                        "known_tools": correlation.get("known_tools"),
                        "summary": correlation.get("summary") or correlation.get("infection_summary"),
                    }
                    _insert_record(con, section="correlation", origin="correlation", source_id="",
                                   identifier=str(correlation.get("malware_family") or hostname or job_id),
                                   score=str(correlation.get("infection_suspicion") or ""), reason="",
                                   raw_index="", occurrence_count=1, payload=corr_payload, hostname=hostname,
                                   truncation_counter=truncation_counter)

                # rc2: structured parsed evidence is part of the core Evidence Pivot.
                parsed_count = 0
                for sec_name, record in _iter_parsed_structured(parsed_path, deadline_monotonic):
                    _check_deadline(deadline_monotonic)
                    parsed_count += 1
                    source_id = str(record.get("source_id") or "")
                    _insert_record(con, section=str(sec_name), origin="parsed_structured",
                                   source_id=source_id,
                                   identifier=_parsed_identifier(str(sec_name), record),
                                   score="", reason="raw structured parsed evidence",
                                   raw_index="", occurrence_count=1,
                                   payload=record, hostname=hostname, truncation_counter=truncation_counter)
                con.execute("UPDATE index_meta SET value='true' WHERE key='parsed_structured_complete'")
                for key in ("scalar_count_truncated", "oversized_scalar_skipped", "depth_truncated"):
                    con.execute("UPDATE index_meta SET value=? WHERE key=?", (str(int(truncation_counter.get(key, 0))), key))
                core_complete = not any(int(truncation_counter.get(key, 0)) > 0 for key in
                                        ("scalar_count_truncated", "oversized_scalar_skipped", "depth_truncated"))
                con.execute("UPDATE index_meta SET value=? WHERE key='core_evidence_complete'",
                            ("true" if core_complete else "false",))
                con.execute("INSERT OR REPLACE INTO index_meta(key,value) VALUES('parsed_structured_record_count',?)", (str(parsed_count),))
                con.execute("UPDATE index_meta SET value='ready' WHERE key='state'")
                con.commit()

            _check_deadline(deadline_monotonic)
            after_identity, _, _, _, _ = _artifact_state(job_root, deadline_monotonic)
            if after_identity["source_set_sha256"] != identity["source_set_sha256"]:
                raise RuntimeError("source_artifact_changed_during_build")
            os.replace(temp, target)
        finally:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
    finally:
        lock.release()
    final_meta = _read_meta(target)
    return target, {
        "reason": "built", "hostname": hostname,
        "core_evidence_complete": final_meta.get("core_evidence_complete", "true") == "true",
        "scalar_count_truncated": int(final_meta.get("scalar_count_truncated", "0") or 0),
        "oversized_scalar_skipped": int(final_meta.get("oversized_scalar_skipped", "0") or 0),
        "depth_truncated": int(final_meta.get("depth_truncated", "0") or 0),
        **identity,
    }

def _query_index(index_path: Path, query: str, limit: int) -> list[dict]:
    needle = query.casefold()
    exact_rows = []
    partial_rows = []
    with sqlite3.connect(index_path) as con:
        con.row_factory = sqlite3.Row
        sql = """
            SELECT e.entity_id,e.entity_type,e.value_raw,e.field_path,
                   r.record_id,r.section,r.origin,r.source_id,r.identifier,r.score,r.reason,
                   r.raw_index,r.occurrence_count,r.hostname
              FROM entity_occurrence e
              JOIN evidence_record r ON r.record_id=e.record_id
             WHERE e.match_key = ? COLLATE NOCASE
             LIMIT ?
        """
        exact_rows = list(con.execute(sql, (needle, limit)))
        remaining = max(0, limit - len(exact_rows))
        if remaining:
            sql2 = """
                SELECT e.entity_id,e.entity_type,e.value_raw,e.field_path,
                       r.record_id,r.section,r.origin,r.source_id,r.identifier,r.score,r.reason,
                       r.raw_index,r.occurrence_count,r.hostname
                  FROM entity_occurrence e
                  JOIN evidence_record r ON r.record_id=e.record_id
                 WHERE e.match_key LIKE ? ESCAPE '\\' COLLATE NOCASE
                   AND e.match_key <> ? COLLATE NOCASE
                 LIMIT ?
            """
            pattern = "%" + needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            partial_rows = list(con.execute(sql2, (pattern, needle, remaining)))

        rows = exact_rows + partial_rows
        out = []
        seen_records = set()
        for row in rows:
            rid = int(row["record_id"])
            # Multiple entity labels may point to the same evidence record. Return it once,
            # while preserving the matched label/value that caused the hit.
            if rid in seen_records:
                continue
            seen_records.add(rid)
            co_rows = list(con.execute(
                "SELECT entity_type,value_raw,field_path FROM entity_occurrence WHERE record_id=? AND entity_id<>? LIMIT 8",
                (rid, int(row["entity_id"])),
            ))
            out.append({
                "section": row["section"],
                "origin": row["origin"],
                "source_id": row["source_id"],
                "identifier": row["identifier"],
                "score": row["score"],
                "reason": row["reason"],
                "raw_index": row["raw_index"],
                "occurrence_count": row["occurrence_count"],
                "hostname": row["hostname"],
                "matched_entity_type": row["entity_type"],
                "matched_value": row["value_raw"],
                "matched_field": row["field_path"],
                "match_kind": "exact" if row in exact_rows else "partial",
                "relationships": [
                    {
                        "relation_type": "same_evidence_record",
                        "basis": "same evidence record",
                        "confidence": "MEDIUM",
                        "causal": False,
                        "entity_type": c[0],
                        "value": c[1],
                        "field": c[2],
                    }
                    for c in co_rows
                    if str(c[1]) != str(row["value_raw"])
                ],
            })
        return out[:limit]


def _query_index_variants(index_path: Path, queries: list[str], limit: int) -> list[dict]:
    """Search bounded query variants while de-duplicating identical evidence rows."""
    out: list[dict] = []
    seen = set()
    for candidate in queries:
        remaining = max(1, limit - len(out))
        for row in _query_index(index_path, candidate, remaining):
            key = (row.get('record_id'), row.get('source_id'), row.get('identifier'),
                   row.get('matched_entity_type'), row.get('matched_value'))
            if key in seen:
                continue
            seen.add(key)
            row = dict(row)
            row['matched_query'] = candidate
            out.append(row)
            if len(out) >= limit:
                return out
    return out


def _extract_explicit_search_literals(user_message: str) -> list[str]:
    """Return conservative analyst-supplied search literals in message order.

    This is a grounding aid, not a general NLP parser.  It deliberately
    recognizes only values whose surface form is useful as an exact evidence
    pivot: Windows paths, hashes, IP addresses, and filename/FQDN-like tokens.
    """
    text = str(user_message or "")
    found: list[tuple[int, str]] = []
    path_spans: list[tuple[int, int]] = []
    for m in _EXPLICIT_WIN_PATH_RE.finditer(text):
        value = m.group(1).strip().strip('`"\'')
        if value:
            found.append((m.start(1), value))
            path_spans.append((m.start(1), m.end(1)))
    for rx in (_EXPLICIT_HASH_TOKEN_RE, _EXPLICIT_IPV4_TOKEN_RE):
        for m in rx.finditer(text):
            value = m.group(0)
            if rx is _EXPLICIT_IPV4_TOKEN_RE:
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue
            found.append((m.start(), value))
    for m in _EXPLICIT_FILELIKE_RE.finditer(text):
        if any(a <= m.start(1) < b for a, b in path_spans):
            continue
        value = m.group(1).strip().strip('`"\'')
        if value and not value.startswith("*."):
            found.append((m.start(1), value))
    out: list[str] = []
    seen = set()
    for _, value in sorted(found, key=lambda row: row[0]):
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out


def _ground_search_query(model_query: str, user_message: str) -> tuple[str, dict]:
    """Keep a single explicit analyst literal from being broadened by the LLM."""
    original = str(model_query or "").strip()
    literals = _extract_explicit_search_literals(user_message)
    if len(literals) != 1:
        return original, {"applied": False, "reason": "explicit_literal_count", "literal_count": len(literals)}
    literal = literals[0]
    if original.casefold() == literal.casefold():
        return original, {"applied": False, "reason": "already_exact", "literal": literal}
    return literal, {
        "applied": True,
        "reason": "single_explicit_user_literal",
        "model_query": original,
        "effective_query": literal,
    }


def _search_query_variants(query: str, model_query: str, user_message: str) -> list[str]:
    """Return bounded deterministic search variants without broadening literals.

    The primary grounded query is always first.  For non-directory free-text
    queries only, add identifier-like tokens from the model query as a fallback
    (e.g. ``ajrouter service`` -> ``ajrouter``).  Explicit analyst file/path/hash/IP
    literals are never broadened.
    """
    primary = str(query or "").strip()
    if not primary:
        return []
    out = [primary]
    if _is_directory_query(primary):
        return out
    literals = _extract_explicit_search_literals(user_message)
    if literals:
        return out
    for raw in re.split(r'[^A-Za-z0-9_.-]+', str(model_query or '')):
        token = raw.strip().strip('`"\'')
        if not token or token.casefold() in _GENERIC_SEARCH_TOKENS:
            continue
        if not _IDENTIFIER_TOKEN_RE.fullmatch(token):
            continue
        if token.isdigit():
            continue
        if token.casefold() not in {x.casefold() for x in out}:
            out.append(token)
        if len(out) >= 4:
            break
    return out


def _is_explicit_hostname_intent(user_message: str) -> bool:
    return bool(_HOSTNAME_INTENT_RE.search(str(user_message or '')))


_HOSTNAME_UNKNOWN_SENTINELS = {"unknown"}


def _is_searchable_hostname(value: object) -> bool:
    """Return True only when a host identity can participate in absence proof.

    Correlation readability and hostname readability are different coverage
    dimensions.  Blank/UNKNOWN hostnames must never be counted as searched when
    answering an authoritative hostname-not-found question.
    """
    text = str(value or "").strip()
    return bool(text and text.casefold() not in _HOSTNAME_UNKNOWN_SENTINELS)


def _correlation_value_matches(query: str, value: str) -> bool:
    q = str(query or "").strip().strip('`"\'').replace("/", "\\").casefold()
    v = str(value or "").strip().strip('`"\'').replace("/", "\\").casefold()
    if not q or not v:
        return False
    if q == v:
        return True
    # Exact basename match is allowed for an explicit filename pivot against a
    # full path in correlation.  This is not substring matching.
    if "\\" not in q and re.fullmatch(r"[^\\]+\.[a-z0-9_+-]{1,12}", q):
        basename = v.rstrip("\\").split("\\")[-1]
        return basename == q
    return False


def _is_case_prevalence_request(user_message: str) -> bool:
    return bool(_PREVALENCE_INTENT_RE.search(str(user_message or "")))


def _normalize_directory_query(query: str) -> str:
    """Normalize only the simple extension glob form used by the chat model.

    This is deliberately not a general glob engine.  ``*.lnk`` becomes ``.lnk``
    so the existing bounded substring Directory search can enumerate extension
    matches.  Paths containing wildcards remain literal and therefore cannot
    broaden scope unexpectedly.
    """
    text = str(query or "").strip()
    m = _SIMPLE_EXT_GLOB_RE.fullmatch(text)
    if m:
        return "." + m.group(1)
    return text


def _directory_source_state(job_root: Path, job_meta: dict,
                            deadline_monotonic: Optional[float]) -> dict:
    """Lightweight schema/integrity gate for direct raw Directory access.

    Avoids building the normalized core Evidence Index just to answer a file
    listing/size question, while preserving the rc3 fail-closed schema and
    parsed-artifact SHA boundary.
    """
    _check_deadline(deadline_monotonic)
    analyzed_path = _select_artifact(job_root, "analyzed_")
    correlation_path = _select_artifact(job_root, "correlation_")
    parsed_path = _select_parsed(job_root)
    if parsed_path is None:
        return {"reason": "parsed_missing"}

    correlation, corr_status = _load_json_bounded(correlation_path, deadline_monotonic, role="correlation")
    if correlation_path is not None and corr_status != "ok":
        return {"reason": corr_status}
    analyzed_meta, analyzed_status = _read_top_level_meta_streaming(
        analyzed_path, deadline_monotonic, role="analyzed")
    if analyzed_path is not None and analyzed_status != "ok":
        return {"reason": analyzed_status}
    parsed_meta, parsed_status = _read_parsed_meta_streaming(parsed_path, deadline_monotonic)
    if parsed_status != "ok":
        return {"reason": parsed_status}

    analyzed_pair = (
        str(analyzed_meta.get("pipeline_version") or ""),
        str(analyzed_meta.get("analysis_schema_version") or ""),
    ) if analyzed_path is not None else ("", "")
    correlation_pair = _version_pair(correlation) if correlation_path is not None else ("", "")
    parsed_pair = (
        str(parsed_meta.get("pipeline_version") or ""),
        str(parsed_meta.get("analysis_schema_version") or ""),
    )
    formal_pairs = [pair for pair in (analyzed_pair, correlation_pair) if pair != ("", "")]
    if not formal_pairs:
        return {"reason": "analysis_artifacts_missing"}
    if any(pair not in SUPPORTED_SCHEMA_PAIRS for pair in formal_pairs + [parsed_pair]):
        return {"reason": "unsupported_schema"}
    expected_pair = formal_pairs[0]
    if any(pair != expected_pair for pair in formal_pairs[1:]) or parsed_pair != expected_pair:
        return {"reason": "artifact_schema_mismatch"}

    claimed = _claimed_parsed_sha(job_root, {"meta": analyzed_meta})
    actual = _sha256_file(parsed_path, deadline_monotonic)
    if not re.fullmatch(r"[0-9a-f]{64}", actual):
        return {"reason": "parsed_sha_unavailable"}
    if claimed and claimed != actual:
        return {"reason": "source_artifact_sha_mismatch"}

    corr_meta = correlation.get("meta") if isinstance(correlation.get("meta"), dict) else {}
    hostname = str(
        analyzed_meta.get("safe_hostname") or analyzed_meta.get("hostname") or
        parsed_meta.get("hostname") or corr_meta.get("safe_hostname") or
        corr_meta.get("hostname") or job_meta.get("hostname") or ""
    )
    return {
        "reason": "supported",
        "hostname": hostname,
        "pipeline_version": expected_pair[0],
        "analysis_schema_version": expected_pair[1],
        "parsed_path": parsed_path,
        "parsed_expected_sha256": claimed,
        "parsed_actual_sha256": actual,
    }


def _is_directory_query(query: str) -> bool:
    text = str(query or "").strip()
    if not text:
        return False
    if _WIN_ABS_RE.match(text) or text.startswith("\\\\"):
        return True
    if text.startswith("*.") or (text.startswith(".") and 2 <= len(text) <= 16):
        return True
    if re.fullmatch(r"[^\\/\s]+\.[A-Za-z0-9_+-]{1,12}", text):
        return True
    return False


def _directory_hit(job_id: str, hostname: str, entry: dict) -> dict:
    return {
        "job_id": job_id,
        "hostname": hostname,
        "section": "directory",
        "origin": "parsed_directory_raw",
        "source_id": entry.get("source_id", ""),
        "identifier": entry.get("path") or entry.get("name"),
        "score": "",
        "reason": "raw directory evidence (before individual LLM evaluation)",
        "date": entry.get("date", ""),
        "size": entry.get("size", ""),
        "name": entry.get("name", ""),
        "dir": entry.get("dir", ""),
        "matched_entity_type": "path_or_filename",
        "matched_value": entry.get("path") or entry.get("name"),
        "match_kind": "raw_directory",
        "relationships": [],
    }


def _read_ledger(job_root: Path) -> list[dict]:
    p = _ledger_path(job_root)
    try:
        rows = json.loads(p.read_text(encoding="utf-8"))
        return rows if isinstance(rows, list) else []
    except (OSError, json.JSONDecodeError, UnicodeError):
        return []


def _write_ledger(job_root: Path, rows: list[dict]) -> None:
    p = _ledger_path(job_root)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(rows[-MAX_LEDGER_ROWS:], ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=p.name + ".", suffix=".tmp", dir=p.parent)
    os.close(fd)
    temp = Path(temp_name)
    try:
        temp.write_text(data, encoding="utf-8")
        os.replace(temp, p)
    finally:
        temp.unlink(missing_ok=True)


class InvestigationEngine:
    """Deterministic local evidence investigation over current/same-case jobs."""

    def __init__(self, *, jobs_dir: Path, job_id: str, case_folder: str,
                 jobs_snapshot: dict, current_output_dir: Optional[Path] = None,
                 current_user_message: str = ""):
        self.jobs_dir = Path(jobs_dir)
        self.job_id = str(job_id or "")
        self.case_folder = str(case_folder or "").strip()
        self.jobs_snapshot = {str(k): dict(v) for k, v in (jobs_snapshot or {}).items() if isinstance(v, dict)}
        self.current_output_dir = Path(current_output_dir) if current_output_dir else None
        self.current_user_message = str(current_user_message or "")

    def _scope(self) -> tuple[list[str], dict]:
        case_ids = []
        if self.case_folder:
            for jid, meta in self.jobs_snapshot.items():
                if str(meta.get("folder") or "").strip() == self.case_folder:
                    case_ids.append(jid)
        if self.job_id and self.job_id not in case_ids:
            case_ids.insert(0, self.job_id)
        if not self.case_folder:
            case_ids = [self.job_id] if self.job_id else []
        case_ids = [jid for jid in case_ids if _safe_job_id(jid)]
        case_ids = list(dict.fromkeys(case_ids))
        actual_case_host_count = (
            sum(1 for meta in self.jobs_snapshot.values()
                if self.case_folder and str(meta.get("folder") or "").strip() == self.case_folder)
            if self.case_folder else (1 if self.job_id else 0)
        )
        scope_truncated = len(case_ids) > DEFAULT_MAX_CASE_JOBS
        case_ids = case_ids[:DEFAULT_MAX_CASE_JOBS]

        scope_basis = "same_folder" if self.case_folder else "current_host_only"
        # Bounded cross-turn scope reuse.  It never expands the live case boundary.
        current_root, _ = _safe_job_root(self.jobs_dir, self.job_id)
        ledger = _read_ledger(current_root) if current_root else []
        if ledger and _FOLLOWUP_RE.search(self.current_user_message):
            previous = ledger[-1].get("matched_job_ids") or []
            narrowed = [jid for jid in case_ids if jid in previous]
            if narrowed:
                case_ids = narrowed
                scope_basis = "previous_result_subset"
        return case_ids, {
            "case_folder": self.case_folder,
            "case_host_count": actual_case_host_count,
            "scope_host_count": len(case_ids),
            "scope_job_count": len(case_ids),
            "scope_basis": scope_basis,
            "scope_truncated": scope_truncated,
            "case_coverage_complete": (not scope_truncated) and len(case_ids) == actual_case_host_count,
        }

    def _record_ledger(self, *, action: str, query: str, scope: dict,
                       matched_job_ids: list[str], result: dict) -> None:
        job_root, reason = _safe_job_root(self.jobs_dir, self.job_id)
        if job_root is None:
            return
        entry = {
            "result_id": hashlib.sha256(f"{time.time_ns()}:{action}:{query}".encode()).hexdigest()[:16],
            "created_at": _now_iso(),
            "action": action,
            "query_fingerprint": hashlib.sha256(str(query).encode("utf-8")).hexdigest(),
            "scope_snapshot_digest": _json_digest({"case_folder": self.case_folder, "scope": scope}),
            "matched_job_ids": list(dict.fromkeys(matched_job_ids))[:DEFAULT_MAX_CASE_JOBS],
            "observed_host_count": result.get("observed_host_count"),
            "searchable_host_count": result.get("searchable_host_count"),
            "result_digest": _json_digest(result),
        }
        rows = _read_ledger(job_root)
        rows.append(entry)
        try:
            _write_ledger(job_root, rows)
        except OSError:
            pass
        result["evidence_ref"] = entry["result_id"]

    def _scan_correlation_exact_positive(self, query: str, scope_ids: list[str],
                                         scope: dict, deadline: float) -> tuple[dict, dict, int, Counter, bool]:
        """Single-pass exact-positive correlation scan for case prevalence.

        rc6 called ``summary()`` first and then scanned the same correlation
        artifacts again inside the original per-turn deadline.  On a 76-host
        real case the second pass timed out after five positive hosts while
        incorrectly inheriting the first pass's complete-coverage flag.  Keep
        schema validation and positive-only semantics, but determine matches,
        host metadata and coverage in one pass.
        """
        unavailable: Counter[str] = Counter()
        matched: dict[str, tuple[str, str]] = {}
        searchable_by_job: dict[str, dict] = {}
        searchable = 0

        for pos, jid in enumerate(scope_ids):
            if time.monotonic() >= deadline:
                unavailable["timeout_not_searched"] += len(scope_ids) - pos
                break
            root, reason = _safe_job_root(self.jobs_dir, jid)
            if root is None:
                unavailable[reason] += 1
                continue
            meta = self.jobs_snapshot.get(jid, {})
            if str(meta.get("status") or "") not in ("done", ""):
                unavailable["job_not_done"] += 1
                continue

            corr_path = _select_artifact(root, "correlation_")
            try:
                corr, corr_status = _load_json_bounded(corr_path, deadline, role="correlation")
            except InvestigationDeadlineExceeded:
                unavailable["timeout_not_searched"] += len(scope_ids) - pos
                break
            if corr_status != "ok":
                unavailable[corr_status] += 1
                continue

            corr_pair = _version_pair(corr)
            analyzed_path = _select_artifact(root, "analyzed_")
            parsed_path = _select_parsed(root)
            try:
                analyzed_meta, analyzed_meta_status = _read_top_level_meta_streaming(
                    analyzed_path, deadline, role="analyzed")
                parsed_meta, parsed_meta_status = _read_parsed_meta_streaming(parsed_path, deadline)
            except InvestigationDeadlineExceeded:
                unavailable["timeout_not_searched"] += len(scope_ids) - pos
                break
            analyzed_pair = (
                str(analyzed_meta.get("pipeline_version") or ""),
                str(analyzed_meta.get("analysis_schema_version") or ""),
            ) if analyzed_meta_status == "ok" else ("", "")
            parsed_pair = (
                str(parsed_meta.get("pipeline_version") or ""),
                str(parsed_meta.get("analysis_schema_version") or ""),
            ) if parsed_meta_status == "ok" else ("", "")

            if corr_pair == ("", ""):
                unavailable["artifact_schema_mismatch"] += 1
                continue
            if corr_pair not in SUPPORTED_SCHEMA_PAIRS:
                unavailable["unsupported_schema"] += 1
                continue
            if analyzed_path is not None:
                if analyzed_meta_status != "ok":
                    unavailable[analyzed_meta_status] += 1
                    continue
                if analyzed_pair not in SUPPORTED_SCHEMA_PAIRS or analyzed_pair != corr_pair:
                    unavailable["artifact_schema_mismatch"] += 1
                    continue
            if parsed_path is not None:
                if parsed_meta_status != "ok":
                    unavailable[parsed_meta_status] += 1
                    continue
                if parsed_pair not in SUPPORTED_SCHEMA_PAIRS or parsed_pair != corr_pair:
                    unavailable["artifact_schema_mismatch"] += 1
                    continue

            searchable += 1
            corr_meta = corr.get("meta") if isinstance(corr.get("meta"), dict) else {}
            row = {
                "job_id": jid,
                "hostname": str(corr_meta.get("safe_hostname") or corr_meta.get("hostname") or meta.get("hostname") or ""),
                "infection_suspicion": str(corr.get("infection_suspicion") or "UNKNOWN").upper(),
                "malware_family": str(corr.get("malware_family") or "UNKNOWN"),
                "pipeline_version": corr_pair[0],
                "analysis_schema_version": corr_pair[1],
            }
            searchable_by_job[jid] = row

            # One host counts at most once even if the same filename appears as
            # both a bare filename IOC and one or more full-path IOCs.
            for item in corr.get("correlated_iocs") or []:
                value = item.get("ioc") if isinstance(item, dict) else item
                text = str(value or "").strip()
                if not text or not _correlation_value_matches(query, text):
                    continue
                types = _entity_types(text, "correlated_iocs.ioc", "correlation")
                priority = ("hash", "ip", "fqdn", "path", "filename")
                typ = next((candidate for candidate in priority if candidate in types), "ioc")
                matched[jid] = (text, typ)
                break

        coverage_complete = (
            searchable == len(scope_ids)
            and not bool(scope.get("scope_truncated"))
        )
        return matched, searchable_by_job, searchable, unavailable, coverage_complete

    def search(self, query: str, limit: int = DEFAULT_LIMIT) -> dict:
        model_query = str(query or "").strip()
        if not model_query:
            return {"error": "query は必須です", "action": "search"}
        if len(model_query) > 512 or any(ord(ch) < 32 for ch in model_query):
            return {"error": "query が長すぎるか制御文字を含んでいます", "action": "search"}
        query, query_grounding = _ground_search_query(model_query, self.current_user_message)
        query_variants = _search_query_variants(query, model_query, self.current_user_message)
        try:
            limit = max(1, min(int(limit or DEFAULT_LIMIT), HARD_LIMIT))
        except (TypeError, ValueError):
            limit = DEFAULT_LIMIT

        scope_ids, scope = self._scope()
        started = time.monotonic()
        deadline = started + DEFAULT_TIMEOUT_SEC
        directory_relevant = _is_directory_query(query)
        directory_query = _normalize_directory_query(query) if directory_relevant else query

        # rc5: exact hostname is a cheap host-level lookup.  Reuse the
        # correlation fast path rather than cold-building every job Evidence
        # Index.  This remains the same public ``search`` action; no hostname
        # tool or caller-controlled scope is introduced.
        if (not directory_relevant and len(query) <= 128 and
                not any(ch.isspace() for ch in query)):
            host_summary = self.summary(limit=1, record_ledger=False)
            observed_hosts = host_summary.get("observed_hosts") or []
            hostname_searchable_rows = [
                row for row in observed_hosts
                if _is_searchable_hostname(row.get("hostname"))
            ]
            hostname_matches = [
                row for row in hostname_searchable_rows
                if str(row.get("hostname") or "").casefold() == query.casefold()
            ]
            hostname_intent = _is_explicit_hostname_intent(self.current_user_message)
            if hostname_matches or hostname_intent:
                fast_hits = []
                matched_ids = []
                for row in hostname_matches[:limit]:
                    jid = str(row.get("job_id") or "")
                    matched_ids.append(jid)
                    fast_hits.append({
                        "job_id": jid,
                        "hostname": str(row.get("hostname") or ""),
                        "section": "host_identity",
                        "origin": "correlation_host",
                        "source_id": "",
                        "identifier": str(row.get("hostname") or ""),
                        "score": str(row.get("infection_suspicion") or ""),
                        "reason": "exact hostname match with host-level correlation summary",
                        "matched_entity_type": "hostname",
                        "matched_value": str(row.get("hostname") or ""),
                        "match_kind": "exact",
                        "infection_suspicion": str(row.get("infection_suspicion") or ""),
                        "malware_family": str(row.get("malware_family") or ""),
                        "pipeline_version": str(row.get("pipeline_version") or ""),
                        "analysis_schema_version": str(row.get("analysis_schema_version") or ""),
                        "relationships": [],
                    })
                scope_host_count = int(scope.get("scope_host_count", len(scope_ids)))
                correlation_searchable = int(host_summary.get("correlation_searchable_host_count") or 0)
                hostname_searchable = len(hostname_searchable_rows)
                hostname_missing_or_unknown = max(0, correlation_searchable - hostname_searchable)
                hostname_coverage_complete = (
                    hostname_searchable == scope_host_count
                    and not bool(scope.get("scope_truncated"))
                )
                correlation_unavailable_reasons = dict(host_summary.get("correlation_unavailable_reasons") or {})
                hostname_unavailable_reasons = dict(correlation_unavailable_reasons)
                if hostname_missing_or_unknown:
                    hostname_unavailable_reasons["hostname_missing_or_unknown"] = hostname_missing_or_unknown
                searchable = hostname_searchable
                observed_count = len(hostname_matches)
                result = {
                    "action": "search",
                    "query": query,
                    "model_query": model_query,
                    "query_grounding": query_grounding,
                    "query_variants": query_variants,
                    "scope": scope,
                    "search_basis": "exact_hostname_correlation_fast_path",
                    "core_index_build_attempted": False,
                    "current_host_hits": [h for h in fast_hits if h.get("job_id") == self.job_id],
                    "other_host_hits": [h for h in fast_hits if h.get("job_id") != self.job_id],
                    "returned_count": len(fast_hits),
                    "truncated": observed_count > limit,
                    "observed_host_count": observed_count,
                    "prevalence_observed_host_count": observed_count,
                    "searchable_host_count": searchable,
                    "correlation_searchable_host_count": correlation_searchable,
                    "hostname_searchable_host_count": hostname_searchable,
                    "hostname_unavailable_host_count": max(0, scope_host_count - hostname_searchable),
                    "hostname_unavailable_reasons": hostname_unavailable_reasons,
                    "hostname_coverage_complete": hostname_coverage_complete,
                    "core_index_readable_host_count": 0,
                    "core_searchable_host_count": 0,
                    "core_partial_host_count": 0,
                    "core_partial_reasons": {},
                    "query_searchable_host_count": searchable,
                    "case_host_count": scope.get("case_host_count", scope_host_count),
                    "scope_host_count": scope_host_count,
                    "scope_truncated": bool(scope.get("scope_truncated")),
                    "case_coverage_complete": bool(scope.get("case_coverage_complete")) and hostname_coverage_complete,
                    "unavailable_host_count": max(0, scope_host_count - hostname_searchable),
                    "query_unavailable_host_count": max(0, scope_host_count - hostname_searchable),
                    "unavailable_reasons": hostname_unavailable_reasons,
                    "prevalence_basis": "correlation_hostname",
                    "prevalence": (f"{observed_count}/{searchable} searchable hosts"
                                   if hostname_coverage_complete and searchable else None),
                    "prevalence_status": "complete" if hostname_coverage_complete else "incomplete_coverage",
                    "coverage_complete": hostname_coverage_complete,
                    "query_coverage_complete": hostname_coverage_complete,
                    "directory_query": False,
                    "directory_raw_searchable_host_count": 0,
                    "directory_raw_partial_host_count": 0,
                    "directory_raw_match_count_total": 0,
                    "directory_raw_unavailable_reasons": {},
                    "directory_prevalence_complete": True,
                    "answer_facts": ({
                        "authoritative": True,
                        "entity_kind": "hostname",
                        "entity_exists": bool(observed_count),
                        "matched_host_count": observed_count,
                        "searchable_host_count": searchable,
                        "scope_host_count": scope_host_count,
                        "case_host_count": scope.get("case_host_count", scope_host_count),
                        "coverage_complete": True,
                        "prevalence": f"{observed_count}/{searchable} searchable hosts" if searchable else None,
                        "matched_hostnames": [str(r.get("hostname") or "") for r in hostname_matches],
                    } if hostname_intent and hostname_coverage_complete else None),
                    "note": (
                        ("Exact hostname matched host-level correlation metadata; no cold core index build was required."
                         if observed_count else
                         "Exact hostname existence was checked across complete hostname coverage and no match was found.")
                        if hostname_coverage_complete else
                        "Exact hostname was checked with incomplete hostname coverage; blank/UNKNOWN or otherwise unavailable host identities are not absence."
                    ),
                }
                self._record_ledger(action="search", query=query, scope=scope,
                                    matched_job_ids=matched_ids, result=result)
                return result

        # rc7: case-prevalence and previous-result follow-up queries use one
        # correlation pass.  rc6 first ran summary() and then rescanned the
        # same 76-host corpus inside the original deadline, so a partial second
        # pass could be mistaken for complete prevalence.  Zero positive
        # matches still fall through to the normal evidence search; correlation
        # remains a positive pivot, never an absence oracle.
        if (_is_case_prevalence_request(self.current_user_message) or
                scope.get("scope_basis") == "previous_result_subset"):
            matched, searchable_by_job, searchable, corr_unavailable, correlation_complete = \
                self._scan_correlation_exact_positive(query, scope_ids, scope, deadline)
            if matched:
                fast_hits = []
                for jid in scope_ids:
                    if jid not in matched or len(fast_hits) >= limit:
                        continue
                    row = searchable_by_job.get(jid, {})
                    text, typ = matched[jid]
                    fast_hits.append({
                        "job_id": jid,
                        "hostname": str(row.get("hostname") or ""),
                        "section": "correlation",
                        "origin": "correlation",
                        "source_id": "",
                        "identifier": text,
                        "score": str(row.get("infection_suspicion") or ""),
                        "reason": "exact positive match in host-level correlated IOC evidence",
                        "matched_entity_type": typ,
                        "matched_value": text,
                        "match_kind": "exact_positive_correlation",
                        "infection_suspicion": str(row.get("infection_suspicion") or ""),
                        "malware_family": str(row.get("malware_family") or ""),
                        "relationships": [],
                    })
                observed_count = len(matched)
                scope_host_count = int(scope.get("scope_host_count", len(scope_ids)))
                matched_job_ids = [jid for jid in scope_ids if jid in matched]
                matched_hostnames = [
                    str((searchable_by_job.get(jid) or {}).get("hostname") or jid)
                    for jid in matched_job_ids
                ]
                correlation_prevalence = (
                    f"{observed_count}/{searchable} searchable hosts"
                    if correlation_complete and searchable else None
                )
                # rc8: Put a compact authoritative aggregate before verbose hit
                # arrays.  chat_tools bounds tool output to 3000 characters; in
                # rc7 the count fields appeared after the hit arrays and could be
                # truncated, causing Qwen to recount only the visible hits.
                answer_facts = {
                    "authoritative": bool(correlation_complete),
                    "matched_host_count": observed_count if correlation_complete else None,
                    "observed_matched_host_count": observed_count,
                    "searchable_host_count": searchable,
                    "scope_host_count": scope_host_count,
                    "case_host_count": scope.get("case_host_count", scope_host_count),
                    "coverage_complete": bool(correlation_complete),
                    "prevalence": correlation_prevalence,
                    "matched_hostnames": matched_hostnames,
                    "instruction": "Use matched_host_count/prevalence as the deterministic Python aggregate; do not recount displayed hits.",
                }
                result = {
                    "action": "search",
                    "query": query,
                    "model_query": model_query,
                    "query_grounding": query_grounding,
                    "query_variants": query_variants,
                    "scope": scope,
                    "search_basis": "correlation_exact_positive_fast_path",
                    "answer_facts": answer_facts,
                    "correlation_scan_passes": 1,
                    "core_index_build_attempted": False,
                    "current_host_hits": [h for h in fast_hits if h.get("job_id") == self.job_id],
                    "other_host_hits": [h for h in fast_hits if h.get("job_id") != self.job_id],
                    "returned_count": len(fast_hits),
                    "truncated": observed_count > limit,
                    "observed_host_count": observed_count,
                    "prevalence_observed_host_count": observed_count,
                    "searchable_host_count": searchable,
                    "core_index_readable_host_count": 0,
                    "core_searchable_host_count": 0,
                    "core_partial_host_count": 0,
                    "core_partial_reasons": {},
                    "query_searchable_host_count": searchable,
                    "case_host_count": scope.get("case_host_count", scope_host_count),
                    "scope_host_count": scope_host_count,
                    "scope_truncated": bool(scope.get("scope_truncated")),
                    "case_coverage_complete": bool(scope.get("case_coverage_complete")) and correlation_complete,
                    "unavailable_host_count": max(0, scope_host_count - searchable),
                    "query_unavailable_host_count": max(0, scope_host_count - searchable),
                    "unavailable_reasons": dict(corr_unavailable),
                    "prevalence_basis": "correlation_exact_positive",
                    "prevalence": correlation_prevalence,
                    "prevalence_status": "complete" if correlation_complete else "incomplete_coverage",
                    "coverage_complete": correlation_complete,
                    "query_coverage_complete": correlation_complete,
                    "directory_query": _is_directory_query(query),
                    "directory_raw_searchable_host_count": 0,
                    "directory_raw_partial_host_count": 0,
                    "directory_raw_match_count_total": 0,
                    "directory_raw_unavailable_reasons": {},
                    "directory_prevalence_complete": False if _is_directory_query(query) else True,
                    "note": (
                        "Case prevalence is a distinct-host count from one complete exact-positive correlation scan; no cold Evidence Index build was required. Correlation non-hits are not used as an absence oracle."
                        if correlation_complete else
                        "Exact positive correlation matches were observed, but the single correlation scan did not cover the full scope; case prevalence is intentionally null."
                    ),
                }
                self._record_ledger(action="search", query=query, scope=scope,
                                    matched_job_ids=list(matched.keys()), result=result)
                return result

        # rc5: file/path/extension questions are answered from the current
        # host raw Directory before any cold case-wide core-index build.  If a
        # raw hit is found, return it immediately with explicit incomplete
        # case prevalence.  Other-host Directory coverage is never fabricated.
        if directory_relevant and self.job_id in scope_ids:
            root, root_reason = _safe_job_root(self.jobs_dir, self.job_id)
            if root is not None:
                try:
                    state = _directory_source_state(
                        root, self.jobs_snapshot.get(self.job_id, {}), deadline)
                except InvestigationDeadlineExceeded:
                    state = {"reason": "directory_search_timeout"}
                if state.get("reason") == "supported":
                    parsed = state.get("parsed_path")
                    try:
                        idx = directory_index.current_index_path(parsed)
                        if idx is not None:
                            raw = directory_index.search_keyword(
                                idx, directory_query, max_results=limit)
                            raw["complete"] = True
                        else:
                            raw = directory_index.search_keyword_streaming(
                                parsed, directory_query, max_results=limit,
                                deadline_monotonic=deadline,
                                max_bytes_scanned=DIRECTORY_STREAM_MAX_BYTES,
                            )
                    except InvestigationDeadlineExceeded:
                        raw = {"total": 0, "hits": [], "complete": False,
                               "stop_reason": "directory_search_timeout"}
                    except Exception:
                        raw = {"total": 0, "hits": [], "complete": False,
                               "stop_reason": "directory_search_error"}
                    if int(raw.get("total", 0) or 0) > 0:
                        hostname = str(state.get("hostname") or "")
                        fast_hits = [
                            _directory_hit(self.job_id, hostname, entry)
                            for entry in (raw.get("hits") or [])[:limit]
                        ]
                        scan_complete = bool(raw.get("complete", True))
                        scope_host_count = int(scope.get("scope_host_count", len(scope_ids)))
                        query_coverage_complete = (
                            scan_complete and scope_host_count == 1 and
                            not bool(scope.get("scope_truncated"))
                        )
                        raw_unavailable = Counter()
                        if not scan_complete:
                            raw_unavailable[str(raw.get("stop_reason") or "directory_partial_scan")] += 1
                        if scope_host_count > 1:
                            raw_unavailable["directory_not_searched_fast_path"] += scope_host_count - 1
                        result = {
                            "action": "search",
                            "query": query,
                            "model_query": model_query,
                            "query_grounding": query_grounding,
                            "query_variants": query_variants,
                            "directory_search_query": directory_query,
                            "scope": scope,
                            "search_basis": "current_host_directory_fast_path",
                            "core_index_build_attempted": False,
                            "current_host_hits": fast_hits,
                            "other_host_hits": [],
                            "returned_count": len(fast_hits),
                            "truncated": bool(raw.get("truncated")) or int(raw.get("total", 0) or 0) > len(fast_hits),
                            "observed_host_count": 1,
                            "prevalence_observed_host_count": 1 if scan_complete else 0,
                            "searchable_host_count": 1 if scan_complete else 0,
                            "core_index_readable_host_count": 0,
                            "core_searchable_host_count": 0,
                            "core_partial_host_count": 0,
                            "core_partial_reasons": {},
                            "query_searchable_host_count": 1 if scan_complete else 0,
                            "case_host_count": scope.get("case_host_count", scope_host_count),
                            "scope_host_count": scope_host_count,
                            "scope_truncated": bool(scope.get("scope_truncated")),
                            "case_coverage_complete": query_coverage_complete,
                            "unavailable_host_count": max(0, scope_host_count - (1 if scan_complete else 0)),
                            "query_unavailable_host_count": max(0, scope_host_count - (1 if scan_complete else 0)),
                            "unavailable_reasons": dict(raw_unavailable),
                            "prevalence_basis": "parsed_directory_raw",
                            "prevalence": ("1/1 searchable hosts" if query_coverage_complete else None),
                            "prevalence_status": "complete" if query_coverage_complete else "incomplete_coverage",
                            "coverage_complete": query_coverage_complete,
                            "query_coverage_complete": query_coverage_complete,
                            "directory_query": True,
                            "directory_raw_searchable_host_count": 1 if scan_complete else 0,
                            "directory_raw_partial_host_count": 0 if scan_complete else 1,
                            "directory_raw_match_count_total": int(raw.get("total", 0) or 0),
                            "directory_raw_unavailable_reasons": dict(raw_unavailable),
                            "directory_prevalence_complete": query_coverage_complete,
                            "note": (
                                "Requested raw Directory evidence was found on the current host before any cold case-wide core-index build. Case prevalence is intentionally not calculated because other-host raw Directory coverage was not searched."
                                if not query_coverage_complete else
                                "Requested raw Directory evidence was found with complete current-host scope coverage."
                            ),
                        }
                        self._record_ledger(action="search", query=query, scope=scope,
                                            matched_job_ids=[self.job_id], result=result)
                        return result

        hits: list[dict] = []
        matched_jobs: set[str] = set()
        searchable_jobs: list[str] = []
        complete_core_jobs: list[str] = []
        partial_core: Counter[str] = Counter()
        unavailable: Counter[str] = Counter()
        host_meta: dict[str, dict] = {}
        host_states: dict[str, dict] = {}

        for jid in scope_ids:
            if time.monotonic() >= deadline:
                unavailable["timeout_not_searched"] += 1
                host_states[jid] = {"reason": "timeout_not_searched"}
                continue
            root, reason = _safe_job_root(self.jobs_dir, jid)
            if root is None:
                unavailable[reason] += 1
                host_states[jid] = {"reason": reason}
                continue
            meta = self.jobs_snapshot.get(jid, {})
            if str(meta.get("status") or "") not in ("done", ""):
                unavailable["job_not_done"] += 1
                host_states[jid] = {"reason": "job_not_done"}
                continue
            try:
                index_path, state = _build_index(root, jid, meta, deadline)
            except InvestigationDeadlineExceeded:
                unavailable["timeout_not_searched"] += 1
                host_states[jid] = {"reason": "timeout_not_searched"}
                continue
            except Exception:
                unavailable["index_build_error"] += 1
                host_states[jid] = {"reason": "index_build_error"}
                continue
            host_states[jid] = state
            if index_path is None:
                unavailable[state.get("reason", "index_unavailable")] += 1
                continue
            searchable_jobs.append(jid)
            if bool(state.get("core_evidence_complete", True)):
                complete_core_jobs.append(jid)
            else:
                partial_core["core_evidence_truncated"] += 1
            hostname = str(state.get("hostname") or "")
            host_meta[jid] = {
                "hostname": hostname,
                "pipeline_version": state.get("pipeline_version", ""),
                "analysis_schema_version": state.get("analysis_schema_version", ""),
            }

            if len(hits) < limit:
                remaining = limit - len(hits)
                rows = _query_index_variants(index_path, query_variants, remaining)
                for row in rows:
                    if len(hits) >= limit:
                        break
                    row["job_id"] = jid
                    hits.append(row)
                    matched_jobs.add(jid)
                if rows:
                    matched_jobs.add(jid)
            else:
                # Display limit is already full; probe only for host prevalence.
                try:
                    if _query_index_variants(index_path, query_variants, 1):
                        matched_jobs.add(jid)
                except Exception:
                    pass

        raw_dir_searchable: list[str] = []
        raw_dir_partial: list[str] = []
        raw_dir_unavailable: Counter[str] = Counter()
        raw_hits_collected: list[dict] = []
        raw_match_count_total = 0
        if directory_relevant:
            for jid in scope_ids:
                if time.monotonic() >= deadline:
                    raw_dir_unavailable["directory_search_timeout"] += 1
                    continue
                state = host_states.get(jid, {})
                if state.get("reason") not in ("ready", "built"):
                    raw_dir_unavailable[state.get("reason", "core_not_searchable")] += 1
                    continue
                if state.get("parsed_support_status") != "supported":
                    raw_dir_unavailable[state.get("parsed_support_status") or "parsed_unavailable"] += 1
                    continue
                root, reason = _safe_job_root(self.jobs_dir, jid)
                if root is None:
                    raw_dir_unavailable[reason] += 1
                    continue
                parsed = _select_parsed(root)
                if parsed is None:
                    raw_dir_unavailable["parsed_missing"] += 1
                    continue
                try:
                    remaining = max(1, limit - len(raw_hits_collected))
                    idx = directory_index.current_index_path(parsed)
                    if idx is not None:
                        raw = directory_index.search_keyword(idx, directory_query, max_results=remaining)
                        raw["complete"] = True
                    elif jid == self.job_id:
                        raw = directory_index.search_keyword_streaming(
                            parsed, directory_query, max_results=remaining,
                            deadline_monotonic=deadline,
                            max_bytes_scanned=DIRECTORY_STREAM_MAX_BYTES,
                        )
                    else:
                        raw_dir_unavailable["directory_index_not_ready"] += 1
                        continue
                    is_complete = bool(raw.get("complete", True))
                    if is_complete:
                        raw_dir_searchable.append(jid)
                    else:
                        raw_dir_partial.append(jid)
                        raw_dir_unavailable[str(raw.get("stop_reason") or "directory_partial_scan")] += 1
                    raw_match_count_total += int(raw.get("total", 0) or 0)
                    if raw.get("total", 0):
                        matched_jobs.add(jid)
                    hostname = host_meta.get(jid, {}).get("hostname") or str(state.get("hostname") or "")
                    if len(raw_hits_collected) < limit:
                        for entry in raw.get("hits", []):
                            if len(raw_hits_collected) >= limit:
                                break
                            raw_hits_collected.append(_directory_hit(jid, hostname, entry))
                except InvestigationDeadlineExceeded:
                    raw_dir_unavailable["directory_search_timeout"] += 1
                except Exception:
                    raw_dir_unavailable["directory_search_error"] += 1

        if directory_relevant and raw_hits_collected:
            merged: list[dict] = []
            seen = set()
            for row in raw_hits_collected + hits:
                key = (row.get("job_id"), row.get("origin"), row.get("source_id"), row.get("identifier"))
                if key in seen:
                    continue
                seen.add(key)
                if len(merged) >= limit:
                    break
                merged.append(row)
            hits = merged
        else:
            hits = hits[:limit]

        scope_host_count = int(scope.get("scope_host_count", len(scope_ids)))
        if directory_relevant:
            query_searchable_ids = set(raw_dir_searchable)
            query_coverage_complete = (
                len(query_searchable_ids) == scope_host_count
                and not raw_dir_partial
                and not bool(scope.get("scope_truncated"))
            )
            prevalence_basis = "parsed_directory_raw"
        else:
            query_searchable_ids = set(complete_core_jobs)
            query_coverage_complete = (
                len(query_searchable_ids) == scope_host_count
                and not bool(scope.get("scope_truncated"))
            )
            prevalence_basis = "normalized_chat_core(analyzed+correlation+parsed_structured+metadata)"
        prevalence_observed = len(matched_jobs & query_searchable_ids)
        prevalence = (
            f"{prevalence_observed}/{len(query_searchable_ids)} searchable hosts"
            if query_coverage_complete and query_searchable_ids else
            ("0/0 searchable hosts" if query_coverage_complete else None)
        )

        current_hits = [h for h in hits if h.get("job_id") == self.job_id]
        other_hits = [h for h in hits if h.get("job_id") != self.job_id]
        result = {
            "action": "search",
            "query": query,
            "model_query": model_query,
            "query_grounding": query_grounding,
            "query_variants": query_variants,
            "directory_search_query": directory_query if directory_relevant else None,
            "scope": scope,
            "current_host_hits": current_hits,
            "other_host_hits": other_hits,
            "returned_count": len(hits),
            "truncated": len(hits) >= limit,
            "observed_host_count": len(matched_jobs),
            "prevalence_observed_host_count": prevalence_observed,
            "searchable_host_count": len(searchable_jobs),
            "core_index_readable_host_count": len(searchable_jobs),
            "core_searchable_host_count": len(complete_core_jobs),
            "core_partial_host_count": len(searchable_jobs) - len(complete_core_jobs),
            "core_partial_reasons": dict(partial_core),
            "query_searchable_host_count": len(query_searchable_ids),
            "case_host_count": scope.get("case_host_count", scope_host_count),
            "scope_host_count": scope_host_count,
            "scope_truncated": bool(scope.get("scope_truncated")),
            "case_coverage_complete": bool(scope.get("case_coverage_complete")) and query_coverage_complete,
            "unavailable_host_count": max(0, scope_host_count - len(searchable_jobs)),
            "query_unavailable_host_count": max(0, scope_host_count - len(query_searchable_ids)),
            "unavailable_reasons": dict(unavailable),
            "prevalence_basis": prevalence_basis,
            "prevalence": prevalence,
            "prevalence_status": "complete" if query_coverage_complete else "incomplete_coverage",
            "coverage_complete": query_coverage_complete,
            "query_coverage_complete": query_coverage_complete,
            "directory_query": directory_relevant,
            "directory_raw_searchable_host_count": len(raw_dir_searchable),
            "directory_raw_partial_host_count": len(raw_dir_partial),
            "directory_raw_match_count_total": raw_match_count_total,
            "directory_raw_unavailable_reasons": dict(raw_dir_unavailable),
            "directory_prevalence_complete": (not directory_relevant) or query_coverage_complete,
            "note": (
                "Query-specific evidence coverage is incomplete; case prevalence is intentionally not calculated and non-hits must not be treated as absence."
                if not query_coverage_complete
                else "Non-hits only establish absence within the explicitly searched evidence scope."
            ),
        }
        self._record_ledger(action="search", query=query, scope=scope,
                            matched_job_ids=sorted(matched_jobs), result=result)
        return result

    def summary(self, limit: int = 20, *, record_ledger: bool = True) -> dict:
        """Return a case summary from host-level correlation artifacts only.

        Summary is intentionally a fast path: it must not cold-build the chat
        Evidence Index just to answer deterministic host-level questions such
        as the HIGH/MEDIUM distribution.  Search/timeline remain responsible
        for building/querying normalized evidence indexes.
        """
        try:
            limit = max(1, min(int(limit or 20), 50))
        except (TypeError, ValueError):
            limit = 20
        scope_ids, scope = self._scope()
        deadline = time.monotonic() + DEFAULT_TIMEOUT_SEC
        correlation_searchable: list[str] = []
        unavailable: Counter[str] = Counter()
        suspicion = Counter()
        families = Counter()
        versions = Counter()
        ioc_hosts: dict[tuple[str, str], set[str]] = defaultdict(set)
        host_rows: list[dict] = []

        for jid in scope_ids:
            if time.monotonic() >= deadline:
                unavailable["timeout_not_searched"] += 1
                continue
            root, reason = _safe_job_root(self.jobs_dir, jid)
            if root is None:
                unavailable[reason] += 1
                continue
            meta = self.jobs_snapshot.get(jid, {})
            if str(meta.get("status") or "") not in ("done", ""):
                unavailable["job_not_done"] += 1
                continue

            corr_path = _select_artifact(root, "correlation_")
            try:
                corr, corr_status = _load_json_bounded(corr_path, deadline, role="correlation")
            except InvestigationDeadlineExceeded:
                unavailable["timeout_not_searched"] += 1
                continue
            if corr_status != "ok":
                unavailable[corr_status] += 1
                continue

            # Preserve rc3's formal-artifact schema consistency guarantee
            # without hashing/indexing the large parsed/analyzed evidence.
            corr_pair = _version_pair(corr)
            analyzed_path = _select_artifact(root, "analyzed_")
            parsed_path = _select_parsed(root)
            try:
                analyzed_meta, analyzed_meta_status = _read_top_level_meta_streaming(
                    analyzed_path, deadline, role="analyzed")
                parsed_meta, parsed_meta_status = _read_parsed_meta_streaming(parsed_path, deadline)
            except InvestigationDeadlineExceeded:
                unavailable["timeout_not_searched"] += 1
                continue
            analyzed_pair = (
                str(analyzed_meta.get("pipeline_version") or ""),
                str(analyzed_meta.get("analysis_schema_version") or ""),
            ) if analyzed_meta_status == "ok" else ("", "")
            parsed_pair = (
                str(parsed_meta.get("pipeline_version") or ""),
                str(parsed_meta.get("analysis_schema_version") or ""),
            ) if parsed_meta_status == "ok" else ("", "")

            if corr_pair == ("", ""):
                unavailable["artifact_schema_mismatch"] += 1
                continue
            if corr_pair not in SUPPORTED_SCHEMA_PAIRS:
                unavailable["unsupported_schema"] += 1
                continue
            if analyzed_path is not None:
                if analyzed_meta_status != "ok":
                    unavailable[analyzed_meta_status] += 1
                    continue
                if analyzed_pair not in SUPPORTED_SCHEMA_PAIRS or analyzed_pair != corr_pair:
                    unavailable["artifact_schema_mismatch"] += 1
                    continue
            if parsed_path is not None:
                if parsed_meta_status != "ok":
                    unavailable[parsed_meta_status] += 1
                    continue
                if parsed_pair not in SUPPORTED_SCHEMA_PAIRS or parsed_pair != corr_pair:
                    unavailable["artifact_schema_mismatch"] += 1
                    continue

            correlation_searchable.append(jid)
            versions[corr_pair] += 1
            corr_meta = corr.get("meta") if isinstance(corr.get("meta"), dict) else {}
            hostname = str(corr_meta.get("safe_hostname") or corr_meta.get("hostname") or meta.get("hostname") or "")
            sus = str(corr.get("infection_suspicion") or "UNKNOWN").upper()
            fam = str(corr.get("malware_family") or "UNKNOWN")
            suspicion[sus] += 1
            families[fam] += 1
            host_rows.append({
                "job_id": jid,
                "hostname": hostname,
                "infection_suspicion": sus,
                "malware_family": fam,
                "pipeline_version": corr_pair[0],
                "analysis_schema_version": corr_pair[1],
            })

            for item in corr.get("correlated_iocs") or []:
                value = item.get("ioc") if isinstance(item, dict) else item
                text = str(value or "").strip()
                if not text:
                    continue
                types = _entity_types(text, "correlated_iocs.ioc", "correlation")
                priority = ("hash", "ip", "fqdn", "path", "filename")
                typ = next((candidate for candidate in priority if candidate in types), "ioc")
                ioc_hosts[(typ, text)].add(jid)

        scope_host_count = int(scope.get("scope_host_count", len(scope_ids)))
        correlation_coverage_complete = (
            len(correlation_searchable) == scope_host_count
            and not bool(scope.get("scope_truncated"))
        )
        observed_high = sum(v for k, v in suspicion.items() if k in {"HIGH", "CRITICAL"})

        shared = []
        rare = []
        hostname_by_job = {row["job_id"]: row["hostname"] for row in host_rows}
        for (typ, value), hosts in ioc_hosts.items():
            row = {
                "entity_type": typ,
                "value": value,
                "host_count": len(hosts),
                "hostnames": [hostname_by_job.get(jid, "") for jid in sorted(hosts)[:20]],
            }
            (shared if len(hosts) >= 2 else rare).append(row)
        shared.sort(key=lambda r: (-r["host_count"], r["entity_type"], r["value"].casefold()))
        rare.sort(key=lambda r: (r["entity_type"], r["value"].casefold()))

        observed_suspicion = dict(suspicion)
        observed_families = dict(families)
        observed_shared = shared[:limit]
        observed_rare = rare[:limit]
        result = {
            "action": "summary",
            "scope": scope,
            "summary_basis": "correlation_fast_path",
            "core_index_build_attempted": False,
            "case_host_count": scope.get("case_host_count", len(scope_ids)),
            "scope_host_count": scope_host_count,
            "searchable_host_count": len(correlation_searchable),
            "correlation_searchable_host_count": len(correlation_searchable),
            "correlation_unavailable_host_count": max(0, scope_host_count - len(correlation_searchable)),
            "correlation_unavailable_reasons": dict(unavailable),
            "unavailable_host_count": max(0, scope_host_count - len(correlation_searchable)),
            "unavailable_reasons": dict(unavailable),
            "scope_truncated": bool(scope.get("scope_truncated")),
            "correlation_coverage_complete": correlation_coverage_complete,
            "case_coverage_complete": bool(scope.get("case_coverage_complete")) and correlation_coverage_complete,
            "coverage_complete": correlation_coverage_complete,
            "observed_infection_suspicion_host_distribution": observed_suspicion,
            "observed_high_or_above_host_count": observed_high,
            "infection_suspicion_host_distribution": observed_suspicion if correlation_coverage_complete else None,
            "high_or_above_host_count": observed_high if correlation_coverage_complete else None,
            "observed_malware_family_host_distribution": observed_families,
            "malware_family_host_distribution": observed_families if correlation_coverage_complete else None,
            "pipeline_schema_distribution": [
                {"pipeline_version": k[0], "analysis_schema_version": k[1], "host_count": v}
                for k, v in sorted(versions.items())
            ],
            "shared_entity_interpretation": (
                "Host prevalence/commonality only. A high host_count does not by itself establish maliciousness, campaign impact, compromise, or causal significance."
            ),
            "observed_shared_high_signal_entities": observed_shared,
            "observed_single_host_high_signal_entities": observed_rare,
            "shared_high_signal_entities": observed_shared if correlation_coverage_complete else None,
            "single_host_high_signal_entities": observed_rare if correlation_coverage_complete else None,
            "observed_hosts": host_rows[:200],
            "hosts": host_rows[:200] if correlation_coverage_complete else None,
            "note": (
                "Correlation coverage is incomplete; case-wide suspicion/family counts and shared-entity conclusions are intentionally null. Observed values describe only searched hosts."
                if not correlation_coverage_complete
                else "Case-wide host-level counts are based on correlation artifacts. Evidence search/timeline uses the separate normalized chat Evidence Index."
            ),
        }
        if record_ledger:
            self._record_ledger(action="summary", query="", scope=scope,
                                matched_job_ids=correlation_searchable, result=result)
        return result

    def timeline(self, query: str, limit: int = 40) -> dict:
        model_query = str(query or "").strip()
        if not model_query:
            return {"error": "timeline actionでは query は必須です", "action": "timeline"}
        query, query_grounding = _ground_search_query(model_query, self.current_user_message)
        try:
            limit = max(1, min(int(limit or 40), 100))
        except (TypeError, ValueError):
            limit = 40
        scope_ids, scope = self._scope()
        deadline = time.monotonic() + DEFAULT_TIMEOUT_SEC

        # rc9: a concrete file/path timeline may have useful raw Directory
        # filesystem metadata even when the rendered report timeline has no row.
        # This timestamp is explicitly typed as filesystem metadata and never
        # promoted to execution/infection time or causality.
        if _is_directory_query(query) and self.job_id in scope_ids:
            root, _ = _safe_job_root(self.jobs_dir, self.job_id)
            if root is not None:
                try:
                    state = _directory_source_state(root, self.jobs_snapshot.get(self.job_id, {}), deadline)
                except InvestigationDeadlineExceeded:
                    state = {"reason": "directory_search_timeout"}
                if state.get("reason") == "supported":
                    parsed = state.get("parsed_path")
                    dq = _normalize_directory_query(query)
                    try:
                        idx = directory_index.current_index_path(parsed)
                        if idx is not None:
                            raw = directory_index.search_keyword(idx, dq, max_results=limit)
                            raw["complete"] = True
                        else:
                            raw = directory_index.search_keyword_streaming(
                                parsed, dq, max_results=limit, deadline_monotonic=deadline,
                                max_bytes_scanned=DIRECTORY_STREAM_MAX_BYTES)
                    except InvestigationDeadlineExceeded:
                        raw = {"total": 0, "hits": [], "complete": False,
                               "stop_reason": "directory_search_timeout"}
                    except Exception:
                        raw = {"total": 0, "hits": [], "complete": False,
                               "stop_reason": "directory_search_error"}
                    dated = [e for e in (raw.get("hits") or []) if str(e.get("date") or "").strip()]
                    if dated:
                        hostname = str(state.get("hostname") or "")
                        hits = [{
                            "job_id": self.job_id,
                            "hostname": hostname,
                            "source_file": Path(parsed).name if parsed else "",
                            "matched_line": str(e.get("path") or e.get("name") or ""),
                            "context_lines": [],
                            "timestamp_raw": str(e.get("date") or ""),
                            "timestamp_kind": "filesystem_metadata",
                            "source_field": "directory.date",
                            "size": e.get("size", ""),
                            "relation_type": "filesystem_metadata_observation",
                            "causal": False,
                            "warning": "Directory date is filesystem metadata; it does not establish execution, infection, or causality.",
                        } for e in dated[:limit]]
                        scope_host_count = int(scope.get("scope_host_count", len(scope_ids)))
                        complete = bool(raw.get("complete", True)) and scope_host_count == 1 and not bool(scope.get("scope_truncated"))
                        unavailable = {} if complete else {"timeline_directory_not_searched_other_hosts": max(0, scope_host_count - 1)}
                        result = {
                            "action": "timeline",
                            "query": query,
                            "model_query": model_query,
                            "query_grounding": query_grounding,
                            "timeline_basis": "current_host_directory_fast_path",
                            "scope": scope,
                            "hits": hits,
                            "returned_count": len(hits),
                            "truncated": bool(raw.get("truncated")) or int(raw.get("total", 0) or 0) > len(hits),
                            "observed_host_count": 1,
                            "searchable_host_count": 1 if bool(raw.get("complete", True)) else 0,
                            "case_host_count": scope.get("case_host_count", scope_host_count),
                            "scope_host_count": scope_host_count,
                            "scope_truncated": bool(scope.get("scope_truncated")),
                            "case_coverage_complete": complete,
                            "unavailable_host_count": max(0, scope_host_count - (1 if bool(raw.get("complete", True)) else 0)),
                            "unavailable_reasons": unavailable,
                            "coverage_complete": complete,
                            "causal": False,
                            "note": "Filesystem metadata timestamp only; not execution/infection time. Other-host timeline coverage was not fabricated.",
                        }
                        self._record_ledger(action="timeline", query=query, scope=scope,
                                            matched_job_ids=[self.job_id], result=result)
                        return result

        needle = query.casefold()
        hits = []
        searched = 0
        unavailable: Counter[str] = Counter()
        matched_jobs = set()
        for jid in scope_ids:
            if time.monotonic() >= deadline:
                unavailable["timeout_not_searched"] += 1
                continue
            root, reason = _safe_job_root(self.jobs_dir, jid)
            if root is None:
                unavailable[reason] += 1
                continue
            try:
                idx, state = _build_index(root, jid, self.jobs_snapshot.get(jid, {}), deadline)
            except InvestigationDeadlineExceeded:
                unavailable["timeout_not_searched"] += 1
                continue
            except Exception:
                unavailable["index_build_error"] += 1
                continue
            if idx is None:
                unavailable[state.get("reason", "index_unavailable")] += 1
                continue
            timeline = _select_timeline(root)
            if timeline is None:
                unavailable["timeline_missing"] += 1
                continue
            searched += 1
            try:
                lines = timeline.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                unavailable["timeline_read_error"] += 1
                continue
            hostname = str(state.get("hostname") or "")
            for pos, line in enumerate(lines):
                if needle not in line.casefold():
                    continue
                matched_jobs.add(jid)
                lo, hi = max(0, pos - 2), min(len(lines), pos + 3)
                hits.append({
                    "job_id": jid,
                    "hostname": hostname,
                    "source_file": timeline.name,
                    "matched_line": line,
                    "context_lines": lines[lo:hi],
                    "relation_type": "temporal_context_only",
                    "causal": False,
                    "warning": "Temporal proximity does not establish causality; timestamp semantics are source-specific.",
                })
                if len(hits) >= limit:
                    break
            if len(hits) >= limit:
                break
        result = {
            "action": "timeline",
            "query": query,
            "model_query": model_query,
            "query_grounding": query_grounding,
            "scope": scope,
            "hits": hits,
            "returned_count": len(hits),
            "truncated": len(hits) >= limit,
            "observed_host_count": len(matched_jobs),
            "searchable_host_count": searched,
            "case_host_count": scope.get("case_host_count", len(scope_ids)),
            "scope_host_count": scope.get("scope_host_count", len(scope_ids)),
            "scope_truncated": bool(scope.get("scope_truncated")),
            "case_coverage_complete": bool(scope.get("case_coverage_complete")) and searched == len(scope_ids),
            "unavailable_host_count": max(0, len(scope_ids) - searched),
            "unavailable_reasons": dict(unavailable),
            "coverage_complete": searched == len(scope_ids) and not bool(scope.get("scope_truncated")),
            "causal": False,
        }
        self._record_ledger(action="timeline", query=query, scope=scope,
                            matched_job_ids=sorted(matched_jobs), result=result)
        return result

    def run(self, action: str, query: str = "", limit: int = DEFAULT_LIMIT) -> dict:
        action = str(action or "").strip().lower()
        if action == "search":
            return self.search(query, limit)
        if action == "summary":
            return self.summary(limit)
        if action == "timeline":
            return self.timeline(query, limit)
        return {"error": "action は search / summary / timeline のいずれかです", "action": action}
