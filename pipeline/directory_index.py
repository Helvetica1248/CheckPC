#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Low-memory searchable index for parsed directory evidence.

The parsed JSON can exceed hundreds of MiB. Chat queries must not deserialize
that document into the long-lived server process. This module builds a compact
SQLite index either from an already-loaded directory list (analysis path) or by
streaming only the ``sections.directory`` JSON array (legacy-job fallback).

v3.70 schema v2 stores each text field once and uses SQLite ``NOCASE`` indexes.
Windows paths are case-insensitive; SQLite covers ASCII case folding while CJK
characters are unaffected by case. This avoids the v1 index's duplicate
case-folded columns and substantially reduces per-job disk use.
"""
from __future__ import annotations

import json
import time
import os
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Iterable, Iterator

INDEX_SCHEMA_VERSION = "2"
INDEX_FILENAME = ".checkpc_directory_index_v2.sqlite3"
_DIRECTORY_ARRAY_RE = re.compile(r'"directory"\s*:\s*\[')


def _text(value: object) -> str:
    return str(value or "").strip()


def _row(entry: dict) -> tuple[str, ...]:
    return (
        str(entry.get("date") or ""),
        str(entry.get("size") or ""),
        str(entry.get("name") or ""),
        str(entry.get("path") or ""),
        str(entry.get("dir") or ""),
        str(entry.get("source_id") or ""),
    )


def iter_directory_entries(parsed_path: str | os.PathLike[str], *, chunk_size: int = 1 << 20) -> Iterator[dict]:
    """Stream objects from the top-level ``sections.directory`` array."""
    decoder = json.JSONDecoder()
    buffer = ""
    found = False
    eof = False
    with open(parsed_path, "r", encoding="utf-8") as fh:
        while True:
            if not eof and (not found or len(buffer) < chunk_size // 2):
                chunk = fh.read(chunk_size)
                if chunk:
                    buffer += chunk
                else:
                    eof = True

            if not found:
                match = _DIRECTORY_ARRAY_RE.search(buffer)
                if match is None:
                    if eof:
                        raise ValueError("sections.directory array not found")
                    buffer = buffer[-128:]
                    continue
                buffer = buffer[match.end():]
                found = True

            progressed = False
            while found:
                stripped = buffer.lstrip()
                if not stripped:
                    buffer = ""
                    break
                if stripped[0] == "]":
                    return
                if stripped[0] == ",":
                    buffer = stripped[1:]
                    progressed = True
                    continue
                try:
                    value, end = decoder.raw_decode(stripped)
                except json.JSONDecodeError:
                    break
                if isinstance(value, dict):
                    yield value
                buffer = stripped[end:]
                progressed = True

            if eof:
                if buffer.strip() and not buffer.lstrip().startswith("]"):
                    raise ValueError("truncated sections.directory array")
                return
            if not progressed:
                chunk = fh.read(chunk_size)
                if chunk:
                    buffer += chunk
                else:
                    eof = True


def index_path_for(parsed_path: str | os.PathLike[str]) -> Path:
    return Path(parsed_path).resolve().parent / INDEX_FILENAME


def _source_identity(parsed_path: Path) -> dict[str, str]:
    stat = parsed_path.stat()
    return {
        "schema_version": INDEX_SCHEMA_VERSION,
        "source_path": str(parsed_path.resolve()),
        "source_size": str(stat.st_size),
        "source_mtime_ns": str(stat.st_mtime_ns),
    }


def _index_is_current(index_path: Path, parsed_path: Path) -> bool:
    if not index_path.is_file():
        return False
    try:
        with sqlite3.connect(index_path) as con:
            meta = dict(con.execute("SELECT key, value FROM meta"))
        expected = _source_identity(parsed_path)
        return all(meta.get(k) == v for k, v in expected.items())
    except (sqlite3.Error, OSError, ValueError):
        return False


def current_index_path(parsed_path: str | os.PathLike[str]) -> Path | None:
    """Return a current existing directory index without building one.

    Case-wide chat searches use this to avoid synchronously indexing every large
    legacy parsed artifact.  Callers can explicitly invoke build_directory_index
    for the current job when raw directory evidence is needed.
    """
    parsed = Path(parsed_path).resolve()
    target = index_path_for(parsed)
    return target if _index_is_current(target, parsed) else None


def build_directory_index(parsed_path: str | os.PathLike[str], *,
                          entries: Iterable[dict] | None = None,
                          force: bool = False) -> Path:
    parsed = Path(parsed_path).resolve()
    target = index_path_for(parsed)
    if not force and _index_is_current(target, parsed):
        return target

    fd, temp_name = tempfile.mkstemp(prefix=target.name + ".", suffix=".tmp", dir=target.parent)
    os.close(fd)
    temp = Path(temp_name)
    count = 0
    try:
        with sqlite3.connect(temp) as con:
            con.execute("PRAGMA journal_mode=OFF")
            con.execute("PRAGMA synchronous=OFF")
            con.execute("PRAGMA temp_store=MEMORY")
            con.executescript("""
                CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE directory_entries (
                    id INTEGER PRIMARY KEY,
                    date TEXT NOT NULL,
                    size TEXT NOT NULL,
                    name TEXT NOT NULL,
                    path TEXT NOT NULL,
                    dir TEXT NOT NULL,
                    source_id TEXT NOT NULL
                );
            """)
            source = entries if entries is not None else iter_directory_entries(parsed)
            batch: list[tuple[str, ...]] = []
            for entry in source:
                if not isinstance(entry, dict):
                    continue
                batch.append(_row(entry))
                if len(batch) >= 5000:
                    con.executemany("""
                        INSERT INTO directory_entries
                        (date,size,name,path,dir,source_id) VALUES (?,?,?,?,?,?)
                    """, batch)
                    count += len(batch)
                    batch.clear()
            if batch:
                con.executemany("""
                    INSERT INTO directory_entries
                    (date,size,name,path,dir,source_id) VALUES (?,?,?,?,?,?)
                """, batch)
                count += len(batch)
            con.executescript("""
                CREATE INDEX idx_directory_name_nocase ON directory_entries(name COLLATE NOCASE);
                CREATE INDEX idx_directory_dir_nocase ON directory_entries(dir COLLATE NOCASE);
                CREATE INDEX idx_directory_path_nocase ON directory_entries(path COLLATE NOCASE);
            """)
            meta = _source_identity(parsed)
            meta["entry_count"] = str(count)
            con.executemany("INSERT INTO meta(key,value) VALUES (?,?)", sorted(meta.items()))
            con.commit()
        os.replace(temp, target)
        return target
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _dict_rows(rows) -> list[dict]:
    keys = ("date", "size", "name", "path", "dir", "source_id")
    return [dict(zip(keys, row)) for row in rows]


def search_keyword(index_path: str | os.PathLike[str], keyword: str,
                   *, max_results: int = 200) -> dict:
    needle = _text(keyword)
    if not needle:
        return {"total": 0, "hits": [], "truncated": False}
    limit = max(1, min(int(max_results or 200), 500))
    cols = "date,size,name,path,dir,source_id"
    with sqlite3.connect(index_path) as con:
        # Always evaluate the full substring scope.  The former exact-name fast
        # path silently suppressed partial matches whenever even one exact file
        # name existed (for example, a file literally named ``a`` made a broad
        # search for ``a`` report only that one row with truncated=False).
        exact_total = con.execute(
            "SELECT COUNT(*) FROM directory_entries WHERE name=? COLLATE NOCASE",
            (needle,),
        ).fetchone()[0]
        pat = "%" + _escape_like(needle) + "%"
        where = "(name LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\' OR dir LIKE ? ESCAPE '\\' OR source_id LIKE ? ESCAPE '\\')"
        args = (pat, pat, pat, pat)
        total = con.execute(f"SELECT COUNT(*) FROM directory_entries WHERE {where}", args).fetchone()[0]
        exact_rows = con.execute(
            f"SELECT {cols} FROM directory_entries WHERE name=? COLLATE NOCASE "
            "ORDER BY path COLLATE NOCASE LIMIT ?",
            (needle, limit),
        ).fetchall() if exact_total else []
        remaining = max(0, limit - len(exact_rows))
        partial_rows = []
        if remaining:
            partial_rows = con.execute(
                f"SELECT {cols} FROM directory_entries WHERE {where} "
                "AND name<>? COLLATE NOCASE "
                "ORDER BY path COLLATE NOCASE LIMIT ?",
                args + (needle, remaining),
            ).fetchall()
        rows = exact_rows + partial_rows
    return {
        "total": total,
        "exact_total": exact_total,
        "match_mode": "substring_with_exact_priority",
        "hits": _dict_rows(rows),
        "truncated": total > limit,
    }


def list_folder(index_path: str | os.PathLike[str], folder_path: str,
                *, max_results: int = 200) -> dict:
    folder = _text(folder_path).rstrip("\\")
    if not folder:
        return {"total": 0, "hits": [], "truncated": False}
    limit = max(1, min(int(max_results or 200), 500))
    prefix = _escape_like(folder + "\\") + "%"
    cols = "date,size,name,path,dir,source_id"
    where = "(dir=? COLLATE NOCASE OR dir LIKE ? ESCAPE '\\')"
    with sqlite3.connect(index_path) as con:
        total = con.execute(f"SELECT COUNT(*) FROM directory_entries WHERE {where}", (folder, prefix)).fetchone()[0]
        rows = con.execute(
            f"SELECT {cols} FROM directory_entries WHERE {where} "
            "ORDER BY dir COLLATE NOCASE,path COLLATE NOCASE LIMIT ?",
            (folder, prefix, limit),
        ).fetchall()
    return {"total": total, "hits": _dict_rows(rows), "truncated": total > limit}


def search_keyword_streaming(parsed_path: str | os.PathLike[str], keyword: str,
                             *, max_results: int = 200,
                             deadline_monotonic: float | None = None,
                             max_bytes_scanned: int | None = None) -> dict:
    """Bounded one-shot keyword search for a legacy parsed directory without an index.

    The scanner preserves the v3.69 pretty-printed format contract but now supports
    an absolute monotonic deadline and byte budget. Partial scans are explicitly
    marked incomplete so callers cannot use them as an absence/prevalence denominator.
    """
    parsed = Path(parsed_path).resolve()
    needle = _text(keyword).casefold()
    if not needle:
        return {"total": 0, "hits": [], "truncated": False, "mode": "streaming", "complete": True}
    try:
        limit = max(1, min(int(max_results or 200), 500))
    except (TypeError, ValueError):
        limit = 200
    try:
        byte_budget = None if max_bytes_scanned is None else max(1, int(max_bytes_scanned))
    except (TypeError, ValueError):
        byte_budget = None

    in_directory = False
    in_entry = False
    entry_lines: list[str] = []
    total = 0
    hits: list[dict] = []
    bytes_scanned = 0
    complete = True
    stop_reason = ""

    with parsed.open("r", encoding="utf-8", errors="strict") as fh:
        for line in fh:
            bytes_scanned += len(line.encode("utf-8"))
            if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                complete = False
                stop_reason = "directory_search_timeout"
                break
            if byte_budget is not None and bytes_scanned > byte_budget:
                complete = False
                stop_reason = "directory_scan_budget_exceeded"
                break
            if not in_directory:
                if line.startswith('    "directory": ['):
                    in_directory = True
                continue
            if not in_entry:
                if line.startswith("    ]"):
                    break
                if line.startswith("      {"):
                    in_entry = True
                    entry_lines = [line]
                continue

            entry_lines.append(line)
            if line.startswith("      },") or line.startswith("      }"):
                text = "".join(entry_lines)
                if needle in text.casefold():
                    total += 1
                    if len(hits) < limit:
                        try:
                            value = json.loads(text.strip().rstrip(","))
                        except json.JSONDecodeError:
                            value = None
                        if isinstance(value, dict):
                            hits.append(value)
                in_entry = False
                entry_lines = []

    return {
        "total": total,
        "hits": hits,
        "truncated": (total > len(hits)) or not complete,
        "mode": "streaming",
        "complete": complete,
        "stop_reason": stop_reason,
        "bytes_scanned": bytes_scanned,
    }
