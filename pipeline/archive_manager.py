#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bounded background archive builder for CheckPC job artifacts (v3.69-rc26).

The HTTP layer only enqueues work and polls state.  All filesystem traversal,
source fingerprinting, compression and archive hashing run on one dedicated
worker thread so the FastAPI event loop is never used for ZIP construction.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import shutil
import stat
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from atomic_io import atomic_write_json, load_json_with_recovery
from path_safety import is_within, resolved
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION
from budget_profile import active_profile
from pipeline_errors import PipelineError
from runtime_identity import (
    assert_runtime_identity, assert_artifact_identity, artifact_identity,
    normalize_analysis_mode,
)

ARCHIVE_KINDS = {"validation", "full"}
COMPRESSION_PROFILES = {"auto", "normal", "fast", "store"}
TERMINAL_JOB_STATES = {"done", "error", "cancelled"}
ACTIVE_ARCHIVE_STATES = {"queued", "building"}


class ArchiveRequestError(RuntimeError):
    def __init__(self, status_code: int, error_kind: str, message: str):
        super().__init__(message)
        self.status_code = int(status_code)
        self.error_kind = str(error_kind)
        self.message = str(message)


@dataclass(frozen=True)
class SourceFile:
    path: Path
    arcname: str
    size: int
    mtime_ns: int
    st_dev: int
    st_ino: int

    def snapshot_line(self) -> bytes:
        return (
            f"{self.arcname}\0{self.size}\0{self.mtime_ns}\0"
            f"{self.st_dev}\0{self.st_ino}\n"
        ).encode("utf-8")


class ArchiveManager:
    """Single-worker archive queue with per-job/kind deduplication."""

    def __init__(self, jobs_dir: str | os.PathLike[str], *, queue_max: int = 16,
                 timeout_sec: float = 3600.0, large_threshold_mb: int = 2048):
        assert_runtime_identity()
        self.jobs_dir = Path(jobs_dir).resolve(strict=False)
        self.queue_max = max(1, int(queue_max))
        self.timeout_sec = max(1.0, float(timeout_sec))
        self.large_threshold_bytes = max(1, int(large_threshold_mb)) * 1024 * 1024
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=self.queue_max)
        self._lock = threading.RLock()
        self._states: dict[tuple[str, str], dict[str, Any]] = {}
        self._stop = threading.Event()
        self._recover_states()
        self._worker = threading.Thread(
            target=self._worker_main, name="checkpc-archive-worker", daemon=True)
        self._worker.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def request(self, job: dict[str, Any], kind: str, compression: str) -> dict[str, Any]:
        kind = str(kind or "")
        compression = str(compression or "")
        if kind not in ARCHIVE_KINDS:
            raise ArchiveRequestError(400, "invalid_archive_kind", "kind must be validation or full")
        if compression not in COMPRESSION_PROFILES:
            raise ArchiveRequestError(
                400, "invalid_compression_profile",
                "compression must be auto, normal, fast or store")
        job_id = str(job.get("job_id") or "")
        job_status = str(job.get("status") or "")
        if job_status not in TERMINAL_JOB_STATES:
            raise ArchiveRequestError(
                409, "job_not_terminal",
                f"archive requires terminal job status; current={job_status}")
        output_dir = str(job.get("output_dir") or "")
        if not output_dir:
            raise ArchiveRequestError(409, "archive_source_missing", "job output_dir is not available")

        key = (job_id, kind)
        with self._lock:
            # A job may queue/build only one archive kind at a time.  This avoids
            # duplicate full-directory traversal and keeps GUI semantics simple.
            for (other_job, other_kind), state in self._states.items():
                if other_job != job_id or state.get("status") not in ACTIVE_ARCHIVE_STATES:
                    continue
                if other_kind == kind and state.get("requested_compression") == compression:
                    out = dict(state)
                    out["deduplicated"] = True
                    return out
                raise ArchiveRequestError(
                    409, "archive_job_busy",
                    f"archive already queued/building for job={job_id} kind={other_kind}")

            existing = self._states.get(key)
            if existing and existing.get("status") == "ready":
                prev = str(existing.get("requested_compression") or "")
                if prev and prev != compression:
                    raise ArchiveRequestError(
                        409, "archive_profile_conflict",
                        f"ready archive uses compression={prev}; requested={compression}")

            state = self._new_state(job, kind, compression)
            self._states[key] = state
            self._persist_state(state)
            try:
                self._queue.put_nowait({
                    "job": self._job_snapshot(job),
                    "kind": kind,
                    "compression": compression,
                })
            except queue.Full:
                self._states.pop(key, None)
                try:
                    self._state_path(job_id, kind).unlink(missing_ok=True)
                except OSError:
                    pass
                raise ArchiveRequestError(429, "archive_queue_full", "archive queue is full")
            return dict(state)

    def status(self, job_id: str, kind: str) -> dict[str, Any]:
        if kind not in ARCHIVE_KINDS:
            raise ArchiveRequestError(400, "invalid_archive_kind", "kind must be validation or full")
        key = (str(job_id), kind)
        with self._lock:
            state = self._states.get(key)
            if not state:
                return {
                    "job_id": str(job_id), "kind": kind, "status": "none",
                    "queued_at": None, "started_at": None, "finished_at": None,
                    "files_total": 0, "files_completed": 0,
                    "bytes_total": 0, "bytes_processed": 0,
                    "error_kind": None, "error_message": None,
                }
            return dict(state)

    def is_job_active(self, job_id: str) -> bool:
        with self._lock:
            return any(jid == job_id and s.get("status") in ACTIVE_ARCHIVE_STATES
                       for (jid, _), s in self._states.items())

    def forget_job(self, job_id: str) -> None:
        if self.is_job_active(job_id):
            raise ArchiveRequestError(409, "archive_job_busy", "archive is queued or building")
        with self._lock:
            for key in [k for k in self._states if k[0] == job_id]:
                self._states.pop(key, None)

    def shutdown(self, timeout: float = 1.0) -> None:
        """Stop the daemon worker for controlled module reloads and tests."""
        self._stop.set()
        worker = getattr(self, "_worker", None)
        if worker is not None and worker.is_alive() and worker is not threading.current_thread():
            worker.join(timeout=max(0.0, float(timeout)))

    def open_ready(self, job_id: str, kind: str):
        state = self.status(job_id, kind)
        if state.get("status") == "none":
            raise ArchiveRequestError(404, "archive_not_requested", "archive has not been requested")
        if state.get("status") != "ready":
            raise ArchiveRequestError(
                409, "archive_not_ready", f"archive status={state.get('status')}")
        archive_path = Path(str(state.get("archive_path") or ""))
        archive_root = self._archive_root(job_id)
        if not archive_path or not is_within(archive_path, archive_root):
            raise ArchiveRequestError(404, "archive_missing", "archive path is invalid")
        try:
            fd = os.open(str(archive_path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc:
            raise ArchiveRequestError(404, "archive_missing", str(exc)) from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or not self._archive_stat_matches(state, st):
                raise ArchiveRequestError(409, "archive_changed", "archive file no longer matches metadata")
            return os.fdopen(fd, "rb", closefd=True), archive_path.name, int(st.st_size)
        except Exception:
            os.close(fd)
            raise

    # ------------------------------------------------------------------
    # Worker and state lifecycle
    # ------------------------------------------------------------------
    def _worker_main(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._process(item)
            finally:
                self._queue.task_done()

    def _process(self, item: dict[str, Any]) -> None:
        job = item["job"]
        job_id = job["job_id"]
        kind = item["kind"]
        key = (job_id, kind)
        with self._lock:
            state = self._states.get(key)
            if not state:
                return
            state.update({
                "status": "building", "started_at": time.time(),
                "error_kind": None, "error_message": None,
            })
            self._persist_state(state)

        tmp_path: Path | None = None
        try:
            archive_root = self._archive_root(job_id)
            output_root = Path(job["output_dir"]).resolve(strict=False)
            # Reject invalid root relationships before any potentially large walk.
            self._validate_roots(archive_root, output_root)
            sources = self._collect_sources(job, kind)
            if kind == "full" and not sources:
                raise ArchiveRequestError(409, "archive_source_empty", "output directory has no regular files")
            if kind == "validation" and not sources:
                raise ArchiveRequestError(409, "archive_source_empty", "validation archive has no eligible files")
            analysis_mode = self._validate_source_identity(sources, job)
            total_bytes = sum(x.size for x in sources)
            source_snapshot = self._source_snapshot(sources)
            effective = self._effective_compression(kind, item["compression"], total_bytes)
            archive_root.mkdir(parents=True, exist_ok=True)
            archive_filename = self._archive_filename(kind, analysis_mode)
            final_path = archive_root / archive_filename
            metadata_path = archive_root / f"{kind}.metadata.json"

            with self._lock:
                state = self._states[key]
                state.update({
                    "files_total": len(sources), "files_completed": 0,
                    "bytes_total": total_bytes, "bytes_processed": 0,
                    "source_snapshot": source_snapshot,
                    "effective_compression": effective,
                    "provenance_recoverable": kind == "full",
                    "analysis_mode": analysis_mode,
                    "archive_filename": archive_filename,
                })
                self._persist_state(state)

            # Fast reuse: source and archive metadata must still match.  No ZIP
            # content read or testzip() is performed on this hot path.
            prior = load_json_with_recovery(metadata_path, {})
            if self._can_reuse(
                    prior, final_path, source_snapshot, item["compression"], effective,
                    analysis_mode):
                st = final_path.stat()
                with self._lock:
                    state = self._states[key]
                    state.update({
                        "status": "ready", "reused": True,
                        "archive_path": str(final_path), "size_bytes": st.st_size,
                        "archive_size": st.st_size, "archive_mtime_ns": st.st_mtime_ns,
                        "archive_st_dev": st.st_dev, "archive_st_ino": st.st_ino,
                        "archive_sha256": prior.get("archive_sha256"),
                        "finished_at": time.time(),
                        "files_completed": len(sources), "bytes_processed": total_bytes,
                    })
                    self._persist_state(state)
                return

            self._check_disk_space(archive_root, total_bytes)
            deadline = time.monotonic() + self.timeout_sec
            tmp_path = archive_root / f".{kind}.{uuid.uuid4().hex}.tmp"
            manifest = self._build_zip(
                tmp_path, sources, job, kind, item["compression"], effective,
                source_snapshot, analysis_mode, key, deadline)
            # Re-open central directory and compare entry names only.  This is
            # bounded metadata I/O, not a full CRC/decompression pass.
            self._ensure_deadline(deadline, "central_directory")
            with zipfile.ZipFile(tmp_path, "r") as zf:
                names = zf.namelist()
                expected = [x.arcname for x in sources] + ["archive_manifest.json"]
                if names != expected:
                    raise RuntimeError("archive central directory does not match source manifest")
            self._ensure_deadline(deadline, "central_directory")

            archive_sha256 = self._hash_file(tmp_path, deadline)
            self._ensure_deadline(deadline, "fsync")
            self._fsync_path(tmp_path)
            self._ensure_deadline(deadline, "replace")
            os.replace(tmp_path, final_path)
            tmp_path = None
            self._fsync_dir(archive_root)
            self._ensure_deadline(deadline, "directory_fsync")
            st = final_path.stat()
            metadata = {
                "job_id": job_id, "kind": kind,
                "requested_compression": item["compression"],
                "effective_compression": effective,
                "source_snapshot": source_snapshot,
                "snapshot_basis": "stat(relative_path,size,mtime_ns,st_dev,st_ino)",
                "archive_path": str(final_path),
                "archive_size": st.st_size, "archive_mtime_ns": st.st_mtime_ns,
                "archive_st_dev": st.st_dev, "archive_st_ino": st.st_ino,
                "archive_sha256": archive_sha256,
                "analysis_mode": analysis_mode,
                "archive_filename": archive_filename,
                "created_at": time.time(),
                "source_files": manifest["source_files"],
            }
            atomic_write_json(metadata_path, metadata)
            with self._lock:
                state = self._states[key]
                state.update({
                    "status": "ready", "reused": False,
                    "archive_path": str(final_path), "size_bytes": st.st_size,
                    "archive_size": st.st_size, "archive_mtime_ns": st.st_mtime_ns,
                    "archive_st_dev": st.st_dev, "archive_st_ino": st.st_ino,
                    "archive_sha256": archive_sha256,
                    "finished_at": time.time(),
                    "files_completed": len(sources), "bytes_processed": total_bytes,
                })
                self._persist_state(state)
        except ArchiveRequestError as exc:
            self._fail_state(key, exc.error_kind, exc.message)
        except Exception as exc:
            self._fail_state(key, "archive_build_failed", f"{type(exc).__name__}: {exc}")
        finally:
            if tmp_path is not None:
                try:
                    tmp_path.unlink(missing_ok=True)
                except OSError:
                    pass

    def _fail_state(self, key: tuple[str, str], error_kind: str, message: str) -> None:
        with self._lock:
            state = self._states.get(key)
            if not state:
                return
            state.update({
                "status": "error", "finished_at": time.time(),
                "error_kind": str(error_kind), "error_message": str(message)[:1000],
            })
            self._persist_state(state)

    # ------------------------------------------------------------------
    # Source enumeration and ZIP writing
    # ------------------------------------------------------------------
    def _collect_sources(self, job: dict[str, Any], kind: str) -> list[SourceFile]:
        job_id = job["job_id"]
        job_root = (self.jobs_dir / job_id).resolve(strict=False)
        output_root = Path(job["output_dir"]).resolve(strict=False)
        if not is_within(output_root, job_root):
            raise ArchiveRequestError(409, "archive_root_invalid", "output_dir escapes job root")
        out: list[SourceFile] = []
        if kind == "full":
            out.extend(self._walk_regular(output_root, "output"))
        else:
            allowed = self._validation_name_allowed
            for src in self._walk_regular(output_root, "output"):
                if allowed(Path(src.arcname).name):
                    out.append(src)
            self._add_direct_file(out, job_root / "job.log.jsonl", "job.log.jsonl", job_root)
            self._add_direct_file(out, job_root / "chat_tool_log.jsonl", "chat_tool_log.jsonl", job_root)
            fallback_root = (self.jobs_dir / "_audit_fallback" / job_id).resolve(strict=False)
            self._add_direct_file(
                out, fallback_root / "chat_tool_log.jsonl",
                "_audit_fallback/chat_tool_log.jsonl", fallback_root)
        out.sort(key=lambda x: x.arcname)
        return out

    @staticmethod
    def _validation_name_allowed(name: str) -> bool:
        return (
            (name.startswith("analyzed_") and name.endswith(".json"))
            or name == "ingest_manifest.json"
            or (name.startswith("correlation_") and name.endswith(".json"))
            or (name.startswith("report_") and name.endswith(".md"))
        )

    def _walk_regular(self, root: Path, arc_prefix: str) -> Iterable[SourceFile]:
        if not root.exists():
            return []
        items: list[SourceFile] = []
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            base = Path(dirpath)
            kept_dirs = []
            for name in sorted(dirnames):
                p = base / name
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                    kept_dirs.append(name)
            dirnames[:] = kept_dirs
            for name in sorted(filenames):
                p = base / name
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                    continue
                if not is_within(p, root):
                    continue
                rel = p.relative_to(root).as_posix()
                arcname = f"{arc_prefix}/{rel}" if arc_prefix else rel
                items.append(SourceFile(
                    p, arcname, st.st_size, st.st_mtime_ns, st.st_dev, st.st_ino))
        return items

    def _add_direct_file(self, out: list[SourceFile], path: Path, arcname: str, root: Path) -> None:
        try:
            st = os.lstat(path)
        except OSError:
            return
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
            return
        if not is_within(path, root):
            return
        out.append(SourceFile(path, arcname, st.st_size, st.st_mtime_ns, st.st_dev, st.st_ino))

    def _build_zip(self, tmp_path: Path, sources: list[SourceFile], job: dict[str, Any],
                   kind: str, requested: str, effective: str, source_snapshot: str,
                   analysis_mode: str, key: tuple[str, str], deadline: float) -> dict[str, Any]:
        if effective == "store":
            compression = zipfile.ZIP_STORED
            compresslevel = None
        else:
            compression = zipfile.ZIP_DEFLATED
            compresslevel = 1 if effective == "fast" else 6
        manifest_files: list[dict[str, Any]] = []
        kwargs: dict[str, Any] = {
            "mode": "w", "compression": compression, "allowZip64": True,
        }
        if compresslevel is not None:
            kwargs["compresslevel"] = compresslevel
        with zipfile.ZipFile(tmp_path, **kwargs) as zf:
            for index, source in enumerate(sources, 1):
                if time.monotonic() > deadline:
                    raise ArchiveRequestError(408, "archive_build_timeout", "archive build exceeded timeout")
                file_hash = self._copy_source(
                    zf, source, compression, compresslevel, deadline, key)
                manifest_files.append({
                    "path": source.arcname, "size": source.size,
                    "mtime_ns": source.mtime_ns, "st_dev": source.st_dev,
                    "st_ino": source.st_ino, "sha256": file_hash,
                    "artifact_type": self._artifact_type(source.arcname),
                })
                with self._lock:
                    state = self._states[key]
                    state["files_completed"] = index
                    self._persist_state(state)
            manifest = {
                "manifest_version": 1,
                "pipeline_version": PIPELINE_VERSION,
                "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
                "analysis_mode": analysis_mode,
                "budget_profile": active_profile().to_dict(),
                "job_id": job["job_id"], "job_status": job.get("status"),
                "snapshot_consistency": (
                    "complete" if job.get("status") == "done" else "terminal_partial"),
                "archive_kind": kind,
                "archive_scope": (
                    "routine_comparison" if kind == "validation" else "all_output_artifacts"),
                "requested_compression": requested,
                "effective_compression": effective,
                "source_snapshot": source_snapshot,
                "snapshot_basis": "stat(relative_path,size,mtime_ns,st_dev,st_ino)",
                "provenance_recoverable": kind == "full",
                "deferred_provenance_requires": (
                    [] if kind == "full" else ["parsed_*.json", "full archive"]),
                "created_at": time.time(),
                "source_files": manifest_files,
            }
            payload = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
            zf.writestr("archive_manifest.json", payload, compress_type=compression,
                        compresslevel=compresslevel)
        return manifest

    def _copy_source(self, zf: zipfile.ZipFile, source: SourceFile, compression: int,
                     compresslevel: int | None, deadline: float,
                     key: tuple[str, str]) -> str:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(source.path), flags)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode)
                    or st.st_dev != source.st_dev or st.st_ino != source.st_ino
                    or st.st_size != source.size or st.st_mtime_ns != source.mtime_ns):
                raise ArchiveRequestError(409, "archive_source_changed", source.arcname)
            zi = zipfile.ZipInfo(source.arcname)
            zi.compress_type = compression
            # ZipFile.open(ZipInfo, "w") reads the level from ZipInfo rather
            # than the ZipFile constructor.  Set it explicitly so the fast
            # profile is truly DEFLATE level 1 for streamed source files.
            zi._compresslevel = compresslevel
            zi.external_attr = (0o100600 & 0xFFFF) << 16
            zi.flag_bits |= 0x800  # UTF-8 filename flag for non-ASCII portability.
            digest = hashlib.sha256()
            copied = 0
            with zf.open(zi, "w", force_zip64=True) as dst:
                while True:
                    if time.monotonic() > deadline:
                        raise ArchiveRequestError(408, "archive_build_timeout", "archive build exceeded timeout")
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    dst.write(chunk)
                    digest.update(chunk)
                    copied += len(chunk)
                    with self._lock:
                        state = self._states[key]
                        state["bytes_processed"] = int(state.get("bytes_processed", 0)) + len(chunk)
            if copied != source.size:
                raise ArchiveRequestError(409, "archive_source_changed", source.arcname)
            return digest.hexdigest()
        finally:
            os.close(fd)

    @staticmethod
    def _artifact_type(arcname: str) -> str:
        name = Path(arcname).name
        if name.startswith("report_") and name.endswith("_timeline.md"):
            return "timeline_report"
        if name.startswith("report_"):
            return "report"
        if name.startswith("analyzed_"):
            return "analyzed"
        if name.startswith("correlation_"):
            return "correlation"
        if name == "ingest_manifest.json":
            return "ingest_manifest"
        if name.endswith("log.jsonl"):
            return "audit_log"
        if name.startswith("parsed_"):
            return "parsed"
        return "artifact"

    @staticmethod
    def _archive_filename(kind: str, analysis_mode: str) -> str:
        if kind == "validation":
            return f"validation_{analysis_mode}.zip"
        return "full.zip"

    @staticmethod
    def _load_source_json(source: SourceFile) -> dict[str, Any]:
        # Artifacts are local trusted outputs, but keep a hard bound so archive
        # naming/identity checks cannot unexpectedly read an enormous file.
        if source.size > 256 * 1024 * 1024:
            raise ArchiveRequestError(
                409, "artifact_metadata_too_large", f"metadata source too large: {source.arcname}")
        try:
            with source.path.open("r", encoding="utf-8") as fh:
                value = json.load(fh)
        except Exception as exc:
            raise ArchiveRequestError(
                409, "artifact_metadata_invalid", f"{source.arcname}: {type(exc).__name__}: {exc}") from exc
        if not isinstance(value, dict):
            raise ArchiveRequestError(
                409, "artifact_metadata_invalid", f"{source.arcname}: JSON root must be object")
        return value

    def _validate_source_identity(self, sources: list[SourceFile], job: dict[str, Any]) -> str:
        assert_runtime_identity()
        identity_sources = [
            src for src in sources
            if Path(src.arcname).name == "ingest_manifest.json"
            or (Path(src.arcname).name.startswith("analyzed_")
                and Path(src.arcname).name.endswith(".json"))
        ]
        if not identity_sources:
            raise ArchiveRequestError(
                409, "artifact_metadata_missing", "ingest_manifest/analyzed metadata is missing")
        modes: set[str] = set()
        for source in identity_sources:
            document = self._load_source_json(source)
            require_parser = Path(source.arcname).name.startswith("analyzed_")
            try:
                identity = assert_artifact_identity(
                    document, label=source.arcname, require_profile=True,
                    require_parser=require_parser,
                )
            except PipelineError as exc:
                raise ArchiveRequestError(409, "artifact_identity_mismatch", str(exc)) from exc
            mode = normalize_analysis_mode(identity.get("analysis_mode"))
            if not mode:
                raise ArchiveRequestError(
                    409, "artifact_analysis_mode_missing", f"{source.arcname}: analysis_mode missing")
            modes.add(mode)
        if len(modes) != 1:
            raise ArchiveRequestError(
                409, "artifact_analysis_mode_mismatch", f"analysis modes disagree: {sorted(modes)}")
        analysis_mode = next(iter(modes))
        expected_job_mode = "LEAN" if bool(job.get("lean", True)) else "FULL"
        if analysis_mode != expected_job_mode:
            raise ArchiveRequestError(
                409, "job_artifact_mode_mismatch",
                f"job mode={expected_job_mode} artifact mode={analysis_mode}")
        for key, expected in (
            ("pipeline_version", PIPELINE_VERSION),
            ("analysis_schema_version", ANALYSIS_SCHEMA_VERSION),
            ("budget_profile", active_profile().name),
        ):
            actual = str(job.get(key) or "")
            if actual and actual != str(expected):
                raise ArchiveRequestError(
                    409, "job_runtime_identity_mismatch",
                    f"{key}: job={actual!r} runtime={expected!r}")
        return analysis_mode

    # ------------------------------------------------------------------
    # Validation / metadata helpers
    # ------------------------------------------------------------------
    def _source_snapshot(self, sources: list[SourceFile]) -> str:
        h = hashlib.sha256()
        for source in sources:
            h.update(source.snapshot_line())
        return h.hexdigest()

    def _effective_compression(self, kind: str, requested: str, total_bytes: int) -> str:
        if requested != "auto":
            return requested
        if kind == "validation":
            return "normal"
        return "fast" if total_bytes >= self.large_threshold_bytes else "normal"

    def _check_disk_space(self, archive_root: Path, total_bytes: int) -> None:
        probe = archive_root if archive_root.exists() else archive_root.parent
        usage = shutil.disk_usage(probe)
        required = int(total_bytes * 1.10) + 16 * 1024 * 1024
        if usage.free < required:
            raise ArchiveRequestError(
                507, "insufficient_storage",
                f"free={usage.free} required={required}")

    @staticmethod
    def _ensure_deadline(deadline: float, phase: str) -> None:
        if time.monotonic() > deadline:
            raise ArchiveRequestError(
                408, "archive_build_timeout",
                f"archive build exceeded timeout during {phase}")

    @classmethod
    def _hash_file(cls, path: Path, deadline: float) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            while True:
                cls._ensure_deadline(deadline, "archive_hash")
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _fsync_path(path: Path) -> None:
        fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        try:
            fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        except OSError:
            return
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _can_reuse(self, prior: dict[str, Any], final_path: Path, source_snapshot: str,
                   requested: str, effective: str, analysis_mode: str) -> bool:
        if not prior or prior.get("source_snapshot") != source_snapshot:
            return False
        if prior.get("requested_compression") != requested:
            return False
        if prior.get("effective_compression") != effective:
            return False
        if normalize_analysis_mode(prior.get("analysis_mode")) != analysis_mode:
            return False
        try:
            st = os.lstat(final_path)
        except OSError:
            return False
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
            return False
        return (
            int(prior.get("archive_size", -1)) == st.st_size
            and int(prior.get("archive_mtime_ns", -1)) == st.st_mtime_ns
            and int(prior.get("archive_st_dev", -1)) == st.st_dev
            and int(prior.get("archive_st_ino", -1)) == st.st_ino
        )

    @staticmethod
    def _archive_stat_matches(state: dict[str, Any], st: os.stat_result) -> bool:
        return (
            int(state.get("archive_size", state.get("size_bytes", -1))) == st.st_size
            and int(state.get("archive_mtime_ns", -1)) == st.st_mtime_ns
            and int(state.get("archive_st_dev", -1)) == st.st_dev
            and int(state.get("archive_st_ino", -1)) == st.st_ino
        )

    def _validate_roots(self, archive_root: Path, output_root: Path) -> None:
        ar = archive_root.resolve(strict=False)
        out = output_root.resolve(strict=False)
        if ar == out or is_within(ar, out) or is_within(out, ar):
            raise ArchiveRequestError(
                409, "archive_root_invalid",
                "archive root and output root must be disjoint")
        job_root = archive_root.parent.resolve(strict=False)
        if not is_within(ar, job_root) or not is_within(out, job_root):
            raise ArchiveRequestError(409, "archive_root_invalid", "archive/output escapes job root")

    def _archive_root(self, job_id: str) -> Path:
        return (self.jobs_dir / str(job_id) / "archives").resolve(strict=False)

    def _state_path(self, job_id: str, kind: str) -> Path:
        return self._archive_root(job_id) / f"{kind}.state.json"

    def _persist_state(self, state: dict[str, Any]) -> None:
        atomic_write_json(self._state_path(state["job_id"], state["kind"]), state)

    def _new_state(self, job: dict[str, Any], kind: str, compression: str) -> dict[str, Any]:
        now = time.time()
        return {
            "job_id": job["job_id"], "job_status": job.get("status"),
            "kind": kind, "status": "queued",
            "requested_compression": compression, "effective_compression": None,
            "queued_at": now, "started_at": None, "finished_at": None,
            "files_total": 0, "files_completed": 0,
            "bytes_total": 0, "bytes_processed": 0,
            "size_bytes": None, "archive_path": None, "archive_sha256": None,
            "source_snapshot": None, "reused": False, "deduplicated": False,
            "provenance_recoverable": kind == "full",
            "error_kind": None, "error_message": None,
        }

    @staticmethod
    def _job_snapshot(job: dict[str, Any]) -> dict[str, Any]:
        return {
            "job_id": str(job.get("job_id") or ""),
            "status": str(job.get("status") or ""),
            "output_dir": str(job.get("output_dir") or ""),
            "finished_at": job.get("finished_at"),
            "hostname": str(job.get("hostname") or ""),
            "lean": bool(job.get("lean", True)),
            "pipeline_version": str(job.get("pipeline_version") or ""),
            "analysis_schema_version": str(job.get("analysis_schema_version") or ""),
            "budget_profile": str(job.get("budget_profile") or ""),
        }

    def _recover_states(self) -> None:
        if not self.jobs_dir.exists():
            return
        for job_dir in self.jobs_dir.iterdir():
            if not job_dir.is_dir() or job_dir.name.startswith("_"):
                continue
            archive_root = job_dir / "archives"
            if not archive_root.is_dir():
                continue
            for tmp in list(archive_root.glob("*.tmp")) + list(archive_root.glob(".*.tmp")):
                try:
                    tmp.unlink()
                except OSError:
                    pass
            for kind in ARCHIVE_KINDS:
                path = archive_root / f"{kind}.state.json"
                state = load_json_with_recovery(path, {})
                if not isinstance(state, dict) or not state:
                    continue
                if state.get("status") in ACTIVE_ARCHIVE_STATES:
                    state["status"] = "error"
                    state["finished_at"] = time.time()
                    state["error_kind"] = "archive_interrupted_by_restart"
                    state["error_message"] = "server restarted while archive was queued/building"
                    atomic_write_json(path, state)
                self._states[(job_dir.name, kind)] = state
