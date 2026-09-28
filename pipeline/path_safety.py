#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Filesystem boundary and untrusted-name helpers."""
from __future__ import annotations
import os
import re
import unicodedata
from pathlib import Path

_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9._-]+")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def safe_component(value: object, *, fallback: str = "UNKNOWN", max_length: int = 80) -> str:
    """Return a portable, non-traversing filename component.

    The original value should be retained separately for display/provenance.
    """
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    text = _CONTROL_RE.sub("_", text)
    text = text.replace("/", "_").replace("\\", "_").replace(":", "_")
    text = _SAFE_COMPONENT_RE.sub("_", text).strip(" ._")
    if not text or text in {".", ".."}:
        text = fallback
    stem = text.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED:
        text = "_" + text
    text = text[:max_length].rstrip(" ._") or fallback
    return text


def safe_upload_filename(value: object, *, fallback: str = "upload.bin", max_length: int = 180) -> str:
    """Sanitize an uploaded basename while retaining a useful extension."""
    raw = Path(str(value or fallback).replace("\\", "/")).name
    raw = unicodedata.normalize("NFKC", raw)
    raw = _CONTROL_RE.sub("_", raw).strip()
    suffix = Path(raw).suffix
    stem = raw[:-len(suffix)] if suffix else raw
    safe_stem = safe_component(stem, fallback="upload", max_length=max(1, max_length - len(suffix)))
    safe_suffix = re.sub(r"[^A-Za-z0-9.]", "", suffix)[:16]
    result = (safe_stem + safe_suffix)[:max_length].rstrip(" .")
    return result or fallback


def resolved(path: str | os.PathLike[str]) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def is_within(path: str | os.PathLike[str], root: str | os.PathLike[str]) -> bool:
    p = resolved(path)
    r = resolved(root)
    try:
        p.relative_to(r)
        return True
    except ValueError:
        return False


def confined_join(root: str | os.PathLike[str], *parts: object) -> Path:
    """Join only sanitized components and assert the result remains below root."""
    base = resolved(root)
    candidate = base.joinpath(*(safe_component(p) for p in parts)).resolve(strict=False)
    if not is_within(candidate, base):
        raise ValueError(f"path escaped root: {candidate}")
    return candidate


def require_within(path: str | os.PathLike[str], root: str | os.PathLike[str]) -> Path:
    p = resolved(path)
    if not is_within(p, root):
        raise ValueError(f"path is outside allowed root: {p}")
    return p
