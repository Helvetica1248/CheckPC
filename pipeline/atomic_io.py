#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Atomic JSON/text persistence helpers."""
from __future__ import annotations
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def _atomic_bytes(path: str | os.PathLike[str], data: bytes) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, target)
        try:
            dir_fd = os.open(str(target.parent), os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except (AttributeError, OSError):
            pass
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def atomic_write_text(path: str | os.PathLike[str], text: str, encoding: str = "utf-8") -> None:
    _atomic_bytes(path, text.encode(encoding))


def atomic_write_json(path: str | os.PathLike[str], obj: Any, *, indent: int | None = 2) -> None:
    data = json.dumps(obj, ensure_ascii=False, indent=indent, sort_keys=False) + "\n"
    atomic_write_text(path, data)


def load_json_with_recovery(path: str | os.PathLike[str], default: Any) -> Any:
    target = Path(path)
    if not target.exists():
        return default
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except Exception:
        corrupt = target.with_name(f"{target.name}.corrupt")
        i = 1
        while corrupt.exists():
            corrupt = target.with_name(f"{target.name}.corrupt.{i}")
            i += 1
        try:
            os.replace(target, corrupt)
        except OSError:
            pass
        return default
