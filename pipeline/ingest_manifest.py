#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build an analysis-side manifest for immutable input and extracted artifacts."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
from typing import Iterable
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION


def sha256_file(path: str | os.PathLike[str], chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def build_manifest(input_path: str, files: Iterable[str] = (), **meta) -> dict:
    ip = os.path.abspath(input_path)
    input_hash = sha256_file(ip)
    records = []
    for p in sorted({os.path.abspath(str(x)) for x in files if x and os.path.isfile(x)}):
        records.append({
            "name": os.path.basename(p),
            "path": p,
            "sha256": sha256_file(p),
            "size": os.path.getsize(p),
            "empty": os.path.getsize(p) == 0,
        })
    return {
        "pipeline_version": PIPELINE_VERSION,
        "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
        "collection_id": input_hash,
        "input_path": ip,
        "input_sha256": input_hash,
        "files": records,
        **meta,
    }
