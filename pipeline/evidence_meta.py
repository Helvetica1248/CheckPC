#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Evidence collection quality states."""
from __future__ import annotations

OBSERVED = "OBSERVED"
EMPTY_UNVERIFIED = "EMPTY_UNVERIFIED"
NOT_COLLECTED = "NOT_COLLECTED"
TRUNCATED_OR_INCOMPLETE = "TRUNCATED_OR_INCOMPLETE"
VALID_STATES = {OBSERVED, EMPTY_UNVERIFIED, NOT_COLLECTED, TRUNCATED_OR_INCOMPLETE}


def event_count(text: str) -> int:
    import re
    return len(re.findall(r"(?m)^Event\[\d+\]", text or ""))


def classify_event_text(text: str, *, max_records: int = 1000) -> dict:
    if not (text or "").strip():
        return {
            "evidence_state": EMPTY_UNVERIFIED,
            "record_count": 0,
            "possibly_truncated": False,
            "coverage_note": "空ファイル。イベントなしと収集失敗を判別不能",
        }
    n = event_count(text)
    truncated = n >= max_records
    return {
        "evidence_state": TRUNCATED_OR_INCOMPLETE if truncated else OBSERVED,
        "record_count": n,
        "possibly_truncated": truncated,
        "coverage_note": (f"CheckPC収集上限{max_records}件へ到達した可能性" if truncated else ""),
    }
