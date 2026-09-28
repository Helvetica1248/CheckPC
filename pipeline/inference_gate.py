#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Process-wide gate for all vLLM requests."""
from __future__ import annotations
import threading
from contextlib import contextmanager
from pipeline_settings import runtime_settings

_LOCK = threading.Lock()
_SEMAPHORE = None
_LIMIT = None


def _get():
    global _SEMAPHORE, _LIMIT
    limit = runtime_settings().max_inflight_llm
    with _LOCK:
        if _SEMAPHORE is None or _LIMIT != limit:
            _SEMAPHORE = threading.BoundedSemaphore(limit)
            _LIMIT = limit
    return _SEMAPHORE


@contextmanager
def inference_slot():
    sem = _get()
    sem.acquire()
    try:
        yield
    finally:
        sem.release()


def limit() -> int:
    _get()
    return int(_LIMIT)
