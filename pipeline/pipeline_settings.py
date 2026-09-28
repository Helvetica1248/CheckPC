#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validated environment settings shared by CLI, server and workers."""
from __future__ import annotations
import math
import os
from dataclasses import dataclass
from pipeline_errors import ConfigurationError


def env_int(name: str, default: int, *, minimum: int | None = None, maximum: int | None = None) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        value = default
    else:
        try:
            value = int(raw)
        except ValueError as exc:
            raise ConfigurationError(f"{name} must be an integer: {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ConfigurationError(f"{name} must be >= {minimum}: {value}")
    if maximum is not None and value > maximum:
        raise ConfigurationError(f"{name} must be <= {maximum}: {value}")
    return value


def env_float(name: str, default: float, *, minimum: float | None = None, maximum: float | None = None) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        value = default
    else:
        try:
            value = float(raw)
        except ValueError as exc:
            raise ConfigurationError(f"{name} must be a number: {raw!r}") from exc
    if not math.isfinite(value):
        raise ConfigurationError(f"{name} must be finite: {value}")
    if minimum is not None and value < minimum:
        raise ConfigurationError(f"{name} must be >= {minimum}: {value}")
    if maximum is not None and value > maximum:
        raise ConfigurationError(f"{name} must be <= {maximum}: {value}")
    return value


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    if raw.strip().lower() in {"1", "true", "yes", "on"}:
        return True
    if raw.strip().lower() in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be boolean: {raw!r}")


@dataclass(frozen=True)
class RuntimeSettings:
    pipeline_max_workers: int
    max_inflight_llm: int
    max_upload_mb: int
    http_port: int
    https_port: int


def runtime_settings() -> RuntimeSettings:
    return RuntimeSettings(
        pipeline_max_workers=env_int("PIPELINE_MAX_WORKERS", 2, minimum=1, maximum=16),
        max_inflight_llm=env_int("CHECKPC_MAX_INFLIGHT_LLM", 9, minimum=1, maximum=128),
        max_upload_mb=env_int("PIPELINE_MAX_UPLOAD_MB", 2048, minimum=1),
        http_port=env_int("PIPELINE_HTTP_PORT", 8001, minimum=1, maximum=65535),
        https_port=env_int("PIPELINE_HTTPS_PORT", 443, minimum=1, maximum=65535),
    )
