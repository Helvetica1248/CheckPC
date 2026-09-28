#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Runtime/package identity guard for CheckPC v3.71.

The constants intentionally duplicate version.py.  A partially overlaid deploy
must fail closed instead of emitting artifacts whose code and metadata belong to
different releases.
"""
from __future__ import annotations

from typing import Any

from pipeline_errors import ConfigurationError, PipelineError
from version import (
    PIPELINE_VERSION,
    ANALYSIS_SCHEMA_VERSION,
    BUDGET_PROFILE_DEFAULT,
)

EXPECTED_PIPELINE_VERSION = "3.71"
EXPECTED_ANALYSIS_SCHEMA_VERSION = "2.1"
EXPECTED_BUDGET_PROFILE = "v370"
_VALID_MODES = {"FULL", "LEAN"}


def assert_runtime_identity() -> dict[str, str]:
    actual = {
        "pipeline_version": str(PIPELINE_VERSION),
        "analysis_schema_version": str(ANALYSIS_SCHEMA_VERSION),
        "budget_profile": str(BUDGET_PROFILE_DEFAULT),
    }
    expected = {
        "pipeline_version": EXPECTED_PIPELINE_VERSION,
        "analysis_schema_version": EXPECTED_ANALYSIS_SCHEMA_VERSION,
        "budget_profile": EXPECTED_BUDGET_PROFILE,
    }
    mismatches = [
        f"{key}: expected={expected[key]!r} actual={actual[key]!r}"
        for key in expected if actual[key] != expected[key]
    ]
    if mismatches:
        raise ConfigurationError(
            "runtime package identity mismatch; clean deploy and process restart required: "
            + "; ".join(mismatches)
        )
    return actual


def normalize_analysis_mode(value: Any) -> str:
    mode = str(value or "").strip().upper()
    return mode if mode in _VALID_MODES else ""


def artifact_identity(document: Any) -> dict[str, str]:
    if not isinstance(document, dict):
        return {}
    meta = document.get("meta") if isinstance(document.get("meta"), dict) else document
    return {
        "pipeline_version": str(meta.get("pipeline_version") or ""),
        "analysis_schema_version": str(meta.get("analysis_schema_version") or ""),
        "budget_profile": str(meta.get("budget_profile") or ""),
        "analysis_mode": normalize_analysis_mode(meta.get("analysis_mode")),
        "parser_version": str(meta.get("parser_version") or ""),
        "package_manifest_sha256": str(meta.get("package_manifest_sha256") or ""),
    }


def assert_artifact_identity(document: Any, *, label: str,
                             analysis_mode: str | None = None,
                             require_profile: bool = True,
                             require_parser: bool = False,
                             require_package: bool = False) -> dict[str, str]:
    expected = assert_runtime_identity()
    identity = artifact_identity(document)
    mismatches: list[str] = []
    for key in ("pipeline_version", "analysis_schema_version"):
        if identity.get(key) != expected[key]:
            mismatches.append(
                f"{key}: expected={expected[key]!r} actual={identity.get(key)!r}"
            )
    if require_profile and identity.get("budget_profile") != expected["budget_profile"]:
        mismatches.append(
            f"budget_profile: expected={expected['budget_profile']!r} "
            f"actual={identity.get('budget_profile')!r}"
        )
    expected_mode = normalize_analysis_mode(analysis_mode)
    if expected_mode and identity.get("analysis_mode") != expected_mode:
        mismatches.append(
            f"analysis_mode: expected={expected_mode!r} actual={identity.get('analysis_mode')!r}"
        )
    if require_parser and identity.get("parser_version") != expected["analysis_schema_version"]:
        mismatches.append(
            f"parser_version: expected={expected['analysis_schema_version']!r} "
            f"actual={identity.get('parser_version')!r}"
        )
    if require_package:
        package_sha = identity.get("package_manifest_sha256", "")
        if len(package_sha) != 64 or any(ch not in "0123456789abcdef" for ch in package_sha.lower()):
            mismatches.append(
                f"package_manifest_sha256: expected=64-char hex actual={package_sha!r}"
            )
    if mismatches:
        raise PipelineError(
            f"artifact identity mismatch ({label}); clean deploy and process restart required: "
            + "; ".join(mismatches)
        )
    return identity
