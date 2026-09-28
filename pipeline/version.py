#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Single source of truth for release and output schema versions."""

PIPELINE_VERSION = "3.71"
ANALYSIS_SCHEMA_VERSION = "2.1"
RELEASE_STATUS = "validation-pending"
BUDGET_PROFILE_DEFAULT = "v370"
UPGRADED_FROM_VERSION = "3.70"


def version_banner() -> str:
    return f"CheckPC Analysis Pipeline v{PIPELINE_VERSION} ({RELEASE_STATUS})"
