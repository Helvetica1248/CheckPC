#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Immutable collector capability profile for CheckPC 6.11.1."""
from __future__ import annotations

CHECKPC_6_11_1 = {
    "name": "checkpc-6.11.1",
    "eventlog_max_records": 1000,
    "eventlog_query_direction_verified": False,
    "eventlog_empty_is_ambiguous": True,
    "userassist_scope": "current_user_only",
    "wmi_scope": "consumer_only",
    "wmi_binding_collected": False,
    "process_executable_path_reliable": False,
    "directory_scope": "system_drive_focused",
    "section_layout": "16_after_XX",
}


def get_collector_profile(version: str) -> dict:
    if str(version).strip() == "6.11.1":
        return dict(CHECKPC_6_11_1)
    p = dict(CHECKPC_6_11_1)
    p["name"] = f"checkpc-{version or 'unknown'}"
    p["profile_inferred"] = True
    return p
