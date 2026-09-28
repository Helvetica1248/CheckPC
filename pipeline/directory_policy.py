#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Canonical executable/script and directory evidence policy for CheckPC v3.70.

The module has no LLM/runtime dependency.  Selection, ranking, deterministic
floors, IOC/path classification and tests import the same extension and path
policy so a new script type cannot be added to only one processing stage.

M0: strong deterministic evidence.  Selection is guaranteed after exact-pattern
    deduplication; M0 is not an automatic malware verdict.
M1: execution artifacts in high-risk writable placements.  Every item remains in
    raw evidence/accounting, while per-item LLM evaluation is bounded.
R : remaining Level1/risk candidates.  There is no fixed Tier-R maximum; R uses
    every normal directory-budget slot left after M0/M1.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

SCRIPT_EXTS = frozenset({
    ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".hta",
})
BINARY_EXTS = frozenset({
    ".exe", ".dll", ".scr", ".com", ".sys", ".msi", ".msp", ".cpl",
    ".ocx", ".pif",
})
EXECUTABLE_EXTS = frozenset(SCRIPT_EXTS | BINARY_EXTS)
STARTUP_EXTS = frozenset(EXECUTABLE_EXTS | {".lnk", ".url"})
ARCHIVE_EXTS = frozenset({".zip", ".rar", ".7z"})

# These aliases make intent explicit in consumers.  IOC/VT modules may union
# additional document/archive extensions, but executable/script coverage must
# never be narrower than these canonical sets.
IOC_EXECUTION_FILE_EXTS = EXECUTABLE_EXTS
VT_EXECUTION_FILE_EXTS = EXECUTABLE_EXTS

_DOUBLE_EXT_DECOY_EXTS = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg",
    ".jpeg", ".png", ".txt", ".csv", ".rtf",
})


def extension_pattern(exts: Iterable[str]) -> str:
    """Return a regex alternation without leading dots, longest first."""
    return "|".join(
        re.escape(ext.lstrip("."))
        for ext in sorted({str(x).lower() for x in exts}, key=lambda x: (-len(x), x))
    )


EXECUTABLE_EXT_PATTERN = extension_pattern(EXECUTABLE_EXTS)
SCRIPT_EXT_PATTERN = extension_pattern(SCRIPT_EXTS)
STARTUP_EXT_PATTERN = extension_pattern(STARTUP_EXTS)

_OS_MASQUERADE_NAMES = frozenset({
    "wmic.exe", "svchost.exe", "rundll32.exe", "lsass.exe", "csrss.exe",
    "services.exe", "winlogon.exe", "dllhost.exe", "conhost.exe", "smss.exe",
    "wininit.exe", "spoolsv.exe", "taskhost.exe", "taskhostw.exe",
    "regsvr32.exe", "mshta.exe", "certutil.exe", "powershell.exe", "explorer.exe",
})
_OS_LEGIT_PREFIXES = (
    "c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
    "c:\\windows\\winsxs\\", "c:\\windows\\servicing\\",
    "c:\\program files\\windowsapps\\",
)
_OS_LEGIT_EXACT = frozenset({r"c:\windows\explorer.exe"})
_DOUBLE_EXT_RE = re.compile(
    rf"\.(?:{extension_pattern(_DOUBLE_EXT_DECOY_EXTS)})"
    rf"\.(?:{EXECUTABLE_EXT_PATTERN})$",
    re.I,
)
_STARTUP_RE = re.compile(r"\\start menu\\programs\\startup\\", re.I)

_ROOT_OS_MANAGED_FILES = frozenset({
    r"c:\hiberfil.sys",
    r"c:\pagefile.sys",
    r"c:\swapfile.sys",
})


def normalize_path(value: Any) -> str:
    return str(value or "").strip().strip('"').replace("/", "\\")


def entry_path(entry: Any) -> str:
    if not isinstance(entry, dict):
        return normalize_path(entry)
    path = entry.get("path") or entry.get("full_path") or entry.get("identifier") or ""
    if path:
        return normalize_path(path)
    directory = normalize_path(entry.get("dir"))
    name = str(entry.get("name") or "").strip()
    if directory and name:
        return directory.rstrip("\\") + "\\" + name
    return normalize_path(name)


def extension(value: Any) -> str:
    path = entry_path(value) if isinstance(value, dict) else normalize_path(value)
    leaf = path.rsplit("\\", 1)[-1].lower()
    if "." not in leaf:
        return ""
    return "." + leaf.rsplit(".", 1)[-1]


def parent_path(value: Any) -> str:
    path = entry_path(value).rstrip("\\")
    return path.rpartition("\\")[0].casefold()


def is_root_os_managed_file(value: Any) -> bool:
    """Return True only for known Windows-managed paging/hibernation files at C:\\ root.

    These .sys files are large OS-managed state files, not executable artifacts
    of interest for malware triage.  Keep them in parsed/raw evidence, but do
    not admit them into Directory LLM/floor candidate selection.
    """
    return entry_path(value).casefold() in _ROOT_OS_MANAGED_FILES


def is_execution_artifact(value: Any) -> bool:
    return extension(value) in EXECUTABLE_EXTS


def extension_risk(value: Any) -> int:
    """Stable selection priority only; this is not a malware verdict."""
    ext = extension(value)
    if ext in {".vbe", ".jse", ".wsf", ".hta", ".ps1", ".psm1", ".pif"}:
        return 4
    if ext in SCRIPT_EXTS:
        return 3
    if ext in {".scr", ".com", ".cpl", ".ocx", ".msi", ".msp"}:
        return 2
    if ext in EXECUTABLE_EXTS:
        return 1
    return 0


def canonical_sort_key(value: Any) -> tuple:
    """Input-order-independent tie-break key used by Depth1 and Depth2."""
    if isinstance(value, dict):
        source_id = str(value.get("source_id") or "").casefold()
        date = str(value.get("date") or value.get("datetime") or "")
        size = str(value.get("size") or "")
        name = str(value.get("name") or "").casefold()
    else:
        source_id = date = size = name = ""
    return (
        -extension_risk(value),
        entry_path(value).casefold(),
        source_id,
        name,
        date,
        size,
    )


def m0_reason(value: Any) -> str:
    """Return a narrow deterministic M0 selection reason, or an empty string."""
    path = entry_path(value)
    if not path:
        return ""
    p = path.casefold()
    leaf = p.rsplit("\\", 1)[-1]
    ext = extension(path)
    if _DOUBLE_EXT_RE.search(p):
        return "double_extension_execution_artifact"
    if leaf in _OS_MASQUERADE_NAMES:
        if p not in _OS_LEGIT_EXACT and not any(p.startswith(x) for x in _OS_LEGIT_PREFIXES):
            return "os_binary_masquerade_outside_system_path"
    if _STARTUP_RE.search(p) and ext in STARTUP_EXTS:
        return "startup_persistence_artifact"
    return ""


def m1_placement(value: Any) -> str:
    """Return the M1 placement class for an execution artifact, or empty string."""
    path = entry_path(value)
    if not path or not is_execution_artifact(path):
        return ""
    if is_root_os_managed_file(path):
        return ""
    p = path.casefold()

    if re.fullmatch(r"[a-z]:\\[^\\]+", p):
        return "drive_root"
    if "\\users\\public\\" in p:
        return "users_public"
    if "\\windows\\temp\\" in p:
        return "windows_temp"
    if "\\$recycle.bin\\" in p:
        return "recycle_bin"

    # ``general_temp`` is intentionally limited to well-known temp roots.
    # Matching an arbitrary path component named ``temp`` promoted build trees,
    # browser assets and package caches into M1.  Direct files and files one child directory below a known root remain
    # M1; deeper descendants are Tier R.
    temp_roots = (
        re.compile(r"^[a-z]:\\users\\[^\\]+\\appdata\\local\\temp\\", re.I),
        re.compile(r"^[a-z]:\\temp\\", re.I),
    )
    for temp_root in temp_roots:
        match = temp_root.match(p)
        if match:
            tail = p[match.end():].strip("\\")
            if tail and tail.count("\\") <= 1:
                return "general_temp"
            break

    marker = "\\programdata\\"
    if marker in p:
        tail = p.split(marker, 1)[1].strip("\\")
        if tail and tail.count("\\") <= 1:
            return "programdata_shallow"

    if re.fullmatch(r".*\\users\\[^\\]+\\appdata\\roaming\\[^\\]+", p):
        return "appdata_roaming_root"
    return ""


def evidence_tier(value: Any) -> str:
    if m0_reason(value):
        return "M0"
    if m1_placement(value):
        return "M1"
    return "R"


def in_known_temp_tree(value: Any) -> bool:
    """Return whether an execution artifact is anywhere below a known Temp root.

    This predicate deliberately has no depth limit.  It controls Level1
    admission, not M1 priority.  Deep descendants of a legitimate Temp root
    therefore remain auditable Tier-R candidates, while arbitrary directory
    components named ``temp`` (package caches, browser assets, build trees) do
    not gain coverage.
    """
    path = entry_path(value)
    if not path or not is_execution_artifact(path):
        return False
    p = path.casefold()
    if "\\windows\\temp\\" in p:
        return True
    if re.match(r"^[a-z]:\\users\\[^\\]+\\appdata\\local\\temp\\", p, re.I):
        return True
    if re.match(r"^[a-z]:\\temp\\", p, re.I):
        return True
    return False


def level1_admit(value: Any) -> bool:
    """Broad directory admission policy, independent from M0/M1 priority.

    M0/M1 decides which candidates receive protected selection slots.  Level1
    decides whether evidence is visible to scoring, deferred accounting and
    reports.  Keeping these decisions separate prevents an M1 precision change
    from silently shrinking evidence coverage.

    Known Windows-managed root paging/hibernation files remain in parsed/raw
    evidence but are intentionally excluded from per-file triage candidates.
    """
    if is_root_os_managed_file(value):
        return False
    if evidence_tier(value) in {"M0", "M1"}:
        return True
    return in_known_temp_tree(value)


def level1_policy_match(value: Any) -> bool:
    """Backward-compatible alias for the v3.70 Level1 admission policy."""
    return level1_admit(value)


def group_key(value: Any) -> tuple[str, str, int, str]:
    """Stable M1 diversity key: placement, parent, extension risk and extension."""
    return (m1_placement(value), parent_path(value), extension_risk(value), extension(value))


def floor_reason(value: Any) -> tuple[str, str] | None:
    """Canonical MEDIUM-floor decision for high-risk execution artifacts."""
    path = entry_path(value)
    if not path:
        return None
    p = path.casefold()
    reason = m0_reason(path)
    if reason == "os_binary_masquerade_outside_system_path":
        leaf = p.rsplit("\\", 1)[-1]
        return (
            "os_masquerade",
            f"[フロア] OSバイナリ名 {leaf} がシステム配置外に存在"
            "（偽装/サイドローディング疑い）のため MEDIUM 未満に降格しない",
        )
    if reason == "double_extension_execution_artifact":
        return (
            "double_extension",
            "[フロア] 二重拡張子の実行可能痕跡のため MEDIUM 未満に降格しない",
        )
    if reason == "startup_persistence_artifact":
        return (
            "startup_persistence",
            "[フロア] Startup配下の永続化可能な実行痕跡のため MEDIUM 未満に降格しない",
        )
    placement = m1_placement(path)
    if placement:
        return (
            "user_writable_execution_artifact",
            "[フロア] 高リスクのユーザー書込可能配置にある実行可能痕跡であり、"
            "製品名やファイル名だけでは無害断定できないため MEDIUM 未満に降格しない",
        )
    return None
