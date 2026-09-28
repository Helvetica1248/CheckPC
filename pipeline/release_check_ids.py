#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stable release-verifier check identifiers.

Logical check IDs intentionally ignore release-instance values such as RC numbers.
The concrete value remains in the human-readable name/detail fields.
"""
from __future__ import annotations

import hashlib
import re


def stable_check_name(name: object) -> str:
    """Remove release-instance values while retaining logical check identity.

    Both release-candidate and formal forms are accepted, so the same logical
    check keeps its ID across ``rcN -> stable`` and future minor-version
    transitions. Concrete values remain in human-readable name/detail fields.
    """
    text = str(name)
    # Context-labelled values must be normalized before generic file labels.
    text = re.sub(
        r"(?i)(version\s*=\s*)v?\d+\.\d+(?:-rc\d+)?",
        r"\1<PIPELINE_VERSION>", text,
    )
    text = re.sub(
        r"(?i)(schema\s*=\s*)v?\d+\.\d+(?:-rc\d+)?",
        r"\1<SCHEMA_VERSION>", text,
    )
    # Budget profiles use compact digits (v369/v370), with optional RC and
    # provisional suffixes.
    text = re.sub(
        r"v\d{3,}(?:-rc\d+)?(?:-provisional)?",
        "<PROFILE_NAME>", text, flags=re.I,
    )
    # Release document filenames use a dotted leading v, with optional RC.
    text = re.sub(
        r"v\d+\.\d+(?:-rc\d+)?",
        "<RELEASE_FILE_VERSION>", text, flags=re.I,
    )
    return text


def find_bare_release_versions(name: object) -> tuple[str, ...]:
    """Return unlabelled dotted release tokens from a verifier check name.

    Check IDs intentionally normalize only typed contexts (``version=``,
    ``schema=``), profile names and leading-``v`` release filenames.  A bare
    token such as ``pipeline 3.70-rc1`` is ambiguous and can drift across an
    RC-to-formal transition, so the release verifier rejects that naming form.
    """
    text = str(name)
    allowed = re.sub(
        r"(?i)(?:version|schema)\s*=\s*v?\d+\.\d+(?:-rc\d+)?",
        " ", text,
    )
    allowed = re.sub(
        r"(?i)v\d{3,}(?:-rc\d+)?(?:-provisional)?",
        " ", allowed,
    )
    allowed = re.sub(
        r"(?i)v\d+\.\d+(?:-rc\d+)?",
        " ", allowed,
    )
    found: list[str] = []
    token_re = re.compile(
        r"(?i)(?<![A-Za-z0-9_.])\d+\.\d+(?:-rc\d+)?(?![A-Za-z0-9_.])")
    stripped = re.sub(r"^[A-Za-z0-9]+:\s*", "", allowed.strip())
    for match in token_re.finditer(allowed):
        token = match.group(0)
        left = allowed[max(0, match.start() - 40):match.start()]
        # RC tokens are unambiguously release-instance values. Formal dotted
        # values are treated as versions only when a nearby type label exists,
        # or when the value is the entire check body. This avoids false positives
        # for ordinary numeric checks such as risk/fair/novelty ratio=1.0.
        if "-rc" in token.lower() or re.search(
                r"(?i)(?:pipeline|schema|release|version)\s*=?\s*$", left):
            found.append(token)
        elif stripped == token:
            found.append(token)
    return tuple(found)


def find_duplicate_check_ids(rows: object) -> dict[str, tuple[str, ...]]:
    """Return check IDs used by more than one result row."""
    grouped: dict[str, list[str]] = {}
    for row in rows or ():
        if not isinstance(row, dict):
            continue
        check_id = str(row.get("id") or "").strip()
        if not check_id:
            continue
        grouped.setdefault(check_id, []).append(str(row.get("name") or ""))
    return {
        check_id: tuple(names)
        for check_id, names in grouped.items()
        if len(names) > 1
    }


def make_check_id(section: object, name: object) -> str:
    """Return a deterministic ID stable across release-candidate numbers."""
    section_text = str(section)
    stable_name = stable_check_name(name)
    digest = hashlib.sha1(
        f"{section_text}\0{stable_name}".encode("utf-8")
    ).hexdigest()[:10]
    prefix = re.sub(r"[^A-Za-z0-9]+", "_", section_text).strip("_") or "ROOT"
    return f"{prefix}_{digest}"
