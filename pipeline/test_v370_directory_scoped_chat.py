#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 formal-promotion regression: directory-scoped chat evidence tools.

base117 end-to-end review found three chat-layer defects:

  A. a directory-scoped question was answered from ``analyzed_all_sections``
     and returned active_setup / persistence_reg / task_scheduler rows;
  B. a raw-index result was generalized into "no other files exist";
  C. real Chrome/Edge paths were rewritten with a ``<version>`` placeholder.

These tests pin the tool-level guarantees that make A and B impossible, and
pin that the tools hand the model unmodified evidence strings so C stays a
prompt-only concern.  ``search_keyword`` is exercised too, because the
host-wide behaviour must remain byte-compatible.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import chat_tools  # noqa: E402

PASS = 0
FAIL = 0

# A real path that contains version-like digits.  It must survive verbatim.
CHROME_PATH = (r"C:\Program Files\Google\Chrome\Application"
               r"\131.0.6778.86\chrome.exe")
MUSIC_DIR = r"C:\Users\Public\Music"
WEF_PATH = r"C:\Users\Public\Music\wef.vbe"
DESKTOP_INI = r"C:\Users\Public\Music\desktop.ini"


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}" + (f": {detail}" if detail else ""))


def build_fixture(tmp: str) -> str:
    out = os.path.join(tmp, "job1")
    os.makedirs(out, exist_ok=True)

    rows = [
        {"dir": os.path.dirname(CHROME_PATH), "name": "chrome.exe",
         "path": CHROME_PATH, "size": "3210000", "date": "2026/07/01  10:00",
         "source_id": "directory:chrome1"},
        {"dir": MUSIC_DIR, "name": "wef.vbe", "path": WEF_PATH,
         "size": "371", "date": "2026/07/15  10:09",
         "source_id": "directory:7304"},
    ]
    # Same path recorded twice with different date/size: two raw records, not
    # provably the same file instance.
    for index, (date, size) in enumerate(
            (("2026/07/01  10:00", "174"), ("2026/07/20  22:15", "282"))):
        rows.append({"dir": MUSIC_DIR, "name": "desktop.ini",
                     "path": DESKTOP_INI, "size": size, "date": date,
                     "source_id": f"directory:dup{index}"})
    # Bulk rows so max_results truncation is reachable.
    for index in range(400):
        rows.append({"dir": rf"C:\App{index}", "name": f"tool{index}.exe",
                     "path": rf"C:\App{index}\tool{index}.exe", "size": "1",
                     "date": "2026/07/02  09:00",
                     "source_id": f"directory:bulk{index:04d}"})

    with open(os.path.join(out, "parsed_TEST.json"), "w", encoding="utf-8") as fh:
        json.dump({"sections": {"directory": rows}}, fh, ensure_ascii=False)

    analyzed = {"sections": {
        "directory": {"entries": [
            {"identifier": WEF_PATH, "score": "HIGH", "reason": "不審なVBE",
             "source_id": "directory:7304", "iocs": [WEF_PATH]},
        ]},
        # These must never appear in a directory-scoped result even though
        # they match the keyword ".exe".
        "active_setup": {"entries": [
            {"identifier": r"C:\Windows\system32\ie4uinit.exe", "score": "LOW",
             "reason": "正規", "source_id": "active_setup:1", "iocs": []},
        ]},
        "persistence_reg": {"entries": [
            {"identifier": r"C:\ProgramData\eve\bad.exe", "score": "HIGH",
             "reason": "永続化", "source_id": "persistence_reg:1", "iocs": []},
        ]},
        "task_scheduler": {"entries": [
            {"identifier": r"C:\Windows\Temp\sched.exe", "score": "MEDIUM",
             "reason": "タスク", "source_id": "task_scheduler:1", "iocs": []},
        ]},
    }}
    with open(os.path.join(out, "analyzed_TEST.json"), "w", encoding="utf-8") as fh:
        json.dump(analyzed, fh, ensure_ascii=False)
    return out


TMP = tempfile.mkdtemp(prefix="checkpc_v370_chat_")
try:
    OUT = build_fixture(TMP)
    ctx = chat_tools.ChatContext(OUT, TMP)

    # ── 1. directory限定検索へ他セクションが混入しない ────────────────
    scoped = ctx.tool_search_directory_evidence(".exe")
    sections = {hit.get("section") for hit in scoped["hits"]}
    check("directory-scoped search returns only directory rows",
          sections == {"directory"}, repr(sections))
    check("directory-scoped search declares the requested section",
          scoped.get("requested_section") == "directory")

    identifiers = " ".join(str(hit.get("identifier") or hit.get("path") or "")
                           for hit in scoped["hits"])
    for foreign in ("ie4uinit.exe", r"ProgramData\eve\bad.exe", "sched.exe"):
        check(f"directory-scoped search excludes {foreign}",
              foreign not in identifiers)

    # ── 2. analyzedとrawの件数を別々に返す ────────────────────────────
    wef = ctx.tool_search_directory_evidence("wef.vbe")
    check("analyzed and raw match counts are reported separately",
          wef.get("analyzed_match_count") == 1 and wef.get("raw_match_count") == 1,
          repr({k: wef.get(k) for k in ("analyzed_match_count", "raw_match_count")}))
    check("total equals analyzed plus raw",
          wef.get("total") == wef.get("analyzed_match_count") + wef.get("raw_match_count"))
    origins = {hit.get("origin") for hit in wef["hits"]}
    check("hits are labelled with their origin", origins == {"analyzed", "raw"},
          repr(origins))
    check("directory-scoped scope names both sources",
          wef.get("scope") == "analyzed_directory+parsed_directory_raw_index",
          repr(wef.get("scope")))

    # ── 3. positive resultにもscope noteがある ────────────────────────
    check("directory-scoped positive result carries a note",
          bool(wef.get("note")) and "断定" in wef["note"], repr(wef.get("note")))

    listing = ctx.tool_list_directory_files(MUSIC_DIR)
    check("list_directory_files positive result carries a note",
          bool(listing.get("note")), repr(listing))
    check("list_directory_files note states the collected-evidence count",
          "収集済みraw directory証拠では" in listing.get("note", ""),
          repr(listing.get("note")))
    check("list_directory_files note forbids the absolute-absence claim",
          "他のファイルは存在しない" in listing.get("note", ""))
    check("list_directory_files note warns about same-path records",
          "同一path" in listing.get("note", ""))
    check("list_directory_files reports returned_count",
          listing.get("returned_count") == len(listing.get("files", [])))

    # ── 4. 0件時に絶対不存在を断定しない ──────────────────────────────
    missing = ctx.tool_search_directory_evidence("zz_no_such_artifact_zz")
    check("zero-hit directory search reports zero", missing.get("total") == 0)
    check("zero-hit directory search refuses an absolute-absence claim",
          "断定できません" in missing.get("note", ""), repr(missing.get("note")))
    check("zero-hit directory search still names its scope",
          missing.get("scope") == "analyzed_directory+parsed_directory_raw_index")

    # ── 5. 同一path複数recordを保持する ───────────────────────────────
    dupes = ctx.tool_search_directory_evidence("desktop.ini")
    raw_dupes = [hit for hit in dupes["hits"] if hit.get("origin") == "raw"]
    check("both raw records for the same path are returned",
          len(raw_dupes) == 2, repr(raw_dupes))
    check("duplicate raw records keep distinct source IDs",
          len({hit.get("source_id") for hit in raw_dupes}) == 2)
    check("duplicate raw records keep distinct dates",
          len({hit.get("date") for hit in raw_dupes}) == 2)
    check("duplicate raw records keep distinct sizes",
          len({hit.get("size") for hit in raw_dupes}) == 2)

    # ── 6. 実パス中のバージョン番号を保持する ─────────────────────────
    chrome = ctx.tool_search_directory_evidence("chrome.exe")
    chrome_paths = [hit.get("path") for hit in chrome["hits"]
                    if hit.get("origin") == "raw"]
    check("real version digits survive verbatim in the path",
          chrome_paths == [CHROME_PATH], repr(chrome_paths))
    check("no placeholder is substituted for the version",
          all("<version>" not in str(hit) for hit in chrome["hits"]))
    check("identifier mirrors the unmodified path",
          all(hit.get("identifier") == hit.get("path")
              for hit in chrome["hits"] if hit.get("origin") == "raw"))

    # ── 7. max_results超過時にtotal/returned_count/truncatedを返す ─────
    capped = ctx.tool_search_directory_evidence(".exe", max_results=10)
    check("capped search reports the full total",
          capped.get("total") == scoped.get("total"),
          f"{capped.get('total')} vs {scoped.get('total')}")
    check("capped search reports returned_count",
          capped.get("returned_count") == len(capped["hits"]) == 10,
          repr(capped.get("returned_count")))
    check("capped search sets truncated", capped.get("truncated") is True)
    check("capped search note states the displayed and total counts",
          "truncated=true" in capped.get("note", ""), repr(capped.get("note")))
    over_cap = ctx.tool_search_directory_evidence(".exe", max_results=9999)
    check("max_results is clamped to the hard limit",
          over_cap.get("returned_count") <= 500)

    # ── 8. 既存search_keywordのhost-wide互換性を維持する ──────────────
    host_wide = ctx.tool_search_keyword(".exe")
    check("search_keyword still searches all analyzed sections",
          host_wide.get("scope") == "analyzed_all_sections", repr(host_wide.get("scope")))
    host_sections = {hit.get("section") for hit in host_wide["hits"]}
    check("search_keyword still returns non-directory sections",
          {"active_setup", "persistence_reg", "task_scheduler"} <= host_sections,
          repr(host_sections))
    check("search_keyword keeps its legacy count key",
          host_wide.get("count") == len(host_wide["hits"]))
    check("search_keyword keeps its raw fallback flag",
          "raw_fallback_searched" in host_wide)
    host_missing = ctx.tool_search_keyword("zz_no_such_artifact_zz")
    check("search_keyword zero-hit still falls back to raw directory",
          host_missing.get("raw_fallback_searched") is True)
    check("search_keyword zero-hit still refuses absolute absence",
          "断定できません" in host_missing.get("note", ""))

    # ── 9. 公開schemaは統合tool、旧directory handlerは内部互換 ──────────
    public_names = {tool["function"]["name"] for tool in chat_tools.build_tool_schema(lv2_policy="local")}
    check("public schema exposes investigate_local only",
          public_names == {"investigate_local"}, repr(sorted(public_names)))
    check("legacy search_directory_evidence is not public",
          "search_directory_evidence" not in public_names)
    check("legacy search_keyword is not public", "search_keyword" not in public_names)

    dispatched = chat_tools.dispatch_tool_call(
        ctx, "search_directory_evidence", {"keyword": "wef.vbe"})
    check("legacy dispatch still routes search_directory_evidence internally",
          dispatched.get("requested_section") == "directory", repr(dispatched)[:200])
    check("legacy dispatch still rejects an empty keyword",
          "error" in chat_tools.dispatch_tool_call(
              ctx, "search_directory_evidence", {"keyword": ""}))

    # ── 10. MITREをツール側で強制しない ───────────────────────────────
    payload = json.dumps(wef, ensure_ascii=False)
    check("directory-scoped result does not inject MITRE technique IDs",
          "T1053" not in payload and "ATT&CK" not in payload)

    # ── 11. system promptが証拠忠実転記とscopeを要求する ──────────────
    prompt_text = open(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "server.py"),
        encoding="utf-8").read()
    start = prompt_text.find("_CHAT_SYSTEM_PROMPT_TMPL")
    prompt_block = prompt_text[start:start + 4000] if start >= 0 else ""
    for label, needle in (
        ("verbatim evidence transcription", "改変・一般化・翻訳せず"),
        ("unified local investigation", "investigate_local"),
        ("coverage denominator separation", "searchable_host_count"),
        ("no absence claim under incomplete coverage", "非hitを案件全体の不存在と断定しない"),
        ("no analyzed-entry prevalence", "analyzed entry数はhost prevalenceとして扱わない"),
        ("no causal inference", "時間的近接は因果関係を意味しない"),
        ("explicit VT intent", "現在の発言"),
        ("untrusted evidence boundary", "BEGIN_UNTRUSTED_TOOL_RESULT"),
    ):
        check(f"system prompt states: {label}", needle in prompt_block,
              needle)

finally:
    shutil.rmtree(TMP, ignore_errors=True)

print(f"\nPASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
