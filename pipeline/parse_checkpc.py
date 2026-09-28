#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parse_checkpc.py
CheckPC_*.txt をセクション別 JSON に構造化する。
判定・フラグ付与は一切行わない。生データの構造化のみ。

Usage:
    python parse_checkpc.py <input_file> [-o output.json]
    python parse_checkpc.py <input_file> --stdout
"""

import re
import sys
import json
import os
import argparse
import fnmatch
import csv
import io
import hashlib
from collections import OrderedDict

from evidence_meta import classify_event_text, NOT_COLLECTED
from collector_profile import get_collector_profile
from source_id import assign_source_ids
from comparison_provenance import annotate_parsed_document
from ingest_manifest import sha256_file
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION
import directory_policy

# ─────────────────────────────────────────────────────────────
# バッチツール（report_CheckPC）のリスト類パス
# /opt/llm/batchtools/SummaryReport_CheckPC/ 以下を参照する
# ─────────────────────────────────────────────────────────────
BATCHTOOLS_DIR = os.environ.get(
    "BATCHTOOLS_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "..", "batchtools", "SummaryReport_CheckPC")
)

# ─────────────────────────────────────────────────────────────
# リスト読み込みユーティリティ（report_CheckPC.py のロジックを Python3 移植）
# ─────────────────────────────────────────────────────────────

def _load_list_dir(dirpath: str) -> str:
    """指定フォルダ以下の全テキストファイルを結合して返す。"""
    if not os.path.isdir(dirpath):
        return ""
    buf = []
    for fname in sorted(os.listdir(dirpath)):
        fpath = os.path.join(dirpath, fname)
        if os.path.isfile(fpath) and not os.path.splitext(fname)[1] in (".sh", ".py", ".xlsx"):
            try:
                buf.append(open(fpath, encoding="utf-8", errors="replace").read())
            except Exception:
                pass
    return "\n".join(buf)


def _parse_list_rules(raw: str) -> list:
    """ホワイトリスト/ブラックリスト行を (rule, comment) のリストに変換。"""
    rules = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "<<" in line:
            rule = line.split("<<", 1)[0].strip().replace('"', "")
            comment = line.split("<<", 1)[1].strip()
        else:
            rule = line.replace('"', "")
            comment = ""
        if rule:
            rules.append((rule, comment))
    return rules


def _match_rule(keyword: str, rule: str) -> bool:
    """
    後方一致マッチ（ワイルドカード * 対応）。
    * はフォルダ区切り \\ を跨がない（report_CheckPC.py の仕様を継承）。
    """
    kw = keyword.replace('"', "").strip().lower()
    rule_l = rule.lower()
    if "*" not in rule_l:
        return kw.endswith(rule_l)
    # * をフォルダ区切り不可のワイルドカードとして処理
    parts = rule_l.split("*")
    tmp = kw
    for i, part in enumerate(parts):
        if len(part) == 0:
            if tmp.find("\\") >= 0:
                return False
            tmp = tmp[len(tmp):]
        elif i == 0 and part in tmp:
            tmp = tmp[tmp.index(part) + len(part):]
        elif i >= 1 and part in tmp:
            before = tmp[: tmp.index(part)]
            if "\\" in before:
                return False
            tmp = tmp[tmp.index(part) + len(part):]
        else:
            return False
    return tmp == ""


def _check_list(keyword: str, rules: list):
    """rules の中から keyword にマッチするルールを返す。なければ (False, "")。"""
    for rule, comment in rules:
        if _match_rule(keyword, rule):
            return True, comment
    return False, ""


# AppCompatCache 用マルウェア頻出パターン（report_CheckPC.py の checkAppCompatCache から移植）
_APPCOMPAT_EXEC_RE = directory_policy.EXECUTABLE_EXT_PATTERN
_APPCOMPAT_SUSPICIOUS_PATTERNS = [
    re.compile(rf"[a-z]:\\[^\\]+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf".:\\program files\\[^\\]+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf".:\\program files \(x86\)\\[^\\]+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf".:\\programdata\\.+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf"c:\\users\\[^\\]+\\[^\\]+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf"c:\\users\\[^\\]+\\appdata\\local\\virtualstore\\programdata\\.+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf"c:\\users\\[^\\]+\\appdata\\local\\virtualstore\\windows\\.+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf".*\\start menu\\programs\\startup\\[^\\]+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf".*\\appdata\\[^\\]+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf".*\\appdata\\roaming\\[^\\]+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf".*\\appdata\\local\\[^\\]+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf".*\\appdata\\locallow\\[^\\]+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf".*\\(local|windows)\\temp\\[^\\]+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf"c:\\users\\public\\[^\\]+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf"c:\\users\\public\\.+\.(?:{_APPCOMPAT_EXEC_RE}|dat)$"),
    re.compile(r"c:\\users\\public\\appdata\\.+$"),
    re.compile(rf"c:\\windows\\tasks\\[^\\]+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf"c:\\windows\\system32\\tasks\\[^\\]+\.(?:{_APPCOMPAT_EXEC_RE}|bin|rar|dat)$"),
    re.compile(rf".*\\[0-9a-zA-Z]{{1,2}}\.(?:{_APPCOMPAT_EXEC_RE}|dat)$"),
    re.compile(r".*\\psexec\.exe$"),
    re.compile(r".*\\psexesvc\.exe$"),
]

# 2バイト文字を含む実行ファイル
_APPCOMPAT_MULTIBYTE_PATTERN = re.compile(rf".*\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$")

# 誤検知除外（正規 Windows ファイル + 既知セキュリティソフト）
# パスが完全一致するもの（ワイルドカード不可）
# ※ wrong_path/blacklisted フラグがある場合は後段で上書きされるため安全
_APPCOMPAT_EXCLUDE_EXACT = {
    # Windows 標準
    "c:\\windows\\system32\\fc.exe",
    "c:\\windows\\syswow64\\fc.exe",
    "c:\\windows\\system32\\sc.exe",
    "c:\\windows\\syswow64\\sc.exe",
    "c:\\windows\\hh.exe",
    # Malwarebytes Anti-Malware（インストールパス）
    "c:\\program files\\malwarebytes\\anti-malware\\ig.exe",
    "c:\\program files\\malwarebytes\\anti-malware\\mbupdatrv5.exe",
    "c:\\program files\\malwarebytes\\anti-malware\\malwarebytes.exe",
    "c:\\program files\\malwarebytes\\anti-malware\\mbamservice.exe",
    "c:\\program files\\malwarebytes\\anti-malware\\mbamtray.exe",
    "c:\\program files\\malwarebytes\\anti-malware\\mbamwsc.exe",
    "c:\\program files\\malwarebytes\\anti-malware\\mb5uns.exe",
    "c:\\program files\\malwarebytes\\anti-malware\\mbbr.exe",
}

# 誤検知除外（パターンマッチ）: 特定ディレクトリ配下を一括 suspicious=False にする
# ここに該当するパスは _APPCOMPAT_SUSPICIOUS_PATTERNS のチェックをスキップする
_APPCOMPAT_EXCLUDE_PREFIXES = (
    # Malwarebytes 自動更新パッケージ（ProgramData 配下の一時フォルダ）
    "c:\\programdata\\malwarebytes\\mbamservice\\",
    # FortiClient（バージョン番号入りパスのため prefix 一致）
    # 追加(2026-06-18): ISHIHARADESKTOP 等で suspicious=True になっていた
    "c:\\program files\\fortinet\\",
    "c:\\program files (x86)\\fortinet\\",
    # Norton Security / Symantec Endpoint Protection
    "c:\\program files\\norton",
    "c:\\program files (x86)\\norton",
    "c:\\program files\\symantec",
    "c:\\programdata\\norton\\",
    "c:\\programdata\\symantec\\",
    # Kaspersky
    "c:\\program files\\kaspersky lab\\",
    "c:\\program files (x86)\\kaspersky lab\\",
    "c:\\programdata\\kaspersky lab\\",
)

# 誤検知除外（部分一致）: パス中にこの文字列を含む場合に suspicious=False にする。
# ユーザー名が可変で prefix 一致できないパスに使用する。
_APPCOMPAT_EXCLUDE_SUBSTRINGS = {
    # Malwarebytes InsightHub 診断ダンプ出力先（AppDataLow 配下）
    # ig.exe が診断実行時にここにコピーされる正規動作
    # 例: C:\Users\<user>\AppData\LocalLow\IGDump\sec\ig.exe
    "\\appdata\\locallow\\igdump\\",
    # OneDrive 同期フォルダ配下の実行ファイル
    # 各国語デスクトップフォルダ（桌面=中国語、デスクトップ=日本語等）に
    # 正規インストーラを一時保存するケースで 2 バイト文字パターンが誤判定する
    # 例: C:\Users\<user>\OneDrive\桌面\Firefox.exe
    "\\onedrive\\",
}

# ─────────────────────────────────────────────────────────────
# グローバルリストキャッシュ（初回アクセス時にロード）
# ─────────────────────────────────────────────────────────────
_lists_loaded = False
_whitelist_rules: list = []
_blacklist_rules: list = []
_filepathinfo_rules: list = []  # (filename, canonical_path)

def _ensure_lists_loaded():
    global _lists_loaded, _whitelist_rules, _blacklist_rules, _filepathinfo_rules
    if _lists_loaded:
        return
    wl_raw = _load_list_dir(os.path.join(BATCHTOOLS_DIR, "filepath_whitelist"))
    bl_raw = _load_list_dir(os.path.join(BATCHTOOLS_DIR, "filepath_blacklist"))
    fi_raw = _load_list_dir(os.path.join(BATCHTOOLS_DIR, "filepathinfo"))
    _whitelist_rules = _parse_list_rules(wl_raw)
    _blacklist_rules = _parse_list_rules(bl_raw)
    # filepathinfo: "filename << canonical_path << comment"
    for line in fi_raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip().replace('"', "") for p in line.split("<<")]
        if len(parts) >= 2:
            _filepathinfo_rules.append((parts[0].lower(), parts[1].lower()))
    _lists_loaded = True

# ─────────────────────────────────────────────────────────────
# セクション境界定義
# CheckPC 6.x.x の出力に合わせた START/END ペア。
# END は次のセクションの START を兼ねる。
# ─────────────────────────────────────────────────────────────
SECTION_BOUNDARIES = OrderedDict([
    ("metadata",         ("Version:",                            "1. Check PC Settings")),
    ("environment",      ("1. Check PC Settings",               "2. Check System Startup Settings")),
    ("persistence_reg",  ("2. Check System Startup Settings",   "3. Check Startup Folder")),
    ("startup_folder",   ("3. Check Startup Folder",            "4. Check Association")),
    ("association_exe",  ("4. Check Association",                 "5. Check UAC Bypass")),
    ("uac_bypass",       ("5. Check UAC Bypass",                  "6. Check Active Startup")),
    ("active_setup",     ("6. Check Active Startup",            "7. Check Task Scheduler")),
    ("task_scheduler",   ("7. Check Task Scheduler",            "8. Check IP Address")),
    ("ipconfig",         ("8. Check IP Address",                "9. Check Route")),
    ("route",            ("9. Check Route",                     "10. Check Proxy")),
    ("proxy",            ("10. Check Proxy",                    "11. Check DNS")),
    ("dns_cache",        ("11. Check DNS",                      "13. Check Net Share")),
    ("net_share",        ("13. Check Net Share",                "14. Check Current Access")),
    ("access_token",     ("14. Check Current Access",          "15. Check Directory")),
    ("directory",        ("15. Check Directory",               "16. Check Netstat")),
    ("netstat",          ("16. Check Netstat",                  "17. Check Tasklist")),
    ("tasklist",         ("17. Check Tasklist",                 "18-1. Check Service")),
    ("service",          ("18-1. Check Service",               "18-2. Check Service Registry")),
    ("service_registry", ("18-2. Check Service Registry",      "19. Check Shadow Copy")),
    ("shadow_copy",      ("19. Check Shadow Copy",             "20. Check Boot")),
    ("boot_config",      ("20. Check Boot",                    "21. Check AppCompatFlags")),
    ("appcompat_flags",  ("21. Check AppCompatFlags",          "22. Check AntiVirus")),
    ("antivirus",        ("22. Check AntiVirus",               "23. Check Prefetch")),
    ("prefetch",         ("23. Check Prefetch",                "24. Check Recent Behavior")),
    ("recent_behavior",  ("24. Check Recent Behavior",         "25. Check persistence")),
    ("com_persistence",  ("25. Check persistence",                 "26. Check Volume Serial")),
    ("volume_serial",    ("26. Check Volume Serial",               "27. Check BitLocker")),
    ("bitlocker",        ("27. Check BitLocker",                    "XX. Check Others")),
    ("others",           ("XX. Check Others",                  "\x1a")),
])

# XX. Check Others 内のサブセクション
OTHER_SUBSECTIONS = OrderedDict([
    ("bam",              "--Check BAM key Execution history--"),
    ("shim_persist",     "--Check Shim persistence--"),
    ("hotkey_cmd",       "--Check Hotkey autorun and CMD autorun --"),
    ("bits_job",         "--BITS JOB--"),
    ("psexec",           "--Check PsExec existence--"),
    ("bits",             "--Check Background Intelligent Transfer Service StateIndex--"),
    ("rdp",              "--Check Remote Desktop Protocol usage--"),
    ("sdelete",          "--Check sdelete tool existence--"),
    ("startup_reg",      "--Check Startup related reg--"),
    # 修正(1): 旧実装ではこのマーカーが OTHER_SUBSECTIONS に存在せず、
    # --Check Office Startup-- ブロック（Word/Excel STARTUP の dir 出力。
    # normal.dot 等のマクロ系永続化ファイルを含む）が直前の "startup_reg" に
    # 吸収されたまま破棄され、parse_startup_folder() に渡らなかった。
    ("office_startup",   "--Check Office Startup--"),
    ("shell_folders",    "--Check Shell Folders reg--"),
    ("hosts",            "--Check hosts File--"),
    ("lmhosts",          "--Check lmhosts File--"),
    ("folder_option",    "--Check Folder Option reg--"),
    ("disable_reg",      "--Check Disable Registry Setting reg--"),
    ("default_browser",  "--Check Default Browser reg--"),
    ("internet_settings","--Check Internet Setting reg--"),
    ("ps_history",       "--PowerShellHistory--"),
    ("wmi",              "--Check WMI Setting--"),
    ("empire",           "--Check Empire Script Code reg--"),
    ("shortcut_link",    "--Check Shortcut Link Startup--"),
    ("mimikatz_restrain","--Check Mimikatz restrain reg--"),
    ("hku_persist",      "--Check LocalSystem account persistence reg--"),
    ("fake_wpad",        "--Check Fake wpad"),
    ("audit_policy",     "--AuditPolicy--"),
    ("mount_points",     "--MountPoints2--"),
    ("pending_rename",   "--PendingFileRenameOperations--"),
    ("group_policies",   "--Check Group Policies--"),
])

# ─────────────────────────────────────────────────────────────
# ユーティリティ
# ─────────────────────────────────────────────────────────────
_SAMPLE_SIZE = 256 * 1024
_DIR_MARKER_LOCALE_GROUPS = (
    (("cp932", "shift_jis"), ("のディレクトリ", "個のディレクトリ")),
    (("gb18030",), ("的目录", "个目录")),
    (("utf-8",), ("Directory of",)),
)


def _sample_file_regions(path: str, sample_size: int = _SAMPLE_SIZE) -> bytes:
    size = os.path.getsize(path)
    if size <= sample_size * 2:
        with open(path, "rb") as f:
            return f.read()
    points = [0, size // 4, size // 2, (size * 3) // 4, max(0, size - sample_size)]
    chunks = []
    with open(path, "rb") as f:
        for pos in points:
            f.seek(max(0, min(pos, max(0, size - sample_size))))
            chunks.append(f.read(sample_size))
    return b"\n".join(chunks)


def _encoding_semantic_score(text: str) -> tuple:
    headings = len(re.findall(r"(?m)^\s*(?:XX|\d+(?:-\d+)?)\.\s+Check\b", text, re.I))
    marker_hits = sum(text.count(m) for _, markers in _DIR_MARKER_LOCALE_GROUPS for m in markers)
    replacements = text.count("\ufffd")
    controls = sum(1 for c in text if ord(c) < 32 and c not in "\n\r\t")
    # Higher is better. Marker/headings dominate replacement count.
    return (marker_hits, headings, -replacements, -controls)


def _pick_fallback_encoding(sample: bytes, candidates: tuple) -> str:
    decoded = {}
    for enc in candidates:
        try:
            decoded[enc] = sample.decode(enc, errors="replace")
        except LookupError:
            continue
    if not decoded:
        return "cp932"
    return max(decoded, key=lambda e: (_encoding_semantic_score(decoded[e]), -candidates.index(e)))


def detect_encoding(path: str) -> str:
    """Detect encoding from five file regions, not only the first 1 MiB."""
    with open(path, "rb") as f:
        head4 = f.read(4)
    if head4.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if head4.startswith(b"\xff\xfe") or head4.startswith(b"\xfe\xff"):
        return "utf-16"
    sample = _sample_file_regions(path)
    candidates = ("utf-8", "cp932", "shift_jis", "gb18030")
    strict = []
    for enc in candidates:
        try:
            text = sample.decode(enc)
            strict.append((enc, _encoding_semantic_score(text)))
        except (UnicodeDecodeError, LookupError):
            pass
    if strict:
        return max(strict, key=lambda x: (x[1], -candidates.index(x[0])))[0]
    return _pick_fallback_encoding(sample, candidates)


def read_file_with_info(path: str) -> tuple[str, dict]:
    enc = detect_encoding(path)
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode(enc, errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    score = _encoding_semantic_score(text)
    info = {
        "encoding": enc,
        "confidence": "high" if score[0] or score[1] >= 5 else "medium",
        "directory_marker_hits": score[0],
        "top_level_heading_hits": score[1],
        "replacement_count": text.count("\ufffd"),
    }
    return text, info


def read_file(path: str) -> str:
    return read_file_with_info(path)[0]


def extract_batch_version(text: str) -> tuple:
    """CheckPC バージョン文字列を (major, minor, patch) で返す。"""
    m = re.search(r"CheckPC-(\d+)\.(\d+)\.(\d+)", text)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return (0, 0, 0)


# ─────────────────────────────────────────────────────────────
# セクション分割
# ─────────────────────────────────────────────────────────────
_SECTION_NUMBER_MAP = {
    "1": "environment", "2": "persistence_reg", "3": "startup_folder",
    "4": "association_exe", "5": "uac_bypass", "6": "active_setup",
    "7": "task_scheduler", "8": "ipconfig", "9": "route", "10": "proxy",
    "11": "dns_cache", "13": "net_share", "14": "access_token",
    "15": "directory", "16": "netstat", "17": "tasklist",
    "18-1": "service", "18-2": "service_registry", "19": "shadow_copy",
    "20": "boot_config", "21": "appcompat_flags", "22": "antivirus",
    "23": "prefetch", "24": "recent_behavior", "25": "com_persistence",
    "26": "volume_serial", "27": "bitlocker", "XX": "others",
}
_TOP_SECTION_RE = re.compile(r"^\s*(?P<number>XX|\d+(?:-\d+)?)\.\s+Check\b", re.I)


def _split_sections_legacy(text: str) -> dict:
    lines = text.split("\n")
    n = len(lines)
    starts = {}
    for sec_key, (start_str, _) in SECTION_BOUNDARIES.items():
        for i, line in enumerate(lines):
            if start_str in line:
                starts[sec_key] = i
                break
    result = {}
    sec_keys = list(SECTION_BOUNDARIES.keys())
    for idx, sec_key in enumerate(sec_keys):
        if sec_key not in starts:
            result[sec_key] = ""
            continue
        begin = starts[sec_key]
        end = n
        for next_key in sec_keys[idx + 1:]:
            if next_key in starts and starts[next_key] > begin:
                end = starts[next_key]
                break
        result[sec_key] = "\n".join(lines[begin:end])
    return result


def split_sections(text: str, return_meta: bool = False):
    """Split by the next heading in physical file order.

    CheckPC 6.11.1 emits section 16 after XX; therefore numeric ordering is not
    a valid boundary rule. Unknown headings are retained rather than discarded.
    """
    lines = text.split("\n")
    headings = []
    for i, line in enumerate(lines):
        m = _TOP_SECTION_RE.match(line)
        if m:
            headings.append((i, m.group("number").upper(), line.strip()))
    if not headings:
        result = _split_sections_legacy(text)
        meta = {"collector_layout": "legacy_fallback", "section_order": [],
                "missing_sections": [], "duplicate_sections": [], "unknown_sections": []}
        return (result, meta) if return_meta else result

    result = {key: "" for key in SECTION_BOUNDARIES}
    result["metadata"] = "\n".join(lines[:headings[0][0]])
    order, duplicates, unknown = [], [], []
    seen = set()
    for pos, (begin, number, heading) in enumerate(headings):
        end = headings[pos + 1][0] if pos + 1 < len(headings) else len(lines)
        key = _SECTION_NUMBER_MAP.get(number)
        if key is None:
            key = f"unknown_{number.lower().replace('-', '_')}"
            unknown.append({"number": number, "heading": heading})
        if key in seen:
            duplicates.append(key)
            key = f"{key}__duplicate_{sum(1 for k in result if k.startswith(key+'__duplicate_')) + 1}"
        seen.add(key)
        order.append(number)
        result[key] = "\n".join(lines[begin:end])
    expected = set(_SECTION_NUMBER_MAP.values())
    missing = sorted(k for k in expected if k not in seen)
    meta = {"collector_layout": "physical_heading_order", "section_order": order,
            "missing_sections": missing, "duplicate_sections": duplicates,
            "unknown_sections": unknown}
    return (result, meta) if return_meta else result


def split_others(others_text: str) -> dict:
    """XX. Check Others を内部サブセクションに分割する。"""
    result = {}
    lines = others_text.split("\n")
    current_key = None
    current_lines = []

    for line in lines:
        matched = None
        for key, marker in OTHER_SUBSECTIONS.items():
            if marker in line:
                matched = key
                break
        if matched:
            if current_key:
                result[current_key] = "\n".join(current_lines)
            current_key = matched
            current_lines = [line]
        elif current_key:
            current_lines.append(line)

    if current_key:
        result[current_key] = "\n".join(current_lines)
    return result


# ─────────────────────────────────────────────────────────────
# セクション別パーサー群
# ─────────────────────────────────────────────────────────────
def parse_persistence_reg(text: str) -> list:
    """
    レジストリ Run キー等の永続化エントリをリスト化。
    判定なし。生エントリのみ。
    """
    entries = []
    current_key = ""
    for line in text.split("\n"):
        line = line.replace("\t", "    ")
        if re.match(r"^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_USERS).*", line):
            current_key = line.strip()
        m = re.match(r" +(.+?)\s+(REG_SZ|REG_EXPAND_SZ)\s+(.*)", line)
        if m:
            entry_name = m.group(1).strip()
            entry_val  = m.group(3).strip()
            if not entry_val:
                continue
            entries.append({
                "reg_key":    current_key,
                "entry_name": entry_name,
                "path":       entry_val,
            })
    return entries


def parse_task_scheduler(text: str) -> list:
    """Parse schtasks CSV with csv.reader; fall back to stable legacy positions."""
    rows = []
    for row in csv.reader(io.StringIO(text)):
        if not row or not any(str(x).strip() for x in row):
            continue
        joined = " ".join(row)
        if "schtasks /fo CSV" in joined or joined.lstrip().upper().startswith("ERROR"):
            continue
        rows.append([str(x).strip() for x in row])
    if not rows:
        return []
    header = rows[0]
    header_l = [h.lower().replace(" ", "") for h in header]
    header_tokens = {"hostname", "ホスト名", "主机名", "taskname", "タスク名", "任务名"}
    has_header = any(any(tok in h for tok in header_tokens) for h in header_l)
    data_rows = rows[1:] if has_header else rows

    def idx_for(*names):
        for i, h in enumerate(header_l):
            if any(n.lower().replace(" ", "") in h for n in names):
                return i
        return None

    mapping = {
        "hostname": idx_for("hostname", "ホスト名", "主机名"),
        "task_name": idx_for("taskname", "タスク名", "任务名"),
        "next_run": idx_for("nextruntime", "次回の実行時刻", "下次运行时间"),
        "last_run": idx_for("lastruntime", "前回の実行時刻", "上次运行时间"),
        "task_path": idx_for("tasktorun", "実行するタスク", "要运行的任务"),
        "run_as": idx_for("runasuser", "実行ユーザー", "运行身份"),
        "start_date": idx_for("startdate", "開始日", "开始日期"),
    }
    out = []
    for row in data_rows:
        if len(row) < 2:
            continue
        def get(key, legacy, default=""):
            i = mapping.get(key)
            if i is not None and i < len(row):
                return row[i].strip()
            return row[legacy].strip() if legacy < len(row) else default
        task_name = get("task_name", 1)
        if not task_name:
            continue
        start_date = get("start_date", 19)
        if mapping.get("start_date") is None and len(row) > 20 and row[20].strip():
            start_date = (start_date + " " + row[20].strip()).strip()
        out.append({
            "hostname": get("hostname", 0), "task_name": task_name,
            "next_run": get("next_run", 2), "last_run": get("last_run", 5),
            "task_path": get("task_path", 8), "run_as": get("run_as", 14),
            "start_date": start_date,
        })
    return out

def parse_dns_cache(text: str) -> list:
    """
    DNS キャッシュエントリをパース。
    既知正規ドメイン（Microsoft/Google/Apple/OS 更新等）はホワイトリストで除外し、
    suspicious フラグを付与する。

    対応フォーマット:
      日本語 Windows: "レコードの種類 . . . : 1"  / "A (ホスト) レコード : 1.2.3.4"
      英語 Windows:   "No records of type A"        / "A (Host) Record : 1.2.3.4"
                      "Record Name . . . . : fqdn"  / "Record Type . . . : 1"
    """
    entries = []
    current_fqdn = ""
    current_record: dict = {}
    for line in text.split("\n"):
        # ── FQDN 行の検出（日英共通: インデント4スペース + ドメイン名のみの行）
        fqdn_m = re.match(r"^ {4}([a-zA-Z0-9][a-zA-Z0-9._\-]+)$", line)
        if fqdn_m:
            if current_record:
                entries.append(current_record)
            current_fqdn = fqdn_m.group(1).strip()
            current_record = {"fqdn": current_fqdn, "type": "", "resolve": "", "nxdomain": False}
            continue

        # ── 英語環境: "Record Name . . . . . . . : fqdn" 形式
        recname_m = re.search(r"Record Name[\s.]+:\s*(\S+)", line, re.I)
        if recname_m and not current_fqdn:
            candidate = recname_m.group(1).strip()
            if re.match(r"[a-zA-Z0-9][a-zA-Z0-9._\-]+", candidate):
                if current_record:
                    entries.append(current_record)
                current_fqdn = candidate
                current_record = {"fqdn": current_fqdn, "type": "", "resolve": "", "nxdomain": False}
                continue

        # ── レコード種別（日本語）
        type_m = re.search(r"レコードの種類.*?:\s*(\d+)", line)
        if type_m:
            current_record["type"] = type_m.group(1)

        # ── 英語: "Record Type . . . : 1"
        rectype_m = re.search(r"Record Type[\s.]+:\s*(\d+)", line, re.I)
        if rectype_m:
            current_record["type"] = rectype_m.group(1)

        # ── IP アドレス解決（日本語）
        resolve_m = re.search(r"A \(ホスト\) レコード.*?:\s*(\S+)", line)
        if not resolve_m:
            # 英語: "A (Host) Record . . . : 1.2.3.4"
            resolve_m = re.search(r"A \(Host\) Record[\s.]+:\s*(\S+)", line, re.I)
        if not resolve_m:
            # 英語別形式: "Data . . . . . . . . . : 1.2.3.4" (type=1のとき)
            resolve_m = re.search(r"Data[\s.]+:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line, re.I)
        if resolve_m:
            current_record["resolve"] = resolve_m.group(1)

        # ── NXDOMAIN / レコードなし の検出（英語環境）
        # "No records of type A" / "No records of type AAAA" 等
        if re.search(r"No records of type", line, re.I):
            current_record["nxdomain"] = True

    if current_record:
        entries.append(current_record)

    result = []
    for e in entries:
        if not e.get("fqdn"):
            continue
        is_known   = _is_known_good_fqdn(e["fqdn"])
        is_empty   = not e.get("resolve", "").strip()
        is_nxdomain = e.get("nxdomain", False)

        # スキップ条件:
        #   1. WL済みドメインかつ resolve 空
        #      → ブロッキングhosts（0.0.0.0向け）または NXDOMAIN の正規ドメイン
        #      → 実際の通信なし、LLMに送る価値なし
        #   2. WL済みドメインかつ明示的 NXDOMAIN（英語環境の "No records of type A"）
        #      → 同上
        # 残すケース:
        #   - WL未登録かつ resolve 空/NXDOMAIN
        #     → DGA / タイポスクワット / 未知C2 疑いとして残す（取りこぼし防止）
        if is_known and (is_empty or is_nxdomain):
            continue

        # ループバック(127.x/::1)に解決されるエントリは hosts ファイル由来の正常なもの。
        # 例: view-localhost → 127.0.0.1 は自己ループバックの hosts 定義。
        # suspicious=False で result に残す（アナリストが確認できるよう除外はしない）。
        resolve_val = e.get("resolve", "")
        if resolve_val.startswith(("127.", "::1")):
            e["suspicious"] = False
            result.append(e)
            continue

        e["suspicious"] = not is_known
        result.append(e)
    return result


# 既知正規ドメインのサフィックスパターン（後方一致）
_DNS_KNOWN_GOOD_SUFFIXES = [
    # Microsoft / Windows
    ".microsoft.com", ".windows.com", ".windowsupdate.com",
    ".microsoftonline.com", ".microsoftazure.com", ".azure.com",
    ".office.com", ".office365.com", ".office.net",
    ".live.com", ".hotmail.com", ".outlook.com",
    ".msftncsi.com", ".msftconnecttest.com",
    ".bing.com", ".msn.com", ".skype.com",
    ".onedrive.com", ".sharepoint.com",
    ".visualstudio.com", ".vs.com", ".vscode.com",
    ".nuget.org",
    # Windows Update / Store
    ".windowsphone.com", ".mp.microsoft.com",
    ".delivery.mp.microsoft.com",
    # Google
    ".google.com", ".googleapis.com", ".gstatic.com",
    ".googleusercontent.com", ".googlesyndication.com",
    ".gvt1.com", ".gvt2.com", ".googletagmanager.com",
    ".chrome.com",
    # Apple
    ".apple.com", ".icloud.com", ".mzstatic.com",
    # Amazon / AWS
    ".amazon.com", ".amazonaws.com", ".cloudfront.net",
    # Cloudflare / CDN
    ".cloudflare.com", ".cloudflare.net",
    ".fastly.net", ".akamai.net", ".akamaized.net", ".akamaihd.net",
    # Mozilla / Firefox
    ".mozilla.org", ".mozilla.com", ".firefox.com",
    # Symantec / セキュリティ製品
    ".symantec.com", ".symcd.com", ".verisign.com",
    ".digicert.com", ".letsencrypt.org",
    # Fortinet / FortiGate（企業ファイアウォール・VPN の更新・ライセンス）
    ".fortinet.com", ".fortinet.net",
    ".fortiguard.com", ".forticloud.com",
    # Zscaler / 社内セキュリティ製品
    ".zscaler.com", ".zscalerx.com", ".zscalertwo.net",
    # Citrix
    ".citrix.com", ".citrixonline.com",
    # Adobe
    ".adobe.com", ".adobecc.com",
    # Zoom / Teams / Slack / コラボ系
    ".zoom.us", ".zoomgov.com",
    ".teams.microsoft.com",
    ".slack.com", ".slack-edge.com",
    # OS / ドライバ更新
    ".windowsphone.com",
    ".ntp.org",
    # その他既知正規
    ".github.com", ".githubusercontent.com",
    ".npmjs.com", ".pypi.org",
    ".ocsp.sectigo.com", ".crl.globalsign.com",
    ".ctldl.windowsupdate.com",

    # ── DNSインフラ系（権威/委任ネームサーバ・CDNエッジ等） ──────────
    # 実データで suspicious=True の 76%(785/1032件) を占めていた
    # クラウド/CDN事業者のNS・委任ドメイン群。サイト本体ではなく
    # 名前解決インフラそのものであり、判定対象として無意味なノイズ。
    # Akamai
    ".akamaiedge.net", ".akadns.net", ".akagtm.org",
    ".edgekey.net", ".edgesuite.net",
    ".dns-tm.com", ".edgedns-tm.info",
    # Azure DNS / Front Door / Traffic Manager
    ".azure-dns.com", ".azure-dns.net", ".azure-dns.org", ".azure-dns.info",
    ".trafficmanager.net", ".azurefd.net", ".cloudapp.net", ".cloudapp.azure.com",
    ".windows.net",
    # Alibaba Cloud DNS
    ".alidns.com",
    # NS1
    ".nsone.net",
    # Microsoft 365 / Office エッジノード（a-msedge / e-msedge / spo-msedge 等）
    ".msedge.net",
    # Google Domains（Google Cloud DNS の委任ネームサーバ ns-cloud-*.googledomains.com）
    ".googledomains.com",
    # Let's Encrypt OCSP/CRL
    ".lencr.org",
    # Mozilla
    ".mozgcp.net", ".thunderbird.net", ".mozaws.net",
    # Dropbox
    ".dropbox.com", ".dropbox-dns.com", ".getdropbox.com", ".dropboxstatic.com",
    # Adobe（追加分）
    ".acrobat.com", ".adobe.io",
    # Adobe テレメトリ・統計・CDN系
    # QERF18B で 6722件が suspicious=True になった原因。
    # ブロッキングhosts で 0.0.0.0 に向けられたドメインが
    # DNS キャッシュに resolve=空 で残るため大量の誤検知が発生。
    ".adobestats.io",           # Adobe テレメトリ（ブロッキング対象になりやすい）
    ".adobecc.io",              # Adobe Creative Cloud 関連
    ".adobegenuine.com",        # Adobe 正規ライセンス認証
    ".adobeauthenticated.com",  # 同上
    # HAProxy / hstatic.io（CDN/静的コンテンツホスティング）
    # 214件が suspicious=True になった原因
    ".hstatic.io",              # Haravan（EC向けCDN、Adobe系サービスで使用）

    # ── Microsoft 系追加（T-33） ──────────────────────────────────────
    # svc.ms: Microsoft Teams/SharePoint の内部CDN短縮ドメイン。
    # <region>-mediap.svc.ms / <service>.svc.ms 等の形式で登場。
    # ※ live.net は全体WL不可（OneDriveはlive.com管理、C2悪用例あり）
    # ※ azure.net 全体は不可（攻撃者のAzure C2を見逃すリスク）→ パターンWLで対応
    ".svc.ms",                  # Microsoft Teams/SharePoint 内部CDN
    ".exp-tas.com",             # Microsoft 実験・テレメトリ基盤（Experimentation TAS）

    # ── Mozilla / Firefox ────────────────────────────────────────────
    # content-signature-2.cdn.mozilla.net = Firefox アドオン署名検証インフラ
    # ※ .mozaws.net / .mozgcp.net は既登録
    ".mozilla.net",             # Firefox CDN・署名検証・更新インフラ

    # ── Google PKI インフラ ───────────────────────────────────────────
    # c.pki.goog = Google OCSP レスポンダー（証明書失効確認）
    # 正規のTLS検証トラフィック。C2利用報告なし。
    ".pki.goog",                # Google PKI/OCSP レスポンダー

    # ── Electronic Arts ──────────────────────────────────────────────
    # accounts.ea.com = EA ゲームプラットフォーム ログイン
    # HOST-REF-08（ゲームPC）で suspicious=True になった。
    ".ea.com",                  # Electronic Arts プラットフォーム

    # ── Bending Spoons（Evernote 買収元・イタリア企業） ──────────────
    # spidersense.bendingspoons.com = Evernote/Splice 等アプリのテレメトリ
    ".bendingspoons.com",       # Bending Spoons テレメトリ
    ".bendingspoonsapps.com",   # 同上 アプリ CDN

    # ── Microsoft 静的コンテンツ（TLDなし形式） ─────────────────────
    # res-1.public.onecdn.static.microsoft のような形式で登場。
    # TLDが "microsoft" のため suffix マッチに ".microsoft" が必要。
    # ただし攻撃者が "evil.static.microsoft" を作れるわけではない
    # （microsoft.com の subdomainとして managed）。
    ".static.microsoft",        # Microsoft 静的コンテンツ配信（TLDなし形式）
    "static.microsoft",         # 完全一致用（先頭サブドメインなしの場合）

    # その他 SaaS / アプリ
    ".grammarly.com", ".wondershare.cc", ".wondershare.com",
    ".xboxlive.com", ".xboxab.com", ".bing.net",
    # 国内レジストラ / 政府機関 NTP
    ".value-domain.com", ".nict.jp",
    # Steam / Valve（ゲームクライアント）
    # SNOWDESKTOP・LILTWIN 等で suspicious=True になっていた
    # 追加(2026-06-18)
    ".steampowered.com", ".valvesoftware.com", ".steamcontent.com",
    ".steamgames.com", ".steam.com", ".steamstat.us",
    # Discord
    ".discord.com", ".discordapp.com", ".discordcdn.com",
    # Syncthing / SyncTrayzor
    ".syncthing.net",
    # WSL2 / Hyper-V 仮想ネットワーク（T-30: parse_hosts では _KNOWN_SAFE_DOMAIN_SUFFIXES で対応済み）
    # dns_cache でも suspicious=True にならないよう WL 追加（T-33）
    ".mshome.net",
    # 逆引き DNS（in-addr.arpa）はローカル正引きの正常動作
    ".in-addr.arpa",   # rstrip(".") 後にマッチ
]

# サフィックス一致では拾えない命名規則（ハイフン区切り等）を
# 正規表現で個別に救済する。
_DNS_KNOWN_GOOD_PATTERNS = [
    # AWS Route53 委任ネームサーバ: ns-1234.awsdns-56.{com|net|org|co.uk}
    re.compile(r"^ns-\d+\.awsdns-\d+\.(com|net|org|co\.uk)$", re.I),
    # Microsoft 365 系エッジノード: ns1.{a,e,t,ax,dual-s,spo}-msedge.net
    re.compile(r"-msedge\.net$", re.I),
    # T-34: microsoftaik.azure.net のみパターンWL。
    # {hash}.microsoftaik.azure.net = TPM/AIK キー認証用エンドポイント。
    # azure.net 全体は攻撃者のC2利用リスクがあるため全体WL不可。
    re.compile(r"\.microsoftaik\.azure\.net$", re.I),
]

# 完全一致ホワイトリスト（短いFQDNで上記サフィックスに引っかからないもの）
_DNS_KNOWN_GOOD_EXACT = {
    "localhost",
    "wpad",
    "dns.google",
    "one.one.one.one",
    "8.8.8.8",
    "1.1.1.1",
}

def _is_known_good_fqdn(fqdn: str) -> bool:
    """既知の正規ドメインであれば True。"""
    f = fqdn.lower().rstrip(".")
    if f in _DNS_KNOWN_GOOD_EXACT:
        return True
    for suffix in _DNS_KNOWN_GOOD_SUFFIXES:
        if f.endswith(suffix) or f == suffix.lstrip("."):
            return True
    for pattern in _DNS_KNOWN_GOOD_PATTERNS:
        if pattern.search(f):
            return True
    return False




def parse_netstat(text: str) -> list:
    """Parse TCP and UDP netstat /nao rows without dropping UDP sockets."""
    connections, seen = [], set()
    reading = False
    for line in text.split("\n"):
        low = line.lower()
        if "netstat/nao" in low or "netstat /nao" in low:
            reading = True
            continue
        if "netstat/fao" in low or "netstat/naob" in low:
            reading = False
        if not reading:
            continue
        tcp = re.match(r"\s*TCP\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*$", line, re.I)
        udp = re.match(r"\s*UDP\s+(\S+)\s+(\S+)\s+(\d+)\s*$", line, re.I)
        if tcp:
            proto, local, remote, state, pid = "TCP", tcp.group(1), tcp.group(2), tcp.group(3), tcp.group(4)
        elif udp:
            proto, local, remote, state, pid = "UDP", udp.group(1), udp.group(2), "", udp.group(3)
        else:
            continue
        key = (proto, local, remote, state, pid)
        if key in seen:
            continue
        seen.add(key)
        connections.append({"proto": proto, "local": local, "remote": remote,
                            "state": state, "pid": pid})
    return connections

def parse_tasklist(text: str) -> list:
    """Parse tasklist output plus PowerShell Win32_Process fixed-width tables."""
    by_pid = {}
    for line in text.split("\n"):
        m = re.match(r"^(.+?)\s+(\d+)\s+\S+\s+\d+\s+([\d,]+) K", line)
        if m:
            pid = m.group(2)
            by_pid.setdefault(pid, {"name": m.group(1).strip(), "pid": pid,
                                    "mem_kb": m.group(3).replace(",", ""),
                                    "exe_path": "", "exe_path_source": "", "cmdline": ""})
        pipe = re.match(r"^(.+?)\|(.+?)\|(\d+)$", line)
        if pipe:
            pid = pipe.group(3)
            proc = by_pid.setdefault(pid, {"name": "", "pid": pid, "mem_kb": "",
                                           "exe_path": "", "exe_path_source": "", "cmdline": ""})
            proc["exe_path"] = pipe.group(1).strip()
            proc["exe_path_source"] = "collected"
            proc["cmdline"] = pipe.group(2).strip()

    lines = text.splitlines()
    for i in range(len(lines) - 1):
        header, sep = lines[i], lines[i + 1]
        if not (re.search(r"\bProcessID\b", header, re.I) and re.match(r"^\s*-{2,}", sep)):
            continue
        names = list(re.finditer(r"\b(Name|ProcessID|Path|ExecutablePath|CommandLine|ParentProcessId|CreationDate|SessionId)\b", header, re.I))
        if len(names) < 2:
            continue
        cols = [(m.group(1), m.start(), names[j + 1].start() if j + 1 < len(names) else None)
                for j, m in enumerate(names)]
        for row in lines[i + 2:]:
            if not row.strip() or re.match(r"^\s*(?:\d+\.|XX\.)\s+Check\b", row, re.I):
                break
            vals = {name.lower(): row[start:end].strip() if end else row[start:].strip()
                    for name, start, end in cols}
            pid = vals.get("processid", "")
            if not pid.isdigit():
                continue
            proc = by_pid.setdefault(pid, {"name": "", "pid": pid, "mem_kb": "",
                                           "exe_path": "", "exe_path_source": "", "cmdline": ""})
            proc["name"] = vals.get("name", proc["name"])
            path = vals.get("executablepath") or vals.get("path") or ""
            if path:
                proc["exe_path"] = path
                proc["exe_path_source"] = "collected"
            proc["cmdline"] = vals.get("commandline", proc["cmdline"])
            for src, dst in (("parentprocessid", "parent_pid"), ("creationdate", "creation_date"),
                             ("sessionid", "session_id")):
                if vals.get(src): proc[dst] = vals[src]
        break

    # Conservative executable inference from quoted/first command token.
    for proc in by_pid.values():
        if not proc.get("exe_path") and proc.get("cmdline"):
            cmd = proc["cmdline"].lstrip()
            if cmd.startswith('"') and '"' in cmd[1:]:
                inferred = cmd[1:cmd.find('"', 1)]
            else:
                inferred = cmd.split(None, 1)[0] if cmd else ""
            if re.search(rf"\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$", inferred, re.I):
                proc["exe_path"] = inferred
                proc["exe_path_source"] = "commandline_inferred"
    return sorted(by_pid.values(), key=lambda x: int(x["pid"]) if str(x["pid"]).isdigit() else 10**12)

def parse_service(svc_text: str, svc_reg_text: str) -> list:
    """サービス情報をパース。sc query + レジストリ両方から収集。"""
    services = {}
    key = ""
    for line in svc_text.split("\n"):
        m = re.match(r"SERVICE_NAME:\s*(.+)", line, re.I)
        if m:
            key = m.group(1).strip().lower()
            services.setdefault(key, {"name": key, "display_name": "", "state": "", "start_type": "", "image_path": "", "service_dll": ""})
        if not key:
            continue
        dm = re.match(r"DISPLAY_NAME:\s*(.+)", line, re.I)
        if dm:
            services[key]["display_name"] = dm.group(1).strip()
        sm = re.match(r"\s+STATE\s*:\s*\d+\s+(.+)", line, re.I)
        if sm:
            services[key]["state"] = sm.group(1).strip()

    key = ""
    for line in svc_reg_text.split("\n"):
        line = line.replace("\t", "    ")
        m = re.match(r"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\([^\\]+)", line, re.I)
        if m:
            key = m.group(1).lower()
            services.setdefault(key, {"name": key, "display_name": "", "state": "", "start_type": "", "image_path": "", "service_dll": ""})
        if not key:
            continue
        start_m = re.match(r"\s+Start\s+REG_DWORD\s+(\S+)", line, re.I)
        if start_m:
            val = start_m.group(1)
            services[key]["start_type"] = {"0x2": "Auto", "0x3": "Manual", "0x4": "Disabled"}.get(val.lower(), val)
        img_m = re.match(r"\s+ImagePath\s+(?:REG_SZ|REG_EXPAND_SZ)\s+(.*)", line, re.I)
        if img_m:
            services[key]["image_path"] = img_m.group(1).strip()
        dll_m = re.match(r"\s+ServiceDll\s+(?:REG_SZ|REG_EXPAND_SZ)\s+(.*)", line, re.I)
        if dll_m:
            services[key]["service_dll"] = dll_m.group(1).strip()

    # ドライバ (.sys) は除外
    return [v for v in services.values() if not v["image_path"].lower().endswith(".sys")]


# Word が引用スタイルXSLを Temp\TCD[hex].tmp\ に一時展開するパターン
# T1220(XSL Script Processing)の本体検出はwmic/msxsl実行痕跡(Prefetch)で行う
_WORD_CITATION_XSL_RE = re.compile(
    r"\\Temp\\TCD[0-9A-Fa-f]+\.tmp\\[^\\]+\.xsl$", re.I
)


# CheckPC 6.11.2 on Japanese Windows can emit a weekday token between
# the date and time (e.g. ``2026/08/10 月  09:16``).  Keep the legacy
# weekday-less form valid as well.  The weekday is presentation metadata, not
# part of the evidence timestamp used by downstream logic, so it is omitted
# from the normalized ``date`` value.
_JP_DIR_FILE_RE = re.compile(
    r"(?P<date>\d{4}/\d{2}/\d{2})(?P<date_gap>\s+)"
    r"(?:(?P<weekday>(?:[月火水木金土日](?:曜日)?)|(?:\([月火水木金土日]\)))(?P<weekday_gap>\s*))?"
    r"(?P<time>\d{2}:\d{2})\s+"
    r"(?P<size>[\d,]+)\s+(?P<name>.+)$"
)


def _match_jp_dir_file_line(line: str):
    """Return a Japanese ``dir`` file-line match with optional weekday."""
    return _JP_DIR_FILE_RE.match(line)


def _normalized_jp_dir_datetime(match) -> str:
    # Preserve the exact legacy date/time separator when no weekday token is
    # present so pre-rev7 source IDs stay stable even for non-standard spacing.
    # Weekday-bearing CheckPC 6.11.2 lines have no legacy equivalent, so the
    # weekday presentation token is removed and the established two-space
    # canonical separator is used downstream.
    gap = "  " if match.group("weekday") else match.group("date_gap")
    return f"{match.group('date')}{gap}{match.group('time')}"


def parse_directory(text: str) -> list:
    """
    dir コマンド出力からファイルリストを構造化。
    判定なし。ファイルパス・日時・サイズのみ。
    Temp\\TCD*.tmp\\*.xsl（Word引用スタイルXSL一時展開）は除外する。

    【高速化】os.path.join (4,274,815回) → 文字列連結に変更。
    os.path.join は Windows/POSIX 両対応のための処理が入り重い。
    directory 出力は常に Windows パス区切り（\\）のため文字列連結で十分。
    """
    files = []
    current_dir = ""
    sep = "\\"
    for line in text.split("\n"):
        # ディレクトリ行の検出（日本語・英語・中国語・韓国語対応）
        for marker in ("のディレクトリ", "Directory of", "的目录", "디렉터리"):
            if marker in line:
                current_dir = line.replace(marker, "").strip().rstrip("\\/")
                break
        if "<DIR>" in line:
            continue

        # 日本語ロケール日付: YYYY/MM/DD [曜日] HH:MM
        # CheckPC 6.11.2 では曜日トークンが入る環境がある。
        m_jp = _match_jp_dir_file_line(line)
        if m_jp and current_dir:
            fname = m_jp.group("name").strip()
            fpath = current_dir + sep + fname
            if _WORD_CITATION_XSL_RE.search(fpath):
                continue
            files.append({
                "date":  _normalized_jp_dir_datetime(m_jp),
                "size":  m_jp.group("size").replace(",", ""),
                "name":  fname,
                "path":  fpath,
                "dir":   current_dir,
            })
            continue

        # 英語ロケール日付: MM/DD/YYYY  HH:MM AM/PM
        m_en = re.match(r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}\s+[AP]M)\s+([\d,]+)\s+(.+)", line)
        if m_en and current_dir:
            fname = m_en.group(3).strip()
            fpath = current_dir + sep + fname
            if _WORD_CITATION_XSL_RE.search(fpath):
                continue
            files.append({
                "date":  m_en.group(1),
                "size":  m_en.group(2).replace(",", ""),
                "name":  fname,
                "path":  fpath,
                "dir":   current_dir,
            })
    return files


def parse_prefetch(text: str) -> list:
    """Prefetch ファイル一覧をパース（作成日・更新日の両方を取得）。"""
    pf_files = []
    mode = None  # "created" | "modified"
    for line in text.split("\n"):
        if re.search(r"created time", line, re.I):
            mode = "created"
            continue
        if re.search(r"modified time", line, re.I):
            mode = "modified"
            continue
        if "<DIR>" in line or not mode:
            continue
        m = re.match(r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2})\s+[\d,]+\s+(.+\.pf\b.*)", line, re.I)
        if not m:
            continue
        fname = m.group(2).strip()
        if mode == "created":
            pf_files.append({"name": fname, "created": m.group(1), "modified": ""})
        elif mode == "modified":
            for pf in pf_files:
                if pf["name"] == fname:
                    pf["modified"] = m.group(1)
    return pf_files


def parse_appcompat_cache_csv(csv_text: str) -> list:
    """Parse ShimCacheParser CSV safely, including quoted commas in paths."""
    _ensure_lists_loaded()
    rows, seen = [], set()
    reader = csv.reader(io.StringIO(csv_text.replace("\r", "")))
    for i, parts in enumerate(reader):
        if i == 0 or not parts:
            continue
        parts = [p.strip() for p in parts]
        if len(parts) < 3:
            continue
        path = parts[2]
        if not path:
            continue
        path_lower = path.lower().strip()
        if path_lower in seen:
            continue
        seen.add(path_lower)
        wl_hit, _ = _check_list(path, _whitelist_rules)
        if wl_hit:
            continue
        bl_hit, bl_comment = _check_list(path, _blacklist_rules)
        suspicious = bl_hit or any(pat.match(path_lower) for pat in _APPCOMPAT_SUSPICIOUS_PATTERNS)
        if not suspicious and _APPCOMPAT_MULTIBYTE_PATTERN.match(path_lower):
            try: path.encode("ascii")
            except UnicodeEncodeError: suspicious = True
        if path_lower in _APPCOMPAT_EXCLUDE_EXACT or any(path_lower.startswith(p) for p in _APPCOMPAT_EXCLUDE_PREFIXES) or any(sub in path_lower for sub in _APPCOMPAT_EXCLUDE_SUBSTRINGS):
            suspicious = False; bl_hit = False
        fname = os.path.basename(path_lower)
        canonical_paths = [cp for fn, cp in _filepathinfo_rules if fn == fname]
        wrong_path = bool(canonical_paths and not any(path_lower == cp for cp in canonical_paths))
        suspicious = suspicious or wrong_path
        rows.append({
            "last_modified": parts[0] if len(parts) > 0 else "",
            "last_update": parts[1] if len(parts) > 1 else "",
            "path": path, "file_size": parts[3] if len(parts) > 3 else "",
            "exec_flag": parts[4] if len(parts) > 4 else "",
            "suspicious": suspicious, "blacklisted": bl_hit,
            "bl_comment": bl_comment, "wrong_path": wrong_path,
        })
    return rows

def parse_recent_behavior(text: str) -> list:
    """Parse CheckPC 24 registry MRU blocks; retain legacy .lnk rows."""
    entries = []
    current_key = ""
    category = ""
    for raw in text.split("\n"):
        line = raw.strip()
        if line.upper().startswith("HKEY_"):
            current_key = line
            low = line.lower()
            if "runmru" in low: category = "RunMRU"
            elif "typedurls" in low: category = "TypedURLs"
            elif "typedpaths" in low: category = "TypedPaths"
            elif "map network drive" in low or "mountpoints" in low: category = "NetworkMRU"
            else: category = "RegistryMRU"
            continue
        m = re.match(r"^([^\s]+)\s+REG_[A-Z0-9_]+\s+(.*)$", line, re.I)
        if m and current_key:
            entries.append({"category": category, "reg_key": current_key,
                            "value_name": m.group(1), "value_data": m.group(2).strip()})
            continue
        lm = re.match(r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2})\s+([\d,]+)\s+(.+\.lnk\b.*)", raw, re.I)
        if lm:
            entries.append({"category": "RecentLink", "date": lm.group(1),
                            "size": lm.group(2).replace(",", ""), "name": lm.group(3).strip()})
    return entries

def parse_registry_dump(text: str, category: str = "registry") -> list:
    entries, current_key = [], ""
    for raw in text.split("\n"):
        line = raw.strip()
        if line.upper().startswith("HKEY_"):
            current_key = line
            continue
        m = re.match(r"^([^\s]+)\s+(REG_[A-Z0-9_]+)\s*(.*)$", line, re.I)
        if m and current_key:
            entries.append({"category": category, "reg_key": current_key,
                            "value_name": m.group(1), "value_type": m.group(2),
                            "value_data": m.group(3).strip()})
    return entries


def parse_wmi_consumers(text: str) -> list:
    entries, current = [], {}
    for raw in text.split("\n"):
        line = raw.strip()
        if not line:
            if current:
                entries.append(current); current = {}
            continue
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(.*)$", line)
        if m:
            current[m.group(1)] = m.group(2).strip()
        elif "EventConsumer" in line:
            if current: entries.append(current)
            current = {"consumer_class": line}
    if current: entries.append(current)
    return entries


def parse_task_event_text(text: str, event_id: str) -> list:
    entries = []
    # Accept the event header variants observed across wevtutil/localized
    # collectors, including optional indentation and ASCII/full-width colon.
    blocks = re.split(
        r"(?m)(?=^[ \t]*Event\[\d+\]\s*[:：]?\s*$)",
        text or "",
    )
    for block in blocks:
        if not block.strip(): continue
        dt = ""
        dm = re.search(r"(?:Date|日時|TimeCreated)\s*[:：]\s*(.+)", block, re.I)
        if dm: dt = dm.group(1).strip()
        task = ""
        tm = re.search(r"(?:Task Name|TaskName|タスク名|任务名称)\s*[:：]\s*(.+)", block, re.I)
        if tm: task = tm.group(1).strip()
        user = ""
        um = re.search(r"(?:User|ユーザー|用户)\s*[:：]\s*(.+)", block, re.I)
        if um: user = um.group(1).strip()
        entries.append({"event_id": str(event_id), "datetime": dt, "task_name": task,
                        "user": user, "raw": block.strip()})
    return entries


def parse_ps_history(text: str) -> list:
    """PowerShell履歴をパース。"""
    commands = []
    for line in text.split("\n"):
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("-"):
            commands.append(line)
    return commands


def parse_startup_folder(text: str) -> list:
    """
    CheckPC の 3. Check Startup Folder セクション + --Check Office Startup-- ブロックをパース。
    dir /a コマンドの出力形式（日付 時刻 サイズ ファイル名）からエントリを抽出する。

    返り値: list of dict
        path        : ファイルフルパス（dir のカレントディレクトリを補完）
        date        : 更新日時文字列
        size        : ファイルサイズ文字列
        source      : "windows_startup" | "office_startup"
        suspicious  : True = .dot/.dotm/.hta/.vbs/.js/.ps1/.bat 等
    """
    entries = []
    seen = set()

    current_dir = ""
    current_source = "windows_startup"

    # parse_directory() と同じ CheckPC 6.11.2 曜日互換パーサを使用する。
    dir_line_re = _JP_DIR_FILE_RE
    dir_header_re = re.compile(
        r"^\s+(.+)\s+のディレクトリ\s*$"
    )

    SUSPICIOUS_EXTS = set(directory_policy.STARTUP_EXTS) | {
        ".dot", ".dotm", ".dotx", ".xlsm", ".xlam"
    }
    OFFICE_STARTUP_PATTERNS = [
        r"microsoft\\word\\startup",
        r"microsoft\\excel\\xlstart",
        r"office\d*\\startup",
        r"office\d*\\xlstart",
    ]

    for line in text.replace("\r\n", "\n").split("\n"):
        # ソース判定の切り替え
        if "--Check Office Startup--" in line or "Office Startup" in line:
            current_source = "office_startup"
            continue

        # ディレクトリヘッダ（"  C:\\foo\\bar のディレクトリ"）
        h = dir_header_re.match(line)
        if h:
            current_dir = h.group(1).strip()
            # ソース判定をディレクトリパスから確定
            dl = current_dir.lower()
            if any(re.search(p, dl) for p in OFFICE_STARTUP_PATTERNS):
                current_source = "office_startup"
            elif "startup" in dl or "programs\\startup" in dl:
                current_source = "windows_startup"
            else:
                # 修正(2026-06-12): split_sections()の境界仕様により、
                # 「3. Check Startup Folder」セクションには
                # 「4. Check Association of EXE」「5. Check UAC Bypass」
                # （C:\\Windows\\System32\\sysprep\\CRYPTBASE.dll existence
                # check 等）の内容も丸ごと取り込まれる。これらのディレクトリ
                # はスタートアップ関連ではない（パスに"startup"を含まず、
                # Office STARTUPパターンにも該当しない）ため、配下のファイル
                # を startup_folder の結果から除外する。
                current_source = "non_startup"
            continue

        # ファイル行
        m = dir_line_re.match(line)
        if not m:
            continue
        date_str = _normalized_jp_dir_datetime(m)
        size_str = m.group("size").strip()
        fname    = m.group("name").strip()

        # <DIR> はスキップ
        if fname.startswith("<"):
            continue

        # スタートアップ関連ではないディレクトリ配下のファイルは除外
        if current_source == "non_startup":
            continue

        # フルパス組み立て
        if os.path.isabs(fname):
            path = fname
        elif current_dir:
            path = os.path.join(current_dir, fname)
        else:
            path = fname

        if path in seen:
            continue
        seen.add(path)

        ext = os.path.splitext(path.lower())[1]
        # office_startup フォルダ内の .dot 系は必ず suspicious
        if current_source == "office_startup":
            suspicious = ext in SUSPICIOUS_EXTS or ext not in {".lnk", ""}
        else:
            suspicious = ext in SUSPICIOUS_EXTS

        entries.append({
            "path":       path,
            "date":       date_str,
            "size":       size_str,
            "source":     current_source,
            "suspicious": suspicious,
        })

    return entries


def parse_hosts(text: str) -> list:
    """
    --Check hosts File-- ブロックの内容をパースする。

    CheckPC は hosts ファイルを type コマンドで表示するため、
    以下のノイズ行が混入する:
      1. "--Check hosts File--"  (セクションヘッダ)
      2. type "C:\\WINDOWS\\System32\\drivers\\etc\\hosts*"  (実行コマンド行)
    これらを前処理で除去してから IP+hostname 行のみを抽出する。

    返り値: list of dict
        ip          : IPアドレス
        hostname    : ホスト名（スペース区切りで複数エイリアスがある場合は最初の1つ）
        suspicious  : True = セキュリティ製品・Microsoft Update系ドメインへのリダイレクト
                      または標準以外のIPへのリダイレクト（MITM/フィッシング疑い）
        raw         : 元の行テキスト（ノイズ除去後）
    """
    # ── 既知の正常エントリ（スキップ対象） ─────────────────────
    _KNOWN_SAFE_EXACT = {
        "127.0.0.1 localhost",
        "::1 localhost",
        "127.0.0.1\tlocalhost",
        "::1\tlocalhost",
    }

    # ── 既知の正常ドメインパターン（後方一致） ─────────────────
    # WSL2 / Hyper-V が hosts に自動書き込む *.mshome.net エントリは
    # 172.x.x.x（Hyper-V 仮想スイッチ）への解決であり正常動作。
    # プライベート IP であっても suspicious=True にしない。
    _KNOWN_SAFE_DOMAIN_SUFFIXES = (
        ".mshome.net",   # WSL2 / Hyper-V 仮想ネットワーク自動生成
    )

    # ── セキュリティ/更新系ドメインへの 0.0.0.0/127.0.0.1 リダイレクト ──
    _SUSPICIOUS_DOMAIN_KEYWORDS = [
        "microsoft.com", "windowsupdate.com", "windows.com",
        "symantec.com", "norton.com", "kaspersky.com", "kaspersky.net",
        "avg.com", "avast.com", "trendmicro.com", "mcafee.com",
        "sophos.com", "eset.com", "malwarebytes.com",
        "virustotal.com", "google.com", "googleapis.com",
    ]
    _SUSPICIOUS_REDIRECT_RE = re.compile(
        r"^(0\.0\.0\.0|127\.0\.0\.1)\s+", re.I
    )

    # ── CheckPC ノイズ行の除去パターン ──────────────────────────
    # 1. "--Check * File--" 形式のセクションヘッダ
    # 2. "type ..." 形式の CheckPC 実行コマンド行
    # 3. "HOSTS のディレクトリ" 等の dir コマンド出力
    _NOISE_RE = re.compile(
        r"^--Check\s|"                     # --Check hosts File-- 等
        r"^type\s+[\"']?[a-z]:\\|"         # type "C:\WINDOWS\..." 等
        r"^\s+.+\s+のディレクトリ|"        # dir ヘッダ（日本語環境）
        r"^\s*\d+\s+個のファイル|"         # dir フッタ
        r"^\s*\d+\s+個のディレクトリ",     # dir フッタ
        re.I
    )

    # ── IP アドレスらしき文字列かを簡易判定 ─────────────────────
    # 最初のトークンが IPv4 または IPv6 の形式でなければ hosts エントリではない
    _IP_RE = re.compile(
        r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"   # IPv4
        r"|::1|::ffff:|"                             # IPv6 ループバック/マップ
        r"[0-9a-f]{0,4}:).*$",                      # IPv6 その他
        re.I
    )

    entries = []
    # ── 大量ブロッキング hosts の早期検出 ──────────────────────
    # Adobe / 広告ブロック目的で 0.0.0.0 に数千件のドメインを向ける
    # ブロッキング hosts が存在する場合、全件パースすると parsed.json が
    # 巨大になり処理時間も増加する。
    # 判定: 非コメント行の 90% 以上が "0.0.0.0 <hostname>" 形式で
    # 100件を超える場合はブロッキング hosts とみなし、
    # 代表エントリ1件のみ残してスキップする（LLM にはこの旨を伝える）。
    _non_comment = [l.strip() for l in text.split('\n')
                    if l.strip() and not l.strip().startswith('#')
                    and not _NOISE_RE.match(l.strip())]
    _zero_block = [l for l in _non_comment if l.startswith('0.0.0.0 ')]
    _BLOCKING_THRESHOLD = 100
    if len(_non_comment) > _BLOCKING_THRESHOLD and len(_zero_block) / max(len(_non_comment), 1) >= 0.9:
        return [{
            "ip":         "0.0.0.0",
            "hostname":   f"[ブロッキングhosts検出: {len(_zero_block)}件を 0.0.0.0 に向けるエントリあり。"
                          f"広告/テレメトリブロック目的と推定。個別エントリはスキップ。]",
            "suspicious": False,
            "raw":        f"[blocking_hosts: {len(_zero_block)} entries]",
        }]

    for line in text.split("\n"):
        line = line.strip()

        # 空行・コメント行をスキップ
        if not line or line.startswith("#"):
            continue

        # CheckPC ノイズ行を除去
        if _NOISE_RE.match(line):
            continue

        # インライン # コメントを除去（タブ/スペース + # 以降）
        line = re.sub(r"\s+#.*$", "", line).strip()
        if not line:
            continue

        # IP + hostname の形式を抽出
        parts = line.split()
        if len(parts) < 2:
            continue
        ip_part   = parts[0]
        host_part = parts[1]   # 最初のホスト名のみ（エイリアスは無視）

        # 最初のトークンが IP アドレス形式でなければスキップ
        # （"type", "--Check" 等の残留ノイズを確実に除去）
        if not _IP_RE.match(ip_part):
            continue

        # 既知正常エントリはスキップ
        canonical = f"{ip_part} {host_part}".lower()
        if canonical in _KNOWN_SAFE_EXACT:
            continue

        # ── suspicious 判定 ──────────────────────────────────────
        suspicious = False
        host_lower = host_part.lower()

        # 既知の正常ドメインパターンに一致する場合は suspicious=False で登録
        # （エントリ自体は除外しない：アナリストが存在を確認できるよう残す）
        if any(host_lower.endswith(sfx) for sfx in _KNOWN_SAFE_DOMAIN_SUFFIXES):
            entries.append({
                "ip":         ip_part,
                "hostname":   host_part,
                "suspicious": False,
                "raw":        line,
            })
            continue

        # セキュリティ/更新系ドメインへの 0.0.0.0/127.0.0.1 リダイレクト → HIGH
        if _SUSPICIOUS_REDIRECT_RE.match(ip_part + " "):
            if any(kw in host_lower for kw in _SUSPICIOUS_DOMAIN_KEYWORDS):
                suspicious = True

        # 上記以外の非ループバック IP への解決（MITM/フィッシング疑い）
        if not suspicious:
            ip_lower = ip_part.lower()
            is_loopback = ip_lower.startswith(("127.", "::1", "0.0.0.0", "fe80:"))
            if not is_loopback:
                suspicious = True   # プライベートIPも含め要確認として残す

        entries.append({
            "ip":         ip_part,
            "hostname":   host_part,
            "suspicious": suspicious,
            "raw":        line,
        })
    return entries


# ── System EventLog 7045（新規サービスインストール）パーサー ─────────────
_7045_EVENT_BLOCK_RE = re.compile(r"(?=Event\[\d+\])", re.M)

def parse_system_7045(event_log_text: str) -> list:
    """
    Eventlog_System_7045_*.txt をパースして新規サービスインストールの一覧を返す。

    Event ID 7045: A new service was installed in the system.
    各イベントブロックから ServiceName / ImagePath / AccountName / Date を抽出する。

    対応フォーマット:
      英語 Windows:   "Service Name:"  / "Image Path:"  / "Account Name:"
      日本語 Windows: "サービス名:"     / "サービス ファイル名:"  / "サービス アカウント:"
      中国語 Windows: "服务名称:"       / "服务文件名:"           / "服务账户:"

    返り値: list of dict
        datetime     : イベント日時
        service_name : インストールされたサービス名
        image_path   : 実行ファイルパス
        account_name : 実行アカウント

    【バグ修正】
    ① 日本語フォーマット「サービス ファイル名:」がパターン未対応だったため
      image_path が全件空文字になっていた（SNOWLAPTOP で発覚）。
    ② seen の重複判定を (service_name, image_path) にしていたため、
      image_path が空の場合は同名サービスの複数バージョンが全て重複扱いになっていた。
      (service_name, datetime) に変更して時刻ベースで重複排除する。
    """
    if not event_log_text or not event_log_text.strip():
        return []

    entries = []
    seen = set()  # (service_name, datetime) で重複除外（同名・同時刻の重複防止）

    for block in _7045_EVENT_BLOCK_RE.split(event_log_text):
        if not block.strip():
            continue

        date_m    = re.search(r"Date:\s*(\S+)", block)
        # サービス名: 英語 / 日本語 / 中国語（簡体字）に対応
        svcname_m = re.search(
            r"(?:Service Name|サービス名|ServiceName|服务名称)[:：]\s*([^\r\n]+)", block, re.I
        )
        # ImagePath: 英語 / 日本語（スペース区切り） / 中国語に対応
        # 日本語 Windows のフィールド名は「サービス ファイル名:」
        # （「サービス」と「ファイル名」の間にスペース1つ、「ファイル名」は1単語）
        imgpath_m = re.search(
            r"(?:Image Path|File Name|イメージ[\s　]*パス|ImagePath"
            r"|サービス[\s　]+ファイル名"             # 日本語 Windows（ファイル名は1単語）
            r"|服务文件名)[:：]\s*([^\r\n]+)",
            block, re.I
        )
        # アカウント名: 英語 / 日本語（スペース区切り） / 中国語に対応
        # 日本語 Windows のフィールド名は「サービス アカウント:」
        account_m = re.search(
            r"(?:Account Name|アカウント名|ServiceAccount"
            r"|サービス[\s　]+アカウント"              # 日本語 Windows
            r"|服务账户)[:：]\s*([^\r\n\x00]+)",
            block, re.I
        )

        if not (date_m and svcname_m):
            continue

        svc  = svcname_m.group(1).strip()
        img  = imgpath_m.group(1).strip().strip('"') if imgpath_m else ""
        acc  = account_m.group(1).strip().rstrip("\x00") if account_m else ""
        dt   = date_m.group(1).strip()

        # 重複除外: 同一サービス名 + 同一日時 のみ除外
        # （同名サービスが複数バージョンで再インストールされる場合は別エントリとして残す）
        key = (svc.lower(), dt)
        if key in seen:
            continue
        seen.add(key)

        entries.append({
            "datetime":     dt,
            "service_name": svc,
            "image_path":   img,
            "account_name": acc,
        })

    # 日時昇順でソート
    entries.sort(key=lambda x: x.get("datetime", ""))
    return entries


def _detect_av_vendor(path: str) -> str:
    """
    ファイルパスからAVベンダ名を推定する。
    将来のVT連携時にベンダ情報をメタデータとして付与するために使用。
    """
    pl = path.lower()
    if "windows defender" in pl or "microsoft antimalware" in pl:
        return "Windows Defender"
    if "eset" in pl:
        return "ESET"
    if "trend micro" in pl or "trendmicro" in pl:
        return "Trend Micro"
    if "kaspersky" in pl:
        return "Kaspersky"
    if "symantec" in pl or "norton" in pl:
        return "Symantec/Norton"
    if "mcafee" in pl:
        return "McAfee"
    if "sophos" in pl:
        return "Sophos"
    if "crowdstrike" in pl:
        return "CrowdStrike"
    if "sentinelone" in pl:
        return "SentinelOne"
    if "malwarebytes" in pl:
        return "Malwarebytes"
    if "avast" in pl or "avg\\" in pl:
        return "Avast/AVG"
    if "avira" in pl:
        return "Avira"
    if "bitdefender" in pl:
        return "Bitdefender"
    if "f-secure" in pl or "fsecure" in pl:
        return "F-Secure"
    if "qualys" in pl:
        return "Qualys"
    if "cylance" in pl:
        return "Cylance"
    return "Unknown AV"


# AV検疫フォルダの汎用パターン（report_CheckPC.py の quarantinefilelist ロジックを継承）
# ベンダ固有パスとすべてのベンダに共通する汎用パターンを網羅する
_AV_QUARANTINE_PATTERNS = [
    # 汎用（ベンダ問わず "quarantine" を含むフォルダ）
    re.compile(r".*\\quarantine\\.*", re.I),
    re.compile(r".*\\quarantinebackup\\.*", re.I),
    re.compile(r".*\\infected\\.*", re.I),
    # ESET
    re.compile(r".*\\eset\\.*\\quarantine\\.*", re.I),
    re.compile(r".*\\eset security\\quarantine\\.*", re.I),
    # Trend Micro
    re.compile(r".*\\trend micro\\.*\\quarantine\\.*", re.I),
    # Kaspersky（検疫DBフォルダ）
    re.compile(r".*\\kaspersky lab\\.*\\qb\\.*", re.I),
    re.compile(r".*\\kaspersky\\.*\\quarantine\\.*", re.I),
    # Symantec / Norton
    re.compile(r".*\\symantec\\.*\\quarantine\\.*", re.I),
    re.compile(r".*\\norton.*\\quarantine\\.*", re.I),
    # McAfee
    re.compile(r".*\\mcafee\\.*\\quarantine\\.*", re.I),
    # Sophos
    re.compile(r".*\\sophos\\.*\\quarantine\\.*", re.I),
    # Malwarebytes
    re.compile(r".*\\malwarebytes\\.*\\quarantine\\.*", re.I),
    # Avast / AVG
    re.compile(r".*\\avast.*\\chest\\.*", re.I),
    re.compile(r".*\\avg.*\\quarantine\\.*", re.I),
    # F-Secure
    re.compile(r".*\\f-secure\\.*\\quarantine\\.*", re.I),
    # CrowdStrike
    re.compile(r".*\\crowdstrike\\.*\\quarantine\\.*", re.I),
    # SentinelOne
    re.compile(r".*\\sentinelone\\.*\\quarantine\\.*", re.I),
    # Cylance
    re.compile(r".*\\cylance\\.*\\quarantine\\.*", re.I),
    # Windows Defender の検疫フォルダ（Eventlogとは別に Directory セクションにも出る）
    re.compile(r"c:\\programdata\\microsoft\\windows defender\\quarantine\\.*", re.I),
]


# AV検疫パスの高速判定用キーワード（substring 事前チェック）
# _AV_QUARANTINE_PATTERNS の全パターンはいずれか必ずこのキーワードを含む。
# path を lower() にして一致確認し、含まれなければ即 False を返す。
# 2,137,401件 × 20パターン の正規表現マッチを 5x 削減する最重要最適化。
_QUARANTINE_KEYWORDS = frozenset(['quarantine', 'infected', '\\qb\\', 'chest'])


def _is_quarantine_path(path: str) -> bool:
    """パスがAV検疫フォルダに該当するか判定。
    まず小文字化した path に対して高速な部分文字列検索を行い、
    いずれのキーワードも含まれなければ即座に False を返す。
    含まれる場合のみ正規表現でベンダ判定を行う。
    """
    pl = path.lower()
    if not any(kw in pl for kw in _QUARANTINE_KEYWORDS):
        return False
    for pat in _AV_QUARANTINE_PATTERNS:
        if pat.match(pl):
            return True
    return False


def parse_rdp_1024(event_log_text: str) -> list:
    """
    Eventlog_TerminalServices-RDPClient_Operational_1024_*.txt をパースする。
    EventID 1024 = RDP クライアントが外部サーバーに接続を試みたイベント。
    接続先サーバー名・日時・ユーザー名を抽出する。

    対応フォーマット:
      日本語: 「RDP ClientActiveX がサーバー (hostname) に接続しようとしています」
      英語:   「RDP ClientActiveX is attempting to connect to server (hostname)」
              「RDP ClientActiveX is connecting to server (hostname)」

    返り値: list of dict
        datetime    : イベント日時
        server      : 接続先サーバー名またはIPアドレス
        user        : 接続ユーザー名（User Name フィールド）
        computer    : 送信元コンピューター名
    """
    if not event_log_text or not event_log_text.strip():
        return []

    # JP/EN 両方のサーバー名抽出パターン
    _SERVER_RE = re.compile(
        r"(?:"
        r"がサーバー\s*\(([^)\x00\r\n]+)\)"   # JP: がサーバー (hostname)
        r"|"
        r"(?:connect(?:ing)?\s+to|attempting\s+to\s+connect\s+to)"
        r"\s+(?:server\s+)?\(([^)\x00\r\n]+)\)"  # EN: connecting to server (hostname)
        r")",
        re.I
    )

    entries = []
    seen = set()
    blocks = re.split(r"(?=Event\[\d+\])", event_log_text)

    for block in blocks:
        if not block.strip():
            continue
        date_m = re.search(r"Date:\s*(\S+)", block)
        user_m = re.search(r"User Name:\s*([^\r\n\x00]+)", block)
        comp_m = re.search(r"Computer:\s*([^\r\n\x00]+)", block)
        srv_m  = _SERVER_RE.search(block)

        if not date_m or not srv_m:
            continue

        server = (srv_m.group(1) or srv_m.group(2) or "").strip().rstrip("\x00").strip()
        if not server:
            continue

        dt   = date_m.group(1).strip()
        user = (user_m.group(1).strip().rstrip("\x00") if user_m else "")
        comp = (comp_m.group(1).strip().rstrip("\x00") if comp_m else "")

        key = (dt, server)
        if key in seen:
            continue
        seen.add(key)

        entries.append({
            "datetime": dt,
            "server":   server,
            "user":     user,
            "computer": comp,
        })

    return entries


def parse_bits_jobs(text: str) -> list:
    """
    "--BITS JOB--" ブロック（bitsadmin /list /allusers /verbose の出力）を
    パースして BITS ジョブの一覧を返す。

    BITS（Background Intelligent Transfer Service）は正規の更新配信に使われるが、
    攻撃者によるペイロードダウンロード・永続化（T1197）にも悪用される。
    特に NOTIFICATION COMMAND LINE が "none" 以外の場合、ジョブ完了時に
    任意コマンドが実行されるため永続化の典型的手口となる。

    返り値: list of dict
        guid          : ジョブ GUID
        display       : ジョブ表示名（DISPLAY）
        type          : ジョブ種別（DOWNLOAD / UPLOAD 等）
        state         : 状態（TRANSFERRED / TRANSFERRING / SUSPENDED / ERROR 等）
        owner         : 所有者（DOMAIN\\user）
        creation_time : 作成日時
        url           : ダウンロード/アップロード元 URL（JOB FILES の左辺）
        local_file    : ローカル保存先パス（JOB FILES の右辺）
        notify_cmd    : 完了時通知コマンド（NOTIFICATION COMMAND LINE）。
                        "none" 以外は T1197 の強い疑い
        integrity     : 所有者の MIC 整合性レベル
        elevated      : 所有者が昇格済みか（true/false）
    """
    if not text or not text.strip():
        return []
    # bitsadmin が "Listed 0 job(s)." を返す場合はジョブなし
    if re.search(r"Listed\s+0\s+job\(s\)", text, re.I):
        return []

    entries = []
    seen = set()
    # 各ジョブは "GUID: {....}" で始まる
    blocks = re.split(r"(?=GUID:\s*\{)", text)
    for block in blocks:
        gm = re.search(r"GUID:\s*(\{[0-9A-Fa-f\-]+\})", block)
        if not gm:
            continue
        guid = gm.group(1)

        def _grab(pat, default=""):
            m = re.search(pat, block, re.I)
            return m.group(1).strip() if m else default

        display   = _grab(r"DISPLAY:\s*'([^']*)'")
        jtype     = _grab(r"\bTYPE:\s*(\S+)")
        state     = _grab(r"\bSTATE:\s*(\S+)")
        owner     = _grab(r"\bOWNER:\s*(\S+)")
        creation  = _grab(r"CREATION TIME:\s*([\d/]+\s+[\d:]+)")
        notify    = _grab(r"NOTIFICATION COMMAND LINE:\s*([^\r\n]+)")
        integrity = _grab(r"owner MIC integrity level:\s*([^\r\n]+)")
        elevated  = _grab(r"owner elevated\s*\?\s*([^\r\n]+)")

        url = local = ""
        fm = re.search(r"(\S+://\S+)\s*->\s*([^\r\n]+)", block)
        if fm:
            url   = fm.group(1).strip()
            local = fm.group(2).strip()

        if guid in seen:
            continue
        seen.add(guid)

        entries.append({
            "guid":          guid,
            "display":       display,
            "type":          jtype,
            "state":         state,
            "owner":         owner,
            "creation_time": creation,
            "url":           url,
            "local_file":    local,
            "notify_cmd":    notify,
            "integrity":     integrity,
            "elevated":      elevated,
        })

    return entries


def parse_inbound_rdp(eid21_text: str = "", eid1149_text: str = "") -> list:
    """
    着信 RDP（リモートからの RDP ログオン）イベントを構造化する（N-1）。

    パイプライン既存の rdp_1024 は「自端末→外部」の外向き RDP（RDPClient）だが、
    本関数は「外部→自端末」の着信 RDP を対象とする。標的型侵入では外部 IP からの
    着信 RDP（特に外国 IP）が最重要の侵入痕跡であり、外向きログだけでは取りこぼす。

    対象イベント:
      EID 21   : TerminalServices-LocalSessionManager/Operational
                 「セッション ログオンに成功しました」。Description に
                 ユーザー / セッション ID / ソース ネットワーク アドレス を含む。
      EID 1149 : TerminalServices-RemoteConnectionManager/Operational
                 「ユーザー認証に成功しました」。User/Domain/Source Network Address。

    返り値: list of dict
        datetime   : イベント日時
        event_id   : "21" or "1149"
        user       : ログオンユーザー（DOMAIN\\user）
        session_id : セッション ID（EID 21 のみ）
        source_ip  : 接続元ネットワークアドレス（"ローカル"/console は除外）
    """
    entries = []
    seen = set()

    def _parse_blocks(text: str, eid: str):
        if not text or not text.strip():
            return
        for block in re.split(r"(?=Event\[\d+\])", text):
            if "Event[" not in block:
                continue
            # UTF-16 由来の null バイトを除去（"ローカル\x00" 等の取りこぼし防止）
            block = block.replace("\x00", "")
            dm = re.search(r"Date:\s*(\S+)", block)
            datetime_ = dm.group(1) if dm else ""
            # ソース ネットワーク アドレス / Source Network Address
            sm = re.search(
                r"(?:ソース\s*ネットワーク\s*アドレス|Source\s*Network\s*Address)\s*[:：]\s*([^\r\n]+)",
                block, re.I,
            )
            source_ip = sm.group(1).strip() if sm else ""
            # コンソール/ローカルログオンは着信ではないため除外
            if not source_ip or source_ip in ("ローカル", "Local", "LOCAL", "local"):
                continue
            # ユーザー（DOMAIN\user 形式。ヘッダの "User: S-1-5-18"(SID) を避けるため
            # バックスラッシュを含むものに限定する）
            um = re.search(
                r"(?:ユーザー|User|ユーザ)\s*[:：]\s*([^\r\n]*\\[^\r\n]+)",
                block, re.I,
            )
            user = um.group(1).strip() if um else ""
            # EID 1149 は User/Domain が分離している場合がある
            if not user:
                dom = re.search(r"(?:ドメイン|Domain)\s*[:：]\s*([^\r\n]+)", block, re.I)
                usr = re.search(r"(?:ユーザー|User|ユーザ)\s*[:：]\s*([^\r\n]+)", block, re.I)
                if dom and usr:
                    user = f"{dom.group(1).strip()}\\{usr.group(1).strip()}"
            sid_m = re.search(r"(?:セッション\s*ID|Session\s*ID)\s*[:：]\s*(\d+)", block, re.I)
            session_id = sid_m.group(1) if sid_m else ""

            key = (datetime_, source_ip, eid)
            if key in seen:
                continue
            seen.add(key)
            entries.append({
                "datetime":   datetime_,
                "event_id":   eid,
                "user":       user,
                "session_id": session_id,
                "source_ip":  source_ip,
            })

    _parse_blocks(eid21_text, "21")
    _parse_blocks(eid1149_text, "1149")
    return entries


# UserAssist KNOWNFOLDERID → 友好パス（N-5）
_UA_KNOWNFOLDER = {
    "1AC14E77-02E7-4E5D-B744-2EB1AE5198B7": r"C:\Windows\System32",
    "D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27": r"C:\Windows\SysWOW64",
    "F38BF404-1D43-42F2-9305-67DE0B28FC23": r"C:\Windows",
    "6D809377-6AF0-444B-8957-A3773F02200E": r"C:\Program Files",
    "7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E": r"C:\Program Files (x86)",
    "905E63B6-C1BF-494E-B29C-65B732D3D21A": r"C:\Program Files",
    "0762D272-C50A-4BB0-A382-697DCD729B80": r"C:\Users",
    "374DE290-123F-4565-9164-39C4925E467B": r"%USERPROFILE%\Downloads",
    "18989B1D-99B5-455B-841C-AB7C74E4DDFC": r"%USERPROFILE%\Videos",
    "33E28130-4E1E-4676-835A-98395C3BC3BB": r"%USERPROFILE%\Pictures",
    "A77F5D77-2E2B-44C3-A6A2-ABA601054A51": r"%APPDATA%\Microsoft\Windows\Start Menu\Programs",
    "B97D20BB-F46A-4C97-BA10-5E3608430854": r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
}


def parse_userassist(reg_text: str) -> list:
    """
    UserAssist レジストリエクスポート（*.reg）を解析する（N-5）。

    UserAssist は GUI（Explorer）から起動されたプログラム/ショートカットの
    実行痕跡を記録する。値名は ROT13 エンコードされ、KNOWNFOLDERID GUID で
    パスが表現される。本関数で復号・解決し、実行パス・実行回数・最終実行日時を返す。

    返り値: list of dict
        path      : 実行されたプログラムのパス（KNOWNFOLDERID 解決済み）
        run_count : 実行回数（hex オフセット4の DWORD）
        last_run  : 最終実行日時（hex オフセット60の FILETIME → "YYYY-MM-DD HH:MM:SS"）
    """
    import codecs as _codecs
    import struct as _struct
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz

    if not reg_text or "UserAssist" not in reg_text:
        return []

    def _filetime(b: bytes) -> str:
        if len(b) < 68:
            return ""
        ft = _struct.unpack("<Q", b[60:68])[0]
        if ft == 0:
            return ""
        try:
            return (_dt(1601, 1, 1, tzinfo=_tz.utc)
                    + _td(microseconds=ft / 10)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return ""

    entries = []
    seen = set()
    # 複数行 hex の継続（末尾 '\'）を結合
    joined = re.sub(r"\\\s*\n\s*", "", reg_text)
    for m in re.finditer(r'"([^"]+)"=hex:([0-9a-fA-F,]*)', joined):
        rawname, hexs = m.group(1), m.group(2)
        name = _codecs.decode(rawname, "rot_13").replace("\\\\", "\\")
        # 制御エントリ（セッション集計）は除外
        if name.startswith("UEME_CTLSESSION") or name.startswith("UEME_CTLCUACount"):
            continue
        if "!" in name and "\\" not in name:
            disp = name  # UWP アプリ ID
        else:
            gm = re.match(r"\{([0-9A-Fa-f-]+)\}\\(.+)", name)
            if gm:
                root = _UA_KNOWNFOLDER.get(gm.group(1).upper(), "{" + gm.group(1) + "}")
                disp = root + "\\" + gm.group(2)
            else:
                disp = name
        try:
            b = bytes(int(x, 16) for x in hexs.split(",") if x.strip())
        except ValueError:
            b = b""
        run = _struct.unpack("<I", b[4:8])[0] if len(b) >= 8 else 0
        last = _filetime(b)
        if disp in seen:
            continue
        seen.add(disp)
        entries.append({"path": disp, "run_count": run, "last_run": last})
    return entries


def parse_av_quarantine(defender_event_log: str = "", directory_text: str = "") -> list:
    """
    全AVベンダの検知・隔離情報を統合してリスト化する。

    情報源:
      1. Eventlog_WindowsDefender_Operational_1116_*.txt
         → 脅威名・パス・日時が明示的に取得できる最も信頼できる情報源
      2. CheckPC の 15. Check Directory セクション
         → ESET/Trend Micro/Kaspersky 等、Defender以外のAVの検疫フォルダ内ファイル
         → ベンダ固有ログが取れない場合でも「検疫フォルダにファイルがある」事実を記録
         → 将来VT連携でのハッシュ照合起点として使用（TODO）

    返り値: list of dict
        source        : "defender_eventlog" | "directory_scan"
        vendor        : 推定AVベンダ名
        datetime      : 日時（directory_scan の場合はファイルの更新日時）
        threat_name   : 脅威名（defender_eventlog のみ。directory_scan は空）
        path          : 検知/隔離ファイルのパス
        size          : ファイルサイズ（directory_scan のみ）
        severity      : 重大度（defender_eventlog のみ）
        note          : 補足情報
    """
    entries = []
    seen = set()  # (source, path) で重複除外

    # ── 1. Defender Eventlog (1116) ─────────────────────────
    if defender_event_log:
        event_blocks = re.split(r"(?=Event\[\d+\])", defender_event_log)
        for block in event_blocks:
            if not block.strip():
                continue

            date_m = re.search(r"Date:\s*(\S+)", block)
            # 修正: 旧正規表現は最初に出現する "Name:" (="Log Name:" や
            # "User Name:" というヘッダ行) にマッチしてしまい、本来の
            # 脅威名 (Description 内の "\tName: <脅威名>") を取得できていなかった。
            # 行頭の空白直後に Name:/名前: が続く行のみを対象にする。
            name_m = re.search(r"^[ \t]+(?:名前|Name|���O)[:：]\s*([^\r\n]+)", block, re.MULTILINE)
            path_m = re.search(r"(?:パス|Path|���X)[:：]\s*(?:file:_|file:)?([^\r\n;|]+)", block)
            sev_m  = re.search(r"(?:重大度|Severity|(?:�d���x))[:：]\s*([^\r\n]+)", block)
            cat_m  = re.search(r"(?:カテゴリ|Category|(?:�J�e�S��))[:：]\s*([^\r\n]+)", block)
            act_m  = re.search(r"(?:アクション|Action)[:：]\s*([^\r\n]+)", block)
            # T-DEF1（v3.57・16-D）: Process Name（検知時の実行プロセス）を抽出。
            # フィールドラベル自体は wevtutil の構造化サブフィールド名のため
            # ロケールに関わらず英語表記（値のみがOSロケールで局所化される。
            # 簡体字中国語ロケール実データ(HOST-REF-11)で "Process Name:" が
            # 英語ラベルのまま出力されることを確認済み）。
            proc_m = re.search(r"Process Name[:：]\s*([^\r\n]+)", block)

            if not date_m:
                continue

            path_val = path_m.group(1).strip().rstrip(";") if path_m else ""
            name_val = name_m.group(1).strip() if name_m else ""

            # URL から threat_name / path を補完（文字化け対策）
            url_m = re.search(r"name=([^&\s\r\n]+)", block)
            if url_m:
                name_val = url_m.group(1)
            if not path_val or "\x00" in path_val or "?" in path_val[:5]:
                path_in_url = re.search(r"file:_([^\r\n;|]+)", block)
                if path_in_url:
                    path_val = path_in_url.group(1).strip()

            key = ("defender_eventlog", path_val)
            if key in seen:
                continue
            seen.add(key)

            entries.append({
                "source":       "defender_eventlog",
                "vendor":       "Windows Defender",
                "datetime":     date_m.group(1).strip(),
                "threat_name":  name_val,
                "path":         path_val,
                "process_name": proc_m.group(1).strip() if proc_m else "",
                "size":         "",
                "severity":     sev_m.group(1).strip() if sev_m else "",
                "note":         cat_m.group(1).strip() if cat_m else "",
            })

    # ── 2. Directory セクションの検疫フォルダスキャン ────────
    if directory_text:
        current_dir = ""
        dir_re = re.compile(
            r"(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2})\s+([\d,]+)\s+(.+)$"
        )
        for line in directory_text.replace("\r\n", "\n").split("\n"):
            for marker in ("のディレクトリ", "Directory of", "的目录", "디렉터리"):
                if marker in line:
                    current_dir = line.replace(marker, "").strip()
                    break
            if "<DIR>" in line or not current_dir:
                continue

            m = dir_re.match(line)
            if not m:
                continue

            fname = m.group(3).strip()
            fpath = os.path.join(current_dir, fname).replace("/", "\\")

            if not _is_quarantine_path(fpath):
                continue

            key = ("directory_scan", fpath)
            if key in seen:
                continue
            seen.add(key)

            entries.append({
                "source":       "directory_scan",
                "vendor":       _detect_av_vendor(fpath),
                "datetime":     m.group(1).strip(),
                "threat_name":  "",   # ベンダ固有ログなしでは不明（VT照合で補完予定）
                "path":         fpath,
                "size":         m.group(2).replace(",", ""),
                "severity":     "",
                "note":         "検疫フォルダ内ファイル。脅威名はVT照合で補完予定",
            })

    # 日時昇順でソート（Defenderのeventlogとdir scanを混在させてタイムラインを統一）
    entries.sort(key=lambda x: x.get("datetime", ""))
    return entries


# 後方互換のエイリアス（既存の呼び出し箇所がある場合のため）
def parse_defender_quarantine(event_log_text: str) -> list:
    return parse_av_quarantine(defender_event_log=event_log_text)


def _normalized_stamp_from_filename(filename: str, prefix: str) -> str:
    base = os.path.basename(filename)
    stem = os.path.splitext(base)[0]
    suffix = stem[len(prefix):] if stem.startswith(prefix) else stem
    return re.sub(r"[^0-9]", "", suffix)


def _select_companion_file(directory: str, prefix: str, datestamp: str) -> tuple[str, str, list]:
    try:
        candidates = sorted(
            f for f in os.listdir(directory)
            if f.startswith(prefix) and os.path.isfile(os.path.join(directory, f)))
    except OSError:
        return "", "directory_unreadable", []
    exact = [f for f in candidates
             if _normalized_stamp_from_filename(f, prefix) == re.sub(r"[^0-9]", "", datestamp or "")]
    if len(exact) == 1:
        return os.path.join(directory, exact[0]), "hostname_timestamp_exact", candidates
    if len(exact) > 1:
        return "", "ambiguous_exact_matches", candidates
    if len(candidates) == 1:
        return os.path.join(directory, candidates[0]), "single_candidate_fallback", candidates
    if candidates:
        return "", "ambiguous_candidates", candidates
    return "", "not_found", []


def parse_eventlog_files(directory: str, hostname: str, datestamp: str,
                         return_meta: bool = False):
    """Read companion logs using host+normalized collection timestamp.

    The old hostname-only first-match behavior could mix separate collections.
    Ambiguous files are now left unassociated and exposed as quality metadata.
    """
    event_data, quality = {}, {}
    patterns = {
        "security_1102": "Eventlog_Security_1102",
        "system_7045": "Eventlog_System_7045",
        "system_104": "Eventlog_System_104",
        "task_106": "Eventlog_TaskScheduler_Operational_106",
        "task_140": "Eventlog_TaskScheduler_Operational_140",
        "task_141": "Eventlog_TaskScheduler_Operational_141",
        "rdp_1024": "Eventlog_TerminalServices-RDPClient_Operational_1024",
        "rdp_in_21": "Eventlog_TerminalServices-LocalSessionMangaer_Operational_21",
        "rdp_in_1149": "Eventlog_TerminalServices-RemoteConnectionMangaer_Operational_1149",
        "defender_1116": "Eventlog_WindowsDefender_Operational_1116",
    }
    for key, category in patterns.items():
        prefix = f"{category}_{hostname}_"
        path, associated_by, candidates = _select_companion_file(directory, prefix, datestamp)
        if path:
            text = read_file(path)
            event_data[key] = text
            q = classify_event_text(text, max_records=1000)
            q.update({"source_file": os.path.basename(path), "associated_by": associated_by,
                      "sha256": sha256_file(path), "size": os.path.getsize(path),
                      "candidate_count": len(candidates)})
        else:
            q = {"evidence_state": NOT_COLLECTED, "record_count": 0,
                 "possibly_truncated": False, "coverage_note": associated_by,
                 "source_file": "", "associated_by": associated_by,
                 "candidate_count": len(candidates), "candidates": candidates}
        quality[key] = q
    return (event_data, quality) if return_meta else event_data


# ─────────────────────────────────────────────────────────────
# メイン構造化処理
# ─────────────────────────────────────────────────────────────
def parse(checkpc_path: str,
          appcompat_csv_path: str = None) -> dict:
    """
    CheckPC_*.txt を受け取り、構造化 JSON dict を返す。
    """
    text, encoding_info = read_file_with_info(checkpc_path)
    sections, section_split_meta = split_sections(text, return_meta=True)
    others   = split_others(sections.get("others", ""))

    # ホスト名・日付スタンプを取得
    # 修正(2026-06-12): ファイル名の正規表現 CheckPC_([^_]+)_(\d+)\.
    # は、タイムスタンプ部分に曜日名（Shift-JIS マルチバイト文字）が
    # 混入したファイル名（例: CheckPC_ASTER_20260608-日曜23440774.txt）
    # を os.fsencode() で取り出すと surrogate escape になり、\d+ が
    # マッチしないため hostname="UNKNOWN" になっていた。
    # 修正方針:
    #   hostname: ファイル名への依存をやめ、CheckPC 本文の
    #             COMPUTERNAME= 行から取得（確実・文字化けなし）
    #   datestamp: ファイル名の hostname 以降のバイト列から数字のみ
    #              を抽出した文字列を meta 記録用に使用
    base = os.path.basename(checkpc_path)

    # hostname を本文の environment セクションから抽出
    env_text = sections.get("environment", "")
    cn_m = re.search(r"^COMPUTERNAME=(.+)$", env_text, re.M)
    if cn_m:
        hostname = cn_m.group(1).strip()
    else:
        # フォールバック: ファイル名の2番目の '_' 区切りフィールド
        fn_m = re.match(r"CheckPC_([^_]+)_", base)
        hostname = fn_m.group(1) if fn_m else "UNKNOWN"

    # datestamp: ファイル名の hostname 以降から数字のみ抽出 (meta 記録用)
    # surrogate escape で渡ってきても re は bytes ベースで処理できないため
    # encode(surrogateescape) → 数字バイトだけ取り出す
    try:
        base_bytes = base.encode("utf-8", "surrogateescape")
        prefix_bytes = f"CheckPC_{hostname}_".encode("utf-8", "surrogateescape")
        if base_bytes.startswith(prefix_bytes):
            stamp_bytes = base_bytes[len(prefix_bytes):].rstrip(b".txt")
        else:
            stamp_bytes = base_bytes
        import re as _re
        datestamp = _re.sub(rb"[^\d]", b"", stamp_bytes).decode("ascii")
    except Exception:
        datestamp = re.sub(r"[^\d]", "", base)

    # CheckPC バージョン
    major, minor, patch = extract_batch_version(sections.get("metadata", "") + sections.get("environment", ""))

    # T-DIR0（v3.57）: directory の生テキストとパース結果を変数化。
    # 「セクション見出しは存在するのに0件抽出」という構造的異常の検出
    # （後段の parse_warnings 判定）に再利用する。
    _directory_raw    = sections.get("directory", "")
    _directory_parsed = parse_directory(_directory_raw)

    result = {
        "meta": {
            "hostname":           hostname,
            "datestamp":          datestamp,
            "checkpc_version":    f"{major}.{minor}.{patch}",
            "source_file":        os.path.abspath(checkpc_path).encode("utf-8", "replace").decode("utf-8"),
            "parser_version":     ANALYSIS_SCHEMA_VERSION,
            "pipeline_version":   PIPELINE_VERSION,
            "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
            "collection_id":      sha256_file(checkpc_path),
            "input_sha256":       sha256_file(checkpc_path),
            "encoding":           encoding_info,
            "section_split":      section_split_meta,
            "collector_profile":  get_collector_profile(f"{major}.{minor}.{patch}"),
        },
        "sections": {
            "persistence_reg":    parse_persistence_reg(sections.get("persistence_reg", "")),
            "association_exe":    parse_registry_dump(sections.get("association_exe", ""), "association_exe"),
            "uac_bypass":         parse_registry_dump(sections.get("uac_bypass", ""), "uac_bypass"),
            "startup_folder":     parse_startup_folder(
                                      sections.get("startup_folder", "") +
                                      "\n" + others.get("office_startup", "")
                                  ),
            "active_setup":       parse_registry_dump(sections.get("active_setup", ""), "active_setup"),
            "task_scheduler":     parse_task_scheduler(sections.get("task_scheduler", "")),
            "dns_cache":          parse_dns_cache(sections.get("dns_cache", "")),
            "netstat":            parse_netstat(sections.get("netstat", "")),
            "tasklist":           parse_tasklist(sections.get("tasklist", "")),
            "service":            parse_service(
                                      sections.get("service", ""),
                                      sections.get("service_registry", "")
                                  ),
            "directory":          _directory_parsed,
            "prefetch":           parse_prefetch(sections.get("prefetch", "")),
            "recent_behavior":    parse_recent_behavior(sections.get("recent_behavior", "")),
            "com_persistence":    parse_registry_dump(sections.get("com_persistence", ""), "com_persistence"),
            "volume_serial":      sections.get("volume_serial", ""),
            "bitlocker":          sections.get("bitlocker", ""),
            "shadow_copy":        sections.get("shadow_copy", ""),
            "boot_config":        sections.get("boot_config", ""),
            "antivirus":          sections.get("antivirus", ""),
            "appcompat_flags":    sections.get("appcompat_flags", ""),  # raw text
            "appcompat_cache":    [],
            "ps_history":         parse_ps_history(others.get("ps_history", "")),
            "shortcut_link":      others.get("shortcut_link", ""),      # raw text
            "wmi":                parse_wmi_consumers(others.get("wmi", "")),
            "hosts":              parse_hosts(others.get("hosts", "")), # 構造化リスト (T-22)
            "psexec":             others.get("psexec", ""),             # raw text
            "rdp":                others.get("rdp", ""),                # raw text
            "bits":               others.get("bits", ""),               # raw text (StateIndex/BAM)
            "bits_jobs":          parse_bits_jobs(others.get("bits_job", "")),  # 構造化 (T-23: --BITS JOB--)
            "pending_rename":     others.get("pending_rename", ""),     # raw text
            "audit_policy":       others.get("audit_policy", ""),       # raw text
            "group_policies":     others.get("group_policies", ""),     # raw text
            "raw_environment":    sections.get("environment", ""),      # raw text
        },
        "event_logs": {},
        "evidence_quality": {"event_logs": {}, "companions": {}},
    }

    # AppCompatCache CSV（ShimCacheParser.py 出力）
    if appcompat_csv_path and os.path.exists(appcompat_csv_path):
        result["sections"]["appcompat_cache"] = parse_appcompat_cache_csv(
            read_file(appcompat_csv_path)
        )

    # EventLog ファイル（同一ディレクトリに存在すれば自動取込）
    input_dir = os.path.dirname(checkpc_path)
    result["event_logs"], result["evidence_quality"]["event_logs"] = parse_eventlog_files(
        input_dir, hostname, datestamp, return_meta=True)

    # T-17: system_7045 の raw テキストを構造化リストに変換して event_logs に上書き
    raw_7045 = result["event_logs"].get("system_7045", "")
    if raw_7045:
        result["event_logs"]["system_7045"] = parse_system_7045(raw_7045)
    else:
        result["event_logs"]["system_7045"] = []

    # T-20: rdp_1024 の raw テキストを構造化リストに変換して event_logs に上書き
    raw_rdp = result["event_logs"].get("rdp_1024", "")
    if raw_rdp:
        result["event_logs"]["rdp_1024"] = parse_rdp_1024(raw_rdp)
    else:
        result["event_logs"]["rdp_1024"] = []

    # N-1: 着信RDP（EID 21 / 1149）を構造化して event_logs["rdp_inbound"] に格納
    raw_21   = result["event_logs"].get("rdp_in_21", "")
    raw_1149 = result["event_logs"].get("rdp_in_1149", "")
    result["event_logs"]["rdp_inbound"] = parse_inbound_rdp(raw_21, raw_1149)

    for _eid, _key in (("106", "task_106"), ("140", "task_140"), ("141", "task_141")):
        _raw_task = result["event_logs"].get(_key, "")
        result["event_logs"][_key] = parse_task_event_text(_raw_task, _eid) if _raw_task else []

    # AV検疫情報を統合（Defender Eventlog + Directory セクションの検疫フォルダ）
    defender_raw = result["event_logs"].get("defender_1116", "")
    directory_raw = sections.get("directory", "")
    result["sections"]["defender_quarantine"] = parse_av_quarantine(
        defender_event_log=defender_raw,
        directory_text=directory_raw,
    )

    # N-5: UserAssist（GUI実行痕跡）。input_dir 内の UserAssist_*.reg を読み込む
    _ua_prefix = f"UserAssist_{hostname}_"
    _ua_path, _ua_by, _ua_candidates = _select_companion_file(input_dir, _ua_prefix, datestamp)
    if _ua_path:
        try:
            result["sections"]["userassist"] = parse_userassist(read_file(_ua_path))
            result["evidence_quality"]["companions"]["userassist"] = {
                "evidence_state": "OBSERVED", "source_file": os.path.basename(_ua_path),
                "associated_by": _ua_by, "sha256": sha256_file(_ua_path),
                "size": os.path.getsize(_ua_path),
            }
        except Exception as _ua_exc:
            result["sections"]["userassist"] = []
            result["evidence_quality"]["companions"]["userassist"] = {
                "evidence_state": "TRUNCATED_OR_INCOMPLETE", "associated_by": _ua_by,
                "coverage_note": f"UserAssist parse failed: {_ua_exc}",
            }
    else:
        result["sections"]["userassist"] = []
        result["evidence_quality"]["companions"]["userassist"] = {
            "evidence_state": "NOT_COLLECTED", "associated_by": _ua_by,
            "candidates": _ua_candidates,
        }

    # T-DIR0（v3.57）: 「セクション見出し(dirコマンド実行痕跡)は存在するのに
    # 抽出結果が0件」という構造的異常を検出し meta.parse_warnings に記録する。
    # parse_checkpc.py 自体は判定（スコアリング）を行わない設計方針のため、
    # ここでは事実（異常の有無）のみを記録し、可視化（MEDIUM表示等）は
    # analyze_section.py 側に委ねる。
    #
    # 【背景】 read_file() のエンコード誤判定（gb18030偏重バグ、上記
    # _pick_fallback_encoding 参照）により directory が常に0件になっていた
    # 実例を cab_tar.gz 添付データで確認したが、原因を問わず「見出しは
    # あるのに0件」という状態自体を検出できる汎用的な安全網として、
    # 発生要因（エンコード起因に限らない）に依存しない形で実装する。
    result["meta"]["parse_warnings"] = []
    if _directory_raw.strip() and "dir /a /r" in _directory_raw and not _directory_parsed:
        result["meta"]["parse_warnings"].append({
            "section": "directory",
            "message": (
                "directory セクションの見出し（dirコマンド実行痕跡）は"
                "検出されたが、エントリが1件も抽出されなかった。"
                "エンコーディング判定異常またはパーサ不整合の可能性。"
                "raw_environment/source_file を目視確認のこと。"
            ),
        })

    _collection_id = result["meta"]["collection_id"]
    for _section_name, _entries in result["sections"].items():
        if isinstance(_entries, list):
            assign_source_ids(_collection_id, _section_name, _entries)
    for _section_name, _entries in result["event_logs"].items():
        if isinstance(_entries, list):
            assign_source_ids(_collection_id, _section_name, _entries)

    annotate_parsed_document(result)
    return result


# ─────────────────────────────────────────────────────────────
# エントリポイント
# ─────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="CheckPC_*.txt をセクション別 JSON に構造化する。判定は行わない。"
    )
    ap.add_argument("input", help="CheckPC_*.txt のパス")
    ap.add_argument("-o", "--output", help="出力 JSON ファイルパス（省略時は自動命名）")
    ap.add_argument("--stdout", action="store_true", help="標準出力に JSON を出力")
    ap.add_argument("--appcompat-csv", help="ParsedAppCompatCache_*.csv のパス（省略時は自動検出）")
    args = ap.parse_args()

    if not os.path.exists(args.input):
        print(f"[ERROR] ファイルが見つかりません: {args.input}", file=sys.stderr)
        sys.exit(1)

    # AppCompatCache CSV の自動検出
    appcompat_csv = args.appcompat_csv
    if not appcompat_csv:
        candidate = args.input.replace("CheckPC", "ParsedAppCompatCache").replace(".txt", ".csv")
        if not os.path.exists(candidate):
            candidate = args.input.replace("CheckPC", "ParsedAppCompatCache")
        if os.path.exists(candidate):
            appcompat_csv = candidate

    result = parse(args.input, appcompat_csv)

    if args.stdout:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    # 出力ファイル名
    if args.output:
        out_path = args.output
    else:
        base = os.path.basename(args.input).replace("CheckPC", "parsed").replace(".txt", ".json")
        out_path = os.path.join(os.path.dirname(args.input), base)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    # サマリ出力
    s = result["sections"]
    print(f"[parse_checkpc] 完了: {out_path}")
    print(f"  ホスト名      : {result['meta']['hostname']}")
    print(f"  CheckPC Ver   : {result['meta']['checkpc_version']}")
    print(f"  永続化Reg     : {len(s['persistence_reg'])} エントリ")
    print(f"  タスクスケジュ: {len(s['task_scheduler'])} タスク")
    print(f"  DNSキャッシュ : {len(s['dns_cache'])} エントリ")
    print(f"  Netstat       : {len(s['netstat'])} 接続")
    print(f"  サービス      : {len(s['service'])} サービス")
    print(f"  ディレクトリ  : {len(s['directory'])} ファイル")
    print(f"  Prefetch      : {len(s['prefetch'])} .pf ファイル")
    print(f"  AppCompatCache: {len(s['appcompat_cache'])} エントリ")
    print(f"  EventLog      : {len(result['event_logs'])} ファイル")


if __name__ == "__main__":
    main()
