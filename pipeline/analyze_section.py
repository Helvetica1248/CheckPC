#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_section.py
parse_checkpc.py の出力 JSON を受け取り、セクション別に LLM で評価する。

Usage:
    python analyze_section.py <parsed.json> [--depth 1-4] [-o results.json]
    python analyze_section.py <parsed.json> --section netstat --depth 3
"""

import re
import sys
import json
import os
import argparse
import time
import threading
import hashlib
from typing import Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from openai import OpenAI
except ImportError:  # テスト/静的監査環境向け。実LLM実行時は依存導入必須。
    class OpenAI:  # pragma: no cover
        def __init__(self, *args, **kwargs):
            raise RuntimeError("openai パッケージが必要です。INSTALL.txt を参照してください。")

from section_prompts import (
    LEAN_IOCS_SECTIONS,
    get_prompt, get_system_prompt, get_level1_filters, LEVEL1_FILTERS
)

# v3.68: トークン予算・暫定プロファイル・IOC 共通化
from token_budget import (
    MAX_MODEL_LEN, CHUNK_SAFETY_MARGIN, CHAT_TEMPLATE_TOKENS,
    ENTRY_INDEX_TOKENS, est_tokens, input_budget, is_context_length_error,
    token_estimator_name, tokenizer_fingerprint,
)
from budget_profile import active_profile
import ioc_utils
import depth2_select
import directory_policy
from provenance import PlannedItem, DispositionLedger, REASON_LABELS
from llm_runtime import create_chat_completion, extract_llm_text
from prompt_safety import wrap_untrusted_evidence
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION
from pipeline_errors import ConfigurationError
from comparison_provenance import (
    COMPARISON_PROVENANCE_SCHEMA_VERSION, build_section_provenance,
    runtime_fingerprint, stage_indices, validate_section_provenance,
)
from source_id import (SOURCE_ID_ALGORITHM_VERSION, canonical_evidence, make_source_id)

# ─────────────────────────────────────────────────────────────
# 設定
# ─────────────────────────────────────────────────────────────
DEFAULT_VLLM_URL   = "http://localhost:8000/v1"
DEFAULT_MODEL      = "qwen25-coder-32b-q3"
DEFAULT_DEPTH      = 1   # v3.68: GUI(=1)/CHANGELOG v3.50 の意図に統一（旧=2）
REQUEST_TIMEOUT    = 300   # 秒

# N-4b: チャンク並列数（vLLM continuous batching を活用するスループット制御）。
# 既定=1（直列・従来挙動）。base117（A4500×2 / 40GB / max_model_len=16384）で
# CHECKPC_CHUNK_WORKERS=2/3/4 を実測し、15分以内かつタイムアウトが出ない最大値に
# 調整する。section_workers(=3) × CHUNK_MAX_WORKERS が同時リクエスト数の上限。
CHUNK_MAX_WORKERS = max(1, int(os.environ.get("CHECKPC_CHUNK_WORKERS", "1")))

# P1(v3.59): チャンク解析失敗時の自動再試行。1=有効（既定）/ 0=無効（従来動作）。
# 失敗チャンクを半分割して各1回だけ再送する（詳細は call_llm_chunked 内
# _call_chunk の docstring 参照）。
CHUNK_RETRY = max(0, int(os.environ.get("CHECKPC_CHUNK_RETRY", "1")))

# v3.68: transport retry（接続・タイムアウト）と coverage split（カバレッジ不足の
# 分割）を分離する（指示5）。CHUNK_RETRY を両方の意味へ流用しない。
#   transport retry: 同一入力を最大 N 回再送（接続エラー・タイムアウトのみ）
#   coverage split : 欠落対象だけを半分に分割し、singleton へ到達するまで最大 M 段
LLM_TRANSPORT_RETRY      = max(0, int(os.environ.get("CHECKPC_LLM_TRANSPORT_RETRY", "2")))
COVERAGE_MAX_SPLIT_DEPTH = max(0, int(os.environ.get("CHECKPC_COVERAGE_MAX_SPLIT_DEPTH", "5")))

# P3(v3.62): LEAN出力モード。1=LLM出力を判定価値のある情報に絞る
# （identifier短縮・構造化セクションのiocs決定論付与・CLEAN最小出力・
#   source_indexカバレッジ検証）。既定=0（従来動作）。
# A/B受け入れ条件（HIGH集合一致等）の合格後にデフォルトONへ切替予定。
# v3.66(提案11): 3ホスト計154件のエントリ単位裁定（HOST-REF-08/HOST-REF-11/
# HOST-REF-02）で正確性がFULL同等以上と確認されたため既定=1（採用）。
# CHECKPC_LEAN_OUTPUT=0 でいつでも従来動作（FULL）へ復帰可能。
# GUI からもジョブ単位で切替可（server.py の LEAN トグル / v3.66）。
LEAN_OUTPUT = max(0, int(os.environ.get("CHECKPC_LEAN_OUTPUT", "1")))

# 深度別 max_tokens
# depth=1: 1024tok に統一（③ 高速化修正）
#   Qwen2.5-Coder-32B Q3_K_M の生成速度 ≈17tok/sec
#   1536→1024 で 512tok 削減 → ≈30秒/ch の節約
#   depth=1 の簡易評価は JSON出力が 500〜700tok で収まるため 1024tok で十分
MAX_TOKENS = {
    "persistence_reg":    {1: 1024, 2: 1024, 3: 2048, 4: 2048},
    "association_exe":    {1: 1024, 2: 1024, 3: 1536, 4: 2048},
    "uac_bypass":         {1: 1024, 2: 1024, 3: 1536, 4: 2048},
    "active_setup":       {1: 1024, 2: 1024, 3: 1536, 4: 2048},
    "com_persistence":    {1: 1024, 2: 1024, 3: 1536, 4: 2048},
    "wmi":                {1: 1024, 2: 1536, 3: 1536, 4: 2048},
    "task_106":           {1: 1024, 2: 1024, 3: 1536, 4: 2048},
    "task_140":           {1: 1024, 2: 1024, 3: 1536, 4: 2048},
    "recent_behavior":    {1: 1024, 2: 1024, 3: 1536, 4: 2048},
    "task_scheduler":     {1: 1024, 2: 1024, 3: 2048, 4: 2048},
    "service":            {1: 1024, 2: 1024, 3: 1500, 4: 2048},
    "directory":          {1: 2048, 2: 2048, 3: 2048, 4: 2048},  # v3.68: d2 1500→2048（tok/件不足の是正）  # depth=1: 1536→2048（chunk_size 15と併せ truncation 防止）
    "dns_cache":          {1: 1024, 2: 1024, 3: 1500, 4: 2048},  # v3.68: d2 800→1024
    "netstat":            {1: 2048, 2: 2048, 3: 1500, 4: 2048},  # v3.68: d2 1024→2048  # 案A: depth1を1024→2048（chunk16→10と併せ truncation解消）
    "prefetch":           {1: 1024, 2: 1024, 3: 1024, 4: 1500},  # v3.68: d2 512→1024
    "startup_folder":     {1: 1024, 2: 1024, 3: 1500, 4: 2048},
    "defender_quarantine":{1: 1024, 2: 1024, 3: 1500, 4: 2048},
    "appcompat_cache":    {1: 1024, 2: 1024, 3: 1500, 4: 2048},
    "ps_history":         {1: 1024, 2: 1024, 3: 1500, 4: 2048},
    "hosts":              {1: 1024, 2: 1024, 3: 1500, 4: 2048},
    "system_7045":        {1: 1024, 2: 1024, 3: 1500, 4: 2048},
    "rdp_1024":           {1: 1024, 2: 1024, 3: 1500, 4: 2048},  # T-20: RDP外向き接続ログ
    "bits_jobs":          {1: 1024, 2: 1024, 3: 1500, 4: 2048},  # T-23: BITS ジョブ
    "security_1102":      {1:  512, 2:  512, 3:  512, 4:  512},
    "system_104":         {1:  512, 2:  512, 3:  512, 4:  512},
    "correlate":          {1:  800, 2: 2048, 3: 2048, 4: 4096},
}

# ── v3.68: depth>=2 用の固定表 CHUNK_SIZE は廃止した ──────────────────
# 旧 CHUNK_SIZE（directory=100, netstat=96, prefetch=80 等）は max_tokens と
# 独立に決まっていたため、depth=2 では 1件あたり 5〜51tok しか割り当たらず
# 全14セクションで必ず出力が切断されていた（v3.67 実測: FULL 50.3% / LEAN 6.8%
# が未評価）。depth>=2 のチャンクは resolve_chunk_plan() が
# 「出力予算 − チャンク固定費」と「実入力の逐次加算」の二段階で決める。
#
# depth=1 は現行の CHUNK_SIZE_DEPTH1 をそのまま上限として使い、FULL/LEAN とも
# チャンク境界を一切変更しない（v3.68-rc2 の互換条件）。
#
# depth=1 専用のチャンクサイズ。
#
# 修正: 旧設定（dns_cache=25, directory/appcompat_cache=100 等、上の CHUNK_SIZE と
# 共用）は「チャンク数を減らせば速い」という前提だったが、実データで検証したところ
# Qwen2.5-Coder-32B の depth=1 出力は 1エントリあたり 110〜160トークン
# （defender_quarantine はOneDriveパスが長く約240トークン）かかっており、
# 旧 chunk_size のままでは max_tokens に到達して JSON が閉じ括弧の手前で
# 打ち切られ、call_llm() が parse_error → 全エントリ [] 扱いになっていた
# （normal.dot/sysprep.exe/Defender検知4件など、HIGH判定済みの結果が
#  丸ごと握り潰されていたのはこれが原因）。
# MAX_TOKENS=1536 に対して 8エントリ/チャンク(=192トークン/エントリの余裕)を
# 基本とし、defender_quarantine のみ 5エントリ/チャンク(=307トークンの余裕)とする。
# depth=1 は Level1 フィルタ後の件数が少ない（今回の実データで最大42件）ため、
# チャンク数が増えても LLM 呼び出し回数は数回程度に収まる。
CHUNK_SIZE_DEPTH1 = {
    "persistence_reg":     8,
    "association_exe":     8,
    "uac_bypass":          8,
    "active_setup":        8,
    "com_persistence":     8,
    "wmi":                 6,
    "task_106":            6,
    "task_140":            6,
    "recent_behavior":    10,
    "task_scheduler":      8,
    "service":             8,
    "directory":           10,   # truncation対策: 15→10。長大パス(Storeパッケージ等)を
                                 # 含む15件で出力が2048tokを超え切断される問題を低減。
                                 # 併せて _salvage_truncated_entries で残存切断分も救出
                                 # （取りこぼし防止: 全件破棄→完了分は保持）
    "dns_cache":           8,
    "netstat":            10,   # 案A: 16→10（max_tokens 2048と併せ 205tok/entry確保。
                                #   旧16件×~130tok=~2080tok>1024で切断・解析不全が多発していた）
    "prefetch":            8,
    "appcompat_cache":     8,
    "startup_folder":      8,
    "defender_quarantine": 5,   # T-35: 3→5（79件→16ch。脅威名あり3件/chunk→5件/chunkでも判定精度維持）
    "ps_history":         15,   # コマンド1行あたりのトークンが少ないため多めに
    "hosts":              30,   # hosts行は短い
    "system_7045":         5,   # イベントブロックが長いため少なめ
    "rdp_1024":           20,   # T-20: 1行が短いため多めに詰める
    "bits_jobs":           5,   # T-23: 1ジョブの情報量が多いため少なめ
}

# ─────────────────────────────────────────────────────────────
# Level 1 絞り込み
# ─────────────────────────────────────────────────────────────
_LEVEL1_COMPILED_CACHE = {}

def _compiled_level1_filter(section: str):
    """Compile the section's OR policy once without changing rc6 semantics."""
    if section in _LEVEL1_COMPILED_CACHE:
        return _LEVEL1_COMPILED_CACHE[section]
    raw = list(get_level1_filters(section) or [])
    if not raw:
        compiled = None
    else:
        # Group every expression so anchors and alternation retain their original
        # meaning. ``__SIZE_ZERO__`` remains a literal marker exactly as in rc6.
        compiled = re.compile("|".join(f"(?:{expr})" for expr in raw), re.I)
    _LEVEL1_COMPILED_CACHE[section] = compiled
    return compiled

def entry_matches_level1(section: str, entry) -> bool:
    """Return the deterministic Level1 predicate.

    The canonical directory admission policy is broader than the M0/M1
    priority policy.  This keeps deep artifacts below known Temp roots visible
    as Tier-R candidates without allowing them to consume protected M1 slots.
    """
    if section == "directory":
        if directory_policy.is_root_os_managed_file(entry):
            return False
        if directory_policy.level1_admit(entry):
            return True
    compiled = _compiled_level1_filter(section)
    if compiled is None:
        return True
    if isinstance(entry, str):
        return bool(compiled.search(entry))
    if not isinstance(entry, dict):
        return False
    return any(bool(compiled.search(value))
               for value in entry.values() if isinstance(value, str))

def apply_level1_filter(section: str, entries: list) -> list:
    """Return entries matching the deterministic Level1 policy."""
    if not get_level1_filters(section):
        return entries
    return [e for e in entries if entry_matches_level1(section, e)]


_TASK140_VOLATILE_LINE_RE = re.compile(
    r"^\s*(?:Event\[\d+\]\s*[:：]?\s*|(?:Date|日時|TimeCreated)\s*[:：].*)$",
    re.IGNORECASE,
)
_TASK140_DESCRIPTION_LINE_RE = re.compile(
    r"^\s*(?:Description|説明|描述)\s*[:：]",
    re.IGNORECASE,
)


def _task140_semantic_key(entry) -> str:
    """Return a timestamp/index-independent EventID 140 grouping key.

    Only transport/event-position fields are removed.  Task text, SID/user,
    computer and the complete Description remain part of the key, so events
    with a different task, actor or message are never merged merely because
    they share the same Microsoft namespace.
    """
    if not isinstance(entry, dict):
        return str(entry)
    raw = entry.get("raw")
    if isinstance(raw, str) and raw.strip():
        lines = []
        in_description = False
        for line in raw.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
            clean = line.replace("\x00", "").rstrip()
            # Drop transport-position/time metadata only from the event header.
            # A task Description is attacker-controlled evidence and may itself
            # contain lines beginning with ``Date:`` or ``Event[n]``; those
            # lines must remain semantic so distinct evidence cannot collapse.
            if not in_description and _TASK140_VOLATILE_LINE_RE.match(clean):
                continue
            lines.append(clean)
            if not in_description and _TASK140_DESCRIPTION_LINE_RE.match(clean):
                in_description = True
        return "\n".join(lines).strip()

    # Defensive fallback for synthetic/unit inputs without raw text.  Keep all
    # semantic fields and remove only the time/identity metadata that is
    # expected to vary between repeated observations.
    semantic = {
        str(k): v for k, v in entry.items()
        if str(k) not in {"datetime", "source_id", "source_index", "_raw_source_index"}
    }
    return json.dumps(semantic, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), default=str)


def aggregate_task140_depth1(entries: list, source_indices: list = None) -> tuple[list, dict]:
    """Collapse repeated TaskScheduler EventID 140 observations for D1 only.

    The first observation remains the LLM binding representative.  All raw
    source IDs/indices and the observation window are retained in audit
    metadata; no group is classified or dropped by this function.
    """
    if not isinstance(entries, list) or not entries:
        return entries, {"raw_count": 0, "group_count": 0, "groups": []}
    if source_indices is None:
        source_indices = list(range(len(entries)))
    if len(source_indices) != len(entries):
        raise ValueError("task_140 source_indices length mismatch")

    grouped = {}
    for entry, raw_index in zip(entries, source_indices):
        key = _task140_semantic_key(entry)
        key_sha256 = hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()
        group = grouped.get(key)
        if group is None:
            group = {
                "representative": entry,
                "raw_indices": [],
                "source_ids": [],
                "datetimes": [],
                "semantic_key_sha256": key_sha256,
            }
            grouped[key] = group
        group["raw_indices"].append(int(raw_index))
        if isinstance(entry, dict):
            sid = str(entry.get("source_id") or "")
            if sid:
                group["source_ids"].append(sid)
            dt = str(entry.get("datetime") or "")
            if dt:
                group["datetimes"].append(dt)

    representatives = []
    audit_groups = []
    by_representative_source_id = {}
    for ordinal, group in enumerate(grouped.values()):
        representative = group["representative"]
        view = dict(representative) if isinstance(representative, dict) else representative
        datetimes = sorted(set(group["datetimes"]))
        samples = datetimes[:3]
        if len(datetimes) > 3 and datetimes[-1] not in samples:
            samples.append(datetimes[-1])
        if isinstance(view, dict):
            view["occurrence_count"] = len(group["raw_indices"])
            view["first_seen"] = datetimes[0] if datetimes else ""
            view["last_seen"] = datetimes[-1] if datetimes else ""
            view["sample_datetimes"] = samples
        representatives.append(view)

        representative_sid = (
            str(view.get("source_id") or "") if isinstance(view, dict) else ""
        )
        audit = {
            "group_index": ordinal,
            "representative_source_id": representative_sid,
            "occurrence_count": len(group["raw_indices"]),
            "first_seen": datetimes[0] if datetimes else "",
            "last_seen": datetimes[-1] if datetimes else "",
            "sample_datetimes": samples,
            "raw_indices": list(group["raw_indices"]),
            "source_ids": list(group["source_ids"]),
            "semantic_key_sha256": str(group.get("semantic_key_sha256") or ""),
        }
        audit_groups.append(audit)
        if representative_sid:
            by_representative_source_id[representative_sid] = audit

    return representatives, {
        "raw_count": len(entries),
        "group_count": len(representatives),
        "collapsed_count": len(entries) - len(representatives),
        "groups": audit_groups,
        "by_representative_source_id": by_representative_source_id,
    }


def _expand_task140_aggregation_results(entry_results: list, aggregation: dict) -> None:
    """Bind one representative LLM result back to every raw event in its group."""
    by_sid = (aggregation or {}).get("by_representative_source_id") or {}
    for result in entry_results or []:
        if not isinstance(result, dict):
            continue
        group = by_sid.get(str(result.get("source_id") or ""))
        if not group:
            continue
        # rev8: semantic aggregation is an explicit one-to-many binding.  Keep
        # the complete raw-index/source-id vectors plus a digest of the semantic
        # grouping key so provenance and validate_semantic_binding can verify
        # every raw member instead of silently degrading to source-id-only bind.
        result.pop("_raw_source_index", None)
        result["_raw_source_indices"] = list(group["raw_indices"])
        result["_source_ids"] = list(group["source_ids"])
        result["_task140_semantic_group_sha256"] = str(
            group.get("semantic_key_sha256") or ""
        )
        result["occurrence_count"] = int(group["occurrence_count"])
        result["first_seen"] = group["first_seen"]
        result["last_seen"] = group["last_seen"]
        result["sample_datetimes"] = list(group["sample_datetimes"])
        result["_source_attribution_method"] = "task140_semantic_group"


def _task140_raw_unevaluated_count(chunk_error: dict, aggregation: dict) -> int | None:
    """Translate failed representative indices back to raw event occurrences."""
    if not isinstance(chunk_error, dict) or not isinstance(aggregation, dict):
        return None
    occurrence_by_rep = {
        int(group["raw_indices"][0]): int(group.get("occurrence_count", 1) or 1)
        for group in aggregation.get("groups", [])
        if isinstance(group, dict) and group.get("raw_indices")
    }
    failed = [
        int(value) for value in (chunk_error.get("unevaluated_indices") or [])
        if isinstance(value, int) and not isinstance(value, bool)
    ]
    if not occurrence_by_rep or not failed:
        return None
    # Unknown representative indices must never be under-counted as one raw
    # event.  Use the full raw_count as a conservative upper bound so the
    # user-facing warning remains fail-closed even if diagnostic metadata is
    # internally inconsistent.
    if any(index not in occurrence_by_rep for index in failed):
        raw_count = int(aggregation.get("raw_count", 0) or 0)
        return raw_count if raw_count > 0 else None
    return sum(occurrence_by_rep[index] for index in failed)


_QUARANTINE_PATH_PREFIX_RE = re.compile(r"^(?:container)?file:_?|^amsi:_?", re.I)

# Defender 隔離ストアのリソース名 = 元ファイルの SHA-1。
#   ...\Quarantine\ResourceData\XX\<SHA1(40hex)> / ...\Quarantine\Resources\XX\<SHA1>
_QUARANTINE_SHA1_RE = re.compile(
    r"Quarantine[\\/]Resource(?:s|Data)[\\/][0-9A-Fa-f]{2}[\\/]([0-9A-Fa-f]{40})\b",
    re.I,
)


def _clean_quarantine_path(path: str) -> str:
    """
    parse_av_quarantine() の path_m 正規表現は "file:_"/"file:" プレフィックス
    の除去を試みるが、"containerfile:_..." 形式（コンテナファイル内の脅威を
    示すDefenderのXMLスキーマ表現）には対応していないため、ここで併せて
    除去する。directory_scan由来のpath（プレフィックスなし）には影響しない。
    """
    return _QUARANTINE_PATH_PREFIX_RE.sub("", path)


def _extract_defender_secondary_iocs(raw_entry: dict) -> list:
    """Defender原文から二次IOCを決定論的に抽出し、由来を保持する。"""
    out = []
    seen = set()
    for field in ("path", "command_line", "threat_name", "detection_source"):
        value = raw_entry.get(field) if isinstance(raw_entry, dict) else None
        if not isinstance(value, str) or not value:
            continue
        for rec in ioc_utils.extract_evidence_iocs(value, source_field=field):
            key = (rec.get("type"), str(rec.get("value", "")).lower())
            if key in seen:
                continue
            seen.add(key)
            out.append(rec)
    return out


def _attach_complete_rule_provenance(
    section: str,
    raw_entries: list,
    result: dict,
    *,
    reason: str,
) -> dict:
    """Attach complete provenance for an all-raw rule-based section.

    Every parsed record is deterministically evaluated even when the display
    layer suppresses or aggregates entries.  This helper intentionally keeps
    selected/evaluated empty because no record is sent to the LLM.
    """
    deterministic_indices = range(len(raw_entries))
    provenance = build_section_provenance(
        section,
        raw_entries,
        selected=(),
        deterministic=deterministic_indices,
        deferred=(),
        evaluated=(),
        unevaluated=(),
        mandatory=(),
        mandatory_applicable=True,
        deterministic_reasons={reason: deterministic_indices},
        provenance_complete=True,
        attribution_errors=(),
    )
    errors = validate_section_provenance(provenance)
    if errors:
        raise AssertionError(
            f"Rule-based provenance invalid ({section}): {'; '.join(errors)}"
        )
    result["_provenance"] = provenance
    result["_selection_stats"] = {
        "raw": len(raw_entries),
        "selected": 0,
        "deterministic": len(raw_entries),
        "deferred": 0,
        "deferred_by_policy": 0,
        "evaluated": 0,
        "selected_unevaluated": 0,
        "selected_coverage_pct": 100.0,
        "provenance_complete": True,
        "attribution_error_count": 0,
    }
    return result




def _attach_atomic_text_rule_provenance(
    section: str, raw_text: str, result: dict, *, collection_id: str, reason: str,
    source_container: str,
) -> dict:
    """Treat one companion/raw text file as one deterministic atomic evidence item."""
    text = str(raw_text or "")
    if not text.strip():
        out = _attach_complete_rule_provenance(section, [], result, reason=reason)
        out["_provenance"]["provenance_scope"] = "derived_atomic_text"
        out["_provenance"]["derived_from"] = {
            "container": source_container, "section": section, "raw_kind": "text",
        }
        return out
    raw_entry = {"raw_text": text}
    source_id = make_source_id(collection_id, section, raw_entry, 0)
    raw_entry["source_id"] = source_id
    for entry in result.get("entries") or []:
        if isinstance(entry, dict):
            entry.setdefault("source_id", source_id)
            entry.setdefault("_raw_source_index", 0)
            entry.setdefault("_source_attribution_method", "derived_atomic_text")
            entry.setdefault("_derived_source_section", section)
    out = _attach_complete_rule_provenance(section, [raw_entry], result, reason=reason)
    out["_provenance"]["provenance_scope"] = "derived_atomic_text"
    out["_provenance"]["derived_from"] = {
        "container": source_container, "section": section, "raw_kind": "text",
    }
    return out

def _build_defender_quarantine_provenance(raw_entries: list) -> dict:
    """Build complete deterministic provenance for Defender evidence.

    Defender detections/quarantine records are evaluated rule-based at every
    depth.  Every parsed raw record is therefore deterministic evidence; the
    display entries may be fewer because duplicate SHA-1 records are grouped.
    """
    deterministic_indices = range(len(raw_entries))
    return build_section_provenance(
        "defender_quarantine",
        raw_entries,
        selected=(),
        deterministic=deterministic_indices,
        deferred=(),
        evaluated=(),
        unevaluated=(),
        mandatory=(),
        mandatory_applicable=True,
        deterministic_reasons={
            "defender_rule_based": deterministic_indices,
        },
        provenance_complete=True,
        attribution_errors=(),
    )


def analyze_defender_quarantine_rule_based(raw_entries: list) -> dict:
    """
    depth=1 用: defender_quarantine をLLMを介さずルールベースで評価する。

    parse_checkpc.py の parse_av_quarantine() が返す各エントリは
    threat_name（Defenderが検知した脅威名。directory_scan由来は空文字）と
    path（検知/隔離ファイルのパス）を持つ。
      - threat_name が非空 → Defenderが脅威を確定的に検知済み → HIGH
      - threat_name が空   → 隔離フォルダ内に存在するが脅威名不明 → MEDIUM
    iocs にはpath（既存の構造化フィールド）をそのまま設定する。
    パス文字列からのドメイン/メールアドレス抽出等の二次IOC抽出は行わない
    （depth>=2 のLLM解析でのみ実施）。
    """
    if not raw_entries:
        return {
            "section": "defender_quarantine", "entries": [],
            "section_summary": "AV検知・隔離エントリなし",
        }

    entries = []
    high = 0
    seen_sha1 = {}      # SHA-1 → 生成済みエントリ（重複時は datetime_all に日時を追記）
    hash_cnt = 0
    for raw_index, e in enumerate(raw_entries):
        if not isinstance(e, dict):
            continue
        threat = (e.get("threat_name") or "").strip()
        path   = _clean_quarantine_path(e.get("path", ""))
        # v3.60: 検知日時をエントリに保持する（レポート・16-D 集約表示用）。
        #   defender_eventlog 由来 → 1116イベントの Date:（検知日時・UTC ISO形式）
        #   directory_scan   由来 → 検疫フォルダ内ファイルの更新日時（検知日時では
        #                           ない）。混同防止のため datetime_kind="更新" を
        #                           付与し、表示層で「ファイル更新日時」と併記する。
        dt = (e.get("datetime") or "").strip()
        dt_kind = "更新" if e.get("source") == "directory_scan" else "検知"
        secondary_iocs = _extract_defender_secondary_iocs(e)
        # Defender 隔離ストアは元ファイルの SHA-1 をリソース名にする:
        #   ...\Quarantine\ResourceData\XX\<SHA1> / ...\Quarantine\Resources\XX\<SHA1>
        # パスから SHA-1 を抽出し、裸のハッシュとして iocs に入れる
        #（vt_post が hash 種別として VT 照合 → レポート掲載する）。
        m = _QUARANTINE_SHA1_RE.search(path)
        sha1 = m.group(1).upper() if m else ""
        if threat:
            high += 1
            iocs = [sha1] if sha1 else ([path] if path else [])
            if sha1:
                hash_cnt += 1
            entry = {
                "identifier": threat,
                "score":      "HIGH",
                "reason":     f"Defenderが検知（脅威名: {threat}）。"
                               + (f"隔離検体SHA-1={sha1}（VT照合対象）。" if sha1 else "")
                               + "ルールベース判定（全depth, LLM未使用）",
                "iocs":       iocs,
                "source_id":  e.get("source_id", ""),
                "deterministic_origin": "defender_rule_based",
                "_raw_source_index": raw_index,
            }
            if secondary_iocs:
                vals = [r["value"] for r in secondary_iocs]
                entry["iocs"] = list(dict.fromkeys(entry.get("iocs", []) + vals))
                entry["_ioc_audit"] = secondary_iocs
            if dt:
                entry["datetime"] = dt
                entry["datetime_kind"] = dt_kind
            entries.append(entry)
        else:
            if sha1:
                # ResourceData と Resources で同一 SHA-1 が重複するため集約。
                # v3.60: 集約時は日時を捨てず datetime_all に全件保持する
                # （表示層が初回〜最終の範囲表示に使う）。
                if sha1 in seen_sha1:
                    prev = seen_sha1[sha1]
                    prev.setdefault("_raw_source_indices", [prev.pop("_raw_source_index")]
                                    if "_raw_source_index" in prev else [])
                    prev["_raw_source_indices"].append(raw_index)
                    if e.get("source_id"):
                        prev.setdefault("_source_ids", [])
                        if prev.get("source_id"):
                            prev["_source_ids"].append(prev.pop("source_id"))
                        prev["_source_ids"].append(e.get("source_id"))
                    if secondary_iocs:
                        prev.setdefault("_ioc_audit", [])
                        seen_a = {(r.get("type"), str(r.get("value", "")).lower())
                                  for r in prev["_ioc_audit"]}
                        for r in secondary_iocs:
                            k = (r.get("type"), str(r.get("value", "")).lower())
                            if k not in seen_a:
                                prev["_ioc_audit"].append(r); seen_a.add(k)
                                prev.setdefault("iocs", []).append(r["value"])
                    if dt:
                        prev.setdefault("datetime_all",
                                        [prev["datetime"]] if prev.get("datetime") else [])
                        prev["datetime_all"].append(dt)
                        prev["datetime_all"].sort()
                        if not prev.get("datetime"):
                            prev["datetime"] = dt
                            prev["datetime_kind"] = dt_kind
                    continue
                hash_cnt += 1
                entry = {
                    "identifier": path,
                    "score":      "MEDIUM",
                    "reason":     f"隔離フォルダ内の検体（SHA-1={sha1}）。脅威名不明だが"
                                   "Defenderが隔離済み。VTハッシュ照合対象。"
                                   "ルールベース判定（全depth, LLM未使用）",
                    "iocs":       [sha1],   # 裸のSHA-1 → vt_post が hash 照合
                    "source_id":  e.get("source_id", ""),
                    "deterministic_origin": "defender_rule_based",
                    "_raw_source_index": raw_index,
                }
                if secondary_iocs:
                    vals = [r["value"] for r in secondary_iocs]
                    entry["iocs"] = list(dict.fromkeys(entry.get("iocs", []) + vals))
                    entry["_ioc_audit"] = secondary_iocs
                if dt:
                    entry["datetime"] = dt
                    entry["datetime_kind"] = dt_kind
                seen_sha1[sha1] = entry
                entries.append(entry)
            else:
                entry = {
                    "identifier": path,
                    "score":      "MEDIUM",
                    "reason":     "脅威名不明。隔離フォルダ内に存在（要VT照合）。"
                                   "ルールベース判定（全depth, LLM未使用）",
                    "iocs":       [path] if path else [],
                    "source_id":  e.get("source_id", ""),
                    "deterministic_origin": "defender_rule_based",
                    "_raw_source_index": raw_index,
                }
                if secondary_iocs:
                    vals = [r["value"] for r in secondary_iocs]
                    entry["iocs"] = list(dict.fromkeys(entry.get("iocs", []) + vals))
                    entry["_ioc_audit"] = secondary_iocs
                if dt:
                    entry["datetime"] = dt
                    entry["datetime_kind"] = dt_kind
                entries.append(entry)

    summary = (f"AV検知・隔離 {len(entries)}件（うち脅威名判明 {high}件 / "
               f"SHA-1取得 {hash_cnt}件→VT照合対象）。"
               "全depthでルールベース評価（LLM未使用）")
    return {
        "section":         "defender_quarantine",
        "entries":         entries,
        "section_summary": summary,
    }


# ── UserAssist ルールベース評価（N-5） ─────────────────────────────────
# GUI 実行痕跡のうち、不審な配置場所からの実行のみを抽出する。
_UA_SCRIPT_EXT = re.compile(
    rf"\.(?:{directory_policy.SCRIPT_EXT_PATTERN}|scr|pif)$", re.I)
_UA_TRUSTED_RE = re.compile(
    r"^(?:C:\\Windows|C:\\Program Files( \(x86\))?)\\", re.I)
_UA_SUSP_FOLDER_RE = re.compile(
    r"\\Videos\\|\\Downloads\\|\\Temp\\|\\Public\\|"
    r"\\AppData\\Local\\Temp\\|\\\$Recycle|"
    rf"\\ProgramData\\[^\\]+\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$|"
    r"%USERPROFILE%\\(Videos|Downloads)\\|"
    r"\\\.[A-Za-z0-9_]+\\|"                                  # ドット始まり隠しフォルダ
    rf"^[D-Zd-z]:\\[^\\]+\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$",
    re.I,
)
# M-4: 上記 SUSP のうち「高リスク配置」（MEDIUM 維持）。Downloads/Desktop 等の
#   通常のユーザーDL/デスクトップ実行はこれに含めず LOW へ降格する。
_UA_HIGHRISK_FOLDER_RE = re.compile(
    r"\\Temp\\|\\AppData\\Local\\Temp\\|\\\$Recycle|\\Public\\|\\Videos\\|"
    rf"\\ProgramData\\[^\\]+\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$|"
    r"\\\.[A-Za-z0-9_]+\\|"                                  # 隠しフォルダ
    rf"^[D-Zd-z]:\\[^\\]+\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$",
    re.I,
)


def analyze_userassist_rule_based(raw_entries: list) -> dict:
    """UserAssist（GUI実行痕跡）を不審パス限定でルールベース評価する（N-5）。
    正規プログラム実行（Windows/Program Files 配下・UWPアプリ）は出力しない。
    """
    if not raw_entries:
        return {"section": "userassist", "entries": [],
                "section_summary": "UserAssist エントリなし"}
    entries = []
    high = 0
    for raw_index, e in enumerate(raw_entries):
        if not isinstance(e, dict):
            continue
        path = e.get("path", "")
        if not path or ("!" in path and "\\" not in path):
            continue  # UWP アプリ ID 等は対象外
        last = e.get("last_run", "")
        run  = e.get("run_count", 0)
        is_script = bool(_UA_SCRIPT_EXT.search(path))
        is_susp   = bool(_UA_SUSP_FOLDER_RE.search(path))
        is_trusted = bool(_UA_TRUSTED_RE.search(path))
        score = None
        if is_script and is_susp:
            score = "HIGH"
            reason = "不審フォルダからスクリプトを GUI 実行（UserAssist）。"
        elif is_script and not is_trusted:
            score = "MEDIUM"
            reason = "ユーザー領域等からスクリプトを GUI 実行（UserAssist）。"
        elif is_susp and not is_trusted:
            # M-4: 高リスク配置（Temp/$Recycle/Public/隠し/非Cドライブ直下等）は
            #   MEDIUM を維持。Downloads 等の通常DL実行は LOW へ降格する
            #   （正規インストーラの実行が大半で MEDIUM は過検出のため）。
            if _UA_HIGHRISK_FOLDER_RE.search(path):
                score = "MEDIUM"
                reason = "不審フォルダ（高リスク配置）から実行体を GUI 実行（UserAssist）。"
            else:
                score = "LOW"
                reason = "ユーザーDL/デスクトップ領域から実行体を GUI 実行（UserAssist）。"
        if score is None:
            continue
        if score == "HIGH":
            high += 1
        entries.append({
            "identifier": f"{path}" + (f"（最終実行 {last}）" if last else ""),
            "score":      score,
            "reason":     reason + f" 実行回数={run}。ルールベース判定（LLM未使用, T1204）",
            "decoded":    None, "lolbas": None,
            "mitre":      ["T1204"],
            "iocs":       [path],
            "source_id":  e.get("source_id", ""),
            "deterministic_origin": "userassist_rule",
            "_raw_source_index": raw_index,
        })
    summary = (f"UserAssist 不審実行 {len(entries)}件（HIGH {high}件）"
               if entries else "UserAssist に不審な実行痕跡なし")
    return {"section": "userassist", "entries": entries, "section_summary": summary}


def apply_suspicious_filter(section: str, entries: list) -> list:
    """
    depth=1 限定: parse_checkpc.py がフラグ付与済みのセクションで
    suspicious=True のエントリのみ返す。
    対象外セクションはそのまま返す。

    対象セクション:
      appcompat_cache : parse_appcompat_cache_csv() が suspicious フラグを付与
      dns_cache       : parse_dns_cache() が suspicious フラグを付与
      hosts           : parse_hosts() が suspicious フラグを付与（T-22）
    """
    if section not in ("appcompat_cache", "dns_cache", "hosts"):
        return entries
    return [e for e in entries if isinstance(e, dict) and e.get("suspicious")]


# ── LLM 結果 post-filter ─────────────────────────────────────────────────────
# 「取りこぼし防止を最優先」の方針のもと、LLM が HIGH/MEDIUM と判定した結果を
# ルールベースで CLEAN に降格させるのは「明らかに正規」と断言できる条件のみに限定する。
# 条件が曖昧な場合は降格させず、誤検知は許容する（取りこぼしより FP を選ぶ）。

# task_scheduler post-filter: 正規 Windows タスクの確実な CLEAN 条件
# ──────────────────────────────────────────────────────────────────
# 以下の条件を全て満たす場合のみ降格（条件が1つでも欠ければ降格しない）:
#   A. タスクパスが \Microsoft\Windows\ 配下
#   B. SYSTEM アカウントで実行
#   C. task_path が既知の正規パターンに完全マッチ
#
# 「C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\...\\MpCmdRun.exe」は
# Windows Defender が自身を Platform ディレクトリ下に展開する正規の仕組みであり
# System32 外でも正規と断言できる唯一の例外として明示的にホワイトリスト化する。
# MpCmdRun.exe のバージョン番号（4.18.xxxxx.x-0）は変動するため prefix マッチを使う。

_TASK_CLEAN_RULES: list[tuple] = [
    # (タスクパスの正規表現, 実行パスの正規表現, 説明)
    # Windows Defender Platform タスク（MpCmdRun.exe）
    (
        re.compile(r"\\Microsoft\\Windows\\Windows Defender\\", re.I),
        re.compile(r"\\ProgramData\\Microsoft\\Windows Defender\\Platform\\"
                   r"[\d.]+-\d+\\MpCmdRun\.exe", re.I),
        "Windows Defender Platform タスク（MpCmdRun.exe）",
    ),
    # StateRepository メンテナンス（rundll32 + System32 DLL + \Microsoft\Windows\ 配下）
    (
        re.compile(r"\\Microsoft\\Windows\\StateRepository\\", re.I),
        re.compile(r"(?:%windir%|C:\\Windows)\\system32\\rundll32\.exe\s+"
                   r"(?:%windir%|C:\\Windows)\\system32\\Windows\.StateRepositoryClient\.dll",
                   re.I),
        "StateRepository メンテナンスタスク（System32 rundll32）",
    ),
    # \Microsoft\Windows\ 配下 + rundll32 + DLL名のみ（%windir%なしの短縮形）
    # 例: rundll32.exe dfdts.dll,DfdGetDefaultPolicy
    #     rundll32.exe sysmain.dll,PfSvWsSwapAssessmentTask
    #     rundll32.exe bfe.dll,BfeOnServiceStartTypeChange
    # これらは System32 配下の正規 DLL で、パスを省略した形で呼ばれる。
    # フルパス形式（%windir%\system32\xxx.dll）はすでに上記ルールでカバー済みのため
    # ここでは「DLL名のみ」かつ「\Microsoft\Windows\ 配下」を条件とする。
    (
        re.compile(r"\\Microsoft\\Windows\\", re.I),
        re.compile(
            # rundll32.exe の後に System32 パス付き DLL OR DLL名のみ（パス区切りなし）
            r"(?:%windir%|C:\\Windows)\\system32\\rundll32\.exe"
            r"(?:\s+(?:%windir%|C:\\Windows)\\system32\\[^\s]+\.dll"  # フルパス DLL
            r"|\s+/d\s+[^\\/\s]+\.dll"                                 # /d フラグ付き
            r"|\s+[^\\/\s]+\.dll)",                                    # DLL名のみ
            re.I),
        "\\Microsoft\\Windows\\ 配下の正規 rundll32 タスク（System32 DLL）",
    ),
]

# startup_folder post-filter: Word ロックファイル（~$*.dot）は永続化と無関係
_STARTUP_LOCK_RE = re.compile(r"[/\\]~\$[^/\\]+\.dot[mx]?$", re.I)

# M-2: directory の既知benign一時ファイル（OS/インストーラ/ドライバ由来）。MEDIUM→LOW 降格。
#   wct<hex>.tmp        : Windows CBS/servicing 一時
#   ns[a-z]<hex>.tmp    : NSIS インストーラ一時（nsa/nsm/nse 等）
#   ~DF<hex>.tmp        : Office/Windows 一時
#   CR_<hex>.tmp\...    : Chrome インストーラ一時
#   amc<hex>.tmp        : AMD ドライバ/ソフトウェア一時（[任意1]）
#   TS<hex>.tmp         : 各種インストーラ一時
#   set<hex>.tmp        : Windows setup/更新 一時
#   <GUID>.tmp          : 各種インストーラ一時（ハイフン区切り36桁）
_DIR_BENIGN_TEMP_RE = re.compile(
    r"[/\\](?:"
    r"wct[0-9A-Fa-f]+\.tmp|"
    r"ns[a-z][0-9A-Fa-f]+\.tmp|"
    r"~DF[0-9A-Fa-f]+\.tmp|"
    r"CR_[0-9A-Fa-f]+\.tmp|"
    r"amc[0-9A-Fa-f]+\.tmp|"
    r"TS[0-9A-Fa-f]+\.tmp|"
    r"set[0-9A-Fa-f]+\.tmp|"
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\.tmp"
    r")$",
    re.I,
)

# system_7045 post-filter (N-2): Windows Defender 動的署名サービス MpKsl{16進}
_MPKSL_NAME_RE = re.compile(r"\bMpKsl[0-9a-fA-F]{6,}\b")
_MPKSL_PATH_RE = re.compile(r"\\(?:ProgramData|Windows)\\Microsoft\\Windows Defender\\", re.I)

# ── known_tools 決定論的検出（N-3） ─────────────────────────────────────────
# フィルタ層（suspicious / Level1）を通さず、parse 済みの全件を直接走査して
# 「既知ツール名・サービスの異常配置・Webシェル」を確実に拾う。
# 取りこぼし防止最優先の方針に基づき、allowlist 方式の脱落を補完する。

# 明確なハックツール / マイナー（ファイル名先頭一致＝発見＝原則 HIGH）
# ※ フルパス部分一致は誤検出（VS等の正規アセンブリ名）を招くため、
#   basename（ファイル名）の先頭アンカーで判定する。
_KT_HACKTOOL_RE = re.compile(
    r"^(?:mimikatz|lazagne|gsecdump|pwdump\d?|rubeus|sharphound|"
    r"cobaltstrike|fscan|nbtscan|xmrig|xmr-?stak|xmrstak|"
    r"badpotato|juicypotato|sweetpotato|printspoofer|godpotato|"
    r"wce|wce64|wceaux\d*|"
    # 中国系攻撃ツール / Webシェル管理クライアント
    r"behinder|godzilla|antsword|suo5|stowaway|earthworm|htran|lcx|"
    # トンネル / C2 フレームワーク
    r"chisel|gost|sliver|havoc|bruteratel|"
    # 資格情報ダンプ / AD攻撃
    r"nanodump|dumpert|secretsdump|crackmapexec|nxc|kerbrute|certipy"
    r")(?:\b|[._\-]|64|32)",
    re.I,
)
# 遠隔操作系デュアルユース（basename 先頭一致。実バイナリ名で判定）
# remoteutilities は実バイナリ rutserv/rfusclient。汎用語は VS 等に誤マッチするため除外。
_KT_REMOTEADMIN_RE = re.compile(
    r"^(?:radmin|rserver3?|famitrfc|anydesk|teamviewer|tv_w32|tv_x64|ammyy|"
    r"ultravnc|tightvnc|winvnc|vncserver|vncviewer|tvnserver|"
    r"screenconnect|connectwisecontrol|splashtop|gotomypc|"
    r"rutserv|rfusclient|ngrok|frpc|frps|nssm|netsupport|"
    r"todesk|sunlogin|sunloginclient|oray|rustdesk|anyviewer|gotohttp|"
    r"awesun|aweray|awerays|"
    r"ateraagent|agentpackage)(?:\b|[._\-]|64|32)",
    re.I,
)

# Microsoft Gaming Services の厳格な正常系。WindowsApps のMicrosoft署名
# package family配下にあり、ServiceNameと実行体名が対応する場合だけ適用する。
_GAMING_SERVICES_NAME_RE = re.compile(r"^GamingServices(?:Net)?$", re.I)
_GAMING_SERVICES_PATH_RE = re.compile(
    r"^[A-Za-z]:\\Program Files\\WindowsApps\\"
    r"Microsoft\.GamingServices_[^\\]+__8wekyb3d8bbwe\\"
    r"GamingServices(?:Net)?\.exe$",
    re.I,
)
# 正規 Windows サービス配置（System32 等）。ここに該当しない C:\Windows\ 配下は異常。
# F: SCCM クライアント（CcmExec 等）は C:\Windows\CCM\ / ccmsetup\ から正規に起動するため追加。
#    ※ Provisioning/PolicyDefinitions 等はサービス配置場所でないため敢えて除外（検出の穴防止）。
_KT_WIN_LEGIT_SVC_RE = re.compile(
    r"\\Windows\\(System32|SysWOW64|WinSxS|Microsoft\.NET|servicing|SystemApps|"
    r"ImmersiveControlPanel|SystemResources|security|INF|WID|CCM|ccmsetup|"
    r"Microsoft\\Windows Defender)\\",
    re.I,
)
# F: システムプロセス名のタイポスクワット（正規には存在しない綴り＝原則 HIGH）
_KT_TYPOSQUAT_RE = re.compile(
    r"^(?:scvhost|svch0st|svchosts|svhost|svchsot|svchot|"
    r"lsasss|ls4ss|lsas|lass|"
    r"csrsss|csrss32|"
    r"winl0gon|winlogon32|winlgon|"
    r"expl0rer|explorrer|explorer32|"
    r"smsss|conhst|taskhostt|rundii32|rundll32_|services32)"
    r"(?:\b|[._\-]|\.exe)",
    re.I,
)
_KT_WIN_PREFIX_RE = re.compile(r"^(?:\"?)(?:%systemroot%|%windir%|c:\\windows)\\", re.I)
# C: サービス異常配置の拡張
# サービスバイナリのパス抽出（引用符/引数を除去し .exe/.dll/.sys までを取得）
_KT_SVC_BIN_RE = re.compile(r'^\s*"?([A-Za-z]:\\[^"]*?\.(?:exe|dll|sys|com|scr|bat))\b', re.I)
_SERVICE_QUOTED_CMD_RE = re.compile(
    r'^\s*"(?P<exe>[A-Za-z]:\\[^"]+?\.(?:exe|dll|sys|com|scr|bat))"(?P<args>.*)$', re.I)
_SERVICE_PLAIN_CMD_RE = re.compile(
    r'^\s*(?P<exe>[A-Za-z]:\\[^"]*?\.(?:exe|dll|sys|com|scr|bat))'
    r'(?P<orphan_quote>")?(?P<args>\s+.*|$)', re.I)
_SERVICE_ARG_PATH_RE = re.compile(
    r'"(?P<quoted>[A-Za-z]:\\[^"]+)"|(?P<plain>[A-Za-z]:\\[^\s"]+)', re.I)
_SERVICE_UNCLOSED_ARG_PATH_RE = re.compile(
    r'(?:^|\s)"(?P<path>[A-Za-z]:\\[^"]+)$', re.I)
_KT_PROGRAM_FILES_RE = re.compile(r'^[A-Za-z]:\\Program Files(?: \(x86\))?\\', re.I)


def _parse_service_command(image_path: str) -> dict:
    """Split a Windows service ImagePath into executable, arguments and path args.

    Event 7045 data in the field can contain a missing opening quote while a
    closing quote remains immediately after ``.exe``.  Treat only that narrow
    form as recoverable and preserve an explicit audit warning.
    """
    raw = str(image_path or "").strip()
    quoted = _SERVICE_QUOTED_CMD_RE.match(raw)
    plain = None if quoted else _SERVICE_PLAIN_CMD_RE.match(raw)
    m = quoted or plain
    if not m:
        return {
            "raw": raw, "executable": "", "arguments": raw,
            "argument_paths": [], "warnings": ["service_command_unparsed"],
        }
    executable = m.group("exe")
    arguments = (m.group("args") or "").strip()
    warnings = []
    if plain is not None and plain.groupdict().get("orphan_quote"):
        warnings.append("unbalanced_closing_quote_after_executable")
    paths = []
    for pm in _SERVICE_ARG_PATH_RE.finditer(arguments):
        path = pm.group("quoted") or pm.group("plain") or ""
        if path and path.casefold() != executable.casefold() and path not in paths:
            paths.append(path)
    unclosed = _SERVICE_UNCLOSED_ARG_PATH_RE.search(arguments)
    if unclosed:
        path = unclosed.group("path").strip()
        if path and path.casefold() != executable.casefold() and path not in paths:
            paths.append(path)
        warnings.append("unbalanced_opening_quote_in_arguments")
    return {
        "raw": raw, "executable": executable, "arguments": arguments,
        "argument_paths": paths, "warnings": warnings,
    }


def _raw_service_for_entry(entry: dict, raw_entries) -> dict:
    if not isinstance(entry, dict) or not isinstance(raw_entries, list):
        return {}
    # source_id is the authoritative stable identity.  Depth1 filtering can
    # change list positions, so a raw index from an older artifact must never
    # override a matching source_id.
    source_id = str(entry.get("source_id", "") or "")
    if source_id:
        for raw in raw_entries:
            if isinstance(raw, dict) and str(raw.get("source_id", "") or "") == source_id:
                return raw
    idx = entry.get("_raw_source_index", entry.get("source_index"))
    try:
        idx = int(idx)
    except (TypeError, ValueError):
        return {}
    if 0 <= idx < len(raw_entries) and isinstance(raw_entries[idx], dict):
        return raw_entries[idx]
    return {}


def _safe_service_summary_value(value: object, limit: int = 120) -> str:
    text = str(value or "")
    text = "".join(" " if ord(ch) < 32 or ord(ch) == 127 else ch for ch in text)
    return re.sub(r"\s+", " ", text).strip()[:limit]


def _rebuild_system_7045_summary(sec_result: dict) -> None:
    """Keep the section summary aligned with post-filtered raw evidence."""
    entries = [e for e in sec_result.get("entries", []) if isinstance(e, dict)]
    counts = {score: 0 for score in ("HIGH", "MEDIUM", "LOW", "CLEAN")}
    for entry in entries:
        score = entry.get("score", "LOW")
        if score in counts:
            counts[score] += 1
    names = []
    for entry in entries:
        name = _safe_service_summary_value(entry.get("identifier", ""))
        if name and name not in names:
            names.append(name)
    name_text = "、".join(names[:5]) or "なし"
    if len(names) > 5:
        name_text += f"ほか{len(names) - 5}件"
    sec_result["section_summary"] = (
        "原イベントのServiceName/ImagePathを権威情報として再評価。"
        f"対象{len(entries)}件（HIGH={counts['HIGH']}、MEDIUM={counts['MEDIUM']}、"
        f"LOW={counts['LOW']}、CLEAN={counts['CLEAN']}）。サービス: {name_text}"
    )
# ユーザー書込可能領域（サービスが起動するのは異常）
_KT_SVC_USERWRITE_RE = re.compile(r"\\Users\\|\\Temp\\|\\\$Recycle|\\AppData\\", re.I)
# うち高確度領域（正規ではまず無い）→ HIGH。Users/AppData は per-user 正規サービスもあるため MEDIUM。
_KT_SVC_HIGHLOC_RE = re.compile(r"\\Temp\\|\\\$Recycle|\\Users\\Public\\", re.I)
_KT_SVC_PROGRAMDATA_RE = re.compile(r"^[A-Za-z]:\\ProgramData\\", re.I)
# ProgramData だが正規のサービス配置（Defender Platform 等）は除外
_KT_SVC_PROGRAMDATA_LEGIT_RE = re.compile(
    r"\\ProgramData\\Microsoft\\Windows Defender\\Platform\\", re.I)
_KT_SVC_NONSYS_ROOT_RE = re.compile(r"^[D-Zd-z]:\\[^\\]+\.(?:exe|dll|scr|com)$", re.I)
# System32 偽装（svchost/lsass 等を非System32で）
_KT_SVC_MASQ_RE = re.compile(
    r"\\(svchost|lsass|csrss|services|winlogon|spoolsv|conhost|dllhost|taskhostw)\.exe$", re.I)
# ── [3] 誤検知抑制 allowlist（batchtools master_filepath_whitelist を根拠に curated）──
# C:\Windows\ 配下に正規配置される著名OEMサービス（音声/Bluetooth/タッチパッド等）。
# 「異常配置サービス」判定から除外する。ベンダ固有の綴り/パスで一致させるため、
# 別パスの同名バイナリ（偽装）は引き続き検出される。
_KT_WIN_OEM_SVC_RE = re.compile(
    r"\\Windows\\(?:"
    r"CxSvc\\|SmartAudio\\|WavesSysSvc\\|Nahimic\\|DTS\\|"          # ベンダ既定サブディレクトリ
    r"Rtk[A-Za-z0-9]*\.(?:exe|dll)|"                                # Realtek（Windows直下 Rtk*）
    r"RtkBtManServ\.exe|"                                            # Realtek Bluetooth
    r"Cx[A-Za-z0-9]*Svc\.exe|"                                       # Conexant（CxMonSvc/CxUtilSvc）
    r"WavesSysSvc[A-Za-z0-9]*\.exe|"                                 # Waves Audio
    r"nahimic[A-Za-z0-9]*\.(?:exe|dll)"                              # Nahimic Audio
    r")",
    re.I,
)
# 既知の per-user updater/同期クライアント（AppData 配置が正規仕様）。
# USERWRITE(Users/AppData) の MEDIUM 判定から除外する。ベンダ固有パスに限定し、
# 無関係な AppData 直下バイナリ（マルウェア常用）は引き続き MEDIUM 検出する。
_KT_SVC_PERUSER_LEGIT_RE = re.compile(
    r"\\AppData\\(?:Local|Roaming)\\(?:"
    r"Microsoft\\(?:OneDrive|Teams|EdgeUpdate|OneDriveStandaloneUpdater)|"
    r"Google\\(?:Update|Chrome|GoogleUpdater)|"
    r"Dropbox|baidu|Wondershare|Kingsoft|Zoom|Adobe|"
    r"Programs\\Opera|Discord|Slack|BraveSoftware"
    r")[\\ ]",
    re.I,
)
# Webシェル候補（Webルート配下の動的拡張子）
_KT_WEBROOT_RE   = re.compile(r"\\(?:htdocs|wwwroot|inetpub|www|web|public_html)\\", re.I)
_KT_WEBSHELL_EXT = re.compile(r"\.(php\d?|aspx?|jspx?|ashx|asmx|cfm|phtml)$", re.I)
# Webシェル候補から除外する既定の正規ディレクトリ/ファイル（XAMPP・主要FW）
_KT_WEBSHELL_LEGIT_RE = re.compile(
    r"\\(?:dashboard|phpmyadmin|webalizer|img|licenses|docs?|examples?|"
    r"vendor|node_modules|wordpress\\wp-(?:admin|includes)|joomla|drupal|"
    r"laravel|symfony|composer)\\|\\(?:index|phpinfo|info|test|config)\.php$",
    re.I,
)


# ── B: LOLBin/ファイルレス コマンドライン悪用検出 ─────────────────────────────
# ps_history / persistence_reg / service / startup_folder のコマンドラインを走査。
_LOLBIN_HIGH = [
    (re.compile(r"certutil(\.exe)?.{0,40}(-urlcache|-decode|-f\s.{0,80}https?://|urlcache.{0,40}https?://)", re.I),
     "certutil ダウンロード/デコード", ["T1105", "T1140"]),
    (re.compile(r"bitsadmin(\.exe)?.{0,40}/transfer", re.I),
     "bitsadmin ダウンロード", ["T1105", "T1197"]),
    (re.compile(r"mshta(\.exe)?.{0,40}(https?://|javascript:|vbscript:)", re.I),
     "mshta リモート/スクリプト実行", ["T1218.005"]),
    (re.compile(r"regsvr32(\.exe)?.{0,40}(/i:https?://|scrobj|/i:.{0,60}\.sct)", re.I),
     "regsvr32 Squiblydoo", ["T1218.010"]),
    (re.compile(r"rundll32(\.exe)?.{0,40}(javascript:|https?://)", re.I),
     "rundll32 スクリプト/リモート実行", ["T1218.011"]),
    (re.compile(r"powershell.{0,80}(-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}|"
                r"frombase64string|downloadstring|downloadfile|"
                r"\b(iex|invoke-expression)\b|invoke-webrequest.{0,40}-out)", re.I),
     "powershell エンコード/ダウンロード実行", ["T1059.001", "T1105"]),
]
_LOLBIN_MED = [
    (re.compile(r"wmic(\.exe)?.{0,40}process.{0,20}call.{0,20}create", re.I),
     "wmic プロセス生成", ["T1047"]),
    (re.compile(r"(msbuild|installutil|regasm|regsvcs)(\.exe)?.{0,60}(https?://|\.xml|\.csproj|/logfile|/u\b)", re.I),
     "AWL/CLM バイパス（msbuild等）", ["T1127", "T1218"]),
    (re.compile(r"esentutl(\.exe)?.{0,40}(/y|/vss|vss)", re.I),
     "esentutl コピー（lsass/ntds 窃取の常套）", ["T1003"]),
    (re.compile(r"(curl|wget)(\.exe)?.{0,80}https?://.{0,80}(\\temp\\|\\appdata\\|\\programdata\\|\\public\\)", re.I),
     "curl/wget で書込領域へ取得", ["T1105"]),
    (re.compile(rf"schtasks(\.exe)?.{{0,40}}/create.{{0,80}}(powershell|https?://|mshta|\.(?:{directory_policy.SCRIPT_EXT_PATTERN}))", re.I),
     "schtasks で不審タスク作成", ["T1053.005"]),
]


# ツール名一致を適用してよい「実行体」か判定（.pdf/.log/.bbx 等への誤マッチ防止）。
# prefetch の "NAME.EXE-XXXXXXXX.pf" 形式と、拡張子なし名（一部CLIツール）も許可。
_KT_EXEC_EXT_RE = re.compile(
    rf"\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$", re.I)
_KT_PREFETCH_RE = re.compile(r"\.exe-[0-9A-Fa-f]{6,}\.pf$", re.I)


def _kt_is_executable(base: str) -> bool:
    if not base:
        return False
    if _KT_EXEC_EXT_RE.search(base) or _KT_PREFETCH_RE.search(base):
        return True
    # 拡張子が無い（ドットを含まない）名は CLI ツール等の可能性があり許可
    return "." not in base


def _kt_path_of(entry) -> str:
    """heterogeneous な parsed エントリからパス/コマンドライン文字列を取り出す。"""
    if isinstance(entry, str):
        return entry
    if not isinstance(entry, dict):
        return ""
    for k in ("image_path", "path", "file_path", "full_path", "commandline",
              "command_line", "name"):
        v = entry.get(k)
        if v:
            return str(v)
    return ""


def analyze_known_tools(sections: dict, collection_id: str = "") -> dict:
    """既知ツール・サービス異常配置・Webシェルを決定論的に検出する（N-3）。
    フィルタを通さず parse 済み全件を走査するため、未知パスでも取りこぼさない。
    """
    entries = []
    seen = set()
    current = {"section": "", "entry": None, "index": None, "ordinal": 0}

    def _set_source(section, entry, index, ordinal):
        current.update(section=str(section), entry=entry, index=index, ordinal=ordinal)

    def _add(score, ident, reason, ioc, mitre, *, source=None):
        key = (score, ioc)
        if key in seen:
            return
        seen.add(key)
        src = dict(source or current)
        raw_entry = src.get("entry")
        source_id = ""
        if isinstance(raw_entry, dict):
            source_id = str(raw_entry.get("source_id") or "")
        if not source_id and collection_id and raw_entry is not None:
            source_id = make_source_id(
                collection_id, str(src.get("section") or "known_tools"),
                raw_entry, int(src.get("ordinal") or 0),
            )
        row = {
            "identifier": ident[:120],
            "score": score,
            "reason": reason,
            "decoded": None, "lolbas": None,
            "mitre": mitre,
            "iocs": [ioc] if ioc else [],
            "deterministic_origin": "known_tools_rule",
            "_derived_source_section": str(src.get("section") or ""),
        }
        if source_id:
            row["source_id"] = source_id
            row["_source_attribution_method"] = "derived_from_raw_source"
        if isinstance(src.get("index"), int):
            row["_raw_source_index"] = int(src["index"])
        entries.append(row)

    # 走査対象（サービス / ShimCache / タスクリスト / ディレクトリ）
    # D: prefetch / persistence_reg / startup_folder を追加（実行痕跡・永続化）
    scan_sets = [
        ("service",         sections.get("service", [])),
        ("appcompat_cache", sections.get("appcompat_cache", [])),
        ("tasklist",        sections.get("tasklist", [])),
        ("directory",       sections.get("directory", [])),
        ("prefetch",        sections.get("prefetch", [])),
        ("persistence_reg", sections.get("persistence_reg", [])),
        ("startup_folder",  sections.get("startup_folder", [])),
    ]

    webshell_hits = []
    webshell_sources = []

    for src, lst in scan_sets:
        if not isinstance(lst, list):
            continue
        duplicate_counts = {}
        for raw_index, e in enumerate(lst):
            raw_key = canonical_evidence(e)
            ordinal = duplicate_counts.get(raw_key, 0)
            duplicate_counts[raw_key] = ordinal + 1
            _set_source(src, e, raw_index, ordinal)
            p = _kt_path_of(e)
            if not p:
                continue
            # ツール名判定は basename（ファイル名）に対して行う（パス中間の誤マッチ防止）。
            # コマンドライン形式（引数付き）の場合は実行体パス部分を取り出してから basename 化。
            mexe = re.match(rf'^\s*"?(.+?\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN}))\b', p, re.I)
            clean = mexe.group(1) if mexe else p.strip().strip('"')
            base = re.split(r"[\\/]", clean)[-1]
            # 0) システムプロセス名のタイポスクワット（正規に存在しない綴り）→ HIGH
            # 0) システムプロセス名のタイポスクワット（正規に存在しない綴り）→ HIGH
            #    ※ ツール名一致は「実行体」のみに限定し、.pdf/.log/.bbx 等の
            #      非実行ファイルへの誤マッチ（TeXのgost, ToDeskのlog等）を防ぐ。
            if _kt_is_executable(base):
                if _KT_TYPOSQUAT_RE.search(base):
                    _add("HIGH", f"システムプロセス偽装（タイポスクワット）: {p}",
                         f"システムプロセス名の誤綴り（scvhost/svch0st 等）を {src} で検出。"
                         "正規には存在しない綴りで、マルウェアの偽装の常套（T1036.005）。",
                         p, ["T1036.005"])
                # 1) ハックツール / マイナー
                if _KT_HACKTOOL_RE.search(base):
                    _add("HIGH", f"既知ハックツール/マイナー: {p}",
                         f"既知の攻撃ツール/マイナー名を {src} で検出。フィルタ非依存の決定論検出。",
                         p, ["T1588.002"])
                # 2) 遠隔操作デュアルユース
                elif _KT_REMOTEADMIN_RE.search(base):
                    _add("MEDIUM", f"遠隔操作ツール: {p}",
                         f"遠隔操作系ツール名を {src} で検出。正規導入か攻撃者導入かを要確認（T1219）。",
                         p, ["T1219"])
            # 3) Webシェル候補（directory のみ。件数が多いので集約）
            if src == "directory" and _KT_WEBROOT_RE.search(p) and _KT_WEBSHELL_EXT.search(p):
                # XAMPP/フレームワーク既定の正規 .php を除外（FP 抑制）
                if not _KT_WEBSHELL_LEGIT_RE.search(p):
                    webshell_hits.append(p)
                    webshell_sources.append(dict(current))

    # サービス異常配置: C:\Windows\ 配下だが System32 等の正規配置でない
    svc = sections.get("service", [])
    if isinstance(svc, list):
        duplicate_counts = {}
        for raw_index, e in enumerate(svc):
            raw_key = canonical_evidence(e)
            ordinal = duplicate_counts.get(raw_key, 0)
            duplicate_counts[raw_key] = ordinal + 1
            _set_source("service", e, raw_index, ordinal)
            img = e.get("image_path", "") if isinstance(e, dict) else ""
            name = e.get("name", "") if isinstance(e, dict) else ""
            if not img:
                continue
            # 環境変数を正規化（%SystemRoot%/%windir% → C:\Windows）してから判定する。
            norm = re.sub(r"%systemroot%|%windir%", r"C:\\Windows", img, flags=re.I)
            # C:\Windows\ 配下だが System32 等でない → MEDIUM
            # （Conexant/Realtek 等の正規OEMが \Windows\<ベンダ>\ を使うため HIGH→MEDIUM に緩和。
            #  悪性も使うため可視化は維持。System32偽装名は別途 HIGH 判定）
            # [3] 著名OEM（CxSvc/Rtk*/Waves 等）の正規配置は allowlist で除外する。
            if (_KT_WIN_PREFIX_RE.search(norm)
                    and not _KT_WIN_LEGIT_SVC_RE.search(norm)
                    and not _KT_WIN_OEM_SVC_RE.search(norm)):
                _add("MEDIUM", f"異常配置サービス: {name} {img}",
                     "C:\\Windows\\ 配下だが System32 等の正規ディレクトリでない場所から "
                     "起動するサービス。正規OEMの可能性もあるが RAT/バックドアの常套手段でもある"
                     "（T1543.003）。要確認。",
                     img, ["T1543.003"])

            # C: サービスバイナリの配置/形態を追加判定
            mbin = _KT_SVC_BIN_RE.search(norm)
            binpath = mbin.group(1) if mbin else ""
            if binpath:
                base = re.split(r"[\\/]", binpath)[-1]
                legit = _KT_WIN_LEGIT_SVC_RE.search(binpath)
                # 1a) Temp/$Recycle/Public 等の高確度領域 → HIGH（正規ではまず無い）
                if _KT_SVC_HIGHLOC_RE.search(binpath):
                    _add("HIGH", f"サービスが高リスク領域から起動: {name} {binpath}",
                         "サービスバイナリが Temp/$Recycle.Bin/Public に存在。正規サービスでは"
                         "ほぼ無く、永続化バックドアの可能性が高い（T1543.003）。",
                         binpath, ["T1543.003"])
                # 1b) Users/AppData → MEDIUM（updater/同期等の正規per-userサービスもある）
                #     [3] 既知の per-user updater/同期（OneDrive/Teams/Google/Baidu/
                #     Wondershare 等）のベンダ固有パスは allowlist で除外する。
                elif (_KT_SVC_USERWRITE_RE.search(binpath)
                      and not _KT_SVC_PERUSER_LEGIT_RE.search(binpath)):
                    _add("MEDIUM", f"サービスがユーザー領域から起動: {name} {binpath}",
                         "サービスバイナリが Users/AppData 等のユーザー書込可能領域に存在。"
                         "正規の per-user サービス（updater/同期クライアント等）の場合もあるが、"
                         "永続化バックドアの可能性もあり要確認（T1543.003）。",
                         binpath, ["T1543.003"])
                # 2) ProgramData / 非システムドライブ直下 → MEDIUM（一部正規あり）
                elif ((_KT_SVC_PROGRAMDATA_RE.search(binpath)
                       and not _KT_SVC_PROGRAMDATA_LEGIT_RE.search(binpath))
                      or _KT_SVC_NONSYS_ROOT_RE.search(binpath)):
                    _add("MEDIUM", f"サービスが非標準領域から起動: {name} {binpath}",
                         "サービスバイナリが ProgramData 直下や非システムドライブ直下に存在。"
                         "正規導入かを要確認（T1543.003）。",
                         binpath, ["T1543.003"])
                # 3) System32 偽装（svchost 等を非System32で）→ HIGH
                if _KT_SVC_MASQ_RE.search(binpath) and not legit:
                    _add("HIGH", f"システムプロセス偽装サービス: {name} {binpath}",
                         "svchost/lsass 等のシステムプロセス名を System32 以外から起動。"
                         "正規プロセスへの偽装の可能性（T1036.005 / T1543.003）。",
                         binpath, ["T1036.005", "T1543.003"])
            # 4) 引用符なしサービスパス＋空白（権限昇格の常套）→ MEDIUM
            if not img.lstrip().startswith('"'):
                mq = re.match(r"^\s*([A-Za-z]:\\[^\"]*?\.exe)(?:\s|$)", img, re.I)
                if mq and " " in mq.group(1):
                    _add("MEDIUM", f"引用符なしサービスパス（空白あり）: {name} {img}",
                         "サービスの実行パスが引用符で囲まれず空白を含む。先頭一致による"
                         "実行ファイル乗っ取りで権限昇格に悪用され得る（T1574.009）。",
                         mq.group(1), ["T1574.009"])

    # Webシェル候補を集約（最大15件サンプル）
    if webshell_hits:
        sample = webshell_hits[:15]
        _add("MEDIUM",
             f"Webシェル候補 {len(webshell_hits)}件（Webルート配下の動的スクリプト）",
             "Webルート（htdocs/wwwroot/inetpub 等）配下に .php/.aspx 等の動的"
             "スクリプトを検出。Webシェルの可能性があり内容の目視確認が必要（T1505.003）。"
             f" サンプル: {', '.join(sample[:5])}",
             webshell_hits[0], ["T1505.003"],
             source=webshell_sources[0] if webshell_sources else None)

    # B: LOLBin/ファイルレス コマンドライン悪用検出
    # コマンドラインを持つセクションを走査（ps_history は文字列, 他は path/image_path）
    cmdline_sets = [
        ("ps_history",      sections.get("ps_history", [])),
        ("persistence_reg", sections.get("persistence_reg", [])),
        ("service",         sections.get("service", [])),
        ("startup_folder",  sections.get("startup_folder", [])),
    ]
    for src, lst in cmdline_sets:
        if not isinstance(lst, list):
            continue
        duplicate_counts = {}
        for raw_index, e in enumerate(lst):
            raw_key = canonical_evidence(e)
            ordinal = duplicate_counts.get(raw_key, 0)
            duplicate_counts[raw_key] = ordinal + 1
            _set_source(src, e, raw_index, ordinal)
            cmd = e if isinstance(e, str) else _kt_path_of(e)
            if not cmd or len(cmd) < 4:
                continue
            hit = False
            for rx, label, mitre in _LOLBIN_HIGH:
                if rx.search(cmd):
                    _add("HIGH", f"LOLBin悪用({label}): {cmd[:90]}",
                         f"{src} で LOLBin 悪用パターン（{label}）を検出。"
                         "ファイルレス攻撃の常套手段。コマンドライン全体の確認を推奨。",
                         cmd[:200], mitre)
                    hit = True
                    break
            if hit:
                continue
            for rx, label, mitre in _LOLBIN_MED:
                if rx.search(cmd):
                    _add("MEDIUM", f"LOLBin悪用({label}): {cmd[:90]}",
                         f"{src} で LOLBin 悪用の疑い（{label}）。正規利用の可能性もあり要確認。",
                         cmd[:200], mitre)
                    break

    high = sum(1 for e in entries if e["score"] == "HIGH")
    med  = sum(1 for e in entries if e["score"] == "MEDIUM")
    if entries:
        summary = f"既知ツール/異常配置の決定論検出: HIGH {high}件 / MEDIUM {med}件"
    else:
        summary = "既知ツール/異常配置・Webシェルの該当なし"
    result = {"section": "known_tools", "entries": entries, "section_summary": summary}
    synthetic = [
        {
            "source_id": str(entry.get("source_id") or ""),
            "derived_source_section": str(entry.get("_derived_source_section") or ""),
            "identifier": str(entry.get("identifier") or ""),
        }
        for entry in entries if str(entry.get("source_id") or "")
    ]
    if len(synthetic) == len(entries):
        result = _attach_complete_rule_provenance(
            "known_tools", synthetic, result, reason="known_tools_rule"
        )
        result["_provenance"]["provenance_scope"] = "derived_findings"
        result["_provenance"]["derived_from_sections"] = sorted({
            str(entry.get("_derived_source_section") or "")
            for entry in entries if entry.get("_derived_source_section")
        })
    return result

# bits_jobs post-filter: Microsoft 正規配信ドメイン（Edge/Windows Update 等）
_BITS_MS_URL_RE = re.compile(
    r"https?://[^\s]*\.("
    r"delivery\.mp\.microsoft\.com"
    r"|dl\.delivery\.mp\.microsoft\.com"
    r"|windowsupdate\.com"
    r"|update\.microsoft\.com"
    r"|download\.microsoft\.com"
    r"|prod\.do\.dsp\.mp\.microsoft\.com"
    r")",
    re.I,
)
# bits_jobs post-filter: 通知コマンド（notify_cmd）が "none" 以外であることを示す痕跡。
# iocs/reason 中に "notify:" や "通知コマンド" 表記でコマンド本体が残る場合に検出。
_BITS_NOTIFY_RE = re.compile(
    r"(?:notify(?:_cmd)?|通知コマンド)\s*[:：]\s*(?!none\b|なし)\S",
    re.I,
)


# v3.61: rdp_1024 の接続先がGUID形式のみのケース（実データ HOST-REF-08 で確認。
# 1024イベントの server フィールドが GUID で、ホスト名/IP がログに記録されない。
# Hyper-V 仮想マシン接続 (vmconnect / 拡張セッション。GUID=VM ID) 等で発生）。
_GUID_ONLY_RE = re.compile(
    r"^\{?[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}?$")
_RDP_GUID_NOTE = ("[注記] 接続先がGUID形式: Hyper-V 仮想マシン接続(vmconnect)等の"
                  "可能性。ホスト名/IPは1024イベントに記録されない")


# ── 提案5(v3.64): 決定論 MEDIUM フロア ──────────────────────────────────────
# LEAN A/B 実測（HOST-REF-08・2回）で、LLM 判定の揺らぎにより実害級のエントリ
# （Public\Libraries\x64.exe、Temp\wmic.exe 等）が HIGH→CLEAN/LOW へ落ちる事象が
# 再現した。この種の「配置だけで疑わしい」パターンは LLM の判定に依存させず、
# ルールで MEDIUM 未満へ落とさない（昇格フロア）。HIGH/MEDIUM は不変・降格なし。
# 対象セクション: directory / appcompat_cache（完全パスを持つ2セクション）。
# 注: ⑥WL降格はフロア後に適用されるため、WL登録済みの正規ファイルは
#     従来どおり CLEAN へ降格できる（明示的なキュレーションを優先）。

# (i) 既知不審配置: 正規利用が稀で攻撃ステージングに頻出するディレクトリ
_FLOOR_SUSP_DIRS = (
    "\\users\\public\\libraries\\",
    "\\perflogs\\",
    "\\$recycle.bin\\",
    "\\windows\\help\\",
    "\\windows\\fonts\\",
    "\\windows\\debug\\",
    "\\windows\\tracing\\",
)
_FLOOR_EXEC_EXT = tuple(sorted(directory_policy.EXECUTABLE_EXTS))

# (ii) OSバイナリ名の偽装: 本来 System32/SysWOW64 に存在するバイナリ名が
#      システム配置外にある場合（DLLサイドローディング・マスカレード疑い）
_FLOOR_OS_BINARIES = {
    "wmic.exe", "svchost.exe", "rundll32.exe", "lsass.exe", "csrss.exe",
    "services.exe", "winlogon.exe", "dllhost.exe", "conhost.exe",
    "smss.exe", "wininit.exe", "spoolsv.exe", "taskhost.exe",
    "taskhostw.exe", "regsvr32.exe", "mshta.exe", "certutil.exe",
    "powershell.exe", "explorer.exe",
}
_FLOOR_LEGIT_PREFIXES = (
    "c:\\windows\\system32\\", "c:\\windows\\syswow64\\",
    "c:\\windows\\winsxs\\", "c:\\windows\\servicing\\",
    "c:\\program files\\windowsapps\\",
)
_FLOOR_LEGIT_EXACT = (r"c:\windows\explorer.exe",)


def _floor_rule(path: str):
    """パスがフロア対象なら (ルールID, 注記) を、対象外なら None を返す。"""
    p = (path or "").lower().replace("/", "\\")
    if not p:
        return None
    canonical = directory_policy.floor_reason(path)
    if canonical and canonical[0] in {"os_masquerade", "double_extension", "startup_persistence"}:
        return canonical
    if any(p.endswith(ext) for ext in _FLOOR_EXEC_EXT):
        if any(d in p for d in _FLOOR_SUSP_DIRS):
            return ("susp_dir",
                    "[フロア] 既知不審配置（攻撃ステージング頻出ディレクトリ）の"
                    "実行ファイルのため MEDIUM 未満に降格しない")
        if canonical:
            return canonical
        if _USER_WRITABLE_EXEC_RE.search(p):
            return ("user_writable_execution_artifact",
                    "[フロア] ユーザー書込可能領域の実行可能痕跡であり、"
                    "製品名やファイル名だけでは無害断定できないため MEDIUM 未満に降格しない")
    return None


# 提案10(v3.66): reason-score矛盾フロア。
# HOST-REF-11裁定で実観測: LLM が reason に「malware関連ドメイン」と書きながら
# score を LOW に下げるケース（vipns4.queniudns.com 等）。判定根拠が悪性に
# 言及しているのにスコアが CLEAN/LOW のエントリは MEDIUM へ床上げする。
# 否定形（「〜ではない」「無関係」「可能性は低い」等）は誤発動防止のため除外。
_CONTRA_ALARM_RE = re.compile(r"(malware|マルウェア|悪性|C2)", re.I)
_CONTRA_NEGATE_RE = re.compile(
    r"(malware|マルウェア|悪性|C2)(?:関連|の要素|の兆候|の根拠|の可能性|性)?"
    r".{0,10}?(ではない|では無い|でない|に該当しない|無関係|なし|認められない|"
    r"見られない|されなかった|されていない|されず|低い|考えにくい)", re.I)


def _apply_reason_contradiction_floor(sec_result: dict) -> int:
    """CLEAN/LOW なのに reason が悪性へ言及するエントリを MEDIUM へ昇格。
    戻り値=昇格数。全セクション対象・冪等（[フロア]注記の二重付与なし）。"""
    n = 0
    for e in sec_result.get("entries", []):
        if not isinstance(e, dict) or e.get("score") not in ("CLEAN", "LOW"):
            continue
        r = e.get("reason") or ""
        # 冪等ガードは本ルール固有のマーカーで判定する（可視性フロアで
        # LOW 化されたエントリへの複合昇格を妨げない）
        if e.get("_floor") == "reason_contradiction" or "スコアと矛盾" in r:
            continue
        # 可視性フロア等の注記文自体を悪性言及と誤認しないよう、
        # 判定は注記付加前の元 reason 部分（[フロア] より前）で行う
        r_orig = r.split("[フロア]")[0]
        if not _CONTRA_ALARM_RE.search(r_orig) or _CONTRA_NEGATE_RE.search(r_orig):
            continue
        e["score"] = "MEDIUM"
        e["reason"] = (r.rstrip() + ("" if r.rstrip().endswith("。") else "。")
                       + "[フロア] 判定根拠が悪性関連に言及しておりスコアと矛盾"
                         "するため MEDIUM へ床上げ（要確認）")
        e["_floor"] = "reason_contradiction"
        e["deterministic_origin"] = "reason_contradiction"
        n += 1
    return n


# 提案8(v3.65): 可視性フロア用 — netstat の LISTENING 識別子パターン
# （例: "0.0.0.0:30193 → 0.0.0.0:0" / "[::]:7680 → [::]:0"）
_NETSTAT_LISTEN_RE = re.compile(r"→\s*(0\.0\.0\.0:0|\[::\]:0)\s*$")
_NETSTAT_STANDARD_REMOTE_PORTS = {22, 53, 80, 123, 443, 993, 995}
_ALLOWED_SCORES = frozenset({"HIGH", "MEDIUM", "LOW", "CLEAN"})
_UNATTRIBUTED_PROCESS_HINTS = frozenset({
    "", "-", "unknown", "unknown process", "n/a", "na", "none", "null",
    "pidなし", "不明", "未取得", "unattributed",
})
_USER_WRITABLE_EXEC_RE = re.compile(
    r"(?:\\users\\[^\\]+\\(?:appdata|downloads|desktop)\\|"
    r"\\users\\public\\|\\windows\\temp\\|"
    r"(?:^|\\)temp\\)", re.I)


def _raw_entry_for_result(entry: dict, raw_entries) -> dict:
    """Resolve raw evidence by stable source_id before positional fallback."""
    if not isinstance(entry, dict) or not isinstance(raw_entries, list):
        return {}
    source_id = str(entry.get("source_id", "") or "")
    if source_id:
        for raw in raw_entries:
            if isinstance(raw, dict) and str(raw.get("source_id", "") or "") == source_id:
                return raw
    idx = entry.get("_raw_source_index", entry.get("source_index"))
    try:
        idx = int(idx)
    except (TypeError, ValueError):
        idx = -1
    if 0 <= idx < len(raw_entries) and isinstance(raw_entries[idx], dict):
        return raw_entries[idx]
    return {}


def _is_unattributed_process_hint(value) -> bool:
    text = re.sub(r"\s+", " ", str(value or "")).strip().casefold()
    if text in _UNATTRIBUTED_PROCESS_HINTS:
        return True
    return bool(re.fullmatch(r"(?:pid\s*[:=]?\s*)?(?:0|-1|unknown|n/?a|none|null)", text))


def _invalid_score_entries(result: object) -> list[dict]:
    if not isinstance(result, dict):
        return []
    return [e for e in (result.get("entries") or [])
            if isinstance(e, dict) and e.get("score") not in _ALLOWED_SCORES]


def _normalise_score_schema(sec_result: dict) -> dict:
    """Fail operationally safe while preserving invalid LLM score provenance."""
    if not isinstance(sec_result, dict):
        return sec_result
    warnings = []
    for pos, entry in enumerate(sec_result.get("entries") or []):
        if not isinstance(entry, dict):
            continue
        raw = entry.get("score")
        if raw in _ALLOWED_SCORES:
            continue
        entry["score_raw"] = raw
        entry["score"] = "MEDIUM"
        entry["score_normalization_warning"] = "invalid_score"
        entry["schema_degraded"] = True
        reason = str(entry.get("reason", "") or "").rstrip()
        note = ("[schema recovery] LLMが許容外scoreを返したため、証拠を欠落させず"
                "MEDIUMへ安全縮退。原値はscore_rawに保持。")
        if note not in reason:
            entry["reason"] = reason + (" " if reason else "") + note
        warnings.append({
            "entry_index": pos,
            "source_id": str(entry.get("source_id", "") or ""),
            "identifier": str(entry.get("identifier", "") or ""),
            "score_raw": raw,
            "action": "normalized_to_MEDIUM",
        })
    if warnings:
        sec_result["schema_degraded"] = True
        sec_result["_schema_warnings"] = warnings
    return sec_result


def _apply_medium_floor(section: str, sec_result: dict) -> int:
    """CLEAN/LOW エントリに決定論フロアを適用し MEDIUM へ昇格する。戻り値=昇格数。
    HIGH/MEDIUM は不変。冪等（[フロア] 注記の二重付与なし）。"""
    n = 0
    for e in sec_result.get("entries", []):
        if not isinstance(e, dict) or e.get("score") not in ("CLEAN", "LOW"):
            continue
        cand = (e.get("iocs") or [None])[0] or e.get("identifier") or ""
        hit = _floor_rule(str(cand))
        if not hit:
            continue
        rule_id, note = hit
        e["score"] = "MEDIUM"
        r = (e.get("reason") or "").rstrip()
        if "[フロア]" not in r:
            e["reason"] = (r + ("" if not r or r.endswith("。") else "。") + note)
        e["_floor"] = rule_id   # 監査用
        e["deterministic_origin"] = rule_id
        n += 1
    return n


def _apply_post_filter(section: str, sec_result: dict, raw_entries=None) -> dict:
    """
    LLM 結果に対してルールベースの post-filter を適用する。
    降格対象エントリの score を CLEAN に書き換え、reason に注記を付加する。
    取りこぼし防止を最優先とするため、条件は厳格に限定する。
    """
    if section == "task_scheduler":
        for entry in sec_result.get("entries", []):
            if entry.get("score") not in ("HIGH", "MEDIUM"):
                continue
            identifier = entry.get("identifier", "")
            task_path  = entry.get("iocs", [""])[0] if entry.get("iocs") else identifier
            for task_re, path_re, desc in _TASK_CLEAN_RULES:
                if task_re.search(identifier) and path_re.search(task_path):
                    orig_score = entry["score"]
                    entry["score"]  = "CLEAN"
                    entry["reason"] = (
                        f"[post-filter: CLEAN降格] {desc}。"
                        f"元スコア={orig_score}。{entry.get('reason','')}"
                    )
                    break   # 最初にマッチしたルールで降格、複数適用はしない

    elif section == "startup_folder":
        raw_entries = raw_entries if isinstance(raw_entries, list) else []

        def _raw_startup(entry):
            idx = entry.get("_raw_source_index") if isinstance(entry, dict) else None
            if isinstance(idx, int) and 0 <= idx < len(raw_entries):
                candidate = raw_entries[idx]
                if isinstance(candidate, dict):
                    return candidate
            identifier = str(entry.get("identifier", "") if isinstance(entry, dict) else "")
            ident_name = identifier.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
            for candidate in raw_entries:
                if not isinstance(candidate, dict):
                    continue
                path = str(candidate.get("path", ""))
                if path.casefold() == identifier.casefold():
                    return candidate
                if path.replace("/", "\\").rsplit("\\", 1)[-1].casefold() == ident_name:
                    return candidate
            return {}

        for entry in sec_result.get("entries", []):
            if not isinstance(entry, dict):
                continue
            raw_entry = _raw_startup(entry)
            identifier = str(entry.get("identifier", ""))
            raw_path = str(raw_entry.get("path", ""))
            lock_name = (raw_path or identifier).replace("/", "\\").rsplit("\\", 1)[-1]
            # ~$*.dot / ~$*.dotm は Word の一時ロックファイル（永続化とは無関係）
            if lock_name.startswith("~$") or _STARTUP_LOCK_RE.search(identifier):
                orig_score = entry.get("score", "CLEAN")
                entry["score"] = "CLEAN"
                entry["reason"] = (
                    f"[post-filter: CLEAN降格] Word 一時ロックファイル（~$プレフィックス）。"
                    f"Word 使用中のみ存在し永続化とは無関係。元スコア={orig_score}。"
                )
                entry["mitre"] = []
                continue

            mandatory_reason = depth2_select.deterministic_mandatory_reason(
                section, raw_entry)
            if mandatory_reason:
                orig_score = str(entry.get("score", "CLEAN"))
                entry["score"] = "HIGH"
                note = ("[deterministic floor: HIGH] Officeスタートアップ配下の"
                        "マクロ対応ファイルで、suspicious=trueかつ一時ロック"
                        "ファイルではない。")
                prior = str(entry.get("reason", "") or "")
                entry["reason"] = note + (f" 元スコア={orig_score}。{prior}" if prior else
                                            f" 元スコア={orig_score}。")
                mitre = list(entry.get("mitre") or [])
                if "T1137.001" not in mitre:
                    mitre.append("T1137.001")
                entry["mitre"] = mitre
                entry["depth2_mandatory_reason"] = mandatory_reason
                entry["deterministic_origin"] = mandatory_reason

    elif section == "system_7045":
        # 中国語環境で大量に出現する正規サービスの AppData 配置を MEDIUM 降格。
        # 取りこぼし防止のため「明らかに正規」かつ「AppData 配置が仕様上の正規動作」
        # と断言できるもの（WPS / Chrome）に限定する。
        # 「2345ブラウザ」「HWiNFO」等のグレーゾーンは降格しない。
        _7045_MEDIUM_RULES = [
            # WPS Office Cloud Service / WPS Update Task
            # Kingsoft の WPS は AppData\Local\Kingsoft に展開するのが正規仕様
            (re.compile(r"WPS\s+Office", re.I),
             re.compile(r"\\AppData\\Local\\Kingsoft\\", re.I),
             "WPS Office の AppData 内サービス（Kingsoft 正規仕様）"),
            # Google Chrome Elevation Service
            # ユーザーインストール時に AppData\Local\Google\Chrome に配置されるのが正規動作
            # ただし path が Google\Chrome 配下でない場合は降格しない
            (re.compile(r"Google\s+Chrome\s+Elevation\s+Service", re.I),
             re.compile(r"\\AppData\\Local\\Google\\Chrome\\", re.I),
             "Google Chrome Elevation Service（AppData ユーザーインストール、正規動作）"),
        ]
        for entry in sec_result.get("entries", []):
            if not isinstance(entry, dict):
                continue
            raw_service = _raw_service_for_entry(entry, raw_entries)
            original_identifier = str(entry.get("identifier", "") or "")
            original_reason = str(entry.get("reason", "") or "")
            raw_service_name = str(
                raw_service.get("service_name", raw_service.get("name", "")) or ""
            ).strip().rstrip("\x00")
            svc = raw_service_name or original_identifier
            if raw_service_name:
                entry["service_name_raw"] = raw_service_name
                if raw_service_name.casefold() != original_identifier.strip().casefold():
                    entry["llm_identifier_raw"] = original_identifier
                    entry["llm_reason_raw"] = original_reason
                    entry["identifier"] = raw_service_name
                    entry["evidence_reconciled"] = True
                    entry["evidence_reconciliation_warning"] = (
                        "llm_identifier_replaced_by_raw_service_name"
                    )
            raw_image = str(raw_service.get("image_path", "") or "")
            if not raw_image:
                raw_image = str((entry.get("iocs") or [""])[0] if entry.get("iocs") else "")
            service_cmd = _parse_service_command(raw_image)
            executable = service_cmd.get("executable", "")
            executable_base = re.split(r"[\\/]", executable)[-1] if executable else ""

            entry["image_path_raw"] = service_cmd.get("raw", "")
            command_warnings = list(service_cmd.get("warnings") or [])
            if command_warnings:
                entry["service_command_warnings"] = command_warnings
                entry["service_command_warning"] = command_warnings[0]
            if executable:
                entry["service_executable"] = executable
                entry["service_arguments"] = service_cmd.get("arguments", "")
                entry["service_argument_paths"] = service_cmd.get("argument_paths", [])
                entry["iocs"] = [executable]

            # rc15: raw ServiceNameとMicrosoft package pathの両方が厳格に一致する
            # Gaming Servicesは、LLMがRustDesk等へ誤同定しても正常サービスとして
            # 決定論的に収束させる。ファイル名VT参考検索の対象にも送らない。
            gaming_name_matches_exe = (
                raw_service_name.casefold()
                == os.path.splitext(executable_base)[0].casefold()
            )
            if (_GAMING_SERVICES_NAME_RE.fullmatch(raw_service_name)
                    and _GAMING_SERVICES_PATH_RE.fullmatch(executable)
                    and gaming_name_matches_exe):
                entry["score"] = "CLEAN"
                entry["reason"] = (
                    "[post-filter: CLEAN降格] Microsoft Gaming Servicesの正規WindowsApps "
                    "package service。原イベントのServiceNameとImagePathが厳格条件に一致。"
                )
                entry["mitre"] = []
                entry["lolbas"] = None
                entry["decoded"] = None
                entry["service_identity_kind"] = "microsoft_gaming_services"
                continue

            # raw eventが存在する場合、LLMのidentifierは遠隔操作ツール判定へ使わない。
            # rawが利用不能な旧fixtureのみ後方互換としてidentifierへfallbackする。
            remote_identity = raw_service_name if raw_service_name else original_identifier
            is_remote_admin = bool(
                _KT_REMOTEADMIN_RE.search(executable_base)
                or _KT_REMOTEADMIN_RE.search(remote_identity)
            )
            if is_remote_admin and executable:
                high_location = bool(_KT_SVC_USERWRITE_RE.search(executable)
                                     or _KT_SVC_HIGHLOC_RE.search(executable))
                program_files = bool(_KT_PROGRAM_FILES_RE.search(executable))
                entry["score"] = "HIGH" if high_location else "MEDIUM"
                if high_location:
                    location_note = "実行ファイルがユーザー書込可能領域に存在するためHIGHを維持"
                elif program_files:
                    location_note = "実行ファイルはProgram Files配下だが遠隔操作サービスのため要確認"
                else:
                    location_note = "既知遠隔操作ツールのサービス登録であり導入主体の確認が必要"
                entry["reason"] = (
                    f"[post-filter: 既知遠隔操作サービス] {location_note}（T1219/T1543.003）。"
                    f"実行ファイル: {executable}"
                )
                entry["mitre"] = sorted(set((entry.get("mitre") or []) + ["T1219", "T1543.003"]))
                continue

            # LLM識別子と原イベントが食い違うが専用正常系にも遠隔操作系にも
            # 該当しない場合、原証拠へ再同期し、危険パスはHIGH、その他はMEDIUMへ
            # 決定論的に収束する。LLM説明は監査用raw fieldにのみ保持する。
            if entry.get("evidence_reconciled"):
                high_location = bool(
                    executable and (
                        _KT_SVC_USERWRITE_RE.search(executable)
                        or _KT_SVC_HIGHLOC_RE.search(executable)
                    )
                )
                entry["score"] = "HIGH" if high_location else "MEDIUM"
                entry["reason"] = (
                    "[post-filter: 証拠再同期] LLM識別子を原イベントのServiceNameへ置換。"
                    + (f"実行ファイル: {executable}。" if executable else "ImagePath未取得。")
                    + ("ユーザー書込可能領域のためHIGH。" if high_location
                       else "サービス登録の由来確認が必要なためMEDIUM。")
                )
                entry["mitre"] = sorted(
                    set(m for m in (entry.get("mitre") or []) if m != "T1219")
                    | {"T1543.003"}
                )
                continue
            if entry.get("score") != "HIGH":
                continue
            # iocs[0] が image_path になっている場合と identifier に含まれる場合がある
            img  = entry.get("iocs", [""])[0] if entry.get("iocs") else ""
            text = svc + " " + img
            # N-2: MpKsl{16進} は Windows Defender の動的署名（KSL）サービス。
            # ProgramData\Microsoft\Windows Defender 配下に一時生成される正規サービスで、
            # サービス名が乱数様のため誤って HIGH 大量検知される（本検体で169件中多数）。
            # サービス名が MpKsl+16進 かつ ImagePath が Defender 配下の場合のみ CLEAN 降格。
            if _MPKSL_NAME_RE.search(text) and (_MPKSL_PATH_RE.search(text) or not img):
                orig_score = entry["score"]
                entry["score"]  = "CLEAN"
                entry["reason"] = (
                    f"[post-filter: CLEAN降格] Windows Defender 動的署名サービス"
                    f"（MpKsl+乱数）。Defender が一時生成する正規サービス。元スコア={orig_score}。"
                )
                continue
            for svc_re, path_re, desc in _7045_MEDIUM_RULES:
                if svc_re.search(text) and path_re.search(text):
                    entry["score"]  = "MEDIUM"
                    entry["reason"] = (
                        f"[post-filter: MEDIUM降格] {desc}。"
                        f"元スコア=HIGH。{entry.get('reason','')}"
                    )
                    break

        _rebuild_system_7045_summary(sec_result)

    elif section == "bits_jobs":
        # T-23: Microsoft 正規配信ドメインかつ通知コマンドなしの BITS ジョブを CLEAN 降格。
        # 取りこぼし防止のため「URL が Microsoft 正規配信」かつ「notify_cmd が none」の
        # 両方を満たす場合のみに限定する（notify_cmd ありは正規ドメインでも降格しない）。
        for entry in sec_result.get("entries", []):
            if entry.get("score") not in ("HIGH", "MEDIUM"):
                continue
            iocs   = entry.get("iocs", []) or []
            blob   = " ".join(iocs) + " " + entry.get("identifier", "") + " " + entry.get("reason", "")
            url_ok = bool(_BITS_MS_URL_RE.search(blob))
            # 通知コマンドの有無は reason / identifier 中の表現から推定できないため、
            # iocs に notify コマンドが含まれていれば降格しない（厳格側）。
            notify_present = bool(_BITS_NOTIFY_RE.search(blob))
            if url_ok and not notify_present:
                orig_score = entry["score"]
                entry["score"]  = "CLEAN"
                entry["reason"] = (
                    f"[post-filter: CLEAN降格] Microsoft 正規配信ドメインかつ通知コマンドなしの "
                    f"BITS ジョブ（Edge/Windows Update の正規動作）。元スコア={orig_score}。"
                    f"{entry.get('reason','')}"
                )

    elif section == "dns_cache":
        # 提案8(v3.65): 可視性フロア。Level1/suspicious フィルタを通過して
        # LLM に届いたドメインは「要確認候補」であり、LLM による完全な無害断定
        # （CLEAN)を許可しない。根拠を創作した CLEAN 化（confabulation。
        # 第3回A/Bの online.autotranshub.com =「一般的なサービスドメイン」と
        # 無根拠に断定→CLEAN、で実観測）による可視性喪失を決定論で防ぐ。
        # LOW は _all 版レポートに掲載され可視性が維持される。FULL/LEAN 両モード対象。
        for e in sec_result.get("entries", []):
            if not isinstance(e, dict) or e.get("score") != "CLEAN":
                continue
            e["score"] = "LOW"
            r = (e.get("reason") or "").rstrip()
            if "[フロア]" not in r:
                e["reason"] = (r + ("" if not r or r.endswith("。") else "。")
                               + "[フロア] 事前フィルタ通過ドメインのため"
                                 "無害断定せず LOW で可視化")
            e["_floor"] = "dns_visibility"
            e["deterministic_origin"] = "dns_visibility"

    elif section == "netstat":
        raw_entries = raw_entries if isinstance(raw_entries, list) else []
        # rc18: 特定IP/portへ寄せず、外部・非標準port・未帰属という証拠クラスを
        # 最低MEDIUMで可視化する。HIGHはTI、既知IOC、永続化等の追加根拠に委ねる。
        for e in sec_result.get("entries", []):
            if not isinstance(e, dict):
                continue
            raw_e = _raw_entry_for_result(e, raw_entries)
            remote = str(raw_e.get("remote", "") or "")
            state = str(raw_e.get("state", "") or "").upper()
            proc_hint = raw_e.get("_proc_hint", raw_e.get("process", raw_e.get("process_name", "")))
            host = remote
            port = ""
            if remote.startswith("[") and "]:" in remote:
                host, port = remote[1:].rsplit("]:", 1)
            elif remote.count(":") == 1:
                host, port = remote.rsplit(":", 1)
            is_external = bool(host) and not ioc_utils.is_private_ip(host)
            is_nonstandard = port.isdigit() and int(port) not in _NETSTAT_STANDARD_REMOTE_PORTS
            if (state in {"ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"}
                    and is_external and is_nonstandard
                    and _is_unattributed_process_hint(proc_hint)
                    and e.get("score") in {"CLEAN", "LOW"}):
                orig = str(e.get("score", "CLEAN"))
                e["score"] = "MEDIUM"
                prior = str(e.get("reason", "") or "")
                e["reason"] = (
                    "[deterministic floor: MEDIUM] プロセス帰属を確認できない外部IPへの"
                    f"非標準ポート接続（{remote}）。元スコア={orig}。" + prior
                )
                e["_floor"] = "netstat_external_nonstandard_unattributed_medium"
                e["deterministic_origin"] = "netstat_external_nonstandard_unattributed_medium"

        # 提案8(v3.65): LISTENING（待受）の CLEAN 禁止・最低 LOW。
        # 待受ポートは攻撃者の受け口になり得るため、プロセス名の一致等のみで
        # 無害断定しない（例: 第3回A/Bの 0.0.0.0:30193「AVCore.exe が使用」→CLEAN）。
        # ルールベースのローカル宛 CLEAN 固定（③前処理・外向き接続）は識別子が
        # 「→ :0」形式でないため対象外。エフェメラル/ループバック LISTENING は
        # 既に LOW 固定（T-29）で本フロアと整合する。
        for e in sec_result.get("entries", []):
            if not isinstance(e, dict) or e.get("score") != "CLEAN":
                continue
            if not _NETSTAT_LISTEN_RE.search(str(e.get("identifier") or "")):
                continue
            e["score"] = "LOW"
            r = (e.get("reason") or "").rstrip()
            if "[フロア]" not in r:
                e["reason"] = (r + ("" if not r or r.endswith("。") else "。")
                               + "[フロア] 待受ポートのため無害断定せず LOW で可視化")
            e["_floor"] = "netstat_listen_visibility"
            e["deterministic_origin"] = "netstat_listen_visibility"

    elif section == "rdp_1024":
        # v3.61: GUID形式の接続先へ決定論注記を付ける（スコア不変・降格なし）。
        # LLMの解釈揺らぎに依存せず、identifier が GUID のみのエントリに
        # 「何のGUIDか・なぜホスト名が無いか」を明示する。冪等（二重付与なし）。
        for e in sec_result.get("entries", []):
            if not isinstance(e, dict):
                continue
            ident = (e.get("identifier") or "").strip()
            if _GUID_ONLY_RE.match(ident) and _RDP_GUID_NOTE not in (e.get("reason") or ""):
                r = (e.get("reason") or "").rstrip()
                e["reason"] = (r + ("" if not r or r.endswith("。") else "。")
                               + _RDP_GUID_NOTE)

    elif section == "wmi":
        for entry in sec_result.get("entries", []):
            if not isinstance(entry, dict):
                continue
            note = "[収集制約] CheckPC-6.11.1はWMI Consumerのみ収集し、__EventFilterと__FilterToConsumerBindingは未収集。有効な永続化かは判定不能。"
            reason = (entry.get("reason") or "").rstrip()
            if note not in reason:
                entry["reason"] = reason + (" " if reason else "") + note
            entry["evidence_scope"] = "consumer_only"

    elif section == "directory":
        # M-2: OS/インストーラ由来の既知benign一時ファイル（wct/ns*/~DF/CR_/GUID .tmp）
        #   を MEDIUM→LOW 降格（CLEAN にはせず可視性は維持）。取りこぼし防止のため
        #   .tmp データファイルのみを対象とし、実行体（.exe/.dll/.sys 等）は対象外。
        for entry in sec_result.get("entries", []):
            if entry.get("score") != "MEDIUM":
                continue
            path = (entry.get("iocs", [""]) or [""])[0] or entry.get("identifier", "")
            if _DIR_BENIGN_TEMP_RE.search(str(path)):
                entry["score"]  = "LOW"
                entry["reason"] = (
                    f"[post-filter: LOW降格] OS/インストーラ由来の既知一時ファイル"
                    f"（wct/ns*/~DF/CR_/GUID .tmp）。元スコア=MEDIUM。"
                    f"{entry.get('reason','')}"
                )

    # 提案5(v3.64): 決定論 MEDIUM フロア（降格分岐の後・全条件の最後に適用）
    if section in ("directory", "appcompat_cache"):
        _apply_medium_floor(section, sec_result)

    # 提案10(v3.66): reason-score矛盾フロア（全セクション・最終段）
    _apply_reason_contradiction_floor(sec_result)

    # rc8: FULL/LEANでIP:port、hash大小文字、FQDN大小文字、command line
    # 表現が揺れないよう、最終成果物のIOCを共通正規化する。ポートは
    # ioc_portsへ分離し、ファイルパスはbasename化せず完全値を保持する。
    for _entry in sec_result.get("entries", []):
        ioc_utils.normalize_entry_iocs(_entry)

    return sec_result
# エントリを A/B/C/D の4優先度に分類してLLM送付とスキップを制御する。
# 「単純に冒頭N行を切り捨てると取りこぼしが発生する」問題に対して
# パターン種別で分類し、重要なものを確実に送付する設計。
#
#  A（最高優先・必ずLLM送付）: 攻撃ツール名・二重拡張子・UAC Bypass・
#                              Windows\\Temp実行ファイル・Tasks配下
#  B（高優先・必ずLLM送付）:   Public/ProgramData/ドライブ直下の exe/dll 等
#  C（低優先・LLM送付 上限3ch）: [78aA]ハッシュ系 tmp/xml/log
#                              アプリキャッシュが大半。上限を設けて送付。
#  D（LLM未送付・別ファイル出力）: zip/rar/7z 圧縮ファイル
#                              ダウンロード・バックアップが大半。
#                              パスを見れば意図が分かるため目視向き。

_DIR_PRIORITY_A = [
    re.compile(r"mimikatz|psexec|gsedump|pwdump|meterpreter", re.I),
    # 二重拡張子（文書偽装）: exe/scr はダブルクリック実行の偽装のため場所問わず A。
    re.compile(r"\.(doc|docx|xls|xlsx|pdf|txt)\.(exe|scr)$", re.I),
    # .dll の二重拡張子: 正規の名前空間DLL（Windows.Data.Pdf.dll,
    #   Microsoft.Ceres.DocParsing.FormatHandlers.Pdf.dll 等）は System32 等の
    #   信頼配置に置かれるため誤爆する。以下の条件でのみ A とする:
    #     · パス区切り "\\" を含む（バレ名だけの値では判定しない）
    #     · 信頼された配置（System32/SysWOW64/WinSxS/Program Files/WindowsApps/
    #       Microsoft.NET/Windows Defender 系）でない
    #   → 信頼配置外（Temp/ユーザー領域等）の .pdf.dll 等は引き続き A で捕捉。
    re.compile(
        r"^(?=.*\\)(?!.*\\(?:System32|SysWOW64|WinSxS|"
        r"Program Files(?: \(x86\))?|Microsoft\.NET|WindowsApps|"
        r"Windows Defender[^\\]*)\\)"
        r".*\.(?:doc|docx|xls|xlsx|pdf|txt)\.dll$", re.I),
    re.compile(r"\\sysprep\\.*cryptbase\.dll", re.I),
    re.compile(rf"\\windows\\temp\\[^\\]+\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$", re.I),
    re.compile(rf"\\windows\\tasks\\[^\\]+\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN}|job)$", re.I),
    re.compile(r"\bwce(64)?\.(exe|dll)\b|\bwceaux(64)?\.dll\b", re.I),
]
_DIR_PRIORITY_B = [
    re.compile(rf"\\public\\.*\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$", re.I),
    re.compile(rf"^[a-z]:\\[^\\]+\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$", re.I),
    re.compile(rf"^[a-z]:\\programdata\\[^\\]+\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$", re.I),
    re.compile(rf"^[a-z]:\\programdata\\[^\\]+\\[^\\]+\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$", re.I),
    re.compile(rf"^[d-z]:\\.*\\[^\\]+\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$", re.I),
    re.compile(r"__SIZE_ZERO__", re.I),
]
_DIR_PRIORITY_C = re.compile(r"[78aA][0-9a-fA-F]{3}\.(tmp|xml|log)$", re.I)
_DIR_PRIORITY_D = re.compile(r"\.(rar|zip|7z)$", re.I)
# depth=1 での C優先度 最大チャンク数（超過分はスキップ）
_DIR_C_MAX_CHUNKS = 3


def _classify_dir_entry(entry: dict) -> str:
    """directory エントリを A/B/C/D の優先度に分類する。"""
    for v in entry.values():
        if not isinstance(v, str):
            continue
        for pat in _DIR_PRIORITY_A:
            if pat.search(v):
                return "A"
    for v in entry.values():
        if not isinstance(v, str):
            continue
        for pat in _DIR_PRIORITY_B:
            if pat.search(v):
                return "B"
    for v in entry.values():
        if not isinstance(v, str):
            continue
        if _DIR_PRIORITY_C.search(v):
            return "C"
        if _DIR_PRIORITY_D.search(v):
            return "D"
    return "B"  # 上記以外は B 扱い（保守的）


# ── N-4c: directory 異常スコアリング ─────────────────────────────────────────
# A/B/C 分類を土台に加点し、上位 DIR_MAX_LLM 件のみ LLM 送付。残りは raw ファイルへ
# 退避（取りこぼし防止のため可視化、黙って捨てない）。上限は env で可変。
DIR_MAX_LLM = max(20, int(os.environ.get("CHECKPC_DIR_MAX_LLM", "200")))

# \Users\Public\ 配下の実行体（exe/dll/script）。サブフォルダを問わず怪しい
# （全ユーザー書込可能・永続領域で、正規実行体はほぼ置かれない）。
# 非実行体（共有ドキュメント等）は除外し、suspdir(+25)のみとする。
_DIR_FEAT_PUBLIC = re.compile(
    rf"\\Users\\Public\\.*\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$",
    re.I)
_DIR_FEAT_DRIVEROOT  = re.compile(rf"^[A-Za-z]:\\[^\\]+\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$", re.I)
_DIR_FEAT_SUSPDIR    = re.compile(
    r"\\(?:Temp|Public|ProgramData|\$Recycle|PerfLogs)\\|"
    r"\\AppData\\Local\\Temp\\|\\\.[A-Za-z0-9_]+\\", re.I)
_DIR_FEAT_DOUBLEEXT  = re.compile(
    rf"\.(?:pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|csv|rtf)\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$", re.I)
_DIR_FEAT_MASQ       = re.compile(
    r"\\(?!.*\\System32\\)(?:svchost|lsass|csrss|services|winlogon|explorer|conhost)\.exe$", re.I)
_DIR_FEAT_SCRIPT     = re.compile(rf"\.(?:{directory_policy.SCRIPT_EXT_PATTERN}|scr|pif)$", re.I)
_DIR_FEAT_HEXNAME    = re.compile(rf"\\[0-9a-fA-F]{{8,}}\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN}|tmp|dat)$", re.I)
# F: 永続化・隠蔽に多い配置
_DIR_FEAT_STARTUP    = re.compile(
    rf"\\Start Menu\\Programs\\Startup\\.*\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN}|lnk|url)$", re.I)
_DIR_FEAT_RECYCLE_EXE = re.compile(rf"\\\$Recycle\.Bin\\.*\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$", re.I)
# AppData\Roaming 直下（名前付きサブフォルダでない）の実行体。正規アプリは
# AppData\Roaming\<アプリ名>\ を使うため、直下の実行体はマルウェアの典型。
_DIR_FEAT_APPDATA_ROOT = re.compile(
    rf"\\AppData\\Roaming\\[^\\]+\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})$", re.I)

def _dir_anomaly_score(entry: dict, cls: str) -> int:
    """directory エントリの異常スコア（高いほど不審）。

    アンカー付き正規表現は、日時・size・source_idを連結したblobではなく、
    canonicalなpath単独へ適用する。これにより実parsed形状でもpath-only試験と
    同じ特徴が発火する。
    """
    score = {"A": 100, "B": 40, "C": 10, "D": 0}.get(cls, 40)
    path = directory_policy.entry_path(entry)
    if _DIR_FEAT_DOUBLEEXT.search(path):    score += 60
    if _DIR_FEAT_MASQ.search(path):         score += 60
    if _DIR_FEAT_PUBLIC.search(path):       score += 40
    if _DIR_FEAT_RECYCLE_EXE.search(path):  score += 40
    if _DIR_FEAT_STARTUP.search(path):      score += 35
    if _DIR_FEAT_DRIVEROOT.search(path):    score += 30
    if _DIR_FEAT_APPDATA_ROOT.search(path): score += 25
    if _DIR_FEAT_SUSPDIR.search(path):      score += 25
    if _DIR_FEAT_SCRIPT.search(path):       score += 20
    if _DIR_FEAT_HEXNAME.search(path):      score += 15
    score += directory_policy.extension_risk(path) * 3
    return score


# ── N-4d(v3.59/案b): directory 同型パターン集約 ──────────────────────────────
# 実運用で発覚（HOST-REF-03）: C:\Windows\temp の GUID名 .tmp.js のような
# 「単一ソフトが量産したとみられる同型ファイル」が全件同点（例: 85点 =
# B40+SUSPDIR25+SCRIPT20）となり、上位 DIR_MAX_LLM 枠の大半を占有して、
# より低い点の要確認エントリを raw 退避へ押し出す。対策として、
# 「同一フォルダ×同一ファイル名パターン」を1シグネチャとみなし、
# シグネチャごとに代表 DIR_SIG_MAX 件のみ LLM 送付する（残りは従来通り
# raw_directory へ退避・件数を⚠エントリで可視化。黙って捨てない）。
DIR_SIG_MAX = max(0, int(os.environ.get("CHECKPC_DIR_SIG_MAX", "3")))
DIR_M1_MAX = max(0, int(os.environ.get("CHECKPC_DIR_M1_MAX", "80")))
DIR_M1_PARENT_MAX = max(1, int(os.environ.get("CHECKPC_DIR_M1_PARENT_MAX", "8")))
DIR_M1_PLACEMENT_MAX = max(1, int(os.environ.get("CHECKPC_DIR_M1_PLACEMENT_MAX", "32")))

_DIR_SIG_HEXRUN = re.compile(r"[0-9a-fA-F]{4,}")
_DIR_SIG_NUMRUN = re.compile(r"\d{3,}")


def _dir_signature(entry: dict) -> str:
    """同型パターン集約用のシグネチャを返す。
    親フォルダ（小文字）＋ 可変部（4文字以上の16進連なり・3桁以上の数字連なり）
    を '#' に正規化したファイル名。GUID名・16進名・タイムスタンプ名の
    量産ファイルが同一シグネチャに畳まれる。拡張子チェーンは保持される
    （.tmp.js と .tmp.exe は別シグネチャ）。"""
    d = entry.get("dir") or ""
    n = entry.get("name") or ""
    if not d and not n:
        d, _, n = (entry.get("path") or "").rpartition("\\")
    n = _DIR_SIG_HEXRUN.sub("#", n.lower())
    n = _DIR_SIG_NUMRUN.sub("#", n)
    return d.lower() + "\\" + n


def _select_dir_llm_entries(scored: list, max_llm: int = None,
                            sig_max: int = None, m1_max: int = None,
                            m1_parent_max: int = None,
                            m1_placement_max: int = None) -> tuple:
    """Select directory entries with bounded M0/M1/Tier-R semantics.

    M0 is guaranteed after same-signature deduplication and may exceed the
    normal directory budget. M1 is selected by placement round-robin with
    parent/placement caps. Tier R has no fixed maximum and consumes every
    normal-budget slot left after M0/M1. All non-selected entries are returned
    for raw-directory output and provenance accounting.
    """
    if max_llm is None:
        max_llm = DIR_MAX_LLM
    if sig_max is None:
        sig_max = DIR_SIG_MAX
    if m1_max is None:
        m1_max = DIR_M1_MAX
    if m1_parent_max is None:
        m1_parent_max = DIR_M1_PARENT_MAX
    if m1_placement_max is None:
        m1_placement_max = DIR_M1_PLACEMENT_MAX

    ordered = sorted(
        scored,
        key=lambda item: (-int(item[0]), *directory_policy.canonical_sort_key(item[2])),
    )
    by_tier = {"M0": [], "M1": [], "R": []}
    for item in ordered:
        by_tier[directory_policy.evidence_tier(item[2])].append(item)

    selected = []
    selected_ids = set()
    deferred_sig = {}
    signature_deferred_ids = set()
    sig_count = {}

    def accept_signature(item) -> bool:
        if sig_max <= 0:
            return True
        sig = _dir_signature(item[2])
        if sig_count.get(sig, 0) >= sig_max:
            deferred_sig[sig] = deferred_sig.get(sig, 0) + 1
            signature_deferred_ids.add(id(item[2]))
            return False
        sig_count[sig] = sig_count.get(sig, 0) + 1
        return True

    def take(item):
        selected.append(item)
        selected_ids.add(id(item[2]))

    for item in by_tier["M0"]:
        if accept_signature(item):
            take(item)

    placement_buckets = {}
    for item in by_tier["M1"]:
        placement = directory_policy.m1_placement(item[2]) or "unknown"
        placement_buckets.setdefault(placement, []).append(item)
    placements = sorted(placement_buckets)
    ptr = {placement: 0 for placement in placements}
    parent_count = {}
    placement_count = {}
    m1_policy_deferred_ids = set()
    m1_selected = 0
    while m1_selected < m1_max:
        progressed = False
        for placement in placements:
            bucket = placement_buckets[placement]
            while ptr[placement] < len(bucket):
                item = bucket[ptr[placement]]
                ptr[placement] += 1
                parent = directory_policy.parent_path(item[2])
                if placement_count.get(placement, 0) >= m1_placement_max:
                    m1_policy_deferred_ids.add(id(item[2]))
                    continue
                if parent_count.get(parent, 0) >= m1_parent_max:
                    m1_policy_deferred_ids.add(id(item[2]))
                    continue
                if not accept_signature(item):
                    continue
                take(item)
                placement_count[placement] = placement_count.get(placement, 0) + 1
                parent_count[parent] = parent_count.get(parent, 0) + 1
                m1_selected += 1
                progressed = True
                break
            if m1_selected >= m1_max:
                break
        if not progressed:
            break

    remaining = max(0, int(max_llm) - len(selected))
    for item in by_tier["R"]:
        if remaining <= 0:
            break
        if accept_signature(item):
            take(item)
            remaining -= 1

    overflow = [item for item in ordered if id(item[2]) not in selected_ids]
    tier_total = {tier: len(vals) for tier, vals in by_tier.items()}
    tier_selected = {tier: 0 for tier in by_tier}
    for item in selected:
        tier_selected[directory_policy.evidence_tier(item[2])] += 1
    tier_deferred = {tier: tier_total[tier] - tier_selected[tier] for tier in by_tier}

    selected_id_set = set(selected_ids)
    for item in by_tier["M1"]:
        eid = id(item[2])
        if eid not in selected_id_set and eid not in signature_deferred_ids:
            m1_policy_deferred_ids.add(eid)
    over_budget_ids = {
        id(item[2]) for item in by_tier["R"]
        if id(item[2]) not in selected_id_set and id(item[2]) not in signature_deferred_ids
    }

    n_deferred_sig = len(signature_deferred_ids)
    deferred_reason_counts = {
        "signature_diversity": n_deferred_sig,
        "m1_policy_bound": len(m1_policy_deferred_ids),
        "over_normal_budget": len(over_budget_ids),
    }
    top = sorted(deferred_sig.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    parent_top = sorted(parent_count.items(), key=lambda kv: (-kv[1], kv[0]))[:20]
    info = {
        "sig_deferred": n_deferred_sig,
        "n_deferred": n_deferred_sig,  # v3.69 compatibility alias
        "deferred_reason_counts": deferred_reason_counts,
        "deferred_reason_semantics": {
            "signature_diversity":
                "duplicate signature encountered before selection budget was exhausted",
            "m1_policy_bound":
                "M1 candidate deferred by M1 total, parent, or placement bound",
            "over_normal_budget":
                "Tier R candidate not selected after the normal directory budget was exhausted",
        },
        "sig_max": sig_max,
        "top": top,
        "tier_total": tier_total,
        "tier_selected": tier_selected,
        "tier_deferred": tier_deferred,
        "m1_limits": {
            "max": m1_max,
            "parent_max": m1_parent_max,
            "placement_max": m1_placement_max,
        },
        "m1_selected_by_placement": dict(sorted(placement_count.items())),
        "m1_selected_by_parent_top": [[parent, count] for parent, count in parent_top],
        "coverage_degraded": bool(sum(tier_deferred.values())),
        "coverage_degraded_m1": bool(tier_deferred["M1"]),
        "normal_budget": int(max_llm),
        "selected_total": len(selected),
        "normal_budget_overrun_by_m0": max(0, len(selected) - int(max_llm)),
    }
    return ([e for _, _, e in selected], [e for _, _, e in overflow], info)

# 10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8 は先頭オクテットだけで一意に
# CIDR境界が決まるため文字列前方一致で安全に判定できる。
# Tailscale 等の CGNAT(100.64.0.0/10) は対象外。
_LOCAL_IP_PREFIXES = (
    "10.", "192.168.", "127.",
    "169.254.",  # APIPA / リンクローカル（WSD/SSDP 等）
    "100.64.",   # CGNAT（Tailscale 等のオーバーレイ VPN）
)


def _is_local_remote(entry: dict) -> bool:
    """netstat エントリの remote (\"IP:port\") が基本的なプライベート/
    ループバックレンジ宛かどうかを判定する。"""
    remote = entry.get("remote", "") if isinstance(entry, dict) else ""
    ip = remote.rsplit(":", 1)[0] if ":" in remote else remote
    if ip.startswith(_LOCAL_IP_PREFIXES):
        return True
    # 修正(2026-06-12): 172.16.0.0/12 (172.16.0.0-172.31.255.255) も
    # RFC1918プライベートレンジ。"172.16." 等の単純な前方一致では
    # 172.17.x.x〜172.31.x.x を取り逃すため、第2オクテットが16-31の
    # 範囲かを整数で判定する。
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2 and parts[1].isdigit():
            return 16 <= int(parts[1]) <= 31
    return False


def _is_public_ip(ip: str) -> bool:
    """着信RDPの接続元(source_ip)が外部（グローバル）IP かどうかを判定する（N-1）。
    プライベート/ループバック/リンクローカル/CGNAT は False。
    IPv4・IPv6 双方を保守的に扱い、判定不能（ホスト名等）は False（=内部扱い）にしない。
    """
    if not ip:
        return False
    s = ip.strip()
    # IPv6
    if ":" in s and "." not in s.split(":")[0]:
        low = s.lower()
        if low in ("::1",) or low.startswith(("fe80", "fc", "fd")):
            return False  # ループバック/リンクローカル/ULA
        return True  # その他 IPv6 はグローバル扱い（保守的）
    # IPv4
    if s.startswith(_LOCAL_IP_PREFIXES):
        return False
    if s.startswith("172."):
        parts = s.split(".")
        if len(parts) >= 2 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return False
    # ドット4組の数値であれば外部 IPv4 とみなす
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    # ホスト名・不明形式は判定不能 → 安全側で外部扱い（取りこぼし防止）
    return True


# 修正(2026-06-12): netstat の depth=1 で、LISTENING のうち
# エフェメラル/動的ポート範囲(49152-65535、IANA定義のDynamic/Private
# Ports、Windows DCOM/RPCの動的エンドポイントが割り当てられる)を
# ルールベースLOW固定とし、LLMには送らずreportには残す。
# この範囲はOSバージョンに依存しないIANA標準のため、6.4.1/(4)で
# 懸念したような「ポート一覧の保守コスト」は発生しない。バックドア/C2の
# 待受ポートは攻撃者が選ぶ固定ポート（8090等）であることが多く、通常
# この範囲には入らないため、port8090/PID19152のような所見は維持される。
_EPHEMERAL_PORT_RANGE = range(49152, 65536)


def _is_ephemeral_rpc_listening(entry: dict) -> bool:
    """netstat エントリが、エフェメラル範囲でLISTENING中かどうかを判定する。"""
    if not isinstance(entry, dict) or entry.get("state") != "LISTENING":
        return False
    local = entry.get("local", "")
    port = local.rsplit(":", 1)[-1] if ":" in local else ""
    return port.isdigit() and int(port) in _EPHEMERAL_PORT_RANGE


# ─────────────────────────────────────────────────────────────
# テキスト変換（JSON → LLM 投入用テキスト）
# ─────────────────────────────────────────────────────────────
def entries_to_text(section: str, entries) -> str:
    """
    セクションデータを LLM が読みやすいテキストに変換する。

    修正(2026-07-10 / v3.58): identifier転写誤差対策（下記参照）のため、
    各エントリ先頭に通し番号 [#N]（0始まり、call_llm_chunked() に渡される
    チャンク内でのローカル番号）を付与するようにした。
    call_llm_chunked() 側で LLM 応答の source_index フィールドと突き合わせ、
    identifier を _canonical_identifier() が返す元データの値へ強制上書きする。

    【背景】 HOST-REF-08 の実データで、タスク名「起動アクセラレータ」が
    LLMの出力上で「起動アクスレートアドレート」という別のカタカナ文字列に
    化けて report に記載される事例を確認した。原因はエンコーディングでは
    なく（生バイトは正しくcp932でデコードできることを実データで確認済み）、
    identifier をLLM自身に自由記述させる設計上、外来語カタカナ等の転写を
    LLMが誤る（ハルシネーション）リスクがあったため。番号方式により、
    identifier の最終確定値をプログラム側の元データで保証する。
    """
    if not entries:
        return "(データなし)"

    if isinstance(entries, str):
        # raw text セクション（startup_folder 等）
        # 長すぎる場合は先頭 4000 文字に制限
        return entries[:4000] if len(entries) > 4000 else entries

    if isinstance(entries, list):
        lines = None
        sep = "\n"

        if section == "persistence_reg":
            lines = [
                f"[{e.get('reg_key','')}] {e.get('entry_name','')} = {e.get('path','')}"
                for e in entries
            ]

        elif section == "task_scheduler":
            sep = "\n\n"
            lines = [
                f"タスク名: {t.get('task_name','')}\n"
                f"  実行パス: {t.get('task_path','')}\n"
                f"  実行ユーザー: {t.get('run_as','')}\n"
                f"  前回実行: {t.get('last_run','')}\n"
                f"  次回実行: {t.get('next_run','')}"
                for t in entries
            ]

        elif section == "service":
            sep = "\n\n"
            lines = [
                f"サービス名: {s.get('name','')} ({s.get('display_name','')})\n"
                f"  状態: {s.get('state','')} 起動: {s.get('start_type','')}\n"
                f"  ImagePath: {s.get('image_path','')}\n"
                f"  ServiceDll: {s.get('service_dll','')}"
                for s in entries
            ]

        elif section == "directory":
            lines = [
                f"{f.get('date','')} {str(f.get('size','') or '').rjust(12)} {f.get('path','')}"
                for f in entries
            ]

        elif section == "dns_cache":
            lines = [f"{d.get('fqdn','')} → {d.get('resolve','')}" for d in entries]

        elif section == "netstat":
            lines = []
            for c in entries:
                proc = c.get("_proc_hint", "")
                proc_str = f" [{proc}]" if proc else ""
                lines.append(
                    f"{c.get('proto','')} {c.get('local','')} → {c.get('remote','')} "
                    f"[{c.get('state','')}] PID:{c.get('pid','')}{proc_str}"
                )

        elif section == "prefetch":
            lines = [
                f"{p.get('name','')} | 作成:{p.get('created','')} | 更新:{p.get('modified','')}"
                for p in entries
            ]

        elif section == "appcompat_cache":
            lines = []
            for r in entries:
                flags = []
                if r.get("blacklisted"):
                    flags.append("blacklisted=true")
                if r.get("wrong_path"):
                    flags.append("wrong_path=true")
                if r.get("suspicious") and not r.get("blacklisted") and not r.get("wrong_path"):
                    flags.append("suspicious=true")
                flag_str = f" [{', '.join(flags)}]" if flags else ""
                bl_comment = f" # {r['bl_comment']}" if r.get("bl_comment") else ""
                lines.append(
                    f"{r.get('last_modified','')} | {r.get('path','')}{flag_str}{bl_comment}"
                )

        elif section == "startup_folder":
            lines = []
            for r in entries:
                flag = " [suspicious=true]" if r.get("suspicious") else ""
                lines.append(
                    f"{r.get('date','')} | {str(r.get('size','') or '').rjust(8)} | "
                    f"[{r.get('source','')}] {r.get('path','')}{flag}"
                )

        elif section == "defender_quarantine":
            lines = []
            for r in entries:
                vendor = r.get("vendor", "")
                threat = r.get("threat_name", "")
                source = r.get("source", "")
                note   = r.get("note", "")
                threat_str = f" | threat:{threat}" if threat else " | threat:不明（VT照合推奨）"
                note_str   = f" | {note}" if note and source == "directory_scan" else ""
                lines.append(
                    f"{r.get('datetime','')} | [{vendor}] | src:{source}"
                    f"{threat_str} | {r.get('path','')}{note_str}"
                )

        elif section == "ps_history":
            # parse_ps_history() が返す str のリスト
            lines = [str(e) for e in entries]

        elif section == "hosts":
            # parse_hosts() が返す dict のリスト（path, ip, hostname, suspicious）
            lines = []
            for r in entries:
                flag = " [suspicious=true]" if r.get("suspicious") else ""
                lines.append(
                    f"{r.get('ip','').ljust(20)} {r.get('hostname','')}{flag}"
                )

        elif section == "system_7045":
            # parse_system_7045() が返す dict のリスト
            lines = [
                f"{e.get('datetime','')} | サービス名: {e.get('service_name','')} | "
                f"ImagePath: {e.get('image_path','')} | "
                f"アカウント: {e.get('account_name','')}"
                for e in entries
            ]

        elif section == "rdp_1024":
            # parse_rdp_1024() が返す dict のリスト
            # 日時・接続先サーバー・ユーザーを1行で表示
            lines = [
                f"{e.get('datetime','')[:19]} | 接続先: {e.get('server','')} | "
                f"ユーザー: {e.get('user','')}"
                for e in entries
            ]

        elif section == "bits_jobs":
            # parse_bits_jobs() が返す dict のリスト
            # 判定の核心である url と notify_cmd を必ず提示する
            lines = [
                f"DISPLAY: {e.get('display','')} | STATE: {e.get('state','')} | "
                f"OWNER: {e.get('owner','')} | 作成: {e.get('creation_time','')}\n"
                f"  URL: {e.get('url','')}\n"
                f"  保存先: {e.get('local_file','')}\n"
                f"  通知コマンド(notify): {e.get('notify_cmd','')} | "
                f"整合性: {e.get('integrity','')} | 昇格: {e.get('elevated','')}"
                for e in entries
            ]

        if lines is None:
            # rc27: 全list-backed sectionを番号付きブロックへ統一する。
            # fallback JSON配列を丸ごと渡すと、LLMがentry順とsource_indexを
            # 取り違えても検出できなかったため、各entryを独立ブロック化する。
            lines = [
                json.dumps(e, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                for e in entries
            ]
            sep = "\n"

        numbered = []
        for i, block in enumerate(lines):
            source_id = ""
            binding_identifier = ""
            if i < len(entries) and isinstance(entries[i], dict):
                source_id = str(entries[i].get("source_id") or "")
                binding_identifier = _canonical_identifier(section, entries[i])
            # rc28: the model must not infer which part of a complex evidence row
            # is the canonical binding value.  Keep the legacy first line intact
            # for readability/tests and add an explicit JSON string on a second
            # line.  The final user-facing identifier is still overwritten from
            # raw evidence after binding succeeds.
            binding_json = json.dumps(binding_identifier, ensure_ascii=False)
            numbered.append(
                f"[#{i}][source_id={source_id}] {block}\n"
                f"  binding_identifier: {binding_json}"
            )
        return sep.join(numbered)

    return json.dumps(entries, ensure_ascii=False, indent=2)


# ─────────────────────────────────────────────────────────────
# チャンク分割
# ─────────────────────────────────────────────────────────────
def _canonical_identifier(section: str, entry) -> str:
    """Return the raw-evidence identifier used for source binding.

    rc27 makes every LLM list section numbered and requires the model to echo
    source_index, source_id and this identifier from the same input block.
    The value is therefore deterministic for every supported list-backed
    section; an empty fallback is not allowed for a dict entry.
    """
    if not isinstance(entry, dict):
        return str(entry) if entry is not None else ""

    if section == "persistence_reg":
        return str(entry.get("path") or entry.get("entry_name") or entry.get("reg_key") or "")
    if section in {"association_exe", "uac_bypass", "active_setup", "com_persistence"}:
        return str(entry.get("value_data") or entry.get("reg_key") or entry.get("value_name") or "")
    if section == "recent_behavior":
        return str(entry.get("value_data") or entry.get("name") or entry.get("reg_key") or "")
    if section == "wmi":
        for key in (
            "Name", "name", "consumer_class", "CommandLineTemplate",
            "ScriptText", "ExecutablePath", "CommandLine", "Class",
        ):
            value = entry.get(key)
            if value not in (None, ""):
                return str(value)
    if section == "task_scheduler":
        return str(entry.get("task_name") or "")
    if section == "service":
        return str(entry.get("name") or "")
    if section == "directory":
        return str(entry.get("path") or "")
    if section == "dns_cache":
        return str(entry.get("fqdn") or "")
    if section == "netstat":
        return f"{entry.get('local','')} → {entry.get('remote','')}"
    if section == "prefetch":
        return str(entry.get("name") or "")
    if section == "appcompat_cache":
        return str(entry.get("path") or "")
    if section == "startup_folder":
        return str(entry.get("path") or "")
    if section == "defender_quarantine":
        return str(entry.get("path") or "")
    if section == "hosts":
        return f"{entry.get('ip','')} {entry.get('hostname','')}".strip()
    if section == "system_7045":
        return str(entry.get("service_name") or "")
    if section == "rdp_1024":
        return str(entry.get("server") or "")
    if section == "bits_jobs":
        return str(entry.get("display") or "")
    if section in {"task_106", "task_140", "task_141"}:
        return str(entry.get("task_name") or entry.get("raw") or "")
    if section == "rdp_inbound":
        return str(entry.get("source_network_address") or entry.get("ip") or entry.get("raw") or "")

    # Generic fail-closed identifier for future list-backed sections. source_id
    # itself is excluded by canonical_evidence(), so this remains stable.
    return canonical_evidence(entry)


def _binding_text(value) -> str:
    """Normalize superficial transcription differences for binding checks."""
    text = str(value or "").strip().strip('"').strip("'")
    text = text.replace("/", "\\")
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\s*→\s*", " → ", text)
    return text.casefold()


def _binding_identifier_candidates(value) -> set[str]:
    """Return conservative representations for binding comparison.

    rc29 permits only deterministic transcription variants observed in the
    base117 COM smoke test:

    * one additional JSON/backslash escape layer;
    * %SystemRoot% / %windir% / \\SystemRoot / <drive>:\\Windows aliases;
    * %CommonProgramFiles% and the standard Common Files expansions.

    Candidates are accepted only when one normalised expected/actual pair is
    identical. Different DLL names, registry keys, CLSIDs and path suffixes
    therefore remain mismatches.
    """
    raw = str(value or "").strip()
    if not raw:
        return set()

    raw_candidates = {raw}

    # The model can preserve one extra JSON/backslash escape layer.
    if "\\\\" in raw:
        raw_candidates.add(raw.replace("\\\\", "\\"))

    # The model can preserve the outer quotes of the input JSON literal.
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        try:
            decoded = json.loads(raw)
        except Exception:
            decoded = None
        if isinstance(decoded, str):
            raw_candidates.add(decoded)
            if "\\\\" in decoded:
                raw_candidates.add(decoded.replace("\\\\", "\\"))

    out: set[str] = set()
    for candidate in raw_candidates:
        text = _binding_text(candidate)
        out.add(text)

        # Canonicalise only well-known Windows directory aliases at the start
        # of a path. Arbitrary environment variables are not expanded.
        win = re.sub(
            r"^(?:%systemroot%|%windir%|\\systemroot|[a-z]:\\windows)(?=\\|$)",
            "<windows-root>",
            text,
            flags=re.IGNORECASE,
        )
        common = re.sub(
            r"^(?:%commonprogramfiles%|[a-z]:\\program files(?: \\(x86\\))?\\common files)(?=\\|$)",
            "<common-program-files>",
            win,
            flags=re.IGNORECASE,
        )
        out.add(common)
    return out


def _binding_identifier_matches(expected: str, actual: str) -> bool:
    if not expected:
        return False
    return bool(
        _binding_identifier_candidates(expected)
        & _binding_identifier_candidates(actual)
    )


def _canonical_iocs(section: str, entry) -> list:
    """
    P3(v3.62): LEAN出力モード用。元データから iocs を決定論的に抽出する。
    対象は LEAN_IOCS_SECTIONS（元データに構造化パス/アドレスを持つセクション）。
    LLM が末尾60文字に省略したパスではなく常に元データの完全値になるため、
    WL照合（v3.53の教訓）・VT照合の安定性も向上する。
    未対応セクション・想定外の型は空リスト（呼び出し側はLLM出力を維持）。
    """
    if not isinstance(entry, dict):
        return []
    vals: list = []
    if section == "persistence_reg":
        vals = [entry.get("path")]
    elif section == "task_scheduler":
        vals = [entry.get("task_path")]
    elif section == "service":
        vals = [entry.get("image_path"), entry.get("service_dll")]
    elif section == "directory":
        vals = [entry.get("path")]
    elif section == "dns_cache":
        vals = [entry.get("fqdn"), entry.get("resolve")]
    elif section == "netstat":
        vals = [entry.get("remote")]
    elif section == "prefetch":
        vals = [entry.get("name")]
    elif section == "appcompat_cache":
        vals = [entry.get("path")]
    elif section == "startup_folder":
        vals = [entry.get("path")]
    elif section == "system_7045":
        vals = [entry.get("image_path")]
    elif section == "rdp_1024":
        vals = [entry.get("server")]
    elif section == "bits_jobs":
        vals = [entry.get("url"), entry.get("local_file")]
    return [v for v in vals if v][:2]


# ─────────────────────────────────────────────────────────────
# v3.68: チャンク計画（出力予算＋入力予算の二段階）
# ─────────────────────────────────────────────────────────────
# oversize 縮退で LLM ビューを中略する自由文フィールドと上限文字数。
# ★通常経路では一切使わない（単独で入力予算を超えるエントリのみ）。
FREE_TEXT_FIELDS = {
    "ps_history":       {"command": 1200},
    "directory":        {"path": 400},
    "appcompat_cache":  {"path": 400},
    "service":          {"image_path": 512, "service_dll": 512},
    "task_scheduler":   {"task_path": 512, "task_name": 256},
    "persistence_reg":  {"path": 512},
    "startup_folder":   {"path": 512},
    "system_7045":      {"image_path": 512},
    "bits_jobs":        {"url": 512, "local_file": 512},
    "prefetch":         {"name": 256},
    "dns_cache":        {"fqdn": 256},
}


def _truncate_middle(sv: str, cap: int) -> str:
    """先頭60% + 中略 + 末尾40%。ファイル名・拡張子を残すため末尾切りにしない。"""
    if len(sv) <= cap:
        return sv
    head = int(cap * 0.6)
    tail = cap - head
    return sv[:head] + f"…({len(sv) - cap}文字省略)…" + (sv[-tail:] if tail else "")


def render_entries(section: str, entries, truncate: bool = False) -> tuple:
    """LLM へ渡すテキストを生成する。原本は一切変更しない。

    truncate=False（既定・通常経路）:
        entries_to_text(section, entries) と1文字も変わらない出力を返す。
        depth=1 の完全再現の前提。
    truncate=True（oversize 縮退経路のみ）:
        FREE_TEXT_FIELDS の長大フィールドを「LLM ビュー」の浅いコピー上でのみ
        中略する。原本 entries は不変。

    戻り値: (text, truncations)
        truncations: [{"field","orig_chars","sent_chars"}, ...]
    """
    if not truncate or not isinstance(entries, list):
        return entries_to_text(section, entries), []
    caps = FREE_TEXT_FIELDS.get(section, {})
    if not caps:
        return entries_to_text(section, entries), []
    views, recs = [], []
    for e in entries:
        if not isinstance(e, dict):
            views.append(e)
            continue
        v = dict(e)                      # 浅いコピー: 原本は不変
        for field, cap in caps.items():
            sv = v.get(field)
            if isinstance(sv, str) and len(sv) > cap:
                v[field] = _truncate_middle(sv, cap)
                recs.append({"field": field, "orig_chars": len(sv),
                             "sent_chars": len(v[field])})
        views.append(v)
    return entries_to_text(section, views), recs


class ChunkSpec(object):
    """1チャンクの送信計画。

    entries        : 原本エントリ（_canonical_identifier/_canonical_iocs はこれを使う）
    source_indices : 各エントリの raw index（provenance 用）
    max_tokens     : このチャンク専用の出力上限（通常は MAX_TOKENS の値）
    truncate       : LLM ビューで中略するか（oversize 縮退時のみ True）
    truncations    : 中略の監査記録
    unevaluable    : 収容不能で LLM へ送れない（selected_unevaluated）
    reason         : unevaluable の理由
    est_input      : 推定入力トークン
    """

    __slots__ = ("entries", "source_indices", "max_tokens", "truncate",
                 "truncations", "unevaluable", "reason", "est_input")

    def __init__(self, entries, source_indices=None, max_tokens=1024,
                 truncate=False, truncations=None, unevaluable=False,
                 reason="", est_input=0):
        self.entries = entries
        self.source_indices = (list(source_indices) if source_indices is not None
                               else list(range(len(entries))))
        self.max_tokens = max_tokens
        self.truncate = truncate
        self.truncations = truncations or []
        self.unevaluable = unevaluable
        self.reason = reason
        self.est_input = est_input

    def __len__(self):
        return len(self.entries)


def _fixed_prompt_tokens(section: str, depth: int, lean: bool,
                         context: str = "") -> int:
    """{data} を除いた固定プロンプト＋システムプロンプト＋chat template の概算。"""
    tmpl = get_prompt(section, depth, lean=lean) or ""
    return (est_tokens(tmpl.replace("{data}", ""))
            + est_tokens(get_system_prompt(context))
            + CHAT_TEMPLATE_TOKENS)


def resolve_n_out_max(section: str, depth: int, lean: bool) -> int:
    """出力予算から 1チャンクの最大件数を算出する（第1段）。

    ★チャンク固定費（JSON 外殻・section_summary 等）を引いてから割る。
      max_tokens // tok_per_entry としない（v3.68 / 指示3）。

    ★depth=1 は現行の CHUNK_SIZE_DEPTH1 を上限として維持し、FULL/LEAN とも
      チャンク境界を変更しない（v3.68-rc2 の互換条件 / 指示3）。
    """
    # ★depth=1 は現行 CHUNK_SIZE_DEPTH1 を【そのまま】使う（min も max も取らない）。
    #   FULL/LEAN ともチャンク境界を一切変更しない（v3.68-rc2 の互換条件 / 指示3）。
    #   動的チャンクは depth>=2 だけに適用する。
    if depth == 1:
        return CHUNK_SIZE_DEPTH1.get(section, 8)

    prof = active_profile()
    max_tok = MAX_TOKENS.get(section, {}).get(depth, 1024)
    tpe = prof.tok_per_entry(section, lean)
    if tpe <= 0:
        # LLM 予算対象外（defender_quarantine 等）。呼ばれない想定だが安全側。
        tpe = 160
    available_output = max_tok - prof.tokens_per_chunk_overhead
    n = max(1, available_output // tpe)
    n = min(n, prof.section_chunk_cap)
    return n


def _resolve_oversize(section: str, entry, gi: int, depth: int, lean: bool,
                      context: str) -> ChunkSpec:
    """単独で入力予算を超えるエントリの縮退（v3.68 / 指示12）。

      S1: 出力 max_tokens を安全な最低値まで縮小
      S2: 長大自由文フィールドのみ LLM ビューで中略（原本は完全保持）
      U : それでも収容不能なら selected_unevaluated として明示
    """
    prof = active_profile()
    fixed = _fixed_prompt_tokens(section, depth, lean, context)
    tpe = prof.tok_per_entry(section, lean) or 160
    floor_out = max(256, tpe + 64)          # JSON 外殻分を加味した安全な最低出力
    budget = input_budget(floor_out, fixed, CHUNK_SAFETY_MARGIN)

    text, _ = render_entries(section, [entry], truncate=False)
    est = est_tokens(text) + ENTRY_INDEX_TOKENS
    if est <= budget:
        return ChunkSpec([entry], [gi], max_tokens=floor_out, est_input=est,
                         reason="oversize_reduced_max_tokens")

    text2, recs = render_entries(section, [entry], truncate=True)
    est2 = est_tokens(text2) + ENTRY_INDEX_TOKENS
    if recs and est2 <= budget:
        return ChunkSpec([entry], [gi], max_tokens=floor_out, truncate=True,
                         truncations=recs, est_input=est2,
                         reason="oversize_truncated")

    return ChunkSpec([entry], [gi], max_tokens=floor_out, unevaluable=True,
                     est_input=est2 if recs else est,
                     reason=f"入力{est2 if recs else est}tok が予算{budget}tok を超過")


def resolve_chunk_plan(section: str, entries: list, depth: int,
                       lean: bool = None, context: str = "",
                       source_indices: list = None) -> dict:
    """出力予算と入力予算の二段階でチャンク分割計画を決定する（v3.68）。

    第1段: resolve_n_out_max()（出力予算 − チャンク固定費 → 件数）
    第2段: 実入力を順番に加算し、コンテキスト予算超過前にチャンクを閉じる

    戻り値:
      {"specs": [ChunkSpec, ...], "max_tokens", "n_out_max", "tok_per_entry",
       "fixed_tokens", "input_budget", "bound_by", "planned_output_tokens"}

    例外: ValueError（入力予算が 0 以下 = 設定不整合。起動時に検出させる）
    """
    if lean is None:
        lean = bool(LEAN_OUTPUT)
    prof = active_profile()
    max_tok = MAX_TOKENS.get(section, {}).get(depth, 1024)
    tpe = prof.tok_per_entry(section, lean) or 160
    n_out_max = resolve_n_out_max(section, depth, lean)
    fixed = _fixed_prompt_tokens(section, depth, lean, context)
    budget = input_budget(max_tok, fixed, CHUNK_SAFETY_MARGIN)
    if budget <= 0:
        raise ValueError(
            f"設定不整合: section={section} depth={depth} lean={lean} で"
            f"入力予算が {budget} tok（max_tokens={max_tok} / 固定={fixed} / "
            f"margin={CHUNK_SAFETY_MARGIN} / max_model_len={MAX_MODEL_LEN}）")

    if source_indices is None:
        source_indices = list(range(len(entries)))

    specs, cur, cur_idx, cur_tok = [], [], [], 0
    bound = set()

    def _close(reason):
        if cur:
            specs.append(ChunkSpec(list(cur), list(cur_idx), max_tokens=max_tok,
                                   est_input=cur_tok))
            bound.add(reason)

    for pos, e in enumerate(entries):
        gi = source_indices[pos]
        text, _ = render_entries(section, [e], truncate=False)
        t = est_tokens(text) + ENTRY_INDEX_TOKENS
        if t > budget:
            _close("input")
            cur, cur_idx, cur_tok = [], [], 0
            specs.append(_resolve_oversize(section, e, gi, depth, lean, context))
            continue
        if cur and (len(cur) >= n_out_max or cur_tok + t > budget):
            _close("output" if len(cur) >= n_out_max else "input")
            cur, cur_idx, cur_tok = [], [], 0
        cur.append(e); cur_idx.append(gi); cur_tok += t
    _close("output" if len(cur) >= n_out_max else "tail")

    n_sel = sum(len(sp) for sp in specs if not sp.unevaluable)
    planned = n_sel * tpe + len(specs) * prof.tokens_per_chunk_overhead
    return {
        "specs": specs,
        "max_tokens": max_tok,
        "n_out_max": n_out_max,
        "tok_per_entry": tpe,
        "fixed_tokens": fixed,
        "input_budget": budget,
        "bound_by": ("input" if "input" in bound else "output"),
        "planned_output_tokens": planned,
        "chunk_overhead_tokens": len(specs) * prof.tokens_per_chunk_overhead,
    }


def chunk_entries(section: str, entries: list, depth: int,
                  lean: bool = None, context: str = "") -> list:
    """後方互換ラッパ。resolve_chunk_plan() の specs からエントリ列を返す。

    ★depth=1 では旧実装（CHUNK_SIZE_DEPTH1 の固定分割）と同一の結果を返す。
      新規コードでは resolve_chunk_plan() を使うこと。
    """
    if not entries:
        return []
    plan = resolve_chunk_plan(section, entries, depth, lean=lean, context=context)
    return [sp.entries for sp in plan["specs"]]


# ─────────────────────────────────────────────────────────────
# LLM 呼び出し
# ─────────────────────────────────────────────────────────────
def extract_first_json_object(text: str) -> Optional[str]:
    r"""
    テキスト中の最初の完全な {...} オブジェクトを波括弧の対応関係を
    数えて抽出する（文字列リテラル内の { } / エスケープを考慮）。

    旧実装の re.search(r"\{[\s\S]+\}", raw) は貪欲マッチのため、
    モデルが正常な1個目のJSONオブジェクトを出力した後に
    同じ内容の繰り返しやプロンプトのエコーを続けてしまった場合
    （Qwen2.5-Coder-32B Q3_K_M で観測される既知の退行挙動）、
    1個目の "{" から最後の "}" までの全体（=1個目の正常なJSON +
    後続のゴミ）を1つの巨大な不正JSONとして抽出してしまい、
    json.loads が必ず失敗していた。

    本関数は1個目の完全なオブジェクトの終端で打ち切って返すため、
    後続に何が続いていても1個目が正常であれば復元できる。
    閉じ括弧に到達できない場合（真の途中切断）は None を返す。
    """
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i+1]
    return None


def _salvage_truncated_entries(raw: str) -> list:
    """max_tokens 到達で切断された JSON から、完了済みの entries オブジェクトを救出する。
    "entries": [ {...}, {...}, {... ←ここで切断 を、完了済みの {...} だけ取り出す。
    文字列内の \\\" や \\\\ を考慮してブレース深度を追跡する（Windowsパス対策）。"""
    m = re.search(r'"entries"\s*:\s*\[', raw)
    if not m:
        return []
    i = m.end()
    n = len(raw)
    out = []
    while i < n:
        # 次のオブジェクト開始 '{' を探す
        while i < n and raw[i] not in "{]":
            i += 1
        if i >= n or raw[i] == "]":
            break
        # '{' から対応する '}' までを文字列考慮で走査
        start = i
        depth = 0
        in_str = False
        esc = False
        end = -1
        while i < n:
            c = raw[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
            else:
                if c == '"':
                    in_str = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            i += 1
        if end < 0:
            break  # 切断途中のオブジェクト → ここで終了
        obj = raw[start:end + 1]
        try:
            out.append(json.loads(obj))
        except json.JSONDecodeError:
            pass
        i = end + 1
    return out


def call_llm(client: OpenAI, model: str, section: str, depth: int,
             data_text: str, verbose: bool = False,
             context: str = "",
             lean: bool = None,
             max_tokens_override: int = None) -> Optional[dict]:
    """
    1 セクション分のデータを LLM に投入し、JSON を返す。
    JSON パースに失敗した場合は raw テキストを返す。
    context が指定された場合はシステムプロンプトに追加コンテキストを付与する。
    """
    if lean is None:
        lean = bool(LEAN_OUTPUT)
    prompt_template = get_prompt(section, depth, lean=lean)
    if not prompt_template:
        print(f"  [WARN] プロンプト未定義: {section} depth={depth}", file=sys.stderr)
        return None

    # Untrusted evidence must not be able to close/reopen the control boundary.
    # Neutralize every reserved marker before adding the single outer boundary.
    bounded_data = wrap_untrusted_evidence(data_text)
    user_msg = prompt_template.replace("{data}", bounded_data)
    tokens   = (int(max_tokens_override) if max_tokens_override is not None
                else MAX_TOKENS.get(section, {}).get(depth, 1024))

    if verbose:
        print(f"  → LLM 呼出し: section={section} depth={depth} "
              f"input_chars={len(user_msg)} max_tokens={tokens}"
              + (f" context={len(context)}chars" if context else ""))

    try:
        # correlate.pyと同じ理由でstopから"```"を除去（実運用で発覚:
        # Qwen2.5-Coderがコードフェンスで書き始めると応答が空になる。
        # extract_first_json_objectはフェンス付き応答からも抽出できるため
        # このstopは不要かつ有害）。
        resp = create_chat_completion(
            client,
            model=model,
            messages=[
                {"role": "system", "content": get_system_prompt(context)},
                {"role": "user",   "content": user_msg},
            ],
            max_tokens=tokens,
            temperature=0.0,
            timeout=REQUEST_TIMEOUT,
        )
    except Exception as e:
        # v3.68: context_length_exceeded は同一入力を再送しても必ず失敗するため
        # transport retry の対象にせず、分割/oversize 縮退へ回す（指示4）。
        err = {"error": str(e), "section": section}
        if is_context_length_error(e):
            err["context_length_exceeded"] = True
        print(f"  [ERROR] LLM 呼出しエラー: {e}", file=sys.stderr)
        return err

    _llm = extract_llm_text(resp)
    _meta = {
        "_finish_reason": _llm.finish_reason,
        "_requested_max_tokens": tokens,
        "_completion_tokens": _llm.usage_completion_tokens,
        "_prompt_tokens": _llm.usage_prompt_tokens,
        "_model_fingerprint": getattr(resp, "system_fingerprint", None) or model,
        "_tokenizer_fingerprint": tokenizer_fingerprint(),
        "_token_estimator": token_estimator_name(),
    }
    if _llm.error:
        _r = {"section": section, "error": _llm.error,
              "parse_error": True, "raw_response": ""}
        _r.update(_meta)
        return _r
    raw = _llm.text
    if _llm.truncated:
        _meta["_truncated"] = True

    # JSON 抽出（最初の完全なオブジェクトのみを取り出す。詳細は
    # extract_first_json_object のdocstring参照）
    obj_str = extract_first_json_object(raw)
    if obj_str:
        try:
            _obj = json.loads(obj_str)
            if isinstance(_obj, dict):
                _obj.update(_meta)
            return _obj
        except json.JSONDecodeError:
            pass

    # フォールバック1: 切断された JSON から完了済みエントリを救出（取りこぼし防止）
    salvaged = _salvage_truncated_entries(raw)
    if salvaged:
        _r = {"section": section, "entries": salvaged,
              "partial_parse": True, "n_salvaged": len(salvaged),
              "raw_response": raw}
        _r.update(_meta)
        return _r
    # フォールバック2: raw テキストをそのまま格納
    _r = {"section": section, "raw_response": raw, "parse_error": True}
    _r.update(_meta)
    return _r


def _call_llm_score_checked(client: OpenAI, model: str, section: str, depth: int,
                            data_text: str, verbose: bool = False, context: str = "",
                            lean: bool = None, max_tokens_override: int = None) -> Optional[dict]:
    """Retry once when a syntactically valid response contains an invalid score."""
    def invoke():
        try:
            return call_llm(client, model, section, depth, data_text, verbose, context,
                            lean=lean, max_tokens_override=max_tokens_override)
        except TypeError as exc:
            if "max_tokens_override" not in str(exc):
                raise
            return call_llm(client, model, section, depth, data_text, verbose, context,
                            lean=lean)

    first = invoke()
    invalid = _invalid_score_entries(first)
    if not invalid:
        return first
    retry = invoke()
    retry_invalid = _invalid_score_entries(retry)
    if isinstance(retry, dict) and not retry.get("error") and not retry.get("parse_error") and not retry_invalid:
        retry["_schema_retry_attempted"] = True
        retry["_schema_retry_succeeded"] = True
        retry["_schema_retry_invalid_count_first"] = len(invalid)
        return retry
    if isinstance(first, dict):
        first["_schema_retry_attempted"] = True
        first["_schema_retry_succeeded"] = False
        first["_schema_retry_invalid_count_first"] = len(invalid)
        first["_schema_retry_invalid_count_second"] = len(retry_invalid)
    return first


def call_llm_chunked(client: OpenAI, model: str, section: str, depth: int,
                     entries: list, verbose: bool = False,
                     context: str = "",
                     lean: bool = None,
                     chunk_plan: dict = None,
                     source_indices: list = None) -> tuple:
    """チャンク計画を保持したまま LLM を呼び出す。

    v3.68-rc2:
      * ``resolve_chunk_plan`` の ``ChunkSpec`` を end-to-end で維持する。
      * FULL/LEAN 共通で source_index カバレッジを検証する。
      * 欠落部分はキューで再帰的に 8→4→2→1 と分割する。
      * oversize/unevaluable は API へ送らず、監査可能な診断を返す。

    戻り値は従来互換の
      ``(entries, section_summary, chunk_errors, chunk_timings)``。
    """
    if lean is None:
        lean = bool(LEAN_OUTPUT)
    if chunk_plan is None:
        chunk_plan = resolve_chunk_plan(
            section, entries, depth, lean=lean, context=context,
            source_indices=source_indices)
    specs = list(chunk_plan.get("specs") or [])
    results = []

    def _normalise_from_source(spec: ChunkSpec, llm_entries: list) -> list:
        """Bind LLM rows to raw evidence and reject cross-entry mixtures.

        rc27 requires a consistent source_index/source_id/identifier triple.
        For multi-entry chunks source_id and identifier are mandatory. A valid
        index alone is no longer sufficient. rev13 keeps that rule strict and
        performs deterministic singleton recovery only in ``_verified`` after
        coverage splitting has reduced an actually missing row to cardinality 1.
        """
        source_id_positions = {}
        identifier_positions = {}
        for pos, source_entry in enumerate(spec.entries):
            if isinstance(source_entry, dict) and source_entry.get("source_id"):
                source_id_positions.setdefault(str(source_entry.get("source_id")), []).append(pos)
            canonical = _canonical_identifier(section, source_entry)
            if canonical:
                identifier_positions.setdefault(_binding_text(canonical), []).append(pos)

        singleton = len(spec.entries) == 1
        for e in llm_entries:
            if not isinstance(e, dict):
                continue
            e.pop("_source_attribution_error", None)
            si = e.get("source_index")
            sid = str(e.get("source_id") or "")
            ident = str(e.get("identifier") or "")
            src = None
            method = ""

            valid_index = (
                isinstance(si, int) and not isinstance(si, bool)
                and 0 <= si < len(spec.entries)
            )
            if valid_index:
                candidate = spec.entries[si]
                expected_sid = (
                    str(candidate.get("source_id") or "")
                    if isinstance(candidate, dict) else ""
                )
                expected_ident = _canonical_identifier(section, candidate)
                if not expected_sid:
                    # Legacy/unit-test inputs created before source_id assignment.
                    # Production parsed evidence always has source_id and takes
                    # the fail-closed branch below.
                    src = candidate
                    method = "legacy_source_index"
                elif sid and sid != expected_sid:
                    e["_source_attribution_error"] = "source_id_index_mismatch"
                    e["_source_attribution_claimed_index"] = int(si)
                elif singleton and sid == expected_sid and not ident:
                    # rc28: a singleton response that copied the stable
                    # source_id but omitted identifier can be recovered because
                    # no other raw entry was present.  A non-empty mismatching
                    # identifier is still rejected, including a neighbouring
                    # entry's identifier used by the negative control.
                    src = candidate
                    method = "singleton_source_id_identifier_omitted"
                elif ident and expected_ident and not _binding_identifier_matches(expected_ident, ident):
                    e["_source_attribution_error"] = "identifier_index_mismatch"
                    e["_source_attribution_claimed_index"] = int(si)
                elif not sid and not ident:
                    e["_source_attribution_error"] = "source_binding_missing"
                    e["_source_attribution_claimed_index"] = int(si)
                elif not sid and ident and expected_ident:
                    # Compatibility fallback: exact canonical identifier is a
                    # sufficient second factor when source_id was omitted.
                    src = candidate
                    method = "source_index_identifier"
                elif not ident:
                    e["_source_attribution_error"] = "identifier_missing"
                    e["_source_attribution_claimed_index"] = int(si)
                else:
                    src = candidate
                    method = "source_index_triple"
            else:
                sid_matches = source_id_positions.get(sid, []) if sid else []
                ident_matches = identifier_positions.get(_binding_text(ident), []) if ident else []
                if len(sid_matches) == 1 and len(ident_matches) == 1 and sid_matches == ident_matches:
                    si = sid_matches[0]
                    src = spec.entries[si]
                    method = "source_id_identifier"
                elif singleton:
                    si = 0
                    src = spec.entries[0]
                    method = "singleton"
                else:
                    e["_source_attribution_error"] = (
                        "source_id_identifier_mismatch"
                        if sid_matches or ident_matches else "unresolved"
                    )
                    e["_source_attribution_candidates"] = max(
                        len(sid_matches), len(ident_matches))

            if e.get("_source_attribution_error"):
                # Coverage accounting must not accept a semantically unbound row.
                e.pop("source_index", None)
                continue

            if src is not None:
                e["source_index"] = int(si)
                canonical = _canonical_identifier(section, src)
                if not canonical:
                    e["_source_attribution_error"] = "canonical_identifier_missing"
                    if valid_index:
                        e["_source_attribution_claimed_index"] = int(si)
                    e.pop("source_index", None)
                    continue
                e["identifier"] = canonical
                if si < len(spec.source_indices):
                    e["_raw_source_index"] = spec.source_indices[si]
                if isinstance(src, dict) and src.get("source_id"):
                    e["source_id"] = src["source_id"]
                elif not singleton and method != "legacy_source_index":
                    e["_source_attribution_error"] = "raw_source_id_missing"
                    if valid_index:
                        e["_source_attribution_claimed_index"] = int(si)
                    e.pop("source_index", None)
                    continue
                repair_meta = e.get("_source_attribution_repair")
                if (isinstance(repair_meta, dict)
                        and repair_meta.get("method") == "coverage_singleton_canonical"):
                    method = "coverage_singleton_canonical"
                e.pop("_source_attribution_claimed_index", None)
                e["_source_attribution_method"] = method

            if isinstance(src, dict) and src.get("datetime") and not e.get("datetime"):
                e["datetime"] = src["datetime"]
                if src.get("source") == "directory_scan":
                    e["datetime_kind"] = "更新"
            if lean:
                e.setdefault("identifier", "")
                e.setdefault("reason", "")
                e.setdefault("mitre", [])
                e.setdefault("iocs", [])
                e.setdefault("decoded", None)
                e.setdefault("lolbas", None)
                if section in LEAN_IOCS_SECTIONS and src is not None:
                    ci = _canonical_iocs(section, src)
                    if ci:
                        e["iocs"] = ci
        return llm_entries

    def _repair_coverage_singleton_binding(spec: ChunkSpec, llm_entries: list,
                                           timing: dict, split_depth: int,
                                           diag: dict | None,
                                           repair_allowed: bool) -> bool:
        """Canonically repair a clean 1:1 coverage retry, and nothing else.

        rev13 deliberately does not turn binding mismatches into a general
        fallback.  Eligibility requires a coverage-split retry (depth > 0),
        one raw row, one schema-valid returned row, a clean transport/parse
        result, and canonical raw binding metadata.  If any binding field is
        wrong or omitted, all three binding fields are replaced atomically.
        """
        if (not repair_allowed or split_depth <= 0
                or len(spec.entries) != 1 or len(llm_entries) != 1):
            return False
        if diag is not None:
            return False
        row = llm_entries[0]
        if not isinstance(row, dict) or row.get("score") not in _ALLOWED_SCORES:
            return False
        raw = spec.entries[0]
        if not isinstance(raw, dict):
            return False
        canonical_sid = str(raw.get("source_id") or "")
        canonical_ident = _canonical_identifier(section, raw)
        if not canonical_sid or not canonical_ident:
            return False

        original_si = row.get("source_index")
        original_sid = str(row.get("source_id") or "")
        original_ident = str(row.get("identifier") or "")
        index_ok = (
            isinstance(original_si, int) and not isinstance(original_si, bool)
            and original_si == 0
        )
        sid_ok = original_sid == canonical_sid
        ident_ok = bool(original_ident) and _binding_identifier_matches(
            canonical_ident, original_ident)
        if index_ok and sid_ok and ident_ok:
            return False

        repaired_fields = []
        if not index_ok:
            repaired_fields.append("source_index")
        if not sid_ok:
            repaired_fields.append("source_id")
        if not ident_ok:
            repaired_fields.append("identifier")
        repair_meta = {
            "method": "coverage_singleton_canonical",
            "original_source_index": original_si,
            "original_source_id": original_sid,
            "original_identifier": original_ident,
            "canonical_source_index": 0,
            "canonical_source_id": canonical_sid,
            "canonical_identifier": canonical_ident,
            "repaired_fields": repaired_fields,
        }
        row["source_index"] = 0
        row["source_id"] = canonical_sid
        row["identifier"] = canonical_ident
        row["_source_attribution_repair"] = repair_meta
        timing["singleton_binding_repair"] = True
        timing["singleton_binding_repair_method"] = "coverage_singleton_canonical"
        timing["singleton_binding_repaired_fields"] = list(repaired_fields)
        return True

    def _subspec(spec: ChunkSpec, positions: list) -> ChunkSpec:
        return ChunkSpec(
            [spec.entries[i] for i in positions],
            [spec.source_indices[i] for i in positions],
            max_tokens=spec.max_tokens,
            truncate=spec.truncate,
            truncations=list(spec.truncations),
            unevaluable=False,
            reason=spec.reason,
            est_input=spec.est_input,
        )

    def _call_once(spec: ChunkSpec, idx: int):
        data_text, runtime_trunc = render_entries(
            section, spec.entries, truncate=bool(spec.truncate))
        t0 = time.time()
        try:
            result = _call_llm_score_checked(
                client, model, section, depth, data_text, verbose, context,
                lean=lean, max_tokens_override=spec.max_tokens)
        except TypeError:
            raise
        elapsed = round(time.time() - t0, 2)
        _fixed_prompt = est_tokens(get_system_prompt(context)) + est_tokens(
            (get_prompt(section, depth, lean=lean) or "").replace("{data}", ""))
        timing = {
            "chunk": idx,
            "n_entries": len(spec.entries),
            "elapsed_sec": elapsed,
            "source_indices": list(spec.source_indices),
            "requested_max_tokens": spec.max_tokens,
            "estimated_input_tokens": spec.est_input,
            "estimated_data_tokens": spec.est_input,
            "estimated_fixed_prompt_tokens": _fixed_prompt,
            "estimated_total_prompt_tokens": spec.est_input + _fixed_prompt,
            "truncated": bool(spec.truncate),
            "truncations": runtime_trunc or list(spec.truncations),
        }
        if isinstance(result, dict):
            for src_key, dst_key in (
                ("_finish_reason", "finish_reason"),
                ("_requested_max_tokens", "requested_max_tokens"),
                ("_completion_tokens", "completion_tokens"),
                ("_prompt_tokens", "prompt_tokens"),
                ("_model_fingerprint", "model_fingerprint"),
                ("_tokenizer_fingerprint", "tokenizer_fingerprint"),
                ("_token_estimator", "token_estimator"),
                ("_schema_retry_attempted", "schema_retry_attempted"),
                ("_schema_retry_succeeded", "schema_retry_succeeded"),
                ("_schema_retry_invalid_count_first", "schema_retry_invalid_count_first"),
                ("_schema_retry_invalid_count_second", "schema_retry_invalid_count_second"),
            ):
                if src_key in result:
                    timing[dst_key] = result[src_key]
            actual = timing.get("prompt_tokens")
            if actual:
                timing["estimate_actual_ratio"] = round(
                    float(timing.get("estimated_input_tokens") or 0) / actual, 4)
        if not result:
            return [], {
                "chunk": idx, "n_entries": len(spec.entries),
                "source_indices": list(spec.source_indices),
                "unevaluated_indices": list(spec.source_indices),
                "selected_unevaluated": True,
                "error": "call_llm returned no result (falsy)",
            }, timing
        if "error" in result:
            diag = {
                "chunk": idx, "n_entries": len(spec.entries),
                "source_indices": list(spec.source_indices),
                "unevaluated_indices": list(spec.source_indices),
                "selected_unevaluated": True,
                "error": result["error"],
            }
            if result.get("context_length_exceeded"):
                diag["context_length_exceeded"] = True
            return [], diag, timing
        if result.get("parse_error"):
            return [], {
                "chunk": idx, "n_entries": len(spec.entries),
                "source_indices": list(spec.source_indices),
                "unevaluated_indices": list(spec.source_indices),
                "selected_unevaluated": True,
                "parse_error": True,
                "raw_response": result.get("raw_response", "")[:2000],
            }, timing
        llm_entries = [e for e in (result.get("entries") or []) if isinstance(e, dict)]
        diag = None
        if result.get("partial_parse"):
            diag = {
                "chunk": idx, "n_entries": len(spec.entries),
                "partial_parse": True,
                "n_salvaged": int(result.get("n_salvaged", len(llm_entries)) or 0),
                "note": "出力切断（完了済み entry はカバレッジ検証へ引き渡し）",
            }
        return llm_entries, diag, timing

    def _call_transport(spec: ChunkSpec, idx: int):
        last = ([], None, {"chunk": idx, "n_entries": len(spec.entries)})
        for attempt in range(LLM_TRANSPORT_RETRY + 1):
            e, d, t = _call_once(spec, idx)
            if attempt:
                t["transport_retry"] = attempt
            last = (e, d, t)
            if d is None:
                return last
            if d.get("context_length_exceeded"):
                return last
            if not d.get("error"):
                return last
        return last

    def _verified(spec: ChunkSpec, idx: int):
        n = len(spec.entries)
        if spec.unevaluable:
            return [], {
                "chunk": idx, "n_entries": n, "source_indices": list(spec.source_indices),
                "oversize": True, "selected_unevaluated": True,
                "unevaluated_indices": list(spec.source_indices),
                "note": "入力が max_model_len を超えるため LLM 未評価: " + spec.reason,
            }, []
        if n == 0:
            return [], None, []

        accepted = {}
        timings = []
        rejected = 0
        rejection_reasons: dict[str, int] = {}
        singleton_used = 0
        singleton_binding_repairs = 0
        unresolved = set()
        binding_rejected = set()
        failure_reasons = []
        # positions は初期 ChunkSpec 内の index。各ノードが独立に細分化される。
        queue = [(list(range(n)), 0)]
        while queue:
            positions, split_depth = queue.pop(0)
            part_spec = _subspec(spec, positions)
            returned, diag, timing = _call_transport(part_spec, idx)
            if isinstance(diag, dict):
                if diag.get("error"):
                    failure_reasons.append(f"error:{str(diag.get('error'))[:240]}")
                elif diag.get("parse_error"):
                    failure_reasons.append("parse_error")
            if split_depth:
                timing["retry"] = True
                timing["retry_reason"] = (
                    "context_length_exceeded" if diag and diag.get("context_length_exceeded")
                    else "coverage_missing")
                timing["coverage_split_depth"] = split_depth
            timings.append(timing)

            # A one-row request must never silently select one row from a
            # multi-row LLM response.  This is fail-closed for both initial
            # singleton chunks and coverage singleton retries.
            if len(positions) == 1 and len(returned) > 1:
                timing["singleton_cardinality_violation"] = True
                rejected += len(returned)
                rejection_reasons["singleton_cardinality_violation"] = (
                    rejection_reasons.get("singleton_cardinality_violation", 0)
                    + len(returned))
                failure_reasons.append("singleton_cardinality_violation")
                unresolved.update(positions)
                continue

            repaired = _repair_coverage_singleton_binding(
                part_spec, returned, timing, split_depth, diag,
                repair_allowed=(
                    len(positions) == 1 and positions[0] not in binding_rejected))
            if repaired:
                singleton_binding_repairs += 1

            # Legacy source_index-only singleton fallback remains available for
            # non-repaired rows. rev13's new source_id/identifier repair is
            # strictly limited to a coverage-split singleton above.
            if len(positions) == 1 and len(returned) == 1 and not repaired:
                si = returned[0].get("source_index")
                if not (isinstance(si, int) and not isinstance(si, bool) and si == 0):
                    returned[0]["source_index"] = 0
                    timing["singleton_fallback"] = True
                    singleton_used += 1

            # Recover an omitted/invalid source_index from structured source_id
            # or a unique canonical identifier before coverage accounting.
            _normalise_from_source(part_spec, returned)

            # A row actually returned in a multi-entry response with a valid
            # claimed source_index but failed binding remains retryable under
            # the legacy coverage algorithm, but that root position is marked
            # ineligible for rev13's new canonical singleton repair.  A later
            # retry may still succeed only by returning a genuinely valid
            # legacy binding, preserving rc27/rc28 behavior.
            if len(positions) > 1:
                for row in returned:
                    if not isinstance(row, dict) or not row.get("_source_attribution_error"):
                        continue
                    claimed = row.get("_source_attribution_claimed_index")
                    if (isinstance(claimed, int) and not isinstance(claimed, bool)
                            and 0 <= claimed < len(positions)):
                        binding_rejected.add(positions[claimed])

            covered_here = set()
            for e in returned:
                si = e.get("source_index")
                if isinstance(si, bool) or not isinstance(si, int) or not (0 <= si < len(positions)):
                    rejected += 1
                    reason = str(e.get("_source_attribution_error") or "invalid_source_index")
                    rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1
                    continue
                root_pos = positions[si]
                if root_pos in accepted:
                    rejected += 1
                    continue
                e["source_index"] = root_pos
                accepted[root_pos] = e
                covered_here.add(root_pos)

            missing = [p for p in positions if p not in covered_here and p not in accepted]
            if not missing:
                continue
            if len(missing) > 1 and split_depth < COVERAGE_MAX_SPLIT_DEPTH:
                mid = len(missing) // 2
                queue.append((missing[:mid], split_depth + 1))
                queue.append((missing[mid:], split_depth + 1))
            elif len(missing) == 1 and split_depth < COVERAGE_MAX_SPLIT_DEPTH:
                # そのノードが複数件だった場合のみ singleton を1回送る。
                if len(positions) > 1:
                    queue.append((missing, split_depth + 1))
                else:
                    unresolved.update(missing)
            else:
                unresolved.update(missing)

        ordered = [accepted[i] for i in sorted(accepted)]
        _normalise_from_source(spec, ordered)
        missing_final = sorted(set(range(n)) - set(accepted))
        if not missing_final:
            return ordered, None, timings
        diag = {
            "chunk": idx, "n_entries": n,
            "source_indices": list(spec.source_indices),
            "partial_parse": True,
            "n_salvaged": len(accepted),
            "retry_attempted": COVERAGE_MAX_SPLIT_DEPTH > 0,
            "coverage": True,
            "lean_coverage": True,
            "selected_unevaluated": True,
            "n_rejected": rejected,
            "rejection_reasons": dict(sorted(rejection_reasons.items())),
            "n_singleton_fallback": singleton_used,
            "n_singleton_binding_repairs": singleton_binding_repairs,
            "binding_rejected_indices": [
                spec.source_indices[i] for i in sorted(binding_rejected)
            ],
            "unevaluated_indices": [spec.source_indices[i] for i in missing_final],
            "note": f"カバレッジ検証: {len(missing_final)}件が未評価",
        }
        if failure_reasons:
            diag["failure_reason"] = " | ".join(dict.fromkeys(failure_reasons))
        return ordered, diag, timings

    chunk_errors = []
    chunk_timings = []
    if not specs:
        return [], "", [], []

    if len(specs) == 1 or CHUNK_MAX_WORKERS <= 1:
        for i, spec in enumerate(specs):
            res, diag, tim = _verified(spec, i)
            results.extend(res)
            chunk_timings.extend(tim)
            if diag:
                chunk_errors.append(diag)
    else:
        with ThreadPoolExecutor(max_workers=CHUNK_MAX_WORKERS) as ex:
            futures = {ex.submit(_verified, spec, i): i for i, spec in enumerate(specs)}
            collected = []
            for fut in as_completed(futures):
                i = futures[fut]
                res, diag, tim = fut.result()
                collected.append((i, res, diag, tim))
            for _, res, diag, tim in sorted(collected):
                results.extend(res)
                chunk_timings.extend(tim)
                if diag:
                    chunk_errors.append(diag)

    chunk_timings.sort(key=lambda t: (
        int(t.get("chunk", 0)), int(t.get("coverage_split_depth", 0)),
        int(t.get("transport_retry", 0))))
    high_med = [e for e in results if e.get("score") in ("HIGH", "MEDIUM")]
    summary = " / ".join(
        f"{str(e.get('identifier',''))[:40]}: {str(e.get('reason',''))[:80]}"
        for e in high_med[:3])
    return results, summary, chunk_errors, chunk_timings


def _task140_group_raw_indices(raw_entries: list, entry: dict) -> tuple[set[int], str]:
    """Validate an explicit task_140 semantic-group one-to-many binding."""
    if str(entry.get("_source_attribution_method") or "") != "task140_semantic_group":
        return set(), "task140_group_method_missing"
    raw_values = entry.get("_raw_source_indices")
    source_ids = entry.get("_source_ids")
    digest = str(entry.get("_task140_semantic_group_sha256") or "")
    if not isinstance(raw_values, list) or not raw_values:
        return set(), "task140_group_raw_indices_missing"
    if not isinstance(source_ids, list) or len(source_ids) != len(raw_values):
        return set(), "task140_group_source_ids_cardinality_mismatch"
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        return set(), "task140_group_digest_invalid"
    indices = []
    for value in raw_values:
        if isinstance(value, bool) or not isinstance(value, int):
            return set(), "task140_group_raw_index_invalid"
        if value < 0 or value >= len(raw_entries):
            return set(), "task140_group_raw_index_out_of_range"
        indices.append(value)
    if len(indices) != len(set(indices)):
        return set(), "task140_group_raw_index_duplicate"
    if any(left >= right for left, right in zip(indices, indices[1:])):
        return set(), "task140_group_raw_indices_not_strictly_increasing"
    if int(entry.get("occurrence_count", 0) or 0) != len(indices):
        return set(), "task140_group_occurrence_count_mismatch"
    representative_sid = str(entry.get("source_id") or "")
    identifier = str(entry.get("identifier") or "")
    if not representative_sid or representative_sid != str(source_ids[0] or ""):
        return set(), "task140_group_representative_source_id_mismatch"
    for pos, idx in enumerate(indices):
        raw = raw_entries[idx]
        if not isinstance(raw, dict):
            return set(), "task140_group_raw_entry_invalid"
        expected_sid = str(raw.get("source_id") or "")
        if not expected_sid or str(source_ids[pos] or "") != expected_sid:
            return set(), "task140_group_source_id_mismatch"
        # Only the representative raw event is required to match the analyzed
        # identifier.  Non-representative members may legitimately have a
        # different raw-text fallback identifier when task_name is empty,
        # because Event[n]/Date metadata is intentionally removed by the
        # semantic grouping key.  Every member is still bound by its exact
        # raw index + source_id and by a semantic digest re-derived below.
        if pos == 0:
            expected_identifier = _canonical_identifier("task_140", raw)
            if not identifier or not _binding_identifier_matches(expected_identifier, identifier):
                return set(), "task140_group_identifier_mismatch"
        key = _task140_semantic_key(raw)
        actual_digest = hashlib.sha256(
            key.encode("utf-8", errors="replace")
        ).hexdigest()
        if actual_digest != digest:
            return set(), "task140_group_semantic_digest_mismatch"
    return set(indices), "task140_semantic_group"


def _result_entry_raw_indices(section: str, raw_entries: list, entry: dict) -> tuple[set[int], str]:
    """Resolve one analyzed entry to raw indices without using free-form reason text.

    Returns ``(indices, method_or_error)``.  Aggregated/raw-index fields are
    authoritative, followed by source_id and a unique canonical identifier.
    Empty indices are never guessed by position.
    """
    if not isinstance(entry, dict) or not isinstance(raw_entries, list):
        return set(), "invalid_entry"
    if section == "task_140" and (
        entry.get("_source_attribution_method") == "task140_semantic_group"
        or entry.get("_task140_semantic_group_sha256")
    ):
        return _task140_group_raw_indices(raw_entries, entry)
    found: set[int] = set()
    for key in ("_raw_source_indices", "_aggregated_source_indices"):
        for value in entry.get(key) or []:
            try:
                idx = int(value)
            except (TypeError, ValueError):
                continue
            if 0 <= idx < len(raw_entries):
                found.add(idx)
    direct = entry.get("_raw_source_index")
    try:
        if direct is not None:
            idx = int(direct)
            if 0 <= idx < len(raw_entries):
                found.add(idx)
    except (TypeError, ValueError):
        pass
    if found:
        # rc27: positional provenance is valid only when source_id and the
        # canonical identifier also agree with every referenced raw entry.
        source_id = str(entry.get("source_id") or "")
        identifier = str(entry.get("identifier") or "")
        for idx in sorted(found):
            raw = raw_entries[idx]
            expected_sid = str(raw.get("source_id") or "") if isinstance(raw, dict) else ""
            expected_ident = _canonical_identifier(section, raw)
            if not source_id or source_id != expected_sid:
                return set(), "raw_index_source_id_mismatch"
            if not identifier or not _binding_identifier_matches(expected_ident, identifier):
                return set(), "raw_index_identifier_mismatch"
        return found, "raw_index_source_id_identifier"

    source_ids = []
    if entry.get("source_id"):
        source_ids.append(str(entry.get("source_id")))
    source_ids.extend(str(x) for x in (entry.get("_source_ids") or []) if x)
    if source_ids:
        sid_to_indices: dict[str, list[int]] = {}
        for idx, raw in enumerate(raw_entries):
            if isinstance(raw, dict) and raw.get("source_id"):
                sid_to_indices.setdefault(str(raw.get("source_id")), []).append(idx)
        candidates = set()
        for sid in source_ids:
            matches = sid_to_indices.get(sid, [])
            if len(matches) != 1:
                return set(), "source_id_ambiguous_or_missing"
            candidates.add(matches[0])
        if candidates:
            return candidates, "source_id"

    identifier = str(entry.get("identifier") or "").strip().casefold()
    if identifier:
        matches = [
            idx for idx, raw in enumerate(raw_entries)
            if str(_canonical_identifier(section, raw) or "").strip().casefold() == identifier
        ]
        if len(matches) == 1:
            return {matches[0]}, "canonical_identifier"
        if len(matches) > 1:
            return set(), "canonical_identifier_ambiguous"
    return set(), "unresolved"


# ─────────────────────────────────────────────────────────────
# セクション別解析
# ─────────────────────────────────────────────────────────────
SECTIONS_TO_ANALYZE = [
    "persistence_reg",
    "association_exe",
    "uac_bypass",
    "active_setup",
    "com_persistence",
    "wmi",
    "startup_folder",       # Word/Excel/Windows スタートアップ永続化
    "task_scheduler",
    "service",
    "directory",
    "dns_cache",
    "netstat",
    "prefetch",
    "appcompat_cache",
    "defender_quarantine",  # Windows Defender 検知・隔離イベント
    "ps_history",           # PowerShell 実行履歴 (T-24)
    "hosts",                # hosts ファイル改ざん検出 (T-22)
    "system_7045",          # 新規サービスインストール eventlog (T-17)
    "security_1102",        # セキュリティログクリア: ルールベース HIGH (T-19)
    "system_104",           # システムログクリア: ルールベース HIGH (T-19)
    "rdp_1024",             # RDP 外向き接続ログ (T-20)
    "bits_jobs",            # BITS ジョブ (T-23)
    "task_106",
    "task_140",
    "task_141",             # タスク削除イベント: ルールベース注記 (T-21-lite)
    "recent_behavior",
    "psexec",               # PsExec存在確認: ルールベース注記 (T-23-psexec)
    "rdp_inbound",          # 着信RDP EID 21/1149: ルールベース (N-1)
    "known_tools",          # 既知ツール/異常パスの決定論的検出: ルールベース (N-3)
    "userassist",           # UserAssist GUI実行痕跡: ルールベース (N-5)
]

def analyze(parsed_json: dict, depth: int,
            client: OpenAI, model: str,
            target_sections: Optional[list] = None,
            verbose: bool = False,
            context: str = "",
            cancel_check: Optional[Callable[[], bool]] = None,
            lean: bool = None,
            progress_callback: Optional[Callable[[object], None]] = None) -> dict:
    """
    構造化 JSON の全セクションを LLM で解析する。
    セクション間は ThreadPoolExecutor で並列実行する（vLLM のバッチ処理を活用）。
    target_sections が指定された場合はそのセクションのみ解析する。
    context が指定された場合はシステムプロンプトに追加コンテキストを付与する。
    cancel_check が指定され、それが True を返すようになった場合、
    未着手のセクションはスキップされる（実行中セクションは完了まで待つ）。
    """
    sections   = parsed_json.get("sections", {})
    event_logs = parsed_json.get("event_logs", {})  # T-17/T-19: EventLog テキスト
    meta       = parsed_json.get("meta", {})
    evidence_quality = parsed_json.get("evidence_quality", {})
    event_quality = evidence_quality.get("event_logs", {}) if isinstance(evidence_quality, dict) else {}
    hostname   = meta.get("hostname", "UNKNOWN")
    _collection_id = str(meta.get("collection_id") or meta.get("input_sha256") or "")

    def _emit_progress(message: str, **detail):
        if not progress_callback:
            return
        payload = {"message": str(message), "phase": "step4", **detail}
        try:
            progress_callback(payload)
        except Exception:
            pass

    # T-18: tasklist の PID → プロセス名マップを事前構築
    # netstat の identifier（local:port）→ pid → プロセス名 の補完に使う。
    # exe_path は tasklist /v でも UWP/保護プロセスは空になるため name のみ使用。
    _tasklist = sections.get("tasklist", [])
    _pid_to_name: dict[str, str] = {
        t.get("pid", ""): t.get("name", "")
        for t in _tasklist
        if t.get("pid") and t.get("name")
    }
    # netstat の local → pid マップ（LISTENINGの127.0.0.1:PORT→PID突合に使う）
    _local_to_pid: dict[str, str] = {
        n.get("local", ""): n.get("pid", "")
        for n in sections.get("netstat", [])
        if n.get("local") and n.get("pid")
    }

    analyze_start = time.time()
    results = {
        "meta":     meta,
        "depth":    depth,
        "sections": {},
    }
    # rc20: 比較前提metadataはfail-closedで生成する。欠落した成果物を
    # compare側で推測して合格させないため、profile/env不正は解析開始前に停止する。
    try:
        _prof = active_profile()
        _profile_dict = _prof.to_dict()
        _max_inflight = int(os.environ.get("CHECKPC_MAX_INFLIGHT_LLM", "9"))
        _pipeline_workers = int(os.environ.get("PIPELINE_MAX_WORKERS", "2"))
    except Exception as exc:
        raise ConfigurationError(f"comparison metadata initialization failed: {exc}") from exc
    if not _profile_dict.get("name") or not _profile_dict.get("fingerprint"):
        raise ConfigurationError("budget profile name/fingerprint is required")
    results["_budget_profile"] = _profile_dict
    results["meta"] = dict(results.get("meta") or {})
    results["meta"].update({
        "pipeline_version": PIPELINE_VERSION,
        "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
        "analysis_mode": "LEAN" if (LEAN_OUTPUT if lean is None else bool(lean)) else "FULL",
        "model": model,
        "depth": depth,
        "budget_profile": _profile_dict.get("name"),
        "budget_profile_fingerprint": _profile_dict.get("fingerprint"),
        "max_inflight_llm": _max_inflight,
        "pipeline_max_workers": _pipeline_workers,
        "comparison_provenance_schema_version": COMPARISON_PROVENANCE_SCHEMA_VERSION,
        "source_id_algorithm_version": SOURCE_ID_ALGORITHM_VERSION,
    })
    results["meta"]["runtime_fingerprint"] = runtime_fingerprint(results["meta"])

    analyze_list = target_sections if target_sections else SECTIONS_TO_ANALYZE

    _EVENT_LOG_SECTIONS = {
        "security_1102", "system_104", "system_7045", "rdp_1024",
        "task_106", "task_140", "task_141", "rdp_inbound",
    }

    def _raw_for_section(sec):
        return event_logs.get(sec) if sec in _EVENT_LOG_SECTIONS else sections.get(sec)

    def _matched_raw_indices(raw_list, filtered_list):
        """filter関数が返した順序保存subsequenceをraw indexへ戻す。"""
        out = []
        j = 0
        for i, item in enumerate(raw_list):
            if j >= len(filtered_list):
                break
            candidate = filtered_list[j]
            if item is candidate or item == candidate:
                out.append(i)
                j += 1
        return set(out)

    def _compress_indices(indices):
        """監査JSONを肥大させず、raw index集合を可逆なrange列へする。"""
        vals = sorted(set(int(x) for x in indices))
        if not vals:
            return []
        ranges = []
        start = prev = vals[0]
        for v in vals[1:]:
            if v == prev + 1:
                prev = v
                continue
            ranges.append([start, prev])
            start = prev = v
        ranges.append([start, prev])
        return ranges

    # depth=2 は LLM 並列処理に入る前に全セクションの選抜を直列確定する。
    # これによりグローバル予算が as_completed の完了順に依存しない。
    _d2_prepared = {}
    _selection_total_elapsed = 0.0
    _selection_per_section = {}
    _selection_planner_elapsed = 0.0
    _selection_postprocess_elapsed = 0.0
    if depth == 2:
        _sel_start = time.time()
        _pools = {}
        _novelty_pools = {}
        _level1_excluded = {}
        _ledgers = {}
        _det_output = {}
        _reason_groups = {}
        _raw_lists = {}
        _llm_sections = []
        _rule_list_sections = {"defender_quarantine", "userassist", "rdp_inbound"}

        # endpoint頻度は選抜前のrawから決定論的に構築する。
        _endpoint_freq = {}
        for _e in sections.get("netstat", []) or []:
            if not isinstance(_e, dict):
                continue
            _remote = str(_e.get("remote", ""))
            _host = _remote
            if _remote.startswith("[") and "]:" in _remote:
                _host = _remote[1:_remote.rfind("]:")]
            elif _remote.count(":") == 1:
                _host = _remote.rsplit(":", 1)[0]
            _endpoint_freq[_host] = _endpoint_freq.get(_host, 0) + 1

        _selection_targets = [s for s in analyze_list
                              if isinstance(_raw_for_section(s), list)
                              and s not in _rule_list_sections and s != "known_tools"]
        _emit_progress(
            f"Step 4A: Depth2選抜準備 0/{len(_selection_targets)}",
            stage="selection_prepare", completed=0, total=len(_selection_targets),
            active_sections=[])
        _prepared_count = 0
        for _sec in analyze_list:
            _t0 = time.time()
            _raw = _raw_for_section(_sec)
            if not isinstance(_raw, list) or _sec in _rule_list_sections or _sec == "known_tools":
                continue
            _raw_lists[_sec] = _raw
            _ledger = DispositionLedger(len(_raw))
            _ledgers[_sec] = _ledger
            _reason_groups[_sec] = {"deferred": {}, "deterministic": {}}
            _det_output[_sec] = []

            # depth2ではLevel1を全LLMリストセクションへ共通適用。
            if get_level1_filters(_sec):
                _allowed = {i for i, item in enumerate(_raw)
                            if entry_matches_level1(_sec, item)}
            else:
                _allowed = set(range(len(_raw)))
            # rc17: deterministic HIGH candidates must reach the global planner
            # even when a future Level1 expression fails to match them.
            _allowed = depth2_select.include_mandatory_indices(_sec, _raw, _allowed)
            _level1_excluded[_sec] = set(range(len(_raw))) - _allowed

            _pool = []
            _novelty_pool = []
            _private_idx, _ephemeral_idx, _loopback_idx, _mpksl_idx, _dir_d_idx = [], [], [], [], []
            for _gi in sorted(_allowed):
                _e = _raw[_gi]
                if _sec == "directory" and _classify_dir_entry(_e) == "D":
                    _dir_d_idx.append(_gi); continue
                if _sec == "netstat" and isinstance(_e, dict):
                    if _is_local_remote(_e):
                        _private_idx.append(_gi); continue
                    if _is_ephemeral_rpc_listening(_e):
                        _ephemeral_idx.append(_gi); continue
                    if (_e.get("state") == "LISTENING" and
                            (str(_e.get("local", "")).startswith("127.0.0.1:") or
                             str(_e.get("local", "")).startswith("[::1]:"))):
                        _loopback_idx.append(_gi); continue
                    _local = _e.get("local", "")
                    _pid = _local_to_pid.get(_local, _e.get("pid", ""))
                    _pname = _pid_to_name.get(_pid, "")
                    if _pname:
                        _e["_proc_hint"] = f"pid={_pid} ({_pname})"
                if _sec == "system_7045" and isinstance(_e, dict):
                    _blob = " ".join(str(_e.get(k, "")) for k in
                                     ("service_name", "name", "identifier", "image_path"))
                    if _MPKSL_NAME_RE.search(_blob):
                        _mpksl_idx.append(_gi); continue
                _pool.append((_gi, _e))

            # v3.69-rc2: Level1非該当群からも少量のnovelty候補を保持する。
            # 明確な低価値/決定論対象はnoveltyへ入れず、通常の繰延として残す。
            for _gi in sorted(_level1_excluded[_sec]):
                _e = _raw[_gi]
                if _sec == "directory" and _classify_dir_entry(_e) == "D":
                    _dir_d_idx.append(_gi); continue
                if _sec == "netstat" and isinstance(_e, dict):
                    if (_is_local_remote(_e) or _is_ephemeral_rpc_listening(_e) or
                        (_e.get("state") == "LISTENING" and
                         (str(_e.get("local", "")).startswith("127.0.0.1:") or
                          str(_e.get("local", "")).startswith("[::1]:")))):
                        continue
                if _sec == "system_7045" and isinstance(_e, dict):
                    _blob = " ".join(str(_e.get(k, "")) for k in
                                     ("service_name", "name", "identifier", "image_path"))
                    if _MPKSL_NAME_RE.search(_blob):
                        continue
                _novelty_pool.append((_gi, _e))

            if _dir_d_idx:
                _reason_groups[_sec]["deferred"]["dir_class_D"] = _dir_d_idx
            if _private_idx:
                _reason_groups[_sec]["deterministic"]["netstat_private"] = _private_idx
                _det_output[_sec].append({
                    "identifier": f"プライベート宛通信 {len(_private_idx)}件",
                    "score": "LOW",
                    "reason": "プライベートIP宛だが正規内部基盤か横移動通信かは収集情報だけでは断定不能。ルールベースLOWで可視化（LLM未送信）。",
                    "decoded": None, "lolbas": None, "mitre": [], "iocs": [],
                    "category": "internal_unclear",
                    "deterministic_origin": "netstat_private",
                    "_aggregated_source_indices": list(_private_idx),
                })
            if _ephemeral_idx:
                _reason_groups[_sec]["deterministic"]["netstat_ephemeral"] = _ephemeral_idx
                _det_output[_sec].append({
                    "identifier": f"エフェメラルRPC LISTENING {len(_ephemeral_idx)}件",
                    "score": "LOW",
                    "reason": "Windows標準RPC動的エンドポイント。ルールベースLOW（LLM未送信）。",
                    "decoded": None, "lolbas": None, "mitre": [], "iocs": [],
                    "deterministic_origin": "netstat_ephemeral",
                    "_aggregated_source_indices": list(_ephemeral_idx),
                })
            if _loopback_idx:
                _reason_groups[_sec]["deterministic"]["netstat_loopback"] = _loopback_idx
                _det_output[_sec].append({
                    "identifier": f"ループバック LISTENING {len(_loopback_idx)}件",
                    "score": "LOW",
                    "reason": "127.0.0.1/::1 LISTENING。ルールベースLOW（LLM未送信）。",
                    "decoded": None, "lolbas": None, "mitre": [], "iocs": [],
                    "deterministic_origin": "netstat_loopback",
                    "_aggregated_source_indices": list(_loopback_idx),
                })
            if _mpksl_idx:
                _reason_groups[_sec]["deterministic"]["mpksl_excluded"] = _mpksl_idx
                _det_output[_sec].append({
                    "identifier": f"MpKsl Defender動的署名サービス {len(_mpksl_idx)}件",
                    "score": "CLEAN",
                    "reason": "Windows Defender正規サービス。ルールベース処理（LLM未送信）。",
                    "decoded": None, "lolbas": None, "mitre": [], "iocs": [],
                    "deterministic_origin": "mpksl_excluded",
                    "_aggregated_source_indices": list(_mpksl_idx),
                })

            # 選抜前に確定しているのは決定論処理だけ。deferredは選抜後に
            # signature/cap/budget/level1を正確に分類して登録する。
            for _reason, _indices in _reason_groups[_sec]["deterministic"].items():
                if _indices:
                    _rep = _indices[0]
                    _ledger.add(PlannedItem(_raw[_rep], _rep, _indices,
                                            "deterministic", _reason,
                                            source_ids=[]))
            _pools[_sec] = _pool
            _novelty_pools[_sec] = _novelty_pool
            _llm_sections.append(_sec)
            _selection_per_section[_sec] = round(time.time() - _t0, 4)
            _prepared_count += 1
            _emit_progress(
                f"Step 4A: Depth2選抜準備 {_prepared_count}/{len(_selection_targets)} "
                f"完了={_sec}",
                stage="selection_prepare", completed=_prepared_count,
                total=len(_selection_targets), active_sections=[],
                last_completed=_sec)

        # ctxはLLM前に確定できる証拠だけを利用する。
        _det_ctx = {}
        _def_raw = sections.get("defender_quarantine", []) or []
        if isinstance(_def_raw, list):
            _det_ctx["defender_quarantine"] = analyze_defender_quarantine_rule_based(
                _def_raw).get("entries", [])
        _det_ctx["known_tools"] = analyze_known_tools(sections, _collection_id).get("entries", [])
        if "directory" in _pools:
            _det_ctx["directory"] = [e for _, e in _pools["directory"]]
        _ctx = depth2_select.build_ctx(_det_ctx, endpoint_freq=_endpoint_freq)
        _emit_progress(
            "Step 4B: Depth2グローバル選抜・予算調整",
            stage="selection_plan", completed=0, total=len(_llm_sections),
            active_sections=list(_llm_sections[:3]))
        def _planner_progress(payload):
            if not isinstance(payload, dict):
                return
            phase = str(payload.get("phase") or "planning")
            labels = {
                "candidate_scoring": "候補整理",
                "novelty_scoring": "novelty候補整理",
                "initial_plan": "初期計画",
                "budget_trim": "予算trim",
                "budget_trim_replan": "trim再計画",
                "backfill": "backfill",
                "frontier_audit": "frontier最大性検査",
                "deferred_accounting": "deferred集計",
            }
            label = labels.get(phase, phase)
            completed = int(payload.get("completed") or payload.get("examined") or 0)
            total = int(payload.get("total") or 0)
            section = str(payload.get("section") or "")
            suffix = f" {completed}/{total}" if total else ""
            if section:
                suffix += f" section={section}"
            if payload.get("added") is not None:
                suffix += f" 追加={int(payload.get('added') or 0)}"
            if payload.get("planned_tokens") is not None:
                suffix += (f" tokens={int(payload.get('planned_tokens') or 0)}"
                           f"/{int(payload.get('budget') or 0)}")
            _emit_progress(
                f"Step 4B: {label}{suffix}",
                stage=f"selection_plan_{phase}", completed=completed, total=total,
                active_sections=[section] if section else [], planner_detail=payload)

        _planner_start = time.time()
        _plans = depth2_select.plan_depth2_selection(
            _pools, _ctx, _llm_sections, ledgers=_ledgers,
            lean=lean, context=context, novelty_pools=_novelty_pools,
            cancel_check=cancel_check, progress_callback=_planner_progress)
        _selection_planner_elapsed = round(time.time() - _planner_start, 4)
        _postprocess_start = time.time()

        for _sec in _llm_sections:
            _raw = _raw_lists[_sec]
            _ledger = _ledgers[_sec]
            _plan_info = _plans.get(_sec, {})
            _selected = list(_plan_info.get("selected") or [])
            _selected_set = {gi for gi, _ in _selected}
            _selected_reasons = _plan_info.get("selected_reasons") or {}

            for _gi, _e in _selected:
                _reason = _selected_reasons.get(_gi, "risk_selected")
                _ledger.add(PlannedItem(_e, _gi, [_gi], "selected", _reason,
                                        source_ids=[_e.get("source_id", "")] if isinstance(_e, dict) else []))

            # Exact deferred reason groups returned by the planner.
            _planned_deferred = set()
            for _reason, _indices in (_plan_info.get("deferred_reasons") or {}).items():
                _indices = sorted(set(int(i) for i in _indices if int(i) not in _selected_set))
                if not _indices:
                    continue
                _planned_deferred.update(_indices)
                _reason_groups[_sec]["deferred"][_reason] = _indices
                _ledger.add(PlannedItem(_raw[_indices[0]], _indices[0], _indices,
                                        "deferred", _reason,
                                        source_ids=[]))

            # Level1-excluded entries that were neither novelty-selected nor assigned
            # another planner reason remain explicitly deferred by Level1 policy.
            _remaining_l1 = sorted(_level1_excluded.get(_sec, set())
                                   - _selected_set - _planned_deferred
                                   - _ledger.deterministic)
            if _remaining_l1:
                _reason_groups[_sec]["deferred"]["level1_excluded"] = _remaining_l1
                _ledger.add(PlannedItem(_raw[_remaining_l1[0]], _remaining_l1[0],
                                        _remaining_l1, "deferred", "level1_excluded",
                                        source_ids=[]))

            # Any still-unclassified item is a policy deferral; use global budget as
            # a conservative explicit reason rather than leaving an unexplained gap.
            _covered = _ledger.selected | _ledger.deterministic | _ledger.deferred
            _remaining = sorted(set(range(len(_raw))) - _covered)
            if _remaining:
                _reason_groups[_sec]["deferred"]["over_global_budget"] = _remaining
                _ledger.add(PlannedItem(_raw[_remaining[0]], _remaining[0], _remaining,
                                        "deferred", "over_global_budget",
                                        source_ids=[]))

            _ledger.verify()
            _stats = _ledger.stats()
            _plan = _plan_info.get("plan")
            _stats.update({
                "planned_output_tokens": (_plan or {}).get("planned_output_tokens", 0),
                "chunk_overhead_tokens": (_plan or {}).get("chunk_overhead_tokens", 0),
                "global_planned_output_tokens": _plan_info.get("global_planned_output_tokens", 0),
                "global_budget": _plan_info.get("global_budget", 0),
                "global_budget_overrun": _plan_info.get("global_budget_overrun", False),
                "budget_overrun": _plan_info.get("budget_overrun", False),
                "cap_overrun": _plan_info.get("cap_overrun", False),
                "mandatory_overrun_tokens": _plan_info.get("mandatory_overrun_tokens", 0),
                "floor_overrun_tokens": _plan_info.get("floor_overrun_tokens", 0),
                "section_floor_target": _plan_info.get("section_floor_target", 0),
                "section_floor_selected": _plan_info.get("section_floor_selected", 0),
                "planner_trim_iterations": _plan_info.get("planner_trim_iterations", 0),
                "planner_trim_dropped": _plan_info.get("planner_trim_dropped", 0),
                "planner_backfill_iterations": _plan_info.get("planner_backfill_iterations", 0),
                "planner_backfill_added": _plan_info.get("planner_backfill_added", 0),
                "unused_budget_tokens": _plan_info.get("unused_budget_tokens", 0),
                "candidate_frontier_size": _plan_info.get("candidate_frontier_size", 0),
                "backfill_candidates_examined": _plan_info.get("backfill_candidates_examined", 0),
                "planner_replan_count": _plan_info.get("planner_replan_count", 0),
                "planner_candidate_probe_limit": _plan_info.get("planner_candidate_probe_limit", 0),
                "planner_trim_iteration_limit": _plan_info.get("planner_trim_iteration_limit", 0),
                "planner_replan_limit": _plan_info.get("planner_replan_limit", 0),
                "planner_probe_limit_hit": _plan_info.get("planner_probe_limit_hit", False),
                "planner_replan_limit_hit": _plan_info.get("planner_replan_limit_hit", False),
                "plan_is_policy_frontier_maximal": _plan_info.get(
                    "plan_is_policy_frontier_maximal", False),
                "global_maximality_not_claimed": _plan_info.get(
                    "global_maximality_not_claimed", True),
                "frontier_addable_candidates": _plan_info.get(
                    "frontier_addable_candidates", []),
                "plan_is_maximal": _plan_info.get("plan_is_maximal", False),
                "maximality_addable_candidates": _plan_info.get("maximality_addable_candidates", []),
            })
            _mandatory_indices = set(_ledger.reasons("selected").get("mandatory_selected", []))
            _prov = build_section_provenance(
                _sec, _raw,
                selected=_ledger.selected,
                deterministic=_ledger.deterministic,
                deferred=_ledger.deferred,
                evaluated=_ledger.selected,
                unevaluated=(),
                mandatory=_mandatory_indices,
                mandatory_applicable=True,
                selected_reasons=_ledger.reasons("selected"),
                deterministic_reasons=_ledger.reasons("deterministic"),
                deferred_reasons=_ledger.reasons("deferred"),
            )
            _prov["source_ids_scope"] = "mandatory_deterministic_selected_evaluated_unevaluated"
            _prov["deferred_source_ids_omitted"] = len(_ledger.deferred)
            _d2_prepared[_sec] = {
                "selected_entries": [e for _, e in _selected],
                "source_indices": [gi for gi, _ in _selected],
                "plan": _plan,
                "deterministic_entries": _det_output[_sec],
                "selection_stats": _stats,
                "provenance": _prov,
                "ledger": _ledger,
            }
        _selection_postprocess_elapsed = round(time.time() - _postprocess_start, 4)
        _selection_total_elapsed = round(time.time() - _sel_start, 4)
        results["_selection_summary"] = {
            "elapsed_sec": _selection_total_elapsed,
            "prepare_elapsed_sec": round(sum(_selection_per_section.values()), 4),
            "planner_elapsed_sec": _selection_planner_elapsed,
            "postprocess_elapsed_sec": _selection_postprocess_elapsed,
            "per_section_elapsed_sec": _selection_per_section,
            "sections_planned": len(_d2_prepared),
        }
        _emit_progress(
            f"Step 4B: Depth2選抜完了 {len(_d2_prepared)}セクション "
            f"({_selection_total_elapsed:.1f}秒)",
            stage="selection_complete", completed=len(_d2_prepared),
            total=len(_d2_prepared), active_sections=[])

        # Multi-million-entry directory runs build large temporary pools and
        # deferred-index sets. Only _d2_prepared, _raw_lists and _ledgers are
        # needed by the subsequent LLM workers. Release the rest before the
        # model phase so rc7 does not carry rc6 selection memory for hours.
        del _pools, _novelty_pools, _level1_excluded, _plans, _reason_groups
        del _det_ctx, _ctx, _det_output

    def _attach_depth1_provenance(sec: str, raw, sec_result):
        """Attach Depth1 provenance from the pre-LLM disposition snapshot.

        Planner disposition is authoritative.  LLM free-form reason text is
        never used to classify deterministic evidence.  Evaluation coverage is
        measured from structured raw-index/source-id/canonical attribution.
        """
        if depth != 1 or not isinstance(raw, list) or not isinstance(sec_result, dict):
            return sec_result
        if isinstance(sec_result.get("_provenance"), dict):
            return sec_result

        plan = sec_result.pop("_depth1_provenance_plan", None)
        plan = plan if isinstance(plan, dict) else {}
        selected = {int(x) for x in (plan.get("selected") or []) if 0 <= int(x) < len(raw)}
        deterministic_reasons = {
            str(reason): {int(x) for x in indices if 0 <= int(x) < len(raw)}
            for reason, indices in (plan.get("deterministic_reasons") or {}).items()
        }
        deterministic = set().union(*deterministic_reasons.values()) if deterministic_reasons else set()
        deferred_reasons = {
            str(reason): {int(x) for x in indices if 0 <= int(x) < len(raw)}
            for reason, indices in (plan.get("deferred_reasons") or {}).items()
        }
        explicitly_deferred = set().union(*deferred_reasons.values()) if deferred_reasons else set()
        selected_reasons = {
            str(reason): {int(x) for x in indices if 0 <= int(x) < len(raw)}
            for reason, indices in (plan.get("selected_reasons") or {}).items()
        }
        if selected and not selected_reasons:
            selected_reasons = {"depth1_selected": set(selected)}

        evaluated = set()
        attribution_errors = []
        for pos, entry in enumerate(sec_result.get("entries") or []):
            if not isinstance(entry, dict):
                continue
            identifier = str(entry.get("identifier") or "")
            if identifier.startswith("⚠") or entry.get("_meta_only"):
                continue
            origin = str(entry.get("deterministic_origin") or "")
            if origin and entry.get("_aggregated_source_indices") is not None:
                claimed = set()
                invalid_claim = False
                for value in entry.get("_aggregated_source_indices") or []:
                    try:
                        idx = int(value)
                    except (TypeError, ValueError):
                        invalid_claim = True
                        continue
                    if 0 <= idx < len(raw):
                        claimed.add(idx)
                    else:
                        invalid_claim = True
                expected = set(deterministic_reasons.get(origin, set()))
                if expected and not invalid_claim and claimed == expected:
                    deterministic.update(claimed)
                    entry.setdefault("_source_attribution_method", "deterministic_plan_aggregate")
                    continue
                attribution_errors.append({
                    "entry_index": pos,
                    "identifier": identifier[:180],
                    "reason": "deterministic_aggregate_plan_mismatch",
                })
                continue

            indices, method = _result_entry_raw_indices(sec, raw, entry)
            # Entries selected before the LLM remain selected even when a
            # deterministic post-filter/floor annotates their final result.
            selected_hits = indices & selected
            if selected_hits:
                evaluated.update(selected_hits)
                entry.setdefault("_source_attribution_method", method)
                continue
            if origin and indices:
                deterministic.update(indices)
                deterministic_reasons.setdefault(origin, set()).update(indices)
                entry.setdefault("_source_attribution_method", method)
                continue
            if indices and not selected:
                # Legacy structured paths without an explicit plan: preserve
                # evidence visibility as selected, never infer deterministic
                # disposition from the reason string.
                selected.update(indices)
                selected_reasons.setdefault("depth1_selected", set()).update(indices)
                evaluated.update(indices)
                entry.setdefault("_source_attribution_method", method)
                continue
            if plan.get("selected") and not indices:
                attribution_errors.append({
                    "entry_index": pos,
                    "identifier": identifier[:180],
                    "reason": method,
                })

        unevaluated = set(selected) - evaluated
        for chunk_error in sec_result.get("_chunk_errors") or []:
            for value in chunk_error.get("unevaluated_indices") or []:
                try:
                    idx = int(value)
                except (TypeError, ValueError):
                    continue
                if idx in selected:
                    unevaluated.add(idx)
        evaluated = set(selected) - unevaluated
        selected.difference_update(deterministic)
        evaluated.intersection_update(selected)
        unevaluated = set(selected) - evaluated
        explicitly_deferred.difference_update(selected | deterministic)
        remaining = set(range(len(raw))) - selected - deterministic - explicitly_deferred
        if remaining:
            deferred_reasons.setdefault("level1_excluded", set()).update(remaining)
        deferred = explicitly_deferred | remaining
        provenance_complete = not attribution_errors
        provenance = build_section_provenance(
            sec, raw,
            selected=selected,
            deterministic=deterministic,
            deferred=deferred,
            evaluated=evaluated,
            unevaluated=unevaluated,
            mandatory=(),
            mandatory_applicable=False,
            selected_reasons=selected_reasons,
            deterministic_reasons=deterministic_reasons,
            deferred_reasons=deferred_reasons,
            provenance_complete=provenance_complete,
            attribution_errors=attribution_errors,
        )
        errors = validate_section_provenance(provenance)
        if errors:
            raise AssertionError(f"Depth1 provenance invalid ({sec}): {'; '.join(errors)}")
        sec_result["_provenance"] = provenance
        sec_result["_selection_stats"] = {
            "raw": len(raw),
            "selected": len(selected),
            "deterministic": len(deterministic),
            "deferred": len(deferred),
            "evaluated": len(evaluated),
            "selected_unevaluated": len(unevaluated),
            "selected_coverage_pct": (100.0 if not selected else
                round(100.0 * len(evaluated) / len(selected), 2)),
            "provenance_complete": provenance_complete,
            "attribution_error_count": len(attribution_errors),
        }
        if attribution_errors:
            sec_result.setdefault("entries", []).append({
                "identifier": f"⚠ {sec}: source attribution incomplete ({len(attribution_errors)}件)",
                "score": "MEDIUM",
                "reason": "LLM結果をraw証拠へ一意に帰属できないため、比較用provenanceを不完全として記録。再解析が必要。",
                "decoded": None, "lolbas": None, "mitre": [], "iocs": [],
            })
        return sec_result

    def analyze_one_section(sec: str, _ctx: str = context) -> tuple:
        """1セクション分の解析を実行し (sec, result) を返す。"""
        # T-17/T-19: event_logs 由来のセクションは sections ではなく event_logs から取得
        _EVENT_LOG_SECTIONS = {"security_1102", "system_104", "system_7045", "rdp_1024", "task_106", "task_140", "task_141", "rdp_inbound"}
        if sec in _EVENT_LOG_SECTIONS:
            raw = event_logs.get(sec)
        else:
            raw = sections.get(sec)

        if raw is None:
            if verbose:
                print(f"  スキップ（データなし）: {sec}")
            return sec, None

        # Map any filtered/selected view back to the original raw list.  The
        # previous Depth1 path passed 0..N-1 after filtering, which could bind
        # an LLM result to a different raw event at the same position.
        _raw_index_by_object = (
            {id(value): idx for idx, value in enumerate(raw)}
            if isinstance(raw, list) else {}
        )
        _raw_index_by_source_id = (
            {str(value.get("source_id")): idx for idx, value in enumerate(raw)
             if isinstance(value, dict) and value.get("source_id")}
            if isinstance(raw, list) else {}
        )

        def _raw_indices_for(view: list, *, fail_closed: bool = False) -> list:
            indices = []
            for fallback, value in enumerate(view):
                idx = _raw_index_by_object.get(id(value))
                if idx is None and isinstance(value, dict) and value.get("source_id"):
                    idx = _raw_index_by_source_id.get(str(value.get("source_id")))
                if idx is None and fail_closed:
                    raise ValueError(
                        f"{sec}: cannot map selected entry to raw index without guessing"
                    )
                indices.append(fallback if idx is None else idx)
            return indices

        def _with_depth1_plan(result: dict, *, selected=(),
                              deterministic_reasons=None,
                              deferred_reasons=None,
                              selected_reasons=None) -> dict:
            if depth != 1 or not isinstance(raw, list) or not isinstance(result, dict):
                return result
            result["_depth1_provenance_plan"] = {
                "selected": sorted(set(int(x) for x in selected)),
                "selected_reasons": {
                    str(k): sorted(set(int(x) for x in v))
                    for k, v in (selected_reasons or {}).items()
                },
                "deterministic_reasons": {
                    str(k): sorted(set(int(x) for x in v))
                    for k, v in (deterministic_reasons or {}).items()
                },
                "deferred_reasons": {
                    str(k): sorted(set(int(x) for x in v))
                    for k, v in (deferred_reasons or {}).items()
                },
            }
            return result

        # T-19: ログクリアイベント（security_1102 / system_104）はルールベース HIGH 判定
        # ファイルが存在してかつ空でなければ即 HIGH。LLM 不要。
        # イベントID 1102: セキュリティログクリア (T1070.001)
        # イベントID 104:  システムログクリア    (T1070.001)
        if sec in ("security_1102", "system_104"):
            raw_text = raw if isinstance(raw, str) else ""
            if not raw_text.strip():
                q = event_quality.get(sec, {}) if isinstance(event_quality, dict) else {}
                state = q.get("evidence_state", "EMPTY_UNVERIFIED")
                print(f"[{hostname}] 収集品質警告（空ファイル）: {sec}")
                return sec, _attach_atomic_text_rule_provenance(
                    sec, raw_text, {
                        "section": sec, "entries": [],
                        "evidence_state": state,
                        "section_summary": "収集ファイルは空。該当イベントなしと収集失敗を判別できないため、不存在の根拠には使用しない。",
                        "_quality": q,
                    }, collection_id=_collection_id, reason="event_log_clear_rule",
                    source_container="event_logs",
                )
            label = "セキュリティログ" if sec == "security_1102" else "システムログ"
            eid   = "1102" if sec == "security_1102" else "104"
            print(f"[{hostname}] 解析中: {sec} (depth={depth}) → ルールベース HIGH 判定")
            return sec, _attach_atomic_text_rule_provenance(
                sec, raw_text, {
                    "section": sec,
                    "entries": [{
                        "identifier": f"EventID {eid}: {label}クリア検出",
                        "score":      "HIGH",
                        "reason":     f"{label}のクリアを確認。証拠隠滅の典型的手口（T1070.001）。"
                                      "ルールベース判定（LLM未使用）",
                        "decoded":    None,
                        "lolbas":     None,
                        "mitre":      ["T1070.001"],
                        "iocs":       [],
                        "deterministic_origin": "event_log_clear_rule",
                    }],
                    "section_summary": f"{label}クリアを検出（EventID {eid}）。証拠隠滅の可能性 HIGH",
                }, collection_id=_collection_id, reason="event_log_clear_rule",
                source_container="event_logs",
            )

        # T-21-lite: タスク削除イベント（TaskScheduler/Operational EventID 141）の
        # ルールベース注記。Operational チャネルは Windows 既定で無効のため
        # 通常は空（=削除痕跡なし）。非空の場合のみ「ログが有効化されており、かつ
        # タスク削除が記録されている」という稀な状況であり、痕跡消去（T1070）の
        # 観点で目視確認に値するため HIGH 注記を付す。LLM は使用しない。
        # フル構造化＋LLM 解析は実データで 140/141 が常に空のため見送り（設計書 T-21）。
        if sec == "task_141":
            q = event_quality.get(sec, {}) if isinstance(event_quality, dict) else {}
            task_events = raw if isinstance(raw, list) else []
            if not task_events:
                state = q.get("evidence_state", "EMPTY_UNVERIFIED")
                if verbose:
                    print(f"[{hostname}] 収集品質警告（空ファイル）: {sec}")
                return sec, _attach_complete_rule_provenance(
                    sec, task_events, {
                        "section": sec, "entries": [],
                        "evidence_state": state,
                        "section_summary": "TaskScheduler EventID 141の収集結果は空。削除イベントなしと収集失敗を判別できない。",
                        "_quality": q,
                    }, reason="task_deleted_rule",
                )
            entries_out = []
            for raw_index, event in enumerate(task_events):
                entries_out.append({
                    "identifier": event.get("identifier") or f"EventID 141: {event.get('task_name','タスク削除')}",
                    "score": "HIGH",
                    "reason": "TaskScheduler/Operationalにタスク削除イベントを確認。痕跡消去の可能性があり目視確認が必要。ルールベース判定。",
                    "decoded": None, "lolbas": None, "mitre": ["T1070"],
                    "iocs": [], "datetime": event.get("datetime", ""),
                    "source_id": event.get("source_id", ""),
                    "deterministic_origin": "task_deleted_rule",
                    "_raw_source_index": raw_index,
                })
            return sec, _attach_complete_rule_provenance(
                sec, task_events, {
                    "section": sec, "entries": entries_out,
                    "evidence_state": q.get("evidence_state", "OBSERVED"),
                    "section_summary": f"タスク削除イベント {len(entries_out)}件を検出（EventID 141）。要目視確認",
                    "_quality": q,
                }, reason="task_deleted_rule",
            )

        # T-23-psexec（v3.57）: CheckPC の「--Check PsExec existence--」
        # （psexec.exe/psexesvc.exe等の存在検索）をルールベースで評価する。
        # LLM は使用しない（task_141/security_1102 と同じ設計方針）。
        #
        # 重大度の検討（実装前に分析官の指示により検討）:
        #   既存サンプル16ホスト（感染確認済み3ホストを含む）を確認したところ、
        #   全ホストで「該当0件」（"End of search: 0 match(es) found." /
        #   "検索の完了: 該当 0 件"）であり、実際の陽性データは手元にない。
        #   PsExecはtask_141/security_1102（ログ消去・タスク削除）とは異なり、
        #   存在自体がVM管理基盤等で正規運用として日常的に使われるデュアルユース
        #   ツールであるため（本パイプラインのknown_tools層で遠隔操作系ツールを
        #   一律MEDIUM扱いにしているのと同じ考え方）、"該当あり"を無条件でHIGHに
        #   するのは適切でないと判断した。MEDIUM（要目視確認）とし、実機で
        #   陽性データを確認できた際に重大度を再検討する。
        if sec == "psexec":
            raw_text = raw if isinstance(raw, str) else ""
            if not raw_text.strip():
                if verbose:
                    print(f"[{hostname}] スキップ（データなし）: {sec}")
                return sec, _attach_atomic_text_rule_provenance(
                    sec, raw_text, {
                        "section": sec, "entries": [],
                        "section_summary": "PsExec存在確認: データなし",
                    }, collection_id=_collection_id, reason="psexec_rule",
                    source_container="sections",
                )
            m = re.search(
                r"(?:End of search:\s*(\d+)\s*match|検索の完了[:：]\s*該当\s*(\d+)\s*件)",
                raw_text)
            count = int((m.group(1) or m.group(2))) if m else 0
            if count == 0:
                if verbose:
                    print(f"[{hostname}] スキップ（該当0件）: {sec}")
                return sec, _attach_atomic_text_rule_provenance(
                    sec, raw_text, {
                        "section": sec, "entries": [],
                        "section_summary": "PsExec関連の痕跡なし（該当0件）",
                    }, collection_id=_collection_id, reason="psexec_rule",
                    source_container="sections",
                )
            print(f"[{hostname}] 解析中: {sec} (depth={depth}) → ルールベース MEDIUM 注記")
            detail = raw_text.strip()
            if len(detail) > 2000:
                detail = detail[:2000] + " …(以降切り詰め)"
            return sec, _attach_atomic_text_rule_provenance(
                sec, raw_text, {
                    "section": sec,
                    "entries": [{
                        "identifier": f"PsExec存在確認: {count}件該当",
                        "score": "MEDIUM",
                        "reason": f"CheckPCのPsExec存在チェックで{count}件該当。"
                                  "PsExecは正規の運用ツールとしても広く使われる"
                                  "デュアルユースツールのため即HIGH判定はせず、"
                                  "内容を目視確認のこと（T1570, T1021.002）。",
                        "decoded": detail,
                        "lolbas": None,
                        "mitre": ["T1570", "T1021.002"],
                        "iocs": [],
                    }],
                    "section_summary": f"PsExec存在確認で{count}件該当。目視確認を推奨（MEDIUM）。",
                }, collection_id=_collection_id, reason="psexec_rule",
                source_container="sections",
            )


        # N-1: 着信RDP（EID 21 / 1149）のルールベース判定。
        # event_logs["rdp_inbound"] は parse_inbound_rdp() が返す dict のリスト。
        # 外部（グローバル）IP からの着信 → HIGH（T1021.001 着信RDP）。
        # 内部（RFC1918 等）からの着信 → LOW（業務上の横移動の可能性、要確認）。
        # コンソール/ローカルログオンは parse 段階で除外済み。LLM は使用しない。
        if sec == "rdp_inbound":
            rdp_list = raw if isinstance(raw, list) else []
            if not rdp_list:
                if verbose:
                    print(f"[{hostname}] スキップ（着信RDPなし）: {sec}")
                return sec, _attach_complete_rule_provenance(
                    sec, rdp_list, {
                        "section": sec, "entries": [],
                        "section_summary": "着信RDPログオンなし",
                    }, reason="rdp_inbound_rule",
                )
            print(f"[{hostname}] 解析中: {sec} (depth={depth}) → ルールベース判定")
            entries_out = []
            ext_cnt = 0
            for raw_index, e in enumerate(rdp_list):
                ip   = e.get("source_ip", "")
                user = e.get("user", "")
                dt   = e.get("datetime", "")
                eid  = e.get("event_id", "")
                is_ext = _is_public_ip(ip)
                if is_ext:
                    ext_cnt += 1
                entries_out.append({
                    "identifier": f"EID {eid} 着信RDP {dt} 接続元={ip} ユーザー={user}",
                    "score":      "HIGH" if is_ext else "LOW",
                    "reason":     (f"外部IP {ip} からの着信RDPログオン。標的型侵入の侵入経路の"
                                   f"可能性が高い（T1021.001）。接続元の地理情報・正当性を要確認。"
                                   if is_ext else
                                   f"内部IP {ip} からの着信RDP。業務上の横移動の可能性。要確認。"),
                    "decoded":    None,
                    "lolbas":     None,
                    "mitre":      ["T1021.001"],
                    "iocs":       [ip] if ip else [],
                    "source_id":  e.get("source_id", ""),
                    "deterministic_origin": "rdp_inbound_rule",
                    "_raw_source_index": raw_index,
                })
            summary = (f"着信RDP {len(entries_out)}件（うち外部IP {ext_cnt}件）。"
                       + ("外部からの着信あり・要重点確認" if ext_cnt else "内部のみ"))
            return sec, _attach_complete_rule_provenance(
                sec, rdp_list, {
                    "section": sec,
                    "entries": entries_out,
                    "section_summary": summary,
                }, reason="rdp_inbound_rule",
            )

        print(f"[{hostname}] 解析中: {sec} (depth={depth})")

        # v3.68-rc2: Defender は全depthでルールベース。
        # ルールベースで評価する。Defender 自身が既に検知・隔離済みの
        # エントリであり、LLMによる「悪性かどうか」の再判定は付加価値が
        # 小さい一方、15エントリ/CHUNK_SIZE_DEPTH1=3=5チャンクと
        # directoryと並び depth=1 全体（23チャンク）で最大級のコストを
        # 占めていた。識別子・スコア・IOC(=path)はparse_checkpc.pyの
        # 構造化済みフィールド(threat_name/path)からそのまま導出する。
        # パス文字列からのドメイン/メールアドレス抽出等の「二次IOC抽出」は
        # depth>=2 のLLM解析（変更なし）でのみ行う（設計書 v3.4 6.4.1）。
        if sec == "defender_quarantine" and isinstance(raw, list):
            _res = analyze_defender_quarantine_rule_based(raw)
            if depth == 2:
                _res["_selection_stats"] = {
                    "raw": len(raw),
                    "selected": 0,
                    "deterministic": len(raw),
                    "deferred": 0,
                    "deferred_by_policy": 0,
                    "evaluated": 0,
                    "selected_unevaluated": 0,
                    "selected_coverage_pct": 100.0,
                    "provenance_complete": True,
                    "attribution_error_count": 0,
                }
                _res["_provenance"] = _build_defender_quarantine_provenance(raw)
            return sec, _with_depth1_plan(
                _res, deterministic_reasons={"defender_rule_based": range(len(raw))})

        # N-5: UserAssist は全 depth でルールベース（不審パス実行のみ抽出・LLM不使用）
        if sec == "userassist" and isinstance(raw, list):
            _ua = analyze_userassist_rule_based(raw)
            return sec, _attach_complete_rule_provenance(
                sec, raw, _ua, reason="userassist_rule")

        # v3.68-rc2: depth2の選抜済みChunkSpecを本番経路で直接使用する。
        if depth == 2 and sec in _d2_prepared:
            _prep = _d2_prepared[sec]
            _selected = _prep["selected_entries"]
            _det_entries = list(_prep["deterministic_entries"])
            if not _selected:
                _sec_result = {
                    "section": sec,
                    "entries": _det_entries,
                    "section_summary": "depth2選抜後のLLM送付対象なし",
                    "_chunk_timings": [],
                    "_selection_stats": _prep["selection_stats"],
                    "_provenance": _prep["provenance"],
                }
                return sec, _apply_post_filter(sec, _normalise_score_schema(_sec_result), raw)
            _entry_results, _summary, _errors, _timings = call_llm_chunked(
                client, model, sec, depth, _selected, verbose, context,
                lean=lean, chunk_plan=_prep["plan"],
                source_indices=_prep["source_indices"])
            _raw_for_depth2 = _raw_lists.get(sec, [])
            _selected_indices = set(_prep["ledger"].selected)
            _evaluated = set()
            _attribution_errors = []
            for _pos, _entry in enumerate(_entry_results):
                _indices, _method = _result_entry_raw_indices(sec, _raw_for_depth2, _entry)
                _hits = _indices & _selected_indices
                if _hits:
                    _evaluated.update(_hits)
                    _entry.setdefault("_source_attribution_method", _method)
                else:
                    _attribution_errors.append({
                        "entry_index": _pos,
                        "identifier": str(_entry.get("identifier") or "")[:180],
                        "reason": _method,
                    })
            _lost = _selected_indices - _evaluated
            for _ce in _errors:
                for _idx in (_ce.get("unevaluated_indices") or []):
                    try:
                        _lost.add(int(_idx))
                    except (TypeError, ValueError):
                        continue
            _lost.intersection_update(_selected_indices)
            if _lost:
                _prep["ledger"].mark_unevaluated(sorted(_lost), "selected_unevaluated")
            _ledger_now = _prep["ledger"]
            _mandatory_now = set(_ledger_now.reasons("selected").get("mandatory_selected", []))
            _evaluated = _ledger_now.selected - _ledger_now.unevaluated
            _provenance_complete = not _attribution_errors
            _sec_result = {
                "section": sec,
                "entries": _entry_results + _det_entries,
                "section_summary": _summary,
                "_chunk_timings": _timings,
                "_selection_stats": dict(_prep["selection_stats"]),
                "_provenance": build_section_provenance(
                    sec, _raw_for_depth2,
                    selected=_ledger_now.selected,
                    deterministic=_ledger_now.deterministic,
                    deferred=_ledger_now.deferred,
                    evaluated=_evaluated,
                    unevaluated=_ledger_now.unevaluated,
                    mandatory=_mandatory_now,
                    mandatory_applicable=True,
                    selected_reasons=_ledger_now.reasons("selected"),
                    deterministic_reasons=_ledger_now.reasons("deterministic"),
                    deferred_reasons=_ledger_now.reasons("deferred"),
                    provenance_complete=_provenance_complete,
                    attribution_errors=_attribution_errors,
                ),
            }
            _sec_result["_selection_stats"].update({
                "evaluated": len(_evaluated),
                "selected_unevaluated": len(_ledger_now.unevaluated),
                "selected_coverage_pct": (100.0 if not _selected_indices else
                    round(100.0 * len(_evaluated) / len(_selected_indices), 2)),
                "provenance_complete": _provenance_complete,
                "attribution_error_count": len(_attribution_errors),
            })
            if _errors:
                _sec_result["_chunk_errors"] = _errors
            if _lost:
                _sec_result["entries"].append({
                    "identifier": f"⚠ {sec}: 選抜済み{len(_lost)}件が未評価",
                    "score": "MEDIUM",
                    "reason": "カバレッジ再送後も評価結果を取得できず。source IDとraw indexを監査情報に保持。",
                    "decoded": None, "lolbas": None, "mitre": [], "iocs": [],
                    "_raw_source_indices": sorted(_lost),
                    "_source_ids": [(_raw_for_depth2[i].get("source_id", "") if i < len(_raw_for_depth2) and isinstance(_raw_for_depth2[i], dict) else "") for i in sorted(_lost)],
                })
            if _attribution_errors:
                _sec_result["entries"].append({
                    "identifier": f"⚠ {sec}: source attribution incomplete ({len(_attribution_errors)}件)",
                    "score": "MEDIUM",
                    "reason": "LLM結果をraw証拠へ一意に帰属できないため、comparison gateではINPUT_ERRORとして扱う。",
                    "decoded": None, "lolbas": None, "mitre": [], "iocs": [],
                })
            return sec, _apply_post_filter(sec, _normalise_score_schema(_sec_result), raw)

        # depth=1: suspicious フラグ絞り込み（appcompat_cache / dns_cache）→ Level1正規表現フィルタ
        local_note = ""
        extra_entries = []
        _dir_d_to_save: list = []   # directory D エントリ（別ファイル出力用）
        _dir_overflow_to_save: list = []   # N-4c: 異常スコア下位の退避エントリ
        _dir_sig_info = None               # N-4d: 同型パターン集約の発生情報（案b）
        _task140_aggregation = None         # rev7: EventID 140 D1意味保持型集約
        _depth1_deterministic_reasons: dict[str, set[int]] = {}
        _depth1_deferred_reasons: dict[str, set[int]] = {}
        if depth == 1 and isinstance(raw, list):
            sus_filtered = apply_suspicious_filter(sec, raw)
            filtered = apply_level1_filter(sec, sus_filtered)
            if verbose:
                print(f"  depth=1 絞り込み: {len(raw)} → {len(filtered)} エントリ")

            # 修正(2026-06-12): netstat はLEVEL1_FILTERS["network"]が
            # ESTABLISHED/SYN_SENT/CLOSE_WAIT を絞り込まず全通過させる設計
            # のため、接続数の多いホストでチャンク数が膨大になる
            # （SNOWLAPTOPで168件→21チャンク、depth=1全体29チャンク中最大）。
            # 基本的なプライベート/ループバックレンジ(10./192.168./127./
            # 172.16.0.0/12)宛はルールベースでCLEAN固定とし、LLMには
            # 外部アドレス宛のみ送る（Tailscale等のCGNAT(100.64.0.0/10)は
            # 対象外=LLMに送られる）。内部ピボット/内部プロキシ経由のC2が
            # 除外対象に含まれる見逃しリスクが残るため、除外件数を
            # section_summaryに明記する（設計書 v3.5/v3.6 参照）。
            if sec == "netstat":
                local_entries = [e for e in filtered if _is_local_remote(e)]
                local_n  = len(local_entries)
                filtered = [e for e in filtered if not _is_local_remote(e)]
                if local_entries:
                    _depth1_deterministic_reasons["netstat_private"] = set(
                        _raw_indices_for(local_entries))

                # T-32: エフェメラルRPC範囲(49152-65535)のLISTENINGはルールベースLOW固定
                ephemeral = [e for e in filtered if _is_ephemeral_rpc_listening(e)]
                filtered  = [e for e in filtered if not _is_ephemeral_rpc_listening(e)]
                if ephemeral:
                    _depth1_deterministic_reasons["netstat_ephemeral"] = set(
                        _raw_indices_for(ephemeral))
                    extra_entries.append({
                        "identifier": f"エフェメラルRPC LISTENING {len(ephemeral)}件",
                        "score":      "LOW",
                        "reason":     "エフェメラルRPCポート(49152-65535)、"
                                       "Windows標準DCOM/RPC動的エンドポイント。"
                                       "ルールベース除外（depth=1、LLM未送信）。",
                        "decoded":    None,
                        "lolbas":     None,
                        "mitre":      None,
                        "iocs":       [e.get("local", "") for e in ephemeral],
                        "deterministic_origin": "netstat_ephemeral",
                        "_aggregated_source_indices": _raw_indices_for(ephemeral),
                    })

                # T-29: ループバック(127.0.0.1/[::1]) LISTENING を
                # ルールベース LOW 固定にして LLM に送らない。
                # 外部への通信経路を持たないため攻撃的な影響がなく、
                # MEDIUM 誤検知の主因になっていた（HOST-REF-08 で 17件 MEDIUM FP）。
                # ただし MathWorksServiceHost.exe 等の感染疑いプロセスが
                # 127.0.0.1 を LISTEN するケースもあるため、プロセス名を
                # IOC として記録し追跡可能性を維持する。
                # T-18: PID → プロセス名 を突合して IOC に付記する。
                lb_listen = [e for e in filtered
                             if e.get("state") == "LISTENING"
                             and (e.get("local", "").startswith("127.0.0.1:")
                                  or e.get("local", "").startswith("[::1]:"))]
                _lb_ids = {id(e) for e in lb_listen}
                filtered = [e for e in filtered if id(e) not in _lb_ids]
                if lb_listen:
                    _depth1_deterministic_reasons["netstat_loopback"] = set(
                        _raw_indices_for(lb_listen))
                    # PID → プロセス名 突合
                    lb_iocs = []
                    for e in lb_listen:
                        local = e.get("local", "")
                        pid   = _local_to_pid.get(local, e.get("pid", ""))
                        pname = _pid_to_name.get(pid, "")
                        ioc   = f"{local} (pid={pid} {pname})" if pname else local
                        lb_iocs.append(ioc)
                    # プロセス名一覧（重複除去）をサマリに含める
                    pnames = sorted(set(
                        _pid_to_name.get(_local_to_pid.get(e.get("local",""), e.get("pid","")), "?")
                        for e in lb_listen
                    ))
                    extra_entries.append({
                        "identifier": f"ループバック LISTENING {len(lb_listen)}件",
                        "score":      "LOW",
                        "reason":     f"127.0.0.1/::1 でのLISTENING。外部通信経路なし。"
                                       f"プロセス: {', '.join(p for p in pnames if p and p != '?')}。"
                                       "ルールベースLOW固定（T-29、LLM未送信）。"
                                       "※感染疑いプロセスがLISTENしている場合は要手動確認。",
                        "decoded":    None,
                        "lolbas":     None,
                        "mitre":      None,
                        "iocs":       lb_iocs,
                        "deterministic_origin": "netstat_loopback",
                        "_aggregated_source_indices": _raw_indices_for(lb_listen),
                    })

                # T-18: LLM に送る残エントリの identifier に PID → プロセス名を付記
                # スコア変更なし。LLM の判定精度向上が目的。
                for e in filtered:
                    local = e.get("local", "")
                    pid   = _local_to_pid.get(local, e.get("pid", ""))
                    pname = _pid_to_name.get(pid, "")
                    if pname:
                        e["_proc_hint"] = f"pid={pid} ({pname})"

                notes = []
                if local_n:
                    notes.append(
                        f"プライベートIP宛(10./192.168./127./172.16-31) {local_n}件を"
                        "除外（ルールベース、depth=1）。"
                    )
                if ephemeral:
                    notes.append(
                        f"エフェメラルRPCポート(49152-65535)のLISTENING "
                        f"{len(ephemeral)}件をルールベースLOW固定（depth=1、"
                        "LLM未送信、reportには残す）。"
                    )
                if lb_listen:
                    notes.append(
                        f"ループバック(127.0.0.1/::1)LISTENING {len(lb_listen)}件を"
                        "ルールベースLOW固定（T-29、LLM未送信）。"
                    )
                local_note = "".join(notes)

            # ── directory: 優先度分類（① T-36修正） ──────────────────
            # A/B: 必ずLLM送付（取りこぼし防止最優先）
            # C:   LLM送付するが上限3ch（アプリキャッシュが大半）
            # D:   LLM未送付・別ファイル出力（zip/rar/7z はパスを見れば分かる）
            if sec == "directory":
                classified = {"A": [], "B": [], "C": [], "D": []}
                for e in filtered:
                    classified[_classify_dir_entry(e)].append(e)

                d_entries = classified["D"]  # 別ファイル出力用

                # N-4c: A/B/C を異常スコアで順位付けし、上位 DIR_MAX_LLM 件のみ LLM 送付。
                # 残り（下位）は raw_directory ファイルへ退避（取りこぼし防止・可視化）。
                scored = []
                for cls in ("A", "B", "C"):
                    for e in classified[cls]:
                        scored.append((_dir_anomaly_score(e, cls), cls, e))
                scored.sort(key=lambda x: x[0], reverse=True)

                # N-4d(v3.59/案b): 同型パターンは代表 DIR_SIG_MAX 件のみ送付
                llm_entries, overflow, _dir_sig_info = _select_dir_llm_entries(scored)
                n_total = len(scored)

                _tier_sel = _dir_sig_info["tier_selected"]
                _tier_total = _dir_sig_info["tier_total"]
                local_note = (
                    f"[DIR-TIER] M0 {_tier_sel['M0']}/{_tier_total['M0']}件、"
                    f"M1 {_tier_sel['M1']}/{_tier_total['M1']}件、"
                    f"Tier R {_tier_sel['R']}/{_tier_total['R']}件を選抜。"
                    f"合計 {len(llm_entries)}/{n_total}件をLLM送付"
                    + (f"（選外{len(overflow)}件はraw_directoryへ退避）" if overflow else "")
                    + (f"（同型パターン集約 {_dir_sig_info['n_deferred']}件を"
                       f"代表{_dir_sig_info['sig_max']}件/型に置換）"
                       if _dir_sig_info.get('n_deferred') else "")
                    + (f"（M0による通常枠超過"
                       f"{_dir_sig_info['normal_budget_overrun_by_m0']}件）"
                       if _dir_sig_info.get('normal_budget_overrun_by_m0') else "")
                    + f" / [D] zip/rar/7z {len(d_entries)}件（別ファイル出力）。"
                )

                _dir_d_to_save = d_entries
                _dir_overflow_to_save = overflow
                if d_entries:
                    _depth1_deferred_reasons["dir_class_D"] = set(
                        _raw_indices_for(d_entries))
                if overflow:
                    _depth1_deferred_reasons["directory_overflow"] = set(
                        _raw_indices_for(overflow))

                if not llm_entries:
                    print(f"[{hostname}] スキップ（directory 異常スコア該当0件）: {sec}")
                    res = {
                        "section": sec,
                        "entries": list(extra_entries),
                        "section_summary": local_note + "LLM送付エントリなし",
                        "_directory_D": _dir_d_to_save,
                        "_directory_overflow": _dir_overflow_to_save,
                        "_directory_policy": _dir_sig_info,
                    }
                    # 退避が発生した場合は可視化エントリを追加（黙って捨てない）
                    if overflow:
                        res["entries"].append({
                            "identifier": f"⚠ directory: 異常スコア下位{len(overflow)}件をLLM未送付（raw_directory退避）",
                            "score": "MEDIUM",
                            "reason": "件数上限(DIR_MAX_LLM)により下位エントリは LLM 評価対象外。"
                                      "raw_directory.md で目視確認のこと。CHECKPC_DIR_MAX_LLM で上限調整可。",
                            "decoded": None, "lolbas": None, "mitre": [], "iocs": [],
                        })
                    # T-DIR0（v3.57）: parse_checkpc.py が「セクション見出しは
                    # あるのに0件抽出」と記録した構造的異常（parse_warnings）が
                    # ある場合、単なる「所見なし」の折りたたみ表示に埋没させず
                    # HIGH視認性のMEDIUM警告として明示する。GB18030偏重バグ
                    # （v3.57で修正）のような、原因を問わない汎用の安全網。
                    _dir_parse_warns = [
                        w for w in meta.get("parse_warnings", [])
                        if w.get("section") == "directory"
                    ]
                    if _dir_parse_warns:
                        res["entries"].append({
                            "identifier": "⚠⚠ directory: セクション見出しは検出されたが0件抽出"
                                          "（パース異常の疑い・要確認）",
                            "score": "MEDIUM",
                            "reason": _dir_parse_warns[0]["message"] +
                                      " 【取りこぼし防止最優先の方針によりMEDIUMで明示。"
                                      "所見なし（正常にクリーン）とは区別すること】",
                            "decoded": None, "lolbas": None, "mitre": [], "iocs": [],
                        })
                        res["section_summary"] = (
                            "⚠ directory抽出異常の疑い。" + res["section_summary"]
                        )
                    return sec, _with_depth1_plan(
                        res,
                        selected=(),
                        deterministic_reasons=_depth1_deterministic_reasons,
                        deferred_reasons=_depth1_deferred_reasons,
                    )
                filtered = llm_entries

            if not filtered:
                print(f"[{hostname}] スキップ（Level1フィルタ 0件）: {sec}")
                return sec, _with_depth1_plan({
                    "section": sec, "entries": extra_entries,
                    "section_summary": local_note + "Level 1 フィルタに該当するエントリなし"
                }, selected=(), deterministic_reasons=_depth1_deterministic_reasons,
                   deferred_reasons=_depth1_deferred_reasons)
            entries = filtered
        elif isinstance(raw, list):
            # depth>=2 でも directory は Level1 フィルタを適用する。
            # 適用しない場合、directory の全エントリ（45万件超）が
            # チャンクに分割されて vLLM キューを飽和させタイムアウトが全発する。
            # Level1 フィルタはどの depth でも有効なパターン（不審な配置場所・
            # ファイル名）で構成されており、depth>=2 で除外する理由はない。
            # 修正(2026-06-17): depth>=2 での directory 全件渡し問題の修正。
            if sec == "directory":
                entries = apply_level1_filter(sec, raw)
                if not entries:
                    return sec, {
                        "section": sec, "entries": [],
                        "section_summary": "Level 1 フィルタに該当するエントリなし"
                    }
            else:
                entries = raw
        else:
            entries = raw

        # FIX-3 (N-4a): system_7045 の MpKsl（Defender 動的署名サービス）は
        # LLM 送付前に除外して処理時間を回収する（実測で WIN の system_7045
        # 1480秒/総1713秒の主因が MpKsl 164件）。除外分は CLEAN サマリ1件として残す。
        if sec == "system_7045" and isinstance(entries, list) and entries:
            def _is_mpksl(e):
                if not isinstance(e, dict):
                    return False
                blob = " ".join(str(e.get(k, "")) for k in
                                ("service_name", "name", "identifier", "image_path"))
                return bool(_MPKSL_NAME_RE.search(blob))
            mpksl = [e for e in entries if _is_mpksl(e)]
            if mpksl:
                entries = [e for e in entries if not _is_mpksl(e)]
                if depth == 1:
                    _depth1_deterministic_reasons["mpksl_excluded"] = set(
                        _raw_indices_for(mpksl))
                extra_entries.append({
                    "identifier": f"MpKsl Defender動的署名サービス {len(mpksl)}件（LLM未送付・正規）",
                    "score":      "CLEAN",
                    "reason":     "Windows Defender が一時生成する動的署名(KSL)サービス。"
                                  "正規のため LLM 送付前に除外し処理時間を回収（取りこぼし防止に影響なし）。",
                    "decoded":    None, "lolbas": None, "mitre": [], "iocs": [],
                    "deterministic_origin": "mpksl_excluded",
                    "_aggregated_source_indices": _raw_indices_for(mpksl),
                })

        # rev7: TaskScheduler EventID 140 は同一意味イベントの反復更新が
        # 数百件に達することがある。D1に限り、Event番号/日時だけが異なる
        # 完全同義イベントを1代表へ集約してLLMへ送る。task/user/computer/
        # Description等はsemantic keyへ残すため、Microsoft名前空間や製品名を
        # allowlistして捨てる処理ではない。raw全件はprovenanceへ保持する。
        if depth == 1 and sec == "task_140" and isinstance(entries, list) and entries:
            _task140_source_indices = _raw_indices_for(entries, fail_closed=True)
            entries, _task140_aggregation = aggregate_task140_depth1(
                entries, _task140_source_indices)
            _collapsed = int(_task140_aggregation.get("collapsed_count", 0))
            if _collapsed:
                local_note += (
                    f"[TASK140-GROUP] raw {_task140_aggregation['raw_count']}件を"
                    f"意味同一 {_task140_aggregation['group_count']}グループへ集約し"
                    f"{_collapsed}件分の重複LLM送付を省略。"
                    "raw/source ID/first-last時刻は監査情報に保持。"
                )

        # リスト型で空になった場合（depth=1フィルタ後またはevent_logs空）は
        # LLM に送らず早期リターンする。
        # （depth=1 の `if not filtered` ブロックで拾えないケース:
        #   depth>=2 かつ ps_history 等が空リストの場合、
        #   次の isinstance チェックで entries_to_text("ps_history", []) が
        #   呼ばれ "(データなし)" として LLM に送信されてしまう）
        if isinstance(entries, list) and len(entries) == 0 and sec not in ("security_1102", "system_104"):
            print(f"[{hostname}] スキップ（解析対象エントリなし）: {sec}")
            return sec, _with_depth1_plan({
                "section": sec, "entries": [],
                "section_summary": "解析対象エントリなし",
            }, selected=(), deterministic_reasons=_depth1_deterministic_reasons,
               deferred_reasons=_depth1_deferred_reasons)

        # チャンク分割が必要なリスト型セクション
        if isinstance(entries, list) and len(entries) > 0:
            # _meta_only エントリ（旧方式の残留）はLLMに送らず分離
            _meta_entries = [e for e in entries if isinstance(e, dict) and e.get("_meta_only")]
            entries       = [e for e in entries if not (isinstance(e, dict) and e.get("_meta_only"))]
            if depth == 1 and sec == "task_140" and _task140_aggregation:
                _groups = list(_task140_aggregation.get("groups", []))
                if len(_groups) != len(entries):
                    raise ValueError("task_140 aggregation representative/group cardinality mismatch")
                _chunk_source_indices = []
                for _group, _representative in zip(_groups, entries):
                    _raw_indices = list(_group.get("raw_indices") or [])
                    if not _raw_indices:
                        raise ValueError("task_140 aggregation group has no raw index")
                    _rep_sid = str((_representative or {}).get("source_id") or "") \
                        if isinstance(_representative, dict) else ""
                    if not _rep_sid or _rep_sid != str(_group.get("representative_source_id") or ""):
                        raise ValueError("task_140 aggregation representative source_id mismatch")
                    _chunk_source_indices.append(int(_raw_indices[0]))
                _depth1_selected_indices = {
                    int(idx)
                    for group in _groups
                    for idx in group.get("raw_indices", [])
                }
            else:
                _chunk_source_indices = _raw_indices_for(entries)
                _depth1_selected_indices = set(_chunk_source_indices) if depth == 1 else set()

            entry_results, section_summary, chunk_errors, chunk_timings = call_llm_chunked(
                client, model, sec, depth, entries, verbose, context
            , lean=lean, source_indices=_chunk_source_indices)
            if depth == 1 and sec == "task_140" and _task140_aggregation:
                _expand_task140_aggregation_results(entry_results, _task140_aggregation)
            sec_result = {
                "section":         sec,
                "entries":         entry_results + extra_entries,
                "section_summary": local_note + section_summary,
                "_chunk_timings":  chunk_timings,
            }
            if depth == 1 and sec == "task_140" and _task140_aggregation:
                # by_representative_source_id is an in-memory lookup only; the
                # serialised audit record keeps the compact group list.
                sec_result["_task140_aggregation"] = {
                    k: v for k, v in _task140_aggregation.items()
                    if k != "by_representative_source_id"
                }

            # directory D エントリを sec_result トップレベルに保存
            # （run_analysis.py の Step6 で参照して別ファイル出力する）
            if sec == "directory" and _dir_d_to_save:
                sec_result["_directory_D"] = _dir_d_to_save
            if sec == "directory" and _dir_sig_info:
                sec_result["_directory_policy"] = _dir_sig_info
            # N-4c: 異常スコア下位の退避分も raw ファイルへ。可視化エントリも追加。
            if sec == "directory" and _dir_overflow_to_save:
                sec_result["_directory_overflow"] = _dir_overflow_to_save
                sec_result["entries"].append({
                    "identifier": f"⚠ directory: 異常スコア選外{len(_dir_overflow_to_save)}件をLLM未送付（raw_directory退避）",
                    "score": "MEDIUM",
                    "reason": "件数上限(DIR_MAX_LLM)・同型パターン集約(N-4d)により選外エントリは "
                              "LLM 評価対象外。raw_directory.md で目視確認のこと。"
                              "CHECKPC_DIR_MAX_LLM で上限調整可。",
                    "decoded": None, "lolbas": None, "mitre": [], "iocs": [],
                })
            if (sec == "directory" and _dir_sig_info
                    and _dir_sig_info.get("coverage_degraded")):
                _tier_total = sum(_dir_sig_info.get("tier_total", {}).values())
                _tier_selected = sum(_dir_sig_info.get("tier_selected", {}).values())
                _tier_deferred = max(0, _tier_total - _tier_selected)
                _reasons = _dir_sig_info.get("deferred_reason_counts", {})
                _reason_txt = "、".join(
                    f"{k}={v}" for k, v in sorted(_reasons.items()) if v)
                sec_result["entries"].append({
                    "identifier": (f"⚠ directory: 候補{_tier_total}件中{_tier_selected}件を"
                                   f"個別LLM評価（未個別評価 {_tier_deferred}件）"),
                    "score": "MEDIUM",
                    "reason": ("M0/M1/Tier Rの有界選抜により、未選抜分は個別LLM評価の対象外。"
                               "全件はparsed raw証拠・監査会計・チャットraw索引に保持される。"
                               "この警告がある場合、レポート記載分だけでファイル不存在を断定しないこと。"
                               + (f" 繰延理由: {_reason_txt}。" if _reason_txt else "")),
                    "decoded": None, "lolbas": None, "mitre": [], "iocs": [],
                })
            # N-4d(v3.59/案b): 同型パターン集約が発生した場合は内訳を可視化
            # （黙って捨てない: 何が何件、代表何件に置換されたかを明示）
            if sec == "directory" and _dir_sig_info and _dir_sig_info.get("n_deferred"):
                _top_txt = "、".join(f"{sig} ×{n}件" for sig, n in _dir_sig_info["top"])
                sec_result["entries"].append({
                    "identifier": f"⚠ directory: 同型パターン{_dir_sig_info['n_deferred']}件を"
                                  f"代表{_dir_sig_info['sig_max']}件/型に集約（raw_directory退避）",
                    "score": "MEDIUM",
                    "reason": "同一フォルダ×同一ファイル名パターン（#は16進/数字の可変部）の"
                              f"量産ファイルは代表のみLLM送付。集約上位: {_top_txt}。"
                              "全量は raw_directory.md で目視確認のこと。"
                              "CHECKPC_DIR_SIG_MAX=0 で無効化（従来動作）。",
                    "decoded": None, "lolbas": None, "mitre": [], "iocs": [],
                })
            # 旧方式（_meta_only エントリ経由）との互換性
            for m in _meta_entries:
                if "_directory_D_entries" in m:
                    sec_result["_directory_D"] = m["_directory_D_entries"]
            if chunk_errors:
                sec_result["_chunk_errors"] = chunk_errors
                # 取りこぼし防止: 失敗チャンクのエントリは破棄されるため、
                # レポートに「解析失敗・要再解析」を MEDIUM で明示する（黙って捨てない）。
                # partial_parse（部分救出）は「未評価＝n_entries − 救出数」のみ計上。
                lost = 0
                salvaged_total = 0
                hard_fail = 0
                kinds = set()
                _task140_occurrence_by_rep = {}
                if sec == "task_140" and _task140_aggregation:
                    _task140_occurrence_by_rep = {
                        int(group["raw_indices"][0]): int(group.get("occurrence_count", 1) or 1)
                        for group in _task140_aggregation.get("groups", [])
                        if group.get("raw_indices")
                    }
                for ce in chunk_errors:
                    n = int(ce.get("n_entries", 0) or 0)
                    _unevaluated = [
                        int(x) for x in (ce.get("unevaluated_indices") or [])
                        if isinstance(x, int) and not isinstance(x, bool)
                    ]
                    _raw_lost = (
                        _task140_raw_unevaluated_count(ce, _task140_aggregation)
                        if _task140_occurrence_by_rep else None
                    )
                    if ce.get("partial_parse"):
                        nsv = int(ce.get("n_salvaged", 0) or 0)
                        lost += (_raw_lost if _raw_lost is not None else max(0, n - nsv))
                        if _task140_occurrence_by_rep:
                            _failed_reps = set(_unevaluated)
                            _all_reps = set(
                                int(x) for x in (ce.get("source_indices") or [])
                                if isinstance(x, int) and not isinstance(x, bool)
                            )
                            salvaged_total += sum(
                                _task140_occurrence_by_rep.get(idx, 1)
                                for idx in (_all_reps - _failed_reps)
                            ) if _all_reps else nsv
                        else:
                            salvaged_total += nsv
                        kinds.add("出力切断（部分救出）")
                    else:
                        lost += (_raw_lost if _raw_lost is not None else n)
                        hard_fail += 1
                        kinds.add("parse_error(truncation等)" if ce.get("parse_error")
                                  else (ce.get("error", "error") or "error")[:40])
                if lost > 0 or hard_fail > 0:
                    _extra = (f"（うち {salvaged_total}件は部分救出済）" if salvaged_total else "")
                    sec_result["entries"].append({
                        "identifier": f"⚠ {sec}: {len(chunk_errors)}チャンクで解析不全・最大{lost}件未評価{_extra}",
                        "score":      "MEDIUM",
                        "reason":     f"LLM応答の解析に問題（{', '.join(sorted(kinds))}）。"
                                      "未評価エントリは取りこぼしの可能性がある。"
                                      "depth を上げる/CHECKPC_DIR_MAX_LLM 等で1チャンク件数を"
                                      "下げる/再解析を推奨。",
                        "decoded": None, "lolbas": None, "mitre": [], "iocs": [],
                    })
                if verbose:
                    for ce in chunk_errors:
                        print(f"  [WARN] {sec} chunk {ce.get('chunk')}: "
                              f"{ce.get('note') or ce.get('error') or 'parse_error'}", file=sys.stderr)
            if depth == 1:
                sec_result = _with_depth1_plan(
                    sec_result,
                    selected=_depth1_selected_indices,
                    selected_reasons={"depth1_selected": _depth1_selected_indices},
                    deterministic_reasons=_depth1_deterministic_reasons,
                    deferred_reasons=_depth1_deferred_reasons,
                )
        else:
            # raw text セクション
            data_text  = entries_to_text(sec, entries)
            llm_result = _call_llm_score_checked(client, model, sec, depth, data_text, verbose)
            if not llm_result:
                sec_result = {"section": sec, "entries": [], "section_summary": "",
                               "_chunk_errors": [{"error": "call_llm returned no result (falsy)"}]}
            elif "error" in llm_result:
                sec_result = {"section": sec, "entries": [], "section_summary": "",
                               "_chunk_errors": [{"error": llm_result["error"]}]}
            elif llm_result.get("parse_error"):
                sec_result = {"section": sec, "entries": [], "section_summary": "",
                               "_chunk_errors": [{"parse_error": True,
                                                   "raw_response": llm_result.get("raw_response", "")[:2000]}]}
            else:
                sec_result = llm_result

        # ── ルールベース post-filter ──────────────────────────────
        # LLM が見落としやすい「既知正規パターン」を確実に CLEAN 降格させる。
        # 取りこぼし防止のため「明らかに正規」な条件に限定する。
        if isinstance(sec_result, dict) and "entries" in sec_result:
            sec_result = _apply_post_filter(sec, _normalise_score_schema(sec_result), raw)

        return sec, sec_result

    _progress_lock = threading.Lock()
    _progress_active = set()
    _progress_terminal = set()
    _progress_completed = 0
    _progress_cancelled = 0
    _progress_failed = 0
    _progress_total = len(analyze_list)

    def _progress_section(stage: str, sec: str):
        nonlocal _progress_completed, _progress_cancelled, _progress_failed
        with _progress_lock:
            if stage == "start":
                if sec not in _progress_terminal:
                    _progress_active.add(sec)
            else:
                _progress_active.discard(sec)
                if sec not in _progress_terminal:
                    _progress_terminal.add(sec)
                    if stage == "complete":
                        _progress_completed += 1
                    elif stage == "cancel":
                        _progress_cancelled += 1
                    elif stage == "fail":
                        _progress_failed += 1
            active = sorted(_progress_active)
            terminal = _progress_completed + _progress_cancelled + _progress_failed
            detail = {
                "stage": "section_analysis",
                "completed": _progress_completed,
                "cancelled": _progress_cancelled,
                "failed": _progress_failed,
                "terminal": terminal,
                "total": _progress_total,
                "active_sections": active,
                "last_completed": sec if stage == "complete" else "",
                "last_cancelled": sec if stage == "cancel" else "",
                "last_failed": sec if stage == "fail" else "",
                "event": stage,
            }
            msg = (f"Step 4C: セクション解析 terminal={terminal}/{_progress_total} "
                   f"完了={_progress_completed} 中断={_progress_cancelled} "
                   f"失敗={_progress_failed} "
                   f"実行中={','.join(active) if active else '-'}")
            if stage == "complete":
                msg += f" 直近完了={sec}"
            elif stage == "cancel":
                msg += f" 直近中断={sec}"
            elif stage == "fail":
                msg += f" 直近失敗={sec}"
        # Never call the server callback while _progress_lock is held.
        _emit_progress(msg, **detail)

    def _timed_analyze_one_section(sec: str) -> tuple:
        """analyze_one_section() のセクション単位タイマー。
        セクションごとの総処理時間(_elapsed_sec)を sec_result に付与する。
        チャンク単位の_chunk_timingsと併用することでセクション内訳・チャンクごとの傾向が分析できる。

        ⑤ 解析完了メッセージはここで表示する（_elapsed_sec が確定してから出力するため）。
        analyze_one_section の return 直前では elapsed_sec = 0.0 になる問題の修正。
        """
        if cancel_check and cancel_check():
            # 中断要求あり：未着手セクションはLLM呼び出しをせずスキップする。
            print(f"[{hostname}] 中断要求によりスキップ: {sec}")
            _progress_section("cancel", sec)
            return sec, {"section": sec, "entries": [], "cancelled": True}

        _progress_section("start", sec)
        t0 = time.time()
        try:
            sec, sec_result = analyze_one_section(sec)
            if depth == 1:
                _raw_for_prov = (event_logs.get(sec) if sec in {
                    "security_1102", "system_104", "system_7045", "rdp_1024",
                    "task_106", "task_140", "task_141", "rdp_inbound"
                } else sections.get(sec))
                sec_result = _attach_depth1_provenance(sec, _raw_for_prov, sec_result)
        except Exception:
            _progress_section("fail", sec)
            raise
        if isinstance(sec_result, dict):
            sec_result["_elapsed_sec"] = round(time.time() - t0, 2)

        # 完了メッセージ（elapsed_sec 確定後に表示）
        if isinstance(sec_result, dict):
            from collections import Counter as _Counter
            entries_out = [e for e in sec_result.get("entries", [])
                           if isinstance(e, dict) and not e.get("_meta_only")]
            score_summary = _Counter(e.get("score", "?") for e in entries_out)
            score_str = "  ".join(
                f"{s}={n}" for s, n in sorted(
                    score_summary.items(),
                    key=lambda x: (["HIGH","MEDIUM","LOW","CLEAN","?"].index(x[0])
                                   if x[0] in ["HIGH","MEDIUM","LOW","CLEAN","?"] else 9)
                )
            )
            elapsed = sec_result.get("_elapsed_sec", 0)
            print(f"[{hostname}] 完了: {sec:<22} entries={len(entries_out):>3}件"
                  f"  {score_str}  ({elapsed:.1f}秒)")
        _progress_section("complete", sec)
        return sec, sec_result

    # セクションを並列実行
    # チャンク内は chunk_workers=1（直列）なので合計最大同時リクエスト数は
    # section_workers: depth に応じて並列数を制御する。
    #   depth=1:   section_workers=3（③ RTX A4500×2 Tensor Parallel 活用）
    #   depth=2:   section_workers=2（従来通り）
    #   depth=3/4: section_workers=1（直列化。キュー飽和防止）
    #     理由: depth>=3 は CHUNK_SIZE が大きく総チャンク数が多い。
    #     section_workers=2 にするとキュー飽和→タイムアウトが多発するため
    #     直列化してキューを安定させる（Tensor Parallel 2枚でも同様）。
    # 修正(2026-06-17): depth>=3 でのキュー飽和対策。
    # 修正(2026-06-24): depth=1 を 2→3 に（③ 高速化修正）。
    #   Tensor Parallel 構成では vLLM が内部バッチ処理するため
    #   3セクション同時投入でもキュー飽和のリスクは低い。
    if depth >= 3:
        max_workers = 1
    elif depth == 1:
        max_workers = min(3, len(analyze_list))
    else:
        max_workers = min(2, len(analyze_list))
    _completed_sections = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_timed_analyze_one_section, sec): sec for sec in analyze_list}
        for future in as_completed(futures):
            sec, sec_result = future.result()
            if sec_result is not None:
                _completed_sections[sec] = sec_result
    # as_completed の完了順ではなく、固定 analyze_list 順で成果物を構築する。
    for _sec in analyze_list:
        if _sec in _completed_sections:
            results["sections"][_sec] = _completed_sections[_sec]

    with _progress_lock:
        _final_detail = {
            "stage": "section_analysis_final",
            "completed": _progress_completed,
            "cancelled": _progress_cancelled,
            "failed": _progress_failed,
            "terminal": _progress_completed + _progress_cancelled + _progress_failed,
            "total": _progress_total,
            "active_sections": sorted(_progress_active),
            "event": "final",
        }
    _emit_progress(
        f"Step 4C: セクション解析終了 terminal={_final_detail['terminal']}/{_progress_total} "
        f"完了={_progress_completed} 中断={_progress_cancelled} 失敗={_progress_failed}",
        **_final_detail)

    # N-3: known_tools は LLM を使わず parse 済み全件を決定論的に走査するため、
    # セクション並列ループの外で実行して注入する（フィルタ層を通さない）。
    if target_sections is None or "known_tools" in analyze_list:
        results["sections"]["known_tools"] = analyze_known_tools(sections, _collection_id)

    # 修正(2026-06-12): 次回のdepth=1高速化検討（vLLM prefix caching・
    # 並列度の再検討、設計書5章ToDo）のため、全体・セクション別の所要時間を
    # analyzed.json側に残す（コンソールログを別途保存しなくても、出力一式
    # だけで計測できるようにする）。
    results["_timing_summary"] = {
        "total_elapsed_sec": round(time.time() - analyze_start, 2),
        "section_max_workers": max_workers,  # depth>=3 では 1 に制限
        "chunk_max_workers": CHUNK_MAX_WORKERS,  # N-4b: CHECKPC_CHUNK_WORKERS で可変
        "per_section_elapsed_sec": {
            sec: d.get("_elapsed_sec")
            for sec, d in results["sections"].items()
            if isinstance(d, dict)
        },
    }

    return results


# ─────────────────────────────────────────────────────────────
# エントリポイント
# ─────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="parse_checkpc.py の JSON 出力をセクション別に LLM 解析する"
    )
    ap.add_argument("input",          help="parse_checkpc.py の出力 JSON パス")
    ap.add_argument("--depth",   "-d", type=int, default=DEFAULT_DEPTH,
                    choices=[1, 2, 3, 4],
                    help="解析深度: 1=Filtered Triage(既定) / 2=Broad Review(検証・再調査用) / "
                         "3,4=試験機能（--experimental-depths 必須）")
    ap.add_argument("--experimental-depths", action="store_true",
                    help="depth 3/4 の試験実行を許可する")
    ap.add_argument("--section", "-s", action="append", dest="sections",
                    help="解析するセクションを指定（複数指定可）。省略時は全セクション")
    ap.add_argument("--output",  "-o", help="出力 JSON ファイルパス（省略時は自動命名）")
    ap.add_argument("--vllm-url",     default=DEFAULT_VLLM_URL,
                    help=f"vllm API エンドポイント（デフォルト: {DEFAULT_VLLM_URL}）")
    ap.add_argument("--model",   "-m", default=DEFAULT_MODEL,
                    help=f"使用モデル名（デフォルト: {DEFAULT_MODEL}）")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="詳細ログを表示")
    args = ap.parse_args()
    if args.depth >= 3 and not args.experimental_depths:
        ap.error("depth 3/4 は試験機能です。--experimental-depths を明示してください。")

    if not os.path.exists(args.input):
        print(f"[ERROR] ファイルが見つかりません: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input, encoding="utf-8") as f:
        parsed = json.load(f)

    client = OpenAI(base_url=args.vllm_url, api_key="dummy")

    # 接続確認
    try:
        models = client.models.list()
        available = [m.id for m in models.data]
        if args.model not in available:
            print(f"[WARN] モデル '{args.model}' が見つかりません。利用可能: {available}",
                  file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] vllm への接続に失敗しました: {e}", file=sys.stderr)
        sys.exit(1)

    depth_names = {1: "Quick", 2: "Standard", 3: "Deep", 4: "Exhaustive"}
    print(f"解析開始 | ホスト: {parsed.get('meta', {}).get('hostname', 'UNKNOWN')} "
          f"| 深度: {args.depth} ({depth_names[args.depth]})")
    if args.sections:
        print(f"対象セクション: {', '.join(args.sections)}")

    start = time.time()
    results = analyze(
        parsed, args.depth,
        client, args.model,
        target_sections=args.sections,
        verbose=args.verbose,
    )
    elapsed = time.time() - start
    print(f"解析完了 ({elapsed:.1f} 秒)")

    # 出力
    if args.output:
        out_path = args.output
    else:
        base = os.path.basename(args.input).replace("parsed_", "analyzed_")
        out_path = os.path.join(os.path.dirname(args.input), base)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"出力: {out_path}")

    # スコアサマリ
    total_high = total_med = 0
    for sec_name, sec_data in results.get("sections", {}).items():
        if isinstance(sec_data, dict):
            entries = sec_data.get("entries", [])
            if isinstance(entries, list):
                h = sum(1 for e in entries if isinstance(e, dict) and e.get("score") == "HIGH")
                m = sum(1 for e in entries if isinstance(e, dict) and e.get("score") == "MEDIUM")
                if h + m > 0:
                    print(f"  {sec_name:20s}: HIGH={h} MEDIUM={m}")
                total_high += h
                total_med  += m
    print(f"  {'合計':20s}: HIGH={total_high} MEDIUM={total_med}")


if __name__ == "__main__":
    main()
