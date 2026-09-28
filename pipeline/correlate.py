#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
correlate.py
analyze_section.py の出力 JSON を受け取り、横断相関・時系列再構成を行う。

Usage:
    python correlate.py <analyzed.json> [--depth 1-4] [-o correlation.json]
"""

import re
import sys
import json
import os
import argparse
import time
try:
    from openai import OpenAI
except ImportError:  # テスト/静的監査環境向け。実LLM実行時は依存導入必須。
    class OpenAI:  # pragma: no cover
        def __init__(self, *args, **kwargs):
            raise RuntimeError("openai パッケージが必要です。INSTALL.txt を参照してください。")

from section_prompts import get_prompt, get_system_prompt
from analyze_section import extract_first_json_object
from report_gen import apply_deterministic_fallback
from known_infra import identify_known_service
from ioc_utils import normalize_evidence_ioc_detail
from token_budget import (MAX_MODEL_LEN, CORR_SAFETY_MARGIN, CHAT_TEMPLATE_TOKENS,
                          est_tokens, token_estimator_name,
                          tokenizer_fingerprint)
from llm_runtime import create_chat_completion, extract_llm_text

DEFAULT_VLLM_URL = "http://localhost:8000/v1"
DEFAULT_MODEL    = "qwen25-coder-32b-q3"
DEFAULT_DEPTH    = 1   # v3.68: 全モジュールで 1 へ統一（旧=2）
REQUEST_TIMEOUT  = 300
CORRELATE_MAX_IOCS = max(1, int(os.environ.get("CHECKPC_CORRELATE_MAX_IOCS", "50")))
CORRELATE_MAX_TIMELINE = max(1, int(os.environ.get("CHECKPC_CORRELATE_MAX_TIMELINE", "50")))
CORRELATE_MAX_TTPS = max(1, int(os.environ.get("CHECKPC_CORRELATE_MAX_TTPS", "50")))
CORRELATE_MAX_ACTIONS = max(1, int(os.environ.get("CHECKPC_CORRELATE_MAX_ACTIONS", "20")))

FALLBACK_REASONS = frozenset({
    "initial_build_error",
    "initial_budget_exhausted",
    "initial_llm_error",
    "retry_build_error",
    "retry_budget_exhausted",
    "retry_llm_error",
    "retry_parse_error",
    "retry_truncated_invalid_json",
    "initial_processing_error",
})


class CorrelateBudgetExhausted(ValueError):
    """Evidence text cannot fit the explicit correlation token budget."""

CORRELATE_RETRY_MAX_TOKENS = max(
    256, int(os.environ.get("CHECKPC_CORRELATE_RETRY_MAX_TOKENS", "4096")))

# vLLM起動時の --max-model-len。
# 旧構成（RTX A4500×1）: 6144
# 現構成（RTX A4500×2 Tensor Parallel）: 16384（kitting manual v2.5以降）
# ※ 変更時は run_analysis.py の --max-model-len 引数と合わせること
# token_budget.pyを単一の真実とする。旧名は外部参照互換の別名。
CHARS_PER_TOKEN = 2.0
TOKEN_SAFETY_MARGIN = CORR_SAFETY_MARGIN


_PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
)

# external_intrusion を示唆するキーワード（significance/ioc本文中）
_EXTERNAL_KEYWORDS = (
    "マルウェア", "C2", "ダウンロード", "侵入", "トロイ", "ランサム",
    "バックドア", "難読化", "痕跡消去", "改竄", "webshell", "Webシェル",
    "エクスプロイト", "exploit",
)
# internal_automation を示唆するキーワード
_INTERNAL_KEYWORDS = (
    "スケジュールタスク", "監視エージェント", "Monitoring Agent", "証明書更新",
    "管理者", "バックアップ", "業務上", "横移動の可能性", "内部IP",
    "パッチ", "SCOM", "エージェント",
)


def _apply_ioc_category_fallback(result: dict) -> int:
    """
    correlated_iocs の各要素に category（external_intrusion/internal_automation/
    unclear）が無い、または不正な値の場合に、キーワード・IPアドレス種別から
    決定論的に補完する（LLMがcategoryを付与しなかった場合の取りこぼし防止）。

    優先順位: ①既知インフラサービス(Azure等) ②プライベートIP ③キーワード一致
             ④どれにも該当しなければ unclear
    戻り値: 補完した件数
    """
    valid = {"external_intrusion", "internal_automation", "internal_unclear", "unclear"}
    n = 0
    for ioc in result.get("correlated_iocs", []) or []:
        if not isinstance(ioc, dict):
            continue
        if ioc.get("category") in valid:
            continue
        ioc_val = str(ioc.get("ioc", ""))
        sig     = str(ioc.get("significance", ""))
        text    = ioc_val + " " + sig

        if identify_known_service(ioc_val):
            ioc["category"] = "internal_automation"
        elif _PRIVATE_IP_RE.search(ioc_val):
            ioc["category"] = "internal_unclear"
        elif any(k in text for k in _EXTERNAL_KEYWORDS):
            ioc["category"] = "external_intrusion"
        elif any(k in text for k in _INTERNAL_KEYWORDS):
            ioc["category"] = "internal_automation"
        else:
            ioc["category"] = "unclear"
        n += 1
    return n


def _annotate_known_infra_services(result: dict) -> int:
    """
    correlated_iocs の各要素に、既知のクラウド/インフラサービスIP
    （Azureプラットフォームintake, パブリックDNS等）が含まれる場合、
    known_service フィールドにサービス名を注記する（安全性の判定ではなく
    識別のみ。分析官が既知サービスかどうかを毎回検索する手間を減らす）。
    戻り値: 注記した件数
    """
    n = 0
    for ioc in result.get("correlated_iocs", []) or []:
        if not isinstance(ioc, dict):
            continue
        svc = identify_known_service(str(ioc.get("ioc", "")))
        if svc:
            ioc["known_service"] = svc
            n += 1
    return n


def _section_order():
    """固定 section 順の単一の真実。analyze_section の定義順に従う。
    完了順（as_completed）に依存させない（v3.68 / C10）。"""
    try:
        from analyze_section import SECTIONS_TO_ANALYZE
        return list(SECTIONS_TO_ANALYZE)
    except Exception:
        return []


def extract_high_medium(results: dict) -> dict:
    """
    セクション別評価結果から HIGH/MEDIUM エントリのみ抽出する。
    ★v3.68(C10): 固定 section 順で構成し、dict 挿入順（as_completed 完了順）に
      依存させない。未知セクションは名前順で末尾に付ける。
    """
    sections = results.get("sections", {})
    order = _section_order()
    known = [s for s in order if s in sections]
    unknown = sorted(set(sections) - set(order))
    filtered = {}
    for sec_name in known + unknown:
        sec_data = sections.get(sec_name)
        if not isinstance(sec_data, dict):
            continue
        entries = sec_data.get("entries", [])
        if not isinstance(entries, list):
            continue
        hm = [e for e in entries if isinstance(e, dict)
              and e.get("score") in ("HIGH", "MEDIUM")]
        if hm:
            filtered[sec_name] = {
                "entries":         hm,
                "section_summary": sec_data.get("section_summary", ""),
            }
    return filtered


def _render_high_line(e, level):
    """HIGH エントリを compression level に応じてレンダリングする。"""
    ident = e.get("identifier", "")
    score = e.get("score", "")
    if level <= 1:
        out = [f"  [{score}] {ident}"]
        reason = e.get("reason", "")
        if level == 1 and reason:
            reason = reason[:120] + ("…" if len(reason) > 120 else "")
        if reason:
            out.append(f"    根拠: {reason}")
        if e.get("decoded"):
            out.append(f"    デコード: {e['decoded']}")
        if e.get("iocs"):
            out.append(f"    IOC: {', '.join(e['iocs'])}")
        return "\n".join(out)
    # level 2: identifier / score / iocs / section のみ
    iocs = e.get("iocs", [])
    tail = f" IOC:{','.join(iocs)}" if iocs else ""
    return f"  [{score}] {ident}{tail}"


def build_correlate_text(filtered: dict, depth: int,
                         budget_tokens: int = None) -> tuple:
    """固定順かつ最終テキスト実測ベースで相関入力を予算内に収める。"""
    if budget_tokens is None:
        budget_tokens = 10 ** 9
    order = _section_order()
    sec_order = [x for x in order if x in filtered] + sorted(
        x for x in filtered if x not in order)
    highs_by_sec = {s: [] for s in sec_order}
    meds_by_sec = {s: [] for s in sec_order}
    for sec in sec_order:
        for e in filtered[sec].get("entries", []):
            (highs_by_sec if e.get("score") == "HIGH" else meds_by_sec)[sec].append(e)
    high_total = sum(len(v) for v in highs_by_sec.values())
    med_total = sum(len(v) for v in meds_by_sec.values())

    def render_high_map(level):
        mapping = {s: [] for s in sec_order}
        individual = aggregated = 0
        if level <= 2:
            for sec in sec_order:
                for e in highs_by_sec[sec]:
                    mapping[sec].append(_render_high_line(e, level))
                    individual += 1
            return mapping, individual, aggregated
        if level == 3:
            for sec in sec_order:
                groups = {}
                group_order = []
                for e in highs_by_sec[sec]:
                    key = (e.get("reason", "") or "")[:60]
                    if key not in groups:
                        groups[key] = []
                        group_order.append(key)
                    groups[key].append(e)
                for key in group_order:
                    g = groups[key]
                    if len(g) >= 2:
                        ident = str(g[0].get("identifier", ""))[:90]
                        mapping[sec].append(
                            f"  [HIGH] {ident} 他{len(g)-1}件、計{len(g)}件が同型")
                        aggregated += len(g)
                    else:
                        mapping[sec].append(_render_high_line(g[0], 2))
                        individual += 1
            return mapping, individual, aggregated
        # level4: sectionごとの件数と短い代表。全sourceを件数で表現する。
        for sec in sec_order:
            g = highs_by_sec[sec]
            if not g:
                continue
            reps = ", ".join(str(x.get("identifier", ""))[:40] for x in g[:3])
            mapping[sec].append(f"  [HIGH] {len(g)}件（代表: {reps}）")
            aggregated += len(g)
        return mapping, individual, aggregated

    def compose(high_map, med_map=None, include_summaries=True):
        med_map = med_map or {}
        lines = []
        for sec in sec_order:
            lines.append(f"\n=== {sec} ===")
            if include_summaries:
                summ = str(filtered[sec].get("section_summary", "") or "")
                if summ:
                    lines.append(f"サマリ: {summ}")
            lines.extend(high_map.get(sec, []))
            lines.extend(med_map.get(sec, []))
        return "\n".join(lines)

    compression = 0
    high_map = {}
    hi_individual = hi_aggregated = 0
    base = ""
    for level in (0, 1, 2, 3, 4):
        hm, indiv, aggr = render_high_map(level)
        candidate = compose(hm, include_summaries=True)
        high_map, hi_individual, hi_aggregated, base = hm, indiv, aggr, candidate
        compression = level
        if est_tokens(candidate) <= budget_tokens:
            break
    if est_tokens(base) > budget_tokens:
        # section summaryを外して最小化。それでも超過する場合は代表を落とし件数のみ。
        base = compose(high_map, include_summaries=False)
    if est_tokens(base) > budget_tokens:
        compression = 4
        high_map = {s: ([f"  [HIGH] {len(highs_by_sec[s])}件"]
                         if highs_by_sec[s] else []) for s in sec_order}
        hi_individual = 0
        hi_aggregated = high_total
        base = compose(high_map, include_summaries=False)
    if est_tokens(base) > budget_tokens:
        # セクション数分の最小件数サマリ。通常は到達しないが明示的に保証する。
        lines = ["【HIGH最小サマリ】"]
        for sec in sec_order:
            if highs_by_sec[sec]:
                lines.append(f"{sec}: HIGH {len(highs_by_sec[sec])}件")
        base = "\n".join(lines)
        high_map = {}
        compression = 4
        hi_individual = 0
        hi_aggregated = high_total
    if est_tokens(base) > budget_tokens:
        # 極端に小さい合成テスト用の最終縮退。総件数が全HIGH sourceを代表する。
        base = f"HIGH={high_total}"
        high_map = {}
        compression = 4
        hi_individual = 0
        hi_aggregated = high_total

    med_lines = {s: [] for s in sec_order}
    ptr = {s: 0 for s in sec_order}
    # 完成テキストを毎回評価するため、統計と実体が乖離しない。
    while True:
        added = False
        for sec in sec_order:
            if ptr[sec] >= len(meds_by_sec[sec]):
                continue
            e = meds_by_sec[sec][ptr[sec]]
            line = _render_high_line(e, min(compression, 2))
            trial = {s: list(v) for s, v in med_lines.items()}
            trial[sec].append(line)
            candidate = compose(high_map, trial,
                                include_summaries=("【HIGH最小サマリ】" not in base))
            if est_tokens(candidate) <= budget_tokens:
                med_lines[sec].append(line)
                ptr[sec] += 1
                base = candidate
                added = True
        if not added:
            break

    final_text = base
    final_tokens = est_tokens(final_text)
    if final_tokens > budget_tokens:
        raise CorrelateBudgetExhausted(
            f"correlate入力予算超過: estimated={final_tokens} budget={budget_tokens}")
    omitted_by_section = {
        sec: len(meds_by_sec[sec]) - ptr[sec]
        for sec in sec_order if len(meds_by_sec[sec]) - ptr[sec] > 0
    }
    included_med = sum(ptr.values())
    stats = {
        "input_total": high_total + med_total,
        "included": high_total + included_med,
        "omitted": med_total - included_med,
        "compression_level": compression,
        "omitted_by_section": omitted_by_section,
        "high_source_total": high_total,
        "high_individual_included": hi_individual,
        "high_aggregated_source_count": hi_aggregated,
        "high_unrepresented": max(0, high_total - hi_individual - hi_aggregated),
        "budget_tokens": budget_tokens,
        "used_tokens": final_tokens,
        "section_order": "SECTIONS_TO_ANALYZE",
        "input_sha256": __import__("hashlib").sha256(final_text.encode("utf-8")).hexdigest(),
        "token_estimator": token_estimator_name(),
        "tokenizer_fingerprint": tokenizer_fingerprint(),
    }
    return final_text, stats



def _parse_correlation_json(raw: str):
    obj_str = extract_first_json_object(raw or "")
    if not obj_str:
        return None
    try:
        value = json.loads(obj_str)
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        return None


def _cap_correlation_output(result: dict) -> dict:
    """Keep correlation output bounded and deterministic.

    Compact retry uses smaller *prompt targets*, but a valid completed JSON is
    never discarded merely for exceeding those targets.  The same hard safety
    limits apply to initial and retry outputs.
    """
    for field, limit in (
        ("correlated_iocs", CORRELATE_MAX_IOCS),
        ("timeline", CORRELATE_MAX_TIMELINE),
        ("mitre_ttps", CORRELATE_MAX_TTPS),
        ("recommended_actions", CORRELATE_MAX_ACTIONS),
    ):
        values = result.get(field)
        if isinstance(values, list) and len(values) > limit:
            result[field] = values[:limit]
            result.setdefault("_output_limits", {})[field] = {
                "limit": limit, "omitted": len(values) - limit,
            }
    return result


def _normalize_correlation_iocs(result: dict) -> int:
    """Normalize correlation IOC elements and retain auditable counters."""
    values = result.get("correlated_iocs")
    if not isinstance(values, list):
        return 0
    normalized = []
    changed = 0
    deduplicated = 0
    dropped_empty = 0
    invalid_port = 0
    raw_preserved = 0
    connection_pair_rejected = 0
    seen = set()
    for value in values:
        if not isinstance(value, dict):
            normalized.append(value)
            continue
        item = dict(value)
        detail = normalize_evidence_ioc_detail(item.get("ioc", ""))
        new_ioc = detail.get("ioc", "")
        if not new_ioc:
            dropped_empty += 1
            continue
        if new_ioc != str(item.get("ioc", "")) or detail.get("ioc_port") is not None:
            changed += 1
        item["ioc"] = new_ioc
        item.pop("ioc_port", None)
        item.pop("ioc_raw", None)
        item.pop("local_ip", None)
        item.pop("local_port", None)
        item.pop("ioc_normalization_kind", None)
        item.pop("ioc_normalization_warning", None)
        if detail.get("ioc_port") is not None:
            item["ioc_port"] = int(detail["ioc_port"])
        if detail.get("ioc_raw") is not None:
            item["ioc_raw"] = detail["ioc_raw"]
            raw_preserved += 1
        for structured_key in ("local_ip", "local_port", "ioc_normalization_kind"):
            if detail.get(structured_key) is not None:
                item[structured_key] = detail[structured_key]
        if detail.get("ioc_normalization_warning"):
            item["ioc_normalization_warning"] = detail["ioc_normalization_warning"]
            if detail["ioc_normalization_warning"] in {
                "invalid_port", "invalid_remote_port", "invalid_local_port"
            }:
                invalid_port += 1
        if detail.get("ioc_normalization_kind") == "connection_pair_rejected":
            connection_pair_rejected += 1
        found = item.get("found_in")
        if isinstance(found, list):
            item["found_in"] = sorted(set(str(x) for x in found))
        elif found is None:
            item["found_in"] = []
        else:
            item["found_in"] = [str(found)]
        key = (
            str(item.get("ioc", "")), item.get("ioc_port"),
            item.get("local_ip"), item.get("local_port"),
            tuple(item.get("found_in", [])), str(item.get("significance", "")),
            str(item.get("category", "")),
        )
        if key in seen:
            deduplicated += 1
            continue
        seen.add(key)
        normalized.append(item)
    result["correlated_iocs"] = normalized
    result["_ioc_normalization"] = {
        "input_count": len(values),
        "output_count": len(normalized),
        "normalized_count": changed,
        "deduplicated_count": deduplicated,
        "dropped_empty_count": dropped_empty,
        "invalid_port_count": invalid_port,
        "raw_preserved_count": raw_preserved,
        "connection_pair_rejected_count": connection_pair_rejected,
    }
    return changed


def _compact_retry_user_message(data_text: str) -> str:
    return f"""# 横断相関 compact retry
前回応答はJSON途中切断またはJSON解析失敗でした。以下の証拠だけを使用し、
必ず単一の完結したJSONオブジェクトのみを返してください。
説明文、コードフェンス、前置きは禁止です。

目標件数（完結したJSONを最優先）:
- infection_summary: 180文字以内
- correlated_iocs: 最大12件。HIGH根拠を優先
- timeline: 最大12件
- mitre_ttps: 最大8件
- recommended_actions: 最大5件
- 不明な値は空配列または Unknown

出力schema:
{{
  "infection_suspicion": "HIGH|MEDIUM|LOW|NONE",
  "infection_summary": "短い要約",
  "malware_family": "Unknown または推定名",
  "correlated_iocs": [{{"ioc":"値","found_in":["section"],"significance":"短い根拠","category":"external_intrusion|internal_automation|internal_unclear|unclear"}}],
  "timeline": [{{"datetime":"Unknownまたは日時","event":"短い事象","evidence":"短い根拠"}}],
  "mitre_ttps": [],
  "recommended_actions": []
}}

## 証拠
{data_text}
"""


def _available_output_tokens(user_message: str, desired_max_tokens: int,
                             system_message: str | None = None) -> dict:
    """Return an auditable context allocation for one chat completion call."""
    system_message = get_system_prompt() if system_message is None else system_message
    system_tokens = est_tokens(system_message)
    user_tokens = est_tokens(user_message)
    available = (
        MAX_MODEL_LEN - TOKEN_SAFETY_MARGIN - system_tokens
        - user_tokens - CHAT_TEMPLATE_TOKENS
    )
    return {
        "system_tokens": system_tokens,
        "user_tokens": user_tokens,
        "message_overhead_tokens": CHAT_TEMPLATE_TOKENS,
        "safety_margin_tokens": TOKEN_SAFETY_MARGIN,
        "available_tokens": available,
        "desired_max_tokens": desired_max_tokens,
        "max_tokens": min(desired_max_tokens, max(0, available)),
        "estimated_total_tokens": (
            system_tokens + user_tokens + CHAT_TEMPLATE_TOKENS
            + TOKEN_SAFETY_MARGIN + min(desired_max_tokens, max(0, available))
        ),
    }


def _data_budget_for_output(user_template: str, desired_max_tokens: int,
                            system_message: str | None = None) -> int:
    """Derive evidence budget by reserving the desired output first."""
    system_message = get_system_prompt() if system_message is None else system_message
    fixed_user = user_template.replace("{data}", "")
    return (
        MAX_MODEL_LEN - TOKEN_SAFETY_MARGIN - est_tokens(system_message)
        - est_tokens(fixed_user) - CHAT_TEMPLATE_TOKENS - desired_max_tokens
    )


def _finalize_correlation(result: dict, meta: dict, depth: int,
                          analyzed_json: dict, corr_stats: dict,
                          finish_reason: str | None,
                          output_truncated: bool | None = None) -> dict:
    result["meta"] = meta
    result["depth"] = depth
    result["finish_reason"] = finish_reason
    if output_truncated is None:
        output_truncated = finish_reason == "length"
    if output_truncated:
        result["output_truncated"] = True
    _cap_correlation_output(result)
    apply_deterministic_fallback(result, analyzed_json)
    _normalize_correlation_iocs(result)
    _apply_ioc_category_fallback(result)
    _annotate_known_infra_services(result)
    input_stats = dict(corr_stats or {})
    input_stats.setdefault("superseded_by_retry", False)
    input_stats.setdefault("effective_input", "initial")
    result["_correlate_input"] = input_stats
    return result


def _fallback_result(meta: dict, depth: int, analyzed_json: dict,
                     corr_stats: dict, *, raw_response: str = "",
                     finish_reason: str | None = None,
                     llm_error: str | None = None,
                     build_error: str | None = None,
                     retry_info: dict | None = None,
                     fallback_reason: str | None = None) -> dict:
    """Return a deterministic result with machine-readable fallback metadata."""
    fallback_reason_raw = None
    if fallback_reason not in FALLBACK_REASONS:
        fallback_reason_raw = "<missing>" if fallback_reason is None else str(fallback_reason)
        print(
            "CHECKPC_CORRELATE_WARNING unknown fallback reason: "
            f"{fallback_reason_raw}; using initial_processing_error",
            file=sys.stderr,
        )
        fallback_reason = "initial_processing_error"
    result = {
        "meta": meta, "depth": depth,
        "raw_response": (raw_response or "")[:200000],
        "parse_error": True,
        "finish_reason": finish_reason,
    }
    if llm_error:
        result["llm_error"] = llm_error
    if build_error:
        result["correlate_build_error"] = build_error
    info = dict(retry_info or {})
    info.setdefault("attempted", False)
    info.setdefault("succeeded", False)
    info["fallback_applied"] = True
    # The validated reason is authoritative. retry_info is diagnostic input and
    # must not be able to reintroduce an unknown reason into the final safety net.
    info["fallback_reason"] = fallback_reason
    if fallback_reason_raw is not None:
        info["fallback_reason_raw"] = fallback_reason_raw
    else:
        # Remove stale/untrusted raw metadata supplied by retry_info when the
        # authoritative reason is already a known vocabulary value.
        info.pop("fallback_reason_raw", None)
    info.setdefault("first_finish_reason", finish_reason)
    info.setdefault("retry_finish_reason", None)
    info["first_truncated"] = info.get("first_finish_reason") == "length"
    info["retry_truncated"] = info.get("retry_finish_reason") == "length"
    info["truncated_twice"] = bool(
        info["first_truncated"] and info["retry_truncated"]
    )
    result["_correlate_retry"] = info
    apply_deterministic_fallback(result, analyzed_json)
    input_stats = dict(corr_stats or {})
    input_stats["superseded_by_retry"] = False
    input_stats["effective_input"] = "deterministic_fallback"
    result["_correlate_input"] = input_stats
    return result


def correlate(analyzed_json: dict, depth: int,
              client: OpenAI, model: str,
              verbose: bool = False) -> dict:
    """横断相関分析を実行する。"""
    meta = analyzed_json.get("meta", {})
    hostname = meta.get("hostname", "UNKNOWN")
    print(f"[{hostname}] 横断相関分析開始 (depth={depth})")

    filtered = extract_high_medium(analyzed_json)
    desired_max_tok = {1: 2048, 2: 2048, 3: 2048, 4: 4096}.get(depth, 2048)
    prompt_template = get_prompt("correlate", depth)
    system_prompt = get_system_prompt()
    if not prompt_template:
        print(f"  [WARN] 相関プロンプト未定義 depth={depth}", file=sys.stderr)
        return {}

    budget_tokens = _data_budget_for_output(
        prompt_template, desired_max_tok, system_prompt)
    empty_stats = {
        "input_total": sum(len(x.get("entries", [])) for x in filtered.values()),
        "included": 0, "omitted": 0, "budget_tokens": budget_tokens,
    }
    if budget_tokens < 1:
        return _fallback_result(
            meta, depth, analyzed_json, empty_stats,
            build_error=f"initial data budget exhausted: {budget_tokens}",
            fallback_reason="initial_budget_exhausted")
    try:
        data_text, corr_stats = build_correlate_text(filtered, depth, budget_tokens)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        print(f"  [ERROR] 相関入力構築エラー: {error}", file=sys.stderr)
        return _fallback_result(
            meta, depth, analyzed_json, empty_stats, build_error=error,
            fallback_reason="initial_build_error")

    if not data_text.strip():
        print("  [INFO] HIGH/MEDIUM エントリなし。相関分析をスキップ。")
        return {
            "meta": meta, "depth": depth,
            "infection_suspicion": "NONE",
            "infection_summary": "HIGH/MEDIUM エントリが検出されませんでした。",
            "correlated_iocs": [], "timeline": [], "mitre_ttps": [],
            "recommended_actions": ["通常の定期監視を継続してください。"],
            "_correlate_input": corr_stats,
        }

    if verbose:
        print(f"  入力データ文字数: {len(data_text)} / "
              f"収容 {corr_stats['included']}/{corr_stats['input_total']} "
              f"(compression_level={corr_stats['compression_level']}, "
              f"high_unrepresented={corr_stats['high_unrepresented']})")

    user_msg = prompt_template.replace("{data}", data_text)
    first_allocation = _available_output_tokens(user_msg, desired_max_tok, system_prompt)
    corr_stats["token_allocation"] = first_allocation
    if first_allocation["max_tokens"] < 256:
        warning = (
            "initial available output tokens below minimum: "
            f"{first_allocation['available_tokens']}")
        print(f"  [WARN] {warning}", file=sys.stderr)
        return _fallback_result(
            meta, depth, analyzed_json, corr_stats, build_error=warning,
            fallback_reason="initial_budget_exhausted")
    if verbose:
        print(f"  推定入力: system={first_allocation['system_tokens']} "
              f"user={first_allocation['user_tokens']} overhead={CHAT_TEMPLATE_TOKENS} / "
              f"max_tokens={first_allocation['max_tokens']} "
              f"(希望値 {desired_max_tok})")

    try:
        resp = create_chat_completion(
            client, model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_msg},
            ],
            max_tokens=first_allocation["max_tokens"],
            temperature=0.0, timeout=REQUEST_TIMEOUT,
        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        print(f"  [ERROR] LLM 呼出しエラー: {error}", file=sys.stderr)
        return _fallback_result(
            meta, depth, analyzed_json, corr_stats, llm_error=error,
            fallback_reason="initial_llm_error")

    first = extract_llm_text(resp)
    first_raw = first.text or ""
    parsed = None if first.error else _parse_correlation_json(first_raw)
    if parsed is not None:
        return _finalize_correlation(
            parsed, meta, depth, analyzed_json, corr_stats,
            first.finish_reason, output_truncated=(first.finish_reason == "length"))

    retry_info = {
        "attempted": True, "succeeded": False,
        "first_finish_reason": first.finish_reason,
        "first_error": first.error,
        "first_raw_chars": len(first_raw),
        "first_truncated": first.finish_reason == "length",
        "retry_truncated": False,
        "truncated_twice": False,
        "fallback_applied": False,
    }
    retry_template = _compact_retry_user_message("{data}")
    retry_budget = _data_budget_for_output(
        retry_template, CORRELATE_RETRY_MAX_TOKENS, system_prompt)
    retry_info["retry_data_budget_tokens"] = retry_budget
    try:
        if retry_budget < 1:
            raise CorrelateBudgetExhausted(f"retry data budget exhausted: {retry_budget}")
        retry_data_text, retry_stats = build_correlate_text(
            filtered, depth, retry_budget)
        retry_info.update({
            "retry_input_total": retry_stats.get("input_total"),
            "retry_included": retry_stats.get("included"),
            "retry_compression_level": retry_stats.get("compression_level"),
            "retry_high_unrepresented": retry_stats.get("high_unrepresented"),
            "retry_input_sha256": retry_stats.get("input_sha256"),
        })
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        retry_info["retry_build_error"] = error
        reason = (
            "retry_budget_exhausted"
            if isinstance(exc, CorrelateBudgetExhausted)
            else "retry_build_error"
        )
        return _fallback_result(
            meta, depth, analyzed_json, corr_stats,
            raw_response=first_raw, finish_reason=first.finish_reason,
            llm_error=first.error, retry_info=retry_info,
            fallback_reason=reason)

    compact_msg = _compact_retry_user_message(retry_data_text)
    retry_allocation = _available_output_tokens(
        compact_msg, CORRELATE_RETRY_MAX_TOKENS, system_prompt)
    retry_info["retry_token_allocation"] = retry_allocation
    retry_info["retry_max_tokens"] = retry_allocation["max_tokens"]
    if retry_allocation["max_tokens"] < 256:
        retry_info["retry_build_error"] = (
            "retry available output tokens below minimum: "
            f"{retry_allocation['available_tokens']}")
        return _fallback_result(
            meta, depth, analyzed_json, corr_stats,
            raw_response=first_raw, finish_reason=first.finish_reason,
            llm_error=first.error, retry_info=retry_info,
            fallback_reason="retry_budget_exhausted")

    second_raw = ""
    second_finish = None
    second_error = None
    try:
        resp2 = create_chat_completion(
            client, model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": compact_msg},
            ],
            max_tokens=retry_allocation["max_tokens"],
            temperature=0.0, timeout=REQUEST_TIMEOUT,
        )
        second = extract_llm_text(resp2)
        second_raw = second.text or ""
        second_finish = second.finish_reason
        second_error = second.error
        parsed2 = None if second.error else _parse_correlation_json(second_raw)
        retry_info.update({
            "retry_finish_reason": second_finish,
            "retry_error": second_error,
            "retry_raw_chars": len(second_raw),
            "retry_truncated": second_finish == "length",
            "truncated_twice": bool(
                first.finish_reason == "length" and second_finish == "length"
            ),
        })
        if parsed2 is not None:
            retry_info["succeeded"] = True
            result = _finalize_correlation(
                parsed2, meta, depth, analyzed_json, corr_stats, second_finish,
                output_truncated=(second_finish == "length"))
            result["_correlate_retry"] = retry_info
            result["_correlate_input"]["superseded_by_retry"] = True
            result["_correlate_input"]["effective_input"] = "retry"
            return result
    except Exception as exc:
        second_error = f"{type(exc).__name__}: {exc}"

    retry_info.update({
        "succeeded": False,
        "retry_finish_reason": second_finish,
        "retry_error": second_error,
        "retry_raw_chars": len(second_raw),
        "retry_truncated": second_finish == "length",
        "truncated_twice": bool(
            first.finish_reason == "length" and second_finish == "length"
        ),
    })
    return _fallback_result(
        meta, depth, analyzed_json, corr_stats,
        raw_response=(second_raw or first_raw),
        finish_reason=(second_finish or first.finish_reason),
        llm_error=(second_error or first.error), retry_info=retry_info,
        fallback_reason=(
            "retry_llm_error" if second_error else
            "retry_truncated_invalid_json" if second_finish == "length" else
            "retry_parse_error"
        ))


def main():
    ap = argparse.ArgumentParser(
        description="analyze_section.py の出力 JSON を横断相関分析する"
    )
    ap.add_argument("input",          help="analyze_section.py の出力 JSON パス")
    ap.add_argument("--depth",   "-d", type=int, default=DEFAULT_DEPTH,
                    choices=[1, 2, 3, 4])
    ap.add_argument("--experimental-depths", action="store_true",
                    help="depth 3/4 の試験実行を許可する")
    ap.add_argument("--output",  "-o", help="出力 JSON ファイルパス（省略時は自動命名）")
    ap.add_argument("--vllm-url",     default=DEFAULT_VLLM_URL)
    ap.add_argument("--model",   "-m", default=DEFAULT_MODEL)
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()
    if args.depth >= 3 and not args.experimental_depths:
        ap.error("depth 3/4 は試験機能です。--experimental-depths を明示してください。")

    if not os.path.exists(args.input):
        print(f"[ERROR] ファイルが見つかりません: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input, encoding="utf-8") as f:
        analyzed = json.load(f)

    client = OpenAI(base_url=args.vllm_url, api_key="dummy")

    start  = time.time()
    result = correlate(analyzed, args.depth, client, args.model, args.verbose)
    elapsed = time.time() - start
    print(f"横断相関完了 ({elapsed:.1f} 秒)")

    if args.output:
        out_path = args.output
    else:
        base = os.path.basename(args.input).replace("analyzed_", "correlation_")
        out_path = os.path.join(os.path.dirname(args.input), base)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"出力: {out_path}")

    # 結果サマリ
    suspicion = result.get("infection_suspicion", "N/A")
    summary   = result.get("infection_summary",   "")
    family    = result.get("malware_family",       "Unknown")
    ioc_count = len(result.get("correlated_iocs", []))
    print(f"\n  感染嫌疑: {suspicion}")
    print(f"  推定ファミリー: {family}")
    print(f"  相関 IOC 数: {ioc_count}")
    if summary:
        print(f"  サマリ: {summary}")


if __name__ == "__main__":
    main()
