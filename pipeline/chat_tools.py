#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CheckPC 解析結果チャット機能 — ツール定義・実行ロジック

方針:
  · Lv.1（読み取り専用）: 既存の analyzed_*.json / correlation_*.json /
    タイムライン出力を参照するのみ。外部通信・副作用なし。常時利用可能。
  · Lv.2（実行系）: 案件内横断検索と許可IOCのVirusTotal追加照会。
    案件単位policyとサーバ全体kill switchの双方で許可された場合だけ利用可能。
    VT値は現在の分析官入力または現在ジョブのIOC欄へグラウンディングし、
    セッションあたりの個別呼び出し回数上限を設ける（既定20回）。
  · 全ツール呼び出しは監査ログ（chat_tool_log.jsonl）に記録する。
  · ツール結果は境界トークンを中和して非信頼データ境界内でLLMへ返し、
    巨大なJSONは呼び出し側でトリミングする。

本モジュールは vLLM 等への実際の接続を持たない。呼び出し側
（server.py）が OpenAI 互換クライアントを渡し、run_chat_turn が
tool-calling ループを回す。単体テストではスタブクライアントを注入して
ネットワーク不要で検証できる。
"""
import bisect
import copy
import json
import os
import re
import sys
import threading
import time
from collections import deque
from pathlib import Path

import directory_index
from chat_investigation import InvestigationEngine
from llm_runtime import create_chat_completion, extract_llm_message, extract_llm_text
from prompt_safety import wrap_untrusted_tool_result
from typing import Optional

from chat_lv2 import (
    CROSS_HOST_TOOL_NAME,
    LV2_POLICY_LOCAL_VT_IOC,
    LV2_POLICY_OFF,
    VT_TOOL_NAME,
    allowed_lv2_tools,
    extract_vt_iocs_from_text,
    normalize_policy,
    redact_object,
    redact_text,
    secure_vt_lookup,
    validate_vt_ioc,
)

# vLLM/ChatML系テンプレートの特殊トークンが、tool-calling往復後の応答等で
# ごく稀に content にそのまま混入することがある（hermesパーサ経由でない
# プレーンテキスト応答時に stop 文字列として登録し損ねるケース等）。
# 表示前に念のため除去する（取りこぼし防止のため広めに列挙）。
_SPECIAL_TOKEN_RE = re.compile(
    r"<\|(?:im_end|im_start|endoftext|end_of_text|eot_id)\|>"
)

def _sanitize_reply(text: str) -> str:
    if not text:
        return text
    return _SPECIAL_TOKEN_RE.sub("", text).strip()


_EXTERNAL_TI_MARKER_PATTERN = (
    r"(?:virus\s*total|(?<![A-Za-z0-9])VT(?![A-Za-z0-9])|"
    r"外部(?:TI|照会|評価)|脅威インテリジェンス|threat\s+intelligence)"
)

# rc13: external-TI authorization is bound to the IOC operand captured by an
# explicitly affirmative external lookup grammar.  We no longer authorize all
# IOC tokens merely because they occur in the same clause/directive.  If a
# target cannot be bound unambiguously, authorization fails closed.
_VT_IOC_TOKEN_ATOM = (
    r"(?<![A-Za-z0-9_.:@/\\-])"
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,511}"
    r"(?![A-Za-z0-9_.:@/\\-])"
)
_VT_IOC_TOKEN_CAPTURE = rf"({_VT_IOC_TOKEN_ATOM})"
# Multi-IOC lists are authorized only when the list itself is the operand of
# the external lookup grammar.  English ``and`` requires whitespace so an FQDN
# such as ``foo-and-bar.com`` is never split as an IOC list.
_VT_IOC_JP_LIST_CAPTURE = rf"({_VT_IOC_TOKEN_ATOM}(?:\s*(?:と|、|,)\s*{_VT_IOC_TOKEN_ATOM}){{1,7}})"
_VT_IOC_EN_LIST_CAPTURE = rf"({_VT_IOC_TOKEN_ATOM}(?:(?:\s+and\s+|\s*,\s*){_VT_IOC_TOKEN_ATOM}){{1,7}})"

_EXTERNAL_TI_JP_ACTION = (
    r"(?:"
    r"調べて(?:ください)?"
    r"|照会して(?:ください)?"
    r"|検索して(?:ください)?"
    r"|確認して(?:ください)?"
    r"|評価して(?:ください)?"
    r"|問い合わせて(?:ください)?"
    r"|問合せして(?:ください)?"
    r"|チェックして(?:ください)?"
    r"|照会|検索|確認|評価|問合せ|チェック"
    r")"
)
_EXTERNAL_TI_JP_CONNECTOR = (
    r"(?:"
    r"で(?!は|なく|ない)"
    r"|に(?!ついて|関して|対して)"
    r"|を\s*(?:使って|用いて|利用して)"
    r")"
)

# ``IOCをVTで確認`` / ``IOCはVirusTotalで調べて``.
_EXTERNAL_TI_JP_TARGET_FIRST_RE = re.compile(
    rf"{_VT_IOC_TOKEN_CAPTURE}\s*(?:を|は)?\s*"
    rf"{_EXTERNAL_TI_MARKER_PATTERN}\s*{_EXTERNAL_TI_JP_CONNECTOR}\s*"
    rf"{_EXTERNAL_TI_JP_ACTION}",
    re.IGNORECASE,
)
_EXTERNAL_TI_JP_TARGET_LIST_RE = re.compile(
    rf"{_VT_IOC_JP_LIST_CAPTURE}\s*(?:を|は)?\s*"
    rf"{_EXTERNAL_TI_MARKER_PATTERN}\s*{_EXTERNAL_TI_JP_CONNECTOR}\s*"
    rf"{_EXTERNAL_TI_JP_ACTION}",
    re.IGNORECASE,
)
# ``VTでIOCを確認`` / ``VirusTotalにIOCを問い合わせて``.
_EXTERNAL_TI_JP_MARKER_FIRST_RE = re.compile(
    rf"{_EXTERNAL_TI_MARKER_PATTERN}\s*{_EXTERNAL_TI_JP_CONNECTOR}\s*"
    rf"(?:(?:接続先|IOC|IP|FQDN|ドメイン|ハッシュ|hash)\s*)?"
    rf"{_VT_IOC_TOKEN_CAPTURE}\s*(?:を|について)?\s*{_EXTERNAL_TI_JP_ACTION}",
    re.IGNORECASE,
)
_EXTERNAL_TI_JP_MARKER_LIST_RE = re.compile(
    rf"{_EXTERNAL_TI_MARKER_PATTERN}\s*{_EXTERNAL_TI_JP_CONNECTOR}\s*"
    rf"(?:(?:接続先|IOC|IP|FQDN|ドメイン|ハッシュ|hash)\s*)?"
    rf"{_VT_IOC_JP_LIST_CAPTURE}\s*(?:を|について)?\s*{_EXTERNAL_TI_JP_ACTION}",
    re.IGNORECASE,
)

# A positive-looking Japanese action is rejected when the same directive
# immediately continues into a negative construction.  This is deliberately
# local to the captured external directive rather than a message-wide denylist.
_EXTERNAL_TI_JP_NEGATIVE_SUFFIX_RE = re.compile(
    r"^\s*(?:"
    r"はいけない|はならない|"
    r"し(?:ない|ません|なくて(?:いい|よい|良い|構わない))|"
    r"(?:は|が)?不要|"
    r"する必要は(?:ない|ありません|無い)|必要は(?:ない|ありません|無い)|"
    r"するつもりは(?:ない|ありません)|べきではない|しないで|するな|は禁止"
    r")",
    re.IGNORECASE,
)

_EXTERNAL_TI_EN_BASE_ACTION = r"(?:check|look\s*up|lookup|query|search)"
_EXTERNAL_TI_EN_GERUND_ACTION = r"(?:checking|looking\s*up|querying|searching)"
_EXTERNAL_TI_EN_ACTION = rf"(?:{_EXTERNAL_TI_EN_BASE_ACTION}|{_EXTERNAL_TI_EN_GERUND_ACTION})"
_EXTERNAL_TI_EN_CONNECTOR = r"(?:with|on|via|using)"

# ``check IOC with VirusTotal`` / ``look up IOC on VT``.
_EXTERNAL_TI_EN_TARGET_FIRST_RE = re.compile(
    rf"(?:please\s+)?{_EXTERNAL_TI_EN_ACTION}\s+{_VT_IOC_TOKEN_CAPTURE}\s+"
    rf"{_EXTERNAL_TI_EN_CONNECTOR}\s+{_EXTERNAL_TI_MARKER_PATTERN}",
    re.IGNORECASE,
)
_EXTERNAL_TI_EN_TARGET_LIST_RE = re.compile(
    rf"(?:please\s+)?{_EXTERNAL_TI_EN_ACTION}\s+{_VT_IOC_EN_LIST_CAPTURE}\s+"
    rf"{_EXTERNAL_TI_EN_CONNECTOR}\s+{_EXTERNAL_TI_MARKER_PATTERN}",
    re.IGNORECASE,
)
# ``VirusTotal lookup IOC``.
_EXTERNAL_TI_EN_MARKER_FIRST_RE = re.compile(
    rf"{_EXTERNAL_TI_MARKER_PATTERN}\s+(?:lookup|query|search|check)\s+{_VT_IOC_TOKEN_CAPTURE}",
    re.IGNORECASE,
)
_EXTERNAL_TI_EN_MARKER_LIST_RE = re.compile(
    rf"{_EXTERNAL_TI_MARKER_PATTERN}\s+(?:lookup|query|search|check)\s+{_VT_IOC_EN_LIST_CAPTURE}",
    re.IGNORECASE,
)
# ``use VirusTotal to check IOC``.
_EXTERNAL_TI_EN_USE_RE = re.compile(
    rf"(?:please\s+)?(?:use|using)\s+{_EXTERNAL_TI_MARKER_PATTERN}\s+"
    rf"(?:to\s+)?{_EXTERNAL_TI_EN_ACTION}\s+{_VT_IOC_TOKEN_CAPTURE}",
    re.IGNORECASE,
)
_EXTERNAL_TI_EN_USE_LIST_RE = re.compile(
    rf"(?:please\s+)?(?:use|using)\s+{_EXTERNAL_TI_MARKER_PATTERN}\s+"
    rf"(?:to\s+)?{_EXTERNAL_TI_EN_ACTION}\s+{_VT_IOC_EN_LIST_CAPTURE}",
    re.IGNORECASE,
)

# Directive-local negative scope.  Prefix inspection is anchored to the action
# match and bounded; punctuation/newline boundaries stop unrelated prior text
# from suppressing a later affirmative directive.
# English external authorization is fail-closed on the *start* of the
# matched lookup directive.  We intentionally do not try to enumerate every
# possible negation word.  A positive-looking lookup substring is eligible
# only when it begins at a directive boundary or immediately after an
# explicitly allowed affirmative coordination token.  This preserves mixed
# local/external routing such as ``check A locally while checking B with VT``
# without authorizing substrings embedded in ``no need to check ...``,
# ``refrain from checking ...``, ``skip checking ...``, etc.
_EXTERNAL_TI_EN_AFFIRMATIVE_PREFIX_RE = re.compile(
    # A bare comma is not a trusted directive boundary: it commonly occurs
    # inside negative constructions (``do not, under any circumstances,``).
    # Comma coordination is accepted only when an explicit affirmative
    # coordinator follows it.
    r"(?:^|(?:\b(?:while|and|then)\s+)|(?:,\s*(?:and|then)\s+))$",
    re.IGNORECASE,
)
_EXTERNAL_TI_EN_NEGATIVE_SUFFIX_RE = re.compile(
    r"^\s*(?:"
    r"(?:is|are)?\s*not\s+(?:necessary|required|needed)|"
    r"(?:isn't|aren't)\s+(?:necessary|required|needed)|"
    r"(?:is|are)\s+unnecessary"
    r")",
    re.IGNORECASE,
)


def _valid_external_ioc_capture(value: str) -> str | None:
    valid, payload = validate_vt_ioc(value)
    if not valid:
        return None
    return str(payload["ioc"]).lower()


def _directive_prefix(message: str, start: int, max_chars: int = 96) -> str:
    """Return bounded text in the same directive immediately before *start*."""
    left = max(0, start - max_chars)
    chunk = str(message[left:start])
    # Security is fail-closed inside one directive, but a completed prior
    # sentence/directive must not suppress a later explicit positive request.
    cut = max(chunk.rfind(x) for x in ("。", "！", "？", ";", "\n", ".", "!", "?"))
    return chunk[cut + 1:] if cut >= 0 else chunk


def _directive_suffix(message: str, end: int, max_chars: int = 80) -> str:
    """Return bounded text in the same directive immediately after *end*."""
    chunk = str(message[end:end + max_chars])
    stops = [i for x in ("。", "！", "？", ";", "\n", ".", "!", "?") if (i := chunk.find(x)) >= 0]
    return chunk[:min(stops)] if stops else chunk


# Japanese authorization also fails closed on the action's *end*.  A bare
# positive-looking action token (e.g. ``確認`` / ``調べて``) is not sufficient
# if the same directive continues with arbitrary text.  This prevents partial
# matches inside ``確認するのはやめて`` / ``調べてほしくない`` without
# growing an unbounded negation vocabulary.  We only permit a recognized next
# directive when it begins with ``そして`` or an IOC explicitly routed to a
# local/external destination.
_EXTERNAL_TI_JP_SAFE_CONTINUATION_RE = re.compile(
    rf"^\s*(?:"
    rf"そして\s*"
    rf"|{_VT_IOC_TOKEN_ATOM}\s*(?:を|は)?\s*"
    rf"(?:ローカル|local|端末内|案件内|virus\s*total|VT|外部TI)"
    rf")",
    re.IGNORECASE,
)


def _japanese_match_has_affirmative_directive_end(message: str, match: re.Match) -> bool:
    """Fail closed unless the Japanese lookup action completes a directive.

    Do not reuse ``_directive_suffix`` here: its ASCII period boundary is useful
    for English sentences but would split a following IPv4 IOC (``8.8.8.8``)
    and break safe mixed routing.  Only hard Japanese/sentence separators bound
    this local suffix inspection.
    """
    after = str(message[match.end():match.end() + 160])
    stops = [i for x in ("。", "！", "？", ";", "\n", "!", "?") if (i := after.find(x)) >= 0]
    if stops:
        after = after[:min(stops)]
    if not after.strip():
        return True
    if _EXTERNAL_TI_JP_NEGATIVE_SUFFIX_RE.search(after):
        return False
    return bool(_EXTERNAL_TI_JP_SAFE_CONTINUATION_RE.match(after))


def _english_match_has_affirmative_directive_start(message: str, match: re.Match) -> bool:
    """Fail-closed English authorization on the match's directive start.

    The regex patterns may find a positive-looking substring anywhere in a
    sentence.  Authorization is allowed only when that substring starts at a
    directive boundary, or follows an explicitly allowed positive
    coordination token.  Arbitrary natural-language prefixes are rejected
    rather than interpreted by a growing negation denylist.
    """
    before = _directive_prefix(message, match.start(), max_chars=192)
    if not before.strip():
        return True
    return bool(_EXTERNAL_TI_EN_AFFIRMATIVE_PREFIX_RE.search(before))


def _match_is_negated(message: str, match: re.Match, *, japanese: bool) -> bool:
    """Return True when the captured external directive is not authorizable."""
    after = _directive_suffix(message, match.end())
    if japanese:
        return not _japanese_match_has_affirmative_directive_end(message, match)
    if not _english_match_has_affirmative_directive_start(message, match):
        return True
    return bool(_EXTERNAL_TI_EN_NEGATIVE_SUFFIX_RE.search(after))


def _authorized_iocs_from_capture(value: str, *, multi: bool) -> set[str]:
    if not multi:
        candidate = _valid_external_ioc_capture(value)
        return {candidate} if candidate else set()
    # The captured substring is itself the operand of the external lookup
    # grammar, so every validated IOC inside that bounded operand is authorized.
    return {str(x).lower() for x in extract_vt_iocs_from_text(value)}


def _extract_explicit_external_ti_iocs(message: str) -> set[str]:
    """Return IOC values directly bound to non-negated external-TI directives.

    Authorization is grammar-bound, not clause-bound.  Local/context IOC tokens
    elsewhere in the same sentence are never authorized by co-occurrence.  An
    explicitly listed multi-IOC operand may authorize multiple IOCs because the
    list itself is directly bound to the external lookup grammar.
    """
    text = str(message or "")
    authorized: set[str] = set()
    patterns = (
        (_EXTERNAL_TI_JP_TARGET_LIST_RE, True, True),
        (_EXTERNAL_TI_JP_MARKER_LIST_RE, True, True),
        (_EXTERNAL_TI_EN_TARGET_LIST_RE, False, True),
        (_EXTERNAL_TI_EN_MARKER_LIST_RE, False, True),
        (_EXTERNAL_TI_EN_USE_LIST_RE, False, True),
        (_EXTERNAL_TI_JP_TARGET_FIRST_RE, True, False),
        (_EXTERNAL_TI_JP_MARKER_FIRST_RE, True, False),
        (_EXTERNAL_TI_EN_TARGET_FIRST_RE, False, False),
        (_EXTERNAL_TI_EN_MARKER_FIRST_RE, False, False),
        (_EXTERNAL_TI_EN_USE_RE, False, False),
    )
    for pattern, japanese, multi in patterns:
        for match in pattern.finditer(text):
            if _match_is_negated(text, match, japanese=japanese):
                continue
            authorized.update(_authorized_iocs_from_capture(match.group(1), multi=multi))
    return authorized


def _is_explicit_external_ti_lookup_request(message: str) -> bool:
    """Compatibility boolean: true iff this turn authorizes at least one IOC."""
    return bool(_extract_explicit_external_ti_iocs(message))


# ── 安全機構パラメータ ─────────────────────────────────────────
LV2_MAX_CALLS_PER_SESSION = int(os.environ.get("CHAT_LV2_MAX_CALLS", "20"))
CROSS_HOST_MAX_HITS = int(os.environ.get("CHAT_CROSS_HOST_MAX_HITS", "50"))
CROSS_HOST_CURRENT_MAX_HITS = int(os.environ.get("CHAT_CROSS_HOST_CURRENT_MAX_HITS", "20"))
CROSS_HOST_MAX_FILE_MB = int(os.environ.get("CHAT_CROSS_HOST_MAX_FILE_MB", "20"))
CROSS_HOST_MAX_TOTAL_MB = int(os.environ.get("CHAT_CROSS_HOST_MAX_TOTAL_MB", "200"))
CROSS_HOST_MAX_JOBS = int(os.environ.get("CHAT_CROSS_HOST_MAX_JOBS", "200"))
CROSS_HOST_MAX_FILES = int(os.environ.get("CHAT_CROSS_HOST_MAX_FILES", "400"))
CROSS_HOST_TIMEOUT_SEC = float(os.environ.get("CHAT_CROSS_HOST_TIMEOUT_SEC", "8"))
CHAT_MAX_TOOL_CALLS_PER_TURN = int(os.environ.get("CHAT_MAX_TOOL_CALLS_PER_TURN", "3"))
TOOL_RESULT_MAX_CHARS = 3000
# vLLMのmax_model_len(既定16384トークン)に対する安全マージン。
# 日本語混じりの内容はトークン密度が高くなりがちなため、保守的に
# 1トークン≒1.5文字と仮定して見積もる（実測が無い前提での安全側の値）。
CHAT_CONTEXT_CHAR_BUDGET = int(os.environ.get("CHAT_CONTEXT_CHAR_BUDGET", "18000"))
AUDIT_FALLBACK_MAX_RECORDS = max(1, int(os.environ.get("CHAT_AUDIT_FALLBACK_MAX_RECORDS", "256")))

_AUDIT_FALLBACK_LOCK = threading.Lock()
_AUDIT_FALLBACK_BUFFER = deque(maxlen=AUDIT_FALLBACK_MAX_RECORDS)

# サンプリングパラメータ（反復・自問自答対策）。
# GGUF量子化＋vLLMの組み合わせでは、モデルが同じ内容を繰り返したり
# 自問自答を続けたりする既知の不安定性が報告されている
# （vLLM公式GitHub Issue #10600等）。低温度・反復ペナルティで
# 緩和を試みる。根本解決ではなく緩和策である点に留意（実機未検証）。
CHAT_TEMPERATURE = float(os.environ.get("CHAT_TEMPERATURE", "0.3"))
CHAT_REPETITION_PENALTY = float(os.environ.get("CHAT_REPETITION_PENALTY", "1.15"))

# v3.71: 回答深度モードはUIから廃止。旧API互換のmode値は受理するが、
# 証拠取得能力・tool budgetは常に同一とする。通常1～2 round、hard max 3。
CHAT_MODE_MAX_ITERATIONS = {
    "simple": int(os.environ.get("CHAT_MAX_TOOL_ITERATIONS", "3")),
    "standard": int(os.environ.get("CHAT_MAX_TOOL_ITERATIONS", "3")),
    "detailed": int(os.environ.get("CHAT_MAX_TOOL_ITERATIONS", "3")),
}
CHAT_DEFAULT_MODE = "standard"


def _authoritative_answer_facts_note(result) -> Optional[str]:
    """Return a transient control note for deterministic Python aggregates.

    Tool evidence remains untrusted.  Only bounded numeric aggregation metadata
    generated by the local investigation engine is promoted into this control
    note.  Raw evidence values/hostnames are never copied into the note.
    """
    if not isinstance(result, dict):
        return None
    facts = result.get("answer_facts")
    if not isinstance(facts, dict) or facts.get("authoritative") is not True:
        return None
    count = facts.get("matched_host_count")
    searchable = facts.get("searchable_host_count")
    case_count = facts.get("case_host_count")
    if not isinstance(count, int) or not isinstance(searchable, int):
        return None
    case_text = str(case_count) if isinstance(case_count, int) else "unknown"
    return (
        "（システム注記: Pythonが決定論的に集計したauthoritative answer_factsがあります。"
        f" matched_host_count={count}, searchable_host_count={searchable}, case_host_count={case_text},"
        " coverage_complete=true。個別hitsを数え直さずmatched_host_countを件数回答に使用してください。"
        " ホスト名列挙を求められている場合はtool result先頭のanswer_facts.matched_hostnamesを使用し、"
        " 表示途中で切り詰められたverbose hitsだけから再構成しないでください。"
        " 追加ツール調査は行わず、この確定集計に基づいて簡潔に回答してください）"
    )


# ── OpenAI Function Calling 形式のツール定義 ───────────────────
# v3.71: LLMにはThreat Intelligence調査上の意味が明確な2系統だけを公開する。
# 旧handlerは後方互換のため内部に残すが、schemaには公開しない。
INVESTIGATE_TOOL_NAME = "investigate_local"

LOCAL_INVESTIGATION_TOOL = {
    "type": "function",
    "function": {
        "name": INVESTIGATE_TOOL_NAME,
        "description": (
            "CheckPCのローカル証拠を調査する唯一のlocal tool。外部通信は行わない。"
            "action=searchはIOC・hostname・ファイル名/パス・service・task・registry・process・"
            "任意keywordをcurrent hostと同一案件folderへ決定論的にmulti-label検索する。"
            "action=summaryはcorrelation artifactだけを使うfast pathで、案件/ホストのTI向け概要・infection_suspicion分布・correlated IOC prevalenceを返す。"
            "action=timelineは指定queryの時系列上の観測文脈を返す。"
            "raw/analyzed/correlation、current/case scope、mixed-version差はPython側で処理する。"
            "ファイル名・拡張子・絶対pathのsearchではcurrent hostのraw directoryをcore indexより先に自動確認する。"
            "単純拡張子glob（例: *.lnk）はPython側で拡張子検索へ正規化する。"
            "exact hostnameはcorrelation fast pathで検索し、cold core indexを不要にする。"
            "coverage_complete=falseまたはunavailableがある場合、非hitを案件全体の不存在と断定しないこと。summaryでcorrelation coverageが不完全な場合、案件全体の確定countはnullでobserved_*だけが返る。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["search", "summary", "timeline"],
                    "description": "search / summary / timeline",
                },
                "query": {
                    "type": "string",
                    "description": "search/timelineの検索対象。summaryでは不要。分析官の語を改変せず渡す。",
                },
                "limit": {
                    "type": "integer",
                    "description": "返却上限。省略可。Python側hard capあり。",
                },
            },
            "required": ["action"],
        },
    },
}

EXTERNAL_TI_TOOL = {
    "type": "function",
    "function": {
        "name": VT_TOOL_NAME,
        "description": (
            "分析官が現在の発言でVirusTotal/外部TI/レピュテーション等の外部照会を明示的に要求した場合だけ、"
            "その発言に明示されたMD5/SHA-1/SHA-256、外部IP、FQDNをVirusTotalへ照会する。"
            "URL、file path、filename、email、private IP、local調査で発見しただけのIOCは送信しない。"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ioc_value": {
                    "type": "string",
                    "description": "現在の分析官発言に明示されたhash、外部IP、またはFQDN",
                }
            },
            "required": ["ioc_value"],
        },
    },
}


def build_tool_schema(lv2_enabled: bool = False, *, lv2_policy: Optional[str] = None,
                      local_enabled: bool = True, vt_enabled: bool = True) -> list:
    """Build the public v3.71 tool schema.

    Local investigation is a normal read-only capability and is independent of
    the legacy Lv.2 policy.  The legacy policy only controls whether the explicit
    external VirusTotal tool is exposed.
    """
    tools = [LOCAL_INVESTIGATION_TOOL] if local_enabled else []
    policy = normalize_policy(
        lv2_policy if lv2_policy is not None else
        (LV2_POLICY_LOCAL_VT_IOC if lv2_enabled else LV2_POLICY_OFF)
    )
    allowed = allowed_lv2_tools(policy, local_enabled=local_enabled, vt_enabled=vt_enabled)
    if VT_TOOL_NAME in allowed:
        tools.append(EXTERNAL_TI_TOOL)
    return tools


# ── チャットセッションのコンテキスト ───────────────────────────
class ChatContext:
    """1ジョブ分のチャットセッションが参照するデータと状態を保持する。"""

    def __init__(self, job_output_dir, jobs_dir, vt_key: str = "", *,
                 job_id: str = "", case_folder: str = "", jobs_metadata=None,
                 lv2_policy: str = LV2_POLICY_OFF, vt_proxy: str = "",
                 vt_rate_delay: float = 0.0, vt_timeout: float = 30.0,
                 vt_cache_ttl: float = 86400.0, vt_cache_max_entries: int = 2048,
                 vt_retry_429_max_seconds: float = 60.0):
        self.output_dir = Path(job_output_dir)
        self.jobs_dir = Path(jobs_dir)
        self.vt_key = vt_key
        self.vt_proxy = vt_proxy
        self.vt_rate_delay = max(0.0, float(vt_rate_delay))
        self.vt_timeout = max(1.0, float(vt_timeout))
        self.vt_cache_ttl = max(0.0, float(vt_cache_ttl))
        self.vt_cache_max_entries = max(0, int(vt_cache_max_entries))
        self.vt_retry_429_max_seconds = max(0.0, float(vt_retry_429_max_seconds))
        self.job_id = str(job_id or "")
        self.case_folder = str(case_folder or "").strip()
        self.jobs_metadata = jobs_metadata
        self.lv2_policy = normalize_policy(lv2_policy)
        self._analyzed: Optional[dict] = None
        self._correlation: Optional[dict] = None
        # v3.57: list_directory_files用。parsed_*.json（LLM評価前の生directory
        # 全件データ）は directory が数百万件規模になり得るため、フォルダ検索用の
        # ソート済みインデックスとして遅延構築・キャッシュする（毎回全件走査しない）。
        self._parsed: Optional[dict] = None  # compatibility only; raw chat uses SQLite index
        self._parsed_path: Optional[Path] = None
        self._directory_index_path: Optional[Path] = None
        self._dir_sorted_keys: Optional[list] = None
        self._dir_sorted_entries: Optional[list] = None
        self._dir_name_keys: Optional[list] = None
        self._dir_name_entries: Optional[list] = None
        self._dir_keyword_cache: dict[str, dict] = {}
        self.lv2_call_count = 0
        self.current_user_message = ""
        self._authorized_vt_iocs: Optional[set[str]] = None

    def update_scope(self, *, job_id: str = "", case_folder: str = "",
                     jobs_metadata=None, lv2_policy: Optional[str] = None) -> None:
        """Cached contextを維持したまま案件境界とポリシーだけを最新化する。"""
        if job_id:
            self.job_id = str(job_id)
        self.case_folder = str(case_folder or "").strip()
        if jobs_metadata is not None:
            self.jobs_metadata = jobs_metadata
        if lv2_policy is not None:
            self.lv2_policy = normalize_policy(lv2_policy)

    def redact(self, value: object) -> object:
        return redact_object(value, api_key=self.vt_key, proxy_url=self.vt_proxy)

    def redact_error(self, value: object) -> str:
        return redact_text(value, api_key=self.vt_key, proxy_url=self.vt_proxy)

    # --- データ読み込み（遅延・キャッシュ） ---
    def _load_analyzed(self) -> dict:
        if self._analyzed is None:
            # run_dir未保存の古いジョブ(output_dirが外側コンテナのまま)にも
            # 対応できるよう再帰的に探索する
            cands = sorted(self.output_dir.rglob("analyzed_*_vt.json")) \
                or sorted(self.output_dir.rglob("analyzed_*.json"))
            if not cands:
                raise FileNotFoundError("analyzed_*.json が見つかりません")
            self._analyzed = json.loads(cands[0].read_text(encoding="utf-8"))
        return self._analyzed

    def _load_correlation(self) -> dict:
        if self._correlation is None:
            cands = sorted(self.output_dir.rglob("correlation_*_vt.json")) \
                or sorted(self.output_dir.rglob("correlation_*.json"))
            self._correlation = json.loads(cands[0].read_text(encoding="utf-8")) if cands else {}
        return self._correlation

    def _find_parsed_path(self) -> Path:
        if self._parsed_path is None:
            cands = sorted(self.output_dir.rglob("parsed_*.json"))
            if not cands:
                raise FileNotFoundError("parsed_*.json が見つかりません")
            self._parsed_path = cands[0]
        return self._parsed_path

    def _ensure_directory_index(self) -> Path:
        """Return the persistent low-memory raw-directory index."""
        parsed_path = self._find_parsed_path()
        if self._directory_index_path is None:
            self._directory_index_path = directory_index.build_directory_index(parsed_path)
        return self._directory_index_path

    @staticmethod
    def _raw_directory_hit(entry: dict) -> dict:
        return {
            "section": "directory_raw",
            "identifier": entry.get("path") or entry.get("name"),
            "score": None,
            "reason": "parsed directory raw evidence（LLM個別評価前）",
            "iocs": [entry.get("path")] if entry.get("path") else [],
            "date": entry.get("date", ""),
            "size": entry.get("size", ""),
            "name": entry.get("name", ""),
            "dir": entry.get("dir", ""),
            "source_id": entry.get("source_id", ""),
            "evaluation_status": "raw_evidence_not_present_in_analyzed_search",
        }

    def _search_raw_directory_keyword(self, keyword: str, max_results: int = 200) -> dict:
        needle = str(keyword or "").strip()
        if not needle:
            return {"total": 0, "hits": [], "truncated": False}
        cache_key = (needle.casefold(), int(max_results or 200))
        if cache_key in self._dir_keyword_cache:
            return copy.deepcopy(self._dir_keyword_cache[cache_key])
        index_path = self._ensure_directory_index()
        raw = directory_index.search_keyword(index_path, needle, max_results=max_results)
        result = {
            "scope": "parsed_directory_raw_index",
            "total": raw["total"],
            "truncated": raw["truncated"],
            "source_file": self._find_parsed_path().name,
            "index_file": index_path.name,
            "hits": [self._raw_directory_hit(entry) for entry in raw["hits"]],
        }
        self._dir_keyword_cache[cache_key] = copy.deepcopy(result)
        return result

    def directory_coverage_summary(self) -> dict:
        try:
            analyzed = self._load_analyzed()
        except Exception:
            return {}
        section = (analyzed.get("sections", {}) or {}).get("directory", {})
        if not isinstance(section, dict):
            return {}
        policy = section.get("_directory_policy") or section.get("directory_policy") or {}
        if not isinstance(policy, dict):
            return {}
        tier_total = policy.get("tier_total") or {}
        tier_selected = policy.get("tier_selected") or {}
        total = sum(int(v or 0) for v in tier_total.values())
        selected = sum(int(v or 0) for v in tier_selected.values())
        return {
            "coverage_degraded": bool(policy.get("coverage_degraded") or total > selected),
            "candidate_count": total,
            "llm_evaluated_count": selected,
            "not_individually_evaluated_count": max(0, total - selected),
            "tier_total": tier_total,
            "tier_selected": tier_selected,
            "deferred_reason_counts": policy.get("deferred_reason_counts") or {},
        }

    def correlation_summary(self) -> dict:
        """Legacy lightweight host summary. v3.71 no longer injects it into system prompt."""
        c = self._load_correlation()
        return {
            "infection_suspicion": c.get("infection_suspicion"),
            "malware_family": c.get("malware_family"),
            "summary": c.get("summary") or c.get("infection_summary"),
            "directory_coverage": self.directory_coverage_summary(),
        }

    def tool_investigate_local(self, action: str, query: str = "", limit: int = 50) -> dict:
        """Run the v3.71 deterministic local Threat Intelligence investigation engine."""
        snapshot = self._jobs_snapshot()
        effective_job_id = self._effective_job_id(snapshot)
        current_meta = snapshot.get(effective_job_id, {})
        folder = self.case_folder or str(current_meta.get("folder") or "").strip()
        engine = InvestigationEngine(
            jobs_dir=self.jobs_dir,
            job_id=effective_job_id,
            case_folder=folder,
            jobs_snapshot=snapshot,
            current_output_dir=self.output_dir,
            current_user_message=self.current_user_message,
        )
        return engine.run(action, query, limit)

    # --- Legacy internal handlers (not exposed to the LLM in v3.71) ---
    def tool_get_section(self, section: str) -> dict:
        d = self._load_analyzed()
        sec = d.get("sections", {}).get(section)
        if sec is None:
            return {
                "error": f"セクション '{section}' が見つかりません",
                "available_sections": sorted(d.get("sections", {}).keys()),
            }
        return sec

    @staticmethod
    def _entry_matches(entry: dict, needle: str) -> bool:
        """identifier だけでなく iocs（ファイルパス等）・reason も検索対象にする。
        defender_quarantine 等は identifier が脅威名で、実際のファイルパスは
        iocs にしか入っていないため、identifier のみの検索では見つからない
        （実運用で発覚: 'wangmeng' というファイル名で検索したが見つからず、
        実際は iocs 内の C:\\...\\wangmeng.dll にのみ存在していた）。"""
        haystack = " ".join([
            str(entry.get("identifier", "")),
            str(entry.get("reason", "")),
            " ".join(str(x) for x in (entry.get("iocs") or [])),
        ]).lower()
        return needle in haystack

    def tool_get_entry_detail(self, section: str, identifier: str) -> dict:
        sec = self.tool_get_section(section)
        if "error" in sec:
            return sec
        needle = (identifier or "").lower()
        hits = [e for e in sec.get("entries", []) if self._entry_matches(e, needle)]
        if not hits:
            return {"error": f"'{identifier}' に一致するエントリが見つかりません（section={section}）。"
                              "他のセクションにある可能性があるため search_keyword の利用を検討してください。"}
        return {"matches": hits}

    def tool_search_keyword(self, keyword: str) -> dict:
        """Search analyzed evidence, then raw directory evidence on zero hits."""
        if not keyword:
            return {"error": "keyword は必須です"}
        needle = keyword.casefold()
        analyzed = self._load_analyzed()
        hits = []
        for sec_name, sec in analyzed.get("sections", {}).items():
            for entry in sec.get("entries", []):
                if self._entry_matches(entry, needle):
                    hits.append({
                        "section": sec_name,
                        "identifier": entry.get("identifier"),
                        "score": entry.get("score"),
                        "reason": entry.get("reason"),
                        "iocs": entry.get("iocs"),
                    })
        if hits:
            return {
                "count": len(hits),
                "hits": hits,
                "scope": "analyzed_all_sections",
                "raw_fallback_searched": False,
                "note": ("analyzed_*.jsonで一致。raw directoryは未検索のため、"
                         "この結果だけから生データ全体の有無は断定しないこと。"),
            }

        try:
            raw = self._search_raw_directory_keyword(keyword)
        except FileNotFoundError as exc:
            return {
                "count": 0,
                "hits": [],
                "scope": "analyzed_all_sections",
                "raw_fallback_searched": False,
                "note": (f"analyzed_*.jsonでは不一致。raw検索不能: {exc}。"
                         "端末上の不存在を断定しないこと。"),
            }
        if raw["total"]:
            return {
                "count": raw["total"],
                "hits": raw["hits"],
                "scope": raw["scope"],
                "raw_fallback_searched": True,
                "truncated": raw["truncated"],
                "source_file": raw["source_file"],
                "note": ("analyzed結果には無かったが、parsedの生directory証拠に存在。"
                         "未選抜または個別LLM評価外の可能性があるため、"
                         "『端末上に存在しない』とは回答しないこと。"),
            }
        return {
            "count": 0,
            "hits": [],
            "scope": "analyzed_all_sections+parsed_directory_raw",
            "raw_fallback_searched": True,
            "truncated": False,
            "source_file": raw.get("source_file"),
            "note": (f"'{keyword}' はanalyzedおよび収集済みraw directory証拠の範囲では"
                     "見つかりませんでした。未収集領域・収集時点後・別表記の可能性があるため、"
                     "端末上の絶対的な不存在までは断定できません。"),
        }

    _DIRECTORY_SCOPE_NOTE = (
        "収集済みanalyzed directoryおよびparsed directory raw indexの範囲での結果です。"
        "端末全体、未収集領域、収集後の変更、同一path記録の実体同一性までは断定しません。"
    )

    def tool_search_directory_evidence(self, keyword: str,
                                       max_results: int = 200) -> dict:
        """Search directory evidence only. Never mixes in other sections."""
        if not keyword:
            return {"error": "keyword は必須です"}
        try:
            limit = int(max_results or 200)
        except (TypeError, ValueError):
            limit = 200
        limit = max(1, min(limit, 500))

        needle = keyword.casefold()
        analyzed_hits: list[dict] = []
        analyzed_section = (self._load_analyzed().get("sections", {})
                            .get("directory") or {})
        for entry in analyzed_section.get("entries", []) or []:
            if not self._entry_matches(entry, needle):
                continue
            analyzed_hits.append({
                "origin": "analyzed",
                "section": "directory",
                "source_id": entry.get("source_id", ""),
                "identifier": entry.get("identifier"),
                "score": entry.get("score"),
                "reason": entry.get("reason"),
                "iocs": entry.get("iocs"),
            })
        analyzed_match_count = len(analyzed_hits)

        raw_error = None
        raw_hits: list[dict] = []
        raw_match_count = 0
        raw_truncated = False
        source_file = None
        try:
            raw = self._search_raw_directory_keyword(keyword, max_results=limit)
        except FileNotFoundError as exc:
            raw_error = str(exc)
        else:
            raw_match_count = int(raw.get("total") or 0)
            raw_truncated = bool(raw.get("truncated"))
            source_file = raw.get("source_file")
            for entry in raw.get("hits", []) or []:
                # _raw_directory_hit() exposes the full path as ``identifier``.
                # Keep both keys so the path is never lost or reconstructed.
                path = entry.get("path") or entry.get("identifier") or ""
                raw_hits.append({
                    "origin": "raw",
                    "section": "directory",
                    "source_id": entry.get("source_id", ""),
                    "identifier": path,
                    "path": path,
                    "name": entry.get("name", ""),
                    "dir": entry.get("dir", ""),
                    "date": entry.get("date", ""),
                    "size": entry.get("size", ""),
                    "evaluation_status": entry.get("evaluation_status", ""),
                })

        # Analyzed rows come first, then raw rows, up to the same result cap.
        hits = analyzed_hits[:limit]
        remaining = max(0, limit - len(hits))
        hits.extend(raw_hits[:remaining])

        total = analyzed_match_count + raw_match_count
        truncated = bool(raw_truncated or total > len(hits))

        if raw_error:
            note = (f"{self._DIRECTORY_SCOPE_NOTE}"
                    f" raw directory索引を検索できませんでした（{raw_error}）。"
                    "analyzed directoryのみの結果です。")
        elif total == 0:
            note = (f"'{keyword}' はdirectoryセクションの収集済み証拠では"
                    "見つかりませんでした。"
                    f"{self._DIRECTORY_SCOPE_NOTE}"
                    "未収集領域・収集時点後の変更・別表記の可能性があるため、"
                    "端末上の絶対的な不存在は断定できません。")
        else:
            note = self._DIRECTORY_SCOPE_NOTE
        if truncated:
            note += (f" 一致 {total}件のうち {len(hits)}件のみ表示しています"
                     "（truncated=true）。")

        return {
            "requested_section": "directory",
            "scope": "analyzed_directory+parsed_directory_raw_index",
            "analyzed_match_count": analyzed_match_count,
            "raw_match_count": raw_match_count,
            "total": total,
            "returned_count": len(hits),
            "truncated": truncated,
            "source_file": source_file,
            "hits": hits,
            "note": note,
        }

    def tool_list_high_medium(self) -> dict:
        d = self._load_analyzed()
        out = []
        for sec_name, sec in d.get("sections", {}).items():
            for e in sec.get("entries", []):
                if e.get("score") in ("HIGH", "MEDIUM"):
                    out.append({
                        "section": sec_name,
                        "identifier": e.get("identifier"),
                        "score": e.get("score"),
                        "reason": e.get("reason"),
                        "iocs": e.get("iocs"),
                    })
        return {"count": len(out), "entries": out}

    def tool_get_timeline(self) -> dict:
        cands = sorted(self.output_dir.rglob("*_timeline.md")) \
            or sorted(self.output_dir.rglob("*timeline*.json"))
        if not cands:
            return {"error": "タイムライン出力が見つかりません"}
        f = cands[0]
        if f.suffix == ".json":
            return json.loads(f.read_text(encoding="utf-8"))
        return {"timeline_md": f.read_text(encoding="utf-8")}

    def tool_list_directory_files(self, folder_path: str, max_results: int = 200) -> dict:
        """List raw directory evidence under a folder using the SQLite index."""
        folder_norm = (folder_path or "").strip().rstrip("\\")
        if not folder_norm:
            return {"error": "folder_path を指定してください"}
        try:
            index_path = self._ensure_directory_index()
            raw = directory_index.list_folder(index_path, folder_norm, max_results=max_results)
        except FileNotFoundError as exc:
            return {"error": str(exc)}
        if not raw["total"]:
            return {
                "folder": folder_path,
                "total": 0,
                "files": [],
                "scope": "parsed_directory_raw_index",
                "note": ("指定フォルダの実データが収集済みraw directory内に見つかりません。"
                         "未走査・パス誤り・表記差の可能性があるため推測で補完しないこと。"),
            }
        files = [
            {
                "date": h.get("date", ""),
                "size": h.get("size", ""),
                "name": h.get("name", ""),
                "dir": h.get("dir", ""),
                "path": h.get("path", ""),
                "source_id": h.get("source_id", ""),
            }
            for h in raw["hits"]
        ]
        note = (
            f"収集済みraw directory証拠では {raw['total']}件です。"
            "端末全体、未収集領域、収集後の変更までは断定しません。"
            "『他のファイルは存在しない』とは回答しないこと。"
            "同一pathが複数記録されている場合も同一ファイル実体とは断定せず、"
            "日付やサイズが異なるものは『同一pathの複数raw record』と表現すること。"
        )
        if raw["truncated"]:
            note += (f" {raw['total']}件のうち {len(files)}件のみ表示しています"
                     "（truncated=true）。")
        return {
            "folder": folder_path,
            "total": raw["total"],
            "returned_count": len(files),
            "truncated": raw["truncated"],
            "scope": "parsed_directory_raw_index",
            "source_file": self._find_parsed_path().name,
            "files": files,
            "note": note,
        }

    # --- Lv.2 ツール実装（外部通信・案件内横断走査を伴う） ---
    def _lv2_gate(self) -> Optional[dict]:
        if self.lv2_call_count >= LV2_MAX_CALLS_PER_SESSION:
            return {"error": f"Lv.2ツールの呼び出し上限（{LV2_MAX_CALLS_PER_SESSION}回/セッション）に達しました。"
                              "質問を絞るか、チャット履歴をリセットして続けてください。"}
        return None

    def _reserve_lv2_call(self) -> Optional[dict]:
        gate = self._lv2_gate()
        if gate:
            return gate
        self.lv2_call_count += 1
        return None

    @staticmethod
    def _iter_scalar_values(value):
        if isinstance(value, dict):
            for item in value.values():
                yield from ChatContext._iter_scalar_values(item)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                yield from ChatContext._iter_scalar_values(item)
        elif isinstance(value, (str, int, float)):
            yield str(value)

    def _grounded_vt_iocs(self) -> set[str]:
        """Return normalized IOC values already present in current-job IOC fields.

        Identifiers and raw evidence are deliberately excluded: a filename such as
        ``secret.project`` is syntactically indistinguishable from an FQDN. Restricting
        implicit lookup to explicit IOC fields prevents the model from converting an
        arbitrary filename/prompt string into an external query.
        """
        if self._authorized_vt_iocs is not None:
            return self._authorized_vt_iocs
        allowed: set[str] = set()
        try:
            analyzed = self._load_analyzed()
        except (OSError, ValueError, FileNotFoundError, json.JSONDecodeError):
            analyzed = {}
        for section in analyzed.get("sections", {}).values():
            if not isinstance(section, dict):
                continue
            for entry in section.get("entries", []):
                if not isinstance(entry, dict):
                    continue
                for candidate in self._iter_scalar_values(entry.get("iocs", [])):
                    valid, payload = validate_vt_ioc(candidate)
                    if valid:
                        allowed.add(str(payload["ioc"]).lower())
        self._authorized_vt_iocs = allowed
        return allowed

    def _vt_ioc_is_grounded(self, ioc_value: object) -> tuple[bool, dict]:
        valid, payload = validate_vt_ioc(ioc_value)
        if not valid:
            return False, payload
        normalized = str(payload["ioc"]).lower()
        message = str(self.current_user_message or "")
        # rc12: derive the IOC-specific authorization set once from the current
        # analyst turn.  The same truth source is used by the VT-disabled
        # pre-check and by actual transmission grounding.
        authorized_iocs = _extract_explicit_external_ti_iocs(message)
        if not authorized_iocs:
            return False, {
                "error": "現在の分析官メッセージに外部TI照会の明示要求がないため送信を拒否しました",
                "reason": "external_ti_not_explicitly_requested",
                "ioc": normalized,
                "ioc_type": payload.get("ioc_type"),
            }
        if normalized in authorized_iocs:
            return True, payload
        return False, {
            "error": ("このIOCは現在の分析官メッセージで外部TI照会を明示許可されていないため、"
                      "モデル生成値・local-only指定値・別directiveの値として外部送信を拒否しました"),
            "reason": "ioc_not_grounded",
            "ioc": normalized,
            "ioc_type": payload.get("ioc_type"),
        }

    def tool_vt_ioc_lookup(self, ioc_value: str) -> dict:
        gate = self._reserve_lv2_call()
        if gate:
            return gate
        grounded, payload = self._vt_ioc_is_grounded(ioc_value)
        if not grounded:
            payload.update({"external_request": False, "cache_hit": False})
            return payload
        return secure_vt_lookup(
            payload["ioc"],
            api_key=self.vt_key,
            proxy_url=self.vt_proxy,
            rate_delay=self.vt_rate_delay,
            timeout=self.vt_timeout,
            cache_ttl_seconds=self.vt_cache_ttl,
            cache_max_entries=self.vt_cache_max_entries,
            retry_429_max_seconds=self.vt_retry_429_max_seconds,
        )

    # v3.69-rc4までの内部呼び出し・古いテストとの互換。公開schemaには出さない。
    def tool_vt_lookup(self, ioc_value: str) -> dict:
        return self.tool_vt_ioc_lookup(ioc_value)

    def _jobs_snapshot(self) -> dict:
        src = self.jobs_metadata
        if callable(src):
            try:
                src = src()
            except Exception:
                src = None
        if isinstance(src, dict):
            return {str(k): dict(v) for k, v in src.items() if isinstance(v, dict)}
        if isinstance(src, list):
            return {str(j.get("job_id")): dict(j) for j in src
                    if isinstance(j, dict) and j.get("job_id")}
        jobs_json = self.jobs_dir / "jobs.json"
        try:
            data = json.loads(jobs_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return {str(j.get("job_id")): dict(j) for j in data
                if isinstance(j, dict) and j.get("job_id")}

    def _effective_job_id(self, snapshot: dict) -> str:
        if self.job_id:
            return self.job_id
        try:
            rel = self.output_dir.resolve().relative_to(self.jobs_dir.resolve())
            if rel.parts:
                return rel.parts[0]
        except (OSError, ValueError):
            pass
        for jid, meta in snapshot.items():
            for key in ("run_dir", "output_dir"):
                value = meta.get(key)
                if not value:
                    continue
                try:
                    if self.output_dir.resolve() == Path(value).resolve():
                        return jid
                except OSError:
                    continue
        return ""

    @staticmethod
    def _safe_job_id(value: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", str(value or ""))) \
            and value not in (".", "..")

    def _select_analyzed_file(self, job_id: str, counters: dict) -> tuple[Optional[Path], str]:
        if not self._safe_job_id(job_id):
            return None, "invalid_job_id"
        try:
            jobs_root = self.jobs_dir.resolve()
            job_path = self.jobs_dir / job_id
            if job_path.is_symlink():
                return None, "job_symlink"
            job_root = job_path.resolve()
            job_root.relative_to(jobs_root)
        except (OSError, ValueError):
            return None, "job_outside_root"
        output_root = job_root / "output"
        if not output_root.is_dir() or output_root.is_symlink():
            return None, "output_missing_or_symlink"

        vt_candidates, base_candidates = [], []
        for root, dirs, files in os.walk(output_root, followlinks=False):
            # Directory symlinks are never traversed.
            dirs[:] = [d for d in dirs if not Path(root, d).is_symlink()]
            for name in sorted(files):
                if not (name.startswith("analyzed_") and name.endswith(".json")):
                    continue
                counters["files_seen"] += 1
                if counters["files_seen"] > CROSS_HOST_MAX_FILES:
                    return None, "file_count_limit"
                f = Path(root) / name
                if f.is_symlink():
                    counters["symlinks_skipped"] += 1
                    continue
                try:
                    resolved = f.resolve()
                    resolved.relative_to(job_root)
                    size = f.stat().st_size
                except (OSError, ValueError):
                    counters["unsafe_files_skipped"] += 1
                    continue
                if size > CROSS_HOST_MAX_FILE_MB * 1024 * 1024:
                    counters["oversized_files_skipped"] += 1
                    continue
                counters["bytes_selected_candidates"] += size
                if counters["bytes_selected_candidates"] > CROSS_HOST_MAX_TOTAL_MB * 1024 * 1024:
                    return None, "total_byte_limit"
                if name.endswith("_vt.json"):
                    vt_candidates.append(resolved)
                else:
                    base_candidates.append(resolved)
        candidates = sorted(vt_candidates) or sorted(base_candidates)
        return (candidates[0], "ok") if candidates else (None, "analyzed_missing")

    @staticmethod
    def _search_file(path: Path, needle: str, limit: int) -> tuple[list, int]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return [], 0
        hits, duplicate_count = [], 0
        seen = set()
        for sec_name, sec in data.get("sections", {}).items():
            if not isinstance(sec, dict):
                continue
            for entry in sec.get("entries", []):
                if not isinstance(entry, dict):
                    continue
                haystack = " ".join([
                    str(entry.get("identifier", "")),
                    str(entry.get("reason", "")),
                    " ".join(str(x) for x in (entry.get("iocs") or [])),
                ]).lower()
                if needle not in haystack:
                    continue
                src = entry.get("source_index")
                try:
                    src_key = json.dumps(src, ensure_ascii=False, sort_keys=True)
                except TypeError:
                    src_key = str(src)
                key = (str(sec_name), src_key, str(entry.get("identifier", "")),
                       tuple(str(x).lower() for x in (entry.get("iocs") or [])))
                if key in seen:
                    duplicate_count += 1
                    continue
                seen.add(key)
                hits.append({
                    "section": sec_name,
                    "source_index": src,
                    "identifier": entry.get("identifier"),
                    "score": entry.get("score"),
                    "iocs": entry.get("iocs") or [],
                })
                if len(hits) >= limit:
                    return hits, duplicate_count
        return hits, duplicate_count

    def tool_cross_host_search(self, ioc_value: str) -> dict:
        gate = self._reserve_lv2_call()
        if gate:
            return gate
        query = str(ioc_value or "").strip()
        if not query:
            return {"error": "ioc_value は必須です"}
        if len(query) > 512 or any(ord(ch) < 32 for ch in query):
            return {"error": "検索値が長すぎるか制御文字を含んでいます"}

        snapshot = self._jobs_snapshot()
        current_job_id = self._effective_job_id(snapshot)
        current_meta = snapshot.get(current_job_id, {})
        folder = self.case_folder or str(current_meta.get("folder") or "").strip()
        if not folder:
            return {
                "error": "案件フォルダが未設定のため横断検索できません。ジョブへ案件フォルダを設定してください",
                "reason": "case_folder_required",
            }

        candidates = []
        for jid, meta in snapshot.items():
            if str(meta.get("folder") or "").strip() != folder:
                continue
            if meta.get("status") not in (None, "done"):
                continue
            candidates.append(jid)
        if current_job_id and current_job_id not in candidates:
            candidates.append(current_job_id)
        candidates = sorted(set(candidates))[:CROSS_HOST_MAX_JOBS]

        counters = {
            "files_seen": 0, "bytes_selected_candidates": 0,
            "symlinks_skipped": 0, "unsafe_files_skipped": 0,
            "oversized_files_skipped": 0, "duplicate_entries_removed": 0,
        }
        skipped_reasons = {}
        current_matches = []
        other_hits = []
        started = time.monotonic()
        timed_out = False

        # Current job first, then other hosts, so its reference information does
        # not consume the other-host hit budget.
        ordered = ([current_job_id] if current_job_id else []) + [j for j in candidates if j != current_job_id]
        for jid in ordered:
            if time.monotonic() - started > CROSS_HOST_TIMEOUT_SEC:
                timed_out = True
                break
            path, reason = self._select_analyzed_file(jid, counters)
            if path is None:
                skipped_reasons[reason] = skipped_reasons.get(reason, 0) + 1
                if reason in ("file_count_limit", "total_byte_limit"):
                    break
                continue
            limit = CROSS_HOST_CURRENT_MAX_HITS if jid == current_job_id else max(1, CROSS_HOST_MAX_HITS - len(other_hits))
            found, dupes = self._search_file(path, query.lower(), limit)
            counters["duplicate_entries_removed"] += dupes
            for hit in found:
                hit["job_id"] = jid
                if jid == current_job_id:
                    current_matches.append(hit)
                else:
                    other_hits.append(hit)
                    if len(other_hits) >= CROSS_HOST_MAX_HITS:
                        break
            if len(other_hits) >= CROSS_HOST_MAX_HITS:
                break

        other_hosts = sorted({h["job_id"] for h in other_hits})
        return {
            "case_folder": folder,
            "query": query,
            "current_job_id": current_job_id,
            "current_job_match_count": len(current_matches),
            "current_job_matches": current_matches,
            "other_host_count": len(other_hosts),
            "other_host_job_ids": other_hosts,
            "count": len(other_hits),
            "other_host_hits": other_hits,
            # Backward-compatible alias; contains other hosts only in rc5.
            "hits": other_hits,
            "truncated": len(other_hits) >= CROSS_HOST_MAX_HITS or timed_out,
            "timed_out": timed_out,
            "scan_summary": {
                "candidate_jobs": len(candidates),
                "files_seen": counters["files_seen"],
                "bytes_considered": counters["bytes_selected_candidates"],
                "symlinks_skipped": counters["symlinks_skipped"],
                "unsafe_files_skipped": counters["unsafe_files_skipped"],
                "oversized_files_skipped": counters["oversized_files_skipped"],
                "duplicate_entries_removed": counters["duplicate_entries_removed"],
                "skipped_reasons": skipped_reasons,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            },
        }



# ── ツール呼び出しディスパッチ ─────────────────────────────────
def dispatch_tool_call(ctx: ChatContext, name: str, arguments: dict) -> dict:
    """OpenAI tool_call 1件を実行し結果dictを返す。"""
    handlers = {
        INVESTIGATE_TOOL_NAME: lambda: ctx.tool_investigate_local(
            arguments.get("action", ""), arguments.get("query", ""), arguments.get("limit", 50)),
        "get_section": lambda: ctx.tool_get_section(arguments.get("section", "")),
        "get_entry_detail": lambda: ctx.tool_get_entry_detail(
            arguments.get("section", ""), arguments.get("identifier", "")),
        "search_keyword": lambda: ctx.tool_search_keyword(arguments.get("keyword", "")),
        "search_directory_evidence": lambda: ctx.tool_search_directory_evidence(
            arguments.get("keyword", ""), arguments.get("max_results", 200)),
        "list_high_medium": lambda: ctx.tool_list_high_medium(),
        "get_timeline": lambda: ctx.tool_get_timeline(),
        "list_directory_files": lambda: ctx.tool_list_directory_files(
            arguments.get("folder_path", ""), arguments.get("max_results", 200)),
        VT_TOOL_NAME: lambda: ctx.tool_vt_ioc_lookup(arguments.get("ioc_value", "")),
        # v3.69-rc4互換。schemaには公開しないが同じ厳格検証を通す。
        "vt_lookup": lambda: ctx.tool_vt_ioc_lookup(arguments.get("ioc_value", "")),
        CROSS_HOST_TOOL_NAME: lambda: ctx.tool_cross_host_search(arguments.get("ioc_value", "")),
    }
    fn = handlers.get(name)
    if fn is None:
        return {"error": f"未知のツール: {name}"}
    try:
        result = fn()
        return ctx.redact(result) if hasattr(ctx, "redact") else result
    except Exception as e:  # ツール内例外でLLMループ全体を落とさない
        detail = f"{type(e).__name__}: {e}"
        if hasattr(ctx, "redact_error"):
            detail = ctx.redact_error(detail)
        return {"error": f"ツール実行エラー: {detail}"}


def is_lv2_tool(name: str) -> bool:
    return name in (VT_TOOL_NAME, "vt_lookup", CROSS_HOST_TOOL_NAME)


def clear_audit_fallback_records() -> None:
    """Clear the bounded in-memory audit fallback buffer (tests/maintenance)."""
    with _AUDIT_FALLBACK_LOCK:
        _AUDIT_FALLBACK_BUFFER.clear()


def get_audit_fallback_records() -> list[dict]:
    """Return a defensive copy of audit records retained after write failures."""
    with _AUDIT_FALLBACK_LOCK:
        return copy.deepcopy(list(_AUDIT_FALLBACK_BUFFER))


def remove_audit_fallback_records(job_id: str) -> int:
    """Remove in-memory fallback records belonging to a completely deleted job."""
    target = str(job_id or "")
    if not target:
        return 0
    with _AUDIT_FALLBACK_LOCK:
        kept = [row for row in _AUDIT_FALLBACK_BUFFER
                if str(row.get("job_id") or "") != target]
        removed = len(_AUDIT_FALLBACK_BUFFER) - len(kept)
        _AUDIT_FALLBACK_BUFFER.clear()
        _AUDIT_FALLBACK_BUFFER.extend(kept)
    return removed


def _safe_error_code(exc: BaseException) -> str:
    errno = getattr(exc, "errno", None)
    return f"{type(exc).__name__}" + (f":errno={errno}" if errno is not None else "")


def _secure_append_jsonl(path: Path, line: str, *, allowed_root: Optional[Path] = None) -> None:
    """Append one JSONL line without following a symlink for the log file."""
    p = Path(path)
    if allowed_root is not None:
        root = Path(allowed_root).resolve()
        parent = p.parent.resolve(strict=False)
        try:
            parent.relative_to(root)
        except ValueError as exc:
            raise PermissionError("audit path escapes jobs root") from exc
    p.parent.mkdir(parents=True, exist_ok=True)
    if allowed_root is not None:
        # Re-check after mkdir so a pre-existing parent symlink or a race that
        # changed the resolved parent cannot silently redirect the append.
        parent = p.parent.resolve()
        try:
            parent.relative_to(root)
        except ValueError as exc:
            raise PermissionError("audit path escapes jobs root") from exc
    if p.exists() and p.is_symlink():
        raise PermissionError("audit log symlink is not allowed")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(p), flags, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def _audit_fallback_path(ctx: Optional[ChatContext]) -> Optional[Path]:
    if ctx is None or not getattr(ctx, "jobs_dir", None):
        return None
    job_id = str(getattr(ctx, "job_id", "") or "unknown")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", job_id):
        job_id = "unknown"
    return Path(ctx.jobs_dir) / "_audit_fallback" / job_id / "chat_tool_log.jsonl"


def _append_entry_with_fallback(log_path, entry: dict, *,
                                ctx: Optional[ChatContext] = None) -> dict:
    line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"
    root = Path(ctx.jobs_dir) if ctx is not None and getattr(ctx, "jobs_dir", None) else None
    try:
        _secure_append_jsonl(Path(log_path), line, allowed_root=root)
        return {"written": True, "fallback": False}
    except Exception as primary_exc:
        fallback_entry = copy.deepcopy(entry)
        fallback_entry["audit_write_status"] = "fallback"
        fallback_entry["audit_primary_error"] = _safe_error_code(primary_exc)
        fallback_line = json.dumps(fallback_entry, ensure_ascii=False, default=str) + "\n"
        with _AUDIT_FALLBACK_LOCK:
            _AUDIT_FALLBACK_BUFFER.append(copy.deepcopy(fallback_entry))

        fallback_file_written = False
        fallback_error = ""
        fallback_path = _audit_fallback_path(ctx)
        if fallback_path is not None and Path(fallback_path) != Path(log_path):
            try:
                _secure_append_jsonl(fallback_path, fallback_line, allowed_root=root)
                fallback_file_written = True
            except Exception as fallback_exc:
                fallback_error = _safe_error_code(fallback_exc)

        # Last-resort process-visible evidence. stderr failure is deliberately
        # ignored because the bounded memory buffer has already retained a copy.
        try:
            stderr_notice = {
                "kind": "audit_fallback_notice",
                "job_id": str(fallback_entry.get("job_id") or ""),
                "tool": str(fallback_entry.get("tool") or fallback_entry.get("kind") or ""),
                "audit_phase": str(fallback_entry.get("audit_phase") or ""),
                "external_network": bool(fallback_entry.get("external_network")),
                "primary_error": fallback_entry.get("audit_primary_error", ""),
            }
            sys.stderr.write(
                "CHECKPC_AUDIT_FALLBACK " +
                json.dumps(stderr_notice, ensure_ascii=False, default=str) + "\n"
            )
            sys.stderr.flush()
        except Exception:
            pass
        return {
            "written": False,
            "fallback": True,
            "fallback_memory": True,
            "fallback_file_written": fallback_file_written,
            "primary_error": _safe_error_code(primary_exc),
            "fallback_error": fallback_error,
        }


def append_audit_log(log_path, name: str, arguments: dict, result: dict, *,
                     ctx: Optional[ChatContext] = None,
                     elapsed_seconds: float = 0.0,
                     audit_phase: str = "completed",
                     external_network_planned: bool = False) -> dict:
    safe_arguments = ctx.redact(arguments) if ctx and hasattr(ctx, "redact") else arguments
    safe_result = ctx.redact(result) if ctx and hasattr(ctx, "redact") else result
    meta = safe_result if isinstance(safe_result, dict) else {}
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tool": name,
        "is_lv2": is_lv2_tool(name),
        "job_id": getattr(ctx, "job_id", "") if ctx else "",
        "case_folder": getattr(ctx, "case_folder", "") if ctx else "",
        "lv2_policy": getattr(ctx, "lv2_policy", LV2_POLICY_OFF) if ctx else LV2_POLICY_OFF,
        "arguments": safe_arguments,
        "external_network": bool(meta.get("external_request")),
        "external_network_planned": bool(external_network_planned),
        "cache_hit": bool(meta.get("cache_hit")),
        "elapsed_seconds": round(max(0.0, elapsed_seconds), 3),
        "audit_phase": audit_phase,
        "result_status": "error" if isinstance(meta, dict) and meta.get("error") else "ok",
        "result_summary": json.dumps(safe_result, ensure_ascii=False, default=str)[:600],
    }
    return _append_entry_with_fallback(log_path, entry, ctx=ctx)


def _append_timing_log(log_path, elapsed_seconds: float, context_message_count: int,
                       *, ctx: Optional[ChatContext] = None) -> dict:
    """LLM呼び出し1回分の所要時間を監査ログに記録する（応答遅延の原因切り分け用）。"""
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "kind": "llm_call_timing",
        "job_id": getattr(ctx, "job_id", "") if ctx else "",
        "case_folder": getattr(ctx, "case_folder", "") if ctx else "",
        "elapsed_seconds": round(elapsed_seconds, 2),
        "context_message_count": context_message_count,
    }
    return _append_entry_with_fallback(log_path, entry, ctx=ctx)


# ── tool-calling ループ本体 ─────────────────────────────────
def compact_history(messages: list) -> list:
    """
    完了済みの過去ターンから、tool-calling往復の中間メッセージ
    （tool_calls付きassistant・role=toolのツール結果）を取り除き、
    system/user/最終assistant応答のみを残す。

    現在処理中の（まだ完了していない）ターンは呼び出し時点でまだ
    このリストに含まれていないため、影響を受けない。

    背景（実運用で発覚）: ツール呼び出しの中間結果を無制限に履歴へ
    残し続けると、会話を数往復重ねただけで vLLM の max_model_len
    （例: 16384トークン）を超過し、"Error Code 400: maximum context
    length is..." で以降の会話が完全に不能になる。ツールの中間結果は
    そのターンの最終回答を生成し終えた時点で役目を終えているため、
    次のターン開始前に破棄してよい。
    """
    compacted = []
    for m in messages:
        role = m.get("role")
        if role in ("system", "user"):
            compacted.append(m)
        elif role == "assistant" and not m.get("tool_calls"):
            compacted.append(m)
        # role == "tool" や tool_calls付きassistantはここで破棄する
    return compacted


def _estimate_context_chars(messages: list, tools: list) -> int:
    """次のLLM呼び出しで送信されるコンテキストの文字数を見積もる
    （実トークナイザ不使用の簡易見積り。安全側に倒すための目安値）。"""
    total = sum(len(json.dumps(m, ensure_ascii=False)) for m in messages)
    total += sum(len(json.dumps(t, ensure_ascii=False)) for t in tools)
    return total


def _wrapup_final_call(client, model: str, messages: list, note: str,
                        fallback_text: str, tool_log_path=None,
                        ctx: Optional[ChatContext] = None) -> tuple:
    """
    ツールをこれ以上使わせず、蓄積済みの情報だけで最後に1回だけ回答させる
    「救済呼び出し」。context_budget_exceeded と
    max_tool_iterations 到達の双方で共用する（v3.57で統合）。

    戻り値: (reply: str, elapsed_seconds: float)
    """
    wrapup_messages = messages + [{"role": "user", "content": note}]
    try:
        call_t0 = time.monotonic()
        resp = create_chat_completion(client, 
            model=model, messages=wrapup_messages,
            temperature=CHAT_TEMPERATURE,
            extra_body={"repetition_penalty": CHAT_REPETITION_PENALTY},
        )
        call_elapsed = time.monotonic() - call_t0
        if tool_log_path:
            _append_timing_log(tool_log_path, call_elapsed, len(wrapup_messages), ctx=ctx)
        text_result = extract_llm_text(resp)
        if text_result.error:
            return fallback_text, call_elapsed
        reply = _sanitize_reply(text_result.text) or fallback_text
        return reply, call_elapsed
    except Exception:
        return fallback_text, 0.0


def run_chat_turn(client, model: str, messages: list, ctx: ChatContext,
                   lv2_enabled: bool = False, mode: str = CHAT_DEFAULT_MODE,
                   tool_log_path=None, *, lv2_policy: Optional[str] = None,
                   local_enabled: bool = True, vt_enabled: bool = True) -> dict:
    """Run one bounded v3.71 chat turn.

    The legacy mode field is accepted for API compatibility but all modes use
    the same local evidence capability and the same hard tool-round budget.
    Public tools are investigate_local and, only when explicitly enabled,
    vt_ioc_lookup.  Tool results remain untrusted evidence.
    """
    if mode not in CHAT_MODE_MAX_ITERATIONS:
        mode = CHAT_DEFAULT_MODE
    max_tool_iterations = CHAT_MODE_MAX_ITERATIONS[mode]

    # Ground external IOC lookups in the current analyst turn. Historical user
    # messages do not authorize a new external request in a later turn.
    if hasattr(ctx, "__dict__"):
        ctx.current_user_message = next(
            (str(m.get("content") or "") for m in reversed(messages) if m.get("role") == "user"),
            "",
        )

    turn_t0 = time.monotonic()

    policy = normalize_policy(
        lv2_policy if lv2_policy is not None else
        (LV2_POLICY_LOCAL_VT_IOC if lv2_enabled else LV2_POLICY_OFF)
    )
    allowed_lv2 = allowed_lv2_tools(policy, local_enabled=local_enabled, vt_enabled=vt_enabled)
    tools = build_tool_schema(lv2_enabled, lv2_policy=policy,
                              local_enabled=local_enabled, vt_enabled=vt_enabled)
    public_tool_names = {str(t.get("function", {}).get("name") or "") for t in tools}

    # rc9: external-TI intent is a control-plane request, not a local-evidence
    # query.  When VT is disabled by policy/kill-switch, answer deterministically
    # before the LLM can reinterpret the request as investigate_local.
    authorized_external_iocs = _extract_explicit_external_ti_iocs(ctx.current_user_message)
    if (VT_TOOL_NAME not in public_tool_names and authorized_external_iocs):
        return {
            "reply": "現在の設定ではVirusTotal（外部TI）照会は無効です。外部通信は行っていません。",
            "tool_calls_made": [],
            "timing": {
                "llm_calls": 0,
                "llm_seconds_total": 0.0,
                "llm_seconds_per_call": [],
                "total_seconds": round(time.monotonic() - turn_t0, 2),
                "context_budget_exceeded": False,
                "tool_iterations_exceeded": False,
                "external_ti_disabled_stopped": True,
                "mode": mode,
            },
        }

    tool_calls_made = []
    tool_calls_this_turn = 0
    llm_seconds_per_call = []
    budget_exceeded = False
    duplicate_tool_stop = False
    authoritative_facts_note = None
    seen_tool_calls: set[tuple[str, str]] = set()

    for _ in range(max_tool_iterations):
        if _estimate_context_chars(messages, tools) > CHAT_CONTEXT_CHAR_BUDGET:
            budget_exceeded = True
            break
        call_t0 = time.monotonic()
        resp = create_chat_completion(client, 
            model=model, messages=messages, tools=tools, tool_choice="auto",
            temperature=CHAT_TEMPERATURE,
            extra_body={"repetition_penalty": CHAT_REPETITION_PENALTY},
        )
        call_elapsed = time.monotonic() - call_t0
        llm_seconds_per_call.append(round(call_elapsed, 2))
        if tool_log_path:
            _append_timing_log(tool_log_path, call_elapsed, len(messages), ctx=ctx)

        msg, message_error = extract_llm_message(resp)
        if message_error:
            raise RuntimeError(f"invalid_chat_response:{message_error}")
        tool_calls = getattr(msg, "tool_calls", None)

        if not tool_calls:
            text_result = extract_llm_text(resp)
            if text_result.error:
                raise RuntimeError(f"invalid_chat_response:{text_result.error}")
            timing = {
                "llm_calls": len(llm_seconds_per_call),
                "llm_seconds_total": round(sum(llm_seconds_per_call), 2),
                "llm_seconds_per_call": llm_seconds_per_call,
                "total_seconds": round(time.monotonic() - turn_t0, 2),
                "context_budget_exceeded": False,
                "tool_iterations_exceeded": False,
                "mode": mode,
            }
            return {"reply": _sanitize_reply(text_result.text),
                    "tool_calls_made": tool_calls_made, "timing": timing}

        messages.append({
            "role": "assistant",
            "content": msg.content,
            "tool_calls": [
                tc if isinstance(tc, dict) else
                (tc.model_dump() if hasattr(tc, "model_dump") else dict(tc))
                for tc in tool_calls
            ],
        })

        for tc in tool_calls:
            func = tc["function"] if isinstance(tc, dict) else tc.function
            name = func["name"] if isinstance(func, dict) else func.name
            raw_args = func["arguments"] if isinstance(func, dict) else func.arguments
            tc_id = tc["id"] if isinstance(tc, dict) else tc.id
            try:
                arguments = json.loads(raw_args or "{}")
            except json.JSONDecodeError:
                arguments = {}

            tool_started = time.monotonic()
            tool_calls_this_turn += 1
            canonical_name = VT_TOOL_NAME if name == "vt_lookup" else name
            try:
                canonical_args = json.dumps(arguments, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            except TypeError:
                canonical_args = str(arguments)
            call_key = (canonical_name, canonical_args)
            will_dispatch = True
            if canonical_name not in public_tool_names:
                seen_tool_calls.add(call_key)
                result = {
                    "error": f"ツール '{canonical_name}' は現在のLLM公開schemaに含まれていません",
                    "reason": "tool_not_public",
                    "tool": canonical_name,
                }
                will_dispatch = False
            elif call_key in seen_tool_calls:
                result = {
                    "error": "同一ターンで同じツールと同じ引数が既に実行済みです",
                    "reason": "duplicate_tool_call",
                    "tool": canonical_name,
                }
                will_dispatch = False
                duplicate_tool_stop = True
            elif tool_calls_this_turn > CHAT_MAX_TOOL_CALLS_PER_TURN:
                result = {"error": f"1ターンのツール呼び出し上限（{CHAT_MAX_TOOL_CALLS_PER_TURN}件）を超えました"}
                will_dispatch = False
            elif is_lv2_tool(name) and canonical_name not in allowed_lv2:
                seen_tool_calls.add(call_key)
                result = {"error": f"外部TIツール '{canonical_name}' は案件ポリシーまたはサーバ設定で無効です"}
                will_dispatch = False
            else:
                seen_tool_calls.add(call_key)
                if tool_log_path and is_lv2_tool(name):
                    append_audit_log(
                        tool_log_path,
                        canonical_name,
                        arguments,
                        {"audit_reserved": True, "external_request": False},
                        ctx=ctx,
                        elapsed_seconds=0.0,
                        audit_phase="reserved",
                        external_network_planned=(canonical_name == VT_TOOL_NAME),
                    )
                result = dispatch_tool_call(ctx, name, arguments)
                note = _authoritative_answer_facts_note(result)
                if note:
                    authoritative_facts_note = note

            tool_elapsed = time.monotonic() - tool_started
            tool_calls_made.append({"name": canonical_name, "arguments": arguments,
                                    "is_lv2": is_lv2_tool(name)})
            if tool_log_path:
                append_audit_log(tool_log_path, canonical_name, arguments, result,
                                 ctx=ctx, elapsed_seconds=tool_elapsed,
                                 audit_phase="completed",
                                 external_network_planned=(will_dispatch and canonical_name == VT_TOOL_NAME))

            content = json.dumps(result, ensure_ascii=False)
            if len(content) > TOOL_RESULT_MAX_CHARS:
                content = content[:TOOL_RESULT_MAX_CHARS] + " …(以降切り詰め)"

            messages.append({
                "role": "tool",
                "tool_call_id": tc_id,
                "name": name,
                # Tool output may contain attacker-controlled filenames, commands,
                # registry values, or log text.  Prevent it from closing/reopening
                # any prompt boundary before presenting it to the model.
                "content": wrap_untrusted_tool_result(content),
            })

        if authoritative_facts_note:
            reply, wrapup_elapsed = _wrapup_final_call(
                client, model, messages,
                note=authoritative_facts_note,
                fallback_text="[決定論的な案件集計は取得済みですが、最終回答の生成に失敗しました]",
                tool_log_path=tool_log_path,
                ctx=ctx,
            )
            if wrapup_elapsed:
                llm_seconds_per_call.append(round(wrapup_elapsed, 2))
            return {
                "reply": reply,
                "tool_calls_made": tool_calls_made,
                "timing": {
                    "llm_calls": len(llm_seconds_per_call),
                    "llm_seconds_total": round(sum(llm_seconds_per_call), 2),
                    "llm_seconds_per_call": llm_seconds_per_call,
                    "total_seconds": round(time.monotonic() - turn_t0, 2),
                    "context_budget_exceeded": False,
                    "tool_iterations_exceeded": False,
                    "authoritative_answer_facts_stopped": True,
                    "mode": mode,
                },
            }

        if duplicate_tool_stop:
            reply, wrapup_elapsed = _wrapup_final_call(
                client, model, messages,
                note="（システム注記: 同一ツール・同一引数の再要求を検出したため、追加ツール調査を終了します。既に得られた証拠とcoverageだけで簡潔に回答してください）",
                fallback_text="[同一のツール調査が繰り返されたため、ここまでの証拠だけで回答を終了しました]",
                tool_log_path=tool_log_path,
                ctx=ctx,
            )
            if wrapup_elapsed:
                llm_seconds_per_call.append(round(wrapup_elapsed, 2))
            return {
                "reply": reply,
                "tool_calls_made": tool_calls_made,
                "timing": {
                    "llm_calls": len(llm_seconds_per_call),
                    "llm_seconds_total": round(sum(llm_seconds_per_call), 2),
                    "llm_seconds_per_call": llm_seconds_per_call,
                    "total_seconds": round(time.monotonic() - turn_t0, 2),
                    "context_budget_exceeded": False,
                    "tool_iterations_exceeded": False,
                    "duplicate_tool_call_stopped": True,
                    "mode": mode,
                },
            }

    if budget_exceeded:
        reply, wrapup_elapsed = _wrapup_final_call(
            client, model, messages,
            note="（システム注記: コンテキスト長の上限に近づいたため、"
                 "これ以上の追加調査はできません。ここまでに得られた"
                 "情報だけで、分かる範囲を簡潔に回答してください）",
            fallback_text="[コンテキスト長の上限に達し、これ以上の調査ができませんでした。"
                          "質問を絞って再度お尋ねください]",
            tool_log_path=tool_log_path,
            ctx=ctx,
        )
        if wrapup_elapsed:
            llm_seconds_per_call.append(round(wrapup_elapsed, 2))
        return {
            "reply": reply,
            "tool_calls_made": tool_calls_made,
            "timing": {
                "llm_calls": len(llm_seconds_per_call),
                "llm_seconds_total": round(sum(llm_seconds_per_call), 2),
                "llm_seconds_per_call": llm_seconds_per_call,
                "total_seconds": round(time.monotonic() - turn_t0, 2),
                "context_budget_exceeded": True,
                "tool_iterations_exceeded": False,
                "mode": mode,
            },
        }

    # v3.57: ツール呼び出し回数の上限に達した場合も、budget_exceeded と同様に
    # それまでの情報で最後に1回だけ回答を試みる（従来は問答無用で諦めていた）。
    reply, wrapup_elapsed = _wrapup_final_call(
        client, model, messages,
        note=f"（システム注記: このターンで使えるツールラウンド上限（{max_tool_iterations}回）に達しました。"
             "これ以上の追加調査はせず、ここまでの証拠とcoverageだけで簡潔に回答してください）",
        fallback_text="[ツール呼び出し回数の上限に達しました。質問を絞って再度お尋ねください]",
        tool_log_path=tool_log_path,
        ctx=ctx,
    )
    if wrapup_elapsed:
        llm_seconds_per_call.append(round(wrapup_elapsed, 2))
    return {
        "reply": reply,
        "tool_calls_made": tool_calls_made,
        "timing": {
            "llm_calls": len(llm_seconds_per_call),
            "llm_seconds_total": round(sum(llm_seconds_per_call), 2),
            "llm_seconds_per_call": llm_seconds_per_call,
            "total_seconds": round(time.monotonic() - turn_t0, 2),
            "context_budget_exceeded": False,
            "tool_iterations_exceeded": True,
            "mode": mode,
        },
    }

