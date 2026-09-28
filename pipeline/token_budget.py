#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
token_budget.py  (v3.69-rc2)

トークン概算とコンテキスト予算計算の共通モジュール。
correlate.py が独自に持っていた CHARS_PER_TOKEN / MAX_MODEL_LEN /
TOKEN_SAFETY_MARGIN を本モジュールへ集約し、analyze_section.py と共通化する。

■ 概算方式（v3.69-rc2 暫定）

    estimated = ceil(ascii_chars / 2.0 + non_ascii_chars / 1.0)
    estimated = ceil(estimated * TOKEN_ESTIMATE_SAFETY_FACTOR)

  ASCII を 3文字/token としないのは、Base64・難読化 PowerShell・
  ランダム文字列に対して過小評価するため（これらは 1〜2 文字/token に
  近づく）。2.0 は安全側の暫定値であり、実測比較で調整する。

  旧 int(len(text) / 2.0) 一律は、日本語テキスト（1文字≒1トークン）を
  約2倍過小評価していた。CheckPC の reason / task_name / Defender 脅威名は
  日本語が支配的であり、correlate の 12000文字切断や chunk の入力見積りが
  実際より甘く出ていた可能性がある。

■ ローカルトークナイザー（任意・新規必須依存にしない）

  CHECKPC_TOKENIZER に transformers のモデルパス/名を指定すると、
  存在する場合のみ実トークナイザーを使う。import 失敗・ロード失敗時は
  黙ってフォールバック概算へ戻る（オフライン base117 で追加依存を
  要求しない）。
"""

import math
import os

# ─────────────────────────────────────────────────────────────
# 定数
# ─────────────────────────────────────────────────────────────
# vLLM 起動時の --max-model-len と一致させること
MAX_MODEL_LEN = 16384

# analyze_section 用の安全マージン
CHUNK_SAFETY_MARGIN = 512
# correlate 用の安全マージン（旧 TOKEN_SAFETY_MARGIN=200 から引き上げ）
CORR_SAFETY_MARGIN = 512

# chat template（role タグ等）の固定オーバヘッド概算
CHAT_TEMPLATE_TOKENS = 48
# entries_to_text が付与する "[#N] " と区切りの分
ENTRY_INDEX_TOKENS = 4

# 概算の重み（v3.69-rc2 暫定）
ASCII_CHARS_PER_TOKEN     = 2.0
NON_ASCII_CHARS_PER_TOKEN = 1.0

# 非推奨: 旧 correlate.py の定数。参照互換のためだけに残す。
# 新規コードでは est_tokens() を使うこと。
CHARS_PER_TOKEN = 2.0
TOKEN_SAFETY_MARGIN = CORR_SAFETY_MARGIN


# ─────────────────────────────────────────────────────────────
# ローカルトークナイザー（任意）
# ─────────────────────────────────────────────────────────────
_TOKENIZER = None
_TOKENIZER_TRIED = False
_TOKENIZER_FINGERPRINT = None


def _get_tokenizer():
    """CHECKPC_TOKENIZER が指定され、かつロードできる場合のみ実体を返す。
    それ以外は None（フォールバック概算を使う）。新規必須依存にはしない。"""
    global _TOKENIZER, _TOKENIZER_TRIED, _TOKENIZER_FINGERPRINT
    if _TOKENIZER_TRIED:
        return _TOKENIZER
    _TOKENIZER_TRIED = True
    name = os.environ.get("CHECKPC_TOKENIZER", "").strip()
    if not name:
        return None
    try:
        from transformers import AutoTokenizer   # noqa: 任意依存
        _TOKENIZER = AutoTokenizer.from_pretrained(name, local_files_only=True)
        _TOKENIZER_FINGERPRINT = f"transformers:{name}"
    except Exception:
        _TOKENIZER = None
        _TOKENIZER_FINGERPRINT = None
    return _TOKENIZER


def tokenizer_fingerprint():
    """監査用: 実際に使ったトークナイザーの識別子。未使用なら概算方式名。"""
    _get_tokenizer()
    return _TOKENIZER_FINGERPRINT or "none"


def token_estimator_name():
    """監査用: 実際に使った推定器の識別子。"""
    if _get_tokenizer() is not None:
        return "tokenizer:" + (_TOKENIZER_FINGERPRINT or "?")
    return ("heuristic:ascii/%.1f+nonascii/%.1f*safety"
            % (ASCII_CHARS_PER_TOKEN, NON_ASCII_CHARS_PER_TOKEN))


# ─────────────────────────────────────────────────────────────
# 概算本体
# ─────────────────────────────────────────────────────────────
def _count_ascii(text):
    """ASCII 文字数を数える。C 実装の encode を使い大量データでも高速。
    encode("ascii","ignore") は非ASCIIを捨てるため、残バイト数＝ASCII文字数。"""
    try:
        return len(text.encode("ascii", "ignore"))
    except Exception:
        return sum(1 for c in text if ord(c) < 128)


def est_tokens_raw(text):
    """安全率を掛ける前の素の概算値（テスト・監査用）。"""
    if not text:
        return 0
    ascii_n = _count_ascii(text)
    non_ascii_n = len(text) - ascii_n
    return math.ceil(ascii_n / ASCII_CHARS_PER_TOKEN
                     + non_ascii_n / NON_ASCII_CHARS_PER_TOKEN)


def est_tokens(text, safety_factor=None):
    """トークン数の概算（安全率込み）。

    ローカルトークナイザーが利用可能ならそれを使う（安全率も適用する。
    実測と概算のどちらでも「見積りが実測を下回らない」ことを優先する）。
    """
    if not text:
        return 0
    if safety_factor is None:
        try:
            from budget_profile import active_profile
            safety_factor = active_profile().token_estimate_safety_factor
        except Exception:
            safety_factor = 1.15

    tok = _get_tokenizer()
    if tok is not None:
        try:
            n = len(tok.encode(text, add_special_tokens=False))
            return math.ceil(n * safety_factor)
        except Exception:
            pass
    return math.ceil(est_tokens_raw(text) * safety_factor)


# ─────────────────────────────────────────────────────────────
# コンテキスト予算
# ─────────────────────────────────────────────────────────────
def input_budget(max_tokens, fixed_tokens, margin=None):
    """入力に使えるトークン予算。負値は設定不整合。"""
    if margin is None:
        margin = CHUNK_SAFETY_MARGIN
    return MAX_MODEL_LEN - max_tokens - margin - fixed_tokens


def is_context_length_error(exc_or_msg):
    """vLLM/OpenAI 互換 API の context length 超過を検出する。

    context_length_exceeded は同一入力を再送しても必ず失敗するため、
    transport retry の対象にせず、入力分割 / oversize 縮退へ回す
    （v3.69-rc2 / 指示4）。
    """
    s = str(exc_or_msg).lower()
    keys = ("context_length_exceeded", "maximum context length",
            "context length", "longer than the maximum",
            "reduce the length of the messages",
            "please reduce the length")
    return any(k in s for k in keys)
