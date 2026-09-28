#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
known_infra.py — 既知のクラウド/インフラサービスのIPアドレスを識別する軽量モジュール。

方針（重要）:
  · 「このIPは安全である」という安全性の判定は一切行わない。
    あくまで「このIPはどのサービスに属するか」という事実のみを注記する。
    安全かどうかの最終判断は分析官が行う。
  · クラウド事業者のIPレンジは膨大かつ頻繁に変更されるため、ここでは
    公式に文書化され、長期間安定している「固定IP」のみを対象とする
    （包括的なIPレピュテーションDBを目指すものではない）。
"""
import re

# 既知のクラウド/インフラ基盤の固定IP（判定ではなく識別のみ）。
# 出典: 各サービスの公式ドキュメントに記載された固定IP。
_KNOWN_INFRA_IPS = {
    "168.63.129.16":   "Azure（プラットフォームIP/Wireserver）",
    "169.254.169.254": "クラウドメタデータサービス（Azure/AWS/GCP等で共通利用）",
    "8.8.8.8":         "Google Public DNS",
    "8.8.4.4":         "Google Public DNS",
    "1.1.1.1":         "Cloudflare Public DNS",
    "1.0.0.1":         "Cloudflare Public DNS",
    "9.9.9.9":         "Quad9 Public DNS",
    "208.67.222.222":  "OpenDNS (Cisco)",
    "208.67.220.220":  "OpenDNS (Cisco)",
}

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def identify_known_service(text: str) -> str:
    """
    文字列からIPアドレスを抽出し、既知のクラウド/インフラサービスに
    該当する場合はサービス名を返す。該当しなければ空文字列を返す。

    安全性の判定は行わない（識別のみ）。分析官が既知サービスかどうかを
    素早く把握するための注記であり、悪性/良性の自動判定ではない。
    """
    if not text:
        return ""
    m = _IP_RE.search(text)
    if not m:
        return ""
    return _KNOWN_INFRA_IPS.get(m.group(1), "")
