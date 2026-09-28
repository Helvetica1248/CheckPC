#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vt_post.py
analyzed.json のエントリから IOC（ハッシュ / 外部IP / FQDN）を抽出し、
VirusTotal API v3 に並列投入してスコアを補正するポスト処理モジュール。

.env ファイル（python-dotenv 不要、標準ライブラリのみ）:
  探索順: スクリプトと同じディレクトリ → 1つ上 → ホームディレクトリ
  記法例 (analysis/.env):
    VT_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    VT_PROXY=http://user:pass@10.110.130.101:8486
    # VT_RATE_DELAY=0.0
    # VT_WORKERS=4

Usage:
    python vt_post.py <analyzed.json>          # .env を自動読み込み
    python vt_post.py analyzed.json --dry-run  # IOC確認のみ
    python vt_post.py analyzed.json --api-key xxxx --proxy http://...  # CLI引数優先
"""

import re
import sys
import json
import os
import time
import argparse
import ipaddress
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


# ─────────────────────────────────────────────────────────────
# .env ローダー（python-dotenv 不要）
# ─────────────────────────────────────────────────────────────
def load_dotenv_simple(start_dir: str = None) -> dict:
    """
    .env ファイルを探索して読み込み、os.environ に反映する。
    既に os.environ に設定済みの変数は上書きしない（CLI 引数・シェル変数が優先）。

    探索順:
      1. start_dir/.env   （スクリプトと同じフォルダ）
      2. start_dir/../.env（リポジトリルート想定）
      3. ~/.env           （ホームディレクトリ）

    .env の書式:
      KEY=value / KEY="value" / KEY='value' / # comment / 空行
    """
    if start_dir is None:
        start_dir = os.path.dirname(os.path.abspath(__file__))

    candidates = [
        os.path.join(start_dir, ".env"),
        os.path.join(start_dir, "..", ".env"),
        os.path.expanduser("~/.env"),
    ]

    for path in candidates:
        path = os.path.normpath(path)
        if not os.path.isfile(path):
            continue
        loaded = {}
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, val = line.partition("=")
                    key = key.strip()
                    val = val.strip()
                    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                        val = val[1:-1]
                    if key and key not in os.environ:
                        os.environ[key] = val
                        loaded[key] = val
        except OSError:
            continue

        if loaded:
            # Never log .env values.  Key-name heuristics are insufficient for
            # secrets embedded in proxy URLs, hashes, cookies, authorization
            # headers, or future configuration names.  Logging sorted key names
            # preserves startup diagnostics without exposing credentials.
            loaded_keys = sorted(loaded)
            print(f"  [.env] {path} → loaded_keys={loaded_keys}")
        return loaded  # 最初に見つかったファイルのみ読む

    return {}


# ─────────────────────────────────────────────────────────────
# 定数
# ─────────────────────────────────────────────────────────────
VT_BASE_URL           = "https://www.virustotal.com/api/v3"
VT_POSITIVE_THRESHOLD = 3
VT_RATE_LIMIT_DELAY   = 0.0    # Enterprise: 0.0、無料: 16.0
VT_REQUEST_TIMEOUT    = 30
MAX_WORKERS           = 4      # Enterprise: 4、無料: 1

SCORE_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "CLEAN": 3}

# ファイルパス型IOCのVT名前検索でスキップする既知正規ファイル名
# （結果が大量すぎて意味をなさない、または正規ツールとして確定済みのもの）
_SKIP_FILEPATH_VT = {
    # Windows 標準LoLBAS（正規利用と悪用が混在、ファイル名だけでは判定不能）
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "msiexec.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe",
    "cmd.exe", "wmic.exe", "bitsadmin.exe", "schtasks.exe",
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    # Windows 標準コマンド
    "explorer.exe", "svchost.exe", "lsass.exe", "services.exe",
    "winlogon.exe", "taskhost.exe", "taskhostw.exe", "conhost.exe",
    "csrss.exe", "smss.exe", "wininit.exe", "spoolsv.exe",
    "ipconfig.exe", "net.exe", "netstat.exe", "tasklist.exe",
    "sc.exe", "reg.exe", "ping.exe", "nslookup.exe",
    # 正規セキュリティソフトの既知ファイル名
    "malwarebytes.exe", "mbamservice.exe", "mbamtray.exe",
    "mbbr.exe", "mb5uns.exe", "mbamwsc.exe",
    # Firefox / Chrome / Edge
    "firefox.exe", "chrome.exe", "msedge.exe",
}

# VT ファイル名検索の結果件数上限（多すぎる名前は汎用すぎてスキップ）
VT_FILESEARCH_LIMIT   = 5   # 取得件数
VT_FILESEARCH_MAX_HIT = 500  # これ以上ヒットしたら汎用名として判定不能→スキップ

VT_STATUS_KEYS = (
    "malicious", "suspicious", "clean", "not_found",
    "too_many_hits", "error", "not_queried",
)


def _empty_status_counts() -> dict:
    return {key: 0 for key in VT_STATUS_KEYS}

# ─────────────────────────────────────────────────────────────
# IOC 分類
# ─────────────────────────────────────────────────────────────
# v3.68: 分類・正規化・パターン・スキップリストは ioc_utils.py へ移設し、
# analyze_section.py（Defender 決定論 IOC 抽出）と共通化した。
# 移設前の挙動は test_v368_ioc_utils.py の golden fixture で固定してある
# （ロジック変更なし）。下記の別名は既存コード・既存テストの後方互換用。
from ioc_utils import (
    classify_ioc as _classify_ioc,
    normalize_ioc as _normalize_ioc,
    is_private_ip, is_known_infra_fqdn, should_query_vt,
    extract_evidence_iocs,
    _SHA256_RE, _MD5_RE, _SHA1_RE, _IPV4_BARE, _FQDN_RE,
    _VALID_TLDS, _is_valid_tld, _KNOWN_FILE_EXTS, _PRIVATE_NETS,
    _SKIP_FQDN_SUFFIXES, _SKIP_FQDN_EXACT,
)


# ─────────────────────────────────────────────────────────────
# VT API 呼び出し
# ─────────────────────────────────────────────────────────────
def _vt_get(endpoint: str, api_key: str, proxies: Optional[dict],
            timeout: float = VT_REQUEST_TIMEOUT) -> dict:
    url = f"{VT_BASE_URL}/{endpoint}"
    try:
        resp = requests.get(
            url,
            headers={"x-apikey": api_key},
            proxies=proxies,
            timeout=timeout,
        )
        if resp.status_code == 404:
            return {"_vt_error": "not_found", "status_code": 404}
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After", "")
            try:
                retry_after = float(retry_after) if retry_after else 0.0
            except (TypeError, ValueError):
                retry_after = 0.0
            return {"_vt_error": "rate_limited", "status_code": 429,
                    "retry_after": retry_after}
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.Timeout:
        return {"_vt_error": "timeout", "status_code": 0}
    except requests.exceptions.ProxyError as e:
        return {"_vt_error": f"proxy_error: {e}", "status_code": 0}
    except requests.exceptions.RequestException as e:
        return {"_vt_error": str(e), "status_code": 0}


def _vt_search_by_name(basename: str, api_key: str,
                       proxies: Optional[dict],
                       timeout: float = VT_REQUEST_TIMEOUT) -> dict:
    """
    VT Intelligence Search（Enterprise専用）でファイル名検索し、
    代表的なレポートを返す。

    返り値: {
        "total_hits": int,        # 総ヒット数
        "representative": dict,   # 最多検知数のファイル attrs（なければ {}）
        "sha256": str,
        "positives": int,
        "total": int,
        "verdict": str,
        "vt_names": list,
        "vt_url": str,
        "vt_error": str,
    }
    """
    url = f"{VT_BASE_URL}/intelligence/search"
    # ファイル名の特殊文字（[ ] : 等。IEキャッシュの "name[1].dll" など）が
    # VT検索クエリを壊し 400 になるため、name 値を二重引用符で囲んで完全一致検索にする。
    # 埋め込みの二重引用符は除去（クエリ破壊防止）。
    safe_name = basename.replace('"', "").strip()
    query = f'name:"{safe_name}"'
    req_params = {"query": query, "limit": VT_FILESEARCH_LIMIT}
    try:
        resp = requests.get(
            url,
            params=req_params,
            headers={"x-apikey": api_key},
            proxies=proxies,
            timeout=timeout,
        )
        if resp.status_code == 403:
            # Enterprise 契約がない場合
            return {"vt_error": "intelligence_search_forbidden(403): Enterprise契約が必要",
                    "total_hits": 0, "verdict": "error", "positives": 0, "total": 0,
                    "vt_names": [], "vt_url": "", "sha256": ""}
        if resp.status_code in (400, 404, 422):
            # 400=クエリ不正（特殊文字残り等）。filepath名前検索は参考値のため
            # error にせず not_found 扱いで穏当に処理（レポートを汚さない）。
            return {"vt_error": "not_found", "total_hits": 0,
                    "verdict": "unknown", "positives": 0, "total": 0,
                    "vt_names": [], "vt_url": "", "sha256": ""}
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as e:
        return {"vt_error": str(e), "total_hits": 0,
                "verdict": "error", "positives": 0, "total": 0,
                "vt_names": [], "vt_url": "", "sha256": ""}

    meta = data.get("meta", {})
    # /intelligence/search は meta.count、旧 /files は meta.total_hits
    total_hits = meta.get("count", meta.get("total_hits", len(data.get("data", []))))
    items = data.get("data", [])

    if total_hits > VT_FILESEARCH_MAX_HIT:
        reason = f"hits={total_hits}>max({VT_FILESEARCH_MAX_HIT})"
        return {"vt_error": reason, "total_hits": total_hits,
                "verdict": "too_many_hits", "positives": 0, "total": 0,
                "vt_names": [], "vt_url": "", "sha256": ""}

    if not items:
        reason = "no_results"
        return {"vt_error": reason, "total_hits": total_hits,
                "verdict": "unknown", "positives": 0, "total": 0,
                "vt_names": [], "vt_url": "", "sha256": ""}

    # 最多検知数のエントリを代表として選択
    def get_positives(item):
        stats = item.get("attributes", {}).get("last_analysis_stats", {})
        return stats.get("malicious", 0) + stats.get("suspicious", 0)

    best = max(items, key=get_positives)
    attrs = best.get("attributes", {})
    sha256 = best.get("id", attrs.get("sha256", ""))
    stats = attrs.get("last_analysis_stats", {})
    positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total     = sum(stats.values())
    results   = attrs.get("last_analysis_results", {})
    vt_names  = [
        f"{eng}:{res.get('result','?')}"
        for eng, res in list(results.items())
        if res.get("category") in ("malicious", "suspicious")
    ][:3]

    if positives >= VT_POSITIVE_THRESHOLD:
        verdict = "malicious"
    elif positives > 0:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "total_hits": total_hits,
        "sha256":     sha256,
        "positives":  positives,
        "total":      total,
        "verdict":    verdict,
        "vt_names":   vt_names,
        "vt_url":     f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else "",
        "vt_error":   "",
    }


def _parse_vt_result(ioc_type: str, vt_data: dict) -> dict:
    if "_vt_error" in vt_data:
        err = vt_data["_vt_error"]
        return {
            "positives": 0, "total": 0,
            "verdict": "unknown" if err == "not_found" else "error",
            "vt_names": [], "vt_url": "",
            "vt_error": "VT未登録" if err == "not_found" else err,
            "retry_after": vt_data.get("retry_after", 0),
        }

    attrs = vt_data.get("data", {}).get("attributes", {})
    vid   = vt_data.get("data", {}).get("id", "")
    stats = attrs.get("last_analysis_stats", {})
    positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total     = sum(stats.values())
    results   = attrs.get("last_analysis_results", {})
    vt_names  = [
        f"{eng}:{res.get('result','?')}"
        for eng, res in list(results.items())
        if res.get("category") in ("malicious", "suspicious")
    ][:3]

    url_map = {
        "hash": f"https://www.virustotal.com/gui/file/{vid}",
        "ip":   f"https://www.virustotal.com/gui/ip-address/{vid}",
        "fqdn": f"https://www.virustotal.com/gui/domain/{vid}",
    }
    verdict = ("malicious" if positives >= VT_POSITIVE_THRESHOLD
               else "suspicious" if positives > 0
               else "clean")
    return {
        "positives": positives, "total": total, "verdict": verdict,
        "vt_names": vt_names, "vt_url": url_map.get(ioc_type, ""), "vt_error": "",
    }


def lookup_ioc(ioc_value: str, api_key: str,
               proxies: Optional[dict] = None,
               rate_delay: float = VT_RATE_LIMIT_DELAY,
               ioc_type: Optional[str] = None,
               timeout: float = VT_REQUEST_TIMEOUT) -> dict:
    """
    単一 IOC を VT に照合。
    - IP:port 形式はポートを除いて照合する。
    - filepath 型はファイル名検索（VT Intelligence Search /intelligence/search?query=name:）で照合する。
    - ioc_type を明示指定することで _normalize_ioc 後の basename でも正しく照合できる。
      （basename はパス区切りを含まないため _classify_ioc が None を返してしまうため）
    """
    if ioc_type is None:
        ioc_type = _classify_ioc(ioc_value)
    if ioc_type is None:
        return {"ioc": ioc_value, "skipped": True}
    if rate_delay > 0:
        time.sleep(rate_delay)

    # filepath: ファイル名検索
    if ioc_type == "filepath":
        # Linux 上で Windows パスの basename を正しく取得する
        _path = ioc_value.strip().replace("/", "\\")
        basename = _path.split("\\")[-1].lower()
        result = _vt_search_by_name(basename, api_key, proxies, timeout=timeout)
        result["ioc"]      = ioc_value
        result["ioc_type"] = ioc_type
        return result

    # IP:port → ポート除去
    lookup_val = ioc_value.strip()
    if ioc_type == "ip" and ":" in lookup_val:
        lookup_val = lookup_val.rsplit(":", 1)[0]

    endpoint_map = {
        "hash": f"files/{lookup_val.lower()}",
        "ip":   f"ip_addresses/{lookup_val}",
        "fqdn": f"domains/{lookup_val.rstrip('.')}",
    }
    raw    = _vt_get(endpoint_map[ioc_type], api_key, proxies, timeout=timeout)
    result = _parse_vt_result(ioc_type, raw)
    result["ioc"]      = ioc_value
    result["ioc_type"] = ioc_type
    return result


# ─────────────────────────────────────────────────────────────
# IOC 抽出
# ─────────────────────────────────────────────────────────────

def extract_iocs_from_analyzed(analyzed_json: dict,
                                min_score: str = "MEDIUM") -> dict:
    """
    analyzed.json の HIGH/MEDIUM エントリの iocs を抽出。
    返り値: {正規化IOC値: {ioc_type, found_in: [{section, entry_idx, identifier, score}]}}

    IP:port と IP 単体が混在する場合（LLM が両形式を iocs に出力することがある）は
    ポートを除去した IP をキーとして重複排除し、VT 照会を1回にまとめる。
    """
    min_idx = SCORE_ORDER.get(min_score, 1)
    ioc_map = {}
    for sec_name, sec_data in analyzed_json.get("sections", {}).items():
        if not isinstance(sec_data, dict):
            continue
        for idx, entry in enumerate(sec_data.get("entries", [])):
            if not isinstance(entry, dict):
                continue
            if SCORE_ORDER.get(entry.get("score", "CLEAN"), 3) > min_idx:
                continue
            for ioc_val in entry.get("iocs", []):
                if not ioc_val or not isinstance(ioc_val, str):
                    continue
                ioc_val = ioc_val.strip()
                ioc_type = _classify_ioc(ioc_val)
                if ioc_type is None:
                    continue
                # IP:port → IP に正規化してキーとする
                norm_key = _normalize_ioc(ioc_val, ioc_type)
                if norm_key not in ioc_map:
                    ioc_map[norm_key] = {"ioc_type": ioc_type, "found_in": []}
                ioc_map[norm_key]["found_in"].append({
                    "section":    sec_name,
                    "entry_idx":  idx,
                    "identifier": entry.get("identifier", ""),
                    "score":      entry.get("score", "CLEAN"),
                })
    return ioc_map


# ─────────────────────────────────────────────────────────────
# スコア補正
# ─────────────────────────────────────────────────────────────
def apply_vt_score(current_score: str, vt_result: dict,
                   ioc_type: Optional[str] = None) -> tuple:
    """
    返り値: (new_score, changed, note)
    補正ルール:
      hash / ip / fqdn:
        malicious (≥ threshold) → HIGH 昇格（現スコアがHIGH未満のみ）
        clean (0件)             → 注記のみ（スコアは変更しない）
        suspicious / unknown / error → スコア変更なし、注記のみ

      filepath:
        スコア変更なし・注記のみ（昇格・降格どちらも行わない）
        理由: filepath 照合は /intelligence/search によるファイル名一致検索であり、
        実際にホスト上に存在するファイルのハッシュは検証していない。
        VT 上に同名の悪性ファイルが存在するだけで malicious と判定されるため、
        スコア昇格の根拠として信頼性が不十分（False Positive のリスクが高い）。
    """
    verdict  = vt_result.get("verdict", "error")
    pos      = vt_result.get("positives", 0)
    total    = vt_result.get("total", 0)
    vt_names = vt_result.get("vt_names", [])
    vt_url   = vt_result.get("vt_url", "")

    # filepath: ハッシュ未検証のため昇格・降格ともに行わず注記のみ
    if ioc_type == "filepath":
        if verdict == "malicious":
            note = (f"[要手動確認] 同名ファイルVT検知: {pos}/{total}"
                    f" ({', '.join(vt_names[:2])})" if vt_names
                    else f"[要手動確認] 同名ファイルVT検知: {pos}/{total}")
            note += " ※ファイル名一致による参考値。実ファイルのハッシュ照合が必要"
        elif verdict == "suspicious":
            note = (f"[参考] 同名ファイルVT要注意: {pos}/{total}"
                    f" ({', '.join(vt_names[:2])})")
        elif verdict == "clean":
            note = f"[参考] 同名ファイルVTクリーン: {pos}/{total}"
        elif verdict == "unknown":
            note = "[参考] 同名ファイルVT未登録"
        elif verdict == "too_many_hits":
            hits = int(vt_result.get("total_hits", 0) or 0)
            note = (f"[参考] 同名候補過多: {hits}件。"
                    "代表ファイルを安全に特定できないため判定不能")
        else:
            note = f"[参考] VTエラー: {vt_result.get('vt_error', '?')}"
        if vt_url:
            note += f" → {vt_url}"
        return current_score, False, note

    if verdict == "malicious":
        new_score = "HIGH" if SCORE_ORDER.get(current_score, 3) > 0 else current_score
        changed   = new_score != current_score
        note = (f"VT検知: {pos}/{total} ({', '.join(vt_names[:2])})" if vt_names
                else f"VT検知: {pos}/{total}")
    elif verdict == "clean":
        new_score, changed = current_score, False
        note = (f"VT照合時点で malicious 判定なし ({pos}/{total})。"
                "標的型・新規検体の偽陰性を考慮しスコアは維持")
    elif verdict == "suspicious":
        new_score, changed = current_score, False
        note = f"VT要注意: {pos}/{total} ({', '.join(vt_names[:2])})"
    elif verdict == "unknown":
        new_score, changed = current_score, False
        note = "VT未登録: スコア変更なし（要手動確認）"
    else:
        new_score, changed = current_score, False
        note = f"VTエラー: {vt_result.get('vt_error', '?')}"

    if vt_url:
        note += f" → {vt_url}"
    return new_score, changed, note


# ─────────────────────────────────────────────────────────────
# メイン処理
# ─────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────
# [2] VT必須条件付き HIGH→MEDIUM 降格（提案A）
#   クリーン端末の嫌疑を HIGH に押し上げる per-user/Temp 配置の正規ソフト
#   （HWiNFO/Baidu/Wondershare 等）と Office スタートアップ・アドイン
#   （Zotero 等）を、以下を すべて 満たす場合のみ MEDIUM へ降格する。
#     C1. 対象セクション（system_7045 / startup_folder）の HIGH
#     C2. パスが既知ベンダ/アドインの allowlist に一致
#     C3. VT 実行済み かつ 当該エントリの VT verdict が malicious でない
#   本関数は vt_enrich 内（＝VT実行時）でのみ呼ばれるため C3 の「VT必須」を満たす。
#   VT-clean は良性の積極証拠に使わず、malicious を降格拒否のゲートにのみ用いる
#   （ファイル名検索の限界を踏まえた安全側設計）。降格幅は MEDIUM 止まり。
# ─────────────────────────────────────────────────────────────
# per-user/Temp 配置の既知ベンダ実行体（system_7045 HIGH の降格対象）
_VT2_SVC_VENDOR_RE = re.compile(
    r"(?:"
    r"HWiNFO|"                                          # HWiNFO（ハード監視。Temp展開ドライバ）
    r"\\baidu\\|\\BaiduNetdisk\\|"                       # Baidu NetDisk
    r"\\Wondershare|"                                    # Wondershare（Filmora 等）
    r"\\Kingsoft\\|"                                     # WPS Office
    r"\\Google\\(?:Update|Chrome|GoogleUpdater)\\|"
    r"\\Microsoft\\(?:OneDrive|Teams|EdgeUpdate)\\|"
    r"\\Dropbox\\|\\Adobe\\|\\Zoom\\|\\Discord\\|\\Slack\\"
    r")",
    re.I,
)
# 既知の Office スタートアップ・アドイン（startup_folder office_startup HIGH の降格対象）
_VT2_OFFICE_ADDIN_RE = re.compile(
    r"\\(?:Zotero|Mendeley|EndNote|Grammarly|PDFMaker|AcrobatPDFMaker|"
    r"NitroPDF|SolidWorks|Wordfast|Trados|EndNoteCwyw|ChemDraw)"
    r"[^\\]*\.(?:dotm?|xlam|xla|ppam|xlsm)$",
    re.I,
)
# per-user/Temp 配置か（system_7045 降格の前提。System32等の正規配置は対象外）
_VT2_PERUSER_LOC_RE = re.compile(r"\\(?:AppData|Temp|Users)\\", re.I)


def _entry_has_malicious_vt(entry: dict) -> bool:
    """エントリの VT 結果に malicious verdict が1つでもあるか。"""
    for r in entry.get("_vt_results", []) or []:
        if r.get("verdict") == "malicious":
            return True
    return False


def apply_peruser_high_downgrade(result: dict) -> int:
    """[2] 既知ベンダの per-user/Temp サービス・Office アドインの HIGH を
    「VT実行済み かつ malicious でない かつ VT照合済み」を条件に MEDIUM 降格する。

    戻り値: 降格した件数。VT malicious / VT未照合(該当エントリに_vt_results無し)は
    降格せず HIGH を維持する（取りこぼし防止・保守側）。
    """
    downgraded = 0
    targets = (("system_7045", False), ("startup_folder", True))
    for sec_name, addin_mode in targets:
        sd = result.get("sections", {}).get(sec_name)
        if not isinstance(sd, dict):
            continue
        for entry in sd.get("entries", []) or []:
            if not isinstance(entry, dict) or entry.get("score") != "HIGH":
                continue
            path = (entry.get("iocs") or [""])[0] or entry.get("identifier", "")
            # C2: allowlist 一致
            if addin_mode:
                if not _VT2_OFFICE_ADDIN_RE.search(path):
                    continue
            else:
                if not (_VT2_PERUSER_LOC_RE.search(path)
                        and _VT2_SVC_VENDOR_RE.search(path)):
                    continue
            # C3: VT 実行済み（このエントリが実際に VT 照合されている）かつ malicious でない
            vt_res = entry.get("_vt_results", []) or []
            if not vt_res:
                continue                      # VT未照合（生成名等）→ 確認不能のため降格しない
            if _entry_has_malicious_vt(entry):
                continue                      # VT malicious → 降格しない（安全側）
            # 降格実行（HIGH→MEDIUM 止まり）
            kind = "Officeアドイン" if addin_mode else "per-user/Temp配置の既知ベンダサービス"
            entry["score"] = "MEDIUM"
            entry["reason"] = (
                f"[VT-gated降格 HIGH→MEDIUM] {kind}（allowlist一致・VT検知なし）。"
                f"元reason: {entry.get('reason', '')}"
            )
            downgraded += 1
    return downgraded


def vt_enrich(analyzed_json: dict,
              api_key: str,
              proxies: Optional[dict] = None,
              min_score: str = "MEDIUM",
              rate_delay: float = VT_RATE_LIMIT_DELAY,
              max_workers: int = MAX_WORKERS,
              verbose: bool = False) -> dict:
    """analyzed.json を受け取り VT 照合でスコアを補正した dict を返す。"""
    import copy
    result   = copy.deepcopy(analyzed_json)
    t_start  = time.time()
    hostname = result.get("meta", {}).get("hostname", "UNKNOWN")
    print(f"[{hostname}] VT ポスト処理開始")

    ioc_map = extract_iocs_from_analyzed(result, min_score=min_score)
    if not ioc_map:
        print(f"  照合対象 IOC なし")
        result["_vt_summary"] = {
            "total_iocs": 0,
            "exact_total_iocs": 0,
            "filepath_total_iocs": 0,
            "status_counts": _empty_status_counts(),
            "exact_status_counts": _empty_status_counts(),
            "filepath_status_counts": _empty_status_counts(),
            "elapsed_sec": 0,
        }
        return result

    print(f"  照合対象 IOC: {len(ioc_map)} 件")
    if verbose:
        for v, info in ioc_map.items():
            locs = [(f["section"], f["score"]) for f in info["found_in"]]
            print(f"    [{info['ioc_type']}] {v[:60]} in {locs}")

    vt_results = {}

    def _lookup_one(ioc_val: str) -> tuple:
        # ioc_map のキーは normalize 後（basename 等）なので ioc_type を明示渡し
        ioc_type = ioc_map[ioc_val]["ioc_type"]
        return ioc_val, lookup_ioc(ioc_val, api_key, proxies, rate_delay, ioc_type)

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_lookup_one, v): v for v in ioc_map}
        done = 0
        for future in as_completed(futures):
            ioc_val, vt_r = future.result()
            vt_results[ioc_val] = vt_r
            done += 1
            if verbose or done % 5 == 0:
                print(f"  [{done}/{len(ioc_map)}] {ioc_val[:50]:50s}"
                      f" → {vt_r.get('verdict','?')} ({vt_r.get('positives',0)})")

    summary = {
        "total_iocs":              len(ioc_map),
        "malicious":               0,   # hash/ip/fqdn のみ（実ハッシュ照合）
        "clean_downgraded":        0,
        "high_upgraded":           0,
        "suspicious_noted":        0,
        "errors":                  0,
        "not_found":               0,
        "filepath_searched":       0,   # filepath VT 照合試行数
        "filepath_skipped_generic":0,   # hits超過などでスキップした数
        "filepath_too_many_hits":  0,   # 候補過多で代表値を確定できなかった数
        "filepath_malicious_noted":0,   # filepath で同名悪性ファイルが見つかった数（参考値、スコア変更なし）
        "exact_total_iocs":        sum(
            1 for info in ioc_map.values() if info.get("ioc_type") != "filepath"),
        "filepath_total_iocs":     sum(
            1 for info in ioc_map.values() if info.get("ioc_type") == "filepath"),
        # rc14: IOC型を問わない一意照合対象単位の状態。レポートはこの値から
        # clean/error/not_found/not_queriedを明示し、未確認をcleanと表示しない。
        "status_counts": _empty_status_counts(),
        # rc15: hash/IP/FQDNの正確照合と、filepathのファイル名参考検索を
        # 別集計にする。レポート上で両者を合算して悪性件数を見せない。
        "exact_status_counts": _empty_status_counts(),
        "filepath_status_counts": _empty_status_counts(),
    }

    for ioc_val, vt_r in vt_results.items():
        if vt_r.get("skipped"):
            summary["status_counts"]["not_queried"] += 1
            scope = (summary["filepath_status_counts"]
                     if vt_r.get("ioc_type") == "filepath"
                     else summary["exact_status_counts"])
            scope["not_queried"] += 1
            continue
        v = vt_r.get("verdict", "error")
        status_key = {
            "malicious": "malicious",
            "suspicious": "suspicious",
            "clean": "clean",
            "unknown": "not_found",
            "too_many_hits": "too_many_hits",
            "error": "error",
        }.get(v, "error")
        summary["status_counts"][status_key] += 1
        is_filepath = vt_r.get("ioc_type") == "filepath"
        scope = (summary["filepath_status_counts"]
                 if is_filepath else summary["exact_status_counts"])
        scope[status_key] += 1
        if is_filepath:
            # filepath は参考値（スコア変更なし）なので malicious カウントには含めない
            if v == "too_many_hits":
                summary["filepath_skipped_generic"] += 1
                summary["filepath_too_many_hits"] += 1
            elif vt_r.get("vt_error") == "no_results":
                summary["filepath_skipped_generic"] += 1
            else:
                summary["filepath_searched"] += 1
                if v == "malicious":
                    summary["filepath_malicious_noted"] += 1
        else:
            # hash / ip / fqdn: 実ハッシュ照合なので malicious は信頼できる
            summary["errors"]           += v == "error"
            summary["not_found"]        += v == "unknown"
            summary["malicious"]        += v == "malicious"
            summary["suspicious_noted"] += v == "suspicious"

        for loc in ioc_map[ioc_val]["found_in"]:
            entries = result["sections"][loc["section"]]["entries"]
            if loc["entry_idx"] >= len(entries):
                continue
            entry = entries[loc["entry_idx"]]
            old_score = entry.get("score", "CLEAN")
            new_score, changed, note = apply_vt_score(old_score, vt_r,
                                                       ioc_type=vt_r.get("ioc_type"))

            # 複数 IOC が同一エントリを指す場合の書き込みルール:
            #   昇格（malicious→HIGH）: より深刻な方向を優先
            #   降格（clean→LOW）:      changed=True のときのみ書き込む（条件は独立）
            # 旧実装は「SCORE_ORDER < existing」（数値小＝HIGH寄り）のみで判定していたため
            # LOW(2) < MEDIUM(1) が False となり clean 降格が書き込まれないバグがあった。
            existing = entry.get("_vt_score", old_score)
            existing_order = SCORE_ORDER.get(existing, 3)
            new_order = SCORE_ORDER.get(new_score, 3)
            if new_order < existing_order:
                # 昇格方向（悪性判定）は常に上書き
                entry["_vt_score"] = new_score
            elif changed and "_vt_score" not in entry:
                # 降格方向（clean判定）は他のIOCで昇格済みでない場合のみ書き込む
                entry["_vt_score"] = new_score

            if "_vt_results" not in entry:
                entry["_vt_results"] = []
            entry["_vt_results"].append({
                "ioc": ioc_val, "ioc_type": vt_r.get("ioc_type", "?"),
                "verdict": v, "positives": vt_r.get("positives", 0),
                "total": vt_r.get("total", 0), "vt_names": vt_r.get("vt_names", []),
                "total_hits": vt_r.get("total_hits", 0),
                "vt_url": vt_r.get("vt_url", ""), "vt_error": vt_r.get("vt_error", ""),
                "note": note,
            })

    for sec_data in result["sections"].values():
        if not isinstance(sec_data, dict):
            continue
        for entry in sec_data.get("entries", []):
            if not isinstance(entry, dict) or "_vt_score" not in entry:
                continue
            old, new = entry["score"], entry.pop("_vt_score")
            if old != new:
                # filepath はスコア変更なし（changed=False 固定）なので加算されないが念のため型を明示
                summary["high_upgraded"]     += new == "HIGH"
                summary["clean_downgraded"]  += new == "LOW" and old == "MEDIUM"
            entry["score"] = new

    # [2] 既知ベンダの per-user/Temp サービス・Office アドインの HIGH を
    #     VT-not-malicious を条件に MEDIUM 降格（VT実行時のみ・提案A）
    summary["peruser_high_downgraded"] = apply_peruser_high_downgrade(result)

    elapsed = round(time.time() - t_start, 2)
    summary["elapsed_sec"] = elapsed
    result["_vt_summary"] = summary
    print(f"  VT 完了 ({elapsed:.1f}秒): "
          f"悪性={summary['malicious']} HIGH昇格={summary['high_upgraded']} "
          f"LOW降格={summary['clean_downgraded']} "
          f"per-user降格={summary['peruser_high_downgraded']} "
          f"未登録={summary['not_found']} 候補過多={summary['filepath_too_many_hits']} "
          f"エラー={summary['errors']}")
    return result


# ─────────────────────────────────────────────────────────────
# エントリポイント
# ─────────────────────────────────────────────────────────────
def main():
    # ★ .env 読み込みを argparse より先に実行（default= 評価前に os.environ を確定させる）
    load_dotenv_simple()

    ap = argparse.ArgumentParser(
        description="analyzed.json に VT 照合結果を付与してスコアを補正する"
    )
    ap.add_argument("input", help="analyze_section.py の出力 JSON パス")
    ap.add_argument("-o", "--output", help="出力 JSON（省略時: *_vt.json）")
    ap.add_argument("--api-key",
                    default=os.environ.get("VT_API_KEY", ""),
                    help="VT API キー（.env/環境変数 VT_API_KEY でも可）")
    ap.add_argument("--proxy",
                    default=os.environ.get("VT_PROXY",
                            os.environ.get("HTTPS_PROXY",
                            os.environ.get("HTTP_PROXY", ""))),
                    help="プロキシ URL（.env の VT_PROXY または環境変数でも可）")
    ap.add_argument("--min-score", default="MEDIUM", choices=["HIGH", "MEDIUM"])
    ap.add_argument("--rate-delay", type=float,
                    default=float(os.environ.get("VT_RATE_DELAY", str(VT_RATE_LIMIT_DELAY))))
    ap.add_argument("--workers", type=int,
                    default=int(os.environ.get("VT_WORKERS", str(MAX_WORKERS))))
    ap.add_argument("--dry-run", action="store_true",
                    help="IOC 抽出のみ（VT 照合なし）")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.input):
        print(f"[ERROR] ファイルが見つかりません: {args.input}", file=sys.stderr)
        sys.exit(1)
    if not args.api_key and not args.dry_run:
        print("[ERROR] VT_API_KEY が未設定です。analysis/.env に VT_API_KEY=... を追加してください",
              file=sys.stderr)
        sys.exit(1)

    with open(args.input, encoding="utf-8") as f:
        analyzed = json.load(f)

    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}
        print(f"  プロキシ: {args.proxy}")

    if args.dry_run:
        ioc_map = extract_iocs_from_analyzed(analyzed, min_score=args.min_score)
        print(f"\n--- dry-run: IOC 抽出結果 ({len(ioc_map)} 件) ---")
        by_type: dict = {"hash": [], "ip": [], "fqdn": [], "filepath": []}
        for v, info in ioc_map.items():
            by_type.get(info["ioc_type"], []).append((v, info["found_in"]))
        for t, items in by_type.items():
            if items:
                print(f"\n[{t}] {len(items)} 件:")
                for v, locs in items:
                    loc_str = ", ".join(f"{l['section']}({l['score']})" for l in locs[:3])
                    print(f"  {v[:64]:64s}  in {loc_str}")
        return

    result = vt_enrich(
        analyzed, api_key=args.api_key, proxies=proxies,
        min_score=args.min_score, rate_delay=args.rate_delay,
        max_workers=args.workers, verbose=args.verbose,
    )

    out_path = args.output or os.path.join(
        os.path.dirname(args.input),
        os.path.basename(args.input).replace(".json", "_vt.json")
    )
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"出力: {out_path}")

    print("\n=== VT 補正後スコアサマリ ===")
    for sec_name, sec_data in result.get("sections", {}).items():
        if not isinstance(sec_data, dict):
            continue
        entries = sec_data.get("entries", [])
        h = sum(1 for e in entries if isinstance(e, dict) and e.get("score") == "HIGH")
        m = sum(1 for e in entries if isinstance(e, dict) and e.get("score") == "MEDIUM")
        if h + m > 0:
            print(f"  {sec_name:25s}: HIGH={h} MEDIUM={m}")


if __name__ == "__main__":
    main()
