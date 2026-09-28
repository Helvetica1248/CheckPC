#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_analysis.py
CheckPC 出力ファイルを受け取り、以下のフローを一括実行する:
  1. CAB デコード (必要な場合)
  2. parse_checkpc.py  → parsed_*.json
  3. shimcache_parse   → appcompat_cache.csv  (ShimCacheParser.py がある場合)
  4. analyze_section.py → analyzed_*.json
  5. correlate.py      → correlation_*.json
  6. report_gen.py     → report_*.md
  7. vt_post.py        → analyzed_*_vt.json        (--vt-key 指定時のみ)
  8. correlate.py      → correlation_*_vt.json    (VT補正後再解析、--vt-key 指定時のみ)
     report_gen.py     → report_*_vt.md           (VT補正後最終レポート)

Usage:
    # 単一ファイル解析
    python run_analysis.py <CheckPC_*.txt または *.cab> [--depth 1-4] [--output-dir ./output]
    python run_analysis.py <input> --depth 1 --section persistence_reg task_scheduler

    # バッチ解析（フォルダ内の全TXT/CABを順次処理）
    python run_analysis.py --batch <フォルダパス> [--depth 1-4] [--output-dir ./output]
    python run_analysis.py --batch <フォルダパス> --workers 2
"""

import sys
import os
import re
import json
import shutil
import subprocess
import directory_index
import argparse
import time
import textwrap
import tempfile
import uuid
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# PyYAML（--context-file 用）
try:
    import yaml as _yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

# 同一ディレクトリのスクリプトを import できるようにパスを追加
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from parse_checkpc import parse as parse_checkpc_fn
from analyze_section import analyze as analyze_fn
from analyze_section import LEAN_OUTPUT
from correlate import correlate as correlate_fn
from report_gen import generate_report, apply_deterministic_fallback
from timeline import build_timeline_markdown, extract_findings_from_results
from defender_dir_report import build_defender_dir_report
from filepath_whitelist import get_whitelist, apply_whitelist_downgrade
from vt_post import vt_enrich, load_dotenv_simple
from atomic_io import atomic_write_json, atomic_write_text
from ingest_manifest import build_manifest
from pipeline_errors import (PipelineError, DecodeError, VllmUnavailableError,
                             PipelineCancelled)
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION
from path_safety import safe_component, confined_join
from budget_profile import active_profile
from runtime_identity import assert_runtime_identity, assert_artifact_identity
from package_integrity import assert_package_integrity
from comparison_provenance import sha256_file as comparison_sha256_file
from pipeline_settings import runtime_settings, env_int
try:
    from openai import OpenAI
except ImportError:  # テスト/静的監査環境向け。実LLM実行時は依存導入必須。
    class OpenAI:  # pragma: no cover
        def __init__(self, *args, **kwargs):
            raise RuntimeError("openai パッケージが必要です。INSTALL.txt を参照してください。")

DEFAULT_VLLM_URL   = "http://localhost:8000/v1"
DEFAULT_MODEL      = "qwen25-coder-32b-q3"
DEFAULT_DEPTH      = 1   # v3.68: 全モジュールで 1 へ統一（旧=2）

class RunCancelled(PipelineCancelled):
    """後方互換名。解析中断は型付きPipelineCancelledとして伝播する。"""
    pass
BATCHTOOLS_DIR     = "/opt/llm/batchtools"
# ShimCacheParser.py のパス。既定は BATCHTOOLS_DIR 配下だが、配置が異なる環境
# （例: ~/llm/batchtools や analysis 直下）では環境変数で単一パスを明示できる。
#   例: export CHECKPC_SHIMCACHE_PARSER=~/llm/batchtools/ShimCacheParser.py
SHIMCACHE_PARSER   = os.environ.get(
    "CHECKPC_SHIMCACHE_PARSER",
    os.path.join(BATCHTOOLS_DIR, "ShimCacheParser.py"))

DEPTH_LABELS = {1: "Quick", 2: "Standard", 3: "Deep", 4: "Exhaustive"}

# トークン節約のため context 全体の文字数上限（目安）
_CONTEXT_MAX_CHARS = 800
_EXTERNAL_CMD_TIMEOUT_SEC = env_int("CHECKPC_EXTERNAL_CMD_TIMEOUT_SEC", 300, minimum=1, maximum=3600)
_MAX_EXTRACTED_FILES = env_int("CHECKPC_MAX_EXTRACTED_FILES", 20000, minimum=1, maximum=1000000)
_MAX_EXTRACTED_BYTES = env_int("CHECKPC_MAX_EXTRACTED_MB", 8192, minimum=1) * 1024 * 1024


# ─────────────────────────────────────────────────────────────
# YAML コンテキストファイルローダー（T-05）
# ─────────────────────────────────────────────────────────────
def load_context_file(path: str) -> str:
    """
    --context-file で指定された YAML ファイルを読み込み、
    LLM のシステムプロンプトに挿入するテキストを生成して返す。

    YAML スキーマ:
        threat_actor   : 脅威アクター名（文字列）
        malware_family : マルウェアファミリー名（文字列）
        known_c2       : 既知 C2・不審 IP/ドメイン（リスト）
        known_iocs     : 既知 IOC（ハッシュ等）（リスト）
        notes          : 感染経緯・キャンペーン情報（自由記述）

    全フィールドはオプション。未記載フィールドは出力から省略される。
    _CONTEXT_MAX_CHARS を超える場合は警告を出して末尾をトリミングする。
    """
    if not os.path.exists(path):
        print(f"[ERROR] --context-file が見つかりません: {path}", file=sys.stderr)
        sys.exit(1)

    ext = os.path.splitext(path)[1].lower()

    # ── YAML 形式 ────────────────────────────────────────────
    if ext in (".yaml", ".yml"):
        if not _YAML_AVAILABLE:
            print("[ERROR] PyYAML が未インストールです。"
                  "`pip install pyyaml` を実行してください。", file=sys.stderr)
            sys.exit(1)
        with open(path, encoding="utf-8") as f:
            try:
                data = _yaml.safe_load(f) or {}
            except _yaml.YAMLError as e:
                print(f"[ERROR] YAML 解析エラー: {e}", file=sys.stderr)
                sys.exit(1)
        return _yaml_to_context(data, path)

    # ── プレーンテキスト形式（.txt 等）─────────────────────
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read().strip()
    return _trim_context(text, path)


def _yaml_to_context(data: dict, src_path: str) -> str:
    """YAML dict を LLM 注入用テキストに変換する。"""
    if not isinstance(data, dict):
        print(f"[WARN] context-file のトップレベルが dict でありません: {src_path}",
              file=sys.stderr)
        return str(data)[:_CONTEXT_MAX_CHARS]

    lines = []

    # 脅威アクター
    actor = data.get("threat_actor") or data.get("threat-actor") or data.get("actor")
    if actor:
        lines.append(f"脅威アクター: {actor}")

    # マルウェアファミリー
    mw = data.get("malware_family") or data.get("malware-family") or data.get("malware")
    if mw:
        lines.append(f"マルウェア: {mw}")

    # 既知 C2
    c2_list = data.get("known_c2") or data.get("known-c2") or data.get("c2") or []
    if isinstance(c2_list, str):
        c2_list = [c2_list]
    if c2_list:
        lines.append("既知C2/不審先:")
        for item in c2_list:
            lines.append(f"  - {item}")

    # 既知 IOC
    ioc_list = data.get("known_iocs") or data.get("known-iocs") or data.get("iocs") or []
    if isinstance(ioc_list, str):
        ioc_list = [ioc_list]
    if ioc_list:
        lines.append("既知IOC:")
        for item in ioc_list:
            lines.append(f"  - {item}")

    # 自由記述（notes）
    notes = data.get("notes") or data.get("memo") or data.get("comment") or ""
    if notes:
        notes = textwrap.dedent(str(notes)).strip()
        lines.append(f"備考:\n{notes}")

    # 未知キーをフォールバックとして追記（typo救済）
    known_keys = {
        "threat_actor", "threat-actor", "actor",
        "malware_family", "malware-family", "malware",
        "known_c2", "known-c2", "c2",
        "known_iocs", "known-iocs", "iocs",
        "notes", "memo", "comment",
    }
    for key, val in data.items():
        if key not in known_keys and val:
            lines.append(f"{key}: {val}")

    text = "\n".join(lines)
    return _trim_context(text, src_path)


def _trim_context(text: str, src_path: str) -> str:
    """_CONTEXT_MAX_CHARS を超えていたら警告してトリミング。"""
    if not text.strip():
        print(f"[WARN] context-file に有効な内容がありません: {src_path}",
              file=sys.stderr)
        return ""
    if len(text) > _CONTEXT_MAX_CHARS:
        print(f"[WARN] context-file のテキストが {len(text)} 文字あります。"
              f"{_CONTEXT_MAX_CHARS} 文字にトリミングします。"
              f"（トークン節約のため。超過分を含めたい場合は notes を分割してください）",
              file=sys.stderr)
        text = text[:_CONTEXT_MAX_CHARS] + "\n（以下省略）"
    return text


# ─────────────────────────────────────────────────────────────
# CAB デコード
# ─────────────────────────────────────────────────────────────
def _validate_extracted_tree(extract_dir: str) -> tuple[int, int]:
    """Reject symlinks and enforce post-extraction file-count/size limits."""
    count = 0
    total = 0
    root = Path(extract_dir)
    for item in root.rglob("*"):
        if item.is_symlink():
            raise DecodeError(f"CAB展開物にシンボリックリンクがあります: {item}")
        if not item.is_file():
            continue
        count += 1
        if count > _MAX_EXTRACTED_FILES:
            raise DecodeError(
                f"CAB展開ファイル数が上限を超えました: {count}>{_MAX_EXTRACTED_FILES}")
        try:
            total += item.stat().st_size
        except OSError as exc:
            raise DecodeError(f"CAB展開物のサイズ取得に失敗しました: {item}: {exc}") from exc
        if total > _MAX_EXTRACTED_BYTES:
            raise DecodeError(
                f"CAB展開後サイズが上限を超えました: {total}>{_MAX_EXTRACTED_BYTES} bytes")
    return count, total


def decode_cab(input_path: str, work_dir: str) -> str:
    """
    Base64 エンコードされた CAB (.txt) または .cab ファイルを展開し、
    CheckPC_*.txt のパスを返す。
    すでに CheckPC テキスト本体の場合はそのまま返す。

    【バグ修正】以前の実装はファイル名が CheckPC*.txt の場合に無条件でテキスト直接入力と
    判断していた。しかし CHECKPC_HOST-REF-11_2026010101010100.txt のように CheckPC* で始まる
    ファイル名を持つ PEM ラップ Base64 CAB が存在する場合に全セクション 0件になるバグがあった。

    判別方法をファイル名からファイル内容（先頭バイト）に変更する:
      - 先頭が "CheckPC_" → CheckPC テキスト本体（パイプラインの先頭ファイル名と一致）
      - 先頭が "-----BEGIN" → PEM ラップ Base64 CAB → デコードが必要
      - それ以外の .txt → Base64 生テキスト → デコードが必要
    """
    fname = os.path.basename(input_path)

    # ── ファイル内容で種別を判定（先頭16バイトで十分）
    with open(input_path, "rb") as f:
        head = f.read(16)

    is_checkpc_text = head.startswith(b"CheckPC_")
    is_pem_wrapped  = head.startswith(b"-----BEGIN")

    # CheckPC テキスト本体（先頭が "CheckPC_" → そのまま返す）
    if is_checkpc_text:
        return input_path

    # .txt ファイル（PEM ラップ or 生 Base64）→ デコードが必要
    if input_path.endswith(".txt") or is_pem_wrapped:
        cab_path = os.path.join(work_dir, re.sub(r"\.txt$", ".cab", fname, flags=re.I))
        print(f"  [decode] Base64 → CAB: {cab_path}")
        result = subprocess.run(
            ["openssl", "base64", "-d", "-in", input_path, "-out", cab_path],
            capture_output=True, timeout=_EXTERNAL_CMD_TIMEOUT_SEC
        )
        if result.returncode != 0:
            raise RuntimeError(f"openssl base64 デコード失敗: {result.stderr.decode()}")
        input_path = cab_path

    # CAB 展開
    if input_path.endswith(".cab"):
        # 【残骸修正】展開先を work_dir（クリーンアップ対象の一時フォルダ）配下にする。
        #   以前は入力CABと同じ場所（例 /test/input/<NAME>）に展開しており、
        #   直接 .cab を渡すと入力フォルダに <NAME> フォルダが残骸として残っていた。
        #   work_dir 配下にすれば、後段の「run_dir へ移動 → _tmp_dir 削除」で回収される。
        extract_dir = os.path.join(
            work_dir, re.sub(r"\.cab$", "", os.path.basename(input_path), flags=re.I))
        os.makedirs(extract_dir, exist_ok=True)
        print(f"  [decode] CAB 展開: {extract_dir}")
        result = subprocess.run(
            ["cabextract", "-e", "SJIS", input_path, "-d", extract_dir],
            capture_output=True, timeout=_EXTERNAL_CMD_TIMEOUT_SEC
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"cabextract 失敗: {result.stderr.decode()}\n"
                "sudo apt install cabextract を実行してください。"
            )
        _validate_extracted_tree(extract_dir)
        # CheckPC_*.txt を探す
        candidates = list(Path(extract_dir).glob("CheckPC*.txt"))
        if not candidates:
            raise FileNotFoundError(f"CAB 内に CheckPC_*.txt が見つかりません: {extract_dir}")
        return str(candidates[0])

    raise ValueError(f"未対応のファイル形式: {input_path}")


# ─────────────────────────────────────────────────────────────
# ShimCache パース
# ─────────────────────────────────────────────────────────────
def _shim_match_key(s: str) -> str:
    """ShimCache 照合用の安定キー。

    CheckPC 収集ファイル名の日時部分には、収集元PCのロケールに依存した曜日文字
    が混入することがある（例: 中国語環境の "周三"=水曜、GBK 格納）。この非ASCII
    部分は CAB 展開時のエンコード変換で文字化けし、環境によって suffix 完全一致が
    壊れるため、非ASCII と、Windows ファイル名に本来現れない置換文字（? 等）を
    除去したホスト名＋日時（英数字）だけで照合する。
    """
    s = re.sub(r"[^\x00-\x7f]", "", s)   # 非ASCII（周三等・U+FFFD 等）を除去
    s = re.sub(r"[?<>:\"|*]", "", s)      # 化け由来の置換文字（Windows禁止文字）を除去
    return s.lower()


def run_shimcache(checkpc_txt: str, work_dir: str) -> str | None:
    """
    AppCompatCache_*.txt または AppCompatibility_*.txt を
    ShimCacheParser.py でパースして CSV を返す。
    ShimCacheParser.py がない場合は None を返す。

    【バグ修正】以前の実装は base.replace("CheckPC", prefix) で候補を推定していたため、
    CHECKPC_HOST-REF-11_*.txt のような大文字ファイル名では置換が効かず Shimcache が
    見つからないエラーになっていた。
    ファイル名の PREFIX を大文字小文字無視の glob 検索に変更する。
    """
    if not os.path.exists(SHIMCACHE_PARSER):
        print(f"  [shimcache] ShimCacheParser.py が見つかりません: {SHIMCACHE_PARSER}")
        print(f"              → 環境変数 CHECKPC_SHIMCACHE_PARSER で正しいパスを指定してください")
        return None

    base      = os.path.basename(checkpc_txt)
    input_dir = os.path.dirname(checkpc_txt)

    # ホスト名・タイムスタンプ部分を抽出（CheckPC_ または CHECKPC_ を除いた残り）
    # 例: "CheckPC_HOST-REF-11_2026010101010100.txt" → "HOST-REF-11_2026010101010100.txt"
    suffix = re.sub(r"^checkpc_", "", base, flags=re.I)

    for prefix in ("AppCompatCache", "AppCompatibility"):
        # 大文字小文字を無視して同一ディレクトリから検索
        for fname in os.listdir(input_dir):
            if re.match(rf"^{prefix}_", fname, re.I) and fname.lower().endswith(".txt"):
                # suffix 部分も一致するか確認（ホスト名・タイムスタンプ）
                # ロケール依存の曜日文字/文字化けを無視する安定キーで比較する。
                fname_suffix = re.sub(rf"^{prefix}_", "", fname, flags=re.I)
                if _shim_match_key(fname_suffix) == _shim_match_key(suffix):
                    candidate = os.path.join(input_dir, fname)
                    # 【文字化け対策】ファイル名にロケール依存の曜日文字（周三等）が
                    #   化けて残ると python2.7/nkf が入出力パスを開けず CSV 未生成に
                    #   なる。ASCII安全な固定作業パスへ複製してからパースする。
                    safe_stem = re.sub(r"[?<>:\"|*]", "",
                                       re.sub(r"[^\x00-\x7f]", "", base))
                    safe_in  = os.path.join(work_dir, "appcompat_input.txt")
                    out_csv  = os.path.join(
                        work_dir,
                        re.sub(r"^checkpc_", "ParsedAppCompatCache_", safe_stem, flags=re.I)
                           .replace(".txt", ".csv"))
                    shutil.copyfile(candidate, safe_in)
                    print(f"  [shimcache] パース中: {fname}")
                    # nkf で UTF-8 化（成功時のみ .utf8 を使い、失敗時は原本を渡す）
                    nkf_result = subprocess.run(
                        ["nkf", "-w", safe_in], capture_output=True,
                        timeout=_EXTERNAL_CMD_TIMEOUT_SEC)
                    parse_input = safe_in
                    if nkf_result.returncode == 0:
                        parse_input = safe_in + ".utf8.tmp"
                        with open(parse_input, "wb") as f:
                            f.write(nkf_result.stdout)
                    proc = subprocess.run(
                        ["python2.7", SHIMCACHE_PARSER, "-t", "-r", parse_input, "-o", out_csv],
                        capture_output=True, timeout=_EXTERNAL_CMD_TIMEOUT_SEC)
                    if parse_input != safe_in and os.path.exists(parse_input):
                        os.remove(parse_input)
                    if os.path.exists(safe_in):
                        os.remove(safe_in)
                    if os.path.exists(out_csv):
                        return out_csv
                    # 照合成功だが CSV 未生成。多くは AppCompatCache が空
                    # （新規構築/クリア直後/VM 等では 0 エントリ＝正常）。
                    # ShimCacheParser のメッセージ（python2 は STDOUT へ出す）も表示。
                    _out = (proc.stdout.decode("utf-8", "replace").strip()
                            if proc.stdout else "")
                    _err = (proc.stderr.decode("utf-8", "replace").strip()
                            if proc.stderr else "")
                    _msg = (_out or _err or "(出力なし)")[:400]
                    print(f"  [shimcache] AppCompatCache にエントリがありません"
                          f"（空のキャッシュ＝新規/クリア直後/VM 等では正常。または"
                          f"未対応フォーマット）。ShimCacheParser: {_msg}")
                    return None
    # ここに到達＝パーサは在るが AppCompatCache_*.txt が照合できなかった
    print(f"  [shimcache] AppCompatCache_*.txt が入力に見つかりません（ホスト名・日時の"
          f"照合不一致、または CAB 内に未収録）: suffix={_shim_match_key(suffix)}")
    return None


# ─────────────────────────────────────────────────────────────
# メイン実行フロー
# ─────────────────────────────────────────────────────────────
def _run_impl(input_path: str,
        depth: int = DEFAULT_DEPTH,
        output_dir: str = None,
        vllm_url: str = DEFAULT_VLLM_URL,
        model: str = DEFAULT_MODEL,
        target_sections: list = None,
        verbose: bool = False,
        skip_llm: bool = False,
        vt_key: str = "",
        vt_proxy: str = "",
        context: str = "",
        cancel_check=None,
        lean: bool = None,
        progress_callback=None,
        _tmp_dir_override: str = None,
        _package_identity: dict | None = None) -> dict:
    """
    全フローを実行して、出力ファイルのパス辞書を返す。
    skip_llm=True の場合は parse のみ実行（テスト用）。
    vt_key が指定された場合は Step 7 で VT post-processing を実行する。
    context が指定された場合は全セクションのシステムプロンプトに追記される。
    cancel_check: 引数無しで呼べて bool を返す callable。True を返すように
      なった場合、各Stepの境界とStep4のセクション単位でチェックし、
      RunCancelled を送出して処理を打ち切る（実行中のLLM呼び出し1回分の
      完了は待つため、即座には止まらない点に注意）。
    """
    def _check_cancel(where: str):
        if cancel_check and cancel_check():
            raise RunCancelled(f"中断要求により停止しました（{where}の直前）")

    def _progress(message: str):
        if progress_callback:
            try:
                progress_callback(message)
            except Exception:
                pass

    start_time = time.time()

    # ── 出力ディレクトリ ─────────────────────────────────────
    # Step 3 (parse) でホスト名・日時が判明するが、CABデコードの中間ファイルは
    # 先に一時フォルダが必要なため、まず仮ディレクトリを作成し、
    # parse 後にサブフォルダへ移行する。
    base_output = output_dir if output_dir else os.path.join(
        os.path.dirname(os.path.abspath(input_path)), "output"
    )
    base_output = str(Path(base_output).expanduser().resolve(strict=False))
    os.makedirs(base_output, exist_ok=True)
    # wrapper が所有するジョブ固有一時領域。全例外・中断経路で finally cleanup される。
    _tmp_dir = _tmp_dir_override or tempfile.mkdtemp(
        prefix=f".tmp_decode_{uuid.uuid4().hex}_", dir=base_output)

    print(f"\n{'='*60}")
    print(f"  マルウェア解析パイプライン v{PIPELINE_VERSION}")
    print(f"  入力    : {input_path}")
    print(f"  解析深度: {depth} ({DEPTH_LABELS.get(depth, '?')})")
    print(f"{'='*60}\n")

    # Step 1: CAB デコード
    print("[Step 1] CAB デコード / ファイル確認")
    _progress("Step 1: CABデコード / ファイル確認")
    try:
        checkpc_txt = decode_cab(input_path, _tmp_dir)
        print(f"  CheckPC テキスト: {checkpc_txt}")
    except Exception as e:
        print(f"  [ERROR] {e}", file=sys.stderr)
        shutil.rmtree(_tmp_dir, ignore_errors=True)
        raise DecodeError(str(e)) from e

    # Step 2: ShimCache パース（一時フォルダに出力）
    _check_cancel("Step 2")
    print("[Step 2] AppCompatCache パース")
    _progress("Step 2: AppCompatCacheパース")
    appcompat_csv = run_shimcache(checkpc_txt, _tmp_dir)
    if appcompat_csv:
        print(f"  AppCompatCache CSV: {appcompat_csv}")
    else:
        print("  → AppCompatCache パースをスキップしました（原因は上記の [shimcache] を参照）")

    # Step 3: CheckPC 構造化
    _check_cancel("Step 3")
    print("[Step 3] CheckPC 出力の構造化")
    _progress("Step 3: CheckPC出力の構造化")
    parsed = parse_checkpc_fn(checkpc_txt, appcompat_csv)
    package_identity = dict(_package_identity or assert_package_integrity(SCRIPT_DIR))
    parsed["meta"]["package_manifest_sha256"] = package_identity["package_manifest_sha256"]
    parsed["meta"]["package_checked_files"] = package_identity["checked_files"]
    hostname  = parsed["meta"]["hostname"]
    datestamp = parsed["meta"]["datestamp"]
    safe_hostname = safe_component(hostname, fallback="UNKNOWN", max_length=80)
    safe_datestamp = safe_component(datestamp, fallback="UNKNOWN_DATE", max_length=40)
    parsed["meta"]["safe_hostname"] = safe_hostname

    # ── ホスト名・日時が判明したのでサブフォルダを確定 ──────
    # 表示用hostnameは保持し、ファイルシステムにはsafe_hostnameだけを使用する。
    run_name = f"{safe_hostname}_{safe_datestamp}"
    run_dir = str(confined_join(base_output, run_name))
    if os.path.exists(run_dir) and os.listdir(run_dir):
        run_dir = str(confined_join(
            base_output, f"{run_name}_{parsed['meta']['input_sha256'][:8]}"))
    os.makedirs(run_dir, exist_ok=True)
    print(f"  出力先  : {run_dir}")

    parsed_path = os.path.join(run_dir, f"parsed_{safe_hostname}_{safe_datestamp}.json")
    atomic_write_json(parsed_path, parsed)
    parsed_artifact_sha256 = comparison_sha256_file(parsed_path)
    # analyzed側からfull archive内のparsed artifactを一意に検証する。
    # parsedファイル自体は自己参照hashを持たせず、実ファイルhashを継承する。
    parsed["meta"]["parsed_artifact_sha256"] = parsed_artifact_sha256
    print(f"  出力: {parsed_path}")
    print(f"  ホスト: {hostname} | CheckPC: {parsed['meta']['checkpc_version']}")
    try:
        directory_index_path = directory_index.build_directory_index(
            parsed_path,
            entries=parsed.get("sections", {}).get("directory", []),
        )
        print(f"  directory raw index: {directory_index_path}")
    except Exception as exc:
        directory_index_path = ""
        print(f"  [WARN] directory raw index生成失敗（チャット初回検索時に再試行）: {exc}",
              file=sys.stderr)

    # ジョブ固有一時領域の中間ファイルだけを当該run_dirへ移動する。
    moved_files = []
    for tmp_file in Path(_tmp_dir).iterdir():
        dest = os.path.join(run_dir, tmp_file.name)
        shutil.move(str(tmp_file), dest)
        moved_files.append(dest)
    shutil.rmtree(_tmp_dir, ignore_errors=True)

    if appcompat_csv:
        appcompat_csv = os.path.join(run_dir, os.path.basename(appcompat_csv))

    _profile = active_profile().to_dict()
    _runtime = runtime_settings()
    manifest = build_manifest(
        input_path, moved_files + [parsed_path],
        hostname=hostname, safe_hostname=safe_hostname, normalized_timestamp=datestamp,
        checkpc_version=parsed.get("meta", {}).get("checkpc_version", ""),
        analysis_mode="LEAN" if (LEAN_OUTPUT if lean is None else bool(lean)) else "FULL",
        depth=depth, model=model, budget_profile=_profile.get("name"),
        budget_profile_fingerprint=_profile.get("fingerprint"),
        pipeline_max_workers=_runtime.pipeline_max_workers,
        max_inflight_llm=_runtime.max_inflight_llm,
        parsed_artifact_sha256=parsed_artifact_sha256,
        raw_evidence_fingerprint=parsed.get("meta", {}).get("raw_evidence_fingerprint", ""),
        comparison_provenance_schema_version=parsed.get("meta", {}).get("comparison_provenance_schema_version", ""),
        source_id_algorithm_version=parsed.get("meta", {}).get("source_id_algorithm_version", ""),
        package_manifest_sha256=parsed.get("meta", {}).get("package_manifest_sha256", ""),
        package_checked_files=parsed.get("meta", {}).get("package_checked_files", 0),
    )
    assert_artifact_identity(
        manifest, label="ingest_manifest", analysis_mode=manifest.get("analysis_mode"),
        require_profile=True, require_parser=False, require_package=True,
    )
    manifest_path = os.path.join(run_dir, "ingest_manifest.json")
    atomic_write_json(manifest_path, manifest)
    outputs = {"parsed": parsed_path, "run_dir": run_dir, "manifest": manifest_path,
               "hostname": hostname, "safe_hostname": safe_hostname}
    if directory_index_path:
        outputs["directory_index"] = str(directory_index_path)

    if skip_llm:
        print("\n[INFO] --skip-llm 指定のため LLM 解析をスキップ")
        return outputs

    # LLM クライアント初期化
    client = OpenAI(base_url=vllm_url, api_key="dummy")
    try:
        models = client.models.list()
        available = [m.id for m in models.data]
        if model not in available:
            print(f"[WARN] モデル '{model}' が見つかりません。利用可能: {available}")
    except Exception as e:
        print(f"[ERROR] vllm 接続失敗: {e}", file=sys.stderr)
        raise VllmUnavailableError(str(e)) from e

    # Step 4: セクション別 LLM 解析
    _check_cancel("Step 4")
    _lean_eff = LEAN_OUTPUT if lean is None else bool(lean)   # 表示用の実効値
    _mode = "LEAN" if _lean_eff else "FULL"
    if context:
        print(f"[Step 4] セクション別 LLM 解析 (depth={depth}, mode={_mode}) + 追加コンテキスト({len(context)}文字)")
    else:
        print(f"[Step 4] セクション別 LLM 解析 (depth={depth}, mode={_mode})")
    _progress(f"Step 4: セクション別LLM解析 depth={depth} mode={_mode}")
    try:
        analyzed = analyze_fn(
            parsed, depth, client, model,
            target_sections=target_sections,
            verbose=verbose,
            context=context,
            cancel_check=cancel_check,
            lean=lean,
            progress_callback=_progress,
        )
    except PipelineCancelled as e:
        raise RunCancelled(str(e)) from e
    # [提案B/Phase2] 既知正規ファイル（filepath whitelist 一致）の MEDIUM/LOW を
    #   CLEAN 降格（HIGH は絶対に触らない）。WL 未在時は no-op。
    try:
        _wl = get_whitelist()
        _wl_n = apply_whitelist_downgrade(analyzed, _wl)
        if _wl_n:
            print(f"  filepath whitelist: {_wl_n}件を CLEAN 降格"
                  f"（WL {_wl.stats().get('exact',0)}+{_wl.stats().get('regex_groups',0)}群）")
    except Exception as e:
        print(f"  [WARN] filepath whitelist 適用スキップ: {e}", file=sys.stderr)

    assert_artifact_identity(
        analyzed, label="analyzed", analysis_mode=_mode,
        require_profile=True, require_parser=True, require_package=True,
    )
    analyzed_path = os.path.join(run_dir, f"analyzed_{safe_hostname}_{safe_datestamp}.json")
    atomic_write_json(analyzed_path, analyzed)
    print(f"  出力: {analyzed_path}")
    outputs["analyzed"] = analyzed_path

    # Step 5: 横断相関。HIGHがなくてもMEDIUM複合・共通IOCがあれば実行する。
    _scored = []
    _medium_sections = set()
    _ioc_sections = {}
    for _sec, _sd in analyzed.get("sections", {}).items():
        if not isinstance(_sd, dict):
            continue
        for _e in _sd.get("entries", []) or []:
            if not isinstance(_e, dict):
                continue
            _score = _e.get("score")
            if _score in ("HIGH", "MEDIUM"):
                _scored.append((_sec, _e))
            if _score == "MEDIUM":
                _medium_sections.add(_sec)
            for _ioc in _e.get("iocs", []) or []:
                _ioc_sections.setdefault(str(_ioc).lower(), set()).add(_sec)
    _high_count = sum(1 for _, e in _scored if e.get("score") == "HIGH")
    _medium_count = sum(1 for _, e in _scored if e.get("score") == "MEDIUM")
    _shared_ioc = any(len(v) >= 2 for v in _ioc_sections.values())
    _medium_threshold = int(os.environ.get("CHECKPC_CORRELATE_MEDIUM_THRESHOLD", "5"))
    _should_correlate = (_high_count > 0 or _medium_count >= _medium_threshold or
                         len(_medium_sections) >= 2 or _shared_ioc)
    if _should_correlate:
        _check_cancel("Step 5")
        print(f"[Step 5] 横断相関分析 depth={depth} HIGH={_high_count} MEDIUM={_medium_count}")
        _progress(f"Step 5: 横断相関 HIGH={_high_count} MEDIUM={_medium_count}")
        correlation = correlate_fn(analyzed, depth, client, model, verbose=verbose)
    else:
        print(f"[Step 5] 横断相関分析スキップ（HIGH={_high_count}, MEDIUM={_medium_count}）")
        correlation = {
            "infection_suspicion": None,
            "infection_summary": "相関条件を満たすHIGH/MEDIUM複合所見なし",
            "malware_family": "Unknown",
            "correlated_iocs": [], "timeline": [],
            "mitre_ttps": [], "recommended_actions": [],
        }
        apply_deterministic_fallback(correlation, analyzed)
    corr_path = os.path.join(run_dir, f"correlation_{safe_hostname}_{safe_datestamp}.json")
    atomic_write_json(corr_path, correlation)
    print(f"  出力: {corr_path}")
    outputs["correlation"] = corr_path

    # Step 6: レポート生成
    _check_cancel("Step 6")
    print("[Step 6] Markdown レポート生成")
    # 標準版（HIGH/MEDIUM のみ展開、LOW は集計）
    report_md = generate_report(analyzed, correlation, full=False)
    report_path = os.path.join(run_dir, f"report_{safe_hostname}_{safe_datestamp}.md")
    atomic_write_text(report_path, report_md)
    print(f"  出力: {report_path}")
    outputs["report"] = report_path
    # 全件版（LOW も全行展開）
    report_all_md = generate_report(analyzed, correlation, full=True)
    report_all_path = os.path.join(run_dir, f"report_{safe_hostname}_{safe_datestamp}_all.md")
    atomic_write_text(report_all_path, report_all_md)
    print(f"  出力: {report_all_path}")
    outputs["report_all"] = report_all_path

    # Step 6b: 感染タイムライン（T-TL4 / 決定論・LLM非依存）
    # parsed の sections と event_logs の両方を渡す（着信RDP・サービス導入・
    # ログ消去等は event_logs 配下にあり、渡さないと年表から欠落する）。
    # 不審(*)標記には analyzed の HIGH/MEDIUM 所見を用いる。
    print("[Step 6b] 感染タイムライン生成")
    try:
        tl_findings = extract_findings_from_results(analyzed)
        tl_md = build_timeline_markdown(
            parsed.get("sections", {}), tl_findings, parsed.get("event_logs"))
        tl_path = os.path.join(run_dir, f"report_{safe_hostname}_{safe_datestamp}_timeline.md")
        atomic_write_text(tl_path, tl_md)
        print(f"  出力: {tl_path}")
        outputs["timeline"] = tl_path
    except Exception as e:
        print(f"  [WARN] タイムライン生成失敗（処理は継続）: {e}", file=sys.stderr)

    # Step 6c: Defender検知ログ集約 ＋ 不審フォルダDirectory抽出（16-D / v3.57）
    # 決定論・LLM非依存。parsed（parse_checkpc.py出力）の
    # sections.defender_quarantine と sections.directory のみを使うため、
    # analyzed（LLM解析後）を待たずに生成できる。
    print("[Step 6c] Defender検知ログ集約＋不審フォルダDirectory抽出")
    try:
        dd_md = build_defender_dir_report(parsed)
        dd_path = os.path.join(run_dir, f"report_{safe_hostname}_{safe_datestamp}_defender_dirs.md")
        atomic_write_text(dd_path, dd_md)
        print(f"  出力: {dd_path}")
        outputs["defender_dirs"] = dd_path
    except Exception as e:
        print(f"  [WARN] Defender集約レポート生成失敗（処理は継続）: {e}", file=sys.stderr)

    # ② directory D（zip/rar/7z）別ファイル出力
    # depth=1 の directory 優先度分類でLLM未送付になった圧縮ファイル一覧を
    # 目視確認用の Markdown として出力する。アナリストがパスを確認して
    # 不審なアーカイブを特定するためのもの。
    dir_sec = analyzed.get("sections", {}).get("directory", {})
    # _directory_D は sec_result["_directory_D"] に保存されるケースと
    # entries の _meta_only エントリ内の _directory_D_entries に保存されるケースがある
    dir_d_entries = dir_sec.get("_directory_D") or []
    if not dir_d_entries:
        for e in dir_sec.get("entries", []):
            if isinstance(e, dict) and e.get("_meta_only") and "_directory_D_entries" in e:
                dir_d_entries = e["_directory_D_entries"]
                break
    if dir_d_entries:
        lines = [
            f"# directory D: 圧縮ファイル一覧（LLM未送付・目視確認用）",
            f"",
            f"**対象ホスト:** {hostname}",
            f"**件数:** {len(dir_d_entries)}件",
            f"",
            f"> zip/rar/7z ファイルはダウンロード・バックアップが大半のためLLM解析対象外。",
            f"> パスを目視確認して不審なアーカイブを特定してください。",
            f"> 不審な場合は `--context` に記載して再実行するか、手動で展開・確認してください。",
            f"",
            f"| 更新日時 | サイズ | パス |",
            f"|---------|--------|------|",
        ]
        for e in sorted(dir_d_entries, key=lambda x: x.get("path", "")):
            date = e.get("date", "")
            size = e.get("size", "")
            path = e.get("path", "").replace("\\\\", "\\")
            lines.append(f"| {date} | {size} | `{path}` |")
        raw_dir_md = "\n".join(lines)
        raw_dir_path = os.path.join(run_dir, f"report_{safe_hostname}_{safe_datestamp}_raw_directory.md")
        atomic_write_text(raw_dir_path, raw_dir_md)
        print(f"  出力: {raw_dir_path}  （zip/rar/7z 目視確認用 {len(dir_d_entries)}件）")
        outputs["report_raw_directory"] = raw_dir_path

    # N-4c: 異常スコア下位でLLM未送付になった退避エントリも raw_directory に出力
    dir_overflow = dir_sec.get("_directory_overflow") or []
    if dir_overflow:
        of_lines = [
            f"",
            f"---",
            f"",
            f"# directory 異常スコア下位（LLM未送付・目視確認用）",
            f"",
            f"**件数:** {len(dir_overflow)}件",
            f"",
            f"> 件数上限(CHECKPC_DIR_MAX_LLM)により、異常スコア下位のエントリは",
            f"> LLM 評価対象外とした。取りこぼし防止のためここに退避している。",
            f"> 必要に応じて上限を上げて再実行（CHECKPC_DIR_MAX_LLM=N）するか手動確認のこと。",
            f"",
            f"| パス |",
            f"|------|",
        ]
        for e in sorted(dir_overflow, key=lambda x: x.get("path", "")):
            path = (e.get("path", "") or "").replace("\\\\", "\\")
            of_lines.append(f"| `{path}` |")
        raw_dir_path = os.path.join(run_dir, f"report_{safe_hostname}_{safe_datestamp}_raw_directory.md")
        existing = ""
        if outputs.get("report_raw_directory") and os.path.exists(raw_dir_path):
            with open(raw_dir_path, encoding="utf-8", errors="replace") as f:
                existing = f.read()
        if not existing:
            existing = "# directory 退避一覧（目視確認用）\n"
        atomic_write_text(raw_dir_path, existing + "\n" + "\n".join(of_lines))
        print(f"  出力: {raw_dir_path}  （異常スコア下位 退避 {len(dir_overflow)}件）")
        outputs["report_raw_directory"] = raw_dir_path

    # Step 7: VT post-processing（--vt-key が指定された場合のみ）
    # LLMパイプラインとは非同期・独立。analyzed.json のスコアを補正した
    # analyzed_*_vt.json を生成する。
    vt_key_resolved = vt_key or os.environ.get("VT_API_KEY", "")
    if vt_key_resolved:
        _check_cancel("Step 7")
        print("[Step 7] VirusTotal ポスト処理")
        vt_proxies = None
        if vt_proxy:
            vt_proxies = {"http": vt_proxy, "https": vt_proxy}
        elif os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY"):
            p = os.environ.get("HTTPS_PROXY", os.environ.get("HTTP_PROXY", ""))
            vt_proxies = {"http": p, "https": p}
        analyzed_vt = vt_enrich(
            analyzed,
            api_key=vt_key_resolved,
            proxies=vt_proxies,
            verbose=verbose,
        )
        assert_artifact_identity(
            analyzed_vt, label="analyzed_vt", analysis_mode=_mode,
            require_profile=True, require_parser=True,
        )
        vt_path = os.path.join(run_dir, f"analyzed_{safe_hostname}_{safe_datestamp}_vt.json")
        atomic_write_json(vt_path, analyzed_vt)
        print(f"  出力: {vt_path}")
        outputs["analyzed_vt"] = vt_path

        # Step 8: VT補正済みスコアで相関分析・レポートを再生成
        # Step 5/6 は VT 前スコアを使っているため、VT でスコアが変わった場合に
        # correlation.json / report.md が実態と乖離する。
        # VT 実行後にもう一度 correlate → report_gen を実行して _vt.json を入力に使う。
        print("[Step 8] VT補正後 再相関分析・レポート生成")
        correlation_vt = correlate_fn(analyzed_vt, depth, client, model, verbose=verbose)
        corr_vt_path = os.path.join(run_dir, f"correlation_{safe_hostname}_{safe_datestamp}_vt.json")
        atomic_write_json(corr_vt_path, correlation_vt)
        print(f"  出力: {corr_vt_path}")
        outputs["correlation_vt"] = corr_vt_path

        # VT後 標準版
        report_vt_md = generate_report(analyzed_vt, correlation_vt, full=False)
        report_vt_path = os.path.join(run_dir, f"report_{safe_hostname}_{safe_datestamp}_vt.md")
        atomic_write_text(report_vt_path, report_vt_md)
        print(f"  出力: {report_vt_path}")
        outputs["report_vt"] = report_vt_path
        # VT後 全件版
        report_vt_all_md = generate_report(analyzed_vt, correlation_vt, full=True)
        report_vt_all_path = os.path.join(run_dir, f"report_{safe_hostname}_{safe_datestamp}_vt_all.md")
        atomic_write_text(report_vt_all_path, report_vt_all_md)
        print(f"  出力: {report_vt_all_path}")
        outputs["report_vt_all"] = report_vt_all_path

        # VT後 感染タイムライン（T-TL4 / VT補正後スコアの所見で不審(*)標記）
        try:
            tl_findings_vt = extract_findings_from_results(analyzed_vt)
            tl_vt_md = build_timeline_markdown(
                parsed.get("sections", {}), tl_findings_vt, parsed.get("event_logs"))
            tl_vt_path = os.path.join(run_dir, f"report_{safe_hostname}_{safe_datestamp}_vt_timeline.md")
            atomic_write_text(tl_vt_path, tl_vt_md)
            print(f"  出力: {tl_vt_path}")
            outputs["timeline_vt"] = tl_vt_path
        except Exception as e:
            print(f"  [WARN] VT後タイムライン生成失敗（処理は継続）: {e}", file=sys.stderr)

    else:
        print("[Step 7] VT ポスト処理スキップ（--vt-key 未指定）")

    elapsed = time.time() - start_time
    # VT 実行時は VT 補正後 correlation を最終サマリに使う
    _vt_corr_path = outputs.get("correlation_vt")
    if _vt_corr_path:
        with open(_vt_corr_path, encoding="utf-8") as _f:
            correlation_final = json.load(_f)
    else:
        correlation_final = correlation
    suspicion = correlation_final.get("infection_suspicion", "N/A")
    print(f"\n{'='*60}")
    print(f"  完了 ({elapsed:.1f} 秒)")
    print(f"  感染嫌疑: {suspicion}")
    final_report = outputs.get("report_vt", report_path)
    print(f"  最終レポート: {final_report}")
    print(f"{'='*60}\n")

    return outputs


def run(input_path: str,
        depth: int = DEFAULT_DEPTH,
        output_dir: str = None,
        vllm_url: str = DEFAULT_VLLM_URL,
        model: str = DEFAULT_MODEL,
        target_sections: list = None,
        verbose: bool = False,
        skip_llm: bool = False,
        vt_key: str = "",
        vt_proxy: str = "",
        context: str = "",
        cancel_check=None,
        lean: bool = None,
        progress_callback=None) -> dict:
    """Execute one analysis with unconditional temporary-directory cleanup."""
    assert_runtime_identity()
    package_identity = assert_package_integrity(SCRIPT_DIR)
    base_output = output_dir if output_dir else os.path.join(
        os.path.dirname(os.path.abspath(input_path)), "output")
    base_output = str(Path(base_output).expanduser().resolve(strict=False))
    os.makedirs(base_output, exist_ok=True)
    tmp_dir = tempfile.mkdtemp(prefix=f".tmp_decode_{uuid.uuid4().hex}_", dir=base_output)
    failure = None
    try:
        return _run_impl(
            input_path, depth=depth, output_dir=base_output, vllm_url=vllm_url,
            model=model, target_sections=target_sections, verbose=verbose,
            skip_llm=skip_llm, vt_key=vt_key, vt_proxy=vt_proxy, context=context,
            cancel_check=cancel_check, lean=lean, progress_callback=progress_callback,
            _tmp_dir_override=tmp_dir, _package_identity=package_identity)
    except Exception as exc:
        failure = {
            "pipeline_version": PIPELINE_VERSION,
            "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
            "input_path": os.path.abspath(input_path),
            "exception_type": type(exc).__name__,
            "error": str(exc),
            "stage": "run_analysis",
            "created_at_epoch": time.time(),
        }
        raise
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        if failure is not None:
            failure["cleanup_result"] = "removed" if not os.path.exists(tmp_dir) else "residual"
            fail_path = os.path.join(base_output, f"failure_manifest_{uuid.uuid4().hex[:12]}.json")
            try:
                atomic_write_json(fail_path, failure)
            except Exception:
                pass


def collect_batch_inputs(batch_dir: str) -> list:
    """
    バッチフォルダから解析対象ファイルを収集する。
    対象:
      - CheckPC_*.txt  : CheckPC テキスト直接入力（非 CAB）
      - *.cab          : CAB ファイル（直接展開）
      - *.txt          : Base64 エンコード CAB（PEM ラップ含む）
                         ※ CheckPC_*.txt は上記で先に拾い済みのため重複しない
    既に処理済み（output/<NAME>_<STAMP>/ フォルダが存在する）はスキップ。

    【バグ修正】以前の実装は CheckPC_*.txt と *.cab のみを対象としており、
    Base64 CAB を HOSTNAME_STAMP.txt という名前で配置した場合に認識されなかった。
    TXT ファイルは全般的に対象とし、decode_input() 内で実ファイルの種別を判定する。
    """
    targets = []
    output_base = os.path.join(batch_dir, "output")
    already_done = set()
    if os.path.isdir(output_base):
        for d in os.listdir(output_base):
            # output/<HOSTNAME>_<DATESTAMP>/ の形式
            if os.path.isdir(os.path.join(output_base, d)) and not d.startswith("_"):
                already_done.add(d)

    for fname in sorted(os.listdir(batch_dir)):
        fpath = os.path.join(batch_dir, fname)
        if not os.path.isfile(fpath):
            continue
        # 対象拡張子: .txt（CheckPC テキスト / Base64 CAB 両方含む）または .cab
        fname_lower = fname.lower()
        if not (fname_lower.endswith(".txt") or fname_lower.endswith(".cab")):
            continue
        # HOSTNAME_DATESTAMP を推定してスキップ判定
        # ファイル名から推定: CheckPC_HOSTNAME_STAMP.txt / HOSTNAME_STAMP.cab / HOSTNAME_STAMP.txt
        m = re.search(r"(?:CheckPC_)?([A-Za-z0-9\-]+)_(\d{14,})", fname)
        if m:
            candidate = f"{m.group(1)}_{m.group(2)}"
            if any(d.startswith(candidate) or candidate.startswith(d) for d in already_done):
                print(f"  [SKIP] 処理済み: {fname}")
                continue
        targets.append(fpath)

    return targets


def run_batch(batch_dir: str,
              depth: int = DEFAULT_DEPTH,
              output_dir: str = None,
              vllm_url: str = DEFAULT_VLLM_URL,
              model: str = DEFAULT_MODEL,
              workers: int = 1,
              verbose: bool = False,
              skip_llm: bool = False,
              vt_key: str = "",
              vt_proxy: str = "",
              context: str = "") -> None:
    """
    バッチフォルダ内の全CheckPC/CABファイルをキューで処理する。

    workers=1: 完全直列（デフォルト。vLLMの同時リクエスト数を増やさない）
    workers=2: 2並列（RTX A4500 + --max-model-len 6144 環境では最大2を推奨）
    workers>2: vLLMのKVキャッシュ上限を超える可能性があるため非推奨
    context: LLM に渡す追加コンテキスト（--context で渡された値）
    """
    base_output = output_dir if output_dir else os.path.join(batch_dir, "output")
    targets = collect_batch_inputs(batch_dir)

    if not targets:
        print("[INFO] 処理対象ファイルが見つかりません（既に全て処理済みか、対象ファイルなし）")
        return

    print(f"\n{'='*60}")
    print(f"  バッチ解析モード")
    print(f"  対象フォルダ : {batch_dir}")
    print(f"  対象ファイル : {len(targets)} 件")
    print(f"  並列数       : {workers}")
    print(f"  出力先       : {base_output}")
    print(f"{'='*60}\n")

    results_summary = []

    def _run_one(fpath: str) -> dict:
        try:
            outputs = run(
                fpath,
                depth=depth,
                output_dir=base_output,
                vllm_url=vllm_url,
                model=model,
                target_sections=None,
                verbose=verbose,
                skip_llm=skip_llm,
                vt_key=vt_key,
                vt_proxy=vt_proxy,
                context=context,
            )
            return {"file": fpath, "status": "OK", "run_dir": outputs.get("run_dir", ""), "report": outputs.get("report", "")}
        except PipelineError as ex:
            return {"file": fpath, "status": f"ERROR: {ex}", "run_dir": "", "report": ""}
        except Exception as ex:
            return {"file": fpath, "status": f"ERROR: {ex}", "run_dir": "", "report": ""}

    if workers == 1:
        for fpath in targets:
            result = _run_one(fpath)
            results_summary.append(result)
    else:
        # 複数ファイルをスレッドで並列実行（ファイル間並列、推論自体はvLLM任せ）
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(_run_one, fp): fp for fp in targets}
            for future in as_completed(futures):
                results_summary.append(future.result())

    # ── バッチ結果サマリ ──────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  バッチ処理完了: {len(targets)} 件")
    print(f"{'='*60}")
    ok  = [r for r in results_summary if r["status"] == "OK"]
    err = [r for r in results_summary if r["status"] != "OK"]
    print(f"  成功: {len(ok)} 件")
    for r in ok:
        print(f"    ✓ {os.path.basename(r['file'])} → {r.get('report','')}")
    if err:
        print(f"  失敗: {len(err)} 件")
        for r in err:
            print(f"    ✗ {os.path.basename(r['file'])} : {r['status']}")

    # バッチサマリJSONを output/ 直下に保存
    summary_path = os.path.join(base_output, f"batch_summary_{int(time.time())}.json")
    atomic_write_json(summary_path, results_summary)
    print(f"\n  バッチサマリ: {summary_path}\n")


def main():
    # .env 読み込み（CLI 引数より先に実行して os.environ に反映）
    load_dotenv_simple()

    ap = argparse.ArgumentParser(
        description="CheckPC 出力から LLM 解析レポートを生成する（全フロー一括実行）"
    )
    # ── 単一ファイルモード ────────────────────────────────
    ap.add_argument("input", nargs="?",
                    help="CheckPC_*.txt / Base64 CAB (.txt) / .cab のいずれか（--batch と排他）")
    # ── バッチモード ──────────────────────────────────────
    ap.add_argument("--batch", "-b", metavar="DIR",
                    help="バッチモード: 指定フォルダ内の全 CheckPC/CAB ファイルを順次処理")
    ap.add_argument("--workers", "-w", type=int, default=1,
                    help="バッチ並列数（デフォルト: 1=直列。RTX A4500 環境では最大 2 を推奨）")
    # ── 共通オプション ────────────────────────────────────
    ap.add_argument("--depth",  "-d", type=int, default=DEFAULT_DEPTH,
                    choices=[1, 2, 3, 4],
                    help="解析深度: 1=Filtered Triage(既定) / 2=Broad Review(検証・再調査用) / "
                         "3,4=試験機能（--experimental-depths 必須）")
    ap.add_argument("--experimental-depths", action="store_true",
                    help="depth 3/4 の試験実行を許可する。depth 3/4 は v4.0 で "
                         "Focused Deep Analysis / Incident Correlation として再定義予定。"
                         "現行の depth 3/4 はセクション単独入力に対し他セクション相関等を"
                         "指示しており根拠のない出力を生む。")
    ap.add_argument("--output-dir", "-o",
                    help="出力ベースディレクトリ（デフォルト: 入力ファイルと同じ場所の output/）")
    ap.add_argument("--section", "-s", action="append", dest="sections",
                    help="解析するセクションを指定（複数可）。省略時は全セクション")
    ap.add_argument("--vllm-url",    default=DEFAULT_VLLM_URL)
    ap.add_argument("--model",  "-m", default=DEFAULT_MODEL)
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--skip-llm",    action="store_true",
                    help="LLM 解析をスキップして parse のみ実行（テスト用）")
    ap.add_argument("--vt-key",
                    default=None,
                    help="VirusTotal API キー（.env の VT_API_KEY でも可）。"
                         "指定時のみ Step 7 の VT ポスト処理を実行")
    ap.add_argument("--vt-proxy",
                    default=None,
                    help="VT API 用プロキシ URL（.env の VT_PROXY でも可）")
    ap.add_argument("--context", "-c",
                    default="",
                    metavar="TEXT",
                    help="LLM に渡す追加コンテキスト（既知 C2・キャンペーン情報等）。"
                         "システムプロンプトに付与される。"
                         "例: --context '既知C2: evil.example.com / 1.2.3.4:443'")
    ap.add_argument("--context-file", "-f",
                    default="",
                    metavar="YAML_PATH",
                    help="追加コンテキストを記述した YAML ファイルのパス（T-05）。"
                         "--context と同時指定した場合は両方が結合される。"
                         "YAML スキーマ: threat_actor / malware_family / "
                         "known_c2 / known_iocs / notes"
                         "例: --context-file context.yaml")
    args = ap.parse_args()
    # v3.68: depth 3/4 は試験機能。--experimental-depths 必須（指示・C11）。
    if getattr(args, "depth", 1) >= 3 and not getattr(args, "experimental_depths", False):
        ap.error("depth 3/4 は試験機能です。--experimental-depths を明示してください。"
                 "（GUI・通常CLIでは depth 1-2 のみ）")

    # .env / 環境変数のフォールバック（load_dotenv_simple() 後なので正しく解決される）
    if args.vt_key is None:
        args.vt_key = os.environ.get("VT_API_KEY", "")
    if args.vt_proxy is None:
        args.vt_proxy = os.environ.get("VT_PROXY",
                         os.environ.get("HTTPS_PROXY",
                         os.environ.get("HTTP_PROXY", "")))

    # T-05: --context-file の内容を --context に結合する
    # 両方指定された場合は --context-file を先頭に置き、--context を末尾に付加
    if args.context_file:
        file_ctx = load_context_file(args.context_file)
        if file_ctx:
            if args.context:
                args.context = file_ctx + "\n" + args.context
            else:
                args.context = file_ctx

    # ── バッチモード ──────────────────────────────────────
    if args.batch:
        if not os.path.isdir(args.batch):
            print(f"[ERROR] バッチフォルダが見つかりません: {args.batch}", file=sys.stderr)
            sys.exit(1)
        run_batch(
            args.batch,
            depth=args.depth,
            output_dir=args.output_dir,
            vllm_url=args.vllm_url,
            model=args.model,
            workers=args.workers,
            verbose=args.verbose,
            skip_llm=args.skip_llm,
            vt_key=args.vt_key,
            vt_proxy=args.vt_proxy,
            context=args.context,
        )
        return

    # ── 単一ファイルモード ────────────────────────────────
    if not args.input:
        ap.error("input ファイルまたは --batch フォルダを指定してください")
    if not os.path.exists(args.input):
        print(f"[ERROR] ファイルが見つかりません: {args.input}", file=sys.stderr)
        sys.exit(1)

    run(
        args.input,
        depth=args.depth,
        output_dir=args.output_dir,
        vllm_url=args.vllm_url,
        model=args.model,
        target_sections=args.sections,
        verbose=args.verbose,
        skip_llm=args.skip_llm,
        vt_key=args.vt_key,
        vt_proxy=args.vt_proxy,
        context=args.context,
    )


if __name__ == "__main__":
    main()

