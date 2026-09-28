#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_all_tests.py — 回帰テスト一括実行ランナー（v3.70）

使い方:
    python3 run_all_tests.py            # 全テストを実行しサマリ表示
    python3 run_all_tests.py -v         # 各テストの生出力も表示

機能:
  1. 本スクリプトと同じディレクトリ、および tests/ サブディレクトリから
     test_*.py を自動検出して順次実行する（v3.57〜58 の未統合分も拾う）。
  2. 各ファイル末尾の「PASS=n FAIL=m」行を集計し、最後に一覧サマリを表示。
  3. KNOWN_FAILURES に登録された既知FAIL（前提ズレ・修正待ち）は「想定内」
     として区別し、新規FAILのみを異常として扱う。
  4. 実データrootはCHECKPC_TEST_EXTRACTで指定する。未設定または不存在なら、
     該当テストをSKIP(環境依存)として明示する（FAIL扱いにしない）。
  5. 終了コード: 新規FAIL または実行エラーが1件でもあれば 1（納品前チェック・
     CI 用）。全て PASS / 想定内 / SKIP なら 0。

メンテナンス:
  - 既知FAILを解消したら KNOWN_FAILURES から削除すること（放置すると
    再発を検知できない）。
  - 実データ必須のテストを追加したら REALDATA_TESTS に登録すること。
"""
import os
import re
import sys
import subprocess
import tempfile
import json
import platform
from datetime import datetime, timezone

sys.dont_write_bytecode = True

from comparison_release_gate import evaluate_release_gate

HERE = os.path.dirname(os.path.abspath(__file__))
VERBOSE = "-v" in sys.argv
RELEASE_MODE = "--release" in sys.argv
TEST_TIMEOUT_SEC = max(30, int(os.environ.get("CHECKPC_TEST_TIMEOUT_SEC", "300")))

def _arg_value(name: str, default=None):
    try:
        return sys.argv[sys.argv.index(name) + 1]
    except (ValueError, IndexError):
        return default

SHARD_INDEX = int(_arg_value("--shard-index", "0"))
SHARD_COUNT = max(1, int(_arg_value("--shard-count", "1")))
SUMMARY_JSON = _arg_value("--summary-json", "")
SHARD_CHILD = os.environ.get("CHECKPC_TEST_SHARD_CHILD") == "1"

# ── 既知FAILの登録（ファイル名 → FAIL行に含まれる識別文字列のリスト）──
# ここに登録された FAIL は「想定内」としてカウントし、終了コードに影響しない。
KNOWN_FAILURES = {
    # test_vt_downgrade.py: HOST-REF-04 再解析後のフィクスチャ前提ズレ
    # （iocs がベースファイル名のみになった）。修正待ち。
    "test_vt_downgrade.py": [
        "Zotero.dotm がVT照合対象IOCに含まれる",
        "HIGH5件相当",
    ],
}

# ── 実データ（解析済みアーカイブ展開）が必要なテスト ──
# 展開データが見つからない環境では SKIP(環境依存) とする。
REALDATA_TESTS = {
    "test_chat_tools_realdata.py",
    "test_report_fallback.py",
    "test_timeline_fixes.py",
    "test_integration_ttl4_ttl5.py",
    "test_vt_downgrade.py",
}
REALDATA_DIR = os.environ.get("CHECKPC_TEST_EXTRACT", "").strip()

_RESULT_RE = re.compile(r"PASS=(\d+)\s+FAIL=(\d+)")
_FAILLINE_RE = re.compile(r"^\s*\[FAIL\]\s*(.+)$", re.M)


def _summary_metadata() -> dict:
    return {
        "summary_schema": 1,
        "release_mode": bool(RELEASE_MODE),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "python": platform.python_version(),
        "host": platform.node(),
        "environment_label": (
            os.environ.get("CHECKPC_TEST_ENV_LABEL", "").strip() or "developer-local"
        ),
    }



def _comparison_gate_summary() -> dict:
    directory = os.environ.get("CHECKPC_COMPARISON_GATE_DIR", "").strip()
    if not RELEASE_MODE:
        return {"required": False, "eligible": False, "directory": directory, "errors": []}
    if not directory:
        return {"required": True, "eligible": False, "directory": "",
                "errors": ["CHECKPC_COMPARISON_GATE_DIR is required in --release mode"]}
    summary = evaluate_release_gate(directory)
    return {"required": True, "directory": directory, **summary}

def _write_summary(path: str, summary: dict) -> None:
    if not path:
        return
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")


def discover() -> list:
    """テストファイルを検出する（自分自身と重複は除外・名前順）。"""
    found = {}
    for d in (HERE, os.path.join(HERE, "tests")):
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if f.startswith("test_") and f.endswith(".py") and f not in found:
                found[f] = os.path.join(d, f)
    return sorted(found.items())


def run_one(name: str, path: str) -> dict:
    """1テストファイルを実行し、結果を辞書で返す。"""
    if name in REALDATA_TESTS and (not REALDATA_DIR or not os.path.isdir(REALDATA_DIR)):
        note = (f"実データ未配置({REALDATA_DIR})" if REALDATA_DIR
                else "CHECKPC_TEST_EXTRACT未設定")
        return {"status": "SKIP", "note": note,
                "p": 0, "f": 0, "new": [], "known": []}
    # PIPE captureを連続使用すると、TestClient等が生成する子スレッド／FDとの
    # 組合せでcommunicate待ちが長時間化する環境がある。出力を一時ファイルへ
    # 直接書き、テスト終了後に読むことでパイプ依存のデッドロックを避ける。
    log_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="checkpc_test_", suffix=".log", delete=False) as logf:
            log_path = logf.name
            child_env = dict(os.environ)
            child_env["PYTHONDONTWRITEBYTECODE"] = "1"
            cp = subprocess.run([sys.executable, path], stdout=logf,
                                stderr=subprocess.STDOUT, env=child_env,
                                timeout=TEST_TIMEOUT_SEC, cwd=os.path.dirname(path))
        out = open(log_path, encoding="utf-8", errors="replace").read()
    except subprocess.TimeoutExpired:
        out = ""
        if log_path and os.path.exists(log_path):
            out = open(log_path, encoding="utf-8", errors="replace").read()
        return {"status": "ERROR", "note": f"タイムアウト({TEST_TIMEOUT_SEC}秒)",
                "p": 0, "f": 0, "new": ["timeout: " + out[-200:]], "known": []}
    finally:
        if log_path:
            try:
                os.unlink(log_path)
            except OSError:
                pass
    if VERBOSE:
        print(out)
    m = None
    for m in _RESULT_RE.finditer(out):
        pass  # 最後の一致（＝最終サマリ行）を採用
    if not m:
        # 結果行が出ずに死んだ（import エラー等）。実データ系の
        # FileNotFoundError は環境依存 SKIP として扱う。
        if name in REALDATA_TESTS and "FileNotFoundError" in out:
            return {"status": "SKIP", "note": "実データ未配置(FileNotFoundError)",
                    "p": 0, "f": 0, "new": [], "known": []}
        tail = "\n".join(out.strip().splitlines()[-5:])
        return {"status": "ERROR", "note": "結果行なし（実行時エラー）",
                "p": 0, "f": 0, "new": [tail], "known": []}
    p, f = int(m.group(1)), int(m.group(2))
    fails = _FAILLINE_RE.findall(out)
    knowns = KNOWN_FAILURES.get(name, [])
    new, known = [], []
    for line in fails:
        if any(k in line for k in knowns):
            known.append(line)
        else:
            new.append(line)
    status = "PASS" if not new else "FAIL"
    if not new and known:
        status = "PASS*"   # 想定内FAILのみ
    return {"status": status, "note": "", "p": p, "f": f,
            "new": new, "known": known}


def main() -> int:
    tests = discover()
    me = os.path.basename(__file__)
    tests = [(n, p) for n, p in tests if n != me]
    if SHARD_COUNT > 1:
        tests = [(n, p) for i, (n, p) in enumerate(tests) if i % SHARD_COUNT == SHARD_INDEX]
        print(f"shard {SHARD_INDEX + 1}/{SHARD_COUNT}", flush=True)
    if not tests:
        print("テストファイルが見つかりません")
        return 1

    print(f"検出テストファイル: {len(tests)}件\n", flush=True)
    results = []
    for name, path in tests:
        r = run_one(name, path)
        results.append((name, r))
        mark = {"PASS": "OK ", "PASS*": "OK*", "SKIP": "SKP",
                "FAIL": "NG ", "ERROR": "ERR"}[r["status"]]
        extra = ""
        if r["known"]:
            extra += f"  想定内FAIL={len(r['known'])}"
        if r["note"]:
            extra += f"  {r['note']}"
        print(f"[{mark}] {name:40s} PASS={r['p']:<4d} FAIL={r['f']:<3d}{extra}", flush=True)
        for line in r["new"]:
            print(f"      [新規FAIL] {line[:120]}")

    total_p = sum(r["p"] for _, r in results)
    total_new = sum(len(r["new"]) for _, r in results)
    total_known = sum(len(r["known"]) for _, r in results)
    n_skip = sum(1 for _, r in results if r["status"] == "SKIP")
    n_err = sum(1 for _, r in results if r["status"] == "ERROR")

    print()
    print("=" * 64)
    print(f"  合計: PASS={total_p}  新規FAIL={total_new}  "
          f"想定内FAIL={total_known}  SKIP={n_skip}ファイル  ERROR={n_err}ファイル")
    comparison_gate = _comparison_gate_summary()
    release_blocked = RELEASE_MODE and (
        total_new > 0 or total_known > 0 or n_skip > 0 or n_err > 0
        or not comparison_gate.get("eligible", False))
    if total_new == 0 and n_err == 0 and not release_blocked:
        print("  判定: 合格（新規FAILなし）")
    elif release_blocked:
        print("  判定: 不合格（releaseモードでは想定内FAIL/SKIPを許容しない）")
    else:
        print("  判定: 不合格（新規FAILまたは実行エラーあり・要確認）")
    if total_known:
        print("  注意: 想定内FAILが残っています。解消したら KNOWN_FAILURES を"
              "更新してください。")
    print("=" * 64)
    summary = _summary_metadata()
    summary.update({
        "pass": total_p, "new_fail": total_new, "known_fail": total_known,
        "skip": n_skip, "error": n_err, "release_blocked": release_blocked,
        "formal_release_eligible": bool(
            RELEASE_MODE and not release_blocked
            and os.environ.get("CHECKPC_TEST_ENV_LABEL", "").strip() == "base117"
            and comparison_gate.get("eligible", False)),
        "comparison_gate": comparison_gate,
        "skipped_tests": sorted(name for name, r in results if r["status"] == "SKIP"),
        "shards": [{
            "index": SHARD_INDEX, "count": SHARD_COUNT,
            "pass": total_p, "new_fail": total_new, "known_fail": total_known,
            "skip": n_skip, "error": n_err,
            "skipped_tests": sorted(name for name, r in results if r["status"] == "SKIP"),
        }],
    })
    _write_summary(SUMMARY_JSON, summary)
    return 0 if (total_new == 0 and n_err == 0 and not release_blocked) else 1


def run_sharded() -> int:
    """Run two bounded shards to avoid long-lived parent FD/thread accumulation.

    Some FastAPI/TestClient combinations leave process resources pending long enough that
    launching more than ~16 test subprocesses from one parent can stall on constrained
    environments. Each shard has its own parent process and retains the one-command UX.
    """
    tests = [(n, p) for n, p in discover() if n != os.path.basename(__file__)]
    if SHARD_CHILD or SHARD_COUNT > 1 or len(tests) <= 14:
        return main()
    shard_count = max(2, min(8, int(os.environ.get("CHECKPC_TEST_SHARDS", "4"))))
    summaries = []
    with tempfile.TemporaryDirectory(prefix="checkpc_test_shards_") as td:
        for idx in range(shard_count):
            out = os.path.join(td, f"summary_{idx}.json")
            cmd = [sys.executable, os.path.abspath(__file__),
                   "--shard-index", str(idx), "--shard-count", str(shard_count),
                   "--summary-json", out]
            if VERBOSE:
                cmd.append("-v")
            if RELEASE_MODE:
                cmd.append("--release")
            env = dict(os.environ)
            env["CHECKPC_TEST_SHARD_CHILD"] = "1"
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            subprocess.run(cmd, cwd=HERE, env=env, check=False)
            if not os.path.exists(out):
                summaries.append({
                    "summary_schema": 1, "release_mode": RELEASE_MODE,
                    "pass": 0, "new_fail": 0, "known_fail": 0,
                    "skip": 0, "error": 1, "release_blocked": RELEASE_MODE,
                    "skipped_tests": [],
                    "shards": [{"index": idx, "count": shard_count,
                                "pass": 0, "new_fail": 0, "known_fail": 0,
                                "skip": 0, "error": 1, "skipped_tests": []}],
                })
            else:
                summaries.append(json.load(open(out, encoding="utf-8")))
    total = {k: sum(int(x.get(k, 0)) for x in summaries)
             for k in ("pass", "new_fail", "known_fail", "skip", "error")}
    comparison_gate = _comparison_gate_summary()
    release_blocked = RELEASE_MODE and (
        any(total[k] > 0 for k in ("new_fail", "known_fail", "skip", "error"))
        or not comparison_gate.get("eligible", False))
    print("\n" + "=" * 64)
    print(f"  全shard合計: PASS={total['pass']}  新規FAIL={total['new_fail']}  "
          f"想定内FAIL={total['known_fail']}  SKIP={total['skip']}ファイル  "
          f"ERROR={total['error']}ファイル")
    ok = total["new_fail"] == 0 and total["error"] == 0 and not release_blocked
    print("  判定: " + ("合格（新規FAILなし）" if ok else "不合格"))
    print("=" * 64)
    shard_rows = []
    skipped_tests = set()
    for idx, summary in enumerate(summaries):
        skipped_tests.update(str(x) for x in summary.get("skipped_tests", []))
        rows = summary.get("shards") or []
        row = dict(rows[0]) if rows else {
            "index": idx, "count": shard_count,
            **{k: int(summary.get(k, 0)) for k in
               ("pass", "new_fail", "known_fail", "skip", "error")},
            "skipped_tests": list(summary.get("skipped_tests", [])),
        }
        row["index"] = idx
        row["count"] = shard_count
        shard_rows.append(row)
    final_summary = _summary_metadata()
    final_summary.update(total)
    final_summary.update({
        "release_blocked": release_blocked,
        "formal_release_eligible": bool(
            RELEASE_MODE and not release_blocked
            and os.environ.get("CHECKPC_TEST_ENV_LABEL", "").strip() == "base117"
            and comparison_gate.get("eligible", False)),
        "comparison_gate": comparison_gate,
        "skipped_tests": sorted(skipped_tests),
        "shards": shard_rows,
    })
    _write_summary(SUMMARY_JSON, final_summary)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(run_sharded())
