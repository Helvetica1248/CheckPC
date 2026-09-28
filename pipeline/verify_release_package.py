#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_release_package.py — 配布パッケージの整合性検証（v3.70）

★ファイル名は "test_" 接頭辞にしない（指示11）。run_all_tests.py の
  discover() は test_*.py を検出するため、"test_clean_install.py" だと
  子環境で自身を再実行し続ける再帰が起こりうる。verify_ 接頭辞にすることで
  検出対象外にする。保険として CHECKPC_CLEAN_INSTALL_CHILD=1 も見る。

検証内容:
  · 全 .py にハードコードパス（/home/claude/scripts, /home/claude/extract,
    /mnt/user-data/uploads）がフォールバック以外に無い
  · README 記載の全テストファイルが実在する（記載と実体の整合）
  · INSTALL.txt 記載の CHECKPC_* 環境変数がコード内に実在する
  · 一時ディレクトリへ展開したクリーン環境で run_all_tests.py が合格する

使い方:
    python3 verify_release_package.py            # 静的検査のみ
    python3 verify_release_package.py --full      # クリーン展開して run_all_tests も実行
"""
import os
import re
import json
import hashlib
import subprocess
import sys

sys.dont_write_bytecode = True

from release_check_ids import (
    find_bare_release_versions, find_duplicate_check_ids, make_check_id,
)

HERE = os.path.dirname(os.path.abspath(__file__))
PASS = FAIL = NOT_APPLICABLE = 0
CHECK_RESULTS = []
CURRENT_SECTION = "ROOT"



def _check_id(name):
    return make_check_id(CURRENT_SECTION, name)


def check(name, cond, detail="", check_id=None):
    global PASS, FAIL
    cid = check_id or _check_id(name)
    if cond:
        print(f"  [OK]  [{cid}] {name}"); PASS += 1
        status = "PASS"
    else:
        print(f"  [FAIL] [{cid}] {name}" + (f": {detail}" if detail else "")); FAIL += 1
        status = "FAIL"
    CHECK_RESULTS.append({"id": cid, "name": name, "status": status,
                          "detail": str(detail)[:1000] if detail else ""})


def not_applicable(name, detail="", check_id=None):
    global NOT_APPLICABLE
    cid = check_id or _check_id(name)
    print(f"  [N/A] [{cid}] {name}" + (f": {detail}" if detail else ""))
    NOT_APPLICABLE += 1
    CHECK_RESULTS.append({"id": cid, "name": name, "status": "NOT_APPLICABLE",
                          "detail": str(detail)[:1000] if detail else ""})


def sec(t):
    global CURRENT_SECTION
    CURRENT_SECTION = t.split(":", 1)[0].strip() or "ROOT"
    print(f"\n{'-' * 60}\n  {t}\n{'-' * 60}")


# 子環境での再帰防止（保険）
if os.environ.get("CHECKPC_CLEAN_INSTALL_CHILD") == "1":
    print("  [SKIP] CHECKPC_CLEAN_INSTALL_CHILD=1（子環境のため自己検証をスキップ）")
    print(f"PASS=0 FAIL=0 N_A=0")
    sys.exit(0)



# ════════════════════════════════════════════════════════════
sec("V0: SHA-256配布manifest")
_sha_file = os.path.join(HERE, "SHA256SUMS.txt")
_sha_errors = []
_sha_listed = set()
if os.path.exists(_sha_file):
    for _line in open(_sha_file, encoding="utf-8"):
        _line = _line.rstrip("\n")
        if not _line.strip():
            continue
        try:
            _expected, _rel = _line.split("  ", 1)
        except ValueError:
            _sha_errors.append("invalid line: " + _line[:80]); continue
        _rel_norm = _rel.replace("\\", "/")
        _sha_listed.add(_rel_norm)
        _path = os.path.join(HERE, _rel)
        if not os.path.isfile(_path):
            _sha_errors.append("missing: " + _rel); continue
        _actual = hashlib.sha256(open(_path, "rb").read()).hexdigest()
        if _actual != _expected:
            _sha_errors.append("mismatch: " + _rel)
    check("V0: SHA256SUMS全項目一致", not _sha_errors, "; ".join(_sha_errors[:8]))
    _actual_files = set()
    for _root, _dirs, _files in os.walk(HERE):
        for _name in _files:
            _rel_actual = os.path.relpath(os.path.join(_root, _name), HERE).replace(os.sep, "/")
            if _rel_actual != "SHA256SUMS.txt":
                _actual_files.add(_rel_actual)
    _unlisted_files = sorted(_actual_files - _sha_listed)
    _listed_missing = sorted(_sha_listed - _actual_files)
    check("V0: 配布実ファイルがSHA256SUMSで全件被覆",
          not _unlisted_files and not _listed_missing,
          repr({"unlisted": _unlisted_files[:20], "missing": _listed_missing[:20]}))
    _cache_artifacts = sorted(
        rel for rel in _actual_files
        if "__pycache__" in rel.split("/")
        or rel.endswith((".pyc", ".pyo"))
        or ".pytest_cache" in rel.split("/")
    )
    check("V0: 配布物にPythonキャッシュ・テストキャッシュを含まない",
          not _cache_artifacts, repr(_cache_artifacts[:20]))
else:
    check("V0: SHA256SUMS.txtが存在", False)
check("V0: release_manifest.jsonが存在", os.path.exists(os.path.join(HERE, "release_manifest.json")))

# The manifest, machine summary and human report must describe the same run.
# This detects packaging inconsistency; it is not proof that tests were executed.
_manifest_path = os.path.join(HERE, "release_manifest.json")
_test_results_path = os.path.join(HERE, "TEST_RESULTS.md")
_actual_results_path = os.path.join(HERE, "test_results.json")
_semantic_errors = []
try:
    _manifest = json.load(open(_manifest_path, encoding="utf-8"))
    _summary = _manifest.get("test_summary") or {}
    _actual = json.load(open(_actual_results_path, encoding="utf-8"))
    _report = open(_test_results_path, encoding="utf-8").read()

    _begin = "<!-- CHECKPC_TEST_SUMMARY_BEGIN -->"
    _end = "<!-- CHECKPC_TEST_SUMMARY_END -->"
    if _begin not in _report or _end not in _report:
        raise ValueError("TEST_RESULTS summary marker missing")
    _block = _report.split(_begin, 1)[1].split(_end, 1)[0]
    _report_values = {}
    for _line in _block.splitlines():
        _line = _line.strip()
        if not _line or "=" not in _line:
            continue
        _key, _value = _line.split("=", 1)
        _report_values[_key.strip()] = _value.strip()

    def _as_bool(value):
        if isinstance(value, bool):
            return value
        lowered = str(value).strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
        raise ValueError(f"invalid boolean: {value!r}")

    _manifest_actual_keys = (
        "summary_schema", "release_mode", "pass", "new_fail", "known_fail",
        "error", "release_blocked", "formal_release_eligible",
        "generated_at", "python", "host", "environment_label",
    )
    for _key in _manifest_actual_keys:
        if _summary.get(_key) != _actual.get(_key):
            _semantic_errors.append(
                f"manifest.{_key}={_summary.get(_key)!r} actual={_actual.get(_key)!r}")
    if int(_summary.get("skipped_test_files", -1)) != int(_actual.get("skip", -2)):
        _semantic_errors.append(
            f"manifest.skipped_test_files={_summary.get('skipped_test_files')!r} "
            f"actual.skip={_actual.get('skip')!r}")
    if int(_summary.get("skip", -1)) != int(_actual.get("skip", -2)):
        _semantic_errors.append(
            f"manifest.skip={_summary.get('skip')!r} actual.skip={_actual.get('skip')!r}")
    if sorted(_summary.get("skipped_tests", [])) != sorted(_actual.get("skipped_tests", [])):
        _semantic_errors.append("manifest/actual skipped_tests mismatch")
    if _summary.get("shards") != _actual.get("shards"):
        _semantic_errors.append("manifest/actual shards mismatch")

    _report_expected = {
        "SUMMARY_SCHEMA": int(_actual.get("summary_schema", -1)),
        "RELEASE_MODE": bool(_actual.get("release_mode")),
        "PASS": int(_actual.get("pass", -1)),
        "NEW_FAIL": int(_actual.get("new_fail", -1)),
        "KNOWN_FAIL": int(_actual.get("known_fail", -1)),
        "ERROR": int(_actual.get("error", -1)),
        "SKIP": int(_actual.get("skip", -1)),
        "RELEASE_BLOCKED": bool(_actual.get("release_blocked")),
        "FORMAL_RELEASE_ELIGIBLE": bool(_actual.get("formal_release_eligible")),
        "SHARD_COUNT": len(_actual.get("shards", [])),
        "SHARD_PASS_TOTAL": sum(int(x.get("pass", 0)) for x in _actual.get("shards", [])),
        "SHARD_NEW_FAIL_TOTAL": sum(int(x.get("new_fail", 0)) for x in _actual.get("shards", [])),
        "SHARD_KNOWN_FAIL_TOTAL": sum(int(x.get("known_fail", 0)) for x in _actual.get("shards", [])),
        "SHARD_SKIP_TOTAL": sum(int(x.get("skip", 0)) for x in _actual.get("shards", [])),
        "SHARD_ERROR_TOTAL": sum(int(x.get("error", 0)) for x in _actual.get("shards", [])),
    }
    for _key, _expected in _report_expected.items():
        if _key not in _report_values:
            _semantic_errors.append(f"TEST_RESULTS missing {_key}")
            continue
        try:
            _found = _as_bool(_report_values[_key]) if isinstance(_expected, bool) else int(_report_values[_key])
        except Exception as _exc:
            _semantic_errors.append(f"TEST_RESULTS invalid {_key}: {_exc}")
            continue
        if _found != _expected:
            _semantic_errors.append(f"TEST_RESULTS {_key}={_found!r} actual={_expected!r}")
    try:
        _report_skips = json.loads(_report_values.get("SKIPPED_TESTS_JSON", "[]"))
    except Exception as _exc:
        _semantic_errors.append(f"TEST_RESULTS invalid SKIPPED_TESTS_JSON: {_exc}")
        _report_skips = []
    if sorted(_report_skips) != sorted(_actual.get("skipped_tests", [])):
        _semantic_errors.append("TEST_RESULTS/actual skipped_tests mismatch")

    _status = str(_manifest.get("release_status", ""))
    if _status not in {"release-candidate", "rc", "validation-pending"}:
        if not _summary.get("release_mode"):
            _semantic_errors.append("formal release requires release_mode=true")
        if not _summary.get("formal_release_eligible"):
            _semantic_errors.append("formal release is not eligible")
        if str(_summary.get("environment_label", "")) != "base117":
            _semantic_errors.append("formal release requires environment_label=base117")
        if not ((_summary.get("comparison_gate") or {}).get("eligible")):
            _semantic_errors.append("formal release requires eligible comparison gate")
except Exception as _exc:
    _semantic_errors.append(f"semantic verification error: {_exc}")
check("V0: manifest/test_results/TEST_RESULTSの三者が一致",
      not _semantic_errors, "; ".join(_semantic_errors[:12]))

# ════════════════════════════════════════════════════════════
sec("V1: ハードコードパスの検出（フォールバック以外）")
_HARD = re.compile(r'["\'](?:/home/claude/(?:output_check|desktop1r5l72q(?:_outer|_outer_parent)?|report_gen\.py|timeline\.py|cabtest|extract)|/mnt/user-data/uploads)')
_ALLOW_CONTEXT = ("os.environ.get", "_c and", "for _c in", '"/opt/llm/analysis"',
                  "CHECKPC_TEST_EXTRACT", "CHECKPC_SCRIPTS", "CHECKPC_TEST_UPLOADS",
                  "os.path.dirname(HERE)", 'os.path.dirname(os.path.abspath(__file__))')
py_files = [f for f in os.listdir(HERE) if f.endswith(".py")]
violations = []
for f in sorted(py_files):
    lines = open(os.path.join(HERE, f), encoding="utf-8").read().split("\n")
    for i, line in enumerate(lines, 1):
        if not _HARD.search(line):
            continue
        if any(a in line for a in _ALLOW_CONTEXT):
            continue
        if line.lstrip().startswith("#"):
            continue
        # フォールバックタプルの継続行（直前行が "for _c in" を含む）は許容
        prev = lines[i - 2] if i >= 2 else ""
        if "for _c in" in prev or "os.environ.get" in prev:
            continue
        violations.append(f"{f}:{i}: {line.strip()[:70]}")
check("V1: ハードコードパスがフォールバック以外に無い",
      not violations, "\n    ".join(violations[:6]))


# ════════════════════════════════════════════════════════════
sec("V2: README 記載テストと実体の整合")
readme = os.path.join(HERE, "README.md")
if os.path.exists(readme):
    txt = open(readme, encoding="utf-8").read()
    mentioned = set(re.findall(r"\btest_[A-Za-z0-9_]+\.py\b", txt))
    missing = sorted(m for m in mentioned if not os.path.exists(os.path.join(HERE, m)))
    check("V2: README 記載の全テストが実在する", not missing,
          "欠落: " + ", ".join(missing))
    # 特に v3.68 のリリースブロッカー
    check("V2: test_server_chat_integration.py が実在する（D-2 ブロッカー）",
          os.path.exists(os.path.join(HERE, "test_server_chat_integration.py")))
else:
    check("V2: README.md が存在する", False, "README.md 不在")



# ════════════════════════════════════════════════════════════
sec("V2b: GUI概念図の梱包")
import hashlib
_svg = os.path.join(HERE, "system_concept.svg")
check("V2b: system_concept.svg が存在し非空",
      os.path.exists(_svg) and os.path.getsize(_svg) > 0)
if os.path.exists(_svg):
    _svg_text = open(_svg, encoding="utf-8").read()
    _svg_required = ("archive worker", "検証用ZIP", "全成果物ZIP", "Chat Lv.2", "監査ログ")
    _svg_missing = [x for x in _svg_required if x not in _svg_text]
    check("V2b: system_concept.svg が現行処理フローを含む",
          not _svg_missing, "missing: " + ", ".join(_svg_missing))
else:
    not_applicable("V2b: system_concept.svg が現行処理フローを含む",
                   "前段の必須存在checkがFAIL")

# ════════════════════════════════════════════════════════════
sec("V3: INSTALL.txt の環境変数とコードの整合")
install = os.path.join(HERE, "INSTALL.txt")
if os.path.exists(install):
    itxt = open(install, encoding="utf-8").read()
    doc_envs = set(re.findall(r"\b(CHECKPC_[A-Z0-9_]+)\b", itxt))
    code = ""
    code_files = py_files + [f for f in os.listdir(HERE) if f.endswith(".sh")]
    for f in code_files:
        code += open(os.path.join(HERE, f), encoding="utf-8").read()
    code_envs = set(re.findall(r"\b(CHECKPC_[A-Z0-9_]+)\b", code))
    # INSTALL に書かれた変数がコードに存在すること（未実装変数の記載を防ぐ）
    phantom = sorted(e for e in doc_envs if e not in code_envs)
    check("V3: INSTALL 記載の CHECKPC_* が全てコードに実在する",
          not phantom, "コード未実装: " + ", ".join(phantom))
else:
    check("V3: INSTALL.txt が存在する", False)


# ════════════════════════════════════════════════════════════
sec("V3b: 依存関係・バージョン定義")
for required in ("pyproject.toml", "requirements.txt", "requirements.lock", "checkpc-pipeline.env.example", "version.py", "runtime_identity.py", "release_manifest.json", "validate_run_provenance.py",
                 "v3.69-rc27_変更概要.md",
                 "v3.69-rc27_チャット移行プロンプト.md",
                 "Claude提示用_v3.69-rc27ダブルチェック依頼.md",
                 "validate_semantic_binding.py",
                 "run_rc27_overnight.sh", "start_rc27_overnight.sh"):

    check(f"V3b: {required} が存在", os.path.exists(os.path.join(HERE, required)))
check("V3b: package内に.env/.env.local/.env.exampleが無い",
      not any(os.path.exists(os.path.join(HERE, name))
              for name in (".env", ".env.local", ".env.example")))
try:
    _external_env_v370 = open(os.path.join(HERE, "checkpc-pipeline.env.example"),
                              encoding="utf-8").read()
    check("V3b: external environment templateがv370 profileを使用",
          "CHECKPC_BUDGET_PROFILE=v370" in _external_env_v370)
except Exception as _external_env_exc_v370:
    check("V3b: external environment templateを読める", False, str(_external_env_exc_v370))

try:
    from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION, UPGRADED_FROM_VERSION
    check("V3b: version=3.70", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
    check("V3b: schema=2.1", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
    check("V3b: formal baseline=3.69", UPGRADED_FROM_VERSION == "3.69", UPGRADED_FROM_VERSION)
    from runtime_identity import (
        EXPECTED_PIPELINE_VERSION, EXPECTED_ANALYSIS_SCHEMA_VERSION,
        EXPECTED_BUDGET_PROFILE, assert_runtime_identity,
    )
    _runtime_guard = assert_runtime_identity()
    check("V3b: runtime identity guardがversion/schema/profileと一致",
          EXPECTED_PIPELINE_VERSION == PIPELINE_VERSION
          and EXPECTED_ANALYSIS_SCHEMA_VERSION == ANALYSIS_SCHEMA_VERSION
          and EXPECTED_BUDGET_PROFILE == "v370"
          and _runtime_guard.get("pipeline_version") == PIPELINE_VERSION,
          repr(_runtime_guard))
except Exception as exc:
    check("V3b: version.py import", False, str(exc))

# ════════════════════════════════════════════════════════════
sec("V4: 新規モジュールの import 健全性")
for mod in ("token_budget", "budget_profile", "ioc_utils", "provenance",
            "depth2_select", "version", "pipeline_settings", "atomic_io",
            "llm_runtime", "source_id", "evidence_meta", "collector_profile",
            "ingest_manifest", "path_safety", "prompt_safety", "chat_lv2",
            "archive_manager", "runtime_identity", "comparison_provenance",
            "compare_runs", "comparison_approval", "comparison_release_gate",
            "validate_run_provenance", "validate_semantic_binding",
            "directory_policy", "directory_index"):
    try:
        __import__(mod)
        check(f"V4: {mod} が import できる", True)
    except Exception as e:
        check(f"V4: {mod} が import できる", False, str(e))


# ════════════════════════════════════════════════════════════
sec("V4b: Python 3構文検査（legacy_py2除外）")
import py_compile
import tempfile as _tempfile_compile
_compile_errors = []
with _tempfile_compile.TemporaryDirectory(prefix="checkpc_pycompile_") as _compile_dir:
    for _idx, _f in enumerate(sorted(py_files)):
        try:
            _cfile = os.path.join(_compile_dir, f"{_idx:04d}.pyc")
            py_compile.compile(os.path.join(HERE, _f), cfile=_cfile, doraise=True)
        except Exception as _exc:
            _compile_errors.append(f"{_f}: {_exc}")
check("V4b: root Python3ファイルが全てcompile可能", not _compile_errors, "; ".join(_compile_errors[:5]))
check("V4b: legacy_py2ディレクトリが存在", os.path.isdir(os.path.join(HERE, "legacy_py2")))


# ════════════════════════════════════════════════════════════
sec("V5: budget_profile が正式検証済みフラグを持つ")
try:
    import budget_profile
    p = budget_profile.active_profile()
    # v3.70 was promoted after base117 real-machine E2E, so the active profile
    # must no longer be provisional and must not carry a re-verification
    # warning.  The numeric-equality check below is what proves promotion
    # changed metadata only.
    check("V5: プロファイルが provisional=False", p.provisional is False)
    check("V5: プロファイルが validated=True",
          getattr(p, "validated", None) is True)
    check("V5: プロファイル名が v370",
          p.name == "v370", p.name)
    check("V5: risk/fair/novelty比率が1.0",
          abs(p.risk_ratio + p.fair_ratio + p.novelty_ratio - 1.0) < 1e-9)
    d = p.to_dict()
    check("V5: to_dict に再検証警告が残っていない",
          d.get("warning") == "", repr(d.get("warning")))
    _v370_prof = budget_profile.PROFILES.get("v370") or {}
    _v369_prof = budget_profile.PROFILES.get("v369") or {}
    _prof_meta = {"name", "note", "provisional", "validated", "warning"}
    _prof_numeric_diff = sorted(
        _k for _k in set(_v370_prof) | set(_v369_prof)
        if _k not in _prof_meta and _v370_prof.get(_k) != _v369_prof.get(_k)
    )
    check("V5: v370の数値予算が正式v369と完全一致",
          not _prof_numeric_diff, repr(_prof_numeric_diff))
except Exception as e:
    check("V5: budget_profile 検証", False, str(e))


# ════════════════════════════════════════════════════════════
if "--full" in sys.argv:
    sec("V6: クリーン展開環境での run_all_tests.py")
    import tempfile
    import shutil
    tmp = tempfile.mkdtemp(prefix="checkpc_clean_")
    try:
        # Copy the exact installed package declared by SHA256SUMS.  Extension-
        # based copying omitted JSON identity files and made the new package
        # preflight fail in an otherwise valid clean-copy test.
        for line in open(os.path.join(HERE, "SHA256SUMS.txt"), encoding="utf-8"):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            _, rel = line.split("  ", 1)
            src = os.path.join(HERE, rel)
            dst = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
        shutil.copy2(os.path.join(HERE, "SHA256SUMS.txt"),
                     os.path.join(tmp, "SHA256SUMS.txt"))
        env = dict(os.environ)
        env["CHECKPC_SCRIPTS"] = tmp
        env["CHECKPC_TEST_EXTRACT"] = os.path.join(tmp, "no_extract")
        env["CHECKPC_CLEAN_INSTALL_CHILD"] = "1"   # 子の verify を SKIP
        _test_cmd = [sys.executable, "run_all_tests.py"]
        _verify_shard = os.environ.get("CHECKPC_VERIFY_SHARD_INDEX", "")
        if _verify_shard != "":
            _test_cmd += ["--shard-index", _verify_shard, "--shard-count",
                          os.environ.get("CHECKPC_VERIFY_SHARD_COUNT", "2")]
            env["CHECKPC_TEST_SHARD_CHILD"] = "1"
        r = subprocess.run(_test_cmd, cwd=tmp, env=env, capture_output=True, text=True)
        ok = "判定: 合格" in r.stdout
        check("V6: クリーン環境で run_all_tests が合格", ok,
              r.stdout.splitlines()[-1] if r.stdout else r.stderr[:200])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if "--clean-env" in sys.argv:
    sec("V7: 新規venvへの依存導入と単体試験")
    import tempfile, shutil, venv
    tmp = tempfile.mkdtemp(prefix="checkpc_venv_")
    try:
        env_dir = os.path.join(tmp, "venv")
        venv.EnvBuilder(with_pip=True).create(env_dir)
        py = os.path.join(env_dir, "bin", "python")
        pip = [py, "-m", "pip", "install"]
        wheelhouse = os.environ.get("CHECKPC_WHEELHOUSE", "")
        if wheelhouse:
            pip += ["--no-index", "--find-links", wheelhouse]
        pip += ["-r", os.path.join(HERE, "requirements.lock")]
        install_cp = subprocess.run(pip, capture_output=True, text=True, timeout=1800)
        check("V7: requirements.lockを新規venvへ導入", install_cp.returncode == 0,
              (install_cp.stderr or install_cp.stdout)[-300:])
        if install_cp.returncode == 0:
            env = dict(os.environ)
            env["CHECKPC_TEST_EXTRACT"] = os.path.join(tmp, "no_extract")
            _test_cmd = [py, os.path.join(HERE, "run_all_tests.py")]
            _verify_shard = os.environ.get("CHECKPC_VERIFY_SHARD_INDEX", "")
            if _verify_shard != "":
                _test_cmd += ["--shard-index", _verify_shard, "--shard-count",
                              os.environ.get("CHECKPC_VERIFY_SHARD_COUNT", "2")]
                env["CHECKPC_TEST_SHARD_CHILD"] = "1"
            cp = subprocess.run(_test_cmd, cwd=HERE, env=env, capture_output=True, text=True, timeout=1800)
            check("V7: 新規venvでrun_all_tests合格", cp.returncode == 0,
                  (cp.stdout or cp.stderr).splitlines()[-1] if (cp.stdout or cp.stderr) else "")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)



# ════════════════════════════════════════════════════════════
sec("V9: rc18/rc19 一般化・schema閉性・有界Step 4B")
try:
    _d2_text = open(os.path.join(HERE, "depth2_select.py"), encoding="utf-8").read()
    _an_text = open(os.path.join(HERE, "analyze_section.py"), encoding="utf-8").read()
    _run_text = open(os.path.join(HERE, "run_analysis.py"), encoding="utf-8").read()
    _cmp_text = open(os.path.join(HERE, "compare_analyzed.py"), encoding="utf-8").read()
    _rp_text = open(os.path.join(HERE, "report_gen.py"), encoding="utf-8").read()
    _rc18_test = os.path.join(HERE, "test_v369_rc18_review.py")
    _rc19_test = os.path.join(HERE, "test_v369_rc19_review.py")
    check("V9: rc18一般化回帰テストが存在",
          os.path.isfile(_rc18_test) and os.path.getsize(_rc18_test) > 0)
    check("V9: rc19有界planner回帰テストが存在",
          os.path.isfile(_rc19_test) and os.path.getsize(_rc19_test) > 0)
    check("V9: 製品名・特定通信先に依存する本番matcherが無い",
          not any(token in (_an_text + _d2_text)
                  for token in ("CodeSetup", "OllamaSetup", "119.3.160.204")))
    check("V9: user-writable execution artifactを汎用分類",
          "user_writable_execution_artifact" in _an_text
          and "is_user_writable_execution_artifact" in _d2_text)
    check("V9: score enum検査・retry・安全縮退が実装",
          "_ALLOWED_SCORES" in _an_text
          and "_call_llm_score_checked" in _an_text
          and "_normalise_score_schema" in _an_text
          and "score_normalization_warning" in _an_text)
    check("V9: netstat一般floorはMEDIUMでsource_id優先照合",
          "netstat_external_nonstandard_unattributed_medium" in _an_text
          and "_raw_entry_for_result" in _an_text
          and "source_id" in _an_text)
    check("V9: 全候補candidate_order再計画を除去",
          "def candidate_order()" not in _d2_text
          and "def _bounded_frontier()" in _d2_text)
    check("V9: policy frontierとglobal非主張を監査",
          "plan_is_policy_frontier_maximal" in _d2_text
          and "global_maximality_not_claimed" in _d2_text
          and "candidate_frontier_size" in _d2_text)
    check("V9: probe/replan/trimに操作上限がある",
          "planner_candidate_probe_limit" in _d2_text
          and "planner_replan_limit" in _d2_text
          and "planner_trim_iteration_limit" in _d2_text)
    check("V9: Step 4Bキャンセルが型付きでrun層へ伝播",
          "PipelineCancelled" in _d2_text
          and "cancel_check=cancel_check" in _an_text
          and "except PipelineCancelled" in _run_text)
    check("V9: Step 4B進捗が細分化",
          all(token in _an_text for token in (
              "候補整理", "予算trim", "backfill", "frontier最大性検査", "deferred集計")))
    check("V9: compareがscore schemaと同一/cross-depthを区別",
          "schema_findings" in _cmp_text
          and "cross-depth" in _cmp_text
          and "same-depth" in _cmp_text)
    check("V9: schema recoveryをレポートへ可視化",
          "schema_degraded" in _rp_text
          and "score_raw" in _rp_text)
    check("V9: 全件繰延を未評価として表示",
          "全件繰延・未評価" in _rp_text and "安全確認済みを意味しません" in _rp_text)
except Exception as _exc:
    check("V9: rc19一般化・有界planner検証", False, str(_exc))


# ════════════════════════════════════════════════════════════
sec("V10: rc20比較ゲート・provenance・正式昇格連携")
try:
    _cp_text = open(os.path.join(HERE, "comparison_provenance.py"), encoding="utf-8").read()
    _cr_text = open(os.path.join(HERE, "compare_runs.py"), encoding="utf-8").read()
    _ca_text = open(os.path.join(HERE, "comparison_approval.py"), encoding="utf-8").read()
    _cg_text = open(os.path.join(HERE, "comparison_release_gate.py"), encoding="utf-8").read()
    _rat_text = open(os.path.join(HERE, "run_all_tests.py"), encoding="utf-8").read()
    _src_text = open(os.path.join(HERE, "source_id.py"), encoding="utf-8").read()
    _parse_text = open(os.path.join(HERE, "parse_checkpc.py"), encoding="utf-8").read()
    _rc20_test = os.path.join(HERE, "test_v369_rc20_review.py")
    check("V10: rc20比較回帰テストが存在",
          os.path.isfile(_rc20_test) and os.path.getsize(_rc20_test) > 0)
    check("V10: 比較modeは4種類を明示指定",
          all(token in _cr_text for token in (
              '"reproducibility"', '"cross-version"', '"full-lean"',
              '"depth1-depth2"', "--mode")))
    check("V10: analyzed-only比較とrun/full archive比較を分離",
          "後方互換のanalyzed単体比較" in _cmp_text
          and "load_run" in _cr_text and "full archive" in _cr_text)
    check("V10: parsed artifact hashとraw evidence fingerprintを分離",
          "parsed_artifact_sha256" in (_cp_text + _run_text)
          and "raw_evidence_fingerprint" in (_cp_text + _parse_text))
    check("V10: source ID algorithm versionとcanonical fallbackを監査",
          "SOURCE_ID_ALGORITHM_VERSION" in _src_text
          and "canonical_fallback_used" in _cr_text
          and "raw_identity_multiset" in _cr_text)
    check("V10: Depth1/Depth2で共通provenance schemaを生成",
          "_attach_depth1_provenance" in _an_text
          and "build_section_provenance" in _an_text
          and all(token in _cp_text for token in (
              '"raw"', '"mandatory"', '"deterministic"', '"selected"',
              '"deferred"', '"evaluated"', '"unevaluated"')))
    check("V10: metadata初期化がfail-closed",
          "comparison metadata initialization failed" in _an_text
          and "runtime_fingerprint" in _an_text)
    check("V10: deterministic HIGH由来を構造化",
          "deterministic_origin" in _an_text and "deterministic_origin" in _cr_text)
    check("V10: comparison resultとapprovalを分離しSHA結合",
          "comparison_result_schema" in _cr_text
          and "comparison_result_sha256" in _ca_text
          and "comparison_approval_schema" in _ca_text)
    check("V10: release gateが4mode・FAIL・未承認REVIEWを検査",
          "REQUIRED_MODES" in _cg_text
          and "unresolved_review_ids" in _cg_text
          and "eligible" in _cg_text)
    check("V10: release modeがcomparison gate directoryを必須化",
          "CHECKPC_COMPARISON_GATE_DIR" in _rat_text
          and 'comparison_gate.get("eligible"' in _rat_text)
    check("V10: rc20で個別9件・製品名・通信先の保持規則を追加していない",
          not any(token in (_cp_text + _cr_text + _an_text) for token in (
              "AppCompatCache 6", "DNS cache 3", "CodeSetup", "OllamaSetup",
              "119.3.160.204")))
except Exception as _exc:
    check("V10: rc20比較ゲート検証", False, str(_exc))


# ════════════════════════════════════════════════════════════
sec("V11: rc21 provenance帰属・release gate fail-closed")
try:
    _rc21_test = os.path.join(HERE, "test_v369_rc21_review.py")
    check("V11: rc21重点回帰テストが存在",
          os.path.isfile(_rc21_test) and os.path.getsize(_rc21_test) > 0)
    check("V11: Depth1 deterministic分類はreason文字列に依存しない",
          '"ルールベース" in reason_text' not in _an_text
          and '"LLM未送信" in reason_text' not in _an_text
          and '"LLM未使用" in reason_text' not in _an_text)
    check("V11: Depth1は処理時点planと構造化originを使用",
          "_depth1_provenance_plan" in _an_text
          and "deterministic_origin" in _an_text
          and "_result_entry_raw_indices" in _an_text)
    check("V11: attribution不能をdeferredへ暗黙分類しない",
          "provenance_complete" in _an_text
          and "attribution_error_count" in _an_text
          and "attribution_errors" in _an_text
          and "never infer deterministic" in _an_text)
    check("V11: Depth2 evaluated/unevaluatedを実測再構築",
          "_evaluated" in _an_text
          and "_selected_indices - _evaluated" in _an_text
          and "mark_unevaluated" in _an_text)
    check("V11: comparison result validatorをapprovalとrelease gateで共用",
          "validate_result_object" in _ca_text
          and "load_result" in _cg_text
          and "compute_result_id" in (_ca_text + _cr_text))
    check("V11: result schema・status・artifact SHAをfail-closed検査",
          "comparison_result_schema" in _ca_text
          and "ALLOWED_RESULT_STATUSES" in _ca_text
          and "parsed_sha256" in _ca_text
          and "analyzed_sha256" in _ca_text
          and '{"PASS", "REVIEW"}' in _cg_text)
    check("V11: source ID coverageとprovenance完全性を比較前検査",
          "parsed_source_id_missing" in _cr_text
          and "stage_source_id_coverage_incomplete" in _cr_text
          and "provenance_incomplete" in _cr_text
          and "analyzed_source_id_missing" in _cr_text)
    check("V11: rc21で個別製品・通信先・9件保持規則を追加していない",
          not any(token in (_cp_text + _cr_text + _an_text + _cg_text) for token in (
              "AppCompatCache 6", "DNS cache 3", "CodeSetup", "OllamaSetup",
              "119.3.160.204")))
except Exception as _exc:
    check("V11: rc21 provenance・release gate検証", False, str(_exc))


# ════════════════════════════════════════════════════════════
sec("V12: rc22 .envログ秘密値非表示")
try:
    import contextlib as _contextlib
    import io as _io
    import tempfile as _tempfile
    from pathlib import Path as _Path
    from vt_post import load_dotenv_simple as _load_dotenv_simple

    _rc22_test = os.path.join(HERE, "test_v369_rc22_review.py")
    check("V12: rc22重点回帰テストが存在",
          os.path.isfile(_rc22_test) and os.path.getsize(_rc22_test) > 0)

    _vt_source = open(os.path.join(HERE, "vt_post.py"), encoding="utf-8").read()
    check("V12: legacy部分マスク辞書を撤去",
          "masked =" not in _vt_source and "→ {masked}" not in _vt_source)
    check("V12: .envログはソート済みキー名のみ",
          "loaded_keys = sorted(loaded)" in _vt_source
          and "loaded_keys={loaded_keys}" in _vt_source)

    _env_snapshot = dict(os.environ)
    try:
        with _tempfile.TemporaryDirectory() as _td:
            _secret_proxy = "verify-proxy-secret-value"
            _secret_hash = "verify-pbkdf2-secret-digest"
            _Path(_td, ".env").write_text(
                "VT_PROXY=http://user:" + _secret_proxy + "@192.0.2.40:8486\n"
                "PIPELINE_AUTH_PBKDF2=310000$verify$" + _secret_hash + "\n"
                "BENIGN_SETTING=verify-benign-value\n",
                encoding="utf-8",
            )
            for _key in ("VT_PROXY", "PIPELINE_AUTH_PBKDF2", "BENIGN_SETTING"):
                os.environ.pop(_key, None)
            _buf = _io.StringIO()
            with _contextlib.redirect_stdout(_buf), _contextlib.redirect_stderr(_buf):
                _loaded = _load_dotenv_simple(_td)
            _out = _buf.getvalue()
            _no_value_leak = all(_value not in _out for _value in (
                _secret_proxy, _secret_hash, "verify-benign-value"))
            check("V12: proxy userinfo・PBKDF2・通常値を一切出力しない",
                  _no_value_leak, "" if _no_value_leak else _out)
            _keys_retained = all(_key in _out for _key in _loaded)
            check("V12: 診断用キー名は保持",
                  _keys_retained, "" if _keys_retained else _out)
    finally:
        os.environ.clear()
        os.environ.update(_env_snapshot)
except Exception as _exc:
    check("V12: rc22 .envログ秘密値非表示検証", False, str(_exc))


# ════════════════════════════════════════════════════════════
sec("V13: rc23 Defender deterministic provenance completeness")
try:
    import analyze_section as _analyze_section
    from comparison_provenance import (
        stage_indices as _stage_indices,
        validate_section_provenance as _validate_section_provenance,
    )
    from source_id import assign_source_ids as _assign_source_ids

    _rc23_test = os.path.join(HERE, "test_v369_rc23_review.py")
    check("V13: rc23重点回帰テストが存在",
          os.path.isfile(_rc23_test) and os.path.getsize(_rc23_test) > 0)

    _empty_prov = _analyze_section._build_defender_quarantine_provenance([])
    check("V13: Defender空sectionのprovenanceが完全",
          _empty_prov.get("raw_count") == 0
          and _empty_prov.get("provenance_complete") is True
          and _validate_section_provenance(_empty_prov) == [],
          repr(_empty_prov))

    _def_raw = [
        {"threat_name": "Trojan:Win32/Fixture.A",
         "path": r"C:\Temp\fixture.exe"},
        {"threat_name": "",
         "path": "C:\\ProgramData\\Microsoft\\Windows Defender\\Quarantine\\ResourceData\\AA\\" + "A" * 40},
    ]
    _assign_source_ids("b" * 64, "defender_quarantine", _def_raw)
    _def_prov = _analyze_section._build_defender_quarantine_provenance(_def_raw)
    _det_stage = (_def_prov.get("stages") or {}).get("deterministic") or {}
    check("V13: Defender全rawがdeterministic",
          _stage_indices(_def_prov, "deterministic") == {0, 1},
          repr(_def_prov))
    check("V13: Defender source ID coverageが完全",
          _det_stage.get("source_ids_complete") is True
          and len(_det_stage.get("source_ids") or []) == 2,
          repr(_det_stage))
    check("V13: Defender selected/evaluated/unevaluatedは空集合",
          _stage_indices(_def_prov, "selected") == set()
          and _stage_indices(_def_prov, "evaluated") == set()
          and _stage_indices(_def_prov, "unevaluated") == set(),
          repr(_def_prov))
    _an_source = open(os.path.join(HERE, "analyze_section.py"), encoding="utf-8").read()
    check("V13: Defender Depth2経路が共通provenance builderを使用",
          '_res["_provenance"] = _build_defender_quarantine_provenance(raw)' in _an_source
          and '"deterministic_ranges": _compress_indices(range(len(raw)))' not in _an_source,
          "legacy hand-written Defender provenance remains")
except Exception as _exc:
    check("V13: rc23 Defender provenance検証", False, str(_exc))


# ════════════════════════════════════════════════════════════
sec("V14: rc24 all-raw rule provenance coverage")
try:
    import analyze_section as _analyze_section_rc24
    from comparison_provenance import (
        missing_raw_backed_provenance_sections as _missing_provenance,
        stage_indices as _stage_indices_rc24,
        validate_section_provenance as _validate_provenance_rc24,
    )
    from source_id import assign_source_ids as _assign_source_ids_rc24

    _rc24_test = os.path.join(HERE, "test_v369_rc24_review.py")
    check("V14: rc24重点回帰テストが存在",
          os.path.isfile(_rc24_test) and os.path.getsize(_rc24_test) > 0)
    _checker = os.path.join(HERE, "validate_run_provenance.py")
    check("V14: 軽量provenance checkerが存在",
          os.path.isfile(_checker) and os.path.getsize(_checker) > 0)

    _fixtures = {
        "task_141": ([{"identifier": "EventID 141", "task_name": "Fixture"}],
                     "task_deleted_rule"),
        "rdp_inbound": ([{"event_id": 1149, "source_ip": "203.0.113.10"}],
                        "rdp_inbound_rule"),
        "userassist": ([{"path": r"C:\Users\fixture\Downloads\sample.exe"},
                        {"path": r"C:\Windows\System32\notepad.exe"}],
                       "userassist_rule"),
    }
    for _section, (_raw, _reason) in _fixtures.items():
        _assign_source_ids_rc24("c" * 64, _section, _raw)
        _result = {"section": _section, "entries": []}
        _analyze_section_rc24._attach_complete_rule_provenance(
            _section, _raw, _result, reason=_reason)
        _prov = _result.get("_provenance") or {}
        _det = (_prov.get("stages") or {}).get("deterministic") or {}
        check(f"V14: {_section}全rawがdeterministic",
              _stage_indices_rc24(_prov, "deterministic") == set(range(len(_raw)))
              and _validate_provenance_rc24(_prov) == [], repr(_prov))
        check(f"V14: {_section} source ID coverage完全",
              _det.get("source_ids_complete") is True
              and len(_det.get("source_ids") or []) == len(_raw), repr(_det))

    _parsed = {
        "sections": {"userassist": _fixtures["userassist"][0]},
        "event_logs": {
            "task_141": _fixtures["task_141"][0],
            "rdp_inbound": _fixtures["rdp_inbound"][0],
        },
    }
    _analyzed = {
        "sections": {
            "task_141": {"entries": []},
            "rdp_inbound": {"entries": []},
            "userassist": {"entries": []},
        }
    }
    check("V14: 欠落provenanceを3sectionすべて検出",
          _missing_provenance(_parsed, _analyzed)
          == ["rdp_inbound", "task_141", "userassist"],
          repr(_missing_provenance(_parsed, _analyzed)))
except Exception as _exc:
    check("V14: rc24 rule provenance検証", False, str(_exc))


# ════════════════════════════════════════════════════════════
sec("V15: rc25 audit boundary hardening")
_rc25_test = os.path.join(HERE, "test_v369_rc25_review.py")
_pkg_guard = os.path.join(HERE, "package_integrity.py")
_bundle_builder = os.path.join(HERE, "build_reproducibility_bundle.py")
_cmp_prov_text = open(os.path.join(HERE, "comparison_provenance.py"), encoding="utf-8").read()
_an_text_rc25 = open(os.path.join(HERE, "analyze_section.py"), encoding="utf-8").read()
_run_text_rc25 = open(os.path.join(HERE, "run_analysis.py"), encoding="utf-8").read()
_cmp_text_rc25 = open(os.path.join(HERE, "compare_runs.py"), encoding="utf-8").read()
check("V15: rc25重点回帰テストが存在", os.path.isfile(_rc25_test))
check("V15: parsed section allowlistがtasklistのみ", 'PARSED_ANALYSIS_EXEMPT_SECTIONS = frozenset({"tasklist"})' in _cmp_prov_text)
check("V15: analyzed section欠落検出が存在", "missing_analyzed_raw_sections" in _cmp_prov_text)
check("V15: atomic text provenanceが存在", "_attach_atomic_text_rule_provenance" in _an_text_rc25)
check("V15: system_104がatomic provenanceを使用", 'reason="event_log_clear_rule"' in _an_text_rc25)
check("V15: package SHA preflightが存在", os.path.isfile(_pkg_guard) and "assert_package_integrity" in _run_text_rc25)
check("V15: package manifest SHAが成果物へ伝播", "package_manifest_sha256" in _run_text_rc25)
check("V15: comparison scopeが明記", "comparison_scope" in _cmp_text_rc25 and "correlation_*.json" in _cmp_text_rc25)
check("V15: downstream evidence bundle生成器が存在", os.path.isfile(_bundle_builder))

# ════════════════════════════════════════════════════════════
sec("V16: rc26 semantic comparison and evidence binding")
_rc26_test = os.path.join(HERE, "test_v369_rc26_review.py")
_cmp_text_rc26 = open(os.path.join(HERE, "compare_runs.py"), encoding="utf-8").read()
_bundle_text_rc26 = open(os.path.join(HERE, "build_reproducibility_bundle.py"), encoding="utf-8").read()
check("V16: rc26重点回帰テストが存在", os.path.isfile(_rc26_test))
for _field in ("identifier", "reason", "iocs", "mitre", "lolbas", "decoded"):
    check(f"V16: semantic field {_field}を比較", f'"{_field}"' in _cmp_text_rc26)
check("V16: comparison result bundle option", "--comparison-result" in _bundle_text_rc26)
check("V16: comparison result included scope", "comparison_result_included" in _bundle_text_rc26)

# ════════════════════════════════════════════════════════════
sec("V17: rc27 semantic source binding and approval cardinality")
_rc27_test = os.path.join(HERE, "test_v369_rc27_review.py")
_semantic_validator = os.path.join(HERE, "validate_semantic_binding.py")
_runner = os.path.join(HERE, "run_rc27_overnight.sh")
_an_text_rc27 = open(os.path.join(HERE, "analyze_section.py"), encoding="utf-8").read()
_cmp_text_rc27 = open(os.path.join(HERE, "compare_runs.py"), encoding="utf-8").read()
_approval_text_rc27 = open(os.path.join(HERE, "comparison_approval.py"), encoding="utf-8").read()
check("V17: rc27重点回帰テストが存在", os.path.isfile(_rc27_test))
check("V17: semantic binding validatorが存在", os.path.isfile(_semantic_validator))
check("V17: 全list-backed sectionを番号化", "全list-backed sectionを番号付きブロックへ統一" in _an_text_rc27)
check("V17: source_index/source_id/identifier三者整合", "source_index_triple" in _an_text_rc27 and "identifier_index_mismatch" in _an_text_rc27)
check("V17: raw binding validatorがfail closed", "raw_index_identifier_mismatch" in _an_text_rc27)
check("V17: duplicate issueをoccurrence_countへ集約", "occurrence_count" in _cmp_text_rc27 and "_aggregate_issues" in _cmp_text_rc27)
check("V17: approval schema v2", "COMPARISON_APPROVAL_SCHEMA = 2" in _approval_text_rc27)
check("V17: overnight runnerは自動approvalを禁止", os.path.isfile(_runner) and "automatic approvals are prohibited" in open(_runner, encoding="utf-8").read())

# ════════════════════════════════════════════════════════════
sec("V18: rc28 explicit binding and strict completeness")
_rc28_test = os.path.join(HERE, "test_v369_rc28_review.py")
_an_text_rc28 = open(os.path.join(HERE, "analyze_section.py"), encoding="utf-8").read()
_prompt_text_rc28 = open(os.path.join(HERE, "section_prompts.py"), encoding="utf-8").read()
_prov_text_rc28 = open(os.path.join(HERE, "validate_run_provenance.py"), encoding="utf-8").read()
check("V18: rc28重点回帰テストが存在", os.path.isfile(_rc28_test))
check("V18: binding_identifierを入力へ明示", "binding_identifier:" in _an_text_rc28)
check("V18: promptがbinding_identifier転記を要求", "binding_identifier が表す文字列値" in _prompt_text_rc28)
check("V18: multi-entry identifier mismatchを維持", "identifier_index_mismatch" in _an_text_rc28)
check("V18: singletonはidentifier欠落のみ救済", "singleton_source_id_identifier_omitted" in _an_text_rc28)
check("V18: D1 deterministic aggregateをplan照合", "deterministic_plan_aggregate" in _an_text_rc28 and "deterministic_aggregate_plan_mismatch" in _an_text_rc28)
check("V18: rejection reasonを監査", '"rejection_reasons"' in _an_text_rc28)
check("V18: release-strict validatorが存在", "--release-strict" in _prov_text_rc28 and "release-strict chunk_errors" in _prov_text_rc28)
_smoke_validator_rc28 = os.path.join(HERE, "validate_binding_smoke.py")
check("V18: section-limited binding smoke validatorが存在", os.path.isfile(_smoke_validator_rc28))
if os.path.isfile(_smoke_validator_rc28):
    _smoke_text_rc28 = open(_smoke_validator_rc28, encoding="utf-8").read()
    check("V18: smoke validatorが未評価・chunk errorを拒否",
          "selected != evaluated" in _smoke_text_rc28 and "chunk_errors" in _smoke_text_rc28)
for _doc in ("v3.69-rc28_変更概要.md", "v3.69-rc28_実機CLI検証手順.md", "v3.69-rc28_TEST_RESULTS.md"):
    check(f"V18: {_doc} が存在", os.path.isfile(os.path.join(HERE, _doc)))


# ════════════════════════════════════════════════════════════
sec("V19: rc29 deterministic Windows path representation equivalence")
_rc29_test = os.path.join(HERE, "test_v369_rc29_review.py")
_an_text_rc29 = open(os.path.join(HERE, "analyze_section.py"), encoding="utf-8").read()
_prompt_text_rc29 = open(os.path.join(HERE, "section_prompts.py"), encoding="utf-8").read()
check("V19: rc29重点回帰テストが存在", os.path.isfile(_rc29_test))
check("V19: representation candidate関数が存在", "_binding_identifier_candidates" in _an_text_rc29)
check("V19: SystemRoot/windir同値化", "%systemroot%|%windir%" in _an_text_rc29)
check("V19: CommonProgramFiles同値化", "%commonprogramfiles%" in _an_text_rc29)
check("V19: multi-entry mismatch拒否を維持", "identifier_index_mismatch" in _an_text_rc29)
check("V19: promptが重複JSONエスケープを禁止", "外側引用符やJSONエスケープを重ねない" in _prompt_text_rc29)
for _doc in ("v3.69-rc29_変更概要.md", "v3.69-rc29_実機CLI検証手順.md", "v3.69-rc29_TEST_RESULTS.md"):
    check(f"V19: {_doc} が存在", os.path.isfile(os.path.join(HERE, _doc)))

# ════════════════════════════════════════════════════════════
sec("V20: rc30 canonical directory policy and raw-search grounding")
_rc30_test = os.path.join(HERE, "test_v369_rc30_vbe_policy.py")
_dir_policy = os.path.join(HERE, "directory_policy.py")
_an_text_rc30 = open(os.path.join(HERE, "analyze_section.py"), encoding="utf-8").read()
_d2_text_rc30 = open(os.path.join(HERE, "depth2_select.py"), encoding="utf-8").read()
_chat_text_rc30 = open(os.path.join(HERE, "chat_tools.py"), encoding="utf-8").read()
check("V20: rc30重点回帰テストが存在", os.path.isfile(_rc30_test))
check("V20: canonical directory policyが存在", os.path.isfile(_dir_policy))
if os.path.isfile(_dir_policy):
    _policy_text_rc30 = open(_dir_policy, encoding="utf-8").read()
    check("V20: VBE/JSE/WSF/MSI/MSPをcanonical化",
          all(token in _policy_text_rc30 for token in ('.vbe', '.jse', '.wsf', '.msi', '.msp')))
check("V20: M1既定上限80・親8・配置32",
      'CHECKPC_DIR_M1_MAX", "80"' in _an_text_rc30
      and 'CHECKPC_DIR_M1_PARENT_MAX", "8"' in _an_text_rc30
      and 'CHECKPC_DIR_M1_PLACEMENT_MAX", "32"' in _an_text_rc30)
check("V20: Tier Rに固定100件上限なし", "Tier R has no fixed maximum" in _an_text_rc30)
check("V20: Depth2 M1繰延理由を監査", "m1_policy_bound" in _d2_text_rc30)
check("V20: chat parsed raw fallbackを実装",
      "parsed_directory_raw" in _chat_text_rc30 and "raw_fallback_searched" in _chat_text_rc30)
for _doc in ("v3.69-rc30_変更概要.md", "v3.69-rc30_実機CLI検証手順.md", "v3.69-rc30_TEST_RESULTS.md"):
    check(f"V20: {_doc} が存在", os.path.isfile(os.path.join(HERE, _doc)))

# ════════════════════════════════════════════════════════════
sec("V21: v3.70 directory evidence determinism and coverage")
try:
    import ast as _ast_v370
    import random as _random_v370
    import tempfile as _tempfile_v370
    from pathlib import Path as _Path_v370
    import analyze_section as _an_v370
    import directory_policy as _dp_v370
    import directory_index as _di_v370
    import ioc_utils as _ioc_v370
    import chat_lv2 as _chatlv2_v370
    import report_gen as _rg_v370
    import pdf_export as _pdf_v370
    import compare_analyzed as _ca_v370
    import comparison_provenance as _cp_v370
    import source_id as _sid_v370
    from chat_tools import ChatContext as _ChatContext_v370

    _canon_v370 = set(_dp_v370.EXECUTABLE_EXTS)
    check("V21: IOC拡張子集合がcanonical execution setを包含",
          not (_canon_v370 - set(_ioc_v370._KNOWN_FILE_EXTS)),
          repr(sorted(_canon_v370 - set(_ioc_v370._KNOWN_FILE_EXTS))))
    check("V21: VT拡張子集合がcanonical execution setを包含",
          not (_canon_v370 - set(_ioc_v370._VT_FILEPATH_EXTS)),
          repr(sorted(_canon_v370 - set(_ioc_v370._VT_FILEPATH_EXTS))))
    _url_ok_v370, _url_detail_v370 = _chatlv2_v370.validate_vt_ioc("sample.url")
    _com_ok_v370, _com_detail_v370 = _chatlv2_v370.validate_vt_ioc("example.com")
    _fake_ok_v370, _fake_detail_v370 = _chatlv2_v370.validate_vt_ioc("sample.notarealtld")
    check("V21: .urlファイル名を外部送信せず有効.comドメインを維持",
          ".url" in _ioc_v370._KNOWN_FILE_EXTS
          and not _url_ok_v370
          and _com_ok_v370 and _com_detail_v370.get("ioc_type") == "fqdn"
          and not _fake_ok_v370 and _fake_detail_v370.get("reason") == "invalid_tld",
          repr((_url_detail_v370, _com_detail_v370, _fake_detail_v370)))
    try:
        _ast_v370.parse(_Path_v370(_dp_v370.__file__).read_text(encoding="utf-8"),
                        feature_version=(3, 10))
        _py310_parse_v370 = True
    except SyntaxError as _syntax_v370:
        _py310_parse_v370 = False
    check("V21: directory_policyがPython 3.10文法でparse可能", _py310_parse_v370)

    def _e_v370(path, index=0):
        parent, _, name = path.rpartition("\\")
        return {"date": "2026/07/15  10:09", "size": "371", "name": name,
                "path": path, "dir": parent,
                "source_id": f"directory:{index:08d}"}

    _wef_v370 = _e_v370(r"C:\Users\Public\Music\wef.vbe", 1)
    _wef_cls_v370 = _an_v370._classify_dir_entry(_wef_v370)
    check("V21: wef.vbeがLevel1/M1/floor/IOCの全経路で有効",
          _an_v370.entry_matches_level1("directory", _wef_v370)
          and _dp_v370.evidence_tier(_wef_v370) == "M1"
          and _an_v370._floor_rule(_wef_v370["path"]) is not None
          and _ioc_v370.classify_ioc(_wef_v370["path"]) == "filepath"
          and _an_v370._dir_anomaly_score(_wef_v370, _wef_cls_v370) >= 120)

    def _alpha_v370(i):
        _alphabet_v370 = "ghijklmnopqrstuvwxyz"
        _chars_v370 = []
        _n_v370 = int(i)
        for _ in range(5):
            _chars_v370.append(_alphabet_v370[_n_v370 % len(_alphabet_v370)])
            _n_v370 //= len(_alphabet_v370)
        return "risk_" + "".join(_chars_v370)

    _m1_v370 = [_e_v370(rf"C:\Users\Public\Music\junk_{_alpha_v370(i)}.exe", i)
                 for i in range(200)]
    _r_v370 = [_e_v370(rf"C:\Users\u\Downloads\{_alpha_v370(i)}.exe", 1000+i)
                for i in range(220)]
    def _run_v370(values):
        _scored = []
        for _entry in values:
            _cls = _an_v370._classify_dir_entry(_entry)
            if _cls != "D":
                _scored.append((_an_v370._dir_anomaly_score(_entry, _cls), _cls, _entry))
        _selected, _overflow, _info = _an_v370._select_dir_llm_entries(
            _scored, max_llm=200, sig_max=3, m1_max=80,
            m1_parent_max=8, m1_placement_max=32)
        _paths = sorted(_dp_v370.entry_path(x).casefold() for x in _selected)
        return _paths, _info

    _base_paths_v370, _base_info_v370 = _run_v370(_m1_v370 + _r_v370)
    _order_ok_v370 = True
    for _seed_v370 in (1, 2, 3, 42):
        _shuffled_v370 = list(_m1_v370 + _r_v370)
        _random_v370.Random(_seed_v370).shuffle(_shuffled_v370)
        _paths_v370, _info_v370 = _run_v370(_shuffled_v370)
        _order_ok_v370 &= (_paths_v370 == _base_paths_v370)
    check("V21: Depth1 directory選抜が入力順非依存", _order_ok_v370)
    check("V21: M1親8件/Tier R残余192件/固定100上限なし",
          _base_info_v370["tier_selected"] == {"M0": 0, "M1": 8, "R": 192},
          repr(_base_info_v370.get("tier_selected")))
    _m0_flood_v370 = [_e_v370(rf"C:\Users\u\Downloads\invoice_{i:03d}.pdf.vbe", 3000+i)
                       for i in range(100)]
    _m0_paths_v370, _m0_info_v370 = _run_v370(_m0_flood_v370)
    check("V21: M0同一シグネチャ大量投入がsig_max=3で有界",
          _m0_info_v370["tier_selected"]["M0"] == 3
          and _m0_info_v370["sig_deferred"] == 97, repr(_m0_info_v370))
    _deep_js_v370 = _e_v370(r"C:\Users\u\AppData\Local\Browser\Extensions\abcdef\script.js", 4000)
    check("V21: 深いAppData/browser JSがM1外",
          _dp_v370.evidence_tier(_deep_js_v370) == "R")
    _known_temp_v370 = _e_v370(r"C:\Users\u\AppData\Local\Temp\stage\payload.vbe", 4001)
    _deep_temp_v370 = _e_v370(r"C:\Users\u\AppData\Local\Temp\vendor\package\assets\payload.js", 4002)
    _arbitrary_temp_v370 = _e_v370(r"C:\node_modules\pkg\temp\build.js", 4003)
    _browser_temp_v370 = _e_v370(r"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Extensions\x\temp\y.js", 4004)
    check("V21: Level1候補判定とM1優先判定を既知Tempツリーで分離",
          _dp_v370.m1_placement(_known_temp_v370) == "general_temp"
          and _an_v370.entry_matches_level1("directory", _deep_temp_v370)
          and _dp_v370.evidence_tier(_deep_temp_v370) == "R"
          and not _dp_v370.m1_placement(_deep_temp_v370)
          and not _an_v370.entry_matches_level1("directory", _arbitrary_temp_v370)
          and _dp_v370.evidence_tier(_arbitrary_temp_v370) == "R"
          and not _an_v370.entry_matches_level1("directory", _browser_temp_v370)
          and _dp_v370.evidence_tier(_browser_temp_v370) == "R")
    check("V21: deferred理由会計がtier繰延総数と一致",
          sum(_base_info_v370["deferred_reason_counts"].values())
          == sum(_base_info_v370["tier_deferred"].values()),
          repr(_base_info_v370))
    check("V21: signature_diversityは予算内で評価された重複のみを表す",
          _base_info_v370.get("deferred_reason_semantics", {}).get("signature_diversity")
          == "duplicate signature encountered before selection budget was exhausted",
          repr(_base_info_v370.get("deferred_reason_semantics")))
    check("V21: M1親別監査値がparent_max以内",
          all(int(n) <= 8 for _p, n in _base_info_v370["m1_selected_by_parent_top"]),
          repr(_base_info_v370.get("m1_selected_by_parent_top")))
    check("V21: comparison provenance/source-id schemaを1で維持",
          _cp_v370.COMPARISON_PROVENANCE_SCHEMA_VERSION == "1"
          and _sid_v370.SOURCE_ID_ALGORITHM_VERSION == "1")
    _policy_only_a_v370 = {"sections": {"directory": {"entries": [],
                            "_directory_policy": {"coverage_degraded": False}}}}
    _policy_only_b_v370 = {"sections": {"directory": {"entries": [],
                            "_directory_policy": {"coverage_degraded": True}}}}
    check("V21: directory policy metadataが比較証拠差分を生成しない",
          _ca_v370.entry_multiset(_policy_only_a_v370)
          == _ca_v370.entry_multiset(_policy_only_b_v370))

    _policy_v370 = {
        "tier_total": {"M0": 0, "M1": 281, "R": 2687},
        "tier_selected": {"M0": 0, "M1": 76, "R": 124},
        "deferred_reason_counts": {"signature_diversity": 852,
                                   "m1_policy_bound": 205,
                                   "over_normal_budget": 1711},
        "coverage_degraded": True,
    }
    _analyzed_v370 = {"meta": {"hostname": "HOST"}, "sections": {
        "directory": {"entries": [], "_directory_policy": _policy_v370}}}
    _notice_v370 = "\n".join(_rg_v370._directory_coverage_notice(_analyzed_v370))
    _standard_md_v370 = _rg_v370.generate_report(_analyzed_v370, {}, full=False)
    _full_md_v370 = _rg_v370.generate_report(_analyzed_v370, {}, full=True)
    _pdf_bytes_v370 = _pdf_v370.md_to_pdf(_standard_md_v370, title="v3.70 coverage verifier")
    check("V21: report/PDF元Markdownが候補/評価/未評価件数を露出",
          "2,968件中" in _notice_v370 and "2,768件" in _notice_v370
          and "2,968件中" in _standard_md_v370 and "2,768件" in _standard_md_v370
          and "2,968件中" in _full_md_v370 and "2,768件" in _full_md_v370
          and _pdf_bytes_v370.startswith(b"%PDF"),
          _notice_v370[:500])

    with _tempfile_v370.TemporaryDirectory() as _td_v370:
        _root_v370 = _Path_v370(_td_v370)
        (_root_v370 / "analyzed_HOST.json").write_text(
            json.dumps(_analyzed_v370, ensure_ascii=False), encoding="utf-8")
        _parsed_v370 = _root_v370 / "parsed_HOST.json"
        _shadow_v370 = [
            _e_v370(r"C:\Temp\a", 9001),
            _e_v370(r"C:\Temp\alpha.exe", 9002),
            _e_v370(r"C:\Temp\beta.dat", 9003),
        ]
        _parsed_v370.write_text(json.dumps({"sections": {"directory": [_wef_v370] + _shadow_v370}},
                                           ensure_ascii=False), encoding="utf-8")
        _ctx_v370 = _ChatContext_v370(_root_v370, _root_v370)
        _hit_v370 = _ctx_v370.tool_search_keyword("wef.vbe")
        check("V21: chat raw fallbackがSQLite索引を使用",
              _hit_v370.get("count") == 1
              and _hit_v370.get("scope") == "parsed_directory_raw_index"
              and _di_v370.index_path_for(_parsed_v370).is_file(),
              repr(_hit_v370))
        _shadow_hit_v370 = _ctx_v370.tool_search_keyword("a")
        check("V21: 完全一致名が部分一致raw検索を抑止しない",
              _shadow_hit_v370.get("total", _shadow_hit_v370.get("count")) >= 3
              and bool(_shadow_hit_v370.get("hits"))
              and _shadow_hit_v370["hits"][0].get("name", "").casefold() == "a",
              repr(_shadow_hit_v370))
        _miss_v370 = _ctx_v370.tool_search_keyword("definitely-not-present.xyz")
        check("V21: chatが端末上の絶対不存在を断定しない",
              "絶対的な不存在" in _miss_v370.get("note", ""), repr(_miss_v370))

    from version import UPGRADED_FROM_VERSION as _upgraded_v370
    import budget_profile as _bp_v370
    _env_template_v370 = _Path_v370(HERE, "checkpc-pipeline.env.example")
    _formal_v369_v370 = _bp_v370.PROFILES.get("v369", {})
    _profile_v370 = _bp_v370.PROFILES.get("v370", {})
    _ignore_profile_v370 = {"name", "note", "provisional", "validated"}
    check("V21: formal v3.69 operational policyを継承",
          _upgraded_v370 == "3.69"
          and _env_template_v370.is_file()
          and not any(_Path_v370(HERE, n).exists() for n in (".env", ".env.local", ".env.example"))
          and "CHECKPC_BUDGET_PROFILE=v370" in _env_template_v370.read_text(encoding="utf-8")
          and bool(_formal_v369_v370.get("validated"))
          and not bool(_formal_v369_v370.get("provisional"))
          and {k: v for k, v in _formal_v369_v370.items() if k not in _ignore_profile_v370}
              == {k: v for k, v in _profile_v370.items() if k not in _ignore_profile_v370})

    _portable_files_v370 = [
        "run_all_tests.py", "test_chat_tools_realdata.py",
        "test_report_fallback.py", "test_timeline_fixes.py",
        "test_integration_ttl4_ttl5.py", "test_vt_downgrade.py",
        "test_shim_netstat.py",
    ]
    _portable_text_v370 = "\n".join(
        open(os.path.join(HERE, name), encoding="utf-8").read()
        for name in _portable_files_v370
    )
    _forbidden_test_paths_v370 = (
        "/home" + "/claude/output_check", "/home" + "/claude/desktop1r5l72q",
        "/home" + "/claude/report_gen.py", "/home" + "/claude/timeline.py",
        "/home" + "/claude/cabtest", "/home" + "/claude/extract",
        "/mnt" + "/user-data/uploads",
    )
    check("V21: formal v3.69 real-data test portabilityを継承",
          not any(x in _portable_text_v370 for x in _forbidden_test_paths_v370)
          and 'CHECKPC_TEST_EXTRACT' in _portable_text_v370
          and 'CHECKPC_TEST_WORKDIR' in _portable_text_v370
          and 'CHECKPC_TEST_NESTED_HOST' in _portable_text_v370
          and 'CHECKPC_TEST_UPLOADS' in _portable_text_v370)

    for _doc_v370 in ("v3.70_変更概要.md", "v3.70_実機CLI検証手順.md", "v3.70_TEST_RESULTS.md",
                      "Claude提示用_v3.70ダブルチェック依頼.md"):
        check(f"V21: {_doc_v370} が存在", os.path.isfile(os.path.join(HERE, _doc_v370)))
    check("V21: v3.70重点回帰テストが存在",
          os.path.isfile(os.path.join(HERE, "test_v370_directory_evidence.py"))
          and os.path.isfile(os.path.join(HERE, "test_v370_formal_inheritance.py")))
except Exception as _exc_v370:
    check("V21: v3.70 behavior verification", False, repr(_exc_v370))

# ════════════════════════════════════════════════════════════
sec("V22: cross-version derived-field comparison")
try:
    import compare_runs as _cr_v370_cmp
    from types import SimpleNamespace as _SimpleNamespace_v370_cmp

    _old_startup_v370_cmp = {
        "path": "Ollama.lnk", "date": "2026/06/18  15:54",
        "size": "736", "source": "windows_startup",
        "suspicious": False, "source_id": "startup_folder:old",
    }
    _new_startup_v370_cmp = dict(_old_startup_v370_cmp)
    _new_startup_v370_cmp["suspicious"] = True
    _new_startup_v370_cmp["source_id"] = "startup_folder:new"
    _cross_old_ids_v370_cmp = _cr_v370_cmp._comparison_raw_identity_multiset(
        "cross-version", "startup_folder", [_old_startup_v370_cmp])
    _cross_new_ids_v370_cmp = _cr_v370_cmp._comparison_raw_identity_multiset(
        "cross-version", "startup_folder", [_new_startup_v370_cmp])
    _strict_old_ids_v370_cmp = _cr_v370_cmp._comparison_raw_identity_multiset(
        "reproducibility", "startup_folder", [_old_startup_v370_cmp])
    _strict_new_ids_v370_cmp = _cr_v370_cmp._comparison_raw_identity_multiset(
        "reproducibility", "startup_folder", [_new_startup_v370_cmp])
    _old_run_v370_cmp = _SimpleNamespace_v370_cmp(
        parsed={"sections": {"startup_folder": [_old_startup_v370_cmp]}},
        analyzed={"sections": {}})
    _new_run_v370_cmp = _SimpleNamespace_v370_cmp(
        parsed={"sections": {"startup_folder": [_new_startup_v370_cmp]}},
        analyzed={"sections": {}})
    _derived_issues_v370_cmp = []
    _cr_v370_cmp._compare_cross_version_derived_fields(
        _old_run_v370_cmp, _new_run_v370_cmp, _derived_issues_v370_cmp)
    check("V22: startup_folder派生suspicious変更をraw削除と誤認しない",
          _cross_old_ids_v370_cmp == _cross_new_ids_v370_cmp
          and _strict_old_ids_v370_cmp != _strict_new_ids_v370_cmp
          and len(_derived_issues_v370_cmp) == 1
          and _derived_issues_v370_cmp[0].get("severity") == "REVIEW"
          and _derived_issues_v370_cmp[0].get("kind") == "parsed_field_transition",
          repr(_derived_issues_v370_cmp))
    check("V22: cross-version比較専用正規化をsource-id/provenanceから分離",
          "_CROSS_VERSION_DERIVED_RAW_FIELDS" in _cr_text
          and "canonical_evidence_sha256" in _cr_text
          and "parsed_field_transition" in _cr_text
          and 'SOURCE_ID_ALGORITHM_VERSION = "1"' in open(
              os.path.join(HERE, "source_id.py"), encoding="utf-8").read())

    # The normalization allowlist is the only place where cross-version raw
    # identity is weakened.  Pin it exactly: adding a second section or a second
    # field must fail the release rather than silently lowering comparison
    # strength.
    _expected_derived_v370_cmp = {"startup_folder": {"suspicious"}}
    _actual_derived_v370_cmp = {
        str(_sec_v370_cmp): set(_fields_v370_cmp)
        for _sec_v370_cmp, _fields_v370_cmp
        in _cr_v370_cmp._CROSS_VERSION_DERIVED_RAW_FIELDS.items()
    }
    check("V22: derived-field正規化allowlistが承認済み1組に固定",
          _actual_derived_v370_cmp == _expected_derived_v370_cmp,
          repr(sorted(
              (_k_v370_cmp, sorted(_v_v370_cmp))
              for _k_v370_cmp, _v_v370_cmp in _actual_derived_v370_cmp.items()
          )))

    # Non-cross-version modes must keep byte-for-byte raw identity.
    _other_strict_v370_cmp = all(
        _cr_v370_cmp._comparison_raw_identity_multiset(
            _mode_v370_cmp, "startup_folder", [_old_startup_v370_cmp])
        != _cr_v370_cmp._comparison_raw_identity_multiset(
            _mode_v370_cmp, "startup_folder", [_new_startup_v370_cmp])
        for _mode_v370_cmp in ("reproducibility", "full-lean", "depth1-depth2")
    )
    check("V22: cross-version以外は派生フィールド差分を検出",
          _other_strict_v370_cmp)

    # Sections outside the allowlist must not be normalized at all.
    _unlisted_strict_v370_cmp = all(
        _cr_v370_cmp._comparison_raw_identity_multiset(
            "cross-version", _sec_v370_cmp, [_old_startup_v370_cmp])
        != _cr_v370_cmp._comparison_raw_identity_multiset(
            "cross-version", _sec_v370_cmp, [_new_startup_v370_cmp])
        for _sec_v370_cmp in ("persistence_reg", "directory", "task_scheduler")
    )
    check("V22: allowlist外セクションはcross-versionでも厳格",
          _unlisted_strict_v370_cmp)

    # Real raw removal must still fail even when the derived field also moved.
    _removed_run_v370_cmp = _SimpleNamespace_v370_cmp(
        parsed={"sections": {"startup_folder": []}}, analyzed={"sections": {}})
    _removal_issues_v370_cmp = []
    _cr_v370_cmp._compare_raw(
        "cross-version", _old_run_v370_cmp, _removed_run_v370_cmp,
        _removal_issues_v370_cmp)
    check("V22: 実raw削除はcross-versionでもFAIL",
          any(_row_v370_cmp.get("severity") == "FAIL"
              and _row_v370_cmp.get("kind") == "raw_evidence_removed"
              for _row_v370_cmp in _removal_issues_v370_cmp),
          repr(_removal_issues_v370_cmp))

    # Approval is keyed by issue ID, so the ID must cover every transition, not
    # just the first eight display samples, and must react to a/b value changes.
    def _transition_v370_cmp(_index, _a=False, _b=True):
        return {"identity": f"startup_folder:d{_index}:0",
                "fields": {"suspicious": {"a": _a, "b": _b}}}

    _base_tr_v370_cmp = [_transition_v370_cmp(_i) for _i in range(20)]
    _tail_tr_v370_cmp = ([_transition_v370_cmp(_i) for _i in range(8)]
                         + [_transition_v370_cmp(_i + 100) for _i in range(12)])
    _value_tr_v370_cmp = [_transition_v370_cmp(_i, _a=True, _b=False)
                          for _i in range(20)]
    _same_tr_v370_cmp = list(reversed(_base_tr_v370_cmp))

    def _digest_v370_cmp(_rows):
        return _cr_v370_cmp._evidence_digest(
            _cr_v370_cmp._sorted_transitions(_rows))

    check("V22: REVIEW証拠digestが9件目以降の変化を反映",
          _digest_v370_cmp(_base_tr_v370_cmp)
          != _digest_v370_cmp(_tail_tr_v370_cmp))
    check("V22: REVIEW証拠digestがa/b値の変化を反映",
          _digest_v370_cmp(_base_tr_v370_cmp)
          != _digest_v370_cmp(_value_tr_v370_cmp))
    check("V22: REVIEW証拠digestが入力順に依存しない",
          _digest_v370_cmp(_base_tr_v370_cmp)
          == _digest_v370_cmp(_same_tr_v370_cmp))
    check("V22: parsed_field_transitionがtransitions_digestを持つ",
          "transitions_digest" in _derived_issues_v370_cmp[0])
except Exception as _exc_v370_cmp:
    check("V22: cross-version derived-field verification", False, repr(_exc_v370_cmp))

# ════════════════════════════════════════════════════════════
sec("V23: formal promotion exact gate binding")
try:
    _promo_path_v370 = os.path.join(HERE, "promote_to_formal.py")
    _promo_text_v370 = open(_promo_path_v370, encoding="utf-8").read()
    _gate_text_v370 = open(os.path.join(HERE, "comparison_release_gate.py"),
                           encoding="utf-8").read()
    _guide_path_v370 = os.path.join(HERE, "v3.70_base117適用手順.md")
    _guide_text_v370 = (open(_guide_path_v370, encoding="utf-8").read()
                        if os.path.isfile(_guide_path_v370) else "")

    check("V23: promotionがcomparison gate directoryを必須引数化",
          '"--comparison-gate-dir"' in _promo_text_v370
          and "required=True" in _promo_text_v370)
    check("V23: promotionがgateを直接再評価",
          "evaluate_release_gate" in _promo_text_v370)
    check("V23: promotionがresultとapprovalを再検証",
          "load_result" in _promo_text_v370
          and "validate_approval" in _promo_text_v370)
    check("V23: test_resultsのgate directoryと直接結合",
          "comparison_gate.directory does not match" in _promo_text_v370
          and "test_results comparison_gate does not match" in _promo_text_v370)
    check("V23: formal_promotionへgate/result/approval SHAを記録",
          all(_token_v370 in _promo_text_v370 for _token_v370 in (
              "comparison_gate_json_sha256", "result_sha256",
              "approval_files", "compare_runs_sha256")))
    check("V23: comparisons_regeneratedを検証結果から導出",
          '"comparisons_regenerated": bool(' in _promo_text_v370
          and 'evidence.get("comparisons_regenerated")' in _promo_text_v370)
    check("V23: release gateがresult IDとapproval SHAを索引化",
          all(_token_v370 in _gate_text_v370 for _token_v370 in (
              '"result_id"', '"compare_runs_sha256"', '"approvals"', '"approval_sha256s"')))
    check("V23: promotion gate binding重点回帰が存在",
          os.path.isfile(os.path.join(HERE,
                                      "test_v370_promotion_gate_binding.py")))
    check("V23: base117手順が実CLIと正しい環境変数を使用",
          all(_token_v370 in _guide_text_v370 for _token_v370 in (
              "compare_runs.py", "--output",
              "comparison_approval.py\" create",
              "comparison_approval.py\" validate",
              "comparison_release_gate.py", "--json-out",
              "CHECKPC_TEST_ENV_LABEL=base117",
              "CHECKPC_COMPARISON_GATE_DIR",
              "/opt/llm/checkpc-pipeline-current.env"))
          and "CHECKPC_TEST_ENVIRONMENT_LABEL" not in _guide_text_v370
          and "--dir" not in _guide_text_v370)
except Exception as _exc_v370_promotion:
    check("V23: formal promotion binding verification", False,
          repr(_exc_v370_promotion))


# ════════════════════════════════════════════════════════════
sec("V24: GUI polling state preservation and header branding")
try:
    _gui_test_path_v370_ui = os.path.join(HERE, "test_v370_gui_polling_state.py")
    _server_path_v370_ui = os.path.join(HERE, "server.py")
    check("V24: GUI polling state重点回帰が存在",
          os.path.isfile(_gui_test_path_v370_ui))

    _gui_env_v370_ui = os.environ.copy()
    _gui_env_v370_ui["PYTHONDONTWRITEBYTECODE"] = "1"
    _gui_proc_v370_ui = subprocess.run(
        [sys.executable, "-B", _gui_test_path_v370_ui,
         "--server", _server_path_v370_ui, "--json"],
        cwd=HERE,
        env=_gui_env_v370_ui,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        check=False,
    )
    try:
        _gui_audit_v370_ui = json.loads(_gui_proc_v370_ui.stdout)
    except Exception:
        _gui_audit_v370_ui = {}

    _gui_baseline_rows_v370_ui = {
        row.get("name"): row
        for row in ((_gui_audit_v370_ui.get("baseline") or {}).get("checks") or [])
    }
    _gui_mutations_v370_ui = {
        row.get("name"): row
        for row in (_gui_audit_v370_ui.get("mutations") or [])
    }

    check("V24: semantic GUI auditが通常server.pyで合格",
          _gui_proc_v370_ui.returncode == 0
          and _gui_audit_v370_ui.get("ok") is True,
          (_gui_proc_v370_ui.stderr or _gui_proc_v370_ui.stdout)[-1000:])
    check("V24: header全体の可視テキストからJ-CRATを除去",
          _gui_baseline_rows_v370_ui.get(
              "header visible text removes J-CRAT", {}).get("ok") is True
          and _gui_baseline_rows_v370_ui.get(
              "header visible text keeps Qwen model", {}).get("ok") is True)
    check("V24: folder signature guard前の状態破壊を拒否",
          _gui_baseline_rows_v370_ui.get(
              "folder signature is not overwritten before guard", {}).get("ok") is True
          and _gui_baseline_rows_v370_ui.get(
              "folder DOM lookup and rebuild happen only after guard", {}).get("ok") is True)
    check("V24: option再構築後に既存選択値とsignatureを復元",
          _gui_baseline_rows_v370_ui.get(
              "folder selection is captured before select rebuild", {}).get("ok") is True
          and _gui_baseline_rows_v370_ui.get(
              "folder selection is restored after select rebuild", {}).get("ok") is True
          and _gui_baseline_rows_v370_ui.get(
              "folder signature updates after all option rebuilding", {}).get("ok") is True)
    check("V24: job-more開始タグとcapture/restore selectorが同じdata-job-idを使用",
          _gui_baseline_rows_v370_ui.get(
              "job-more details start tag carries stable data-job-id", {}).get("ok") is True
          and _gui_baseline_rows_v370_ui.get(
              "capture and restore selectors use the actual data-job-id attribute", {}).get("ok") is True)
    check("V24: matching job IDのdetailsをopen=trueで復元",
          _gui_baseline_rows_v370_ui.get(
              "restore opens matching job IDs", {}).get("ok") is True
          and _gui_baseline_rows_v370_ui.get(
              "job list replacement restores open menus after innerHTML", {}).get("ok") is True)
    _required_mutations_v370_ui = {
        "semantic_break_signature_guard",
        "semantic_break_open_restore",
        "semantic_break_data_job_id_masked",
        "semantic_add_visible_jcrat_separately",
    }
    check("V24: 4種類のsemantic negative mutationを全件拒否",
          set(_gui_mutations_v370_ui) == _required_mutations_v370_ui
          and all(_gui_mutations_v370_ui[name].get("rejected") is True
                  for name in _required_mutations_v370_ui),
          repr(_gui_mutations_v370_ui))
except Exception as _exc_v370_ui:
    check("V24: GUI polling state verification", False, repr(_exc_v370_ui))


# ════════════════════════════════════════════════════════════
sec("V25: deferred details GUI rendering")
try:
    _deferred_test = os.path.join(HERE, "test_v370_deferred_details_gui.py")
    check("V25: deferred details GUI回帰が存在", os.path.isfile(_deferred_test))
    _deferred_env = os.environ.copy()
    _deferred_env["PYTHONDONTWRITEBYTECODE"] = "1"
    _deferred_proc = subprocess.run(
        [sys.executable, "-B", _deferred_test],
        cwd=HERE, env=_deferred_env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=60, check=False,
    )
    _deferred_output = (_deferred_proc.stdout or "") + (_deferred_proc.stderr or "")
    check("V25: sec-deferred固定形式を安全に描画",
          _deferred_proc.returncode == 0 and "FAIL=0" in _deferred_output,
          _deferred_output[-1500:])
    _server_text_v25 = open(os.path.join(HERE, "server.py"), encoding="utf-8").read()
    check("V25: sec-deferred警告CSSが存在",
          ".md-content details.sec-deferred" in _server_text_v25
          and ".md-content details.sec-deferred summary" in _server_text_v25)
except Exception as _exc_v25:
    check("V25: deferred details GUI verification", False, repr(_exc_v25))


# ════════════════════════════════════════════════════════════
sec("V26: CheckPC weekday parser and Task140 D1 aggregation")
try:
    _rev7_test = os.path.join(HERE, "test_v370_rev7_weekday_task140.py")
    check("V26: rev7 weekday/task140重点回帰が存在", os.path.isfile(_rev7_test))
    _rev7_env = os.environ.copy()
    _rev7_env["PYTHONDONTWRITEBYTECODE"] = "1"
    _rev7_proc = subprocess.run(
        [sys.executable, "-B", _rev7_test],
        cwd=HERE, env=_rev7_env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=60, check=False,
    )
    _rev7_output = (_rev7_proc.stdout or "") + (_rev7_proc.stderr or "")
    check("V26: weekday互換と意味保持型集約回帰が合格",
          _rev7_proc.returncode == 0 and "PASS=27 FAIL=0" in _rev7_output,
          _rev7_output[-2000:])

    import parse_checkpc as _pc_v26
    import analyze_section as _as_v26
    _dir_v26 = _pc_v26.parse_directory(
        " C:\\Temp のディレクトリ\n"
        "2026/08/10 月  09:16             1,234 sample.exe\n"
        "2026/08/10  09:17             2,345 legacy.exe\n"
    )
    check("V26: 曜日あり/なしdir形式を同時受理",
          len(_dir_v26) == 2
          and _dir_v26[0].get("date") == "2026/08/10  09:16"
          and _dir_v26[1].get("date") == "2026/08/10  09:17",
          repr(_dir_v26))
    _as_text_v26 = open(os.path.join(HERE, "analyze_section.py"),
                        encoding="utf-8").read()
    check("V26: Task140集約はD1限定かつ製品allowlist非依存",
          'depth == 1 and sec == "task_140"' in _as_text_v26
          and "UpdateOrchestrator" not in _as_text_v26
          and "SvcRestartTask" not in _as_text_v26
          and "OneSettings" not in _as_text_v26)
    check("V26: Task140監査メタデータがsource ID/indexと時刻窓を保持",
          all(token in _as_text_v26 for token in (
              '"raw_indices"', '"source_ids"', '"occurrence_count"',
              '"first_seen"', '"last_seen"', '"sample_datetimes"')))
    check("V26: 実データ手動validatorが同梱",
          os.path.isfile(os.path.join(HERE, "validate_rev7_realdata.py")))

    import report_gen as _rg_v26
    _low_rows_v26 = _rg_v26._aggregate_low_entries([
        {"identifier": "Task A", "score": "LOW", "occurrence_count": 7},
        {"identifier": "Task B", "score": "LOW", "occurrence_count": 3},
    ], "task_140")
    check("V26: task_140 reportがsemantic groupのraw発生数を可視化",
          any("| 10 |" in row for row in _low_rows_v26)
          and "×5件" in _rg_v26._display_identifier(
              {"identifier": "Task A", "occurrence_count": 5}, "task_140"))
    check("V26: task_140 MEDIUMを汎用reason集約で再集約しない",
          "task_140" in _rg_v26._MED_AGG_EXCLUDE_SECTIONS)

    _runtime_tool_v26 = os.path.join(HERE, "verify_analysis_runtime_unchanged.py")
    _baseline_v26 = os.path.join(HERE, "analysis_runtime_baseline.json")
    _baseline_proc_v26 = subprocess.run(
        [sys.executable, "-B", _runtime_tool_v26, "--baseline", _baseline_v26],
        cwd=HERE, env=_rev7_env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=60, check=False)
    check("V26: rev7 runtime baselineが候補コード自身と一致",
          _baseline_proc_v26.returncode == 0,
          ((_baseline_proc_v26.stdout or "") + (_baseline_proc_v26.stderr or ""))[-1500:])
except Exception as _exc_v26:
    check("V26: rev7 parser/aggregation verification", False, repr(_exc_v26))


# ════════════════════════════════════════════════════════════
sec("V27: Task140 semantic-group binding hardening")
try:
    _rev8_test = os.path.join(HERE, "test_v370_rev8_task140_binding.py")
    check("V27: rev8 semantic-group binding重点回帰が存在", os.path.isfile(_rev8_test))
    _rev8_env = os.environ.copy()
    _rev8_env["PYTHONDONTWRITEBYTECODE"] = "1"
    _rev8_proc = subprocess.run(
        [sys.executable, "-B", _rev8_test],
        cwd=HERE, env=_rev8_env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=60, check=False,
    )
    _rev8_output = (_rev8_proc.stdout or "") + (_rev8_proc.stderr or "")
    check("V27: semantic-group binding/locale/header/date回帰が合格",
          _rev8_proc.returncode == 0 and "PASS=23 FAIL=0" in _rev8_output,
          _rev8_output[-2200:])

    _as_text_v27 = open(os.path.join(HERE, "analyze_section.py"), encoding="utf-8").read()
    _vsb_text_v27 = open(os.path.join(HERE, "validate_semantic_binding.py"), encoding="utf-8").read()
    check("V27: Task140一対多bindingがraw-index/source-id/digestを明示",
          all(token in _as_text_v27 for token in (
              '"_raw_source_indices"', '"_source_ids"',
              '"_task140_semantic_group_sha256"',
              '"task140_semantic_group"')))
    check("V27: semantic validatorがTask140 groupを明示検証",
          all(token in _vsb_text_v27 for token in (
              "_validate_task140_group_streamed",
              "task140_group_semantic_digest_mismatch",
              "task140_group_source_id_mismatch",
              "task140_group_identifier_mismatch")))
    check("V27: 日本語/中国語Description境界とEvent[n]:を許容",
          "(?:Description|説明|描述)" in _as_text_v27
          and r"Event\[\d+\]\s*[:：]?" in _as_text_v27)
    check("V27: task140集約経路はraw-index推測fallbackを禁止",
          "_raw_indices_for(entries, fail_closed=True)" in _as_text_v27
          and "aggregation representative source_id mismatch" in _as_text_v27)
    check("V27: chunk失敗警告をraw occurrenceへ展開",
          "_task140_raw_unevaluated_count" in _as_text_v27)
    check("V27: dead aggregation index fieldを出力しない",
          "_aggregation_source_indices" not in _as_text_v27)
    check("V27: rev8実データvalidatorが同梱",
          os.path.isfile(os.path.join(HERE, "validate_rev8_realdata.py")))
    _pre_rev8 = os.path.join(HERE, "analysis_runtime_baseline_pre_rev8.json")
    _runtime_tool_v27 = os.path.join(HERE, "verify_analysis_runtime_unchanged.py")
    _pre_proc_v27 = subprocess.run(
        [sys.executable, "-B", _runtime_tool_v27, "--baseline", _pre_rev8],
        cwd=HERE, env=_rev8_env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=60, check=False)
    _pre_output_v27 = (_pre_proc_v27.stdout or "") + (_pre_proc_v27.stderr or "")
    check("V27: pre-rev8 runtime baselineは旧4mode再利用をfail-closed拒否",
          _pre_proc_v27.returncode == 1
          and "analyze_section.py" in _pre_output_v27
          and "parse_checkpc.py" in _pre_output_v27
          and "RESULT: FAIL" in _pre_output_v27,
          _pre_output_v27[-1800:])
except Exception as _exc_v27:
    check("V27: Task140 semantic-group verification", False, repr(_exc_v27))


# ════════════════════════════════════════════════════════════
sec("V28: rev9 Task140 empty-task binding and failure accounting")
try:
    _rev9_test = os.path.join(HERE, "test_v370_rev9_task140_binding.py")
    check("V28: rev9 Task140重点回帰が存在", os.path.isfile(_rev9_test))
    _rev9_env = os.environ.copy()
    _rev9_env["PYTHONDONTWRITEBYTECODE"] = "1"
    _rev9_proc = subprocess.run(
        [sys.executable, "-B", _rev9_test],
        cwd=HERE, env=_rev9_env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=60, check=False,
    )
    _rev9_output = (_rev9_proc.stdout or "") + (_rev9_proc.stderr or "")
    check("V28: empty-task/group/parser/accounting/comparison回帰が合格",
          _rev9_proc.returncode == 0 and "PASS=20 FAIL=0" in _rev9_output,
          _rev9_output[-2400:])

    _as_text_v28 = open(os.path.join(HERE, "analyze_section.py"), encoding="utf-8").read()
    _vsb_text_v28 = open(os.path.join(HERE, "validate_semantic_binding.py"), encoding="utf-8").read()
    _pc_text_v28 = open(os.path.join(HERE, "parse_checkpc.py"), encoding="utf-8").read()
    _cmp_text_v28 = open(os.path.join(HERE, "compare_runs.py"), encoding="utf-8").read()
    check("V28: analyzerは代表rawのみidentifier照合し全member digest/source-idを維持",
          "if pos == 0:" in _as_text_v28
          and "task140_group_semantic_digest_mismatch" in _as_text_v28
          and "task140_group_source_id_mismatch" in _as_text_v28)
    check("V28: streamed validatorも代表rawのみidentifier照合",
          "if position == 0:" in _vsb_text_v28
          and "task140_group_semantic_digest_mismatch" in _vsb_text_v28)
    check("V28: parse_task_event_textがindent/colon付きEvent headerを分割",
          r"^[ \t]*Event\[\d+\]\s*[:：]?\s*$" in _pc_text_v28)
    check("V28: hard LLM failure診断にraw representative indicesを保持",
          _as_text_v28.count('"unevaluated_indices": list(spec.source_indices)') >= 4)
    check("V28: unknown representative未評価数を1件と推測しない",
          "if any(index not in occurrence_by_rep for index in failed):" in _as_text_v28
          and 'aggregation.get("raw_count"' in _as_text_v28)
    check("V28: rev9実データvalidatorがsemantic bindingまで検証",
          os.path.isfile(os.path.join(HERE, "validate_rev9_realdata.py"))
          and "task140_bound_raw_1000" in open(os.path.join(HERE, "validate_rev9_realdata.py"), encoding="utf-8").read()
          and "streamed_semantic_binding_accept" in open(os.path.join(HERE, "validate_rev9_realdata.py"), encoding="utf-8").read())
    check("V28: comparatorがtask140 occurrence_count差分を可視化",
          "COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION = 2" in _cmp_text_v28
          and "task140_occurrence_count_difference" in _cmp_text_v28)

    _pre_rev9 = os.path.join(HERE, "analysis_runtime_baseline_pre_rev9.json")
    _runtime_tool_v28 = os.path.join(HERE, "verify_analysis_runtime_unchanged.py")
    _pre_proc_v28 = subprocess.run(
        [sys.executable, "-B", _runtime_tool_v28, "--baseline", _pre_rev9],
        cwd=HERE, env=_rev9_env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=60, check=False)
    _pre_output_v28 = (_pre_proc_v28.stdout or "") + (_pre_proc_v28.stderr or "")
    check("V28: pre-rev9 runtime baselineは旧4mode再利用をfail-closed拒否",
          _pre_proc_v28.returncode == 1
          and "analyze_section.py" in _pre_output_v28
          and "parse_checkpc.py" in _pre_output_v28
          and "RESULT: FAIL" in _pre_output_v28,
          _pre_output_v28[-1800:])
except Exception as _exc_v28:
    check("V28: rev9 Task140 verification", False, repr(_exc_v28))


# ════════════════════════════════════════════════════════════
sec("V29: rev10 comparator evidence binding and Task140 canonical order")
try:
    _rev10_order = os.path.join(HERE, "test_v370_rev10_task140_order.py")
    _rev10_cmp = os.path.join(HERE, "test_v370_rev10_comparison_evidence.py")
    check("V29: rev10 Task140順序重点回帰が存在", os.path.isfile(_rev10_order))
    check("V29: rev10 comparison evidence E2Eが存在", os.path.isfile(_rev10_cmp))
    _rev10_env = os.environ.copy()
    _rev10_env["PYTHONDONTWRITEBYTECODE"] = "1"
    _rev10_order_proc = subprocess.run(
        [sys.executable, "-B", _rev10_order], cwd=HERE, env=_rev10_env,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
    _rev10_order_out = (_rev10_order_proc.stdout or "") + (_rev10_order_proc.stderr or "")
    check("V29: Task140 canonical order/同時swap回帰が合格",
          _rev10_order_proc.returncode == 0 and "PASS=18 FAIL=0" in _rev10_order_out,
          _rev10_order_out[-2200:])
    _rev10_cmp_proc = subprocess.run(
        [sys.executable, "-B", _rev10_cmp], cwd=HERE, env=_rev10_env,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, check=False)
    _rev10_cmp_out = (_rev10_cmp_proc.stdout or "") + (_rev10_cmp_proc.stderr or "")
    check("V29: comparator v2 producer→gate→promotion E2Eが合格",
          _rev10_cmp_proc.returncode == 0 and "PASS=7 FAIL=0" in _rev10_cmp_out,
          _rev10_cmp_out[-2600:])

    _gate_v29 = open(os.path.join(HERE, "comparison_release_gate.py"), encoding="utf-8").read()
    _promote_v29 = open(os.path.join(HERE, "promote_to_formal.py"), encoding="utf-8").read()
    _cmp_v29 = open(os.path.join(HERE, "compare_runs.py"), encoding="utf-8").read()
    check("V29: producer evidence versionは2",
          "COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION = 2" in _cmp_v29)
    check("V29: release gateはproducer current evidence versionを直接参照",
          "CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION" in _gate_v29
          and "implementation.get(\"evidence_version\") != CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION" in _gate_v29)
    check("V29: promotionもcurrent evidence versionとcurrent comparator SHAを要求",
          "CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION" in _promote_v29
          and "implementation_version != CURRENT_COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION" in _promote_v29
          and "implementation_sha != expected_compare_sha" in _promote_v29)
    check("V29: gate/promotion証跡にevidence versionを結合",
          "comparison_implementation_evidence_version" in _gate_v29
          and "comparison_implementation_evidence_version" in _promote_v29)
    check("V29: rev10 realdata validatorが存在",
          os.path.isfile(os.path.join(HERE, "validate_rev10_realdata.py")))

    _pre_rev10 = os.path.join(HERE, "analysis_runtime_baseline_pre_rev10.json")
    _runtime_v29 = os.path.join(HERE, "verify_analysis_runtime_unchanged.py")
    _pre_proc_v29 = subprocess.run(
        [sys.executable, "-B", _runtime_v29, "--baseline", _pre_rev10],
        cwd=HERE, env=_rev10_env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=60, check=False)
    _pre_out_v29 = (_pre_proc_v29.stdout or "") + (_pre_proc_v29.stderr or "")
    check("V29: pre-rev10 runtime baselineはanalyze_section変更をfail-closed検出",
          _pre_proc_v29.returncode == 1
          and "analyze_section.py" in _pre_out_v29
          and "RESULT: FAIL" in _pre_out_v29, _pre_out_v29[-1800:])
except Exception as _exc_v29:
    check("V29: rev10 verification", False, repr(_exc_v29))



# ════════════════════════════════════════════════════════════
sec("V30: rev11 current-package artifact identity binding")
try:
    _rev11_pkg = os.path.join(HERE, "test_v370_rev11_package_identity_binding.py")
    check("V30: rev11 package identity E2Eが存在", os.path.isfile(_rev11_pkg))
    check("V30: rev11実データvalidatorが存在",
          os.path.isfile(os.path.join(HERE, "validate_rev11_realdata.py")))
    _rev11_env = os.environ.copy()
    _rev11_env["PYTHONDONTWRITEBYTECODE"] = "1"
    _rev11_proc = subprocess.run(
        [sys.executable, "-B", _rev11_pkg], cwd=HERE, env=_rev11_env,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
    _rev11_out = (_rev11_proc.stdout or "") + (_rev11_proc.stderr or "")
    check("V30: current package positive/old-package negative E2Eが合格",
          _rev11_proc.returncode == 0 and "PASS=13 FAIL=0" in _rev11_out,
          _rev11_out[-3200:])

    _gate_v30 = open(os.path.join(HERE, "comparison_release_gate.py"), encoding="utf-8").read()
    _promote_v30 = open(os.path.join(HERE, "promote_to_formal.py"), encoding="utf-8").read()
    _runtime_v30 = open(os.path.join(HERE, "verify_analysis_runtime_unchanged.py"), encoding="utf-8").read()
    _cmp_v30 = open(os.path.join(HERE, "compare_runs.py"), encoding="utf-8").read()
    check("V30: gateがSHA256SUMS自身のSHAをcurrent package identityに使用",
          "def current_package_manifest_sha256" in _gate_v30
          and 'manifest = root / "SHA256SUMS.txt"' in _gate_v30
          and "return sha256_file(manifest)" in _gate_v30)
    check("V30: current v3.70 artifactのmanifest不一致をgateが拒否",
          "pipeline_version != PIPELINE_VERSION" in _gate_v30
          and "current artifact side {side} package manifest mismatch" in _gate_v30)
    check("V30: gate証跡にcurrent manifestと各current artifact identityを保持",
          '"current_package_manifest_sha256": current_manifest_sha' in _gate_v30
          and '"current_artifacts": current_artifacts' in _gate_v30)
    check("V30: promotionがcurrent package identityをdirect gateと再照合",
          "evaluate_release_gate(root, package_dir=HERE)" in _promote_v30
          and "current_package_manifest_sha256(HERE)" in _promote_v30
          and "package manifest mismatch during promotion" in _promote_v30)
    check("V30: formal promotion証跡へcurrent package identityを記録",
          '"current_package_manifest_sha256": evidence.get("current_package_manifest_sha256")' in _promote_v30
          and '"current_artifacts": current_artifacts' in _promote_v30)
    check("V30: runtime baseline PASSだけではartifact再利用を許可しない文言",
          "does NOT authorize reuse of existing 4-mode artifacts" in _runtime_v30
          and "exact current package manifest identity" in _runtime_v30)
    check("V30: comparator producer evidence version 2を維持",
          "COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION = 2" in _cmp_v30)
except Exception as _exc_v30:
    check("V30: rev11 package identity verification", False, repr(_exc_v30))


# ════════════════════════════════════════════════════════════
sec("V31: rev12 run-lineage binding and report/UI simplification")
try:
    _rev12_test = os.path.join(HERE, "test_v370_rev12_lineage_gui.py")
    check("V31: rev12 lineage/GUI重点回帰が存在", os.path.isfile(_rev12_test))
    _rev12_env = os.environ.copy()
    _rev12_env["PYTHONDONTWRITEBYTECODE"] = "1"
    _rev12_proc = subprocess.run(
        [sys.executable, "-B", _rev12_test], cwd=HERE, env=_rev12_env,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=120, check=False)
    _rev12_out = (_rev12_proc.stdout or "") + (_rev12_proc.stderr or "")
    check("V31: parsed/analyzed lineage + GUI/report回帰が合格",
          _rev12_proc.returncode == 0 and "PASS=29 FAIL=0" in _rev12_out,
          _rev12_out[-4000:])

    _cmp_v31 = open(os.path.join(HERE, "compare_runs.py"), encoding="utf-8").read()
    _gate_v31 = open(os.path.join(HERE, "comparison_release_gate.py"), encoding="utf-8").read()
    _promote_v31 = open(os.path.join(HERE, "promote_to_formal.py"), encoding="utf-8").read()
    _dir_v31 = open(os.path.join(HERE, "directory_policy.py"), encoding="utf-8").read()
    _report_v31 = open(os.path.join(HERE, "report_gen.py"), encoding="utf-8").read()
    _server_v31 = open(os.path.join(HERE, "server.py"), encoding="utf-8").read()
    check("V31: comparatorがparsed/analyzed package identityを厳格照合",
          "parsed_analyzed_run_identity_mismatch" in _cmp_v31
          and '"package_manifest_sha256"' in _cmp_v31)
    check("V31: gate/promotionがparsed package identityも再照合",
          "parsed/analyzed package manifest mismatch" in _gate_v31
          and "parsed/analyzed run identity mismatch during promotion" in _promote_v31)
    check("V31: comparison evidenceへparsed/analyzed/ingest SHAを保持",
          all(token in _cmp_v31 for token in (
              '"parsed_sha256"', '"analyzed_sha256"', '"ingest_manifest_sha256"',
              '"parsed_meta"', '"ingest_manifest_identity"')))
    check("V31: C直下OS管理3ファイルだけをDirectory候補から除外",
          all(name in _dir_v31 for name in ("hiberfil.sys", "pagefile.sys", "swapfile.sys"))
          and "is_root_os_managed_file" in _dir_v31)
    check("V31: 収集品質セクションを最終reportへ出力しない",
          '## ⚠ 収集品質・解析制約' not in _report_v31)
    check("V31: signature_diversityをuser-facing coverage理由から除外",
          'key != "signature_diversity"' in _report_v31)
    check("V31: report modal open時に先頭へscroll reset",
          'id="reportModalBody"' in _server_v31
          and 'requestAnimationFrame(() => { reportBody.scrollTop = 0; });' in _server_v31)
except Exception as _exc_v31:
    check("V31: rev12 verification", False, repr(_exc_v31))


# ════════════════════════════════════════════════════════════
sec("V32: rev13 coverage-singleton canonical binding")
try:
    _rev13_test = os.path.join(HERE, "test_v370_rev13_singleton_binding.py")
    check("V32: rev13 singleton binding重点回帰が存在", os.path.isfile(_rev13_test))
    _rev13_env = os.environ.copy()
    _rev13_env["PYTHONDONTWRITEBYTECODE"] = "1"
    _rev13_proc = subprocess.run(
        [sys.executable, "-B", _rev13_test], cwd=HERE, env=_rev13_env,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=120, check=False)
    _rev13_out = (_rev13_proc.stdout or "") + (_rev13_proc.stderr or "")
    check("V32: singleton/multi-entry binding mutation回帰が合格",
          _rev13_proc.returncode == 0 and "PASS=32 FAIL=0" in _rev13_out,
          _rev13_out[-4200:])

    _as_text_v32 = open(os.path.join(HERE, "analyze_section.py"), encoding="utf-8").read()
    check("V32: canonical repairはcoverage split singleton限定",
          "def _repair_coverage_singleton_binding" in _as_text_v32
          and "split_depth <= 0" in _as_text_v32
          and "repair_allowed" in _as_text_v32
          and '"coverage_singleton_canonical"' in _as_text_v32)
    check("V32: singleton複数entryはcardinality violationでfail-closed",
          '"singleton_cardinality_violation"' in _as_text_v32
          and "len(positions) == 1 and len(returned) > 1" in _as_text_v32)
    check("V32: multi-entry binding rejectionを新canonical repairへ流用しない",
          '"_source_attribution_claimed_index"' in _as_text_v32
          and "positions[0] not in binding_rejected" in _as_text_v32)
    check("V32: repair監査metadataがoriginal/canonical/repaired_fieldsを保持",
          all(token in _as_text_v32 for token in (
              '"original_source_index"', '"original_source_id"',
              '"original_identifier"', '"canonical_source_index"',
              '"canonical_source_id"', '"canonical_identifier"',
              '"repaired_fields"')))

    _runtime_v32 = os.path.join(HERE, "verify_analysis_runtime_unchanged.py")
    _current_v32 = os.path.join(HERE, "analysis_runtime_baseline.json")
    _current_proc_v32 = subprocess.run(
        [sys.executable, "-B", _runtime_v32, "--baseline", _current_v32],
        cwd=HERE, env=_rev13_env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=60, check=False)
    check("V32: rev13 runtime baselineが候補コード自身と一致",
          _current_proc_v32.returncode == 0,
          ((_current_proc_v32.stdout or "") + (_current_proc_v32.stderr or ""))[-1800:])

    _pre_rev13 = os.path.join(HERE, "analysis_runtime_baseline_pre_rev13.json")
    _pre_proc_v32 = subprocess.run(
        [sys.executable, "-B", _runtime_v32, "--baseline", _pre_rev13],
        cwd=HERE, env=_rev13_env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=60, check=False)
    _pre_out_v32 = (_pre_proc_v32.stdout or "") + (_pre_proc_v32.stderr or "")
    check("V32: rev12 runtime baselineとの差分はanalyze_sectionのみで4mode再利用を拒否",
          _pre_proc_v32.returncode == 1
          and "analyze_section.py" in _pre_out_v32
          and _pre_out_v32.count("[CHANGED ]") == 1
          and "RESULT: FAIL" in _pre_out_v32, _pre_out_v32[-2200:])
except Exception as _exc_v32:
    check("V32: rev13 singleton binding verification", False, repr(_exc_v32))


# ════════════════════════════════════════════════════════════
sec("V33: rev14 depth1-depth2 signature-diversity comparison")
try:
    _rev14_test = os.path.join(HERE, "test_v370_rev14_depth_comparison.py")
    check("V33: rev14 depth comparison重点回帰が存在", os.path.isfile(_rev14_test))
    _rev14_env = os.environ.copy()
    _rev14_env["PYTHONDONTWRITEBYTECODE"] = "1"
    _rev14_proc = subprocess.run(
        [sys.executable, "-B", _rev14_test], cwd=HERE, env=_rev14_env,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=120, check=False)
    _rev14_out = (_rev14_proc.stdout or "") + (_rev14_proc.stderr or "")
    check("V33: signature-diversity fail-closed mutation回帰が合格",
          _rev14_proc.returncode == 0 and "PASS=19 FAIL=0" in _rev14_out,
          _rev14_out[-4200:])

    _cmp_v33 = open(os.path.join(HERE, "compare_runs.py"), encoding="utf-8").read()
    check("V33: 例外はdepth1-depth2のD1 HIGH消失だけに限定",
          'mode == "depth1-depth2" and score_a == "HIGH"' in _cmp_v33
          and "_depth2_signature_diversity_resolution" in _cmp_v33)
    check("V33: D2 raw存在とexact signature_diversity provenanceを要求",
          'len(matches) != 1' in _cmp_v33
          and '"signature_diversity"' in _cmp_v33
          and '_provenance_reasons_for_index' in _cmp_v33)
    check("V33: representativeはsame planner signature + selected/evaluated + source-id binding必須",
          '_depth2_planner_signature' in _cmp_v33
          and 'candidate_indices = sorted((selected & evaluated)' in _cmp_v33
          and 'len(bound_entries) != 1' in _cmp_v33)
    check("V33: HIGH代表とnon-deterministic MEDIUM代表だけREVIEW",
          '"signature_diversity_high_represented"' in _cmp_v33
          and '"signature_diversity_high_to_medium"' in _cmp_v33
          and 'and not deterministic_high' in _cmp_v33)
    check("V33: comparison evidenceにremoved/representative bindingを保持",
          all(token in _cmp_v33 for token in (
              '"removed_source_id"', '"removed_raw_index"',
              '"planner_signature"', '"deferred_reason"',
              '"representative_source_ids"', '"representative_raw_indices"',
              '"representative_scores"', '"representative_best_score"')))
    check("V33: comparator evidence version 2を維持しSHA bindingで旧結果再利用を拒否",
          "COMPARISON_IMPLEMENTATION_EVIDENCE_VERSION = 2" in _cmp_v33)
    def _sha_v33(name):
        h = hashlib.sha256()
        with open(os.path.join(HERE, name), "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    check("V33: Depth2 plannerはrev13から変更なし",
          _sha_v33("depth2_select.py") ==
          "711b884badf45989e3f209dfb2555c3861805dfa0b6b8e400528e2001bd566ae")
    check("V33: rev13 singleton analysis runtimeは変更なし",
          _sha_v33("analyze_section.py") ==
          "862996a0505755181b7b53b876bafce1bbf6de3ecfb74680becef682aafc727a")
    check("V33: compare_runs.pyはrev13 comparatorから更新済み",
          _sha_v33("compare_runs.py") !=
          "5f326791d9b61a0917864d82952bc2dc637b8946d08473a8dc01491c7a040510")
except Exception as _exc_v33:
    check("V33: rev14 depth comparison verification", False, repr(_exc_v33))


# ════════════════════════════════════════════════════════════
sec("V8: check ID命名規約・一意性")
# Evaluate only checks emitted before this section, so the meta-checks do not
# inspect themselves and the result remains deterministic.
_prior_check_results = list(CHECK_RESULTS)
_bare_version_names = []
for _row in _prior_check_results:
    _tokens = find_bare_release_versions(_row.get("name", ""))
    if _tokens:
        _bare_version_names.append(
            f"{_row.get('name', '')}: {', '.join(_tokens)}")
check("V8: check名にラベル無し裸バージョンが無い",
      not _bare_version_names, "; ".join(_bare_version_names[:8]))
_duplicate_ids = find_duplicate_check_ids(_prior_check_results)
_duplicate_detail = "; ".join(
    f"{check_id}: {' | '.join(names)}"
    for check_id, names in sorted(_duplicate_ids.items())
)
check("V8: check IDが全件一意",
      not _duplicate_ids, _duplicate_detail[:1000])

_json_out = None
for _i, _arg in enumerate(sys.argv):
    if _arg == "--json-out" and _i + 1 < len(sys.argv):
        _json_out = sys.argv[_i + 1]
        break
if _json_out:
    _payload = {
        "summary_schema": 1,
        "pass": PASS, "fail": FAIL, "not_applicable": NOT_APPLICABLE,
        "checks": CHECK_RESULTS,
    }
    _tmp = _json_out + ".tmp"
    with open(_tmp, "w", encoding="utf-8", newline="\n") as _fh:
        json.dump(_payload, _fh, ensure_ascii=False, indent=2, sort_keys=True)
        _fh.write("\n")
        _fh.flush(); os.fsync(_fh.fileno())
    os.replace(_tmp, _json_out)

print(f"\n{'=' * 60}")
print(f"  検証結果: PASS={PASS}  FAIL={FAIL}  N/A={NOT_APPLICABLE}  "
      f"合計={PASS + FAIL + NOT_APPLICABLE}")
print(f"{'=' * 60}")
print(f"PASS={PASS} FAIL={FAIL} N_A={NOT_APPLICABLE}")
sys.exit(1 if FAIL else 0)
