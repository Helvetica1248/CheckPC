# -*- coding: utf-8 -*-
"""P3: LEAN出力モード（v3.62）の回帰テスト。

対象:
  · section_prompts.get_prompt(lean=True) — LEAN系統のプロンプト選択
  · analyze_section._canonical_iocs — 12セクションの決定論iocs抽出
  · LEAN E2E（スタブLLM）— CLEAN最小出力の補完・iocs決定論付与・identifier上書き
  · source_index カバレッジ検証 — 欠落再送・無効/重複の不採用（誤帰属防止）・
    再送不能時の⚠可視化・CHECKPC_CHUNK_RETRY=0
  · LEAN_OUTPUT=0（既定）での従来動作維持（回帰）
"""
import sys, os, re, json, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
for _c in (os.environ.get("CHECKPC_SCRIPTS", ""), HERE,
           os.path.dirname(HERE), "/home/claude/scripts"):
    if _c and os.path.exists(os.path.join(_c, "analyze_section.py")):
        SCRIPTS = _c
        break
else:
    print("analyze_section.py が見つかりません"); sys.exit(2)
sys.path.insert(0, SCRIPTS)
def _mod(name):
    spec = importlib.util.spec_from_file_location(name, f"{SCRIPTS}/{name}.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
sp = _mod("section_prompts")
a  = _mod("analyze_section")

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: print(f"  [OK]  {name}"); PASS += 1
    else: print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1
def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

# ── スタブLLM ─────────────────────────────────────────────
class _SeqClient:
    """応答列を順に返すスタブ。使い切り後は auto 応答（callable）にフォールバック。"""
    def __init__(self, responses=(), auto=None):
        self._resp = list(responses); self._auto = auto
        self.calls = []
        outer = self
        class _O: pass
        class _Completions:
            @staticmethod
            def create(**kw):
                user = [m for m in kw["messages"] if m["role"] == "user"][0]["content"]
                outer.calls.append(user)
                r = outer._resp.pop(0) if outer._resp else outer._auto
                if isinstance(r, Exception): raise r
                if callable(r): r = r(user)
                m = _O(); m.content = r
                c = _O(); c.message = m
                resp = _O(); resp.choices = [c]
                return resp
        class _Chat: pass
        self.chat = _Chat(); self.chat.completions = _Completions()

def _idxs(user_msg):
    return [int(m) for m in re.findall(r"^\[#(\d+)\]", user_msg, re.M)]


def _bindings(user_msg):
    out = []
    for line in user_msg.splitlines():
        m = re.match(r"^\[#(\d+)\]\[source_id=([^\]]*)\]\s+(.*)$", line)
        if not m:
            continue
        body = m.group(3)
        pm = re.search(r"([A-Za-z]:\\.*)$", body)
        out.append((int(m.group(1)), m.group(2), pm.group(1) if pm else body))
    return out


def _lean_auto(user_msg):
    """全件 CLEAN のrc27 binding-complete LEAN正常応答。"""
    ents = [{"source_index": i, "source_id": sid, "identifier": ident,
             "score": "CLEAN", "reason": "問題なし"}
            for i, sid, ident in _bindings(user_msg)]
    return json.dumps({"section": "x", "entries": ents,
                       "section_summary": "s"}, ensure_ascii=False)

def _dir_entries(n, stem="file"):
    return [{"path": f"C:\\Users\\Public\\{stem}{i}.exe",
             "name": f"{stem}{i}.exe", "dir": "C:\\Users\\Public",
             "date": "2026/01/01  00:00", "size": "100"} for i in range(n)]

GARBAGE = "％％JSONではない％％"

# ════════════════════════════════════════════════════════════
sec("L1: LEANプロンプト系統の選択")
f = sp.get_prompt("directory", 1, lean=True)
check("L1: lean版にsource bindingの正確転写要求", "一字一句" in f and "source_id" in f)
check("L1: lean版(構造化)に iocs フィールドがない", '"iocs"' not in f)
check("L1v3: CLEANも5フィールド必須", "5フィールド" in f and "source_id" in f)
check("L1v3: 旧2フィールド指示が残っていない", "2フィールドのみ" not in f)
check("L1: lean版に欠番禁止（カバレッジ）指示がある", "欠番" in f)
check("L1: lean版に identifier省略禁止", "省略禁止" in f)
check("L1v2: LOWも5フィールド必須", f.count("5フィールド") >= 2)
check("L1v2: CLEAN偏向対策（迷う場合はLOW）の指示がある",
      "迷う場合は CLEAN に倒さず LOW" in f)
check("L1v2: 『簡潔さのために判定を変えない』指示がある",
      "判定を変えない" in f)
g = sp.get_prompt("ps_history", 2, lean=True)
check("L1: 自由文セクション(ps_history)は lean でも iocs 維持", '"iocs"' in g)
h = sp.get_prompt("directory", 1)          # 既定=FULL
check("L1: 既定(FULL)は従来どおり（回帰）", "一字一句" in h and '"iocs"' in h)
check("L1: lean対象セクションが承認済み12セクションと一致",
      sp.LEAN_IOCS_SECTIONS == {
          "directory", "prefetch", "appcompat_cache", "task_scheduler",
          "service", "system_7045", "netstat", "dns_cache", "rdp_1024",
          "bits_jobs", "startup_folder", "persistence_reg"},
      str(sorted(sp.LEAN_IOCS_SECTIONS)))

# ════════════════════════════════════════════════════════════
sec("L2: _canonical_iocs（決定論iocs抽出）")
cases = [
    ("directory",       {"path": r"C:\x\a.exe"},                       [r"C:\x\a.exe"]),
    ("persistence_reg", {"path": r"C:\r\b.exe"},                       [r"C:\r\b.exe"]),
    ("task_scheduler",  {"task_path": r"C:\t\c.exe"},                  [r"C:\t\c.exe"]),
    ("service",         {"image_path": r"C:\s.exe", "service_dll": r"C:\d.dll"},
                                                     [r"C:\s.exe", r"C:\d.dll"]),
    ("dns_cache",       {"fqdn": "evil.test", "resolve": "1.2.3.4"},   ["evil.test", "1.2.3.4"]),
    ("netstat",         {"remote": "5.6.7.8:443"},                     ["5.6.7.8:443"]),
    ("prefetch",        {"name": "EVIL.EXE-1234.pf"},                  ["EVIL.EXE-1234.pf"]),
    ("appcompat_cache", {"path": r"C:\a\p.exe"},                       [r"C:\a\p.exe"]),
    ("startup_folder",  {"path": r"C:\su\q.lnk"},                      [r"C:\su\q.lnk"]),
    ("system_7045",     {"image_path": r"C:\sys\r.sys"},               [r"C:\sys\r.sys"]),
    ("rdp_1024",        {"server": "10.0.0.9"},                        ["10.0.0.9"]),
    ("bits_jobs",       {"url": "http://e/x", "local_file": r"C:\t.dll"},
                                                     ["http://e/x", r"C:\t.dll"]),
]
for s_, e_, want in cases:
    got = a._canonical_iocs(s_, e_)
    check(f"L2: {s_}", got == want, f"got={got}")
check("L2: 未対応セクションは空リスト（LLM出力を維持する側に倒す）",
      a._canonical_iocs("ps_history", {"x": 1}) == [])
check("L2: 空フィールドは除外", a._canonical_iocs("service", {"image_path": ""}) == [])

# ════════════════════════════════════════════════════════════
_orig_lean = a.LEAN_OUTPUT
try:
    a.LEAN_OUTPUT = 1

    sec("L3: LEAN E2E（CLEAN最小出力の補完・iocs決定論付与）")
    def _mixed(user_msg):
        rows = []
        for i, sid, ident in _bindings(user_msg):
            row = {"source_index": i, "source_id": sid, "identifier": ident,
                   "score": "CLEAN", "reason": "問題なし"}
            if i == 1:
                row.update({"score": "MEDIUM", "reason": "不審な配置",
                            "decoded": None, "lolbas": None, "mitre": ["T1204"]})
            elif i == 2:
                row.update({"score": "LOW", "reason": "一時ファイル"})
            rows.append(row)
        return json.dumps({"section": "directory", "entries": rows}, ensure_ascii=False)
    cli = _SeqClient(auto=_mixed)
    ents = _dir_entries(4)
    res, summ, errs, tims = a.call_llm_chunked(cli, "dummy", "directory", 2, ents)
    check("L3: プロンプトがrc27 binding系統", "source_id" in cli.calls[0] and "省力化ルール" in cli.calls[0])
    check("L3: 全4件が返る", len(res) == 4, f"={len(res)}")
    check("L3: chunk_errors なし", errs == [], str(errs))
    by_si = {e["source_index"]: e for e in res}
    cl = by_si[0]
    check("L3: CLEAN最小出力に identifier が元データから補完される",
          cl["identifier"] == ents[0]["path"], str(cl))
    check("L3v3: CLEAN のLLM由来 reason が保持される",
          cl["reason"] == "問題なし", str(cl))
    check("L3: CLEAN の欠損フィールドが補完される（下流互換）",
          cl["mitre"] == [] and cl["decoded"] is None and cl["lolbas"] is None, str(cl))
    cl2 = by_si[3]
    check("L3v3: CLEANもbinding fieldを維持",
          cl2["score"] == "CLEAN" and cl2["reason"] == "問題なし"
          and cl2["identifier"] == ents[3]["path"], str(cl2))
    check("L3: CLEAN にも決定論 iocs が付与される（identifier/datetime と同じ"
          "「元データ由来フィールドは常に付与」の一貫挙動・監査用）",
          cl["iocs"] == [ents[0]["path"]], str(cl["iocs"]))
    md = by_si[1]
    check("L3: MEDIUM の iocs が元データから決定論付与（LLM未出力でも完全パス）",
          md["iocs"] == [ents[1]["path"]], str(md["iocs"]))
    check("L3: MEDIUM の identifier も完全パスへ上書き（15文字ヒントを置換）",
          md["identifier"] == ents[1]["path"], md["identifier"])
    check("L3: LLMの判定価値(reason/mitre)は保持",
          md["reason"] == "不審な配置" and md["mitre"] == ["T1204"])
    lw = by_si[2]
    check("L3v2: LOW compact（3フィールド）の欠損補完＋identifier/iocs決定論付与",
          lw["reason"] == "一時ファイル" and lw["mitre"] == []
          and lw["identifier"] == ents[2]["path"]
          and lw["iocs"] == [ents[2]["path"]], str(lw))

    sec("L4: カバレッジ検証（欠落の決定論検出→欠落分のみ再送）")
    def _skip23(user_msg):
        ents = [{"source_index": i, "source_id": sid, "identifier": ident,
                 "score": "CLEAN", "reason": "問題なし"}
                for i, sid, ident in _bindings(user_msg) if i < 2]
        return json.dumps({"section": "directory", "entries": ents}, ensure_ascii=False)
    cli = _SeqClient([_skip23], auto=_lean_auto)
    res, summ, errs, tims = a.call_llm_chunked(cli, "dummy", "directory", 2,
                                               _dir_entries(4, stem="cov"))
    check("L4: 欠落2件が再送で回復し全4件カバー", len(res) == 4, f"={len(res)}")
    check("L4: chunk_errors なし", errs == [], str(errs))
    retry_calls = "\n".join(cli.calls[1:])
    check("L4: 再送プロンプトは欠落分(cov2/cov3)のみ",
          "cov2.exe" in retry_calls and "cov3.exe" in retry_calls
          and "cov0.exe" not in retry_calls and "cov1.exe" not in retry_calls)
    check("L4: 再送分の timings に retry=True", any(t.get("retry") for t in tims))
    check("L4: source_index がチャンク基準へ正規化される",
          sorted(e["source_index"] for e in res) == [0, 1, 2, 3],
          str(sorted(e.get("source_index") for e in res)))

    sec("L5: 無効/重複 source_index は不採用（誤帰属の構造的防止）")
    def _bad_si(user_msg):
        binds = _bindings(user_msg)
        i0, sid0, ident0 = binds[0]
        return json.dumps({"section": "directory", "entries": [
            {"source_index": i0, "source_id": sid0, "identifier": ident0,
             "score": "CLEAN", "reason": "問題なし"},
            {"source_index": 99, "source_id": "invalid", "identifier": "invalid",
             "score": "HIGH", "reason": "誤帰属候補"},
            {"source_index": None, "score": "HIGH"},
            {"source_index": i0, "source_id": sid0, "identifier": ident0,
             "score": "HIGH", "reason": "duplicate"},
        ]}, ensure_ascii=False)
    cli = _SeqClient([_bad_si], auto=_lean_auto)
    ents = _dir_entries(3, stem="bad")
    res, summ, errs, tims = a.call_llm_chunked(cli, "dummy", "directory", 2, ents)
    check("L5: 無効応答は採用されず全3件が正しくカバー",
          len(res) == 3 and errs == [], f"res={len(res)} errs={errs}")
    check("L5: index0 は初回の CLEAN 採用（重複 HIGH は不採用）",
          [e for e in res if e["source_index"] == 0][0]["score"] == "CLEAN")
    check("L5: 未カバー分(bad1/bad2)のみ再送",
          "bad1.exe" in "\n".join(cli.calls[1:]) and
          "bad0.exe" not in "\n".join(cli.calls[1:]))
    check("L5: identifier は全て元データ値（誤帰属なし）",
          sorted(e["identifier"] for e in res) == sorted(e["path"] for e in ents))

    sec("L6: 再送不能時の⚠可視化（v3.68: coverage split で singleton まで分割）")
    # v3.68: 全滅 GARBAGE は coverage split で最大 COVERAGE_MAX_SPLIT_DEPTH 段まで
    # 分割再送され、singleton まで到達しても回復しなければ⚠診断1件で残る。
    # 旧 CHUNK_RETRY=1（半分割1段のみ）より深く分割するため呼出回数は増える。
    cli = _SeqClient([GARBAGE], auto=lambda u: GARBAGE)   # 常に GARBAGE
    res, summ, errs, tims = a.call_llm_chunked(cli, "dummy", "directory", 2,
                                               _dir_entries(4))
    check("L6: 全滅×再送失敗 → ⚠診断1件", len(errs) == 1, str(errs))
    d = errs[0] if errs else {}
    check("L6: 診断が partial_parse 規約＋coverage フラグ",
          d.get("partial_parse") and (d.get("coverage") or d.get("lean_coverage")), str(d))
    check("L6: 未評価計上が正確（n=4, salvaged=0）",
          d.get("n_entries") == 4 and d.get("n_salvaged") == 0, str(d))
    check("L6: selected_unevaluated フラグが立つ（取りこぼしの明示）",
          d.get("selected_unevaluated") is True, str(d))
    check("L6: coverage split で複数回再送される（初回より多い）",
          len(cli.calls) >= 3, f"={len(cli.calls)}")
    _orig_retry = a.CHUNK_RETRY
    _orig_split = a.COVERAGE_MAX_SPLIT_DEPTH
    try:
        # v3.68: 「再送しない」は COVERAGE_MAX_SPLIT_DEPTH=0 で表現する
        # （CHUNK_RETRY は coverage split の意味に流用しない・指示5）。
        a.CHUNK_RETRY = 0
        a.COVERAGE_MAX_SPLIT_DEPTH = 0
        cli = _SeqClient([_skip23], auto=_lean_auto)
        res, summ, errs, tims = a.call_llm_chunked(cli, "dummy", "directory", 2,
                                                   _dir_entries(4, stem="nr"))
        check("L6: SPLIT=0 では再送せず欠落を即⚠可視化",
              len(cli.calls) == 1 and len(errs) == 1
              and errs[0].get("n_salvaged") == 2, f"calls={len(cli.calls)} errs={errs}")
        check("L6: SPLIT=0 の診断は selected_unevaluated=True",
              errs and errs[0].get("selected_unevaluated") is True, str(errs))
    finally:
        a.CHUNK_RETRY = _orig_retry
        a.COVERAGE_MAX_SPLIT_DEPTH = _orig_split
finally:
    a.LEAN_OUTPUT = _orig_lean

# ════════════════════════════════════════════════════════════
sec("L7: LEAN_OUTPUT=0 指定時は従来動作を完全維持（回帰）")
import subprocess as _sp
_r = _sp.run([sys.executable, "-c",
              "import importlib.util;"
              f"s=importlib.util.spec_from_file_location('a','{SCRIPTS}/analyze_section.py');"
              "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
              "print(m.LEAN_OUTPUT)"],
             capture_output=True, text=True,
             env={**os.environ, "CHECKPC_LEAN_OUTPUT": "0"})
check("L7: 環境変数=0 で従来動作へ復帰できる", _r.stdout.strip() == "0", _r.stdout)
a.LEAN_OUTPUT = 0   # 以降のL7ケースはFULL経路の回帰
def _full_auto(user_msg):
    ents = [{"source_index": i, "source_id": sid, "identifier": ident,
             "score": "CLEAN", "reason": "ok", "mitre": [], "iocs": []}
            for i, sid, ident in _bindings(user_msg)]
    return json.dumps({"section": "directory", "entries": ents}, ensure_ascii=False)
cli = _SeqClient(auto=_full_auto)
res, summ, errs, tims = a.call_llm_chunked(cli, "dummy", "directory", 2, _dir_entries(4))
check("L7: FULLプロンプトが使われる（一字一句あり）", "一字一句" in cli.calls[0])
check("L7: 従来どおり全件評価・エラーなし", len(res) == 4 and errs == [])
# 無効 source_index のフォールバック
# v3.68: 新既定（_call_chunk_verified）では、singleton（part1件・返却1件）は
# source_index=0 を安全付与し、identifier は元データ値へ上書きする（誤帰属防止）。
# 旧 v3.58 の「LLM identifier をそのまま保持」は LEGACY 経路の挙動として検証する。
def _full_badsi(user_msg):
    _, _, ident = _bindings(user_msg)[0]
    return json.dumps({"section": "directory", "entries": [
        {"source_index": None, "identifier": ident, "score": "LOW",
         "reason": "r", "mitre": [], "iocs": []}]}, ensure_ascii=False)
# 新既定: singleton 安全帰属 + identifier 元データ上書き
cli = _SeqClient([_full_badsi])
res, summ, errs, tims = a.call_llm_chunked(cli, "dummy", "directory", 2, _dir_entries(1))
check("L7(新): singleton は source_index=0 で採用し identifier を元データ値へ上書き",
      len(res) == 1 and res[0]["identifier"] == "C:\\Users\\Public\\file0.exe", str(res))
# v3.68-rc2: 旧identifier帰属経路は安全性のため廃止。環境変数を指定しても
# singletonの決定論帰属と元データ上書きを維持する。
os.environ["CHECKPC_LEGACY_CHUNK"] = "1"
try:
    cli = _SeqClient([_full_badsi])
    res2, _, _, _ = a.call_llm_chunked(cli, "dummy", "directory", 2, _dir_entries(1))
    check("L7: LEGACY指定でも安全なsingleton帰属を維持",
          len(res2) == 1 and res2[0]["identifier"] == "C:\\Users\\Public\\file0.exe", str(res2))
finally:
    os.environ.pop("CHECKPC_LEGACY_CHUNK", None)
a.LEAN_OUTPUT = _orig_lean   # 復元

# ════════════════════════════════════════════════════════════
sec("L8: temperature=0.0（判定の再現性 / v3.63）")
class _KwCli:
    kwargs = []
    class chat:
        class completions:
            @staticmethod
            def create(**kw):
                _KwCli.kwargs.append(kw)
                class _O: pass
                m = _O(); m.content = _full_auto(
                    [x for x in kw["messages"] if x["role"] == "user"][0]["content"])
                c = _O(); c.message = m
                r = _O(); r.choices = [c]
                return r
a.call_llm_chunked(_KwCli, "dummy", "directory", 2, _dir_entries(2))
check("L8: analyze_section の LLM 呼び出しが temperature=0.0",
      _KwCli.kwargs and _KwCli.kwargs[0].get("temperature") == 0.0,
      str(_KwCli.kwargs[0].get("temperature") if _KwCli.kwargs else None))
_src_corr = open(os.path.join(SCRIPTS, "correlate.py"), encoding="utf-8").read()
check("L8: correlate.py も temperature=0.0（回帰ピン）",
      "temperature=0.0" in _src_corr and "temperature=0.1" not in _src_corr)

print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
