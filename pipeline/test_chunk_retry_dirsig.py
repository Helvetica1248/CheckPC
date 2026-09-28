# -*- coding: utf-8 -*-
"""P1: チャンク自動リトライ / N-4d(案b): directory同型パターン集約 の回帰テスト。

v3.59 で追加。LLM はスタブ（_SeqClient）で代替し、実LLMは使わない。
配置場所は analyze_section.py と同じディレクトリ、または tests/ サブディレクトリ、
または CHECKPC_SCRIPTS 環境変数で指定。
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
spec = importlib.util.spec_from_file_location("a", f"{SCRIPTS}/analyze_section.py")
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
# v3.66でLEANが既定ONになったため、本ファイルは FULL 経路（v3.59 の
# リトライ機構）の回帰を担う位置づけとして明示的にFULLへ固定する。
# LEAN経路の回帰は test_p3_lean_output.py / test_v366_fixes.py が担う。
a.LEAN_OUTPUT = 0
# v3.68-rc2: FULL/LEAN共通のcoverage split経路を検証する。

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: print(f"  [OK]  {name}"); PASS += 1
    else: print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1
def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")


# ════════════════════════════════════════════════════════════
# スタブLLMクライアント
# ════════════════════════════════════════════════════════════
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


def _ok_json(user_msg):
    """Return an exact source_index/source_id/identifier triple for every row."""
    ents = [{"source_index": i, "source_id": sid, "identifier": ident,
             "score": "CLEAN", "reason": "ok", "mitre": [], "iocs": []}
            for i, sid, ident in _bindings(user_msg)]
    return json.dumps({"section": "directory", "entries": ents}, ensure_ascii=False)

class _SeqClient:
    """指定した応答列を順に返す OpenAI 互換スタブ。
    要素: 文字列（そのまま返す）/ callable（user_msgを受けて文字列を返す）/
          Exception（呼び出し時に送出＝接続エラー模擬）。
    使い切った後は _ok_json で自動応答する。"""
    def __init__(self, responses=()):
        self._resp = list(responses)
        self.calls = []            # 各呼び出しの user メッセージを記録
        outer = self
        class _Msg: pass
        class _Choice: pass
        class _Resp: pass
        class _Completions:
            @staticmethod
            def create(**kw):
                user = [m for m in kw["messages"] if m["role"] == "user"][0]["content"]
                outer.calls.append(user)
                r = outer._resp.pop(0) if outer._resp else _ok_json
                if isinstance(r, Exception):
                    raise r
                if callable(r):
                    r = r(user)
                m = _Msg(); m.content = r
                c = _Choice(); c.message = m
                resp = _Resp(); resp.choices = [c]
                return resp
        class _Chat: pass
        self.chat = _Chat(); self.chat.completions = _Completions()

def _dir_entries(n, stem="file"):
    """directoryセクション形式のテストエントリを n 件生成する。"""
    return [{"path": f"C:\\Users\\Public\\{stem}{i}.exe",
             "name": f"{stem}{i}.exe", "dir": "C:\\Users\\Public",
             "date": "2026/01/01  00:00", "size": "100"} for i in range(n)]

GARBAGE = "％％ここにJSONはありません％％"
def _truncated_first_only(user_msg):
    """[#0] only complete; [#1] is truncated."""
    i, sid, ident = _bindings(user_msg)[0]
    return ('{"section": "directory", "entries": ['
            + json.dumps({"source_index": i, "source_id": sid,
                          "identifier": ident, "score": "CLEAN",
                          "reason": "ok", "mitre": [], "iocs": []},
                         ensure_ascii=False)
            + ', {"source_index": 1, "identifier": "truncated", "sco')


# ════════════════════════════════════════════════════════════
sec("P1-R1: parse_error → 半分割再試行で全件回復")
cli = _SeqClient([GARBAGE])          # 初回のみ失敗、以降は自動正常応答
ents = _dir_entries(4)
res, summ, errs, tims = a.call_llm_chunked(cli, "dummy", "directory", 2, ents)
check("R1: 呼び出し回数=3（初回1＋再試行2半）", len(cli.calls) == 3, f"={len(cli.calls)}")
check("R1: 全4件が評価される", len(res) == 4, f"={len(res)}")
check("R1: identifierが元データ値へ上書きされている",
      sorted(e["identifier"] for e in res) ==
      sorted(e["path"] for e in ents), str([e.get("identifier") for e in res]))
check("R1: chunk_errors は空（⚠を出さない）", errs == [], str(errs))
check("R1: timings に retry=True が2件残る（監査痕跡）",
      sum(1 for t in tims if t.get("retry")) == 2, str(tims))

# ════════════════════════════════════════════════════════════
sec("P1-R2: partial_parse → 救出済みを除いた残りのみ再送")
cli = _SeqClient([_truncated_first_only])
ents = _dir_entries(4, stem="reg")
res, summ, errs, tims = a.call_llm_chunked(cli, "dummy", "directory", 2, ents)
check("R2: 全4件が評価される（救出1＋再送3）", len(res) == 4, f"={len(res)}")
check("R2: chunk_errors は空", errs == [], str(errs))
retry_calls = "\n".join(cli.calls[1:])
check("R2: 再送プロンプトに救出済み reg0 が含まれない（二重評価防止）",
      "reg0.exe" not in retry_calls)
check("R2: 再送プロンプトに未評価 reg1〜3 が全て含まれる",
      all(f"reg{i}.exe" in retry_calls for i in (1, 2, 3)))
check("R2: identifier の重複なし",
      len({e["identifier"] for e in res}) == 4,
      str(sorted(e["identifier"] for e in res)))

# ════════════════════════════════════════════════════════════
sec("P1-R3: 接続エラー（例外）→ 再試行で回復")
cli = _SeqClient([RuntimeError("connection refused")])
res, summ, errs, tims = a.call_llm_chunked(cli, "dummy", "directory", 2, _dir_entries(4))
check("R3: 全4件が評価される", len(res) == 4, f"={len(res)}")
check("R3: chunk_errors は空", errs == [], str(errs))

# ════════════════════════════════════════════════════════════
sec("P1-R4: 再試行も失敗 → 従来規約の⚠診断（後退なし）")
cli = _SeqClient([GARBAGE] * 20)
res, summ, errs, tims = a.call_llm_chunked(cli, "dummy", "directory", 2, _dir_entries(4))
check("R4: 診断が1件残る", len(errs) == 1, str(errs))
d = errs[0] if errs else {}
check("R4: retry_attempted フラグが付く", d.get("retry_attempted") is True, str(d))
check("R4: 未評価計上が正しい（n_entries=4, n_salvaged=0 → lost=4）",
      d.get("n_entries") == 4 and d.get("n_salvaged") == 0, str(d))
check("R4: partial_parse 規約で返る（消費側の集計互換）",
      d.get("partial_parse") is True, str(d))

# ════════════════════════════════════════════════════════════
sec("P1-R5: singletonのparse_errorは無意味な同一再送をしない")
cli = _SeqClient([GARBAGE])
res, summ, errs, tims = a.call_llm_chunked(cli, "dummy", "directory", 2, _dir_entries(1))
check("R5: 呼び出し回数=1", len(cli.calls) == 1, f"={len(cli.calls)}")
check("R5: selected_unevaluatedとして可視化",
      len(res) == 0 and len(errs) == 1 and errs[0].get("selected_unevaluated") is True,
      f"res={len(res)} errs={errs}")

# ════════════════════════════════════════════════════════════
sec("P1-R6: COVERAGE_MAX_SPLIT_DEPTH=0 で分割しない")
_orig = a.COVERAGE_MAX_SPLIT_DEPTH
try:
    a.COVERAGE_MAX_SPLIT_DEPTH = 0
    cli = _SeqClient([GARBAGE])
    res, summ, errs, tims = a.call_llm_chunked(cli, "dummy", "directory", 2, _dir_entries(4))
    check("R6: 再試行されない（呼び出し1回のみ）", len(cli.calls) == 1, f"={len(cli.calls)}")
    check("R6: coverage診断が残る",
          len(errs) == 1 and errs[0].get("coverage") is True, str(errs))
finally:
    a.COVERAGE_MAX_SPLIT_DEPTH = _orig

# ════════════════════════════════════════════════════════════
sec("N-4d-S1: _dir_signature 正規化")
def sig(p):
    d, _, n = p.rpartition("\\")
    return a._dir_signature({"path": p, "name": n, "dir": d})
check("S1: GUID名同士は同一シグネチャ",
      sig(r"C:\Windows\temp\a1b2c3d4-e5f6-7890-abcd-ef0123456789.tmp.js")
      == sig(r"C:\Windows\temp\ffee0011-2233-4455-6677-889900aabbcc.tmp.js"))
check("S1: 16進名・数字名も畳まれる",
      sig(r"C:\Windows\temp\deadbeef01.tmp.js") == sig(r"C:\Windows\temp\0123456789.tmp.js"))
check("S1: フォルダが違えば別シグネチャ",
      sig(r"C:\Windows\temp\a1b2c3d4e5f6.tmp.js") != sig(r"C:\Users\Public\a1b2c3d4e5f6.tmp.js"))
check("S1: 拡張子チェーンが違えば別シグネチャ",
      sig(r"C:\Windows\temp\a1b2c3d4e5f6.tmp.js") != sig(r"C:\Windows\temp\a1b2c3d4e5f6.tmp.exe"))
check("S1: 通常ファイル名同士は別シグネチャ（kernel32≠user32）",
      sig(r"C:\Windows\System32\kernel32.dll") != sig(r"C:\Windows\System32\user32.dll"))
check("S1: 大文字小文字は無視",
      sig(r"C:\WINDOWS\TEMP\ABCD1234.TMP.JS") == sig(r"c:\windows\temp\abcd1234.tmp.js"))

# ════════════════════════════════════════════════════════════
sec("N-4d-S2: _select_dir_llm_entries 選抜ロジック")
def scored_of(paths, score=85):
    out = []
    for p in paths:
        d, _, n = p.rpartition("\\")
        out.append((score, "B", {"path": p, "name": n, "dir": d}))
    return out

# 同型50件(85点) + 多様10件(70点)。従来は多様側が押し出される。
same = scored_of([rf"C:\Windows\temp\{i:08x}abcd.tmp.js" for i in range(50)], 85)
div  = scored_of([rf"C:\Users\u{i}\AppData\Roaming\tool{i}.exe" for i in range(10)], 70)
scored = same + div   # スコア降順（85群→70群）

llm, ovf, info = a._select_dir_llm_entries(scored, max_llm=20, sig_max=3)
check("S2: 同型は代表3件のみ送付",
      sum(1 for e in llm if e["name"].endswith(".tmp.js")) == 3,
      f"={sum(1 for e in llm if e['name'].endswith('.tmp.js'))}")
check("S2: 押し出されていた多様10件が全て繰り上がって送付される",
      sum(1 for e in llm if e["name"].endswith(".exe")) == 10)
check("S2: 総数保存（送付+退避=60）", len(llm) + len(ovf) == 60,
      f"llm={len(llm)} ovf={len(ovf)}")
check("S2: sig_info の退避件数=47", info and info["n_deferred"] == 47, str(info))
check("S2: 集約上位シグネチャに tmp.js 型が入る",
      info and any(".tmp.js" in s for s, _ in info["top"]), str(info))
check("S2: 退避側はスコア降順を維持（先頭は85点群）",
      ovf and ovf[0]["name"].endswith(".tmp.js"))

# max_llm 上限は引き続き有効
many = scored_of([rf"C:\d{i}\u{i}.exe" for i in range(30)], 80)  # 全て別シグネチャ
llm2, ovf2, info2 = a._select_dir_llm_entries(many, max_llm=20, sig_max=3)
check("S2: 別シグネチャのみでも max_llm=20 で頭打ち",
      len(llm2) == 20 and len(ovf2) == 10)
check("S2: 上限超過のみでは集約0件をpolicy infoで明示",
      info2 and info2.get("n_deferred") == 0)

# sig_max=0 disables only signature aggregation; M1 anti-monopoly bounds remain active.
llm3, ovf3, info3 = a._select_dir_llm_entries(scored, max_llm=20, sig_max=0)
check("S2: sig_max=0でもM1親/配置上限は維持",
      info3 and info3.get("n_deferred") == 0
      and info3.get("coverage_degraded") is True
      and len(llm3) < 20)

# ════════════════════════════════════════════════════════════
sec("N-4d-S3: analyze() 統合（可視化エントリ・HOST-REF-03事象の再現と解消）")
_parsed = {
    "meta": {"hostname": "TESTHOST"},
    "sections": {"directory":
        [{"path": rf"C:\Windows\Temp\{i:04x}{i:04x}-aa{i:02x}.tmp.js",
          "name": f"{i:04x}{i:04x}-aa{i:02x}.tmp.js", "dir": r"C:\Windows\Temp",
          "date": "2026/01/01  00:00", "size": "10"} for i in range(30)]
        + [{"path": r"C:\Users\Public\Libraries\invoice.pdf.exe",
            "name": "invoice.pdf.exe", "dir": r"C:\Users\Public\Libraries",
            "date": "2026/01/01  00:00", "size": "10"}]},
    "event_logs": {},
}
cli = _SeqClient()   # 全て自動正常応答
r = a.analyze(_parsed, depth=1, client=cli, model="dummy",
              target_sections=["directory"])
sec_r = r["sections"]["directory"]
agg = [e for e in sec_r["entries"] if "同型パターン" in str(e.get("identifier"))]
check("S3: 同型集約の⚠可視化エントリが出る", len(agg) == 1,
      str([e.get("identifier") for e in sec_r["entries"]])[:300])
check("S3: 可視化エントリに件数と代表数が明記される",
      agg and "27件" in agg[0]["identifier"] and "代表3件" in agg[0]["identifier"],
      agg[0]["identifier"] if agg else "")
check("S3: 可視化エントリの reason に集約シグネチャと無効化手段が明記される",
      agg and "tmp.js" in agg[0]["reason"] and "CHECKPC_DIR_SIG_MAX" in agg[0]["reason"],
      agg[0]["reason"][:200] if agg else "")
check("S3: 退避分が _directory_overflow に保存される（raw_directory向け）",
      len(sec_r.get("_directory_overflow", [])) == 27,
      f"={len(sec_r.get('_directory_overflow', []))}")
check("S3: section_summary に集約の注記が入る",
      "同型パターン集約" in sec_r.get("section_summary", ""),
      sec_r.get("section_summary", "")[:200])
check("S3: 高スコアの二重拡張子 invoice.pdf.exe はLLM送付されている",
      any("invoice.pdf.exe" in c for c in cli.calls))
_tmpjs_sent = sum(
    1 for call in cli.calls for line in call.splitlines()
    if line.startswith("[#") and ".tmp.js" in line
)
check("S3: LLMに送られた tmp.js は代表3件のみ", _tmpjs_sent == 3, f"={_tmpjs_sent}")

print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
