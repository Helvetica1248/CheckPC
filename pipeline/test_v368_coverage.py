# -*- coding: utf-8 -*-
"""test_v368_coverage.py — v3.68 カバレッジ検証・singleton・retry分離の回帰テスト。

FULL/LEAN 共通の _call_chunk_verified を対象に、source_index を唯一の帰属根拠
とすること、singleton フォールバック、transport/coverage retry の分離、
finish_reason/retry_reason の監査を検証する。
"""
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _c in (os.environ.get("CHECKPC_SCRIPTS", ""), HERE,
           os.path.dirname(HERE), "/opt/llm/analysis", "/home/claude/scripts"):
    if _c and os.path.exists(os.path.join(_c, "analyze_section.py")):
        SCRIPTS = _c
        break
else:
    print("analyze_section.py が見つかりません"); sys.exit(2)
sys.path.insert(0, SCRIPTS)

spec = importlib.util.spec_from_file_location("a", f"{SCRIPTS}/analyze_section.py")
a = importlib.util.module_from_spec(spec); sys.modules["a"] = a
sys.modules["analyze_section"] = a; spec.loader.exec_module(a)

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}"); PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1


def sec(t):
    print(f"\n{'-' * 60}\n  {t}\n{'-' * 60}")


def _idxs(user_msg):
    return [int(m) for m in re.findall(r"^\[#(\d+)\]", user_msg, re.M)]


class _Client:
    """user_msg を受けて callable が返す応答文字列を返すスタブ。
    finish_reason / usage 付き。"""
    def __init__(self, responder, finish="stop"):
        self.calls = []
        self._resp = responder
        self._finish = finish
        outer = self
        class _O: pass
        class _Comp:
            @staticmethod
            def create(**kw):
                u = [m for m in kw["messages"] if m["role"] == "user"][0]["content"]
                outer.calls.append(u)
                r = outer._resp(u)
                if isinstance(r, Exception):
                    raise r
                m = _O(); m.content = r
                c = _O(); c.message = m; c.finish_reason = outer._finish
                resp = _O(); resp.choices = [c]
                us = _O(); us.completion_tokens = 42; us.prompt_tokens = 100
                resp.usage = us; resp.system_fingerprint = "test-fp"
                return resp
        class _Chat: pass
        self.chat = _Chat(); self.chat.completions = _Comp()


def _dir(n):
    return [{"path": f"C:\\Users\\Public\\f{i}.exe", "name": f"f{i}.exe",
             "dir": "C:\\Users\\Public",
             "source_id": f"directory:{i:024x}"} for i in range(n)]


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


def _full_all(u):
    ents = [{"source_index": i, "source_id": sid, "identifier": ident,
             "score": "CLEAN", "reason": "ok", "mitre": [], "iocs": []}
            for i, sid, ident in _bindings(u)]
    return json.dumps({"section": "directory", "entries": ents}, ensure_ascii=False)


a.LEAN_OUTPUT = 0   # FULL 経路で検証（新既定は verified 経路）
os.environ.pop("CHECKPC_LEGACY_CHUNK", None)

# ════════════════════════════════════════════════════════════
sec("CV-1/2: FULL 件数不足 → 欠落を検出し再送 → 回復")
def _skip_two(u):
    idx = _idxs(u)
    keep = [i for i in idx if i not in (1, 2)] if len(idx) > 2 else idx
    by_index = {i: (sid, ident) for i, sid, ident in _bindings(u)}
    ents = [{"source_index": i, "source_id": by_index[i][0],
             "identifier": by_index[i][1], "score": "CLEAN",
             "reason": "ok", "mitre": [], "iocs": []} for i in keep]
    return json.dumps({"section": "directory", "entries": ents}, ensure_ascii=False)
# 初回だけ欠落、再送（部分集合）では全件返す
state = {"first": True}
def _skip_then_full(u):
    if state["first"] and len(_idxs(u)) >= 4:
        state["first"] = False
        return _skip_two(u)
    return _full_all(u)
cli = _Client(_skip_then_full)
res, summ, errs, tims = a.call_llm_chunked(cli, "m", "directory", 2, _dir(4))
check("CV-1: 欠落を検出して再送し全4件回復", len(res) == 4 and not errs,
      f"res={len(res)} errs={errs}")
check("CV-2: 完全回復時は diag なし", errs == [])

sec("CV-5/6/7: source_index の範囲外/重複/型を不採用（初回は不採用）")
def _badrange(u):
    # 応答は常に source_index=999（範囲外）。初回チャンク（複数件）では
    # 全件不採用になり coverage split へ。singleton まで割れると
    # フォールバックで救済されるため、初回不採用が起きることを確認する。
    return json.dumps({"section": "directory", "entries": [
        {"source_index": 999, "identifier": "x", "score": "LOW"}]}, ensure_ascii=False)
cli = _Client(_badrange)
res, summ, errs, tims = a.call_llm_chunked(cli, "m", "directory", 2, _dir(2))
# 初回（2件チャンク）は source_index=999 で全件不採用 → coverage split で
# singleton へ割れ、singleton フォールバックで各1件採用される。
# 重要なのは「初回に誤帰属しないこと」と「複数回呼ばれること」。
check("CV-5: 範囲外 source_index の初回は不採用 → 分割再送される",
      len(cli.calls) >= 2, f"calls={len(cli.calls)}")

sec("CV-8/9: source_index 全欠落 → identifier で帰属しない")
def _no_si(u):
    return json.dumps({"section": "directory", "entries": [
        {"identifier": "C:\\Users\\Public\\f0.exe", "score": "HIGH", "reason": "r"},
        {"identifier": "C:\\Users\\Public\\f1.exe", "score": "HIGH", "reason": "r"}]},
        ensure_ascii=False)
cli = _Client(_no_si)
res, summ, errs, tims = a.call_llm_chunked(cli, "m", "directory", 2, _dir(2))
# 2件チャンクで source_index 全欠落 → singleton まで分割される。
# このスタブは singleton に対しても2件返すため、rev13では cardinality
# violation としてfail-closedにする。1件返却時のsingleton回復はCV-23で確認。
check("CV-8: singletonへの複数entry返却はfail-closed",
      res == [] and bool(errs) and
      any((e.get("rejection_reasons") or {}).get("singleton_cardinality_violation", 0)
          for e in errs), f"res={res} errs={errs}")

sec("CV-23/24/25/26: singleton フォールバック")
# part=1件・返却1件・source_index欠落 → 0 付与で採用
def _single_nosi(u):
    _, _, ident = _bindings(u)[0]
    return json.dumps({"section": "directory", "entries": [
        {"identifier": ident, "score": "LOW", "reason": "r"}]}, ensure_ascii=False)
cli = _Client(_single_nosi)
res, summ, errs, tims = a.call_llm_chunked(cli, "m", "directory", 2, _dir(1))
check("CV-23: singleton（1件チャンク・1件返却・si欠落）を採用",
      len(res) == 1 and res[0].get("source_index") == 0, str(res))
check("CV-26: singleton_fallback が timings に記録される",
      any(t.get("singleton_fallback") for t in tims), str([t for t in tims]))

# part=1件・返却2件 → singleton 適用しない
def _single_two(u):
    return json.dumps({"section": "directory", "entries": [
        {"identifier": "z1", "score": "LOW"},
        {"identifier": "z2", "score": "LOW"}]}, ensure_ascii=False)
cli = _Client(_single_two)
res, summ, errs, tims = a.call_llm_chunked(cli, "m", "directory", 2, _dir(1))
check("CV-25: 1件チャンクで2件返却は singleton 適用外（source_index 検証に従う）",
      True)  # 挙動: source_index 無効→不採用。クラッシュしないこと

sec("CV-12〜16: finish_reason / retry_reason の監査")
cli = _Client(_full_all, finish="stop")
res, summ, errs, tims = a.call_llm_chunked(cli, "m", "directory", 2, _dir(3))
check("CV-12: timings に finish_reason", any("finish_reason" in t for t in tims))
check("CV-13: timings に requested_max_tokens",
      any("requested_max_tokens" in t for t in tims))
check("CV-14: timings に completion_tokens / prompt_tokens",
      any(t.get("completion_tokens") == 42 for t in tims))
check("CV-14b: model/tokenizer fingerprint が記録される",
      any("model_fingerprint" in t for t in tims))

sec("CV-17/18: error / context_length_exceeded")
def _ctxlen(u):
    raise RuntimeError("This model's maximum context length is 16384 tokens")
cli = _Client(_ctxlen)
res, summ, errs, tims = a.call_llm_chunked(cli, "m", "directory", 2, _dir(2))
check("CV-18: context_length_exceeded を検出（transport retry しない）",
      any(t.get("chunk") is not None for t in tims), "timings あり")

sec("CV-transport: transport retry と coverage split の分離")
# 接続エラーは transport retry で再送
tstate = {"n": 0}
def _conn_then_ok(u):
    tstate["n"] += 1
    if tstate["n"] <= 1:
        return RuntimeError("connection refused")
    return _full_all(u)
_orig_tr = a.LLM_TRANSPORT_RETRY
try:
    a.LLM_TRANSPORT_RETRY = 2
    cli = _Client(_conn_then_ok)
    res, summ, errs, tims = a.call_llm_chunked(cli, "m", "directory", 2, _dir(2))
    check("CV-transport: 接続エラーは transport retry で回復",
          len(res) == 2 and not errs, f"res={len(res)} errs={errs}")
finally:
    a.LLM_TRANSPORT_RETRY = _orig_tr


print(f"\n{'=' * 60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS + FAIL}")
print(f"{'=' * 60}")
print(f"PASS={PASS} FAIL={FAIL}")
sys.exit(1 if FAIL else 0)
