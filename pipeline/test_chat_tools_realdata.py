# -*- coding: utf-8 -*-
"""
チャット機能(chat_tools.py)の回帰テスト。

方針:
  · Lv.1ツールは実データ(analyzed_*.json)に対して正しい結果を返すこと。
  · Lv.2ツールは呼び出し上限・VT_API_KEY未設定時のガードが機能すること。
  · run_chat_turn はネットワーク不要のスタブLLMクライアントで
    tool-callingループの往復・履歴追記・監査ログを検証する。
"""
import os
import sys, importlib.util, json, glob, tempfile, shutil
from pathlib import Path

for _c in (os.environ.get("CHECKPC_SCRIPTS", ""), os.path.dirname(os.path.abspath(__file__)),
           os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
           "/opt/llm/analysis", "/home/claude/scripts"):
    if _c and os.path.exists(os.path.join(_c, "analyze_section.py")):
        SCRIPTS = _c
        break
else:
    print("analyze_section.py が見つかりません"); sys.exit(2)
sys.path.insert(0, SCRIPTS)

REALDATA_ROOT = Path(os.environ["CHECKPC_TEST_EXTRACT"]).expanduser().resolve()
TEST_WORKDIR = Path(os.environ["CHECKPC_TEST_WORKDIR"]).expanduser().resolve()
TEST_WORKDIR.mkdir(parents=True, exist_ok=True)
try:
    TEST_WORKDIR.relative_to(REALDATA_ROOT)
except ValueError as exc:
    raise RuntimeError("CHECKPC_TEST_WORKDIR must be inside CHECKPC_TEST_EXTRACT") from exc


def _load(modname, filename):
    spec = importlib.util.spec_from_file_location(modname, f"{SCRIPTS}/{filename}")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


vt = _load("vt_post", "vt_post.py")
sys.modules["vt_post"] = vt  # chat_tools が import vt_post するため事前登録
ct = _load("chat_tools", "chat_tools.py")

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: print(f"  [OK]  {name}"); PASS += 1
    else: print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1
def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

# ════════════════════════════════════════════════════════════
sec("ツールスキーマ構築")
lv1_only = ct.build_tool_schema(lv2_enabled=False)
lv1_lv2 = ct.build_tool_schema(lv2_enabled=True)
expected_lv1_names = {
    "get_section", "get_entry_detail", "search_keyword",
    "search_directory_evidence", "list_high_medium",
    "get_timeline", "list_directory_files",
}
expected_lv2_names = expected_lv1_names | {"vt_ioc_lookup", "cross_host_search"}
lv1_names = {t["function"]["name"] for t in lv1_only}
names = {t["function"]["name"] for t in lv1_lv2}
check("lv2_enabled=False → Lv.1のみ(7件、directory-scoped search含む)",
      lv1_names == expected_lv1_names, f"names={lv1_names}")
check("lv2_enabled=True → Lv.1+Lv.2(9件)",
      names == expected_lv2_names, f"names={names}")
check("想定ツール名が揃っている", names == expected_lv2_names, f"names={names}")
check("is_lv2_tool: vt_ioc_lookup → True", ct.is_lv2_tool("vt_ioc_lookup"))
check("is_lv2_tool: get_section → False", not ct.is_lv2_tool("get_section"))

# ════════════════════════════════════════════════════════════
sec("ChatContext（実データ: HOST-REF-04）")
HOST_DIR = REALDATA_ROOT / "HOST-REF-04_2026010301010100"
JOBS_DIR = REALDATA_ROOT
ctx = ct.ChatContext(HOST_DIR, JOBS_DIR, vt_key="")

r = ctx.tool_get_section("startup_folder")
check("get_section: startup_folder取得成功", "entries" in r, f"r={str(r)[:200]}")
check("get_section: Zotero.dotmエントリを含む",
      any("Zotero" in str(e.get("identifier", "")) for e in r.get("entries", [])))

r2 = ctx.tool_get_section("no_such_section")
check("get_section: 存在しないセクション → error+候補一覧",
      "error" in r2 and "available_sections" in r2)

r3 = ctx.tool_get_entry_detail("startup_folder", "zotero")
check("get_entry_detail: 部分一致(小文字)で検索できる",
      "matches" in r3 and len(r3["matches"]) >= 1, f"r3={str(r3)[:200]}")

r4 = ctx.tool_get_entry_detail("startup_folder", "存在しない文字列xyz")
check("get_entry_detail: 一致なし → error", "error" in r4)

r5 = ctx.tool_list_high_medium()
check("list_high_medium: HIGH/MEDIUMのみ抽出される",
      all(e["score"] in ("HIGH", "MEDIUM") for e in r5["entries"]) and r5["count"] > 0,
      f"count={r5.get('count')}")

# ════════════════════════════════════════════════════════════
sec("Lv.2 安全機構")
ctx2 = ct.ChatContext(HOST_DIR, JOBS_DIR, vt_key="")  # VT_API_KEY未設定
r6 = ctx2.tool_vt_lookup("wsnativepushservice.exe")
check("vt_lookup: VT_API_KEY未設定 → error", "error" in r6, f"r6={r6}")

ctx3 = ct.ChatContext(HOST_DIR, JOBS_DIR, vt_key="dummy-key-for-limit-test")
ctx3.lv2_call_count = ct.LV2_MAX_CALLS_PER_SESSION  # 上限到達状態を模擬
r7 = ctx3.tool_vt_lookup("example.com")
check(f"vt_lookup: 呼び出し上限({ct.LV2_MAX_CALLS_PER_SESSION}回)到達 → error",
      "error" in r7 and "上限" in r7["error"])
r8 = ctx3.tool_cross_host_search("example.com")
check("cross_host_search: 呼び出し上限はvt_lookupと共有(同一カウンタ)", "error" in r8)

# ════════════════════════════════════════════════════════════
sec("横断検索（実データ: 6ホストバッチ、JOBS_DIR/{job_id}/output/ 構造で検証）")
# server.py の実レイアウトは JOBS_DIR/{job_id}/output/*.json。
# バッチ実行結果(output_check)は output サブフォルダを持たない別レイアウトのため、
# 本番相当の構造を一時ディレクトリに再現してから横断検索を検証する。
_real_hosts = [
    "HOST-REF-02_2026010601010100", "HOST-REF-04_2026010301010100",
    "HOST-REF-08_2026010201010100", "HOST-REF-09_2026010401010100",
    "HOST-REF-10_2026010501010100", "HOST-REF-11_2026010101010100",
]
with tempfile.TemporaryDirectory(dir=TEST_WORKDIR) as jobs_root:
    jobs_root = Path(jobs_root)
    jobs_meta = {}
    for h in _real_hosts:
        out_dir = jobs_root / h / "output"
        out_dir.mkdir(parents=True)
        jobs_meta[h] = {"job_id": h, "folder": "REALDATA", "status": "done"}
        # chat_tools が実際に参照するのは analyzed_*.json のみ。
        # parsed_*.json（CheckPC生データ、ホストによっては数百MB〜1GB近い）を
        # 誤って巻き込まないよう対象を限定し、read/write copyではなく
        # rc5の横断検索はsymlinkを拒否するため、analyzedのみ通常コピーする。
        for f in (REALDATA_ROOT / h).glob("analyzed_*.json"):
            (out_dir / f.name).write_bytes(f.read_bytes())

    ctx4 = ct.ChatContext(jobs_root / "HOST-REF-04_2026010301010100" / "output", jobs_root, vt_key="",
                          job_id="HOST-REF-04_2026010301010100", case_folder="REALDATA",
                          jobs_metadata=jobs_meta, lv2_policy="local")
    r9 = ctx4.tool_cross_host_search("Zotero")
    hostset = {h["job_id"] for h in r9["other_host_hits"]}
    check("cross_host_search: 現在ホストと他ホストを分離してZoteroを返す",
          r9.get("current_job_match_count", 0) >= 1 and len(hostset) >= 1,
          f"current={r9.get('current_job_match_count')} hostset={hostset}")

    ctx5 = ct.ChatContext(jobs_root / "HOST-REF-04_2026010301010100" / "output", jobs_root, vt_key="",
                          job_id="HOST-REF-04_2026010301010100", case_folder="REALDATA",
                          jobs_metadata=jobs_meta, lv2_policy="local")
    r10 = ctx5.tool_cross_host_search("HWiNFO")
    check("cross_host_search: 現在/他ホストのいずれかでHWiNFOがヒットする",
          r10["count"] + r10.get("current_job_match_count", 0) >= 1, f"r10={str(r10)[:200]}")

# ════════════════════════════════════════════════════════════
sec("dispatch_tool_call")
d1 = ct.dispatch_tool_call(ctx, "get_section", {"section": "startup_folder"})
check("dispatch_tool_call: 正常系", "entries" in d1)
d2 = ct.dispatch_tool_call(ctx, "unknown_tool_xyz", {})
check("dispatch_tool_call: 未知のツール名 → error", "error" in d2)

class _Boom:
    def tool_get_section(self, *a, **k):
        raise RuntimeError("boom")
d3 = ct.dispatch_tool_call(_Boom(), "get_section", {"section": "x"})
check("dispatch_tool_call: ツール内例外を握りつぶしerror化する", "error" in d3, f"d3={d3}")

# ════════════════════════════════════════════════════════════
sec("run_chat_turn（スタブLLMクライアントによるtool-callingループ検証）")

class _StubMsg:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls

class _StubToolCall:
    def __init__(self, tc_id, name, arguments):
        self.id = tc_id
        self.function = type("F", (), {"name": name, "arguments": json.dumps(arguments, ensure_ascii=False)})()
    def model_dump(self):
        return {"id": self.id, "type": "function",
                "function": {"name": self.function.name, "arguments": self.function.arguments}}

class _StubResp:
    def __init__(self, msg):
        self.choices = [type("C", (), {"message": msg})()]

class _StubClient:
    """1回目はget_sectionツールを呼び、2回目でテキスト応答を返すLLMを模擬する。"""
    def __init__(self):
        self.calls = 0
        class _Chat:
            def __init__(self, outer): self.outer = outer
            class _Completions:
                def __init__(self, outer): self.outer = outer
                def create(self, model, messages, tools=None, tool_choice=None, **kwargs):
                    self.outer.calls += 1
                    if self.outer.calls == 1:
                        tc = _StubToolCall("call_1", "get_section", {"section": "startup_folder"})
                        return _StubResp(_StubMsg(content=None, tool_calls=[tc]))
                    return _StubResp(_StubMsg(content="Zoteroのアドインが確認できました。", tool_calls=None))
            @property
            def completions(self):
                return self._Completions(self.outer)
        self.chat = _Chat(self)

with tempfile.TemporaryDirectory(dir=TEST_WORKDIR) as tmpd:
    log_path = Path(tmpd) / "chat_tool_log.jsonl"
    messages = [{"role": "system", "content": "test"}, {"role": "user", "content": "startup_folderを見せて"}]
    stub = _StubClient()
    result = ct.run_chat_turn(stub, "dummy-model", messages, ctx,
                               lv2_enabled=False, tool_log_path=log_path)
    check("run_chat_turn: 最終replyがテキストで返る",
          result["reply"] == "Zoteroのアドインが確認できました。", f"result={result}")
    check("run_chat_turn: tool_calls_madeに1件記録される",
          len(result["tool_calls_made"]) == 1 and result["tool_calls_made"][0]["name"] == "get_section")
    check("run_chat_turn: timing情報が返る（LLM呼び出し2回分）",
          result["timing"]["llm_calls"] == 2 and
          len(result["timing"]["llm_seconds_per_call"]) == 2 and
          result["timing"]["llm_seconds_total"] >= 0,
          f"timing={result.get('timing')}")
    check("run_chat_turn: messagesにassistant(tool_calls)とtool結果が追記される",
          any(m["role"] == "tool" for m in messages) and
          any(m["role"] == "assistant" and m.get("tool_calls") for m in messages))
    check("run_chat_turn: 監査ログファイルが書き出される", log_path.exists())
    log_lines = [json.loads(l) for l in log_path.read_text(encoding="utf-8").splitlines()]
    tool_entries = [e for e in log_lines if "tool" in e]
    timing_entries = [e for e in log_lines if e.get("kind") == "llm_call_timing"]
    check("run_chat_turn: 監査ログにツール呼び出しが1件(get_section)記録される",
          len(tool_entries) == 1 and tool_entries[0]["tool"] == "get_section")
    check("run_chat_turn: 監査ログにLLM呼び出し2回分のタイミングが記録される（tool_call往復+最終応答）",
          len(timing_entries) == 2, f"timing_entries={timing_entries}")

# Lv.2ツールが無効時に呼ばれようとした場合のガード
class _StubClientLv2Attempt:
    def __init__(self):
        self.calls = 0
        outer = self
        class _Chat:
            class _Completions:
                def create(self, model, messages, tools=None, tool_choice=None, **kwargs):
                    outer.calls += 1
                    if outer.calls == 1:
                        tc = _StubToolCall("call_1", "vt_lookup", {"ioc_value": "1.2.3.4"})
                        return _StubResp(_StubMsg(content=None, tool_calls=[tc]))
                    return _StubResp(_StubMsg(content="確認しました。", tool_calls=None))
            completions = _Completions()
        self.chat = _Chat()

with tempfile.TemporaryDirectory(dir=TEST_WORKDIR) as tmpd:
    log_path = Path(tmpd) / "chat_tool_log.jsonl"
    messages = [{"role": "system", "content": "test"}, {"role": "user", "content": "1.2.3.4をVT照会して"}]
    stub2 = _StubClientLv2Attempt()
    result2 = ct.run_chat_turn(stub2, "dummy-model", messages, ctx,
                               lv2_enabled=False, tool_log_path=log_path)
    tool_msg = [m for m in messages if m["role"] == "tool"][0]
    check("run_chat_turn: lv2_enabled=Falseでvt_lookup呼び出し試行 → 無効化エラーを返す",
          "無効" in tool_msg["content"], f"content={tool_msg['content']}")

# ════════════════════════════════════════════════════════════
sec("実運用バグの再現・修正確認: run_dirが1階層深いケース（環境指定実データ）")
# run_analysis.py の run() は output_dir 直下ではなく
# output_dir/{hostname}_{datestamp}/ という1階層深い場所に
# analyzed_*.json 等を書き出す。存在しないホスト固定パスには依存せず、
# CHECKPC_TEST_NESTED_HOSTで指定した実データを本番相当構造へコピーする。
NESTED_HOST_NAME = os.environ.get(
    "CHECKPC_TEST_NESTED_HOST", "HOST-REF-11_2026010101010100"
)
NESTED_HOST_DIR = REALDATA_ROOT / NESTED_HOST_NAME
outer_container = TEST_WORKDIR / "nested_outer"
nested_parent = TEST_WORKDIR / "nested_parent"
shutil.rmtree(outer_container, ignore_errors=True)
shutil.rmtree(nested_parent, ignore_errors=True)
outer_container.mkdir(parents=True, exist_ok=True)
nested_parent.mkdir(parents=True, exist_ok=True)
nested_dir = outer_container / NESTED_HOST_NAME
nested_dir.mkdir(parents=True, exist_ok=True)
# rglobはデフォルトでシンボリックリンク先を辿らないため、実ファイルをコピーする
# （parsed_*.json はCheckPC生データで大きいため対象外。analyzed/correlation/
# report(timeline)のみで十分）
for pattern in ("analyzed_*.json", "correlation_*.json", "report_*_timeline.md"):
    for f in Path(NESTED_HOST_DIR).glob(pattern):
        (nested_dir / f.name).write_text(f.read_text(encoding="utf-8"), encoding="utf-8")

ctx_nested = ct.ChatContext(outer_container, nested_parent, vt_key="")
r = ctx_nested.tool_get_section("directory")
check("修正後: 外側コンテナを渡しても再帰探索でanalyzed_*.jsonを発見できる",
      "error" not in r or "entries" in r, f"r={str(r)[:200]}")

r2 = ctx_nested.tool_list_high_medium()
check("修正後: list_high_mediumも1階層深い実データに対して正常動作する",
      "count" in r2 and r2["count"] >= 0, f"r2={str(r2)[:200]}")

r3 = ctx_nested.tool_get_timeline()
check("修正後: get_timelineも1階層深いタイムラインファイルを発見できる",
      "timeline_md" in r3, f"r3のキー={list(r3.keys())}")

# ════════════════════════════════════════════════════════════
sec("実運用バグの再現・修正確認: identifierに無くiocsにのみ存在するキーワード検索")
# 実運用で発覚: defender_quarantineの identifier は脅威名（例:
# "Trojan:Win32/Ravartar!rfn"）であり、実際のファイルパス（wangmeng.dll等）は
# iocs フィールドにしか無い。従来の get_entry_detail は identifier のみを
# 検索していたため「wangmeng」で検索しても見つからず、LLMが何度も
# 空振りの試行を繰り返し、応答の遅延・コンテキスト肥大化・回答精度低下の
# 三重の悪影響につながっていた。

r4 = ctx_nested.tool_get_entry_detail("defender_quarantine", "wangmeng")
check("修正後: get_entry_detailでもiocs内のwangmengを発見できる（従来はidentifierのみで失敗していた）",
      "matches" in r4 and len(r4["matches"]) >= 1, f"r4={str(r4)[:300]}")

r5 = ctx_nested.tool_search_keyword("wangmeng")
check("修正後: search_keywordで全セクション横断でもwangmengを発見できる",
      r5["count"] >= 1 and any("wangmeng" in str(h.get("iocs")) for h in r5["hits"]),
      f"r5={str(r5)[:300]}")
check("search_keyword: ヒットしたセクションはdefender_quarantine",
      all(h["section"] == "defender_quarantine" for h in r5["hits"]), f"hits={r5['hits']}")

r6 = ctx_nested.tool_search_keyword("該当しない架空キーワードxyz123")
check("search_keyword: 該当なしの場合はcount=0とnoteを返す（エラーにしない）",
      r6["count"] == 0 and "note" in r6, f"r6={r6}")

# ════════════════════════════════════════════════════════════
sec("コンテキスト長超過対策: compact_history（完了済みターンのtool往復を圧縮）")
sample_history = [
    {"role": "system", "content": "システムプロンプト"},
    {"role": "user", "content": "1問目"},
    {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "type": "function",
     "function": {"name": "get_section", "arguments": "{}"}}]},
    {"role": "tool", "tool_call_id": "c1", "name": "get_section", "content": "巨大なJSON結果" * 100},
    {"role": "assistant", "content": "1問目への最終回答です"},
    {"role": "user", "content": "2問目"},
    {"role": "assistant", "content": "2問目への最終回答です（tool不使用）"},
]
compacted = ct.compact_history(sample_history)
check("compact_history: tool_calls付きassistantが除去される",
      not any(m.get("role") == "assistant" and m.get("tool_calls") for m in compacted))
check("compact_history: role=toolのメッセージが除去される",
      not any(m.get("role") == "tool" for m in compacted))
check("compact_history: system/user/最終assistant応答は保持される（7件→5件）",
      len(compacted) == 5, f"compacted={compacted}")
check("compact_history: 会話の順序・内容は保持される",
      [m["content"] for m in compacted] ==
      ["システムプロンプト", "1問目", "1問目への最終回答です", "2問目", "2問目への最終回答です（tool不使用）"])

# 空リスト・system無しでも壊れないことを確認
check("compact_history: 空リストでもエラーにならない", ct.compact_history([]) == [])

# ── サニタイズ関数の検証 ─────────────────────────────────────
sec("応答文の特殊トークン除去（<|im_end|>混入対策）")
check("末尾の<|im_end|>が除去される",
      ct._sanitize_reply("こんにちは<|im_end|>") == "こんにちは")
check("文中の<|im_start|>等も除去される",
      ct._sanitize_reply("A<|im_start|>B<|im_end|>C") == "ABC")
check("特殊トークンがない通常文はそのまま", ct._sanitize_reply("通常の応答文") == "通常の応答文")
check("空文字列はそのまま", ct._sanitize_reply("") == "")

# ════════════════════════════════════════════════════════════
sec("反復・自問自答対策: サンプリングパラメータが実際に渡される")
# GGUF量子化＋vLLMの組み合わせで報告されている反復・自問自答の
# 既知の不安定性（vLLM公式Issue #10600等）に対する緩和策として、
# temperature/repetition_penaltyを明示的に渡すようにした。
# 実際にclient.chat.completions.create()へ渡っていることを確認する。

class _RecordingCompletions:
    def __init__(self):
        self.received_kwargs = None
    def create(self, model, messages, **kwargs):
        self.received_kwargs = kwargs
        return _StubResp(_StubMsg(content="回答します。", tool_calls=None))

class _RecordingClient:
    def __init__(self, base_url=None, api_key=None):
        self.completions_obj = _RecordingCompletions()
        self.chat = type("C", (), {"completions": self.completions_obj})()

rec_client = _RecordingClient()
with tempfile.TemporaryDirectory(dir=TEST_WORKDIR) as tmpd:
    log_path = Path(tmpd) / "chat_tool_log.jsonl"
    messages = [{"role": "system", "content": "test"}, {"role": "user", "content": "こんにちは"}]
    ct.run_chat_turn(rec_client, "dummy-model", messages, ctx, lv2_enabled=False, tool_log_path=log_path)
    kw = rec_client.completions_obj.received_kwargs
    check("temperatureがCHAT_TEMPERATURE(既定0.3)で渡される",
          kw.get("temperature") == ct.CHAT_TEMPERATURE, f"kwargs={kw}")
    check("repetition_penaltyがextra_body経由でCHAT_REPETITION_PENALTY(既定1.15)として渡される",
          kw.get("extra_body", {}).get("repetition_penalty") == ct.CHAT_REPETITION_PENALTY,
          f"kwargs={kw}")


# ════════════════════════════════════════════════════════════
sec("ターン内コンテキスト予算超過の安全弁（Error Code 400再発防止）")
# 実運用で発覚: compact_historyはターンをまたいだ蓄積は防げるが、
# 1ターン内で複数回の大きなツール結果が積み重なるケース（例:
# search_keywordで見つからず何度も別の切り口を試す）には対応できず、
# vLLMのmax_model_lenを実際に超過する事象が再発した。
# _estimate_context_charsによる予算チェックが機能することを検証する。

check("_estimate_context_chars: メッセージ・ツールスキーマのサイズを合算する",
      ct._estimate_context_chars(
          [{"role": "user", "content": "a" * 100}], []) > 100)

class _StubBigToolResp:
    """毎回get_sectionを呼び続け、大きな結果を返し続けるLLMを模擬
    （予算超過に達するまでツール呼び出しを繰り返すシナリオ）"""
    def __init__(self):
        self.call_count = 0
    def create(self, model, messages, tools=None, tool_choice=None, **kwargs):
        self.call_count += 1
        if tools:  # tools付き呼び出し = 通常ラウンド
            tc = _StubToolCall(f"c{self.call_count}", "get_section", {"section": "directory"})
            return _StubResp(_StubMsg(content=None, tool_calls=[tc]))
        else:  # tools無し = 予算超過後の最終ラップアップ呼び出し
            return _StubResp(_StubMsg(content="ここまでの情報で回答します。", tool_calls=None))

class _StubBigToolClient:
    def __init__(self, base_url=None, api_key=None):
        self.completions_obj = _StubBigToolResp()
        self.chat = type("C", (), {"completions": self.completions_obj})()

# 予算を意図的に小さく設定し、数ラウンドで超過するようにして検証する
_orig_budget = ct.CHAT_CONTEXT_CHAR_BUDGET
ct.CHAT_CONTEXT_CHAR_BUDGET = 2000
try:
    with tempfile.TemporaryDirectory(dir=TEST_WORKDIR) as tmpd:
        log_path = Path(tmpd) / "chat_tool_log.jsonl"
        messages = [{"role": "system", "content": "s" * 500},
                    {"role": "user", "content": "巨大セクションを何度も見て調べて"}]
        stub_big = _StubBigToolClient()
        result = ct.run_chat_turn(stub_big, "dummy-model", messages, ctx,
                                   lv2_enabled=False, mode="detailed",
                                   tool_log_path=log_path)
        check("予算超過時: context_budget_exceeded=Trueが記録される",
              result["timing"]["context_budget_exceeded"] is True, f"timing={result['timing']}")
        check("予算超過時: 無限にツール呼び出しを続けず、途中で打ち切って最終回答を返す",
              result["reply"] == "ここまでの情報で回答します。", f"reply={result['reply']}")
        check("予算超過時: detailedモード上限を使い切る前に打ち切られる",
              stub_big.completions_obj.call_count < ct.CHAT_MODE_MAX_ITERATIONS["detailed"], f"call_count={stub_big.completions_obj.call_count}")
finally:
    ct.CHAT_CONTEXT_CHAR_BUDGET = _orig_budget


print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
