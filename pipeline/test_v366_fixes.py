# -*- coding: utf-8 -*-
"""v3.66 の回帰テスト。

対象:
  · 提案10: reason-score矛盾フロア（悪性言及×CLEAN/LOW → MEDIUM。
    HOST-REF-11裁定で実観測した queniudns 型の封鎖。否定形は不発）
  · 提案11: LEAN 既定ON（採用判定）＋ 環境変数=0 での復帰
  · lean のパラメータ化（run→analyze→call_llm_chunked。並行ジョブで
    モード混在しても安全な引数渡し方式）
  · server GUI: LEANトグル（/analyze の lean Form・ジョブ保存・UI要素）
"""
import sys, os, re, json, importlib.util, subprocess

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
a = _mod("analyze_section")

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: print(f"  [OK]  {name}"); PASS += 1
    else: print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1
def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

def one(section, score, ident, reason):
    r = {"entries": [{"identifier": ident, "score": score,
                      "reason": reason, "iocs": [ident], "mitre": []}]}
    a._apply_post_filter(section, r)
    return r["entries"][0]

# ════════════════════════════════════════════════════════════
sec("C1: reason-score矛盾フロア（提案10）")
e = one("dns_cache", "LOW", "vipns4.queniudns.com",
        "ドメイン名が不審。malware関連ドメイン。")
check("C1: queniudns型（malware言及×LOW）→ MEDIUM（実観測ケースの封鎖）",
      e["score"] == "MEDIUM", str(e))
check("C1: 注記に矛盾の説明・元reason保持",
      "スコアと矛盾" in e["reason"] and e["reason"].startswith("ドメイン名が不審"),
      e["reason"])
check("C1: 監査用 _floor=reason_contradiction",
      e.get("_floor") == "reason_contradiction")
check("C1: マルウェア（和語）×CLEAN → MEDIUM",
      one("directory", "CLEAN", r"C:\x.exe", "マルウェアの配置場所として既知")["score"]
      == "MEDIUM")
check("C1: C2言及×LOW → MEDIUM",
      one("netstat", "LOW", "1.2.3.4:443 → 5.6.7.8:443", "C2通信の特徴に類似")["score"]
      == "MEDIUM")
# 否定形は不発（誤発動防止）
for reason in ("malware関連ではない", "マルウェアの兆候なし", "悪性の根拠なし",
               "C2の可能性は低い", "マルウェアは検出されなかった",
               "悪性とは考えにくい", "malwareに該当しない"):
    check(f"C1: 否定形不発『{reason}』",
          one("dns_cache", "LOW", "x.com", reason)["score"] == "LOW", reason)
check("C1: 悪性語を含まない通常reasonは不変",
      one("dns_cache", "LOW", "y.com", "用途不明のドメイン")["score"] == "LOW")
check("C1: HIGH/MEDIUM は対象外",
      one("dns_cache", "HIGH", "c2.evil", "malware関連")["score"] == "HIGH"
      and one("dns_cache", "MEDIUM", "z.com", "malware関連")["score"] == "MEDIUM")
# 冪等性
r = {"entries": [{"identifier": "q.com", "score": "LOW",
                  "reason": "malware関連ドメイン", "iocs": []}]}
a._apply_post_filter("dns_cache", r); a._apply_post_filter("dns_cache", r)
check("C1: 冪等（矛盾注記は1回のみ）",
      r["entries"][0]["reason"].count("スコアと矛盾") == 1)
# 可視性フロア(CLEAN→LOW)との複合: dns CLEAN×悪性言及 → LOW床上げ後さらにMEDIUMへ
e2 = one("dns_cache", "CLEAN", "bad.example", "malware配布に使われるドメイン")
check("C1: dns可視性フロアと複合昇格（CLEAN→LOW→MEDIUM）",
      e2["score"] == "MEDIUM", str(e2))
# 全セクション対象（ps_history等の自由文セクションでも動く）
check("C1: 自由文セクション(ps_history)でも矛盾フロアが効く",
      one("ps_history", "LOW", "cmd1", "難読化されたmalwareローダの可能性")["score"]
      == "MEDIUM")

# ════════════════════════════════════════════════════════════
sec("C2: LEAN既定ON（提案11）と環境変数復帰")
check("C2: モジュール既定値=1（3ホスト裁定に基づく採用）", a.LEAN_OUTPUT == 1,
      str(a.LEAN_OUTPUT))
_r = subprocess.run([sys.executable, "-c",
                     "import importlib.util;"
                     f"s=importlib.util.spec_from_file_location('a','{SCRIPTS}/analyze_section.py');"
                     "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                     "print(m.LEAN_OUTPUT)"],
                    capture_output=True, text=True,
                    env={**os.environ, "CHECKPC_LEAN_OUTPUT": "0"})
check("C2: CHECKPC_LEAN_OUTPUT=0 で従来動作へ復帰可能", _r.stdout.strip() == "0")

# ════════════════════════════════════════════════════════════
sec("C3: lean パラメータの伝播（引数 > モジュール既定）")
class _Cli:
    calls = []
    class chat:
        class completions:
            @staticmethod
            def create(**kw):
                user = [m for m in kw["messages"] if m["role"] == "user"][0]["content"]
                _Cli.calls.append(user)
                idxs = [int(m) for m in re.findall(r"^\[#(\d+)\]", user, re.M)]
                class _O: pass
                m2 = _O(); m2.content = json.dumps({"section": "directory", "entries": [
                    {"source_index": i, "identifier": f"e{i}", "score": "CLEAN",
                     "reason": "ok", "mitre": [], "iocs": []} for i in idxs]},
                    ensure_ascii=False)
                c = _O(); c.message = m2
                rr = _O(); rr.choices = [c]
                return rr
ents = [{"path": f"C:\\t\\f{i}.exe", "name": f"f{i}.exe", "dir": "C:\\t",
         "date": "2026/01/01  00:00", "size": "1"} for i in range(2)]
_Cli.calls = []
a.call_llm_chunked(_Cli, "dummy", "directory", 2, ents, lean=False)
check("C3: lean=False 明示でFULLプロンプト（既定ONでも上書きされる）",
      "一字一句" in _Cli.calls[0])
_Cli.calls = []
a.call_llm_chunked(_Cli, "dummy", "directory", 2, ents, lean=True)
check("C3: lean=True 明示でLEANプロンプト", "省力化ルール" in _Cli.calls[0])
_Cli.calls = []
a.call_llm_chunked(_Cli, "dummy", "directory", 2, ents)   # None=既定(1)
check("C3: 未指定はモジュール既定(LEAN)に従う", "省力化ルール" in _Cli.calls[0])
import inspect
check("C3: run() が lean を受け取る（server→run→analyze 配線）",
      "lean" in inspect.signature(_mod("run_analysis").run).parameters)

# ════════════════════════════════════════════════════════════
sec("C4: server GUI トグル")
client = None
try:
    from fastapi.testclient import TestClient
    sv = _mod("server")
    sv._run_job = lambda *args, **kw: None   # 実解析は起動しない
    client = TestClient(sv.app)
except Exception as ex:
    print(f"  [SKIP] serverテスト環境が未整備のためスキップ: {ex}")
if client:
    html = client.get("/").text
    check("C4: GUIにLEANトグル(leanToggle)がある", 'id="leanToggle"' in html)
    check("C4: トグルは既定チェック（LEAN）", 'id="leanToggle" checked' in html)
    check("C4: 送信JSが lean を FormData に含める",
          'fd.append("lean"' in html)
    check("C4: ジョブ一覧に FULL/LEAN バッジ",
          "j.lean === false" in html)
    res = client.post("/analyze",
                      files={"file": ("t.cab", b"dummy")},
                      data={"depth": "1", "lean": "0"})
    check("C4: /analyze が lean=0 を受理", res.status_code == 200, str(res.status_code))
    jid = res.json().get("job_id")
    check("C4: ジョブに lean=False が保存される",
          sv._jobs.get(jid, {}).get("lean") is False, str(sv._jobs.get(jid, {}).get("lean")))
    res2 = client.post("/analyze",
                       files={"file": ("t2.cab", b"dummy")},
                       data={"depth": "1"})
    jid2 = res2.json().get("job_id")
    check("C4: lean未指定の既定はLEAN(True)",
          sv._jobs.get(jid2, {}).get("lean") is True)

print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
