# -*- coding: utf-8 -*-
"""v3.68-rc2: critical end-to-end integration regressions."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import analyze_section as a
import compare_analyzed as cmp
import correlate as corr

PASS = FAIL = 0

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}"); PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1

def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

class StubClient:
    def __init__(self, responder=None):
        self.calls = []
        self.responder = responder or self._normal
        outer = self
        class Obj: pass
        class Completions:
            @staticmethod
            def create(**kw):
                outer.calls.append(kw)
                text = outer.responder(kw)
                msg = Obj(); msg.content = text
                choice = Obj(); choice.message = msg; choice.finish_reason = "stop"
                usage = Obj(); usage.completion_tokens = 100; usage.prompt_tokens = 200
                resp = Obj(); resp.choices = [choice]; resp.usage = usage
                resp.system_fingerprint = "stub"
                return resp
        class Chat: pass
        self.chat = Chat(); self.chat.completions = Completions()
    @staticmethod
    def _normal(kw):
        user = [m["content"] for m in kw["messages"] if m["role"] == "user"][0]
        entries = []
        for line in user.splitlines():
            m = re.match(r"^\[#(\d+)\]\[source_id=([^\]]*)\]\s+(.*)$", line)
            if not m:
                continue
            body = m.group(3)
            path = re.search(r"([A-Za-z]:\\.*?)(?:\s+\[|$)", body)
            entries.append({"source_index": int(m.group(1)), "source_id": m.group(2),
                            "identifier": path.group(1) if path else body,
                            "score":"CLEAN", "reason":"ok", "mitre":[], "iocs":[]})
        return json.dumps({"section":"x", "entries":entries})

sec("I1: depth2 selection is connected to analyze()")
raw = [{"path": fr"C:\\Users\\u\\AppData\\Roaming\\tool{i}.exe",
        "name": f"tool{i}.exe", "datetime": "2026-01-01T00:00:00"}
       for i in range(300)]
cli = StubClient()
out = a.analyze({"meta":{"hostname":"T"},
                 "sections":{"appcompat_cache":raw}, "event_logs":{}},
                2, cli, "stub", target_sections=["appcompat_cache"], lean=True)
sr = out["sections"]["appcompat_cache"]
st = sr.get("_selection_stats", {})
check("I1: selection stats recorded", bool(st), str(sr.keys()))
check("I1: not all 300 entries selected", 0 < st.get("selected", 0) < 300, str(st))
check("I1: deferred entries tracked", st.get("deferred_by_policy", 0) > 0, str(st))
check("I1: provenance ranges recorded", bool(sr.get("_provenance", {}).get("deferred_ranges")))
check("I1: actual LLM prompts contain fewer than 300 source rows",
      sum(len(re.findall(r"^\[#", [m["content"] for m in c["messages"] if m["role"]=="user"][0], re.M))
          for c in cli.calls) == st.get("selected"), f"calls={len(cli.calls)} stats={st}")

sec("I2: Defender depth2 is rule based and never calls LLM")
cli2 = StubClient()
defraw = [{"threat_name":"Trojan:Win32/Test.A", "path":r"C:\\Temp\\x.exe",
           "datetime":"2026-01-01T00:00:00Z", "source":"defender_eventlog"}]
out2 = a.analyze({"meta":{"hostname":"T"},
                  "sections":{"defender_quarantine":defraw}, "event_logs":{}},
                 2, cli2, "stub", target_sections=["defender_quarantine"])
check("I2: no LLM call", len(cli2.calls) == 0, str(len(cli2.calls)))
check("I2: deterministic HIGH retained",
      out2["sections"]["defender_quarantine"]["entries"][0]["score"] == "HIGH")
check("I2: deterministic provenance recorded",
      out2["sections"]["defender_quarantine"]["_selection_stats"]["deterministic"] == 1)

sec("I3: ChunkSpec max_tokens/truncation/unevaluable survive to transport")
entry = {"command":"A"*5000 + "-END"}
spec = a.ChunkSpec([entry], [77], max_tokens=320, truncate=True,
                   truncations=[{"field":"command","orig_chars":5004,"sent_chars":1200}])
cli3 = StubClient()
res, _, errs, tim = a.call_llm_chunked(cli3, "stub", "ps_history", 2, [entry],
                                       chunk_plan={"specs":[spec]}, lean=False)
check("I3: requested max_tokens is spec value", cli3.calls[0]["max_tokens"] == 320)
user3 = [m["content"] for m in cli3.calls[0]["messages"] if m["role"]=="user"][0]
check("I3: truncated view sent", "文字省略" in user3 and "-END" in user3)
check("I3: original entry unchanged", len(entry["command"]) == 5004)
cli3b = StubClient()
uspec = a.ChunkSpec([entry], [77], max_tokens=256, unevaluable=True, reason="too large")
_, _, errs_u, _ = a.call_llm_chunked(cli3b, "stub", "ps_history", 2, [entry],
                                     chunk_plan={"specs":[uspec]})
check("I3: unevaluable does not call API", len(cli3b.calls) == 0)
check("I3: unevaluable is explicit", errs_u and errs_u[0].get("selected_unevaluated") is True)

sec("I4: coverage queue recursively reaches singleton")
def missing_si(kw):
    user = [m["content"] for m in kw["messages"] if m["role"] == "user"][0]
    rows = []
    for line in user.splitlines():
        m = re.match(r"^\[#(\d+)\]\[source_id=[^\]]*\]\s+(.*)$", line)
        if not m:
            continue
        path = re.search(r"([A-Za-z]:\\.*)$", m.group(2))
        rows.append({"identifier": path.group(1) if path else m.group(2),
                     "score":"CLEAN", "reason":"ok", "mitre":[], "iocs":[]})
    return json.dumps({"section":"directory", "entries":rows})
cli4 = StubClient(missing_si)
entries4 = [{"path":fr"C:\\Users\\Public\\f{i}.exe", "name":f"f{i}.exe"} for i in range(8)]
# 動的予算では directory の通常チャンクは7件になるため、
# 8→4→2→1 の再帰分割自体を検証するここでは明示 ChunkSpec を渡す。
spec4 = a.ChunkSpec(entries4, source_indices=list(range(8)), max_tokens=2048)
res4, _, errs4, _ = a.call_llm_chunked(
    cli4, "stub", "directory", 2, entries4,
    chunk_plan={"specs": [spec4], "max_tokens": 2048},
)
sizes = [len(re.findall(r"^\[#", [m["content"] for m in c["messages"] if m["role"]=="user"][0], re.M))
         for c in cli4.calls]
check("I4: all 8 recovered", len(res4) == 8 and not errs4, f"res={len(res4)} errs={errs4}")
check("I4: split sequence includes 8,4,2,1", all(x in sizes for x in (8,4,2,1)), str(sizes))

sec("I5: correlate final text itself respects budget")
big = {"sections":{"directory":{"section_summary":"s", "entries":[
    {"identifier":f"h{i}", "score":"HIGH", "reason":"same reason " + "x"*80,
     "iocs":[], "mitre":[]} for i in range(40)]}}}
text5, stats5 = corr.build_correlate_text(corr.extract_high_medium(big), 2, 200)
check("I5: final estimated tokens <= budget", corr.est_tokens(text5) <= 200,
      f"{corr.est_tokens(text5)}")
check("I5: no HIGH source unrepresented", stats5["high_unrepresented"] == 0, str(stats5))

sec("I6: duplicate-key minority HIGH disappearance is fatal")
def doc(scores):
    return {"sections":{"x":{"entries":[
        {"identifier":"same", "datetime":"", "iocs":[], "score":s, "reason":s}
        for s in scores]}}}
fatal, adj, _ = cmp.compare(doc(["HIGH"]+["CLEAN"]*9), doc(["CLEAN"]*10), False)
check("I6: HIGH disappearance detected", any(x[0] == "HIGH→LOW/CLEAN" or x[0] == "既存HIGH消失" for x in fatal), str(fatal))

sec("I7: SVG/package and direct CLI depth gates")
svg = HERE / "system_concept.svg"
svg_text = svg.read_text(encoding="utf-8") if svg.exists() else ""
check("I7: SVG restored", svg.exists() and svg.stat().st_size > 1000
      and "archive worker" in svg_text and "検証用ZIP" in svg_text
      and "全成果物ZIP" in svg_text)
for script in ("analyze_section.py", "correlate.py"):
    r = subprocess.run([sys.executable, str(HERE/script), "dummy.json", "--depth", "3"],
                       capture_output=True, text=True)
    check(f"I7: {script} rejects depth3 without flag", r.returncode == 2 and "experimental-depths" in r.stderr,
          f"rc={r.returncode} err={r.stderr[:100]}")

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
