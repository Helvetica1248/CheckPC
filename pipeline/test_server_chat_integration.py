# -*- coding: utf-8 -*-
"""server.py integration tests isolated from cabextract/vLLM/background workers."""
import importlib.util
import io
import os
import sys
import tempfile
from pathlib import Path
import types
import json
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
for _c in (os.environ.get("CHECKPC_SCRIPTS", ""), HERE,
           os.path.dirname(HERE), "/opt/llm/analysis"):
    if _c and os.path.exists(os.path.join(_c, "server.py")):
        SCRIPTS = _c
        break
else:
    print("server.py が見つかりません"); raise SystemExit(2)
sys.path.insert(0, SCRIPTS)

PASS = FAIL = 0

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}"); PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1

def sec(t):
    print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

try:
    from fastapi.testclient import TestClient
except Exception as e:
    print(f"  [SKIP] fastapi.testclient unavailable: {e}")
    print("PASS=0 FAIL=0")
    raise SystemExit(0)

# No external OpenAI package is required for this integration test.
if "openai" not in sys.modules:
    m = types.ModuleType("openai")
    class DummyOpenAI:
        def __init__(self, *a, **kw): pass
    m.OpenAI = DummyOpenAI
    sys.modules["openai"] = m

_tmp = tempfile.TemporaryDirectory(prefix="checkpc_server_test_")
os.environ["PIPELINE_JOBS_DIR"] = _tmp.name
os.environ.pop("PIPELINE_API_KEY", None)
os.environ["CHAT_LV2_LOCAL_ENABLED"] = "1"
os.environ["CHAT_LV2_VT_IOC_ENABLED"] = "1"
os.environ["CHAT_LV2_DEFAULT_POLICY"] = "off"
os.environ["CHAT_MODEL"] = "dummy-model"

spec = importlib.util.spec_from_file_location("server_test_instance", os.path.join(SCRIPTS, "server.py"))
srv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(srv)
import chat_tools as ct

class DummyFuture:
    def cancel(self): return True
    def done(self): return False

class DummyExecutor:
    def __init__(self): self.calls = []
    def submit(self, fn, *args, **kwargs):
        self.calls.append((fn, args, kwargs))
        return DummyFuture()
    def shutdown(self, *args, **kwargs): pass

try:
    srv._executor.shutdown(wait=False, cancel_futures=True)
except Exception:
    pass
srv._executor = DummyExecutor()
srv._jobs.clear()
srv._cancel_events.clear()
client = TestClient(srv.app)

sec("S1: basic endpoints")
r = client.get("/")
check("GET / is 200", r.status_code == 200, str(r.status_code))
check("GUI depth range 1-2", 'min="1" max="2"' in r.text)
r = client.get("/chatconfig")
check("GET /chatconfig is 200", r.status_code == 200)
check("chatconfig has lv2_enabled", "lv2_enabled" in r.json())

sec("S2: depth validation without starting real jobs")
def post_depth(d):
    return client.post("/analyze",
        files={"file": ("t.cab", io.BytesIO(b"x"), "application/octet-stream")},
        data={"depth": str(d), "lean": "1"})
r1, r2, r3, r4 = [post_depth(x) for x in (1,2,3,4)]
check("depth1 accepted", r1.status_code == 200, str(r1.status_code))
check("depth2 accepted", r2.status_code == 200, str(r2.status_code))
check("depth3 rejected", r3.status_code == 400, str(r3.status_code))
check("depth4 rejected", r4.status_code == 400, str(r4.status_code))
check("only two background submissions recorded", len(srv._executor.calls) == 2,
      str(len(srv._executor.calls)))

sec("S3: unknown jobs")
check("unknown status 404", client.get("/status/nope").status_code == 404)
check("unknown result 404", client.get("/result/nope").status_code == 404)
check("unknown cancel 4xx", 400 <= client.post("/jobs/nope/cancel").status_code < 500)

sec("S4: jobs and result formats")
check("GET /jobs 200", client.get("/jobs").status_code == 200)
for fmt in ("md", "timeline", "all", "pdf", "timeline_pdf"):
    check(f"unknown result {fmt} is not 500",
          client.get("/result/nope", params={"format": fmt}).status_code != 500)

sec("S5: help assets")
r = client.get("/help/system-concept.svg")
check("system concept 200", r.status_code == 200, str(r.status_code))
check("system concept content-type", "image/svg+xml" in r.headers.get("content-type", ""),
      r.headers.get("content-type", ""))

sec("S6: API key")
old = srv.API_KEY
try:
    srv.API_KEY = "secret"
    check("missing key 401", client.get("/jobs").status_code == 401)
    check("valid key 200", client.get("/jobs", headers={"X-API-Key":"secret"}).status_code == 200)
    check("invalid key 401", client.get("/jobs", headers={"X-API-Key":"bad"}).status_code == 401)
finally:
    srv.API_KEY = old

sec("S7: case policy API and effective tool config")

def write_job(jid, folder, identifier):
    run = Path(_tmp.name) / jid / "output" / "run"
    run.mkdir(parents=True, exist_ok=True)
    analyzed = {
        "meta": {
            "hostname": jid, "safe_hostname": jid,
            "pipeline_version": "3.71", "analysis_schema_version": "2.1",
            "package_manifest_sha256": "a" * 64,
            "collection_id": "c" * 64,
            "source_id_algorithm_version": "1",
            "parsed_artifact_sha256": "b" * 64,
        },
        "sections": {"netstat": {"entries": [{
            "identifier": identifier, "score": "HIGH", "reason": identifier,
            "iocs": [identifier], "source_index": 1,
        }]}}
    }
    (run / f"analyzed_{jid}_vt.json").write_text(json.dumps(analyzed), encoding="utf-8")
    (run / f"correlation_{jid}.json").write_text(json.dumps({
        "infection_suspicion": "MEDIUM", "malware_family": "unknown", "summary": "test"
    }), encoding="utf-8")
    job = {
        "job_id": jid, "filename": f"{jid}.cab", "status": "done", "folder": folder,
        "chat_lv2_policy": "off", "output_dir": str(Path(_tmp.name) / jid / "output"),
        "run_dir": str(run), "submitted_at": 1, "depth": 1, "lean": True,
    }
    srv._jobs[jid] = job
    return run

run_a = write_job("jobA", "CASE-1", "evil.example.com")
run_b = write_job("jobB", "CASE-1", "evil.example.com")
run_c = write_job("jobC", "CASE-2", "evil.example.com")
srv._save_jobs()

r = client.post("/jobs/jobA/chat-policy", json={"policy": "local"})
check("policy update 200", r.status_code == 200, r.text)
check("same folder policy propagated", srv._jobs["jobA"]["chat_lv2_policy"] == "local"
      and srv._jobs["jobB"]["chat_lv2_policy"] == "local"
      and srv._jobs["jobC"]["chat_lv2_policy"] == "off")
r = client.get("/chatconfig", params={"job_id": "jobA"})
check("job config exposes local only", r.json().get("effective_tools") == ["investigate_local"], r.text)
r = client.post("/jobs/jobA/chat-policy", json={"policy": "local_vt_ioc"})
check("local_vt_ioc exposes both tools", set(r.json().get("effective_tools", [])) ==
      {"investigate_local", "vt_ioc_lookup"}, r.text)
check("invalid policy rejected", client.post("/jobs/jobA/chat-policy", json={"policy":"all"}).status_code == 400)

sec("S8: POST chat tool loop, audit retention and reset")
class StubMsg:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls

class StubToolCall:
    def __init__(self, tc_id, name, args):
        self.id = tc_id
        self.function = type("F", (), {"name": name, "arguments": json.dumps(args)})()
    def model_dump(self):
        return {"id": self.id, "type": "function",
                "function": {"name": self.function.name, "arguments": self.function.arguments}}

class StubResp:
    def __init__(self, msg):
        self.choices = [type("C", (), {"message": msg})()]

class ChatOpenAI:
    def __init__(self, *args, **kwargs):
        self.calls = 0
        outer = self
        class Completions:
            def create(self, model, messages, tools=None, tool_choice=None, **kwargs):
                outer.calls += 1
                if tools and outer.calls == 1:
                    return StubResp(StubMsg(None, [StubToolCall(
                        "call-1", "investigate_local", {"action": "search", "query": "evil.example.com"})]))
                return StubResp(StubMsg("案件内の他ホストにも一致があります。", None))
        self.chat = type("Chat", (), {"completions": Completions()})()

srv.OpenAI = ChatOpenAI
r = client.post("/chat/jobA", json={"message":"他ホストにもある？", "mode":"standard"})
check("POST chat succeeds", r.status_code == 200, r.text)
check("chat reports investigate_local tool", r.json().get("tool_calls", [{}])[0].get("name") == "investigate_local", r.text)
audit_a = Path(_tmp.name) / "jobA" / "chat_tool_log.jsonl"
history_a = Path(_tmp.name) / "jobA" / "chat_history.json"
check("audit and history persisted", audit_a.exists() and history_a.exists())
audit_text = audit_a.read_text(encoding="utf-8")
check("audit has case/policy and no absolute paths", '"case_folder": "CASE-1"' in audit_text
      and '"lv2_policy": "local_vt_ioc"' in audit_text
      and str(Path(_tmp.name)) not in audit_text, audit_text)
r = client.delete("/chat/jobA")
check("chat reset retains audit and clears conversation ledger",
      r.status_code == 200 and r.json().get("audit_log_retained") is True
      and r.json().get("evidence_ledger_reset") is True
      and audit_a.exists() and not history_a.exists()
      and not (Path(_tmp.name)/"jobA"/"chat_cache"/"evidence_ledger_v1.json").exists(), r.text)

sec("S9: two-job chat isolation")
# Restore local policy consistently for CASE-1 and execute both jobs concurrently.
client.post("/jobs/jobA/chat-policy", json={"policy":"local"})
def ask(jid):
    return client.post(f"/chat/{jid}", json={"message":f"{jid} query", "mode":"standard"})
with ThreadPoolExecutor(max_workers=2) as ex:
    ra, rb = list(ex.map(ask, ("jobA", "jobB")))
check("two concurrent chats succeed", ra.status_code == 200 and rb.status_code == 200,
      f"A={ra.text} B={rb.text}")
ha = client.get("/chat/jobA/history").json().get("messages", [])
hb = client.get("/chat/jobB/history").json().get("messages", [])
check("histories remain job-separated", any(m.get("content") == "jobA query" for m in ha)
      and not any(m.get("content") == "jobB query" for m in ha)
      and any(m.get("content") == "jobB query" for m in hb)
      and not any(m.get("content") == "jobA query" for m in hb), f"A={ha} B={hb}")
check("audit logs remain job-separated", (Path(_tmp.name)/"jobA"/"chat_tool_log.jsonl").exists()
      and (Path(_tmp.name)/"jobB"/"chat_tool_log.jsonl").exists())

sec("S10: complete job deletion removes retained audit")
ct.clear_audit_fallback_records()
fallback_a = Path(_tmp.name) / "_audit_fallback" / "jobA" / "chat_tool_log.jsonl"
blocker = Path(_tmp.name) / "audit_blocker"
blocker.write_text("not a directory", encoding="utf-8")
ctx_a = ct.ChatContext(run_a, Path(_tmp.name), vt_key="", job_id="jobA",
                       case_folder="CASE-1", lv2_policy="local")
ct.append_audit_log(
    blocker / "chat_tool_log.jsonl", "cross_host_search", {"ioc_value": "evil.example.com"},
    {"matches": 1}, ctx=ctx_a, audit_phase="completed")
fallback_was_present = fallback_a.exists() and any(
    row.get("job_id") == "jobA" for row in ct.get_audit_fallback_records())
check("job deletion succeeds", client.delete("/jobs/jobA").status_code == 200)
check("complete deletion removes job directory/audit", not (Path(_tmp.name)/"jobA").exists())
check("complete deletion removes file and memory fallback audit",
      fallback_was_present and not fallback_a.parent.exists()
      and not any(row.get("job_id") == "jobA" for row in ct.get_audit_fallback_records()))
ct.clear_audit_fallback_records()

try:
    client.close()
except Exception:
    pass
srv._jobs.clear(); srv._cancel_events.clear(); _tmp.cleanup()
print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
