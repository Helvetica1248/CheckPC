# -*- coding: utf-8 -*-
"""Focused regression for v3.71 Threat-Intelligence chat redesign."""
import json
import hashlib
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import chat_tools as ct
import chat_investigation as ci
import directory_index as di

PASS = FAIL = 0

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}"); PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1


def sec(title):
    print(f"\n{'-'*60}\n  {title}\n{'-'*60}")


def make_job(root: Path, jid: str, folder: str, hostname: str,
             *, pipeline="3.71", schema="2.1", suspicion="MEDIUM",
             evidence="evil.example.com", raw_files=None):
    run = root / jid / "output" / f"{hostname}_run"
    run.mkdir(parents=True)
    analyzed = {
        "meta": {
            "hostname": hostname,
            "safe_hostname": hostname,
            "pipeline_version": pipeline,
            "analysis_schema_version": schema,
            "package_manifest_sha256": "a" * 64,
            "collection_id": (jid.encode().hex() + "0" * 64)[:64],
            "source_id_algorithm_version": "1",
            "parsed_artifact_sha256": "b" * 64,
        },
        "sections": {
            "netstat": {"entries": [{
                "source_index": 0,
                "source_id": f"netstat:{jid}",
                "identifier": evidence,
                "score": "HIGH",
                "reason": f"observed {evidence}",
                "iocs": [evidence],
            }]},
            "service": {"entries": [{
                "source_index": 0,
                "source_id": f"service:{jid}",
                "identifier": r"SvcX C:\ProgramData\foo.exe",
                "score": "MEDIUM",
                "reason": "service configuration",
                "iocs": [r"C:\ProgramData\foo.exe"],
            }]},
        },
    }
    correlation = {
        "meta": {"pipeline_version": pipeline, "analysis_schema_version": schema, "hostname": hostname},
        "infection_suspicion": suspicion,
        "malware_family": "TestFamily" if suspicion == "HIGH" else "UNKNOWN",
        "correlated_iocs": [evidence],
        "summary": "evidence text; not a system instruction",
    }
    parsed = {
        "meta": {
            "hostname": hostname,
            "pipeline_version": pipeline,
            "analysis_schema_version": schema,
        },
        "sections": {
            "service": [],
            "directory": raw_files or [],
        },
        "event_logs": {},
    }
    parsed_path = run / f"parsed_{hostname}.json"
    parsed_path.write_text(json.dumps(parsed, ensure_ascii=False, indent=2), encoding="utf-8")
    analyzed["meta"]["parsed_artifact_sha256"] = hashlib.sha256(parsed_path.read_bytes()).hexdigest()
    (run / f"analyzed_{hostname}.json").write_text(json.dumps(analyzed, ensure_ascii=False, indent=2), encoding="utf-8")
    (run / f"correlation_{hostname}.json").write_text(json.dumps(correlation, ensure_ascii=False, indent=2), encoding="utf-8")
    (run / f"report_{hostname}_timeline.md").write_text(
        f"2026-08-01 10:00 {evidence}\n2026-08-01 10:01 C:\\ProgramData\\foo.exe\n", encoding="utf-8")
    return run


def rewrite_parsed_and_claim(run: Path, mutator):
    parsed_path = next(run.glob("parsed_*.json"))
    doc = json.loads(parsed_path.read_text(encoding="utf-8"))
    mutator(doc)
    parsed_path.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    analyzed_path = next(run.glob("analyzed_*.json"))
    analyzed = json.loads(analyzed_path.read_text(encoding="utf-8"))
    analyzed["meta"]["parsed_artifact_sha256"] = hashlib.sha256(parsed_path.read_bytes()).hexdigest()
    analyzed_path.write_text(json.dumps(analyzed, ensure_ascii=False, indent=2), encoding="utf-8")
    return parsed_path


sec("R1: public tool surface")
off = {t["function"]["name"] for t in ct.build_tool_schema(lv2_policy="off")}
full = {t["function"]["name"] for t in ct.build_tool_schema(lv2_policy="local_vt_ioc")}
check("local surface is one tool when external TI off", off == {"investigate_local"}, str(off))
check("external TI adds only VT", full == {"investigate_local", "vt_ioc_lookup"}, str(full))
check("legacy handlers are not public", not ({"search_keyword", "cross_host_search", "get_section"} & full), str(full))

with tempfile.TemporaryDirectory(prefix="v371_chat_ti_") as td:
    root = Path(td)
    run_a = make_job(root, "jobA", "CASE-1", "HOST-A", pipeline="3.69", schema="2.0", suspicion="HIGH",
                     raw_files=[
                         {"date":"2026/08/01  10:00","size":"1610612736","name":"pagefile.sys",
                          "path":r"C:\pagefile.sys","dir":"C:","source_id":"directory:a"},
                         {"date":"2026/08/01  10:00","size":"100","name":"Shortcut.lnk",
                          "path":r"C:\Users\Public\Desktop\Shortcut.lnk","dir":r"C:\Users\Public\Desktop",
                          "source_id":"directory:b"},
                     ])
    run_b = make_job(root, "jobB", "CASE-1", "HOST-B", evidence="other.example.com", suspicion="MEDIUM")
    make_job(root, "jobC", "CASE-2", "HOST-C", evidence="evil.example.com", suspicion="HIGH")
    # Same CASE but intentionally unsupported schema: must be unavailable, not absent.
    run_d = make_job(root, "jobD", "CASE-1", "HOST-D", pipeline="3.68", schema="1.9", evidence="evil.example.com",
                     raw_files=[{"date":"2026/08/01  10:00","size":"42","name":"unknownonly.exe",
                                 "path":r"C:\Temp\unknownonly.exe","dir":r"C:\Temp","source_id":"directory:d"}])
    # parsed-only structured evidence: absent from analyzed, present only in parsed service.
    def _mutate_b(pb_doc):
        pb_doc["sections"]["service"] = [{"name":"parsedonlysvc","display_name":"Parsed Only Service",
                                            "image_path":r"C:\ProgramData\parsedonly.exe",
                                            "source_id":"service:parsed-only"}]
        pb_doc["event_logs"]["system_7045"] = [{"service_name":"EventOnly7045",
                                                   "image_path":r"C:\Temp\eventonly.exe",
                                                   "source_id":"system_7045:event-only"}]
    rewrite_parsed_and_claim(run_b, _mutate_b)
    meta = {
        "jobA": {"job_id":"jobA","folder":"CASE-1","status":"done"},
        "jobB": {"job_id":"jobB","folder":"CASE-1","status":"done"},
        "jobC": {"job_id":"jobC","folder":"CASE-2","status":"done"},
        "jobD": {"job_id":"jobD","folder":"CASE-1","status":"done"},
    }
    ctx = ct.ChatContext(run_a, root, job_id="jobA", case_folder="CASE-1", jobs_metadata=meta, lv2_policy="local")

    sec("R2: same-folder search and mixed-version accounting")
    ctx.current_user_message = "evil.example.com を案件内で調べて"
    r = ctx.tool_investigate_local("search", "evil.example.com", 20)
    check("current host match found", any(h.get("hostname") == "HOST-A" for h in r.get("current_host_hits", [])), str(r))
    check("other CASE excluded", "jobC" not in json.dumps(r, ensure_ascii=False), str(r))
    check("unsupported same-case host is unavailable", r.get("unavailable_reasons", {}).get("unsupported_schema") == 1, str(r))
    check("case/searchable denominators separated", r.get("case_host_count") == 3 and r.get("searchable_host_count") == 2, str(r))
    check("coverage incomplete is explicit", r.get("coverage_complete") is False, str(r))

    sec("R2b: folder scope metadata is not searchable evidence")
    ctx.current_user_message = "CASE-1を検索"
    rf = ctx.tool_investigate_local("search", "CASE-1", 20)
    check("folder literal does not become evidence hit", rf.get("observed_host_count") == 0, str(rf))

    sec("R2c: parsed-only structured evidence is indexed")
    ctx.current_user_message = "parsedonlysvcを調べて"
    rps = ctx.tool_investigate_local("search", "parsedonlysvc", 20)
    check("parsed-only service is found", any(h.get("origin") == "parsed_structured" and h.get("job_id") == "jobB" for h in rps.get("other_host_hits", [])), str(rps))
    check("parsed structured search is complete for supported scope subset", rps.get("core_searchable_host_count") == 2, str(rps))

    sec("R2d: parsed event_logs evidence is indexed")
    ctx.current_user_message = "EventOnly7045を調べて"
    rel = ctx.tool_investigate_local("search", "EventOnly7045", 20)
    check("event_logs-only system_7045 is found", any(h.get("origin") == "parsed_structured" and h.get("section") == "system_7045" for h in rel.get("other_host_hits", [])), str(rel))
    check("event_logs search remains coverage-aware", rel.get("core_searchable_host_count") == 2, str(rel))

    sec("R3: hostname is normal evidence, no dedicated tool")
    ctx.current_user_message = "HOST-Bについて調べて"
    rh = ctx.tool_investigate_local("search", "HOST-B", 10)
    check("hostname search finds other host", any(h.get("job_id") == "jobB" for h in rh.get("other_host_hits", [])), str(rh))

    sec("R4: directory raw beats analyzed-only limitation")
    ctx.current_user_message = "pagefile.sysのサイズは？"
    rp = ctx.tool_investigate_local("search", "pagefile.sys", 10)
    raw = [h for h in rp.get("current_host_hits", []) if h.get("origin") == "parsed_directory_raw"]
    check("pagefile raw hit returned", len(raw) == 1, str(rp))
    check("pagefile size preserved", raw and raw[0].get("size") == "1610612736", str(raw))
    ctx.current_user_message = "LNKファイルを10個"
    rl = ctx.tool_investigate_local("search", ".lnk", 10)
    check("directory streaming/index searched", rl.get("directory_raw_searchable_host_count") >= 1, str(rl))
    check("raw LNK returned", any(h.get("origin") == "parsed_directory_raw" for h in rl.get("current_host_hits", [])), str(rl))

    check("incomplete directory coverage suppresses case prevalence", rp.get("prevalence") is None and rp.get("prevalence_status") == "incomplete_coverage", str(rp))
    check("directory query denominator is query-specific", rp.get("query_searchable_host_count") == 1 and rp.get("scope_host_count") == 3, str(rp))

    sec("R4a: legacy Directory streaming is bounded")
    parsed_a = next(run_a.glob("parsed_*.json"))
    rd = di.search_keyword_streaming(parsed_a, "pagefile.sys", max_results=10,
                                     deadline_monotonic=time.monotonic() - 0.001,
                                     max_bytes_scanned=1024)
    check("expired streaming deadline reports incomplete", rd.get("complete") is False and rd.get("stop_reason") == "directory_search_timeout", str(rd))

    sec("R4b: unsupported schema cannot bypass via Directory streaming")
    ctx_d = ct.ChatContext(run_d, root, job_id="jobD", case_folder="CASE-1", jobs_metadata=meta, lv2_policy="local")
    ctx_d.current_user_message = "unknownonly.exeを調べて"
    ru = ctx_d.tool_investigate_local("search", "unknownonly.exe", 10)
    check("unsupported current host returns no raw Directory hit", ru.get("returned_count") == 0, str(ru))
    check("unsupported schema is explicit", ru.get("unavailable_reasons", {}).get("unsupported_schema", 0) >= 1, str(ru))

    sec("R4c: display limit is independent from prevalence probing")
    ctx.current_user_message = "foo.exeを検索"
    rlim = ctx.tool_investigate_local("search", "foo.exe", 1)
    check("returned_count obeys limit", rlim.get("returned_count") == 1, str(rlim))
    check("host prevalence still probes later hosts", rlim.get("observed_host_count") == 2, str(rlim))

    sec("R4d: index build honors absolute deadline")
    try:
        ci._build_index(root / "jobB", "jobB", meta["jobB"], time.monotonic() - 0.001)
        expired = False
    except ci.InvestigationDeadlineExceeded:
        expired = True
    check("expired build deadline is rejected", expired)

    sec("R5: deterministic correlation-fast case summary")
    ctx.current_user_message = "案件概要とHIGH台数"
    rs = ctx.tool_investigate_local("summary", "", 10)
    check("summary uses correlation fast path", rs.get("summary_basis") == "correlation_fast_path" and rs.get("core_index_build_attempted") is False, str(rs))
    check("observed HIGH count remains machine-readable", rs.get("observed_high_or_above_host_count") == 1, str(rs))
    check("incomplete correlation coverage suppresses case-wide HIGH count", rs.get("high_or_above_host_count") is None and rs.get("correlation_coverage_complete") is False, str(rs))
    check("summary denominator keeps unsupported host", rs.get("case_host_count") == 3 and rs.get("correlation_searchable_host_count") == 2, str(rs))
    pairs = {(x.get("pipeline_version"), x.get("analysis_schema_version")) for x in rs.get("pipeline_schema_distribution", [])}
    check("v3.69/v3.71 both supported", {("3.69","2.0"),("3.71","2.1")}.issubset(pairs), str(pairs))

    sec("R6: timeline is non-causal")
    rt = ctx.tool_investigate_local("timeline", "evil.example.com", 10)
    check("timeline hit returned", rt.get("returned_count", 0) >= 1, str(rt))
    check("timeline explicitly non-causal", rt.get("causal") is False and all(h.get("causal") is False for h in rt.get("hits", [])), str(rt))

    sec("R6b: follow-up subset does not shrink actual case count")
    ctx.current_user_message = "evil.example.comを調べて"
    _ = ctx.tool_investigate_local("search", "evil.example.com", 10)
    ctx.current_user_message = "そのホストでfoo.exeを調べて"
    rfup = ctx.tool_investigate_local("search", "foo.exe", 10)
    check("actual case count remains stable", rfup.get("case_host_count") == 3, str(rfup))
    check("follow-up subset has separate scope count", rfup.get("scope_host_count") == 1 and rfup.get("scope", {}).get("scope_basis") == "previous_result_subset", str(rfup))

    sec("R7: bounded evidence ledger")
    ledger = root / "jobA" / "chat_cache" / "evidence_ledger_v1.json"
    check("ledger persisted outside output", ledger.is_file() and "output" not in str(ledger.relative_to(root/"jobA")), str(ledger))
    rows = json.loads(ledger.read_text(encoding="utf-8"))
    check("ledger is bounded machine-readable evidence refs", isinstance(rows, list) and rows and rows[-1].get("result_id"), str(rows[-1] if rows else None))

sec("R7b: folder literal stays out of system prompt control plane")
server_src = (HERE / "server.py").read_text(encoding="utf-8")
check("scope notice does not interpolate folder literal", "same-folder" not in server_src[server_src.find("def _chat_lv2_notice"):server_src.find("def _build_chat_system_prompt")].lower() and "'{folder}'" not in server_src)

sec("R8: duplicate tool+args is dispatched once")
class StubMsg:
    def __init__(self, content=None, tool_calls=None): self.content=content; self.tool_calls=tool_calls
class StubTC:
    def __init__(self, n):
        self.id=f"c{n}"; self.function=type("F",(),{"name":"investigate_local","arguments":json.dumps({"action":"search","query":"foo.exe"})})()
    def model_dump(self): return {"id":self.id,"type":"function","function":{"name":self.function.name,"arguments":self.function.arguments}}
class StubResp:
    def __init__(self,msg): self.choices=[type("C",(),{"message":msg})()]
class StubClient:
    def __init__(self):
        self.calls=0; outer=self
        class C:
            def create(self, **kwargs):
                outer.calls += 1
                if outer.calls == 1: return StubResp(StubMsg(None,[StubTC(1)]))
                if outer.calls == 2: return StubResp(StubMsg(None,[StubTC(2)]))
                return StubResp(StubMsg("done",None))
        self.chat=type("Chat",(),{"completions":C()})()

with tempfile.TemporaryDirectory() as td:
    ctx = ct.ChatContext(td, td, job_id="jobA", jobs_metadata={"jobA":{"job_id":"jobA","folder":"","status":"done"}})
    original = ct.dispatch_tool_call
    dispatched=[]
    try:
        ct.dispatch_tool_call=lambda _ctx,name,args: (dispatched.append((name,args)) or {"ok":True})
        rr=ct.run_chat_turn(StubClient(),"stub",[{"role":"system","content":"x"},{"role":"user","content":"foo"}],ctx)
        check("duplicate call did not dispatch twice", len(dispatched) == 1, str(dispatched))
        check("turn still reaches final answer", rr.get("reply") == "done", str(rr))
    finally:
        ct.dispatch_tool_call=original

sec("R9: fabricated legacy tool name is not dispatched")
class LegacyTC:
    def __init__(self):
        self.id="legacy1"
        self.function=type("F",(),{"name":"cross_host_search","arguments":json.dumps({"ioc_value":"evil.example.com"})})()
    def model_dump(self): return {"id":self.id,"type":"function","function":{"name":self.function.name,"arguments":self.function.arguments}}
class LegacyClient:
    def __init__(self):
        self.calls=0; outer=self
        class C:
            def create(self, **kwargs):
                outer.calls += 1
                if outer.calls == 1: return StubResp(StubMsg(None,[LegacyTC()]))
                return StubResp(StubMsg("legacy blocked",None))
        self.chat=type("Chat",(),{"completions":C()})()
with tempfile.TemporaryDirectory() as td:
    ctx = ct.ChatContext(td, td, job_id="jobA", jobs_metadata={"jobA":{"job_id":"jobA","folder":"","status":"done"}})
    original = ct.dispatch_tool_call
    dispatched=[]
    try:
        ct.dispatch_tool_call=lambda _ctx,name,args: (dispatched.append((name,args)) or {"ok":True})
        rr=ct.run_chat_turn(LegacyClient(),"stub",[{"role":"system","content":"x"},{"role":"user","content":"x"}],ctx)
        check("legacy public-name fabrication does not dispatch", dispatched == [], str(dispatched))
        check("legacy-blocked turn reaches final answer", rr.get("reply") == "legacy blocked", str(rr))
    finally:
        ct.dispatch_tool_call=original


sec("R10: bounded scalar truncation never claims complete coverage")
with tempfile.TemporaryDirectory(prefix="v371_rc3_trunc_") as td:
    root = Path(td)
    run = make_job(root, "jobT", "CASE-T", "HOST-T")
    def _many(doc):
        rec = {f"field_{i:03d}": f"value{i}" for i in range(1, 97)}
        rec["field_097"] = "TARGET97"
        doc["sections"]["service"] = [rec]
    rewrite_parsed_and_claim(run, _many)
    meta_t={"jobT":{"job_id":"jobT","folder":"CASE-T","status":"done"}}
    ctx_t=ct.ChatContext(run, root, job_id="jobT", case_folder="CASE-T", jobs_metadata=meta_t, lv2_policy="local")
    ctx_t.current_user_message="TARGET97"
    rr=ctx_t.tool_investigate_local("search","TARGET97",10)
    check("97th scalar is not silently treated as absent", rr.get("coverage_complete") is False and rr.get("prevalence") is None, str(rr))
    check("scalar-count truncation is machine-readable", rr.get("core_partial_reasons",{}).get("core_evidence_truncated",0) == 1, str(rr))

with tempfile.TemporaryDirectory(prefix="v371_rc3_long_") as td:
    root = Path(td)
    run = make_job(root, "jobL", "CASE-L", "HOST-L")
    def _long(doc):
        doc["sections"]["service"] = [{"command_line":"A" * 4096 + "LONGTARGET"}]
    rewrite_parsed_and_claim(run, _long)
    meta_l={"jobL":{"job_id":"jobL","folder":"CASE-L","status":"done"}}
    ctx_l=ct.ChatContext(run, root, job_id="jobL", case_folder="CASE-L", jobs_metadata=meta_l, lv2_policy="local")
    ctx_l.current_user_message="LONGTARGET"
    rr=ctx_l.tool_investigate_local("search","LONGTARGET",10)
    check("oversized scalar omission makes coverage incomplete", rr.get("coverage_complete") is False and rr.get("prevalence") is None, str(rr))

sec("R11: formal artifact schema pairs must agree")
with tempfile.TemporaryDirectory(prefix="v371_rc3_corr_") as td:
    root=Path(td)
    run=make_job(root,"jobM","CASE-M","HOST-M")
    cp=next(run.glob("correlation_*.json"))
    corr=json.loads(cp.read_text(encoding="utf-8"))
    corr["meta"]["pipeline_version"]="3.69"; corr["meta"]["analysis_schema_version"]="2.0"
    cp.write_text(json.dumps(corr,ensure_ascii=False,indent=2),encoding="utf-8")
    meta_m={"jobM":{"job_id":"jobM","folder":"CASE-M","status":"done"}}
    ctx_m=ct.ChatContext(run,root,job_id="jobM",case_folder="CASE-M",jobs_metadata=meta_m,lv2_policy="local")
    ctx_m.current_user_message="evil.example.com"
    rr=ctx_m.tool_investigate_local("search","evil.example.com",10)
    check("correlation schema mismatch is unavailable", rr.get("returned_count")==0 and rr.get("unavailable_reasons",{}).get("artifact_schema_mismatch",0)==1, str(rr))
    check("schema mismatch cannot claim complete coverage", rr.get("coverage_complete") is False, str(rr))

sec("R12: parsed cache identity is bound to actual file SHA")
with tempfile.TemporaryDirectory(prefix="v371_rc3_sha_") as td:
    root=Path(td)
    run=make_job(root,"jobS","CASE-S","HOST-S")
    def _svca(doc): doc["sections"]["service"]=[{"name":"SvcA","source_id":"service:a"}]
    parsed_path=rewrite_parsed_and_claim(run,_svca)
    meta_s={"jobS":{"job_id":"jobS","folder":"CASE-S","status":"done"}}
    ctx_s=ct.ChatContext(run,root,job_id="jobS",case_folder="CASE-S",jobs_metadata=meta_s,lv2_policy="local")
    ctx_s.current_user_message="SvcA"
    before=ctx_s.tool_investigate_local("search","SvcA",10)
    check("initial parsed value is indexed", before.get("returned_count",0)>=1, str(before))
    doc=json.loads(parsed_path.read_text(encoding="utf-8")); doc["sections"]["service"]=[{"name":"SvcB","source_id":"service:b"}]
    parsed_path.write_text(json.dumps(doc,ensure_ascii=False,indent=2),encoding="utf-8")
    ctx_s.current_user_message="SvcA"
    stale=ctx_s.tool_investigate_local("search","SvcA",10)
    check("stale cache is not reused after parsed mutation", stale.get("returned_count")==0, str(stale))
    check("claimed-vs-actual SHA mismatch is explicit", stale.get("unavailable_reasons",{}).get("source_artifact_sha_mismatch",0)==1, str(stale))

sec("R13: >200-host case exposes scope truncation")
with tempfile.TemporaryDirectory(prefix="v371_rc3_scope_") as td:
    root=Path(td)
    (root/"job000").mkdir()
    meta={f"job{i:03d}":{"job_id":f"job{i:03d}","folder":"BIG","status":"done"} for i in range(250)}
    eng=ci.InvestigationEngine(jobs_dir=root,job_id="job000",case_folder="BIG",jobs_snapshot=meta)
    ids,scope=eng._scope()
    check("scope is bounded at configured max", len(ids)==ci.DEFAULT_MAX_CASE_JOBS, str(scope))
    check("case-wide coverage distinguishes truncated scope", scope.get("case_host_count")==250 and scope.get("scope_truncated") is True and scope.get("case_coverage_complete") is False, str(scope))

sec("R14: summary fast path does not build core indexes")
with tempfile.TemporaryDirectory(prefix="v371_rc4_summary_") as td:
    root = Path(td)
    run1 = make_job(root, "job1", "CASE-SUM", "HOST-1", suspicion="HIGH")
    run2 = make_job(root, "job2", "CASE-SUM", "HOST-2", suspicion="MEDIUM", evidence="other.example.com")
    meta_sum = {
        "job1":{"job_id":"job1","folder":"CASE-SUM","status":"done"},
        "job2":{"job_id":"job2","folder":"CASE-SUM","status":"done"},
    }
    ctx_sum = ct.ChatContext(run1, root, job_id="job1", case_folder="CASE-SUM", jobs_metadata=meta_sum, lv2_policy="local")
    ctx_sum.current_user_message = "案件内に感染嫌疑がHIGH以上のホストは何台ある？"
    before = list(root.glob("*/chat_cache/chat_evidence_v1.sqlite"))
    rs = ctx_sum.tool_investigate_local("summary", "", 10)
    after = list(root.glob("*/chat_cache/chat_evidence_v1.sqlite"))
    check("complete correlation coverage returns exact HIGH count", rs.get("high_or_above_host_count") == 1 and rs.get("correlation_coverage_complete") is True, str(rs))
    check("complete summary returns full suspicion distribution", rs.get("infection_suspicion_host_distribution") == {"HIGH":1,"MEDIUM":1}, str(rs))
    check("cold summary creates no chat evidence sqlite", before == [] and after == [], str(after))

sec("R15: core truncation does not poison complete correlation summary")
with tempfile.TemporaryDirectory(prefix="v371_rc4_partialcore_") as td:
    root = Path(td)
    run1 = make_job(root, "job1", "CASE-PC", "HOST-1", suspicion="HIGH")
    run2 = make_job(root, "job2", "CASE-PC", "HOST-2", suspicion="MEDIUM")
    def _truncate(doc):
        rec = {f"field_{i:03d}": f"value{i}" for i in range(1, 98)}
        doc["sections"]["service"] = [rec]
    rewrite_parsed_and_claim(run2, _truncate)
    meta_pc = {
        "job1":{"job_id":"job1","folder":"CASE-PC","status":"done"},
        "job2":{"job_id":"job2","folder":"CASE-PC","status":"done"},
    }
    ctx_pc = ct.ChatContext(run1, root, job_id="job1", case_folder="CASE-PC", jobs_metadata=meta_pc, lv2_policy="local")
    ctx_pc.current_user_message = "案件内HIGH台数"
    rs = ctx_pc.tool_investigate_local("summary", "", 10)
    check("parsed truncation is irrelevant to correlation-only host count", rs.get("correlation_coverage_complete") is True and rs.get("high_or_above_host_count") == 1, str(rs))
    check("summary still does not build truncated host core index", not any(root.glob("*/chat_cache/chat_evidence_v1.sqlite")), str(list(root.glob("*/chat_cache/chat_evidence_v1.sqlite"))))

sec("R16: rc5 cold search fast paths avoid case-wide core index build")
with tempfile.TemporaryDirectory(prefix="v371_rc5_fast_",) as td:
    root = Path(td)
    run_a = make_job(root, "jobA", "CASE-F", "HOST-A", pipeline="3.69", schema="2.0", suspicion="HIGH",
                     raw_files=[
                         {"date":"2026/08/01  10:00","size":"1610612736","name":"pagefile.sys",
                          "path":r"C:\pagefile.sys","dir":"C:","source_id":"directory:a"},
                         {"date":"2026/08/01  10:00","size":"100","name":"Shortcut.lnk",
                          "path":r"C:\Users\Public\Desktop\Shortcut.lnk","dir":r"C:\Users\Public\Desktop",
                          "source_id":"directory:b"},
                     ])
    make_job(root, "jobB", "CASE-F", "HOST-B", evidence="b.example.com", suspicion="MEDIUM")
    make_job(root, "jobC", "CASE-F", "HOST-C", evidence="c.example.com", suspicion="MEDIUM")
    meta = {
        "jobA":{"job_id":"jobA","folder":"CASE-F","status":"done"},
        "jobB":{"job_id":"jobB","folder":"CASE-F","status":"done"},
        "jobC":{"job_id":"jobC","folder":"CASE-F","status":"done"},
    }
    ctx = ct.ChatContext(run_a, root, job_id="jobA", case_folder="CASE-F", jobs_metadata=meta, lv2_policy="local")

    ctx.current_user_message = "HOST-Bという名前のホストの情報を出して"
    rh = ctx.tool_investigate_local("search", "HOST-B", 10)
    check("exact hostname uses correlation fast path",
          rh.get("search_basis") == "exact_hostname_correlation_fast_path" and rh.get("core_index_build_attempted") is False,
          str(rh))
    check("exact hostname returns host-level correlation details",
          any(h.get("job_id") == "jobB" and h.get("infection_suspicion") == "MEDIUM" for h in rh.get("other_host_hits", [])),
          str(rh))
    check("hostname fast path creates no Evidence Index",
          not list(root.glob("*/chat_cache/chat_evidence_v1.sqlite")),
          str(list(root.glob("*/chat_cache/chat_evidence_v1.sqlite"))))

    # Reset the follow-up ledger so a previous hostname match cannot narrow the file query scope.
    (root / "jobA" / "chat_cache" / "evidence_ledger_v1.json").unlink(missing_ok=True)
    ctx.current_user_message = "pagefile.sysのファイルサイズは？"
    rp = ctx.tool_investigate_local("search", "pagefile.sys", 10)
    check("pagefile uses current-host Directory fast path",
          rp.get("search_basis") == "current_host_directory_fast_path" and rp.get("core_index_build_attempted") is False,
          str(rp))
    check("pagefile fast path returns raw size immediately",
          any(h.get("origin") == "parsed_directory_raw" and h.get("size") == "1610612736" for h in rp.get("current_host_hits", [])),
          str(rp))
    check("Directory fast path creates no Evidence Index",
          not list(root.glob("*/chat_cache/chat_evidence_v1.sqlite")),
          str(list(root.glob("*/chat_cache/chat_evidence_v1.sqlite"))))

    (root / "jobA" / "chat_cache" / "evidence_ledger_v1.json").unlink(missing_ok=True)
    ctx.current_user_message = "LNKファイルを10個列挙して"
    rl = ctx.tool_investigate_local("search", "*.lnk", 10)
    check("simple extension glob is normalized",
          rl.get("directory_search_query") == ".lnk",
          str(rl))
    check("*.lnk returns raw Directory hit",
          any(str(h.get("identifier") or "").lower().endswith(".lnk") for h in rl.get("current_host_hits", [])),
          str(rl))
    check("extension fast path remains prevalence fail-closed across case",
          rl.get("prevalence") is None and rl.get("query_coverage_complete") is False,
          str(rl))

sec("R17: duplicate tool request forces final answer immediately")
class Rc5DupClient:
    def __init__(self):
        self.calls=0; outer=self
        class C:
            def create(self, **kwargs):
                outer.calls += 1
                if outer.calls == 1: return StubResp(StubMsg(None,[StubTC(1)]))
                if outer.calls == 2: return StubResp(StubMsg(None,[StubTC(2)]))
                return StubResp(StubMsg("forced-final",None))
        self.chat=type("Chat",(),{"completions":C()})()
with tempfile.TemporaryDirectory() as td:
    ctx = ct.ChatContext(td, td, job_id="jobA", jobs_metadata={"jobA":{"job_id":"jobA","folder":"","status":"done"}})
    original = ct.dispatch_tool_call
    dispatched=[]
    try:
        ct.dispatch_tool_call=lambda _ctx,name,args: (dispatched.append((name,args)) or {"ok":True})
        rr=ct.run_chat_turn(Rc5DupClient(),"stub",[{"role":"system","content":"x"},{"role":"user","content":"foo"}],ctx)
        check("duplicate stop still dispatches exactly once", len(dispatched) == 1, str(dispatched))
        check("duplicate stop uses no extra tool round",
              rr.get("timing",{}).get("duplicate_tool_call_stopped") is True and rr.get("timing",{}).get("tool_iterations_exceeded") is False,
              str(rr))
        check("duplicate stop reaches forced final answer", rr.get("reply") == "forced-final", str(rr))
    finally:
        ct.dispatch_tool_call=original

sec("R18: rc6 explicit literal grounding + correlation prevalence fast path")
with tempfile.TemporaryDirectory(prefix="v371_rc6_grounding_") as td:
    root = Path(td)
    pcinfo = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\PC情報取得.lnk"
    run_a = make_job(root, "jobA", "CASE-P", "HOST-A", suspicion="HIGH", evidence=pcinfo,
                     raw_files=[
                         {"date":"2026/08/01  10:00","size":"2226075648","name":"pagefile.sys",
                          "path":r"C:\pagefile.sys","dir":"C:","source_id":"directory:page"},
                         {"date":"2026/08/01  10:00","size":"2080","name":"PC情報取得.lnk",
                          "path":pcinfo,"dir":r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
                          "source_id":"directory:pcinfo"},
                         {"date":"2026/08/01  10:00","size":"100","name":"Shortcut.lnk",
                          "path":r"C:\Users\Public\Desktop\Shortcut.lnk","dir":r"C:\Users\Public\Desktop",
                          "source_id":"directory:shortcut"},
                     ])
    make_job(root, "jobB", "CASE-P", "HOST-B", suspicion="MEDIUM", evidence=pcinfo)
    make_job(root, "jobC", "CASE-P", "HOST-C", suspicion="MEDIUM", evidence="c.example.com")
    make_job(root, "jobD", "CASE-P", "HOST-D", suspicion="MEDIUM", evidence="d.example.com")
    meta = {jid:{"job_id":jid,"folder":"CASE-P","status":"done"} for jid in ("jobA","jobB","jobC","jobD")}
    ctx = ct.ChatContext(run_a, root, job_id="jobA", case_folder="CASE-P", jobs_metadata=meta, lv2_policy="local")

    ctx.current_user_message = "PC情報取得.lnkは案件内の何台で見つかる？"
    r = ctx.tool_investigate_local("search", "*.lnk", 50)
    check("explicit filename overrides broadened model glob",
          r.get("query") == "PC情報取得.lnk" and r.get("query_grounding",{}).get("applied") is True,
          str(r))
    check("exact positive correlation fast path returns distinct-host prevalence",
          r.get("search_basis") == "correlation_exact_positive_fast_path" and
          r.get("observed_host_count") == 2 and r.get("prevalence") == "2/4 searchable hosts" and
          r.get("core_index_build_attempted") is False,
          str(r))
    check("correlation prevalence fast path creates no Evidence Index",
          not list(root.glob("*/chat_cache/chat_evidence_v1.sqlite")),
          str(list(root.glob("*/chat_cache/chat_evidence_v1.sqlite"))))

    ctx.current_user_message = "そのホスト名を列挙して。"
    follow = ctx.tool_investigate_local("search", "PC情報取得.lnk", 50)
    follow_names = {h.get("hostname") for h in follow.get("current_host_hits",[]) + follow.get("other_host_hits",[])}
    check("follow-up reuses previous matched-host subset",
          follow.get("scope",{}).get("scope_basis") == "previous_result_subset" and
          follow.get("scope_host_count") == 2 and follow.get("case_host_count") == 4 and
          follow_names == {"HOST-A","HOST-B"},
          str(follow))

    # Clear ledger: pagefile should use the exact user literal, not the model's *.sys broadening.
    (root / "jobA" / "chat_cache" / "evidence_ledger_v1.json").unlink(missing_ok=True)
    ctx.current_user_message = "pagefile.sysのファイルサイズは？"
    page = ctx.tool_investigate_local("search", "*.sys", 10)
    check("pagefile explicit literal overrides *.sys",
          page.get("query") == "pagefile.sys" and page.get("query_grounding",{}).get("applied") is True,
          str(page))
    check("grounded pagefile still uses Directory fast path and returns size",
          page.get("search_basis") == "current_host_directory_fast_path" and
          any(h.get("size") == "2226075648" and str(h.get("identifier") or "").lower().endswith("pagefile.sys")
              for h in page.get("current_host_hits",[])),
          str(page))

    # No explicit filename exists in the analyst message: keep rc5 extension listing semantics.
    (root / "jobA" / "chat_cache" / "evidence_ledger_v1.json").unlink(missing_ok=True)
    ctx.current_user_message = "LNKファイルを10個列挙して。"
    listing = ctx.tool_investigate_local("search", "*.lnk", 10)
    check("generic LNK listing is not over-grounded",
          listing.get("query") == "*.lnk" and listing.get("query_grounding",{}).get("applied") is False and
          listing.get("directory_search_query") == ".lnk",
          str(listing))

    # Correlation non-hit is positive-only: fall through to raw Directory evidence.
    rawonly = r"C:\Temp\OnlyRaw.exe"
    rewrite_parsed_and_claim(run_a, lambda doc: doc["sections"]["directory"].append(
        {"date":"2026/08/01  11:00","size":"42","name":"OnlyRaw.exe","path":rawonly,
         "dir":r"C:\Temp","source_id":"directory:rawonly"}))
    (root / "jobA" / "chat_cache" / "evidence_ledger_v1.json").unlink(missing_ok=True)
    ctx.current_user_message = "OnlyRaw.exeは案件内の何台で見つかる？"
    fallback = ctx.tool_investigate_local("search", "OnlyRaw.exe", 10)
    check("zero correlation exact hit falls through instead of declaring absence",
          fallback.get("search_basis") == "current_host_directory_fast_path" and
          any(str(h.get("identifier") or "").lower().endswith("onlyraw.exe") for h in fallback.get("current_host_hits",[])),
          str(fallback))

sec("R19: rc7 single-pass correlation filename/path prevalence")
with tempfile.TemporaryDirectory(prefix="v371_rc7_corr_single_pass_") as td:
    root = Path(td)
    target_name = "PC情報取得.lnk"
    target_path = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\PC情報取得.lnk"
    other_path = r"C:\Other\PC情報取得.lnk"
    meta = {}
    for i in range(76):
        jid = f"job{i:02d}"
        host = f"HOST-{i:02d}"
        if i < 5:
            evidence = target_name
        elif i < 22:
            evidence = target_path
        elif i == 22:
            evidence = "barPC情報取得.lnk"
        elif i == 23:
            evidence = other_path
        else:
            evidence = f"other-{i}.example.com"
        run = make_job(root, jid, "CASE-76", host, evidence=evidence)
        meta[jid] = {"job_id":jid,"folder":"CASE-76","status":"done"}
        if i == 0:
            # Same host carries both bare filename and full path.  It must still
            # count as one host prevalence observation.
            cp = next(run.glob("correlation_*.json"))
            doc = json.loads(cp.read_text(encoding="utf-8"))
            doc["correlated_iocs"] = [target_name, target_path]
            cp.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")

    ctx = ct.ChatContext(root / "job00" / "output" / "HOST-00_run", root,
                         job_id="job00", case_folder="CASE-76", jobs_metadata=meta, lv2_policy="local")
    original_load = ci._load_json_bounded
    correlation_loads = {"n": 0}
    def counted_load(path, deadline_monotonic, *, role):
        if role == "correlation":
            correlation_loads["n"] += 1
        return original_load(path, deadline_monotonic, role=role)
    try:
        ci._load_json_bounded = counted_load
        ctx.current_user_message = "PC情報取得.lnkは案件内の何台で見つかる？"
        r = ctx.tool_investigate_local("search", "PC情報取得.lnk", 50)
    finally:
        ci._load_json_bounded = original_load

    names = {h.get("hostname") for h in r.get("current_host_hits",[]) + r.get("other_host_hits",[])}
    check("single-pass correlation scan covers all 76 hosts exactly once",
          r.get("correlation_scan_passes") == 1 and correlation_loads["n"] == 76 and
          r.get("query_searchable_host_count") == 76 and r.get("coverage_complete") is True,
          f"loads={correlation_loads['n']} result={r}")
    check("filename exact + full-path basename matches dedupe to 23 distinct hosts",
          r.get("observed_host_count") == 23 and r.get("prevalence") == "23/76 searchable hosts" and len(names) == 23,
          str(r))
    check("substring filename does not false-match",
          "HOST-22" not in names, str(sorted(names)))
    facts = r.get("answer_facts") or {}
    check("authoritative answer_facts exposes deterministic count before verbose hits",
          facts.get("authoritative") is True and facts.get("matched_host_count") == 23 and
          len(facts.get("matched_hostnames") or []) == 23, str(facts))
    preview = json.dumps(r, ensure_ascii=False)[:ct.TOOL_RESULT_MAX_CHARS]
    check("bounded tool preview retains authoritative count",
          '"matched_host_count": 23' in preview and preview.find('"answer_facts"') < preview.find('"current_host_hits"'),
          preview[:600])

    # A full-path pivot remains exact.  The other path with the same basename
    # must not be folded into this path prevalence.
    (root / "job00" / "chat_cache" / "evidence_ledger_v1.json").unlink(missing_ok=True)
    ctx.current_user_message = f"{target_path}は案件内の何台で見つかる？"
    p = ctx.tool_investigate_local("search", target_path, 50)
    check("full-path pivot does not broaden to same-basename other path",
          p.get("observed_host_count") == 18 and p.get("prevalence") == "18/76 searchable hosts",
          str(p))

sec("R20: rc8 authoritative answer facts stop recounting visible hits")
class Rc8FactsTC:
    def __init__(self):
        self.id="facts1"
        self.function=type("F",(),{
            "name":"investigate_local",
            "arguments":json.dumps({"action":"search","query":"PC情報取得.lnk"}, ensure_ascii=False),
        })()
    def model_dump(self):
        return {"id":self.id,"type":"function","function":{
            "name":self.function.name,"arguments":self.function.arguments}}

class Rc8FactsClient:
    def __init__(self):
        self.calls=0; self.final_messages=None; outer=self
        class C:
            def create(self, **kwargs):
                outer.calls += 1
                if outer.calls == 1:
                    return StubResp(StubMsg(None,[Rc8FactsTC()]))
                outer.final_messages = kwargs.get("messages") or []
                return StubResp(StubMsg("案件内の22台で確認されました。",None))
        self.chat=type("Chat",(),{"completions":C()})()

with tempfile.TemporaryDirectory() as td:
    ctx = ct.ChatContext(td, td, job_id="jobA", jobs_metadata={"jobA":{"job_id":"jobA","folder":"CASE","status":"done"}})
    original = ct.dispatch_tool_call
    dispatched=[]
    hostnames=[f"HOST-{i:02d}" for i in range(22)]
    long_hits=[{
        "job_id":f"job{i:02d}","hostname":hostnames[i],"identifier":r"C:\\ProgramData\\"+("X"*200)+"\\PC情報取得.lnk",
        "reason":"Y"*300,
    } for i in range(22)]
    result={
        "action":"search",
        "search_basis":"correlation_exact_positive_fast_path",
        "answer_facts":{
            "authoritative":True,
            "matched_host_count":22,
            "observed_matched_host_count":22,
            "searchable_host_count":76,
            "scope_host_count":76,
            "case_host_count":76,
            "coverage_complete":True,
            "prevalence":"22/76 searchable hosts",
            "matched_hostnames":hostnames,
        },
        "current_host_hits":long_hits[:1],
        "other_host_hits":long_hits[1:],
        "observed_host_count":22,
        "prevalence":"22/76 searchable hosts",
        "coverage_complete":True,
    }
    try:
        ct.dispatch_tool_call=lambda _ctx,name,args: (dispatched.append((name,args)) or result)
        client=Rc8FactsClient()
        rr=ct.run_chat_turn(client,"stub",[
            {"role":"system","content":"x"},
            {"role":"user","content":"PC情報取得.lnkは案件内の何台で見つかる？"},
        ],ctx)
        check("authoritative prevalence dispatches exactly once", len(dispatched)==1, str(dispatched))
        check("authoritative prevalence forces final without another tool round",
              client.calls==2 and rr.get("timing",{}).get("authoritative_answer_facts_stopped") is True and
              rr.get("timing",{}).get("tool_iterations_exceeded") is False, str(rr))
        check("final grounding note carries Python count instead of raw hostnames",
              client.final_messages is not None and
              "matched_host_count=22" in str(client.final_messages[-1].get("content") or "") and
              "HOST-00" not in str(client.final_messages[-1].get("content") or ""),
              str(client.final_messages[-1] if client.final_messages else None))
        tool_msgs=[m for m in (client.final_messages or []) if m.get("role")=="tool"]
        check("bounded untrusted tool result exposes answer_facts before verbose hits",
              bool(tool_msgs) and '"matched_host_count": 22' in tool_msgs[-1].get("content","") and
              tool_msgs[-1].get("content","").find('"answer_facts"') < tool_msgs[-1].get("content","").find('"current_host_hits"'),
              (tool_msgs[-1].get("content","")[:800] if tool_msgs else "no tool message"))
        check("final answer follows deterministic count", rr.get("reply")=="案件内の22台で確認されました。", str(rr))
    finally:
        ct.dispatch_tool_call=original


sec("R21: rc9 identifier-token fallback, Directory timeline, hostname negative, VT-off guard")
with tempfile.TemporaryDirectory(prefix="v371_rc9_") as td:
    root = Path(td)
    run_a = make_job(root, "jobA", "CASE-R9", "HOST-A", pipeline="3.69", schema="2.0", suspicion="HIGH",
                     raw_files=[
                         {"date":"2022/09/07 16:03","size":"2080","name":"PC情報取得.lnk",
                          "path":r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\PC情報取得.lnk",
                          "dir":r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
                          "source_id":"directory:r9"},
                     ])
    run_b = make_job(root, "jobB", "CASE-R9", "HOST-B", pipeline="3.69", schema="2.0", suspicion="MEDIUM")
    def _mutate_r9(pb_doc):
        pb_doc["sections"]["service"] = [{
            "name":"ajrouter", "display_name":"AllJoyn Router Service",
            "image_path":r"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted",
            "source_id":"service:ajrouter",
        }]
    rewrite_parsed_and_claim(run_b, _mutate_r9)
    meta = {
        "jobA":{"job_id":"jobA","folder":"CASE-R9","status":"done"},
        "jobB":{"job_id":"jobB","folder":"CASE-R9","status":"done"},
    }
    ctx = ct.ChatContext(run_a, root, job_id="jobA", case_folder="CASE-R9", jobs_metadata=meta, lv2_policy="local")

    ctx.current_user_message = "ajrouterサービスについて案件内の観測状況を調べて。"
    rs = ctx.tool_investigate_local("search", "ajrouter service", 20)
    check("identifier-like token fallback finds parsed ajrouter service",
          any(h.get("matched_query") == "ajrouter" and h.get("origin") == "parsed_structured"
              for h in rs.get("other_host_hits", [])), str(rs))
    check("identifier fallback remains bounded and visible",
          rs.get("query_variants", [None])[:2] == ["ajrouter service", "ajrouter"], str(rs.get("query_variants")))

    ctx.current_user_message = "PC情報取得.lnkについて、確認できる範囲で観測時系列を教えて。"
    rt = ctx.tool_investigate_local("timeline", "PC情報取得.lnk", 10)
    th = (rt.get("hits") or [{}])[0]
    check("Directory metadata provides timeline fallback",
          rt.get("timeline_basis") == "current_host_directory_fast_path" and
          th.get("timestamp_raw") == "2022/09/07 16:03" and
          th.get("timestamp_kind") == "filesystem_metadata", str(rt))
    check("Directory timeline is explicitly non-causal",
          rt.get("causal") is False and th.get("causal") is False and
          "does not establish execution" in str(th.get("warning") or ""), str(rt))

    ctx.current_user_message = "ZZZ-NO-SUCH-HOST-987654というホストは案件内に存在する？"
    rn = ctx.tool_investigate_local("search", "ZZZ-NO-SUCH-HOST-987654", 10)
    nf = rn.get("answer_facts") or {}
    check("complete hostname coverage can authoritatively return not-found",
          rn.get("search_basis") == "exact_hostname_correlation_fast_path" and
          rn.get("coverage_complete") is True and rn.get("observed_host_count") == 0 and
          nf.get("authoritative") is True and nf.get("entity_exists") is False and
          nf.get("matched_host_count") == 0, str(rn))

    # Incomplete hostname coverage must never become authoritative absence.
    bad_run = make_job(root, "jobC", "CASE-R9", "HOST-C", pipeline="3.68", schema="1.9", suspicion="MEDIUM")
    meta["jobC"]={"job_id":"jobC","folder":"CASE-R9","status":"done"}
    ctx2 = ct.ChatContext(run_a, root, job_id="jobA", case_folder="CASE-R9", jobs_metadata=meta, lv2_policy="local")
    ctx2.current_user_message = "NOHOSTというホストは案件内に存在する？"
    rn2 = ctx2.tool_investigate_local("search", "NOHOST", 10)
    check("incomplete hostname coverage refuses authoritative absence",
          rn2.get("observed_host_count") == 0 and rn2.get("coverage_complete") is False and
          not (rn2.get("answer_facts") or {}).get("authoritative"), str(rn2))

class Rc9BombClient:
    def __init__(self):
        outer=self
        class C:
            def create(self, **kwargs):
                raise AssertionError("LLM must not be called when explicit VT lookup is disabled")
        self.chat=type("Chat",(),{"completions":C()})()

with tempfile.TemporaryDirectory() as td:
    ctx = ct.ChatContext(td, td, job_id="jobA", jobs_metadata={"jobA":{"job_id":"jobA","folder":"CASE","status":"done"}})
    rr = ct.run_chat_turn(Rc9BombClient(), "stub", [
        {"role":"system","content":"x"},
        {"role":"user","content":"8.8.8.8をVirusTotalで調べて。"},
    ], ctx, lv2_policy="local", local_enabled=True, vt_enabled=False)
    check("VT-off explicit lookup is stopped before LLM/tool dispatch",
          rr.get("tool_calls_made") == [] and rr.get("timing",{}).get("llm_calls") == 0 and
          rr.get("timing",{}).get("external_ti_disabled_stopped") is True, str(rr))
    check("VT-off reply explicitly states no external communication",
          "VirusTotal" in rr.get("reply","") and "外部通信は行っていません" in rr.get("reply", ""), str(rr))
    check("explicit no-VT wording is not misclassified as external lookup intent",
          ct._is_explicit_external_ti_lookup_request("VTを使わず8.8.8.8をローカルで調べて") is False)


sec("R22/R23: rc10 hostname coverage + rc11 VT positive-allowlist gate")
negative_vt_requests = [
    "VTを使わず8.8.8.8をローカルで調べて",
    "VirusTotalを使わないで8.8.8.8を調べて",
    "外部TIを使わず8.8.8.8を調べて",
    "VTは使わなくていいので8.8.8.8を調べて",
]
for text in negative_vt_requests:
    check(f"external-TI negation is not affirmative: {text}",
          ct._is_explicit_external_ti_lookup_request(text) is False)
check("affirmative VT lookup remains affirmative",
      ct._is_explicit_external_ti_lookup_request("8.8.8.8をVirusTotalで調べて") is True)

# rc11: external-TI authorization is positive-allowlist based.  Explicit
# alternatives/negations and generic VT discussion must remain local even if a
# lookup verb appears elsewhere in the same current turn.
rc11_negative_vt_requests = [
    "VTではなくローカルで8.8.8.8を調べて",
    "VTじゃなくローカルで8.8.8.8を調べて",
    "VirusTotalではなくローカルだけで8.8.8.8を調べて",
    "外部TIではなくローカルだけで8.8.8.8を調べて",
    "VT以外で8.8.8.8を調べて",
    "do not use VT; check 8.8.8.8 locally",
    "don't use VT; check 8.8.8.8 locally",
    "VirusTotalとは何？ 8.8.8.8をローカルで調べて",
    "VTについて説明して。8.8.8.8はローカルで確認して",
]
for text in rc11_negative_vt_requests:
    check(f"rc11 no affirmative external intent: {text}",
          ct._is_explicit_external_ti_lookup_request(text) is False)

rc11_positive_vt_requests = [
    "8.8.8.8をVirusTotalで調べて",
    "8.8.8.8をVTで照会して",
    "VirusTotalに8.8.8.8を問い合わせて",
    "外部TIで8.8.8.8を確認して",
    "check 8.8.8.8 with VirusTotal",
    "look up 8.8.8.8 on VirusTotal",
]
for text in rc11_positive_vt_requests:
    check(f"rc11 affirmative external intent: {text}",
          ct._is_explicit_external_ti_lookup_request(text) is True)

# Even if the model fabricates a VT tool call while VT is enabled, the shared
# deterministic predicate must block a negated current-turn instruction before
# secure_vt_lookup can perform external I/O.
class Rc10ForcedVtTC:
    def __init__(self):
        self.id="vt1"
        self.function=type("F",(),{
            "name":"vt_ioc_lookup",
            "arguments":json.dumps({"ioc_value":"8.8.8.8"}),
        })()
    def model_dump(self):
        return {"id":self.id,"type":"function","function":{
            "name":self.function.name,"arguments":self.function.arguments}}

class Rc10ForcedVtClient:
    def __init__(self):
        self.calls=0; outer=self
        class C:
            def create(self, **kwargs):
                outer.calls += 1
                if outer.calls == 1:
                    return StubResp(StubMsg(None,[Rc10ForcedVtTC()]))
                return StubResp(StubMsg("external blocked",None))
        self.chat=type("Chat",(),{"completions":C()})()

with tempfile.TemporaryDirectory(prefix="v371_rc10_vt_") as td:
    ctx = ct.ChatContext(td, td, vt_key="dummy", job_id="jobA",
                         jobs_metadata={"jobA":{"job_id":"jobA","folder":"CASE","status":"done"}},
                         lv2_policy="local_vt_ioc")
    original_secure = ct.secure_vt_lookup
    external_calls=[]
    try:
        ct.secure_vt_lookup=lambda *a, **kw: (external_calls.append((a,kw)) or {"external_request":True})
        rr=ct.run_chat_turn(
            Rc10ForcedVtClient(), "stub",
            [{"role":"system","content":"x"},
             {"role":"user","content":"VTを使わず8.8.8.8をローカルで調べて"}],
            ctx, lv2_policy="local_vt_ioc", local_enabled=True, vt_enabled=True)
        check("forced VT tool under explicit negation performs zero external calls",
              external_calls == [], str(external_calls))
        check("forced VT tool remains locally rejected and turn completes",
              rr.get("reply") == "external blocked" and
              [x.get("name") for x in rr.get("tool_calls_made",[])] == ["vt_ioc_lookup"], str(rr))
    finally:
        ct.secure_vt_lookup=original_secure

# rc11 attack fixtures: even if Qwen fabricates vt_ioc_lookup, every explicit
# no-VT / non-external formulation must be rejected before secure_vt_lookup.
for text in [
    "VTではなくローカルで8.8.8.8を調べて",
    "VTじゃなくローカルで8.8.8.8を調べて",
    "VirusTotalではなくローカルだけで8.8.8.8を調べて",
    "外部TIではなくローカルだけで8.8.8.8を調べて",
    "VT以外で8.8.8.8を調べて",
    "do not use VT; check 8.8.8.8 locally",
    "don't use VT; check 8.8.8.8 locally",
    "VirusTotalとは何？ 8.8.8.8をローカルで調べて",
    "VTについて説明して。8.8.8.8はローカルで確認して",
]:
    with tempfile.TemporaryDirectory(prefix="v371_rc11_vt_") as td:
        ctx = ct.ChatContext(td, td, vt_key="dummy", job_id="jobA",
                             jobs_metadata={"jobA":{"job_id":"jobA","folder":"CASE","status":"done"}},
                             lv2_policy="local_vt_ioc")
        ctx.current_user_message = text
        original_secure = ct.secure_vt_lookup
        external_calls=[]
        try:
            ct.secure_vt_lookup=lambda *a, **kw: (external_calls.append((a,kw)) or {"external_request":True})
            denied=ctx.tool_vt_ioc_lookup("8.8.8.8")
            check(f"rc11 forced wrong VT call blocked: {text}",
                  external_calls == [] and denied.get("external_request") is False,
                  str({"calls":external_calls,"result":denied}))
        finally:
            ct.secure_vt_lookup=original_secure


sec("R24: rc12 IOC-specific external-TI authorization")

rc12_negative_directives = [
    "VTで8.8.8.8を確認する必要はない。ローカルで調べて",
    "VTで8.8.8.8を検索してはいけない。ローカルで調べて",
    "VirusTotalで8.8.8.8を照会するつもりはない。ローカルで確認して",
    "VTで8.8.8.8を調べる必要はありません。ローカルだけで調べて",
    "don't check 8.8.8.8 with VirusTotal; check locally",
    "do not look up 8.8.8.8 on VT; inspect it locally",
    "please don't query 8.8.8.8 via VirusTotal",
    "do not search 8.8.8.8 using VT",
]
for text in rc12_negative_directives:
    check(f"rc12 explicit prohibition authorizes no external IOC: {text}",
          ct._extract_explicit_external_ti_iocs(text) == set())
    check(f"rc12 compatibility intent is false for prohibition: {text}",
          ct._is_explicit_external_ti_lookup_request(text) is False)

rc12_positive_directives = {
    "8.8.8.8をVirusTotalで調べて": {"8.8.8.8"},
    "8.8.8.8をVTで照会して": {"8.8.8.8"},
    "VirusTotalに8.8.8.8を問い合わせて": {"8.8.8.8"},
    "外部TIで8.8.8.8を確認して": {"8.8.8.8"},
    "check 8.8.8.8 with VirusTotal": {"8.8.8.8"},
    "look up 8.8.8.8 on VirusTotal": {"8.8.8.8"},
}
for text, expected in rc12_positive_directives.items():
    check(f"rc12 explicit positive directive binds IOC: {text}",
          ct._extract_explicit_external_ti_iocs(text) == expected)

mixed_jp = "8.8.8.8はローカルで調べて、1.1.1.1をVirusTotalで調べて"
mixed_en = "check 8.8.8.8 locally, and check 1.1.1.1 with VirusTotal"
mixed_global_neg = "8.8.8.8はVT不要。1.1.1.1はVirusTotalで調べて"
for text in (mixed_jp, mixed_en, mixed_global_neg):
    check(f"rc12 mixed routing authorizes only external-target IOC: {text}",
          ct._extract_explicit_external_ti_iocs(text) == {"1.1.1.1"})

# Forced wrong tool calls must respect IOC-specific authorization even with VT ON.
with tempfile.TemporaryDirectory(prefix="v371_rc12_vt_binding_") as td:
    ctx = ct.ChatContext(td, td, vt_key="dummy", job_id="jobA",
                         jobs_metadata={"jobA":{"job_id":"jobA","folder":"CASE","status":"done"}},
                         lv2_policy="local_vt_ioc")
    original_secure = ct.secure_vt_lookup
    external_calls=[]
    try:
        ct.secure_vt_lookup=lambda *a, **kw: (external_calls.append((a,kw)) or {"external_request":True})

        for text in rc12_negative_directives:
            ctx.current_user_message = text
            external_calls.clear()
            denied = ctx.tool_vt_ioc_lookup("8.8.8.8")
            check(f"rc12 forced VT call blocked for explicit prohibition: {text}",
                  external_calls == [] and denied.get("external_request") is False,
                  str({"calls":external_calls,"result":denied}))

        ctx.current_user_message = mixed_jp
        external_calls.clear()
        local_only = ctx.tool_vt_ioc_lookup("8.8.8.8")
        check("rc12 mixed routing blocks local-only IOC",
              external_calls == [] and local_only.get("external_request") is False and
              local_only.get("reason") == "ioc_not_grounded",
              str({"calls":external_calls,"result":local_only}))

        external_calls.clear()
        external_ok = ctx.tool_vt_ioc_lookup("1.1.1.1")
        check("rc12 mixed routing permits explicitly external IOC only",
              len(external_calls) == 1 and external_ok.get("external_request") is True,
              str({"calls":external_calls,"result":external_ok}))
    finally:
        ct.secure_vt_lookup=original_secure

# Disabled pre-check must use the exact same authorized IOC set.  A mixed turn
# with one explicit VT target is stopped, while a pure prohibition remains local.
with tempfile.TemporaryDirectory(prefix="v371_rc12_vt_precheck_") as td:
    ctx = ct.ChatContext(td, td, job_id="jobA",
                         jobs_metadata={"jobA":{"job_id":"jobA","folder":"CASE","status":"done"}})
    rr = ct.run_chat_turn(Rc9BombClient(), "stub", [
        {"role":"system","content":"x"},
        {"role":"user","content":mixed_jp},
    ], ctx, lv2_policy="local", local_enabled=True, vt_enabled=False)
    check("rc12 VT-disabled precheck stops turn when authorized external IOC set is nonempty",
          rr.get("timing",{}).get("external_ti_disabled_stopped") is True and
          rr.get("timing",{}).get("llm_calls") == 0, str(rr))



sec("R25: rc13 VT grammar binds only captured external-target IOC")

rc13_same_directive_cases = [
    "8.8.8.8はローカルで調べて1.1.1.1をVirusTotalで調べて",
    "1.1.1.1をVirusTotalで調べて8.8.8.8はローカルで確認して",
    "8.8.8.8はローカルで調べてそして1.1.1.1をVTで照会して",
    "check 8.8.8.8 locally while checking 1.1.1.1 with VirusTotal",
    "8.8.8.8と比較しながら1.1.1.1をVirusTotalで調べて",
]
for text in rc13_same_directive_cases:
    check(f"rc13 same-directive binding authorizes external target only: {text}",
          ct._extract_explicit_external_ti_iocs(text) == {"1.1.1.1"})

check("rc13 hyphenated FQDN remains bindable without directive splitting",
      ct._extract_explicit_external_ti_iocs(
          "check foo-and-bar.com with VirusTotal") == {"foo-and-bar.com"})

# Force the model's wrong VT choice for the local/context IOC.  Security must
# still reject it, while the explicitly bound external IOC remains usable.
with tempfile.TemporaryDirectory(prefix="v371_rc13_same_clause_") as td:
    ctx = ct.ChatContext(td, td, vt_key="dummy", job_id="jobA",
                         jobs_metadata={"jobA":{"job_id":"jobA","folder":"CASE","status":"done"}},
                         lv2_policy="local_vt_ioc")
    original_secure = ct.secure_vt_lookup
    external_calls=[]
    try:
        ct.secure_vt_lookup=lambda *a, **kw: (external_calls.append((a,kw)) or {"external_request":True})
        for text in rc13_same_directive_cases:
            ctx.current_user_message = text
            external_calls.clear()
            denied = ctx.tool_vt_ioc_lookup("8.8.8.8")
            check(f"rc13 same-directive local/context IOC never reaches external transport: {text}",
                  external_calls == [] and denied.get("external_request") is False and
                  denied.get("reason") == "ioc_not_grounded",
                  str({"calls":external_calls,"result":denied}))

            external_calls.clear()
            allowed = ctx.tool_vt_ioc_lookup("1.1.1.1")
            check(f"rc13 same-directive explicitly bound IOC is externally eligible: {text}",
                  len(external_calls) == 1 and allowed.get("external_request") is True,
                  str({"calls":external_calls,"result":allowed}))
    finally:
        ct.secure_vt_lookup=original_secure


sec("R26: rc14 directive-local negation and multi-IOC external binding")

rc14_negative_binding_cases = [
    "8.8.8.8をVTで確認しなくていい。ローカルで調べて",
    "8.8.8.8をVTで確認しなくてよい",
    "8.8.8.8をVTで確認不要",
    "8.8.8.8をVTで確認は不要",
    "8.8.8.8をVTで確認しない",
    "avoid checking 8.8.8.8 with VirusTotal; check it locally",
    "without checking 8.8.8.8 with VirusTotal, check it locally",
    "rather than checking 8.8.8.8 with VirusTotal, check it locally",
    "avoid using VirusTotal to check 8.8.8.8",
    "without using VirusTotal to check 8.8.8.8",
]
for text in rc14_negative_binding_cases:
    check(f"rc14 directive-local explicit negation authorizes nothing: {text}",
          ct._extract_explicit_external_ti_iocs(text) == set())

with tempfile.TemporaryDirectory(prefix="v371_rc14_negative_binding_") as td:
    ctx = ct.ChatContext(td, td, vt_key="dummy", job_id="jobA",
                         jobs_metadata={"jobA":{"job_id":"jobA","folder":"CASE","status":"done"}},
                         lv2_policy="local_vt_ioc")
    original_secure = ct.secure_vt_lookup
    external_calls=[]
    try:
        ct.secure_vt_lookup=lambda *a, **kw: (external_calls.append((a,kw)) or {"external_request":True})
        for text in rc14_negative_binding_cases:
            ctx.current_user_message=text
            external_calls.clear()
            denied=ctx.tool_vt_ioc_lookup("8.8.8.8")
            check(f"rc14 negated directive never reaches external transport: {text}",
                  external_calls == [] and denied.get("external_request") is False,
                  str({"calls":external_calls,"result":denied}))
    finally:
        ct.secure_vt_lookup=original_secure

# P1 cleanup: multiple IOCs explicitly bound to one external directive should
# all be authorized, while context/local IOCs outside that binding remain out.
rc14_multi_external_cases = {
    "8.8.8.8と1.1.1.1をVirusTotalで調べて": {"8.8.8.8","1.1.1.1"},
    "VirusTotalで8.8.8.8と1.1.1.1を調べて": {"8.8.8.8","1.1.1.1"},
    "check 8.8.8.8 and 1.1.1.1 with VirusTotal": {"8.8.8.8","1.1.1.1"},
    "use VirusTotal to check 8.8.8.8 and 1.1.1.1": {"8.8.8.8","1.1.1.1"},
}
for text, expected in rc14_multi_external_cases.items():
    check(f"rc14 explicit multi-IOC external directive binds every listed IOC: {text}",
          ct._extract_explicit_external_ti_iocs(text) == expected,
          str(ct._extract_explicit_external_ti_iocs(text)))

# Existing P0/P1 safety controls remain intact.
check("rc14 same-directive local/external routing remains IOC-specific",
      ct._extract_explicit_external_ti_iocs(
          "8.8.8.8はローカルで調べて1.1.1.1をVirusTotalで調べて") == {"1.1.1.1"})
check("rc14 hyphenated FQDN remains bindable",
      ct._extract_explicit_external_ti_iocs(
          "check foo-and-bar.com with VirusTotal") == {"foo-and-bar.com"})

sec("R27: rc15 English directive-bound affirmative VT authorization")

rc15_negative_english_prefix_cases = [
    "no need to check 8.8.8.8 with VirusTotal; check locally",
    "there is no need to check 8.8.8.8 with VirusTotal",
    "not necessary to check 8.8.8.8 with VirusTotal",
    "refrain from checking 8.8.8.8 with VirusTotal",
    "skip checking 8.8.8.8 with VirusTotal",
]
for text in rc15_negative_english_prefix_cases:
    check(f"rc15 non-affirmative English directive authorizes nothing: {text}",
          ct._extract_explicit_external_ti_iocs(text) == set(),
          str(ct._extract_explicit_external_ti_iocs(text)))

with tempfile.TemporaryDirectory(prefix="v371_rc15_negative_prefix_") as td:
    ctx = ct.ChatContext(td, td, vt_key="dummy", job_id="jobA",
                         jobs_metadata={"jobA":{"job_id":"jobA","folder":"CASE","status":"done"}},
                         lv2_policy="local_vt_ioc")
    original_secure = ct.secure_vt_lookup
    external_calls=[]
    try:
        ct.secure_vt_lookup=lambda *a, **kw: (external_calls.append((a,kw)) or {"external_request":True})
        for text in rc15_negative_english_prefix_cases:
            ctx.current_user_message=text
            external_calls.clear()
            denied=ctx.tool_vt_ioc_lookup("8.8.8.8")
            check(f"rc15 non-affirmative English directive never reaches external transport: {text}",
                  external_calls == [] and denied.get("external_request") is False,
                  str({"calls":external_calls,"result":denied}))
    finally:
        ct.secure_vt_lookup=original_secure

rc15_positive_boundary_controls = {
    "check 8.8.8.8 with VirusTotal": {"8.8.8.8"},
    "please check 8.8.8.8 with VirusTotal": {"8.8.8.8"},
    "check 8.8.8.8 locally while checking 1.1.1.1 with VirusTotal": {"1.1.1.1"},
    "check 8.8.8.8 locally and check 1.1.1.1 with VirusTotal": {"1.1.1.1"},
    "check foo-and-bar.com with VirusTotal": {"foo-and-bar.com"},
}
for text, expected in rc15_positive_boundary_controls.items():
    check(f"rc15 directive-bound positive control remains authorized: {text}",
          ct._extract_explicit_external_ti_iocs(text) == expected,
          str(ct._extract_explicit_external_ti_iocs(text)))

sec("R28: rc16 directive boundary / Japanese action-terminal VT authorization")

rc16_negative_english_comma_cases = [
    "do not, under any circumstances, check 8.8.8.8 with VirusTotal",
    "never, ever, check 8.8.8.8 with VirusTotal",
    "please do not, for any reason, check 8.8.8.8 with VirusTotal",
    "no need, check 8.8.8.8 with VirusTotal",
]
rc16_negative_japanese_terminal_cases = [
    "8.8.8.8をVTで確認するのはやめて、ローカルで調べて",
    "8.8.8.8をVTで検索するのはやめて",
    "8.8.8.8をVirusTotalで照会するのはやめて",
    "8.8.8.8をVTでチェックするのはやめて",
    "8.8.8.8をVTで調べてほしくない",
    "8.8.8.8をVTで確認してほしくない",
    "8.8.8.8をVTで照会してほしくない",
]
for text in rc16_negative_english_comma_cases + rc16_negative_japanese_terminal_cases:
    check(f"rc16 explicit negative directive authorizes nothing: {text}",
          ct._extract_explicit_external_ti_iocs(text) == set(),
          str(ct._extract_explicit_external_ti_iocs(text)))

with tempfile.TemporaryDirectory(prefix="v371_rc16_negative_directive_") as td:
    ctx = ct.ChatContext(td, td, vt_key="dummy", job_id="jobA",
                         jobs_metadata={"jobA":{"job_id":"jobA","folder":"CASE","status":"done"}},
                         lv2_policy="local_vt_ioc")
    original_secure = ct.secure_vt_lookup
    external_calls=[]
    try:
        ct.secure_vt_lookup=lambda *a, **kw: (external_calls.append((a,kw)) or {"external_request":True})
        for text in rc16_negative_english_comma_cases + rc16_negative_japanese_terminal_cases:
            ctx.current_user_message=text
            external_calls.clear()
            denied=ctx.tool_vt_ioc_lookup("8.8.8.8")
            check(f"rc16 explicit negative never reaches external transport: {text}",
                  external_calls == [] and denied.get("external_request") is False,
                  str({"calls":external_calls,"result":denied}))
    finally:
        ct.secure_vt_lookup=original_secure

# Keep legitimate mixed routing and directive-bound positive controls.
rc16_positive_boundary_controls = {
    "check 8.8.8.8 with VirusTotal": {"8.8.8.8"},
    "check 8.8.8.8 locally while checking 1.1.1.1 with VirusTotal": {"1.1.1.1"},
    "check 8.8.8.8 locally, and check 1.1.1.1 with VirusTotal": {"1.1.1.1"},
    "1.1.1.1をVirusTotalで調べて8.8.8.8はローカルで確認して": {"1.1.1.1"},
    "8.8.8.8はローカルで調べてそして1.1.1.1をVTで照会して": {"1.1.1.1"},
}
for text, expected in rc16_positive_boundary_controls.items():
    check(f"rc16 positive directive control remains authorized: {text}",
          ct._extract_explicit_external_ti_iocs(text) == expected,
          str(ct._extract_explicit_external_ti_iocs(text)))

with tempfile.TemporaryDirectory(prefix="v371_rc10_hostcov_") as td:
    root=Path(td)
    run1=make_job(root,"job1","CASE-HC","HOST1")
    run2=make_job(root,"job2","CASE-HC","HOST2")
    run3=make_job(root,"job3","CASE-HC","HOST3")
    for run, replacement in ((run2,"UNKNOWN"),(run3,"")):
        cp=next(run.glob("correlation_*.json"))
        corr=json.loads(cp.read_text(encoding="utf-8"))
        corr["meta"]["hostname"]=replacement
        cp.write_text(json.dumps(corr,ensure_ascii=False,indent=2),encoding="utf-8")
    meta={
        "job1":{"job_id":"job1","folder":"CASE-HC","status":"done"},
        "job2":{"job_id":"job2","folder":"CASE-HC","status":"done"},
        "job3":{"job_id":"job3","folder":"CASE-HC","status":"done"},
    }
    ctx=ct.ChatContext(run1,root,job_id="job1",case_folder="CASE-HC",jobs_metadata=meta,lv2_policy="local")
    ctx.current_user_message="HOSTXというホストは案件内に存在する？"
    rh=ctx.tool_investigate_local("search","HOSTX",10)
    check("blank and UNKNOWN are excluded from hostname searchable denominator",
          rh.get("correlation_searchable_host_count")==3 and
          rh.get("hostname_searchable_host_count")==1 and
          rh.get("hostname_unavailable_host_count")==2 and
          rh.get("hostname_unavailable_reasons",{}).get("hostname_missing_or_unknown")==2,
          str(rh))
    check("incomplete hostname coverage cannot authoritatively prove not-found",
          rh.get("hostname_coverage_complete") is False and
          rh.get("coverage_complete") is False and rh.get("prevalence") is None and
          not (rh.get("answer_facts") or {}).get("authoritative"), str(rh))
    check("hostname helper treats blank and UNKNOWN as unavailable",
          ci._is_searchable_hostname("") is False and
          ci._is_searchable_hostname("UNKNOWN") is False and
          ci._is_searchable_hostname("HOST1") is True)

server_text=(HERE/"server.py").read_text(encoding="utf-8")
check("system prompt guards commonality from maliciousness/impact overstatement",
      "prevalenceが高いことだけを根拠に悪性・感染・キャンペーン影響・因果関係を断定しない" in server_text,
      "prompt guard missing")

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)

