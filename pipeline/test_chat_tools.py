# -*- coding: utf-8 -*-
"""v3.71 chat TI redesign synthetic regression tests (no real corpus/network)."""
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import chat_lv2
import chat_tools as ct

PASS = FAIL = 0

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"  [OK]  {name}"); PASS += 1
    else:
        print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1

def sec(title):
    print(f"\n{'-'*60}\n  {title}\n{'-'*60}")


def analyzed(identifier, *, score="HIGH", iocs=None, source_index=1):
    return {
        "sections": {
            "netstat": {
                "entries": [{
                    "identifier": identifier,
                    "score": score,
                    "reason": f"reason {identifier}",
                    "iocs": iocs or [identifier],
                    "source_index": source_index,
                }]
            }
        }
    }


sec("T1: policy-specific tool schema")
base = {t["function"]["name"] for t in ct.build_tool_schema(False, lv2_policy="off")}
local = {t["function"]["name"] for t in ct.build_tool_schema(False, lv2_policy="local")}
full = {t["function"]["name"] for t in ct.build_tool_schema(False, lv2_policy="local_vt_ioc")}
check("off exposes investigate_local only", base == {"investigate_local"}, str(base))
check("local exposes investigate_local only", local == {"investigate_local"}, str(local))
check("local_vt_ioc exposes only two public tools", full == {"investigate_local", "vt_ioc_lookup"}, str(full))
check("server VT kill switch removes VT", "vt_ioc_lookup" not in {
    t["function"]["name"] for t in ct.build_tool_schema(
        False, lv2_policy="local_vt_ioc", local_enabled=True, vt_enabled=False)
})

sec("T2: VT deterministic allow/deny boundary")
allowed = {
    "44d88612fea8a8f36de82e1278abb02f": "hash",
    "3395856ce81f2b7382dee72602f798b642f14140": "hash",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "hash",
    "8.8.8.8": "ip",
    "8.8.4.4:53": "ip",
    "example.com": "fqdn",
}
for value, typ in allowed.items():
    ok, payload = chat_lv2.validate_vt_ioc(value)
    check(f"allowed {value}", ok and payload.get("ioc_type") == typ, str(payload))
for value, reason in {
    "https://example.com/a": "url_forbidden",
    r"C:\\Users\\user\\sample.exe": "filepath_forbidden",
    "sample.exe": "filename_or_invalid_fqdn",
    "user@example.com": "email_forbidden",
    "192.168.1.5": "non_global_ip",
    "224.0.0.1": "non_global_ip",
    "239.255.255.250": "non_global_ip",
    "ff02::1": "non_global_ip",
    "240.0.0.1": "non_global_ip",
    "255.255.255.255": "non_global_ip",
    "free text": "arbitrary_string",
}.items():
    ok, payload = chat_lv2.validate_vt_ioc(value)
    check(f"blocked {value}", not ok and payload.get("reason") == reason, str(payload))

sec("T3: VT proxy/timeout/cache and secret masking")
chat_lv2.clear_shared_cache()
calls = []
orig_lookup = chat_lv2.vt_post.lookup_ioc
try:
    def fake_lookup(value, key, **kwargs):
        calls.append((value, key, kwargs))
        return {"verdict": "clean", "positives": 0, "total": 70,
                "vt_error": "", "diagnostic": f"proxy=http://u:p@proxy:8080 key={key}"}
    chat_lv2.vt_post.lookup_ioc = fake_lookup
    r1 = chat_lv2.secure_vt_lookup(
        "example.com", api_key="SECRETKEY", proxy_url="http://u:p@proxy:8080",
        timeout=12, cache_ttl_seconds=60, rate_delay=0)
    r2 = chat_lv2.secure_vt_lookup(
        "example.com", api_key="SECRETKEY", proxy_url="http://u:p@proxy:8080",
        timeout=12, cache_ttl_seconds=60, rate_delay=0)
    check("first lookup calls VT once", len(calls) == 1, str(calls))
    check("proxy and timeout propagated", calls[0][2].get("proxies", {}).get("https") == "http://u:p@proxy:8080"
          and calls[0][2].get("timeout") == 12, str(calls[0]))
    check("second lookup is shared cache hit", r2.get("cache_hit") is True and len(calls) == 1, str(r2))
    check("API key and proxy credentials redacted", "SECRETKEY" not in json.dumps(r1)
          and "u:p@" not in json.dumps(r1), json.dumps(r1))
finally:
    chat_lv2.vt_post.lookup_ioc = orig_lookup
    chat_lv2.clear_shared_cache()

sec("T3b: VT requires explicit external-TI intent and exact current-turn grounding")
with tempfile.TemporaryDirectory(prefix="chat_grounded_") as td:
    root = Path(td)
    out = root / "jobA" / "output" / "run"
    out.mkdir(parents=True)
    (out / "analyzed_jobA.json").write_text(
        json.dumps(analyzed("C:\\secret\\project.alpha", iocs=["evil.example.com"]), ensure_ascii=False),
        encoding="utf-8")
    ctx = ct.ChatContext(out, root, vt_key="k", job_id="jobA", case_folder="CASE-1")
    calls = []
    orig_lookup = chat_lv2.vt_post.lookup_ioc
    try:
        chat_lv2.vt_post.lookup_ioc = lambda value, key, **kwargs: (
            calls.append(value) or {"verdict": "clean", "vt_error": "", "positives": 0, "total": 70})
        denied = ctx.tool_vt_ioc_lookup("secret.dev")
        ctx.current_user_message = "VTで example.com を確認してください"
        explicit = ctx.tool_vt_ioc_lookup("example.com")
        ctx.current_user_message = "evil.example.com がローカル証拠にありました"
        observed = ctx.tool_vt_ioc_lookup("evil.example.com")
        ctx.current_user_message = "VTで接続先 cdn.evil-c2.com を確認"
        parent_domain = ctx.tool_vt_ioc_lookup("evil-c2.com")
        ctx.current_user_message = "VTで mail.corp.internal.attacker.jp を確認"
        suffix_domain = ctx.tool_vt_ioc_lookup("attacker.jp")
        ctx.current_user_message = "VTで evil.com を確認"
        partial_domain = ctx.tool_vt_ioc_lookup("il.com")
        long_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        ctx.current_user_message = "VTで " + long_hash + " を確認"
        partial_hash = ctx.tool_vt_ioc_lookup(long_hash[:32])
        check("no explicit external intent is rejected", denied.get("reason") == "external_ti_not_explicitly_requested"
              and denied.get("external_request") is False, str(denied))
        check("exact IOC plus explicit VT request is allowed", "example.com" in calls, str(calls))
        check("local evidence alone never authorizes VT", observed.get("reason") == "external_ti_not_explicitly_requested"
              and "evil.example.com" not in calls, str(observed))
        check("parent domain substring is rejected", parent_domain.get("reason") == "ioc_not_grounded",
              str(parent_domain))
        check("suffix domain substring is rejected", suffix_domain.get("reason") == "ioc_not_grounded",
              str(suffix_domain))
        check("partial domain substring is rejected", partial_domain.get("reason") == "ioc_not_grounded",
              str(partial_domain))
        check("partial hash substring is rejected", partial_hash.get("reason") == "ioc_not_grounded",
              str(partial_hash))
    finally:
        chat_lv2.vt_post.lookup_ioc = orig_lookup
        chat_lv2.clear_shared_cache()

sec("T4: 429 Retry-After controlled retry")
seq = []
orig_lookup = chat_lv2.vt_post.lookup_ioc
orig_sleep = chat_lv2.time.sleep
try:
    def fake_429(value, key, **kwargs):
        seq.append(value)
        if len(seq) == 1:
            return {"verdict": "error", "vt_error": "rate_limited", "retry_after": 1}
        return {"verdict": "clean", "vt_error": "", "positives": 0, "total": 70}
    chat_lv2.vt_post.lookup_ioc = fake_429
    chat_lv2.time.sleep = lambda _seconds: None
    result = chat_lv2.secure_vt_lookup(
        "8.8.8.8", api_key="k", retry_429_max_seconds=2,
        cache_ttl_seconds=0, rate_delay=0)
    check("429 retried once", len(seq) == 2 and result.get("external_request_count") == 2, str(result))
finally:
    chat_lv2.vt_post.lookup_ioc = orig_lookup
    chat_lv2.time.sleep = orig_sleep
    chat_lv2.clear_shared_cache()

sec("T5: case-scoped cross-host search, dedupe and symlink rejection")
with tempfile.TemporaryDirectory(prefix="chat_lv2_jobs_") as td:
    root = Path(td)
    meta = {}
    for jid, folder in (("jobA", "CASE-1"), ("jobB", "CASE-1"), ("jobC", "CASE-2")):
        out = root / jid / "output" / "run"
        out.mkdir(parents=True)
        (out / f"analyzed_{jid}.json").write_text(
            json.dumps(analyzed("evil.example.com", source_index=1), ensure_ascii=False), encoding="utf-8")
        # VT variant should be selected exclusively; same logical entry must not be doubled.
        (out / f"analyzed_{jid}_vt.json").write_text(
            json.dumps(analyzed("evil.example.com", source_index=1), ensure_ascii=False), encoding="utf-8")
        meta[jid] = {"job_id": jid, "folder": folder, "status": "done"}
    outside = root.parent / (root.name + "_outside")
    outside.mkdir(exist_ok=True)
    try:
        (root / "jobD").symlink_to(outside, target_is_directory=True)
        meta["jobD"] = {"job_id": "jobD", "folder": "CASE-1", "status": "done"}
    except OSError:
        pass

    ctx = ct.ChatContext(root / "jobA" / "output" / "run", root,
                         job_id="jobA", case_folder="CASE-1", jobs_metadata=meta,
                         lv2_policy="local")
    result = ctx.tool_cross_host_search("evil.example.com")
    check("current job separated", result.get("current_job_match_count") == 1, str(result))
    check("same-case other host only", result.get("other_host_job_ids") == ["jobB"], str(result))
    check("base/_vt are not double counted", result.get("count") == 1, str(result))
    check("other case excluded", "jobC" not in json.dumps(result), str(result))
    if "jobD" in meta:
        check("symlink job skipped", result.get("scan_summary", {}).get("skipped_reasons", {}).get("job_symlink", 0) >= 1,
              str(result.get("scan_summary")))
    no_folder = ct.ChatContext(root / "jobA" / "output", root,
                               job_id="jobA", case_folder="", jobs_metadata={"jobA": {"folder": ""}})
    blocked = no_folder.tool_cross_host_search("evil")
    check("empty case folder rejected", blocked.get("reason") == "case_folder_required", str(blocked))

sec("T6: Lv.2 count is per individual tool call")
with tempfile.TemporaryDirectory() as td:
    ctx = ct.ChatContext(td, td, vt_key="dummy")
    ctx.lv2_call_count = ct.LV2_MAX_CALLS_PER_SESSION - 1
    # First call is syntactically rejected but still consumes the attempt budget.
    first = ctx.tool_vt_ioc_lookup(r"C:\\secret\\x.exe")
    second = ctx.tool_vt_ioc_lookup("8.8.8.8")
    check("forbidden attempt does not transmit", first.get("external_request") is False, str(first))
    check("next individual call hits session limit", "上限" in second.get("error", ""), str(second))

sec("T7: audit log retains context and masks credentials")
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "audit.jsonl"
    ctx = ct.ChatContext(td, td, vt_key="APISECRET", vt_proxy="http://user:pass@proxy:8080",
                         job_id="jobA", case_folder="CASE-1", lv2_policy="local_vt_ioc")
    ct.append_audit_log(
        p, "vt_ioc_lookup", {"ioc_value": "example.com"},
        {"error": "proxy_error http://user:pass@proxy:8080 APISECRET", "external_request": True},
        ctx=ctx, elapsed_seconds=0.25)
    text = p.read_text(encoding="utf-8")
    row = json.loads(text)
    check("audit contains job/case/policy", row.get("job_id") == "jobA"
          and row.get("case_folder") == "CASE-1" and row.get("lv2_policy") == "local_vt_ioc", text)
    check("audit masks secrets", "APISECRET" not in text and "user:pass" not in text, text)
    check("audit records external flag/duration", row.get("external_network") is True
          and row.get("elapsed_seconds") == 0.25, text)

sec("T8: audit write failure does not drop chat or external-call evidence")
with tempfile.TemporaryDirectory(prefix="chat_audit_failure_") as td:
    root = Path(td)
    out = root / "jobA" / "output" / "run"
    out.mkdir(parents=True)
    blocker = root / "blocked_parent"
    blocker.write_text("not a directory", encoding="utf-8")
    bad_log = blocker / "chat_tool_log.jsonl"

    class StubMsg:
        def __init__(self, content=None, tool_calls=None):
            self.content = content
            self.tool_calls = tool_calls

    class StubToolCall:
        def __init__(self):
            self.id = "call-1"
            self.function = type("F", (), {
                "name": "vt_ioc_lookup",
                "arguments": json.dumps({"ioc_value": "example.com"}),
            })()
        def model_dump(self):
            return {"id": self.id, "type": "function",
                    "function": {"name": self.function.name,
                                 "arguments": self.function.arguments}}

    class StubResp:
        def __init__(self, msg):
            self.choices = [type("C", (), {"message": msg})()]

    class StubClient:
        def __init__(self):
            self.calls = 0
            outer = self
            class Completions:
                def create(self, **_kwargs):
                    outer.calls += 1
                    if outer.calls == 1:
                        return StubResp(StubMsg(None, [StubToolCall()]))
                    return StubResp(StubMsg("VT照会結果を確認しました。", None))
            self.chat = type("Chat", (), {"completions": Completions()})()

    ctx = ct.ChatContext(out, root, vt_key="k", job_id="jobA",
                         case_folder="CASE-1", lv2_policy="local_vt_ioc")
    ct.clear_audit_fallback_records()
    chat_lv2.clear_shared_cache()
    vt_calls = []
    orig_lookup = chat_lv2.vt_post.lookup_ioc
    try:
        chat_lv2.vt_post.lookup_ioc = lambda value, key, **kwargs: (
            vt_calls.append(value) or {"verdict": "clean", "vt_error": "",
                                       "positives": 0, "total": 70})
        result = ct.run_chat_turn(
            StubClient(), "stub-model",
            [{"role": "system", "content": "system"},
             {"role": "user", "content": "example.com をVTで確認してください"}],
            ctx, tool_log_path=bad_log, lv2_policy="local_vt_ioc")
        fallback = ct.get_audit_fallback_records()
        fallback_file = root / "_audit_fallback" / "jobA" / "chat_tool_log.jsonl"
        phases = {row.get("audit_phase") for row in fallback if row.get("tool") == "vt_ioc_lookup"}
        completed_external = any(
            row.get("tool") == "vt_ioc_lookup"
            and row.get("audit_phase") == "completed"
            and row.get("external_network") is True
            for row in fallback
        )
        check("chat continues after primary audit failure",
              result.get("reply") == "VT照会結果を確認しました。", str(result))
        check("external VT request completed once", vt_calls == ["example.com"], str(vt_calls))
        check("reserved and completed audit survive in memory fallback",
              {"reserved", "completed"}.issubset(phases) and completed_external, str(fallback))
        check("fallback audit file is written", fallback_file.exists()
              and '"audit_write_status": "fallback"' in fallback_file.read_text(encoding="utf-8"))
    finally:
        chat_lv2.vt_post.lookup_ioc = orig_lookup
        chat_lv2.clear_shared_cache()
        ct.clear_audit_fallback_records()

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
