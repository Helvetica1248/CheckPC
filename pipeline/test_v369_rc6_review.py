#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 Claude review R1-R3 formal regression tests."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import chat_lv2
import chat_tools as ct
from version import ANALYSIS_SCHEMA_VERSION, BUDGET_PROFILE_DEFAULT, PIPELINE_VERSION

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: object = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [OK]  {name}")
    else:
        FAIL += 1
        suffix = f": {detail}" if detail else ""
        print(f"  [FAIL] {name}{suffix}")


def section(title: str) -> None:
    print(f"\n{'-' * 64}\n  {title}\n{'-' * 64}")


section("V1: rc6 identity")
check("V1-1 pipeline version", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("V1-2 analysis schema", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("V1-3 provisional profile", BUDGET_PROFILE_DEFAULT == "v370",
      BUDGET_PROFILE_DEFAULT)

section("R1: global-unicast-only VT IP boundary")
for value in ("224.0.0.1", "239.255.255.250", "ff02::1", "240.0.0.1", "255.255.255.255"):
    valid, payload = chat_lv2.validate_vt_ioc(value)
    check(f"R1 reject {value}", not valid and payload.get("reason") == "non_global_ip", payload)
for value in ("8.8.8.8", "2001:4860:4860::8888"):
    valid, payload = chat_lv2.validate_vt_ioc(value)
    check(f"R1 allow global unicast {value}", valid and payload.get("ioc_type") == "ip", payload)

section("R2: exact-token grounding")
sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
check("R2-1 full subdomain only",
      chat_lv2.extract_vt_iocs_from_text("接続先は cdn.evil-c2.com でした") == {"cdn.evil-c2.com"})
check("R2-2 full deep domain only",
      chat_lv2.extract_vt_iocs_from_text("mail.corp.internal.attacker.jp") ==
      {"mail.corp.internal.attacker.jp"})
check("R2-3 no partial domain",
      "il.com" not in chat_lv2.extract_vt_iocs_from_text("evil.com は危険"))
check("R2-4 no partial hash",
      sha256[:32] not in chat_lv2.extract_vt_iocs_from_text(sha256))
check("R2-5 URL/path/email do not authorize components",
      not chat_lv2.extract_vt_iocs_from_text(
          r"https://evil.example/a C:\case\secret.project analyst@example.com"))
check("R2-6 explicit FQDN:port normalizes to FQDN",
      chat_lv2.extract_vt_iocs_from_text("example.com:443") == {"example.com"})

with tempfile.TemporaryDirectory(prefix="rc6_grounding_") as td:
    root = Path(td)
    out = root / "jobA" / "output" / "run"
    out.mkdir(parents=True)
    ctx = ct.ChatContext(out, root, vt_key="k", job_id="jobA",
                         case_folder="CASE-1", lv2_policy="local_vt_ioc")
    ctx.current_user_message = "接続先は cdn.evil-c2.com でした"
    allowed, _ = ctx._vt_ioc_is_grounded("cdn.evil-c2.com")
    parent_allowed, parent_payload = ctx._vt_ioc_is_grounded("evil-c2.com")
    check("R2-7 exact IOC grounded", allowed)
    check("R2-8 parent domain rejected", not parent_allowed and
          parent_payload.get("reason") == "ioc_not_grounded", parent_payload)

section("R3: audit failure fallback and chat continuity")
with tempfile.TemporaryDirectory(prefix="rc6_audit_") as td:
    root = Path(td)
    out = root / "jobA" / "output" / "run"
    out.mkdir(parents=True)
    blocker = root / "blocked_parent"
    blocker.write_text("not a directory", encoding="utf-8")
    bad_log = blocker / "chat_tool_log.jsonl"
    ctx = ct.ChatContext(out, root, vt_key="k", job_id="jobA",
                         case_folder="CASE-1", lv2_policy="local_vt_ioc")

    ct.clear_audit_fallback_records()
    status = ct.append_audit_log(
        bad_log, "vt_ioc_lookup", {"ioc_value": "example.com"},
        {"external_request": True, "cache_hit": False}, ctx=ctx,
        audit_phase="completed", external_network_planned=True)
    records = ct.get_audit_fallback_records()
    check("R3-1 append failure is contained", status.get("fallback") is True, status)
    check("R3-2 memory fallback retains external evidence",
          any(row.get("external_network") is True for row in records), records)
    fallback_file = root / "_audit_fallback" / "jobA" / "chat_tool_log.jsonl"
    check("R3-3 per-job fallback file written", fallback_file.exists())

    class StubMessage:
        def __init__(self, content=None, tool_calls=None):
            self.content = content
            self.tool_calls = tool_calls

    class StubToolCall:
        def __init__(self):
            self.id = "call-1"
            self.function = type("Function", (), {
                "name": "vt_ioc_lookup",
                "arguments": json.dumps({"ioc_value": "example.com"}),
            })()

        def model_dump(self):
            return {
                "id": self.id,
                "type": "function",
                "function": {
                    "name": self.function.name,
                    "arguments": self.function.arguments,
                },
            }

    class StubResponse:
        def __init__(self, message):
            self.choices = [type("Choice", (), {"message": message})()]

    class StubClient:
        def __init__(self):
            self.calls = 0
            outer = self

            class Completions:
                def create(self, **_kwargs):
                    outer.calls += 1
                    if outer.calls == 1:
                        return StubResponse(StubMessage(None, [StubToolCall()]))
                    return StubResponse(StubMessage("監査退避後も回答を継続しました。", None))

            self.chat = type("Chat", (), {"completions": Completions()})()

    ct.clear_audit_fallback_records()
    chat_lv2.clear_shared_cache()
    vt_calls: list[str] = []
    original_lookup = chat_lv2.vt_post.lookup_ioc
    try:
        chat_lv2.vt_post.lookup_ioc = lambda value, key, **kwargs: (
            vt_calls.append(value) or {
                "verdict": "clean", "vt_error": "", "positives": 0, "total": 70,
            })
        turn = ct.run_chat_turn(
            StubClient(), "stub-model",
            [{"role": "system", "content": "system"},
             {"role": "user", "content": "example.com をVTで確認してください"}],
            ctx, tool_log_path=bad_log, lv2_policy="local_vt_ioc")
        records = ct.get_audit_fallback_records()
        phases = {row.get("audit_phase") for row in records
                  if row.get("tool") == "vt_ioc_lookup"}
        completed_external = any(
            row.get("tool") == "vt_ioc_lookup"
            and row.get("audit_phase") == "completed"
            and row.get("external_network") is True
            for row in records
        )
        check("R3-4 chat response continues", turn.get("reply") == "監査退避後も回答を継続しました。",
              turn)
        check("R3-5 VT request occurred once", vt_calls == ["example.com"], vt_calls)
        check("R3-6 reservation and completion retained",
              {"reserved", "completed"}.issubset(phases) and completed_external, records)
    finally:
        chat_lv2.vt_post.lookup_ioc = original_lookup
        chat_lv2.clear_shared_cache()
        ct.clear_audit_fallback_records()

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
