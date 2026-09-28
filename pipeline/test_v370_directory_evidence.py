#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 directory evidence, determinism, coverage and raw-index regressions."""
from __future__ import annotations

import ast
import hashlib
import json
import random
import tempfile
from pathlib import Path

import analyze_section as a
import budget_profile
import depth2_select as d2
import directory_index
import directory_policy as dp
import ioc_utils
import chat_lv2
import report_gen
import pdf_export
import runtime_identity
import compare_analyzed
import comparison_provenance
import source_id
import server
from chat_tools import ChatContext
from version import ANALYSIS_SCHEMA_VERSION, BUDGET_PROFILE_DEFAULT, PIPELINE_VERSION

PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail="") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [OK]  {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}: {detail}")


def entry(path: str, index: int = 0, *, size: str = "371") -> dict:
    parent, _, name = path.rpartition("\\")
    return {
        "date": "2026/07/15  10:09",
        "size": size,
        "name": name,
        "path": path,
        "dir": parent,
        "source_id": f"directory:{index:08d}",
    }


def scored(entries: list[dict]) -> list[tuple[int, str, dict]]:
    out = []
    for value in entries:
        cls = a._classify_dir_entry(value)
        if cls != "D":
            out.append((a._dir_anomaly_score(value, cls), cls, value))
    return out


def selected_digest(entries: list[dict]) -> tuple[str, dict, list[str]]:
    selected, _overflow, info = a._select_dir_llm_entries(
        scored(entries), max_llm=200, sig_max=3,
        m1_max=80, m1_parent_max=8, m1_placement_max=32,
    )
    keys = sorted(dp.entry_path(value).casefold() for value in selected)
    return hashlib.sha256("\n".join(keys).encode("utf-8")).hexdigest(), info, keys


print("[1] identity")
check("pipeline version is 3.71", PIPELINE_VERSION == "3.71", PIPELINE_VERSION)
check("analysis schema is 2.1", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("budget profile is v370", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)
try:
    identity = runtime_identity.assert_runtime_identity()
    check("runtime identity guard", identity["pipeline_version"] == "3.71", identity)
except Exception as exc:
    check("runtime identity guard", False, exc)

print("\n[2] canonical extension policy")
canon = set(dp.EXECUTABLE_EXTS)
check("IOC extensions cover canonical execution set", not (canon - set(ioc_utils._KNOWN_FILE_EXTS)), sorted(canon - set(ioc_utils._KNOWN_FILE_EXTS)))
check("VT extensions cover canonical execution set", not (canon - set(ioc_utils._VT_FILEPATH_EXTS)), sorted(canon - set(ioc_utils._VT_FILEPATH_EXTS)))
for ext in (".vbe", ".jse", ".wsf", ".msi", ".msp", ".cmd"):
    candidate = entry(rf"C:\Users\Public\Music\sample{ext}")
    check(f"Level1 covers {ext}", a.entry_matches_level1("directory", candidate))
    check(f"M1/floor covers {ext}", dp.evidence_tier(candidate) == "M1" and a._floor_rule(candidate["path"]) is not None)
    check(f"IOC classifies {ext} path", ioc_utils.classify_ioc(candidate["path"]) == "filepath", ioc_utils.classify_ioc(candidate["path"]))
check(".url is treated as a filename, not an FQDN", ".url" in ioc_utils._KNOWN_FILE_EXTS)
valid_url_name, url_payload = chat_lv2.validate_vt_ioc("sample.url")
check("bare .url filename is blocked before VT", not valid_url_name and url_payload.get("reason") in {"filename_or_invalid_fqdn", "invalid_tld"}, url_payload)
valid_com, com_payload = chat_lv2.validate_vt_ioc("example.com")
check("valid .com domain remains allowed", valid_com and com_payload.get("ioc_type") == "fqdn", com_payload)
valid_fake, fake_payload = chat_lv2.validate_vt_ioc("sample.notarealtld")
check("invalid TLD is blocked by second guard", not valid_fake and fake_payload.get("reason") == "invalid_tld", fake_payload)
source = Path(dp.__file__).read_text(encoding="utf-8")
try:
    ast.parse(source, feature_version=(3, 10))
    py310_ok = True
except SyntaxError:
    py310_ok = False
check("directory_policy parses with Python 3.10 grammar", py310_ok)

print("\n[3] feature scoring")
wef = entry(r"C:\Users\Public\Music\wef.vbe", 1)
wef_cls = a._classify_dir_entry(wef)
check("wef.vbe score is path-based and high priority", a._dir_anomaly_score(wef, wef_cls) >= 120, a._dir_anomaly_score(wef, wef_cls))
variants = {
    "double extension": entry(r"C:\Users\u\Downloads\invoice.pdf.vbe", 2),
    "Startup": entry(r"C:\Users\u\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.vbe", 3),
    "Recycle Bin": entry(r"C:\$Recycle.Bin\S-1-5-21\payload.vbe", 4),
}
for label, value in variants.items():
    score = a._dir_anomaly_score(value, a._classify_dir_entry(value))
    check(f"{label} VBE receives anomaly score", score > 0, score)

print("\n[4] bounded M1 and residual Tier R")
def alpha_name(i: int) -> str:
    alphabet = "ghijklmnopqrstuvwxyz"
    chars = []
    n = i
    for _ in range(5):
        chars.append(alphabet[n % len(alphabet)])
        n //= len(alphabet)
    return "risk_" + "".join(chars)

m1 = [entry(rf"C:\Users\Public\Music\junk_{alpha_name(i)}.exe", i) for i in range(200)]
r_entries = [entry(rf"C:\Users\u\Downloads\{alpha_name(i)}.exe", 1000 + i) for i in range(220)]
_digest, info, _keys = selected_digest(m1 + r_entries)
check("normal directory cap remains 200", info["selected_total"] == 200, info)
check("same M1 parent is bounded to 8", info["tier_selected"]["M1"] == 8, info)
check("Tier R consumes all 192 residual slots", info["tier_selected"]["R"] == 192, info)
check("Tier R has no fixed 100 cap", info["tier_selected"]["R"] > 100, info)
check("deferred reason accounting is complete", sum(info["deferred_reason_counts"].values()) == sum(info["tier_deferred"].values()), info)
check("deferred reason semantics are explicit",
      info.get("deferred_reason_semantics", {}).get("signature_diversity")
      == "duplicate signature encountered before selection budget was exhausted", info)
check("sig_deferred has compatibility alias", info["sig_deferred"] == info["n_deferred"], info)
check("parent audit proves cap", all(int(count) <= 8 for _parent, count in info["m1_selected_by_parent_top"]), info)
check("coverage degradation covers all tiers", info["coverage_degraded"] is True, info)
m0_flood = [entry(rf"C:\Users\u\Downloads\invoice_{i:03d}.pdf.vbe", 3000 + i) for i in range(100)]
_m0_selected, _m0_overflow, m0_info = a._select_dir_llm_entries(
    scored(m0_flood), max_llm=200, sig_max=3,
    m1_max=80, m1_parent_max=8, m1_placement_max=32,
)
check("M0 same-signature flood is bounded by sig_max",
      m0_info["tier_selected"]["M0"] == 3
      and m0_info["sig_deferred"] == 97, m0_info)
deep_appdata_js = entry(r"C:\Users\u\AppData\Local\Browser\Extensions\abcdef\script.js", 4000)
check("deep AppData/browser JS remains Tier R",
      dp.evidence_tier(deep_appdata_js) == "R", dp.evidence_tier(deep_appdata_js))
known_temp = entry(r"C:\Users\u\AppData\Local\Temp\stage\payload.vbe", 4001)
deep_temp = entry(r"C:\Users\u\AppData\Local\Temp\vendor\package\assets\payload.js", 4002)
arbitrary_temp = entry(r"C:\node_modules\pkg\temp\build.js", 4003)
browser_temp = entry(r"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Extensions\x\temp\y.js", 4004)
check("known shallow user temp remains M1", dp.m1_placement(known_temp) == "general_temp", dp.m1_placement(known_temp))
check("deep known-temp descendant remains a Level1 Tier-R candidate",
      a.entry_matches_level1("directory", deep_temp)
      and dp.evidence_tier(deep_temp) == "R"
      and not dp.m1_placement(deep_temp),
      (a.entry_matches_level1("directory", deep_temp), dp.evidence_tier(deep_temp), dp.m1_placement(deep_temp)))
check("arbitrary temp component does not gain Level1 admission",
      not a.entry_matches_level1("directory", arbitrary_temp)
      and dp.evidence_tier(arbitrary_temp) == "R",
      (a.entry_matches_level1("directory", arbitrary_temp), dp.evidence_tier(arbitrary_temp)))
check("browser-extension temp component does not gain Level1 admission",
      not a.entry_matches_level1("directory", browser_temp)
      and dp.evidence_tier(browser_temp) == "R",
      (a.entry_matches_level1("directory", browser_temp), dp.evidence_tier(browser_temp)))
# Deep known-temp evidence must be visible in deferred accounting even when not selected.
strong_m0 = entry(r"C:\Users\u\Downloads\invoice.pdf.vbe", 4005)
_admitted = a.apply_level1_filter("directory", [deep_temp, strong_m0])
_admitted_scored = scored(_admitted)
_admitted_selected, _admitted_overflow, _admitted_info = a._select_dir_llm_entries(
    _admitted_scored, max_llm=1, sig_max=3,
    m1_max=80, m1_parent_max=8, m1_placement_max=32,
)
check("deep known-temp Tier-R candidate is counted when deferred",
      deep_temp in _admitted
      and _admitted_info["tier_total"]["R"] == 1
      and _admitted_info["tier_deferred"]["R"] == 1
      and sum(_admitted_info["deferred_reason_counts"].values())
          == sum(_admitted_info["tier_deferred"].values()),
      _admitted_info)

print("\n[5] Depth1 input-order independence")
base_hash, _base_info, base_keys = selected_digest(m1 + r_entries)
all_same = True
for seed in (1, 2, 3, 42, 12345):
    shuffled = list(m1 + r_entries)
    random.Random(seed).shuffle(shuffled)
    digest, _info, keys = selected_digest(shuffled)
    all_same &= digest == base_hash and keys == base_keys
check("Depth1 selection set is shuffle-invariant", all_same, base_hash)
check("wef.vbe remains selected under noise", any(path.endswith("\\wef.vbe") for path in selected_digest(m1 + r_entries + [wef])[2]))

print("\n[6] Depth2 input-order independence")
budget_profile.reset_profile()
small_entries = m1[:40] + r_entries[:80] + [wef]

def depth2_paths(values: list[dict]) -> tuple[list[str], dict]:
    # Raw indexes intentionally follow the supplied order. Selected paths must not.
    pools = {"directory": [(idx, value) for idx, value in enumerate(values)]}
    result = d2.plan_depth2_selection(
        pools, ctx=d2.empty_ctx(), section_order=["directory"], ledgers={}, lean=True,
        novelty_pools={"directory": []}, context="",
    )["directory"]
    paths = sorted(dp.entry_path(value).casefold() for _idx, value in result["selected"])
    return paths, result

try:
    depth_base, depth_result = depth2_paths(small_entries)
    depth_same = True
    for seed in (7, 17, 71):
        shuffled = list(small_entries)
        random.Random(seed).shuffle(shuffled)
        got, _result = depth2_paths(shuffled)
        depth_same &= got == depth_base
    check("Depth2 selection set is shuffle-invariant", depth_same, depth_base[:5])
    check("Depth2 M1 policy remains bounded", depth_result["directory_policy"]["tier_selected"]["M1"] <= 8, depth_result["directory_policy"])
except Exception as exc:
    check("Depth2 deterministic planner", False, repr(exc))

print("\n[7] report/chat coverage visibility")
policy = {
    "tier_total": {"M0": 0, "M1": 281, "R": 2687},
    "tier_selected": {"M0": 0, "M1": 76, "R": 124},
    "tier_deferred": {"M0": 0, "M1": 205, "R": 2563},
    "deferred_reason_counts": {"signature_diversity": 852, "m1_policy_bound": 205, "over_normal_budget": 1711},
    "coverage_degraded": True,
}
analyzed_fixture = {"meta": {"hostname": "HOST"}, "sections": {"directory": {"entries": [], "_directory_policy": policy}}}
notice = "\n".join(report_gen._directory_coverage_notice(analyzed_fixture))
check("report exposes evaluated/deferred counts", "2,968件中" in notice and "2,768件" in notice, notice)
standard_md = report_gen.generate_report(analyzed_fixture, {}, full=False)
full_md = report_gen.generate_report(analyzed_fixture, {}, full=True)
check("standard Markdown exposes coverage warning", "2,968件中" in standard_md and "2,768件" in standard_md)
check("full Markdown exposes coverage warning", "2,968件中" in full_md and "2,768件" in full_md)
pdf_bytes = pdf_export.md_to_pdf(standard_md, title="v3.70 coverage test")
check("PDF conversion consumes coverage-bearing Markdown", pdf_bytes.startswith(b"%PDF") and len(pdf_bytes) > 1000, len(pdf_bytes))

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    (root / "analyzed_HOST.json").write_text(json.dumps(analyzed_fixture, ensure_ascii=False), encoding="utf-8")
    exact_shadow = [
        entry(r"C:\Temp\a", 9001),
        entry(r"C:\Temp\alpha.exe", 9002),
        entry(r"C:\Temp\beta.dat", 9003),
    ]
    parsed = {"sections": {"directory": [wef] + r_entries[:20] + exact_shadow}}
    parsed_path = root / "parsed_HOST.json"
    parsed_path.write_text(json.dumps(parsed, ensure_ascii=False), encoding="utf-8")
    ctx = ChatContext(root, root)
    exact = ctx.tool_search_keyword("wef.vbe")
    check("chat fallback uses SQLite raw index", exact.get("count") == 1 and exact.get("scope") == "parsed_directory_raw_index", exact)
    shadow = ctx.tool_search_keyword("a")
    check("exact filename does not suppress substring matches", shadow.get("total", shadow.get("count")) >= 3 and shadow.get("truncated") is False, shadow)
    check("exact filename is ordered first", bool(shadow.get("hits")) and shadow["hits"][0].get("name", "").casefold() == "a", shadow)
    check("chat keeps parsed JSON out of memory", getattr(ctx, "_parsed", None) is None)
    broad = ctx.tool_search_keyword(".exe")
    check("chat broad search is bounded and scoped", broad.get("raw_fallback_searched") is True and broad.get("scope") == "parsed_directory_raw_index", broad)
    missing = ctx.tool_search_keyword("definitely-not-present.xyz")
    check("chat never asserts absolute absence", "絶対的な不存在" in missing.get("note", ""), missing)
    folder = ctx.tool_list_directory_files(r"C:\Users\Public\Music")
    check("folder listing uses raw index", folder.get("scope") == "parsed_directory_raw_index" and folder.get("total", 0) >= 1, folder)
    coverage = ctx.directory_coverage_summary()
    check("chat context exposes coverage counts", coverage.get("not_individually_evaluated_count") == 2768, coverage)
    prompt = server._build_chat_system_prompt(ctx, {"lv2_policy": "disabled"})
    check("chat system prompt keeps evidence-derived coverage out of system layer", "未個別評価 2768件" not in prompt and "investigate_local" in prompt, prompt[:500])
    index_path = directory_index.index_path_for(parsed_path)
    check("persistent directory index created", index_path.is_file(), index_path)

print("\n[8] comparison compatibility")
check("comparison provenance schema remains 1",
      comparison_provenance.COMPARISON_PROVENANCE_SCHEMA_VERSION == "1",
      comparison_provenance.COMPARISON_PROVENANCE_SCHEMA_VERSION)
check("source-id algorithm remains 1",
      source_id.SOURCE_ID_ALGORITHM_VERSION == "1",
      source_id.SOURCE_ID_ALGORITHM_VERSION)
policy_only_a = {"meta": {}, "sections": {"directory": {"entries": [], "_directory_policy": {"coverage_degraded": False}}}}
policy_only_b = {"meta": {}, "sections": {"directory": {"entries": [], "_directory_policy": {"coverage_degraded": True}}}}
check("directory policy metadata is not a comparable evidence row",
      list(compare_analyzed._iter_comparable_entries(policy_only_a)) == []
      and list(compare_analyzed._iter_comparable_entries(policy_only_b)) == [])
check("directory policy metadata does not change comparison multisets",
      compare_analyzed.entry_multiset(policy_only_a) == compare_analyzed.entry_multiset(policy_only_b))

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
