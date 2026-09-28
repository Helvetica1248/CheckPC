#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 minimal audit hardening regressions."""
from __future__ import annotations
import copy, json, tempfile
from pathlib import Path

import analyze_section
from comparison_provenance import (
    PARSED_ANALYSIS_EXEMPT_SECTIONS, annotate_parsed_document,
    missing_analyzed_raw_sections, validate_section_provenance,
)
from validate_run_provenance import validate
from compare_runs import compare_runs, RunArtifacts
from package_integrity import verify_package_integrity
from build_reproducibility_bundle import build_bundle
from source_id import assign_source_ids
from version import PIPELINE_VERSION, ANALYSIS_SCHEMA_VERSION, BUDGET_PROFILE_DEFAULT

PASS=FAIL=0
def check(name, cond, detail=""):
    global PASS,FAIL
    if cond: PASS+=1; print(f"  [OK]  {name}")
    else: FAIL+=1; print(f"  [FAIL] {name}: {detail}")

print("--- identity ---")
check("pipeline", PIPELINE_VERSION=="3.70", PIPELINE_VERSION)
check("schema", ANALYSIS_SCHEMA_VERSION=="2.1", ANALYSIS_SCHEMA_VERSION)
check("profile", BUDGET_PROFILE_DEFAULT=="v370", BUDGET_PROFILE_DEFAULT)

print("--- parsed section coverage ---")
parsed={"meta":{"collection_id":"a"*64,"input_sha256":"a"*64},
        "sections":{"tasklist":[],"directory":[],"dns_cache":[]},"event_logs":{}}
for n,v in parsed["sections"].items(): assign_source_ids("a"*64,n,v)
annotate_parsed_document(parsed)
analyzed={"sections":{"directory":{"_provenance":{}},"dns_cache":{"_provenance":{}}}}
check("tasklist explicit exemption", PARSED_ANALYSIS_EXEMPT_SECTIONS==frozenset({"tasklist"}), PARSED_ANALYSIS_EXEMPT_SECTIONS)
check("all present except exempt", missing_analyzed_raw_sections(parsed,analyzed)==[], missing_analyzed_raw_sections(parsed,analyzed))
dropped=copy.deepcopy(analyzed); dropped["sections"].pop("dns_cache")
check("missing empty raw section detected", missing_analyzed_raw_sections(parsed,dropped)==["dns_cache"], missing_analyzed_raw_sections(parsed,dropped))
check("validator fails closed", any("dns_cache: analyzed section missing" in x for x in validate(parsed,dropped)), validate(parsed,dropped))

print("--- derived text provenance ---")
fixture={
 "meta":{"hostname":"FIX","collection_id":"b"*64,"input_sha256":"b"*64,
         "parser_version":ANALYSIS_SCHEMA_VERSION,"pipeline_version":PIPELINE_VERSION,
         "analysis_schema_version":ANALYSIS_SCHEMA_VERSION},
 "sections":{"psexec":"End of search: 1 match(es) found.\nC:\\Tools\\PsExec.exe"},
 "event_logs":{"security_1102":"Event ID: 1102","system_104":"Event ID: 104"},
 "evidence_quality":{"event_logs":{}},
}
res=analyze_section.analyze(fixture,1,object(),"qwen25-coder-32b-q3",
    target_sections=["security_1102","system_104","psexec"],lean=False)
for name in ("security_1102","system_104","psexec"):
    row=res["sections"][name]; prov=row.get("_provenance") or {}; entries=row.get("entries") or []
    check(f"{name} provenance", validate_section_provenance(prov)==[], validate_section_provenance(prov))
    check(f"{name} atomic raw", prov.get("raw_count")==1, prov)
    check(f"{name} source id", bool(entries and entries[0].get("source_id")), entries)
    check(f"{name} scope", prov.get("provenance_scope")=="derived_atomic_text", prov)

check("derived checker accepts complete", validate(fixture,res)==[], validate(fixture,res))
broken=copy.deepcopy(res); broken["sections"]["system_104"]["entries"][0].pop("source_id",None)
check("derived checker rejects missing source id", any("system_104: derived entry source_id missing" in x for x in validate(fixture,broken)), validate(fixture,broken))

print("--- known tools attribution ---")
sections={"directory":[{"path":r"C:\Temp\mimikatz.exe","source_id":"directory:fixture"}],
 "service":[],"appcompat_cache":[],"tasklist":[],"prefetch":[],"persistence_reg":[],
 "startup_folder":[],"ps_history":[]}
kt=analyze_section.analyze_known_tools(sections,"c"*64)
check("known_tools finding", len(kt.get("entries") or [])==1, kt)
check("known_tools source inherited", kt["entries"][0].get("source_id")=="directory:fixture", kt["entries"])
check("known_tools provenance", validate_section_provenance(kt.get("_provenance") or {})==[], kt.get("_provenance"))
check("known_tools derived scope", (kt.get("_provenance") or {}).get("provenance_scope")=="derived_findings", kt.get("_provenance"))

print("--- package integrity ---")
with tempfile.TemporaryDirectory() as td:
    root=Path(td); (root/"a.txt").write_text("ok",encoding="utf-8")
    import hashlib
    h=hashlib.sha256((root/"a.txt").read_bytes()).hexdigest()
    (root/"SHA256SUMS.txt").write_text(f"{h}  a.txt\n",encoding="utf-8")
    good=verify_package_integrity(root)
    check("package valid", good["valid"] and good["checked_files"]==1, good)
    (root/"a.txt").write_text("tampered",encoding="utf-8")
    bad=verify_package_integrity(root)
    check("package tamper rejected", not bad["valid"] and any("mismatch" in x for x in bad["errors"]), bad)
    target=root/"target.txt"; target.write_text("target",encoding="utf-8")
    link=root/"link.txt"
    try:
        link.symlink_to(target.name)
        lh=hashlib.sha256(target.read_bytes()).hexdigest()
        (root/"SHA256SUMS.txt").write_text(f"{lh}  link.txt\n",encoding="utf-8")
        linked=verify_package_integrity(root)
        check("package symlink rejected", not linked["valid"] and any("symlink" in x for x in linked["errors"]), linked)
    except OSError:
        check("package symlink rejected", True, "symlink unavailable")


with tempfile.TemporaryDirectory() as td:
    root=Path(td)
    (root/"listed.txt").write_text("ok\n",encoding="utf-8")
    h=hashlib.sha256((root/"listed.txt").read_bytes()).hexdigest()
    (root/"SHA256SUMS.txt").write_text(f"{h}  listed.txt\n",encoding="utf-8")
    (root/"sitecustomize.py").write_text("raise SystemExit(1)\n",encoding="utf-8")
    result=verify_package_integrity(root)
    check("unlisted package file rejected", not result["valid"] and "unlisted file: sitecustomize.py" in result["errors"], result)

with tempfile.TemporaryDirectory() as td:
    root=Path(td)
    (root/"listed.txt").write_text("ok\n",encoding="utf-8")
    h=hashlib.sha256((root/"listed.txt").read_bytes()).hexdigest()
    (root/"SHA256SUMS.txt").write_text(f"{h}  listed.txt\n",encoding="utf-8")
    cache=root/"__pycache__"; cache.mkdir()
    (cache/"listed.cpython-310.pyc").write_bytes(b"cache")
    result=verify_package_integrity(root)
    check("runtime cache artifacts allowed", result["valid"], result)


print("--- downstream evidence bundle ---")
with tempfile.TemporaryDirectory() as td:
    root=Path(td)/"run"; root.mkdir()
    for name in ("parsed_FIX.json","analyzed_FIX.json","correlation_FIX.json","report_FIX.md","ingest_manifest.json"):
        (root/name).write_text(name,encoding="utf-8")
    out=Path(td)/"bundle.tar.gz"
    bundle=build_bundle(root,out)
    names=bundle["scope"]["bundle_included"]
    check("bundle includes downstream", all(x in names for x in ("correlation_FIX.json","report_FIX.md","ingest_manifest.json")), names)
    check("bundle scope remains explicit", bundle["scope"]["comparison_included"]==["parsed_*.json","analyzed_*.json"], bundle)
    check("bundle created", out.is_file() and len(bundle["bundle_sha256"])==64, bundle)

print("--- comparison scope ---")
# compare result construction is covered without disk loading by minimal artifacts.
meta={"input_sha256":"x","model":"m","pipeline_version":PIPELINE_VERSION,
 "analysis_schema_version":ANALYSIS_SCHEMA_VERSION,"depth":1,"analysis_mode":"LEAN",
 "budget_profile":BUDGET_PROFILE_DEFAULT,"budget_profile_fingerprint":"f",
 "max_inflight_llm":1,"pipeline_max_workers":1,"runtime_fingerprint":"r",
 "source_id_algorithm_version":"1","raw_evidence_fingerprint":"e",
 "section_raw_evidence":{},"package_manifest_sha256":"p"*64}
with tempfile.TemporaryDirectory() as td:
    root=Path(td); pp=root/"parsed.json"; ap=root/"analyzed.json"
    docp={"meta":meta,"sections":{},"event_logs":{}}; doca={"meta":meta,"sections":{}}
    pp.write_text(json.dumps(docp),encoding="utf-8"); ap.write_text(json.dumps(doca),encoding="utf-8")
    a=RunArtifacts("A",root,pp,ap,docp,doca); b=RunArtifacts("B",root,pp,ap,docp,doca)
    result=compare_runs("reproducibility",a,b)
    scope=result.get("comparison_scope") or {}
    check("scope includes parsed/analyzed", scope.get("included")==["parsed_*.json","analyzed_*.json","ingest_manifest.json (when present)"], scope)
    check("scope excludes downstream", "correlation_*.json" in (scope.get("excluded") or []), scope)

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL==0 else 1)
