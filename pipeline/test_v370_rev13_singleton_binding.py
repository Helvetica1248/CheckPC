#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 rev13 coverage-singleton binding regressions.

The rev13 recovery is intentionally narrow: a clean coverage-split retry that
has exactly one raw row and exactly one schema-valid LLM row may have its
source_index/source_id/identifier triple canonically re-bound.  Multi-entry
binding violations remain hard rejections and cannot be laundered through a
later singleton retry.
"""
from __future__ import annotations

import analyze_section as a
from analyze_section import ChunkSpec

PASS = FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [OK]  {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}: {detail}")


ROWS = [
    {"source_id": "netstat:a", "proto": "TCP", "local": "10.0.0.1:1234",
     "remote": "8.8.8.8:443", "state": "ESTABLISHED", "pid": "1"},
    {"source_id": "netstat:b", "proto": "TCP", "local": "10.0.0.1:1235",
     "remote": "1.1.1.1:443", "state": "ESTABLISHED", "pid": "2"},
]
IDENT = [a._canonical_identifier("netstat", row) for row in ROWS]
ORIG_CALL = a._call_llm_score_checked
ORIG_DEPTH = a.COVERAGE_MAX_SPLIT_DEPTH


def invoke(fake, rows=None, source_indices=None, split_depth=3):
    rows = list(rows if rows is not None else ROWS)
    source_indices = list(source_indices if source_indices is not None else [100, 101])
    a._call_llm_score_checked = fake
    a.COVERAGE_MAX_SPLIT_DEPTH = split_depth
    try:
        spec = ChunkSpec(rows, source_indices, max_tokens=1024)
        return a.call_llm_chunked(
            None, "m", "netstat", 1, rows, lean=True,
            chunk_plan={"specs": [spec]}, source_indices=source_indices)
    finally:
        a._call_llm_score_checked = ORIG_CALL
        a.COVERAGE_MAX_SPLIT_DEPTH = ORIG_DEPTH


def parent_omits_b(singleton_rows):
    def fake(client, model, section, depth, data_text, verbose=False,
             context="", lean=None, max_tokens_override=None):
        has_a = "netstat:a" in data_text
        has_b = "netstat:b" in data_text
        if has_a and has_b:
            return {"section": section, "entries": [{
                "source_index": 0, "source_id": "netstat:a",
                "identifier": IDENT[0], "score": "LOW", "reason": "A"
            }]}
        if has_b:
            return {"section": section, "entries": list(singleton_rows)}
        return {"section": section, "entries": []}
    return fake


def diag_of(errors):
    return errors[0] if errors else {}


# --- Multi-entry binding must remain fail-closed. ---
def multi_wrong_sid(client, model, section, depth, data_text, verbose=False,
                    context="", lean=None, max_tokens_override=None):
    return {"section": section, "entries": [
        {"source_index": 0, "source_id": "netstat:b", "identifier": IDENT[0],
         "score": "LOW", "reason": "wrong sid A"},
        {"source_index": 1, "source_id": "netstat:a", "identifier": IDENT[1],
         "score": "LOW", "reason": "wrong sid B"},
    ]}

out, _, errors, _ = invoke(multi_wrong_sid)
diag = diag_of(errors)
check("multi-entry source_id mismatch -> no accepted rows", out == [], out)
check("multi-entry source_id mismatch -> REJECT diagnostic",
      diag.get("rejection_reasons", {}).get("source_id_index_mismatch", 0) >= 2, diag)
check("multi-entry source_id mismatch is not singleton-laundered",
      diag.get("n_singleton_binding_repairs", 0) == 0 and
      sorted(diag.get("binding_rejected_indices", [])) == [100, 101], diag)


def multi_wrong_ident(client, model, section, depth, data_text, verbose=False,
                      context="", lean=None, max_tokens_override=None):
    return {"section": section, "entries": [
        {"source_index": 0, "source_id": "netstat:a", "identifier": IDENT[1],
         "score": "LOW", "reason": "wrong ident A"},
        {"source_index": 1, "source_id": "netstat:b", "identifier": IDENT[0],
         "score": "LOW", "reason": "wrong ident B"},
    ]}

out, _, errors, _ = invoke(multi_wrong_ident)
diag = diag_of(errors)
check("multi-entry identifier mismatch -> no accepted rows", out == [], out)
check("multi-entry identifier mismatch -> REJECT diagnostic",
      diag.get("rejection_reasons", {}).get("identifier_index_mismatch", 0) >= 2, diag)
check("multi-entry identifier mismatch is not singleton-laundered",
      diag.get("n_singleton_binding_repairs", 0) == 0 and
      sorted(diag.get("binding_rejected_indices", [])) == [100, 101], diag)


def multi_wrong_index(client, model, section, depth, data_text, verbose=False,
                      context="", lean=None, max_tokens_override=None):
    return {"section": section, "entries": [
        {"source_index": 1, "source_id": "netstat:a", "identifier": IDENT[0],
         "score": "LOW", "reason": "wrong index A"},
        {"source_index": 0, "source_id": "netstat:b", "identifier": IDENT[1],
         "score": "LOW", "reason": "wrong index B"},
    ]}

out, _, errors, _ = invoke(multi_wrong_index)
diag = diag_of(errors)
check("multi-entry source_index mismatch -> no accepted rows", out == [], out)
check("multi-entry source_index mismatch -> REJECT diagnostic",
      diag.get("rejection_reasons", {}).get("source_id_index_mismatch", 0) >= 2, diag)
check("multi-entry source_index mismatch is not singleton-laundered",
      diag.get("n_singleton_binding_repairs", 0) == 0 and
      sorted(diag.get("binding_rejected_indices", [])) == [100, 101], diag)

# --- Correct singleton retry remains ACCEPT without repair. ---
correct_b = [{"source_index": 0, "source_id": "netstat:b", "identifier": IDENT[1],
              "score": "LOW", "reason": "correct B"}]
out, _, errors, timings = invoke(parent_omits_b(correct_b))
check("singleton correct binding -> ACCEPT", len(out) == 2 and not errors, (out, errors))
check("singleton correct binding does not fabricate repair metadata",
      not out[1].get("_source_attribution_repair") and
      not any(t.get("singleton_binding_repair") for t in timings), (out, timings))

# --- source_id mistranscription is canonically repaired only on coverage retry. ---
wrong_sid_b = [{"source_index": 0, "source_id": "netstat:TYPO", "identifier": IDENT[1],
                "score": "LOW", "reason": "sid typo"}]
out, _, errors, timings = invoke(parent_omits_b(wrong_sid_b))
repair = out[1].get("_source_attribution_repair", {}) if len(out) == 2 else {}
check("singleton source_id mistranscription -> ACCEPT", len(out) == 2 and not errors, (out, errors))
check("singleton source_id -> canonical source_id", len(out) == 2 and out[1].get("source_id") == "netstat:b", out)
check("singleton source_id repair is audited",
      repair.get("method") == "coverage_singleton_canonical" and
      repair.get("original_source_id") == "netstat:TYPO" and
      "source_id" in repair.get("repaired_fields", []), repair)
check("singleton source_id repair timing is audited",
      any(t.get("singleton_binding_repair_method") == "coverage_singleton_canonical" for t in timings), timings)

# --- identifier mistranscription is canonically repaired. ---
wrong_ident_b = [{"source_index": 0, "source_id": "netstat:b", "identifier": IDENT[0],
                  "score": "LOW", "reason": "identifier typo"}]
out, _, errors, _ = invoke(parent_omits_b(wrong_ident_b))
repair = out[1].get("_source_attribution_repair", {}) if len(out) == 2 else {}
check("singleton identifier mistranscription -> ACCEPT", len(out) == 2 and not errors, (out, errors))
check("singleton identifier -> canonical identifier", len(out) == 2 and out[1].get("identifier") == IDENT[1], out)
check("singleton identifier repair is audited",
      repair.get("original_identifier") == IDENT[0] and
      "identifier" in repair.get("repaired_fields", []), repair)

# --- all three binding fields can be atomically repaired in the same narrow path. ---
all_wrong_b = [{"source_index": 9, "source_id": "netstat:TYPO", "identifier": IDENT[0],
                "score": "LOW", "reason": "all binding metadata wrong"}]
out, _, errors, _ = invoke(parent_omits_b(all_wrong_b))
repair = out[1].get("_source_attribution_repair", {}) if len(out) == 2 else {}
check("singleton triple mistranscription -> ACCEPT", len(out) == 2 and not errors, (out, errors))
check("singleton triple repaired atomically",
      len(out) == 2 and out[1].get("source_index") == 1 and
      out[1].get("source_id") == "netstat:b" and out[1].get("identifier") == IDENT[1], out)
check("singleton triple audit lists all fields",
      repair.get("repaired_fields") == ["source_index", "source_id", "identifier"], repair)
check("final attribution method records canonical singleton recovery",
      len(out) == 2 and out[1].get("_source_attribution_method") == "coverage_singleton_canonical", out)

# --- 0 returned rows stay unevaluated. ---
out, _, errors, _ = invoke(parent_omits_b([]))
diag = diag_of(errors)
check("singleton zero rows -> one row remains unevaluated",
      len(out) == 1 and diag.get("unevaluated_indices") == [101], (out, diag))
check("singleton zero rows -> no repair", diag.get("n_singleton_binding_repairs", 0) == 0, diag)

# --- >1 returned rows are explicit fail-closed cardinality violations. ---
two_b = [
    {"source_index": 0, "source_id": "netstat:b", "identifier": IDENT[1],
     "score": "LOW", "reason": "B1"},
    {"source_index": 0, "source_id": "netstat:b", "identifier": IDENT[1],
     "score": "LOW", "reason": "B2"},
]
out, _, errors, timings = invoke(parent_omits_b(two_b))
diag = diag_of(errors)
check("singleton multiple rows -> fail-closed unevaluated",
      len(out) == 1 and diag.get("unevaluated_indices") == [101], (out, diag))
check("singleton multiple rows -> explicit cardinality violation",
      diag.get("rejection_reasons", {}).get("singleton_cardinality_violation", 0) == 2 and
      "singleton_cardinality_violation" in diag.get("failure_reason", ""), diag)
check("singleton multiple rows -> no repair",
      diag.get("n_singleton_binding_repairs", 0) == 0 and
      any(t.get("singleton_cardinality_violation") for t in timings), (diag, timings))

# Initial singleton is NOT rev13 repair-eligible.  Existing strict triple binding
# remains authoritative when source_index is valid.
def initial_wrong_sid(client, model, section, depth, data_text, verbose=False,
                      context="", lean=None, max_tokens_override=None):
    return {"section": section, "entries": [{
        "source_index": 0, "source_id": "netstat:TYPO", "identifier": IDENT[0],
        "score": "LOW", "reason": "initial singleton wrong sid"
    }]}

out, _, errors, _ = invoke(initial_wrong_sid, rows=[ROWS[0]], source_indices=[100])
diag = diag_of(errors)
check("initial singleton wrong source_id remains REJECT", out == [] and bool(errors), (out, errors))
check("initial singleton wrong source_id not rev13-repaired",
      diag.get("n_singleton_binding_repairs", 0) == 0 and
      diag.get("rejection_reasons", {}).get("source_id_index_mismatch", 0) >= 1, diag)

# Repair requires valid raw source_id and canonical identifier.
row_missing_sid = dict(ROWS[1]); row_missing_sid.pop("source_id")
row_a = ROWS[0]
rows_missing_sid = [row_a, row_missing_sid]
ident_missing_sid = a._canonical_identifier("netstat", row_missing_sid)

def parent_then_missing_sid(client, model, section, depth, data_text, verbose=False,
                            context="", lean=None, max_tokens_override=None):
    if "netstat:a" in data_text and "1.1.1.1:443" in data_text:
        return {"section": section, "entries": [{
            "source_index": 0, "source_id": "netstat:a", "identifier": IDENT[0],
            "score": "LOW", "reason": "A"
        }]}
    return {"section": section, "entries": [{
        "source_index": 0, "source_id": "TYPO", "identifier": ident_missing_sid,
        "score": "LOW", "reason": "raw sid absent"
    }]}

out, _, errors, _ = invoke(parent_then_missing_sid, rows=rows_missing_sid,
                            source_indices=[100, 101])
check("raw source_id missing -> no rev13 canonical repair",
      not any(e.get("_source_attribution_repair") for e in out), (out, errors))
check("raw source_id missing preserves legacy fixture fallback",
      len(out) == 2 and not errors and out[1].get("_source_attribution_method") == "legacy_source_index",
      (out, errors))

# Invalid schema score must not unlock rev13 binding repair.
invalid_score_b = [{"source_index": 0, "source_id": "netstat:TYPO", "identifier": IDENT[0],
                    "score": "NOT_A_SCORE", "reason": "invalid schema"}]
out, _, errors, _ = invoke(parent_omits_b(invalid_score_b))
diag = diag_of(errors)
check("schema-invalid singleton binding is not repaired",
      len(out) == 1 and bool(errors) and diag.get("n_singleton_binding_repairs", 0) == 0,
      (out, errors))

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
