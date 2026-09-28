#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""compare_analyzed.py — A/B エントリ単位裁定スクリプト（v3.69-rc2 / C12）

使い方:
    python3 compare_analyzed.py <A: analyzed_*.json> <B: analyzed_*.json>
                                [--strict-regression]

終了コード（指示13）:
    0 合格 / 1 回帰不合格 / 2 引数・入力・スキーマエラー / 3 要裁定 / 4 内部処理エラー

自動不合格（両モード共通）:
    既存 HIGH の消失 / HIGH→LOW/CLEAN / 未評価 / chunk_errors
モード差:
    通常比較           : HIGH→MEDIUM = 要裁定 / エントリ消失(非HIGH) = 不合格
    --strict-regression : HIGH→MEDIUM = 不合格 / エントリ消失(非HIGH) = 不合格

本ツールは後方互換のanalyzed単体比較であり、比較前提metadataや段階別provenanceを
fail-closed検証しない。正式ゲートには compare_runs.py を使用する。

v3.69-rc27: 二段階照合＋score schema閉性＋同一Depth/cross-Depth意味論。両側に存在する非空source_idを最初に照合し、
source_idで対応しなかった残余だけをcanonical keyで照合する。これにより、
一部のlegacy entryにsource_idが無いだけで全体がcanonical modeへ落ち、同一証拠を
「消失＋新規」と誤報する問題を防ぐ。v3.67成果物にはraw indexがないため、
集約置換は「集約置換の可能性あり」の要裁定補助表示に留める。
"""
import collections
import json
import sys

try:
    import ioc_utils
except Exception:
    ioc_utils = None

ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0}
SCORES = ("HIGH", "MEDIUM", "LOW", "CLEAN")

EXIT_OK, EXIT_REGRESSION, EXIT_INPUT_ERROR, EXIT_ADJUDICATE, EXIT_INTERNAL = 0, 1, 2, 3, 4


def load(p):
    return json.load(open(p, encoding="utf-8"))


def analysis_depth(doc):
    meta = doc.get("meta", {}) if isinstance(doc, dict) else {}
    try:
        return int(meta.get("depth", doc.get("depth", 0)))
    except (TypeError, ValueError):
        return 0


def schema_findings(doc, label):
    invalid = []
    degraded = []
    for sec, entry in _iter_comparable_entries(doc):
        score = entry.get("score")
        ident = str(entry.get("identifier", ""))[:80]
        if score not in SCORES:
            invalid.append(("invalid_score", sec, ident, f"{label} score={score!r}", "", ""))
        if entry.get("score_normalization_warning") or entry.get("schema_degraded"):
            degraded.append(("schema_degraded", sec, ident,
                             f"{label} raw={entry.get('score_raw')!r} normalized={score!r}",
                             str(entry.get("reason", "")), ""))
    return invalid, degraded


def _deterministic_high_reason(text):
    value = str(text or "").casefold()
    return ("deterministic floor: high" in value
            or "depth2_mandatory_reason" in value
            or "決定論" in value and "high" in value)


def _canon_iocs(e):
    out = []
    for i in (e.get("iocs") or []):
        s = str(i)
        if ioc_utils is not None:
            t = ioc_utils.classify_syntactic(s)
            if t == "ip":
                s = ioc_utils.normalize_ioc(s, "ip")
        out.append(s)
    return tuple(sorted(out))


def _iter_comparable_entries(doc):
    """Yield (section, entry) pairs used by A/B comparison."""
    for sec, sr in doc.get("sections", {}).items():
        for e in sr.get("entries", []):
            if not isinstance(e, dict):
                continue
            ident = str(e.get("identifier", ""))
            if ident.startswith("⚠"):
                continue
            yield sec, e


def has_complete_source_ids(doc):
    """Return True only when every comparable entry has a non-empty source_id.

    Empty documents deliberately return False so comparison falls back to the
    schema-neutral canonical key.  A global decision is required: choosing the
    key per entry makes an old result and a new result for the same evidence
    impossible to match.
    """
    saw_entry = False
    for _sec, e in _iter_comparable_entries(doc):
        saw_entry = True
        if not str(e.get("source_id", "") or ""):
            return False
    return saw_entry


def comparison_key_mode(a, b):
    """Return the rc8 two-stage matching mode label."""
    return "source_id_then_canonical"


def canonical_key(sec, e, use_source_id=True):
    source_id = str(e.get("source_id", "") or "")
    if use_source_id and source_id:
        return (sec, f"source_id:{source_id}", "", ())
    return (sec, str(e.get("identifier", "")), str(e.get("datetime", "") or ""),
            _canon_iocs(e))


def entry_multiset(doc, use_source_id=None):
    if use_source_id is None:
        use_source_id = has_complete_source_ids(doc)
    ms = collections.defaultdict(collections.Counter)
    reasons = collections.defaultdict(dict)
    for sec, e in _iter_comparable_entries(doc):
        k = canonical_key(sec, e, use_source_id=bool(use_source_id))
        sc = e.get("score", "?")
        ms[k][sc] += 1
        reasons[k].setdefault(sc, e.get("reason", "") or "")
    return ms, reasons


def _pair_shared_source_ids(a_entries, b_entries):
    """Pair shared source_id entries deterministically, returning residuals.

    Exact scores are paired first. Remaining entries are paired by severity so a
    true score transition remains visible. Excess duplicates fall through to
    canonical matching instead of being silently discarded.
    """
    severity = ["HIGH", "MEDIUM", "LOW", "CLEAN", "?"]
    a_left = list(a_entries)
    b_left = list(b_entries)
    pairs = []
    for score in severity:
        aa = [x for x in a_left if x[1].get("score", "?") == score]
        bb = [x for x in b_left if x[1].get("score", "?") == score]
        n = min(len(aa), len(bb))
        for i in range(n):
            pairs.append((aa[i], bb[i]))
            a_left.remove(aa[i])
            b_left.remove(bb[i])
    a_left.sort(key=lambda x: (-ORDER.get(x[1].get("score", "?"), -1),
                               str(x[1].get("identifier", ""))))
    b_left.sort(key=lambda x: (-ORDER.get(x[1].get("score", "?"), -1),
                               str(x[1].get("identifier", ""))))
    n = min(len(a_left), len(b_left))
    pairs.extend(zip(a_left[:n], b_left[:n]))
    return pairs, a_left[n:], b_left[n:]


def two_stage_entry_multisets(a, b):
    """Build A/B multisets using source_id first and canonical residuals second.

    rc27 preserves unmatched source IDs when both artifacts use the same source
    ID algorithm. Falling those rows back to an empty/ambiguous identifier
    collapsed many distinct pieces of evidence into duplicate comparison rows.
    Canonical fallback remains available only for legacy/different algorithms
    or entries that genuinely lack source_id.
    """
    a_all = list(_iter_comparable_entries(a))
    b_all = list(_iter_comparable_entries(b))
    a_sid = collections.defaultdict(list)
    b_sid = collections.defaultdict(list)
    a_residual, b_residual = [], []
    for sec, e in a_all:
        sid = str(e.get("source_id", "") or "")
        (a_sid[(sec, sid)] if sid else a_residual).append((sec, e))
    for sec, e in b_all:
        sid = str(e.get("source_id", "") or "")
        (b_sid[(sec, sid)] if sid else b_residual).append((sec, e))

    ma = collections.defaultdict(collections.Counter)
    mb = collections.defaultdict(collections.Counter)
    ra = collections.defaultdict(dict)
    rb = collections.defaultdict(dict)

    def add_side(target_ms, target_reasons, sec, sid, rows):
        for idx, (_, entry) in enumerate(rows):
            key = (sec, f"source_id:{sid}#{idx}", "", ())
            score = entry.get("score", "?")
            target_ms[key][score] += 1
            target_reasons[key].setdefault(score, entry.get("reason", "") or "")

    shared = sorted(set(a_sid) & set(b_sid))
    for sec, sid in shared:
        pairs, a_extra, b_extra = _pair_shared_source_ids(
            a_sid[(sec, sid)], b_sid[(sec, sid)])
        for idx, ((_, ea), (_, eb)) in enumerate(pairs):
            k = (sec, f"source_id:{sid}#{idx}", "", ())
            sa, sb = ea.get("score", "?"), eb.get("score", "?")
            ma[k][sa] += 1
            mb[k][sb] += 1
            ra[k].setdefault(sa, ea.get("reason", "") or "")
            rb[k].setdefault(sb, eb.get("reason", "") or "")
        # Duplicate source IDs are invalid elsewhere, but preserve their
        # identities here so diagnostics cannot collapse by empty identifier.
        if a_extra:
            add_side(ma, ra, sec, sid, a_extra)
        if b_extra:
            add_side(mb, rb, sec, sid, b_extra)

    meta_a = a.get("meta", {}) if isinstance(a, dict) else {}
    meta_b = b.get("meta", {}) if isinstance(b, dict) else {}
    alg_a = str(meta_a.get("source_id_algorithm_version") or "")
    alg_b = str(meta_b.get("source_id_algorithm_version") or "")
    same_algorithm = bool(alg_a and alg_a == alg_b)

    for sec, sid in sorted(set(a_sid) - set(b_sid)):
        if same_algorithm:
            add_side(ma, ra, sec, sid, a_sid[(sec, sid)])
        else:
            a_residual.extend(a_sid[(sec, sid)])
    for sec, sid in sorted(set(b_sid) - set(a_sid)):
        if same_algorithm:
            add_side(mb, rb, sec, sid, b_sid[(sec, sid)])
        else:
            b_residual.extend(b_sid[(sec, sid)])

    for sec, e in a_residual:
        k = canonical_key(sec, e, use_source_id=False)
        sc = e.get("score", "?")
        ma[k][sc] += 1
        ra[k].setdefault(sc, e.get("reason", "") or "")
    for sec, e in b_residual:
        k = canonical_key(sec, e, use_source_id=False)
        sc = e.get("score", "?")
        mb[k][sc] += 1
        rb[k].setdefault(sc, e.get("reason", "") or "")
    return ma, ra, mb, rb


def _duplicate_source_id_adjudications(a, b):
    """Return mandatory adjudications for duplicate source_id bundles.

    source_id is expected to be unique within a section.  If either side has a
    multiplicity greater than one, directional pairing is ambiguous even when
    score multisets are identical, so the comparison must exit with code 3.
    """
    grouped = []
    for doc in (a, b):
        mapping = collections.defaultdict(list)
        for sec, entry in _iter_comparable_entries(doc):
            sid = str(entry.get("source_id", "") or "")
            if sid:
                mapping[(sec, sid)].append(entry)
        grouped.append(mapping)
    out = []
    keys = sorted(set(grouped[0]) | set(grouped[1]))
    for sec, sid in keys:
        aa = grouped[0].get((sec, sid), [])
        bb = grouped[1].get((sec, sid), [])
        if len(aa) <= 1 and len(bb) <= 1:
            continue
        def describe(entries):
            scores = collections.Counter(str(e.get("score", "?")) for e in entries)
            score_text = ",".join(f"{k}:{scores[k]}" for k in sorted(scores)) or "none"
            idents = [str(e.get("identifier", "")) for e in entries]
            return f"count={len(entries)} scores={score_text} identifiers={idents[:6]}"
        out.append((
            "ambiguous_source_id_bundle", sec,
            f"source_id:{sid}",
            f"A={len(aa)} B={len(bb)}",
            describe(aa), describe(bb),
        ))
    return out


def has_aggregation(doc, section):
    sr = doc.get("sections", {}).get(section, {})
    for e in sr.get("entries", []):
        if isinstance(e, dict) and (e.get("_aggregated_source_indices")
                                    or e.get("aggregated_source_indices")):
            return True
    return False


def n_unevaluated(doc):
    n = 0
    for sr in doc.get("sections", {}).values():
        for ce in (sr.get("_chunk_errors") or []):
            if ce.get("oversize") or ce.get("selected_unevaluated"):
                ui = ce.get("unevaluated_indices")
                n += len(ui) if ui else max(0, int(ce.get("n_entries", 0) or 0)
                                            - int(ce.get("n_salvaged", 0) or 0))
            elif ce.get("partial_parse"):
                n += max(0, int(ce.get("n_entries", 0) or 0)
                         - int(ce.get("n_salvaged", 0) or 0))
    return n


def n_chunk_errors(doc):
    return sum(len(sr.get("_chunk_errors") or [])
               for sr in doc.get("sections", {}).values())


def timings(doc):
    per = {}
    for sec, sr in doc.get("sections", {}).items():
        ts = sr.get("_chunk_timings") or []
        if ts:
            per[sec] = sum(t.get("elapsed_sec", 0) for t in ts)
    return per


def compare(a, b, strict):
    """canonical keyごとのスコア件数をマルチセットとして比較する。

    最頻スコアへ縮約せず、同スコアを先に相殺した後、残数を重大度順に
    対応付ける。これにより「HIGH×1 + CLEAN×9 → CLEAN×10」の少数HIGH消失を
    確実に検出する。
    """
    key_mode = comparison_key_mode(a, b)
    depth_a, depth_b = analysis_depth(a), analysis_depth(b)
    cross_depth = bool(depth_a and depth_b and depth_a != depth_b)
    ma, ra, mb, rb = two_stage_entry_multisets(a, b)
    keys = sorted(set(ma) | set(mb), key=lambda k: (k[0], k[1], k[2], k[3]))
    fatal = []
    adjud = _duplicate_source_id_adjudications(a, b)
    matrix = collections.Counter()

    severity = ["HIGH", "MEDIUM", "LOW", "CLEAN"]
    for k in keys:
        sec = k[0]
        ca = collections.Counter(ma.get(k, {}))
        cb = collections.Counter(mb.get(k, {}))

        # 同スコアを先に相殺する。
        for sc in severity:
            n = min(ca.get(sc, 0), cb.get(sc, 0))
            if n:
                matrix[(sc, sc)] += n
                ca[sc] -= n
                cb[sc] -= n

        # A側残数を重大度順に、B側の最も重大な残数へ対応させる。
        for sa in severity:
            while ca.get(sa, 0) > 0:
                sb = next((x for x in severity if cb.get(x, 0) > 0), None)
                ca[sa] -= 1
                if sb is None:
                    if sa == "HIGH":
                        fatal.append(("既存HIGH消失", sec, k[1], "HIGH->(消失)",
                                      ra[k].get("HIGH", ""), ""))
                    else:
                        hint = (" (集約置換の可能性あり)"
                                if has_aggregation(b, sec) else "")
                        # rc18: 同一Depthでもcross-Depthでも、証拠の消失は選抜・
                        # provenance回帰として自動不合格。スコアの妥当性とは分離する。
                        fatal.append(("エントリ消失" + hint, sec, k[1],
                                      f"{sa}->(消失)", ra[k].get(sa, ""), ""))
                    continue
                cb[sb] -= 1
                matrix[(sa, sb)] += 1
                if sa == "HIGH" and sb in ("LOW", "CLEAN"):
                    fatal.append(("HIGH→LOW/CLEAN", sec, k[1], f"{sa}->{sb}",
                                  ra[k].get(sa, ""), rb[k].get(sb, "")))
                elif sa == "HIGH" and sb == "MEDIUM":
                    rec = ("HIGH->MEDIUM", sec, k[1], f"{sa}->{sb}",
                           ra[k].get(sa, ""), rb[k].get(sb, ""))
                    if strict or (cross_depth and _deterministic_high_reason(ra[k].get("HIGH", ""))):
                        fatal.append(rec)
                    else:
                        adjud.append(rec)
                elif ORDER.get(sb, 0) < ORDER.get(sa, 0):
                    adjud.append(("降格", sec, k[1], f"{sa}->{sb}",
                                  ra[k].get(sa, ""), rb[k].get(sb, "")))
                elif ORDER.get(sb, 0) > ORDER.get(sa, 0):
                    adjud.append(("昇格", sec, k[1], f"{sa}->{sb}",
                                  ra[k].get(sa, ""), rb[k].get(sb, "")))

        # B側に残ったものは新規エントリ。
        for sb in severity:
            for _ in range(cb.get(sb, 0)):
                if sb in ("HIGH", "MEDIUM"):
                    adjud.append((f"新{sb}", sec, k[1], f"(新規)->{sb}",
                                  "", rb[k].get(sb, "")))
    return fatal, adjud, matrix


def main():
    argv = list(sys.argv[1:])
    strict = "--strict-regression" in argv
    argv = [x for x in argv if not x.startswith("--")]
    if len(argv) != 2:
        print(__doc__)
        return EXIT_INPUT_ERROR
    try:
        a, b = load(argv[0]), load(argv[1])
    except Exception as e:
        print(f"[入力エラー] {e}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    try:
        fatal, adjud, matrix = compare(a, b, strict)
        invalid_a, degraded_a = schema_findings(a, "A")
        invalid_b, degraded_b = schema_findings(b, "B")
        fatal.extend(invalid_a + invalid_b)
        if strict:
            fatal.extend(degraded_a + degraded_b)
        else:
            adjud.extend(degraded_a + degraded_b)
        undet_a, undet_b = n_unevaluated(a), n_unevaluated(b)
        cer_a, cer_b = n_chunk_errors(a), n_chunk_errors(b)
        if undet_a or undet_b:
            fatal.append(("未評価残", "-", "-", f"A={undet_a} B={undet_b}", "", ""))
        if cer_a or cer_b:
            fatal.append(("chunk_errors", "-", "-", f"A={cer_a} B={cer_b}", "", ""))
        relation = ("cross-depth" if analysis_depth(a) != analysis_depth(b)
                    and analysis_depth(a) and analysis_depth(b) else "same-depth")
        mode = "strict-regression" if strict else "通常比較"
        print("=" * 70)
        print(f"比較モード: {mode} / {relation} (A depth={analysis_depth(a)} B depth={analysis_depth(b)})")
        print(f"照合キー: {comparison_key_mode(a, b)}")
        print("=" * 70)
        print(f"\n① 自動不合格（{len(fatal)}件・0件必須）")
        for tag, sec, ident, tr, xa, xb in fatal:
            print(f"  [不合格:{tag}] {sec}: {tr}  {str(ident)[:70]}")
            if xa:
                print(f"      A: {str(xa)[:88]}")
            if xb:
                print(f"      B: {str(xb)[:88]}")
        print(f"\n② 遷移マトリクス（A→B・マルチセット件数対応）")
        print(f"{'A/B':>8} " + "  ".join(f"{s:>6}" for s in SCORES))
        for sa in SCORES:
            row = [matrix.get((sa, sb), 0) for sb in SCORES]
            print(f"{sa:>8} " + "  ".join(f"{n:>6}" for n in row))
        print(f"\n③ 要裁定（{len(adjud)}件）")
        for tag, sec, ident, tr, xa, xb in sorted(adjud, key=lambda r: (r[1], r[0])):
            print(f"  [{tag}] {sec}: {tr}  {str(ident)[:70]}")
        print(f"\n④ 健全性 / 処理時間")
        ta, tb = timings(a), timings(b)
        tot_a, tot_b = sum(ta.values()), sum(tb.values())
        print(f"  chunk_errors: A {cer_a} / B {cer_b}   未評価: A {undet_a} / B {undet_b}")
        if tot_a:
            print(f"  LLM合計: {tot_a:.1f}s -> {tot_b:.1f}s ({(1 - tot_b / tot_a) * 100:+.1f}%)")
        print(f"\n⑥ 判定サマリ")
        print(f"  自動不合格: {len(fatal)}件 / 要裁定: {len(adjud)}件  モード: {mode}")
        if fatal:
            print("  終了コード: 1（回帰不合格）")
            return EXIT_REGRESSION
        if adjud:
            print("  終了コード: 3（要裁定）")
            return EXIT_ADJUDICATE
        print("  終了コード: 0（合格）")
        return EXIT_OK
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"[内部エラー] {e}", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main())
