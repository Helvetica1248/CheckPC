#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Disposition ledger for every raw evidence item (v3.69-rc26)."""
from __future__ import annotations


class PlannedItem:
    """One planner decision with compact, immutable raw-index provenance.

    ``source_indices`` is borrowed until :meth:`freeze_source_indices` performs
    one complete validation pass.  Only after that pass succeeds are compact
    immutable ranges committed and the caller-owned container released.  This
    makes audit provenance immutable without allocating a second multi-million
    element list.

    The planner contract requires strictly increasing, unique indices.  Freeze
    is idempotent.  Compatibility iterators always finish freezing before their
    first ``yield``, so an early ``break`` cannot truncate the audit ranges.
    """

    def __init__(self, entry, representative_index, source_indices,
                 disposition, reason="", source_ids=None):
        self.entry = entry
        self.representative_index = int(representative_index)
        self._borrowed_source_indices = source_indices
        self._source_index_ranges: tuple[tuple[int, int], ...] = ()
        self._source_count = 0
        self.source_ids = tuple(str(x) for x in (source_ids or []))
        self.disposition = disposition
        self.reason = reason or ""

    def freeze_source_indices(self) -> None:
        """Validate the full borrowed sequence, then atomically freeze ranges.

        No object state is changed if normalization or ordering validation
        fails.  This method is intentionally idempotent.
        """
        source = self._borrowed_source_indices
        if source is None:
            return
        ranges: list[tuple[int, int]] = []
        start = prev = None
        count = 0
        for raw in source:
            idx = int(raw)
            if prev is not None and idx <= prev:
                raise ValueError(
                    "source_indices must be strictly increasing and unique")
            if start is None:
                start = prev = idx
            elif idx == prev + 1:
                prev = idx
            else:
                ranges.append((start, prev))
                start = prev = idx
            count += 1
        if start is not None:
            ranges.append((start, prev))
        # Commit only after the complete validation pass succeeds.
        self._source_index_ranges = tuple(ranges)
        self._source_count = count
        self._borrowed_source_indices = None

    def iter_source_indices(self):
        """Yield frozen indices; freezing completes before the first yield."""
        self.freeze_source_indices()
        for start, end in self._source_index_ranges:
            yield from range(start, end + 1)

    def consume_source_indices(self):
        """Compatibility alias for :meth:`iter_source_indices`."""
        yield from self.iter_source_indices()

    @property
    def source_indices(self):
        """Compatibility view.  Internal hot paths use compressed ranges."""
        self.freeze_source_indices()
        return tuple(
            value
            for start, end in self._source_index_ranges
            for value in range(start, end + 1)
        )

    @property
    def source_index_ranges(self):
        self.freeze_source_indices()
        return [list(x) for x in self._source_index_ranges]

    def to_audit(self):
        self.freeze_source_indices()
        return {
            "representative_index": self.representative_index,
            "source_index_ranges": self.source_index_ranges,
            "source_count": self._source_count,
            "source_ids": list(self.source_ids),
            "disposition": self.disposition,
            "reason": self.reason,
        }


REASON_LABELS = {
    "level1_excluded": "Level1フィルタ不該当",
    "suspicious_false": "suspicious=False",
    "dir_class_D": "zip/rar/7z（raw_directoryへ退避）",
    "signature_diversity": "同型シグネチャ多様性制約",
    "m1_policy_bound": "M1高リスク配置の層化上限",
    "over_section_cap": "section cap超過",
    "over_global_budget": "global budget超過",
    "mandatory_selected": "mandatory選抜",
    "representative_selected": "最低代表選抜",
    "risk_selected": "risk pool選抜",
    "fair_selected": "fair pool選抜",
    "novelty_selected": "novelty pool選抜",
    "selected_unevaluated": "選抜済みだがLLM未評価",
    "netstat_private": "プライベート/ローカル通信の決定論処理",
    "netstat_ephemeral": "エフェメラルRPCの決定論処理",
    "netstat_loopback": "ループバックLISTENINGの決定論処理",
    "mpksl_excluded": "Defender MpKslの決定論処理",
    "defender_rule_based": "Defenderルールベース確定",
    "userassist_rule_based": "UserAssistルールベース確定",
    "rdp_inbound_rule_based": "着信RDPルールベース確定",
    "coverage_missing": "カバレッジ再送後も未評価",
}

_DEFERRED_POLICY_REASONS = {
    "level1_excluded", "suspicious_false", "dir_class_D", "signature_diversity",
    "m1_policy_bound", "over_section_cap", "over_global_budget",
}


class DispositionLedger:
    def __init__(self, n_raw):
        self.n_raw = int(n_raw)
        self._state = {}  # raw_index -> (disposition, reason)
        self._items = []
        self._unevaluated = {}
        self._indices_cache = {}

    def add(self, item: PlannedItem):
        """Atomically classify one item.

        The ledger is intentionally single-threaded.  Phase 1 performs a full
        read-only validation pass; phase 2 commits only after no exception is
        possible from index normalization/range/conflict checks.
        """
        if item.disposition not in {"selected", "deterministic", "deferred"}:
            raise ValueError(f"invalid disposition: {item.disposition}")
        item.freeze_source_indices()

        # Phase 1: validation only.  Do not mutate _state/_items/cache.
        for idx in item.iter_source_indices():
            if idx < 0 or idx >= self.n_raw:
                raise ValueError(f"raw index out of range: {idx}")
            previous = self._state.get(idx)
            # selected may replace prior level1 deferred when novelty sampling promotes it.
            if previous and not (item.disposition == "selected" and previous[0] == "deferred"):
                if previous != (item.disposition, item.reason):
                    raise ValueError(f"raw index {idx} already classified as {previous}")

        # Phase 2: commit.  The validated frozen ranges are stable for this pass.
        for idx in item.iter_source_indices():
            self._state[idx] = (item.disposition, item.reason)
        self._items.append(item)
        self._indices_cache.clear()

    def mark_unevaluated(self, raw_index, reason="selected_unevaluated"):
        indices = raw_index if isinstance(raw_index, (list, tuple, set)) else [raw_index]
        # Selected/unevaluated sets are bounded by the planner selection cap;
        # materializing this tuple avoids partial mutation on int/range errors.
        normalized = tuple(int(value) for value in indices)
        for idx in normalized:
            if idx < 0 or idx >= self.n_raw:
                raise ValueError(f"raw index out of range: {idx}")
        for idx in normalized:
            self._unevaluated[idx] = reason
            # Keep selected disposition: this is an explicit failure, not policy deferral.
            if idx not in self._state:
                self._state[idx] = ("selected", reason)
        self._indices_cache.clear()

    def indices(self, disposition):
        cached = self._indices_cache.get(disposition)
        if cached is None:
            cached = frozenset(i for i, (d, _) in self._state.items() if d == disposition)
            self._indices_cache[disposition] = cached
        return set(cached)

    @property
    def selected(self):
        return self.indices("selected")

    @property
    def deterministic(self):
        return self.indices("deterministic")

    @property
    def deferred(self):
        return self.indices("deferred")

    @property
    def unevaluated(self):
        return set(self._unevaluated)

    def raw_disposition(self):
        out = []
        for i in range(self.n_raw):
            d, r = self._state.get(i, ("unclassified", ""))
            out.append({"raw_index": i, "disposition": d, "reason": r,
                        "unevaluated_reason": self._unevaluated.get(i, "")})
        return out

    def reasons(self, disposition=None):
        out = {}
        for i, (d, reason) in self._state.items():
            if disposition is None or d == disposition:
                out.setdefault(reason or "unspecified", []).append(i)
        for values in out.values():
            values.sort()
        return out

    def stats(self):
        by_reason = {}
        for _, (disposition, reason) in self._state.items():
            key = f"{disposition}:{reason or 'unspecified'}"
            by_reason[key] = by_reason.get(key, 0) + 1
        selected = self.selected
        deterministic = self.deterministic
        deferred = self.deferred
        return {
            "raw": self.n_raw,
            "selected": len(selected),
            "deterministic": len(deterministic),
            "deferred": len(deferred),
            "deferred_by_policy": len(deferred),
            "selected_unevaluated": len(self._unevaluated),
            "selected_coverage_pct": (100.0 if not selected else
                round(100.0 * (len(selected) - len(self._unevaluated)) / len(selected), 2)),
            "by_reason": by_reason,
        }

    def verify(self):
        errors = []
        selected, deterministic, deferred = (
            self.selected, self.deterministic, self.deferred)
        if selected & deterministic:
            errors.append(
                f"selected∩deterministic 非空: {sorted(selected & deterministic)[:8]}")
        if deterministic & deferred:
            errors.append(
                f"deterministic∩deferred 非空: {sorted(deterministic & deferred)[:8]}")
        if selected & deferred:
            errors.append(
                f"selected∩deferred 非空: {sorted(selected & deferred)[:8]}")
        expected = set(range(self.n_raw))
        covered = selected | deterministic | deferred
        if covered != expected:
            errors.append(
                f"未分類/範囲外: missing={sorted(expected-covered)[:8]} "
                f"extra={sorted(covered-expected)[:8]}")
        for item in self._items:
            if (item.disposition == "deferred" and
                    item.reason not in _DEFERRED_POLICY_REASONS):
                errors.append(f"deferredの理由がpolicy外: {item.reason}")
        if errors:
            raise AssertionError("; ".join(errors))
        return True
