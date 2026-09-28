#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
depth2_select.py  (v3.69-rc26)

depth=2（Broad Review）のエントリ選抜を section worker の外へ分離し、
グローバル出力予算とセクション別 cap のもとで決定論的に選抜する。

処理順（指示8）:
    canonical raw map 構築
    → ルールベース前処理
    → 決定論的 ctx 構築
    → 全セクション選抜
    → (呼出側で) section worker による LLM 処理

選抜順（指示6）:
    1. 狭く定義した mandatory 候補（予算・cap を超えても選抜）
    2. セクション別最低代表枠（D2_MIN_REP）
    3. 残予算の 75% を、多様性制約付きグローバルリスク順で配分
    4. 残予算の 25% を、固定 SECTION_ORDER のラウンドロビンで配分
    5. 一方で使い切れない予算を他方へ移管

★予算は「候補件数」ではなく resolve_chunk_plan による planned_output_tokens で
  再計算し、超過なら最低優先度の非 mandatory を落として再チャンクする（指示7）。

ctx は LLM 判定前に得られる決定論的情報のみ（指示8）。他セクションの
LLM HIGH/MEDIUM・LLM reason・LLM 生成 IOC は使用禁止。
"""

import os
import re

import ioc_utils
import directory_policy
from budget_profile import active_profile
from provenance import PlannedItem, DispositionLedger
from pipeline_errors import PipelineCancelled, PipelineError


# ─────────────────────────────────────────────────────────────
# mandatory 判定用パターン（狭く定義・指示6）
# ─────────────────────────────────────────────────────────────
_PS_MANDATORY_RE = re.compile(
    r"(-enc\b|-encodedcommand|frombase64string|"
    r"downloadstring|downloadfile|invoke-webrequest|"
    r"set-executionpolicy\s+bypass|- executionpolicy\s+bypass|-ep\s+bypass|"
    r"invoke-mimikatz|mimikatz|sekurlsa|lsass|comsvcs\.dll|minidump|"
    r"new-scheduledtask|register-scheduledjob|new-service|"
    r"wmi.*eventfilter|eventconsumer)", re.I)

_PS_TIER1_RE = re.compile(
    r"(iex\b|invoke-expression|-w\s+hidden|-windowstyle\s+hidden|"
    r"certutil|bitsadmin|mshta|regsvr32|rundll32|msiexec|"
    r"curl\b|wget\b|-nop\b|-noprofile)", re.I)

_ENCODED_LONG_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")

# rc17: Office startup の既知HIGH候補を、Level1・signature・budgetより前に
# 決定論的に識別する。~$ はOffice一時ロックファイルなので除外する。
_OFFICE_STARTUP_MACRO_EXTS = {".dot", ".dotm", ".xlsm", ".xlam"}
_EXECUTABLE_EXTS = directory_policy.EXECUTABLE_EXTS
_USER_WRITABLE_PATH_RE = re.compile(
    r"(?:\\users\\[^\\]+\\(?:appdata|downloads|desktop)\\|"
    r"\\users\\public\\|\\windows\\temp\\|"
    r"(?:^|\\)temp\\)", re.I)
_DIR_M1_MAX = max(0, int(os.environ.get("CHECKPC_DIR_M1_MAX", "80")))
_DIR_M1_PARENT_MAX = max(1, int(os.environ.get("CHECKPC_DIR_M1_PARENT_MAX", "8")))
_DIR_M1_PLACEMENT_MAX = max(1, int(os.environ.get("CHECKPC_DIR_M1_PLACEMENT_MAX", "32")))


def is_user_writable_execution_artifact(entry) -> bool:
    """Classify by canonical M1 evidence properties, never by product basename."""
    return bool(directory_policy.m1_placement(entry))


def _entry_path(entry):
    if not isinstance(entry, dict):
        return ""
    return str(entry.get("path") or entry.get("name") or entry.get("identifier") or "")


def deterministic_mandatory_reason(section, entry):
    """Return a stable mandatory reason known before any LLM call.

    Keep this intentionally narrow.  It is a selection guarantee, not a
    general malware verdict.  The final score floor is applied separately by
    analyze_section._apply_post_filter().
    """
    if not isinstance(entry, dict):
        return ""
    if section == "directory":
        return directory_policy.m0_reason(entry)
    if section != "startup_folder":
        return ""
    path = _entry_path(entry)
    name = path.replace("/", "\\").rsplit("\\", 1)[-1]
    if name.startswith("~$"):
        return ""
    ext = "." + name.lower().rsplit(".", 1)[-1] if "." in name else ""
    if (str(entry.get("source", "")).lower() == "office_startup"
            and entry.get("suspicious") is True
            and ext in _OFFICE_STARTUP_MACRO_EXTS):
        return "office_startup_macro_suspicious"
    return ""


def include_mandatory_indices(section, raw_entries, allowed_indices):
    """Union deterministic mandatory candidates into the Level1 allow-set."""
    allowed = set(int(i) for i in (allowed_indices or ()))
    if section not in {"startup_folder", "directory"}:
        return allowed
    for idx, entry in enumerate(raw_entries or []):
        if deterministic_mandatory_reason(section, entry):
            allowed.add(idx)
        elif section == "directory" and directory_policy.m1_placement(entry):
            # M1 is not mandatory LLM evidence. It is only protected from being
            # discarded before bounded stratified selection and accounting.
            allowed.add(idx)
    return allowed


def _entry_text(entry):
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        return " ".join(str(v) for v in entry.values() if isinstance(v, (str, int)))
    return str(entry)


def _is_unattributed_process_hint(value) -> bool:
    text = re.sub(r"\s+", " ", str(value or "")).strip().casefold()
    return text in {"", "-", "unknown", "unknown process", "n/a", "na", "none", "null", "pidなし", "不明", "未取得", "unattributed"}


# ─────────────────────────────────────────────────────────────
# ctx（決定論ヒント）の型
# ─────────────────────────────────────────────────────────────
def empty_ctx():
    return {
        "file_basenames": {
            "defender": set(),
            "known_tools": set(),
            "directory_suspicious": set(),
        },
        "iocs": {"ip": set(), "fqdn": set(), "hash": set()},
        "time_anchors": [],           # 決定論イベント時刻（epoch 秒）
        "endpoint_frequency": {},      # 正規化済み remote → 出現回数
    }


def _basename(path):
    if not path:
        return ""
    return path.replace("/", "\\").split("\\")[-1].lower()


def build_ctx(det_sections, endpoint_freq=None, time_anchors=None):
    """決定論的 ctx を構築する（指示8）。

    det_sections: {section: [rule_based_entry, ...]} の形で、
      Defender / known_tools / directory 決定論分類などの結果を受け取る。
      ★LLM 出力は一切渡さないこと。
    """
    ctx = empty_ctx()
    for sec, entries in (det_sections or {}).items():
        for e in entries or []:
            if not isinstance(e, dict):
                continue
            # ファイル名（Defender / known_tools / directory）
            for key in ("path", "name", "image_path", "file", "identifier"):
                bn = _basename(e.get(key, ""))
                if not bn:
                    continue
                if sec == "defender_quarantine":
                    ctx["file_basenames"]["defender"].add(bn)
                elif sec in ("known_tools",):
                    ctx["file_basenames"]["known_tools"].add(bn)
                elif sec == "directory":
                    ctx["file_basenames"]["directory_suspicious"].add(bn)
            # 決定論 IOC（Defender の path/threat 由来など）
            for ioc in (e.get("iocs") or []):
                t = ioc_utils.classify_syntactic(str(ioc))
                if t in ("ip", "fqdn", "hash"):
                    ctx["iocs"][t].add(ioc_utils.normalize_ioc(str(ioc), t)
                                       if t == "ip" else str(ioc))
    if endpoint_freq:
        ctx["endpoint_frequency"] = dict(endpoint_freq)
    if time_anchors:
        ctx["time_anchors"] = list(time_anchors)
    return ctx


# ─────────────────────────────────────────────────────────────
# セクション別選抜スコア（指示5・6）
# 戻り値: (tier, score, tiebreak_tuple)
#   tier 0 = mandatory（予算・cap 超過でも選抜）
#   tier 1 = 通常候補
# ─────────────────────────────────────────────────────────────
def _sig_generic(section, entry):
    """多様性確保用の粗いシグネチャ。"""
    if section == "netstat":
        r = entry.get("remote", "") if isinstance(entry, dict) else ""
        ip = r.rsplit(":", 1)[0] if ":" in r else r
        return ".".join(ip.split(".")[:3]) if ip.count(".") == 3 else ip
    if section == "dns_cache":
        f = entry.get("fqdn", "") if isinstance(entry, dict) else ""
        return ".".join(f.lower().rsplit(".", 2)[-2:]) if f else ""
    txt = _entry_text(entry).lower()
    m = re.search(rf"[^\\/]+\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})\b", txt)
    return m.group(0) if m else txt[:32]



def _stable_entry_key(section, entry):
    """Input-order-independent tie-break for planner selection."""
    if section == "directory":
        return directory_policy.canonical_sort_key(entry)
    return (_sig_generic(section, entry).casefold(), _entry_text(entry).casefold())

def section_selection_score(section, entry, ctx):
    prof = active_profile()
    text = _entry_text(entry)
    tl = text.lower()
    bn = ""
    if isinstance(entry, dict):
        for k in ("name", "path", "image_path", "identifier"):
            if entry.get(k):
                bn = _basename(entry.get(k)); break

    mandatory = False
    score = 10
    d = ctx["file_basenames"]

    # ── mandatory（狭く定義・指示6）: known_tools / Defender / floor / 既知IOC ──
    pre_reason = deterministic_mandatory_reason(section, entry)
    if pre_reason:
        mandatory = True; score += 110
    if bn and (bn in d["defender"] or bn in d["known_tools"]):
        mandatory = True; score += 100
    # 既知IOC完全一致
    if isinstance(entry, dict):
        for ioc in (entry.get("iocs") or []):
            iv = str(ioc)
            it = ioc_utils.classify_syntactic(iv)
            key = ioc_utils.normalize_ioc(iv, it) if it == "ip" else iv
            if it in ("ip", "fqdn", "hash") and key in ctx["iocs"].get(it, ()):
                mandatory = True; score += 90; break

    # ── セクション別の tier1 加点 ──
    if section == "ps_history":
        if _PS_MANDATORY_RE.search(text):
            mandatory = True; score += 80         # ★mandatory ではなく明示の危険パターン
        if _PS_TIER1_RE.search(text):
            score += 40
        if _ENCODED_LONG_RE.search(text):
            score += 30
        if len(text) > 500:
            score += 15
    elif section == "netstat":
        remote = entry.get("remote", "") if isinstance(entry, dict) else ""
        ip = remote.rsplit(":", 1)[0] if ":" in remote else remote
        port = remote.rsplit(":", 1)[1] if ":" in remote else ""
        is_ext = bool(ip) and not ioc_utils.is_private_ip(ip)
        nonstd = port.isdigit() and int(port) not in (80, 443, 53, 123, 993, 995, 22)
        state = entry.get("state", "") if isinstance(entry, dict) else ""
        hint = entry.get("_proc_hint") if isinstance(entry, dict) else None
        if is_ext:
            score += 50
        if nonstd:
            score += 40
        if state == "LISTENING" and (str(entry.get("local", "")).startswith("0.0.0.0")
                                     or str(entry.get("local", "")).startswith("[::]")):
            score += 30
        if _is_unattributed_process_hint(hint):
            score += 25
        freq = ctx["endpoint_frequency"].get(ip, 0)
        if freq == 1:
            score += 20
        elif freq >= 10:
            score -= 10
    elif section in ("prefetch", "appcompat_cache"):
        # Prefetch は通常フルパスを持たない。AppCompatCache等でパスがある場合、
        # 製品名ではなく「ユーザー書込可能領域の実行痕跡」という証拠クラスを優先する。
        if bn and bn in d["directory_suspicious"]:
            score += 30
        if is_user_writable_execution_artifact(entry):
            score += 55
        elif re.search(r"\\(temp|appdata|public|perflogs|\$recycle)", tl):
            score += 40
        if re.search(r"\b(svchost|rundll32|lsass|services|csrss)\b", tl):
            score += 30
        if re.search(r"\b(certutil|mshta|regsvr32|bitsadmin)\b", tl):
            score += 10
    elif section == "directory":
        placement = directory_policy.m1_placement(entry)
        if placement:
            score += 55
        score += directory_policy.extension_risk(entry) * 6
        if directory_policy.m0_reason(entry):
            score += 70
        if re.search(r"\\(?:perflogs|windows\\help|windows\\fonts|windows\\debug|windows\\tracing)\\", tl):
            score += 35
    elif section == "dns_cache":
        fqdn = entry.get("fqdn", "") if isinstance(entry, dict) else ""
        if fqdn and ioc_utils.classify_syntactic(fqdn) == "fqdn":
            if not ioc_utils.is_known_infra_fqdn(fqdn):
                score += 40
        labels = fqdn.split(".") if fqdn else []
        if labels:
            head = labels[0]
            vowels = sum(c in "aeiou" for c in head.lower())
            if len(head) >= 8 and vowels <= max(1, len(head) // 6):
                score += 20     # ランダム性の高いラベル
    else:
        # その他（persistence_reg / task_scheduler / service / startup_folder /
        #        system_7045 / rdp_1024 / bits_jobs / hosts）
        if re.search(r"\\(temp|appdata|public|programdata)", tl):
            score += 30
        if section == "bits_jobs" and isinstance(entry, dict):
            nc = str(entry.get("notify_cmd", "")).lower()
            if nc and nc != "none":
                mandatory = True; score += 60

    if mandatory:
        tier = 0
    elif section == "directory" and directory_policy.m1_placement(entry):
        tier = 1
    elif section == "directory":
        tier = 2
    else:
        tier = 1
    tiebreak = (_sig_generic(section, entry), -score)
    return tier, score, tiebreak


# ─────────────────────────────────────────────────────────────
# 予算配分（指示6・7）
# ─────────────────────────────────────────────────────────────
def novelty_selection_score(section, entry):
    """Score Level1-excluded entries for a small deterministic novelty sample.

    This does not label an entry malicious. It only favors entries unlike the
    already-selected known-pattern population.
    """
    text = _entry_text(entry)
    tl = text.lower()
    score = 1
    if len(text) > 300:
        score += 15
    if re.search(r"[A-Za-z0-9+/]{100,}={0,2}", text):
        score += 35
    if re.search(r"\\(temp|appdata|public|perflogs|programdata|\$recycle)", tl):
        score += 25
    if re.search(rf"\.(?:{directory_policy.EXECUTABLE_EXT_PATTERN})\b", tl):
        score += 20
    if section == "netstat" and isinstance(entry, dict):
        remote = str(entry.get("remote", ""))
        host = remote.rsplit(":", 1)[0] if ":" in remote else remote
        port = remote.rsplit(":", 1)[1] if ":" in remote else ""
        if host and not ioc_utils.is_private_ip(host):
            score += 25
        if port.isdigit() and int(port) not in (53, 80, 123, 443, 993, 995):
            score += 20
    if section == "dns_cache" and isinstance(entry, dict):
        fqdn = str(entry.get("fqdn", ""))
        if fqdn and not ioc_utils.is_known_infra_fqdn(fqdn):
            score += 20
    # Stable tiebreak via signature text; callers also include raw index.
    return score, _sig_generic(section, entry)



def _build_deferred_reasons(normal_candidates, novelty_candidates, chosen_set,
                            signature_deferred_indices, cap_full,
                            policy_deferred_indices=None):
    """Build exact deferred groups without quadratic list membership.

    rc6 stored ``signature_diversity`` as a list and then performed
    ``gi in list`` for every remaining candidate.  On multi-million-entry
    directory sections this became O(N^2).  A set subtraction preserves the
    exact classification while reducing membership to O(1).
    """
    signature_set = (signature_deferred_indices if isinstance(signature_deferred_indices, set)
                     else {int(gi) for gi in signature_deferred_indices})
    policy_set = (policy_deferred_indices if isinstance(policy_deferred_indices, set)
                  else {int(gi) for gi in (policy_deferred_indices or ())})
    remaining_set = set(normal_candidates)
    remaining_set.update(novelty_candidates)
    remaining_set.difference_update(chosen_set)
    remaining_set.difference_update(signature_set)
    remaining_set.difference_update(policy_set)
    remaining = sorted(remaining_set)
    deferred = {"signature_diversity": sorted(signature_set)}
    if policy_set:
        deferred["m1_policy_bound"] = sorted(policy_set)
    if remaining:
        reason = "over_section_cap" if cap_full else "over_global_budget"
        deferred[reason] = remaining
    return deferred


def plan_depth2_selection(pools, ctx, section_order, ledgers=None, lean=None,
                          context="", novelty_pools=None, cancel_check=None,
                          progress_callback=None):
    """Plan deterministic risk/fair/novelty selection across all sections.

    ``pools`` contains Level1-matched candidates. ``novelty_pools`` contains
    Level1-excluded candidates that remain eligible for the small novelty pool.
    The function returns exact selected/deferred reasons so provenance never
    conflates signature diversity, section cap and global budget.
    """
    prof = active_profile()
    total_budget = prof.d2_output_token_budget
    novelty_pools = novelty_pools or {}
    ledgers = ledgers or {}
    cancel_interval = max(1, int(getattr(prof, "planner_cancel_check_interval", 4096)))
    progress_interval = max(cancel_interval, int(getattr(
        prof, "planner_progress_interval", 65536)))

    def _progress(phase, **detail):
        if not progress_callback:
            return
        payload = {"phase": str(phase), **detail}
        try:
            progress_callback(payload)
        except Exception:
            pass

    def _check_cancel(phase, examined=0, total=0, section=""):
        should_check = (not examined) or (examined % cancel_interval == 0)
        if should_check and cancel_check and cancel_check():
            raise PipelineCancelled(
                f"Depth2 selection cancelled during {phase}"
                + (f" section={section}" if section else ""))
        if examined and examined % progress_interval == 0:
            _progress(phase, examined=int(examined), total=int(total or 0), section=section)

    def cost(sec):
        return max(0, prof.tok_per_entry(sec))

    def cap(sec):
        return prof.section_cap(sec)

    scored = {}
    signature_deferred = {sec: set() for sec in section_order}
    policy_deferred = {sec: set() for sec in section_order}
    mandatory_sets = {sec: set() for sec in section_order}
    all_candidate_indices = {sec: set() for sec in section_order}
    tier_input_counts = {sec: {0: 0, 1: 0, 2: 0} for sec in section_order}
    _progress("candidate_scoring", completed=0, total=len(section_order))
    for sec_no, sec in enumerate(section_order, 1):
        _check_cancel("candidate_scoring", section=sec)
        tmp = []
        pool_values = pools.get(sec, [])
        pool_total = len(pool_values) if hasattr(pool_values, "__len__") else 0
        for pos, (gi, e) in enumerate(pool_values, 1):
            _check_cancel("candidate_scoring", pos, pool_total, sec)
            tier, sc, tb = section_selection_score(sec, e, ctx)
            all_candidate_indices[sec].add(gi)
            tier_input_counts[sec][tier] = tier_input_counts[sec].get(tier, 0) + 1
            tmp.append((tier, -sc, tb[0], _stable_entry_key(sec, e), gi, e, sc))
        tmp.sort(key=lambda x: (x[0], x[1], x[2], x[3]))
        sig_count = {}
        kept = []
        m1_count = 0
        m1_parent_count = {}
        m1_placement_count = {}
        for tier, negsc, sig, _stable, gi, e, sc in tmp:
            if sec == "directory":
                # Exact-pattern deduplication also applies to M0 so a generated
                # duplicate family cannot create an unbounded mandatory overrun.
                if sig_count.get(sig, 0) >= prof.sig_max_d2:
                    signature_deferred[sec].add(gi)
                    continue
                if tier == 1:
                    placement = directory_policy.m1_placement(e) or "unknown"
                    parent = directory_policy.parent_path(e)
                    if (m1_count >= _DIR_M1_MAX
                            or m1_parent_count.get(parent, 0) >= _DIR_M1_PARENT_MAX
                            or m1_placement_count.get(placement, 0) >= _DIR_M1_PLACEMENT_MAX):
                        policy_deferred[sec].add(gi)
                        continue
                    m1_count += 1
                    m1_parent_count[parent] = m1_parent_count.get(parent, 0) + 1
                    m1_placement_count[placement] = m1_placement_count.get(placement, 0) + 1
                sig_count[sig] = sig_count.get(sig, 0) + 1
                if tier == 0:
                    mandatory_sets[sec].add(gi)
                kept.append((tier, sc, sig, gi, e))
                continue
            if tier == 0:
                mandatory_sets[sec].add(gi)
                kept.append((tier, sc, sig, gi, e))
                continue
            if sig_count.get(sig, 0) >= prof.sig_max_d2:
                signature_deferred[sec].add(gi)
                continue
            sig_count[sig] = sig_count.get(sig, 0) + 1
            kept.append((tier, sc, sig, gi, e))
        scored[sec] = kept
        _progress("candidate_scoring", completed=sec_no, total=len(section_order),
                  section=sec, candidates=pool_total)

    novelty_scored = {}
    _progress("novelty_scoring", completed=0, total=len(section_order))
    for sec_no, sec in enumerate(section_order, 1):
        _check_cancel("novelty_scoring", section=sec)
        vals = []
        sig_count = {}
        novelty_values = novelty_pools.get(sec, [])
        novelty_total = len(novelty_values) if hasattr(novelty_values, "__len__") else 0
        for pos, (gi, e) in enumerate(novelty_values, 1):
            _check_cancel("novelty_scoring", pos, novelty_total, sec)
            sc, sig = novelty_selection_score(sec, e)
            vals.append((-sc, sig, _stable_entry_key(sec, e), gi, e, sc))
        vals.sort(key=lambda x: (x[0], x[1], x[2]))
        kept = []
        for negsc, sig, _stable, gi, e, sc in vals:
            if sig_count.get(sig, 0) >= prof.sig_max_d2:
                signature_deferred[sec].add(gi)
                continue
            sig_count[sig] = sig_count.get(sig, 0) + 1
            kept.append((sc, sig, gi, e))
        novelty_scored[sec] = kept
        _progress("novelty_scoring", completed=sec_no, total=len(section_order),
                  section=sec, candidates=novelty_total)

    selected = {sec: [] for sec in section_order}
    selected_reason = {sec: {} for sec in section_order}
    selected_members = {sec: set() for sec in section_order}
    selected_priority = {sec: {} for sec in section_order}
    selected_kind = {sec: {} for sec in section_order}
    used_est = 0
    mandatory_overrun_by_section = {sec: 0 for sec in section_order}
    floor_overrun_by_section = {sec: 0 for sec in section_order}
    protected_floor = {sec: set() for sec in section_order}
    floor_target = {sec: 0 for sec in section_order}
    cap_overrun = {sec: False for sec in section_order}

    def choose(sec, gi, e, reason, allow_overrun=False, overrun_kind="",
               priority=0, candidate_kind=0):
        nonlocal used_est
        if gi in selected_members[sec]:
            return False
        c = cost(sec)
        if not allow_overrun:
            if len(selected[sec]) >= cap(sec) or used_est + c > total_budget:
                return False
        selected[sec].append((gi, e))
        selected_members[sec].add(gi)
        selected_reason[sec][gi] = reason
        selected_priority[sec][gi] = int(priority)
        selected_kind[sec][gi] = int(candidate_kind)
        before_over = max(0, used_est - total_budget)
        used_est += c
        after_over = max(0, used_est - total_budget)
        added_over = max(0, after_over - before_over)
        if allow_overrun:
            if len(selected[sec]) > cap(sec):
                cap_overrun[sec] = True
            if added_over and overrun_kind == "mandatory":
                mandatory_overrun_by_section[sec] += added_over
            elif added_over and overrun_kind == "floor":
                floor_overrun_by_section[sec] += added_over
        return True

    # 1. Mandatory always survives.
    for sec in section_order:
        for tier, sc, sig, gi, e in scored[sec]:
            if tier == 0:
                choose(sec, gi, e, "mandatory_selected", allow_overrun=True, overrun_kind="mandatory", priority=sc, candidate_kind=0)

    # 2. Minimum known-pattern representatives.  rc17: the floor may
    # explicitly overrun the estimate and is protected from the later planned-
    # token trim.  This prevents a small section from collapsing to zero.
    for sec in section_order:
        target = min(prof.d2_min_rep, cap(sec), len(scored[sec]))
        floor_target[sec] = max(floor_target[sec], target)
        for tier, sc, sig, gi, e in scored[sec]:
            if len(selected[sec]) >= target:
                break
            if choose(sec, gi, e, "representative_selected",
                      allow_overrun=True, overrun_kind="floor", priority=sc, candidate_kind=0):
                protected_floor[sec].add(gi)

    # 3. Minimum novelty representatives, if any Level1-excluded candidates exist.
    for sec in section_order:
        target = min(prof.novelty_min_rep, prof.novelty_section_cap,
                     max(0, cap(sec) - len(selected[sec])), len(novelty_scored[sec]))
        chosen_n = 0
        for sc, sig, gi, e in novelty_scored[sec]:
            if chosen_n >= target:
                break
            if choose(sec, gi, e, "novelty_selected",
                      allow_overrun=True, overrun_kind="floor", priority=sc, candidate_kind=1):
                protected_floor[sec].add(gi)
                chosen_n += 1
        floor_target[sec] += chosen_n

    remaining = max(0, total_budget - used_est)
    risk_budget = int(remaining * prof.risk_ratio)
    fair_budget = int(remaining * prof.fair_ratio)
    novelty_budget = remaining - risk_budget - fair_budget

    # 4. Risk pool: global score order.
    global_cands = []
    for sec in section_order:
        selected_set = selected_members[sec]
        for tier, sc, sig, gi, e in scored[sec]:
            if tier != 0 and gi not in selected_set:
                global_cands.append((-sc, sec, _stable_entry_key(sec, e), gi, e))
    global_cands.sort(key=lambda x: (x[0], x[1], x[2], x[3]))
    spent = 0
    for negsc, sec, _stable, gi, e in global_cands:
        c = cost(sec)
        if spent + c > risk_budget:
            continue
        if choose(sec, gi, e, "risk_selected", priority=-negsc, candidate_kind=0):
            spent += c
    fair_budget += max(0, risk_budget - spent)

    # 5. Fair round robin.
    remain = {}
    for sec in section_order:
        ss = selected_members[sec]
        remain[sec] = [(gi, e, sc) for tier, sc, sig, gi, e in scored[sec]
                       if tier != 0 and gi not in ss]
    ptr = {sec: 0 for sec in section_order}
    spent = 0
    while True:
        added = False
        for sec in section_order:
            if ptr[sec] >= len(remain[sec]):
                continue
            gi, e, sc = remain[sec][ptr[sec]]
            ptr[sec] += 1
            c = cost(sec)
            if spent + c > fair_budget:
                continue
            if choose(sec, gi, e, "fair_selected", priority=sc, candidate_kind=0):
                spent += c
                added = True
        if not added:
            break
    novelty_budget += max(0, fair_budget - spent)

    # 6. Additional novelty pool up to per-section novelty cap.
    novelty_counts = {
        sec: sum(1 for r in selected_reason[sec].values() if r == "novelty_selected")
        for sec in section_order
    }
    novelty_global = []
    for sec in section_order:
        ss = selected_members[sec]
        for sc, sig, gi, e in novelty_scored[sec]:
            if gi not in ss:
                novelty_global.append((-sc, sec, _stable_entry_key(sec, e), gi, e))
    novelty_global.sort(key=lambda x: (x[0], x[1], x[2], x[3]))
    spent = 0
    for negsc, sec, _stable, gi, e in novelty_global:
        if novelty_counts[sec] >= prof.novelty_section_cap:
            continue
        c = cost(sec)
        if spent + c > novelty_budget:
            continue
        if choose(sec, gi, e, "novelty_selected", priority=-negsc, candidate_kind=1):
            novelty_counts[sec] += 1
            spent += c

    from analyze_section import resolve_chunk_plan  # delayed to avoid import cycle

    def make_plan(sec, chosen=None):
        chosen = sorted(selected[sec] if chosen is None else chosen, key=lambda x: _stable_entry_key(sec, x[1]))
        return (resolve_chunk_plan(sec, [e for _, e in chosen], 2, lean=lean,
                                   context=context, source_indices=[gi for gi, _ in chosen])
                if chosen else None)

    _progress("initial_plan", completed=0, total=len(section_order))
    result = {}
    for sec_no, sec in enumerate(section_order, 1):
        _check_cancel("initial_plan", section=sec)
        selected[sec].sort(key=lambda x: _stable_entry_key(sec, x[1]))
        result[sec] = {
            "selected": selected[sec],
            "selected_reasons": dict(selected_reason[sec]),
            "plan": make_plan(sec),
            "budget_overrun": (mandatory_overrun_by_section[sec] > 0
                               or floor_overrun_by_section[sec] > 0),
            "cap_overrun": cap_overrun[sec],
            "mandatory_overrun_tokens": mandatory_overrun_by_section[sec],
            "floor_overrun_tokens": floor_overrun_by_section[sec],
            "section_floor_target": floor_target[sec],
            # Mandatory entries may already satisfy the representative floor.
            # Report the fulfilled section floor, not only newly protected entries.
            "section_floor_selected": min(floor_target[sec], len(selected[sec])),
        }
        _progress("initial_plan", completed=sec_no, total=len(section_order), section=sec)

    def total_planned():
        return sum(r["plan"]["planned_output_tokens"] for r in result.values() if r["plan"])

    # Planned chunk overhead may push the estimate beyond the real budget.
    # rc19 keeps this phase bounded: trim operates only on the selected set,
    # while backfill probes a policy frontier consisting of actually dropped
    # candidates plus a small per-section reserve. It never re-plans millions
    # of raw candidates and does not claim global knapsack maximality.
    guard = 0
    total_dropped = 0
    total_backfilled = 0
    backfill_iterations = 0
    dropped_global = {sec: [] for sec in section_order}
    current_total = total_planned()
    trim_batch_max = max(1, int(getattr(prof, "planner_trim_batch_max", 8)))
    trim_iteration_limit = max(1, int(getattr(prof, "planner_trim_iteration_limit", 512)))
    frontier_reserve = max(0, int(getattr(prof, "planner_frontier_reserve_per_section", 32)))
    probe_limit = max(1, int(getattr(prof, "planner_candidate_probe_limit", 1024)))
    replan_limit = max(1, int(getattr(prof, "planner_replan_limit", 512)))
    probes = 0
    replans = 0
    probe_limit_hit = False
    replan_limit_hit = False

    _progress("budget_trim", planned_tokens=current_total, budget=total_budget,
              trim_iterations=0, dropped=0)
    while current_total > total_budget and guard < trim_iteration_limit:
        _check_cancel("budget_trim", guard, 0)
        guard += 1
        droppable = []
        for sec in section_order:
            for gi, entry in result[sec]["selected"]:
                if selected_reason[sec].get(gi) == "mandatory_selected":
                    continue
                if gi in protected_floor[sec]:
                    continue
                droppable.append((selected_priority[sec].get(gi, 0),
                                  selected_kind[sec].get(gi, 0), sec, gi, entry,
                                  selected_reason[sec].get(gi, "risk_selected")))
        if not droppable:
            break
        # Lowest priority is trimmed first; novelty loses ties before known-pattern
        # evidence. All keys are stable and host-independent.
        droppable.sort(key=lambda x: (x[0], -x[1], x[2], _stable_entry_key(x[2], x[4]), x[3]))
        over = current_total - total_budget
        estimated_costs = [max(1, cost(sec)) for _, _, sec, _, _, _ in droppable]
        min_cost = min(estimated_costs) if estimated_costs else 1
        estimated_n = max(1, (over + min_cost - 1) // min_cost)
        batch_size = 1 if over <= (4 * min_cost) else min(
            trim_batch_max, estimated_n, len(droppable))
        batch = droppable[:batch_size]
        affected = set()
        for priority, kind, sec, gi, entry, prior_reason in batch:
            result[sec]["selected"] = [
                (g, e) for g, e in result[sec]["selected"] if g != gi]
            selected_members[sec].discard(gi)
            selected_reason[sec].pop(gi, None)
            selected_priority[sec].pop(gi, None)
            selected_kind[sec].pop(gi, None)
            dropped_global[sec].append(
                (priority, kind, gi, entry, prior_reason))
            affected.add(sec)
            total_dropped += 1
        for sec in sorted(affected):
            _check_cancel("budget_trim_replan", section=sec)
            if replans >= replan_limit:
                raise PipelineError(
                    "Depth2 planner replan limit exceeded during budget trim: "
                    f"limit={replan_limit} planned={current_total} budget={total_budget}")
            result[sec]["selected_reasons"] = dict(selected_reason[sec])
            result[sec]["plan"] = make_plan(sec, result[sec]["selected"])
            replans += 1
        new_total = total_planned()
        _progress("budget_trim", planned_tokens=new_total, budget=total_budget,
                  trim_iterations=guard, dropped=total_dropped)
        if new_total >= current_total and batch_size == len(droppable):
            break
        current_total = new_total

    if current_total > total_budget:
        remaining_droppable = any(
            selected_reason[sec].get(gi) != "mandatory_selected"
            and gi not in protected_floor[sec]
            for sec in section_order for gi, _entry in result[sec]["selected"]
        )
        if remaining_droppable:
            raise PipelineError(
                "Depth2 planner trim iteration limit exceeded before budget convergence: "
                f"limit={trim_iteration_limit} planned={current_total} budget={total_budget}")

    def _bounded_frontier():
        """Return a deterministic bounded policy frontier.

        Dropped candidates are always considered first. Additional candidates
        are drawn only from the already sorted top prefix of each section. The
        scan is bounded by selected count + reserve and therefore independent
        of a section's raw cardinality.
        """
        frontier = []
        seen = set()

        for sec in section_order:
            for priority, kind, gi, entry, prior_reason in sorted(
                    dropped_global[sec], key=lambda x: (-x[0], x[1], _stable_entry_key(sec, x[3]), x[2])):
                key = (sec, gi)
                if key in seen or gi in selected_members[sec]:
                    continue
                seen.add(key)
                frontier.append((-priority, kind, sec, gi, entry,
                                 "backfill_trimmed_selected"))

        def add_prefix(sec, values, kind, reason):
            added = 0
            for item in values:
                if kind == 0:
                    _tier, priority, _sig, gi, entry = item
                    if _tier == 0:
                        continue
                else:
                    priority, _sig, gi, entry = item
                if gi in selected_members[sec] or (sec, gi) in seen:
                    continue
                seen.add((sec, gi))
                frontier.append((-priority, kind, sec, gi, entry, reason))
                added += 1
                if added >= frontier_reserve:
                    break

        for sec in section_order:
            add_prefix(sec, scored[sec], 0, "backfill_risk_selected")
            add_prefix(sec, novelty_scored[sec], 1, "backfill_novelty_selected")
        frontier.sort(key=lambda x: (x[0], x[1], x[2], _stable_entry_key(x[2], x[4]), x[3]))
        return frontier

    frontier = _bounded_frontier()
    frontier_size = len(frontier)
    failed_frontier = []
    _progress("backfill", examined=0, total=frontier_size, added=0,
              planned_tokens=current_total, budget=total_budget)
    if current_total <= total_budget and frontier:
        backfill_iterations = 1
        for pos, (_neg, kind, sec, gi, entry, reason) in enumerate(frontier, 1):
            _check_cancel("backfill", pos, frontier_size, sec)
            if probes >= probe_limit:
                probe_limit_hit = True
                break
            probes += 1
            if gi in selected_members[sec] or len(result[sec]["selected"]) >= cap(sec):
                continue
            if replans >= replan_limit:
                replan_limit_hit = True
                break
            tentative = sorted(result[sec]["selected"] + [(gi, entry)], key=lambda x: _stable_entry_key(sec, x[1]))
            new_plan = make_plan(sec, tentative)
            replans += 1
            old_tokens = ((result[sec].get("plan") or {}).get("planned_output_tokens", 0))
            new_tokens = ((new_plan or {}).get("planned_output_tokens", 0))
            candidate_total = current_total - old_tokens + new_tokens
            if candidate_total > total_budget:
                failed_frontier.append((sec, gi))
                continue
            result[sec]["selected"] = tentative
            result[sec]["plan"] = new_plan
            selected_members[sec].add(gi)
            selected_reason[sec][gi] = reason
            selected_priority[sec][gi] = int(-_neg)
            selected_kind[sec][gi] = int(kind)
            result[sec]["selected_reasons"] = dict(selected_reason[sec])
            current_total = candidate_total
            total_backfilled += 1
            if pos == frontier_size or pos % 16 == 0:
                _progress("backfill", examined=pos, total=frontier_size,
                          added=total_backfilled, planned_tokens=current_total,
                          budget=total_budget)

    # Under monotonic chunk accounting, a candidate that did not fit before
    # later additions cannot become addable. If an operation limit was hit,
    # frontier maximality is explicitly false rather than silently claimed.
    frontier_addable = []
    policy_frontier_maximal = (
        current_total <= total_budget
        and not probe_limit_hit
        and not replan_limit_hit
    )
    global_maximality_not_claimed = True
    _progress("frontier_audit", examined=min(probes, frontier_size),
              total=frontier_size, addable=len(frontier_addable),
              policy_frontier_maximal=policy_frontier_maximal)
    total = total_planned()
    _progress("deferred_accounting", completed=0, total=len(section_order))
    for sec_no, sec in enumerate(section_order, 1):
        _check_cancel("deferred_accounting", section=sec)
        chosen_set = {gi for gi, _ in result[sec]["selected"]}
        normal_candidates = set(all_candidate_indices[sec])
        novelty_candidates = {gi for sc, sig, gi, e in novelty_scored[sec]}
        cap_full = len(result[sec]["selected"]) >= cap(sec)
        deferred = _build_deferred_reasons(
            normal_candidates, novelty_candidates, chosen_set,
            signature_deferred[sec], cap_full, policy_deferred[sec])
        if dropped_global[sec]:
            # _build_deferred_reasons() already sees globally dropped candidates
            # as unselected.  Keep the explicit reason but do not duplicate indices.
            merged = set(deferred.get("over_global_budget", []))
            merged.update(int(x[2]) for x in dropped_global[sec])
            deferred["over_global_budget"] = sorted(merged)
        result[sec]["deferred_reasons"] = {
            reason: sorted(set(int(x) for x in indices))
            for reason, indices in deferred.items()
        }
        if sec == "directory":
            _selected_tiers = {0: 0, 1: 0, 2: 0}
            _m1_parent_counts = {}
            _m1_placement_counts = {}
            for gi, entry in result[sec]["selected"]:
                _tier, _score, _tb = section_selection_score(sec, entry, ctx)
                _selected_tiers[_tier] = _selected_tiers.get(_tier, 0) + 1
                if _tier == 1:
                    _parent = directory_policy.parent_path(entry)
                    _placement = directory_policy.m1_placement(entry) or "unknown"
                    _m1_parent_counts[_parent] = _m1_parent_counts.get(_parent, 0) + 1
                    _m1_placement_counts[_placement] = _m1_placement_counts.get(_placement, 0) + 1
            _tier_total_named = {
                "M0": tier_input_counts[sec].get(0, 0),
                "M1": tier_input_counts[sec].get(1, 0),
                "R": tier_input_counts[sec].get(2, 0),
            }
            _tier_selected_named = {
                "M0": _selected_tiers.get(0, 0),
                "M1": _selected_tiers.get(1, 0),
                "R": _selected_tiers.get(2, 0),
            }
            _tier_deferred_named = {
                key: _tier_total_named[key] - _tier_selected_named[key]
                for key in _tier_total_named
            }
            _reason_counts = {
                reason: len(indices)
                for reason, indices in result[sec]["deferred_reasons"].items()
            }
            result[sec]["directory_policy"] = {
                "tier_total": _tier_total_named,
                "tier_selected": _tier_selected_named,
                "tier_deferred": _tier_deferred_named,
                "deferred_reason_counts": dict(sorted(_reason_counts.items())),
                "m1_limits": {
                    "max": _DIR_M1_MAX,
                    "parent_max": _DIR_M1_PARENT_MAX,
                    "placement_max": _DIR_M1_PLACEMENT_MAX,
                },
                "m1_policy_deferred": len(policy_deferred[sec]),
                "m1_selected_by_placement": dict(sorted(_m1_placement_counts.items())),
                "m1_selected_by_parent_top": [
                    [parent, count] for parent, count in sorted(
                        _m1_parent_counts.items(), key=lambda item: (-item[1], item[0]))[:20]
                ],
                "coverage_degraded": bool(sum(_tier_deferred_named.values())),
                "coverage_degraded_m1": bool(_tier_deferred_named["M1"]),
                "tier_r_fixed_max": None,
            }
        result[sec]["global_planned_output_tokens"] = total
        result[sec]["global_budget"] = total_budget
        result[sec]["global_budget_overrun"] = total > total_budget
        result[sec]["planner_trim_iterations"] = guard
        result[sec]["planner_trim_dropped"] = total_dropped
        result[sec]["planner_backfill_iterations"] = backfill_iterations
        result[sec]["planner_backfill_added"] = total_backfilled
        result[sec]["unused_budget_tokens"] = max(0, total_budget - total)
        result[sec]["candidate_frontier_size"] = frontier_size
        result[sec]["backfill_candidates_examined"] = probes
        result[sec]["planner_replan_count"] = replans
        result[sec]["planner_candidate_probe_limit"] = probe_limit
        result[sec]["planner_trim_iteration_limit"] = trim_iteration_limit
        result[sec]["planner_replan_limit"] = replan_limit
        result[sec]["planner_probe_limit_hit"] = probe_limit_hit
        result[sec]["planner_replan_limit_hit"] = replan_limit_hit
        result[sec]["plan_is_policy_frontier_maximal"] = policy_frontier_maximal
        # Compatibility alias. rc19 explicitly does not claim global knapsack maximality.
        result[sec]["plan_is_maximal"] = policy_frontier_maximal
        result[sec]["global_maximality_not_claimed"] = global_maximality_not_claimed
        result[sec]["frontier_addable_candidates"] = [
            {"section": s, "raw_index": int(i)} for s, i in frontier_addable
        ]
        result[sec]["maximality_addable_candidates"] = [
            {"section": s, "raw_index": int(i)} for s, i in frontier_addable
        ]
        _progress("deferred_accounting", completed=sec_no, total=len(section_order), section=sec)
    return result
