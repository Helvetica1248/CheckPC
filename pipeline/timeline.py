# -*- coding: utf-8 -*-
"""簡易感染タイムライン（T-TL）。

タイムスタンプを持つ各セクションのイベントを時系列に統合し、攻撃の流れ
（初期侵入→実行→永続化→防御回避→C2/横展開→影響）を1つの年表で俯瞰する。

設計方針:
  - 決定論ベース（LLM 非依存）。truncation や応答揺らぎの影響を受けない。
  - 既存 parse 済みセクションの確定フィールドのみを読む。
  - 時刻は JST に正規化して扱う（TZ-1）。UTCマーカー(Z/+00:00)や明示オフセットを
    持つ時刻は JST(+09:00) へ変換し、マーカー無しは JST ローカルとして扱う。
  - HIGH/MEDIUM 所見のIOC/パスを含むイベントを「不審(*)」として標記する。
"""

import re
import unicodedata
from datetime import datetime, timedelta


def _dwidth(s: str) -> int:
    """文字列の表示幅（全角=2, 半角=1）。"""
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in s)


def _pad(s: str, width: int) -> str:
    """表示幅 width に右側スペース埋め（全角考慮）。"""
    s = str(s)
    pad = width - _dwidth(s)
    return s + (" " * pad if pad > 0 else "")

# ─────────────────────────────────────────────────────────────
# 時刻源の定義: section -> (timestamp_field, phase, base_severity, mitre, formatter)
# formatter は entry(dict) を受け取り、表示用文字列を返す。
# ─────────────────────────────────────────────────────────────


def _g(e, *keys):
    """entry から最初に見つかった非空フィールドを返す。"""
    for k in keys:
        v = e.get(k)
        if v not in (None, "", []):
            return str(v)
    return ""


EVENT_SOURCES = {
    "security_1102": {
        "ts": "datetime", "phase": "防御回避", "sev": "HIGH", "mitre": ["T1070.001"],
        "fmt": lambda e: "セキュリティイベントログ消去 (EID1102)",
    },
    "system_104": {
        "ts": "datetime", "phase": "防御回避", "sev": "HIGH", "mitre": ["T1070.001"],
        "fmt": lambda e: f"イベントログ消去 (EID104) {_g(e, 'log', 'channel', 'log_name')}".rstrip(),
    },
    "system_7045": {
        "ts": "datetime", "phase": "永続化", "sev": "MEDIUM", "mitre": ["T1543.003"],
        "fmt": lambda e: f"サービス導入: {_g(e, 'service_name', 'name')} "
                         f"({_g(e, 'image_path')})".rstrip(),
    },
    "rdp_inbound": {
        "ts": "datetime", "phase": "横展開/初期侵入", "sev": "MEDIUM", "mitre": ["T1021.001"],
        "fmt": lambda e: f"着信RDP: {_g(e, 'user', 'account_name')}"
                         f"@{_g(e, 'source_ip')} (EID{_g(e, 'event_id')})",
    },
    "rdp_1024": {
        "ts": "datetime", "phase": "横展開", "sev": "LOW", "mitre": ["T1021.001"],
        "fmt": lambda e: f"外向きRDP: {_g(e, 'user')} → {_g(e, 'server', 'computer')}",
    },
    "defender_quarantine": {
        "ts": "datetime", "phase": "検知/影響", "sev": "HIGH", "mitre": ["T1204"],
        "fmt": lambda e: f"AV検知/隔離: {_g(e, 'threat_name')} {_g(e, 'path')}".rstrip(),
    },
    "bits_jobs": {
        "ts": "creation_time", "phase": "永続化/ダウンロード", "sev": "MEDIUM", "mitre": ["T1197"],
        # TL-D: parse_bits_jobs の出力キーは "display"（name/display_name/job_name
        #   は存在しないため従来は常に空表示だった）。display を主に参照し、
        #   ダウンロード元 URL / 保存先があれば併記する（年表上の有用性向上）。
        "fmt": lambda e: ("BITSジョブ: " + (_g(e, "display", "name", "job_name") or "(無名)")
                          + (f" → {_g(e, 'url', 'local_file')}"
                             if _g(e, "url", "local_file") else "")),
    },
    "userassist": {
        "ts": "last_run", "phase": "実行", "sev": "LOW", "mitre": ["T1204.002"],
        # TL-E: run_count が 0/不明のときは "(x0)" 表示が「実行回数0」と誤読される
        #   ため回数表記を省く。1以上のときのみ "(実行N回)" を付す。
        "fmt": lambda e: ("GUI実行: " + _g(e, "path")
                          + (f" (実行{_g(e, 'run_count')}回)"
                             if _g(e, "run_count") not in ("", "0", "?") else "")),
    },
    "prefetch": {
        "ts": "modified", "phase": "実行", "sev": "LOW", "mitre": ["T1059"],
        "fmt": lambda e: f"実行痕跡(Prefetch): {_g(e, 'name')}",
    },
}

# 表示順のためのphase優先度（同時刻の安定ソート用）
_PHASE_ORDER = {
    "初期侵入": 0, "横展開/初期侵入": 1, "実行": 2, "永続化": 3,
    "永続化/ダウンロード": 3, "防御回避": 4, "横展開": 5, "検知/影響": 6,
}

# T-TL6: 重大度ランク（クラスタの最高重大度・代表イベント選定用）
_SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}

# T-TL6: 不審イベントのクラスタ分割ギャップ（時間）。
#   このギャップ以上あいたら別インシデントとして分割する。
#   env CHECKPC_TL_CLUSTER_GAP_H で可変（既定24h）。
import os as _os
try:
    _CLUSTER_GAP_HOURS = float(_os.environ.get("CHECKPC_TL_CLUSTER_GAP_H", "24"))
except (TypeError, ValueError):
    _CLUSTER_GAP_HOURS = 24.0

# 時刻フォーマット候補
# TL-B: CheckPC 実出力は "2026/06/25  22:38"（スラッシュ区切り・秒なし・
#   日付と時刻の間がダブルスペース）形式が混在する。prefetch.modified は
#   全件がこの形式のため、従来の _TS_FORMATS では 0件パースとなり全除外
#   されていた（取りこぼし）。スラッシュ+秒なし／ドットを追加し、
#   入力側で連続空白を単一化して strptime に通す。
_TS_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y/%m/%d %H:%M",     # TL-B: prefetch/defender directory_scan 系
    "%Y.%m.%d %H:%M:%S",  # TL-B: 念のためドット区切りも許容
    "%Y.%m.%d %H:%M",
]


def _parse_ts(s: str):
    """時刻文字列を datetime(JST・naive) へ変換する。失敗時 None。

    TZ 正規化（TZ-1）:
      · 末尾に UTC マーカー "Z" または "+00:00" があれば UTC とみなし +9h して JST 化。
      · 末尾に明示オフセット "+HH:MM"/"-HH:MM" があれば、それを解して JST(+09:00) 化。
      · マーカーが無い時刻は CheckPC のローカル成果物（prefetch/userassist 等）
        由来とみなし、既に JST として無変換で扱う。
    返す datetime は tzinfo を持たない JST naive（表示・ソート用）。

    ※ 限界: Z 等のマーカーを欠くイベントログ時刻（ホストによっては実体が
      UTC の場合がある）は自動変換しない。要ならソース単位の上書きで対応する。
    """
    if not s:
        return None
    s = s.strip()

    # タイムゾーンマーカーを検出（除去前に判定する）
    tz_shift_hours = 0  # JST へ寄せるための加算時間
    m_z = re.search(r"[Zz]$", s)
    m_off = re.search(r"([+\-])(\d{2}):?(\d{2})$", s)
    if m_z:
        # UTC → JST(+09:00): +9h
        tz_shift_hours = 9
        s = s[:m_z.start()].strip()
    elif m_off:
        sign = 1 if m_off.group(1) == "+" else -1
        off_h = sign * (int(m_off.group(2)) + int(m_off.group(3)) / 60.0)
        # 現地(off) → UTC は -off、UTC → JST は +9 なので、JST へは (9 - off)
        tz_shift_hours = 9 - off_h
        s = s[:m_off.start()].strip()

    # 小数秒を除去（"HH:MM:SS.ffffff" の小数部のみ。ドット区切り日付は保持）
    s = re.sub(r"(\d{1,2}:\d{2}:\d{2})\.\d+", r"\1", s).strip()
    # 日付と時刻の間のダブルスペース等を単一スペースへ正規化（TL-B）
    s = re.sub(r"\s+", " ", s)

    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if tz_shift_hours:
                dt = dt + timedelta(hours=tz_shift_hours)
            return dt
        except ValueError:
            continue
    return None


# ─────────────────────────────────────────────────────────────
# TL-C: 不審(*)突合に使う所見の厳格化
#   旧実装は extract_findings_from_results が identifier から
#   `[A-Za-z]:\\[^\s"]+` でパスを抜くため "C:\Program Files\..." が
#   空白で切れて "C:\Program" になり、部分一致で全 Program Files パスに
#   誤マッチ → クリーン端末でも多数の正規アプリが不審(*)化していた。
#   ここでは突合キーとして「汎用的すぎる所見」を除外するガードを設ける。
# ─────────────────────────────────────────────────────────────
_GENERIC_FINDINGS = {
    "0.0.0.0", "127.0.0.1", "::", "::1", "0:0:0:0:0:0:0:0", "localhost",
}
# ドライブ直下の一般フォルダ名のみ（"c:\program" 等の切れ端）
_DRIVE_PREFIX_RE = re.compile(
    r"^[a-z]:\\(?:program(?: files(?: \(x86\))?)?|programdata|windows|"
    r"users|temp|public|system32)?\\?$", re.I)
# 0.0.0.0:port / [::]:port / 127.0.0.1:port のような待受タプル
_LISTEN_TUPLE_RE = re.compile(
    r"^(?:0\.0\.0\.0|127\.0\.0\.1|\[?::1?\]?):\d+$", re.I)
# 突合キーの最小長（ポート番号や2〜3文字トークンの広域誤マッチを防ぐ）
_MIN_FINDING_LEN = 8


def _is_generic_finding(f: str) -> bool:
    """部分一致の突合キーとして使うと誤マッチを招く汎用所見か判定する。"""
    f = f.strip()
    if len(f) < _MIN_FINDING_LEN:
        return True
    fl = f.lower()
    if fl in _GENERIC_FINDINGS:
        return True
    if _DRIVE_PREFIX_RE.match(fl):
        return True
    if _LISTEN_TUPLE_RE.match(fl):
        return True
    return False


def _normalize_findings(findings) -> list:
    """所見（IOC/パス/識別子の集合）を小文字化したリストにする。

    TL-C: 汎用的すぎて部分一致で誤爆する所見（ドライブ直下の切れ端・
    裸の待受タプル・短いトークン）は突合キーから除外する。
    実行体ファイル名やドメイン・完全パス等の固有性が高い所見は残す。
    """
    out = []
    for f in findings or []:
        if not f:
            continue
        s = str(f)
        if _is_generic_finding(s):
            continue
        out.append(s.lower())
    return out


def _merge_event_sources(sections: dict, event_logs=None) -> dict:
    """TL-A: timeline の時刻源を sections と event_logs の両方から集める。

    parsed.json は meta/sections/event_logs の3層構造で、
    system_7045 / rdp_inbound / rdp_1024 / security_1102 / system_104 は
    sections ではなく event_logs 配下に格納される。旧 extract_events は
    sections だけを見ていたため、これら5ソース（着信RDP・サービス導入・
    ログ消去）が常時0件となり、永続化/横展開/防御回避フェーズがまるごと
    欠落していた（取りこぼし）。ここで両者を合成する。

    合成規則: 同名キーが両方に非空 list で存在する場合は sections を優先
    （defender_quarantine は sections 側が正、event_logs.defender_1116 は空）。
    """
    merged = {}
    for src in (sections or {}, event_logs or {}):
        if not isinstance(src, dict):
            continue
        for k, v in src.items():
            if isinstance(v, list) and v and k not in merged:
                merged[k] = v
    return merged


def extract_events(sections: dict, findings=None, event_logs=None) -> dict:
    """各セクションからタイムスタンプ付きイベントを抽出する。

    戻り値: {"events": [...], "skipped": int, "sources": {section: count}}
    各 event: {datetime, ts, section, phase, severity, summary, mitre, suspicious}
    """
    findings_lc = _normalize_findings(findings)
    merged = _merge_event_sources(sections, event_logs)  # TL-A
    events = []
    skipped = 0
    sources = {}

    for section, cfg in EVENT_SOURCES.items():
        lst = merged.get(section)
        if not isinstance(lst, list):
            continue
        cnt = 0
        for e in lst:
            if not isinstance(e, dict):
                continue
            ts_raw = e.get(cfg["ts"], "")
            dt = _parse_ts(str(ts_raw)) if ts_raw else None
            if dt is None:
                if ts_raw:
                    skipped += 1
                continue
            try:
                summary = cfg["fmt"](e)
            except Exception:
                summary = f"{section} イベント"
            # 所見との突合（IOC/パスが所見に含まれれば不審）
            blob = (summary + " " + " ".join(
                str(v) for v in e.values() if isinstance(v, str))).lower()
            suspicious = any(fl and fl in blob for fl in findings_lc)
            events.append({
                "datetime":  dt,
                "ts":        dt.strftime("%Y-%m-%d %H:%M:%S"),
                "section":   section,
                "phase":     cfg["phase"],
                "severity":  cfg["sev"],
                "summary":   summary,
                "mitre":     list(cfg["mitre"]),
                "suspicious": suspicious,
            })
            cnt += 1
        if cnt:
            sources[section] = cnt

    return {"events": events, "skipped": skipped, "sources": sources}


def _cluster_suspicious(susp_events: list, gap_hours: float = None) -> list:
    """T-TL6: 不審イベントを時間ギャップで分割しインシデント窓（クラスタ）化する。

    連続する不審イベントの間隔が gap_hours 以上あいたら別クラスタに分割する。
    各クラスタは {from, to, count, max_severity, high_medium_count,
    representative, phases} を持つ。susp_events は時刻昇順であること。
    """
    if gap_hours is None:
        gap_hours = _CLUSTER_GAP_HOURS
    if not susp_events:
        return []
    gap = timedelta(hours=gap_hours)
    groups = []
    cur = [susp_events[0]]
    for prev, ev in zip(susp_events, susp_events[1:]):
        if (ev["datetime"] - prev["datetime"]) > gap:
            groups.append(cur)
            cur = [ev]
        else:
            cur.append(ev)
    groups.append(cur)

    clusters = []
    for g in groups:
        # 最高重大度のイベントを代表に（同順位なら先頭）
        rep = max(g, key=lambda e: _SEVERITY_RANK.get(e["severity"], 0))
        hm = sum(1 for e in g if e["severity"] in ("HIGH", "MEDIUM"))
        clusters.append({
            "from":  g[0]["ts"],
            "to":    g[-1]["ts"],
            "count": len(g),
            "max_severity": rep["severity"],
            "high_medium_count": hm,
            "representative": rep["summary"],
            "phases": sorted({e["phase"] for e in g}),
        })
    return clusters


def build_timeline(sections: dict, findings=None, event_logs=None) -> dict:
    """イベントを抽出し時系列ソートして返す。"""
    res = extract_events(sections, findings, event_logs)
    res["events"].sort(
        key=lambda ev: (ev["datetime"], _PHASE_ORDER.get(ev["phase"], 9)))
    # 不審イベントの時間窓（min〜max の単一包絡。後方互換のため保持）
    susp = [ev for ev in res["events"] if ev["suspicious"]]
    if susp:
        res["suspicious_window"] = {
            "from": susp[0]["ts"], "to": susp[-1]["ts"], "count": len(susp),
        }
    else:
        res["suspicious_window"] = None
    # T-TL6: 単一窓は古い良性実行が1件でも MEDIUM 化すると数年幅に膨張し
    #   実用性を欠くため、時間ギャップでインシデント窓に分割する。
    res["suspicious_clusters"] = _cluster_suspicious(susp)
    return res


# ─────────────────────────────────────────────────────────────
# T-TL5（前倒し）: LOW 実行痕跡の抑制
#   userassist / prefetch の LOW は正規アプリの利用ログが大半で、年表を
#   数百行に膨らませ実害イベント（HIGH/MEDIUM・着信RDP等）を埋もれさせる。
#   既定では「不審でない LOW 実行痕跡」を抑制し、不審時間窓の前後±30分に
#   入るものだけ残す（攻撃前後の実行コンテキストは保持＝不審窓フォーカス）。
#   full=True で全件展開する。
# ─────────────────────────────────────────────────────────────
# （timedelta は先頭で import 済み）

_LOW_EXEC_SECTIONS = {"userassist", "prefetch"}
_SUSPICIOUS_WINDOW_MARGIN_MIN = 30


def _is_low_exec_noise(ev: dict) -> bool:
    """抑制対象（不審でない userassist/prefetch の LOW 実行痕跡）か。"""
    return (ev.get("severity") == "LOW"
            and ev.get("section") in _LOW_EXEC_SECTIONS
            and not ev.get("suspicious"))


def _collect_anchor_times(events: list) -> list:
    """保持の基準点（不審 または HIGH/MEDIUM のイベント）の時刻一覧。"""
    return [ev["datetime"] for ev in events
            if ev.get("datetime") and
            (ev.get("suspicious") or ev.get("severity") in ("HIGH", "MEDIUM"))]


def _near_any_anchor(ev: dict, anchors: list,
                     margin_min=_SUSPICIOUS_WINDOW_MARGIN_MIN) -> bool:
    """イベントが いずれかのアンカー時刻 ±margin 分以内にあるか。"""
    dt = ev.get("datetime")
    if not dt or not anchors:
        return False
    sec = margin_min * 60
    return any(abs((dt - a).total_seconds()) <= sec for a in anchors)


def _filter_events_for_display(events: list, sw, full: bool):
    """表示用にイベントを絞り込み、(表示リスト, 抑制件数) を返す。

    full=True なら全件。False なら「不審でない LOW 実行痕跡」のうち、
    不審/HIGH/MEDIUM イベント（アンカー）の ±30分 から外れたものを抑制する。
    攻撃前後の実行コンテキストは残しつつ、無関係なアプリ利用ログを落とす。
    """
    if full:
        return events, 0
    anchors = _collect_anchor_times(events)
    shown, suppressed = [], 0
    for ev in events:
        if _is_low_exec_noise(ev) and not _near_any_anchor(ev, anchors):
            suppressed += 1
        else:
            shown.append(ev)
    return shown, suppressed


def render_timeline_text(timeline: dict, max_rows: int = 300, full: bool = False) -> str:
    """ベタ打ち整形（罫線なし・等幅前提）の年表テキストを生成する。"""
    events = timeline.get("events", [])
    sw = timeline.get("suspicious_window")
    # T-TL5: 不審でない LOW 実行痕跡を抑制（不審窓±30分は残す）
    shown_events, suppressed = _filter_events_for_display(events, sw, full)
    lines = []
    lines.append("=" * 78)
    lines.append("感染タイムライン（決定論抽出 / 時刻は JST 正規化）")
    lines.append("=" * 78)

    clusters = timeline.get("suspicious_clusters", []) or []
    if sw:
        # T-TL6: 単一 min〜max span は数年幅に膨張し誤解を招くため、
        #   ここでは総件数のみ示し、実窓は下のインシデント窓（クラスタ）で示す。
        lines.append(f"不審イベント: {sw['count']}件（* 印。時間窓は下記インシデント窓を参照）")
    else:
        lines.append("不審イベント（所見との突合一致）: なし")

    # T-TL6: 不審インシデント窓（時間ギャップクラスタ）を表示。
    #   HIGH/MEDIUM を含むクラスタ＝実インシデント窓を優先表示し、
    #   LOW*のみのクラスタ（古い良性実行の羅列）は件数集計に留める。
    if clusters:
        incident = [c for c in clusters if c["high_medium_count"] > 0]
        low_only = [c for c in clusters if c["high_medium_count"] == 0]
        shown_clusters = clusters if full else incident
        gap_h = _CLUSTER_GAP_HOURS
        label = "全クラスタ" if full else "HIGH・MEDIUM含む"
        lines.append(
            f"不審インシデント窓（{gap_h:g}hギャップ / {label} {len(shown_clusters)}件）:")
        # 最高重大度→新しい順で並べる（初動は直近の重大インシデント優先）
        order = sorted(
            shown_clusters,
            key=lambda c: (_SEVERITY_RANK.get(c["max_severity"], 0), c["to"]),
            reverse=True)
        for i, c in enumerate(order, 1):
            span = c["from"] if c["from"] == c["to"] else f"{c['from']} 〜 {c['to']}"
            rep = c["representative"]
            if _dwidth(rep) > 44:
                # 表示幅44で切り詰め
                acc = ""
                for ch in rep:
                    if _dwidth(acc + ch) > 44:
                        break
                    acc += ch
                rep = acc + "…"
            lines.append(
                f"  [{i}] {_pad(span, 41)} {c['max_severity']:6} "
                f"{c['count']:3}件  {rep}")
        if not full and low_only:
            n_low = sum(c["count"] for c in low_only)
            lines.append(
                f"  （LOW実行のみの不審クラスタ {len(low_only)}件・計{n_low}件は省略 / --full で表示）")

    src = timeline.get("sources", {})
    if src:
        lines.append("取得元: " + " ".join(f"{k}={v}" for k, v in src.items()))
    if timeline.get("skipped"):
        lines.append(f"※ 時刻解析不能で除外: {timeline['skipped']}件")
    if suppressed:
        lines.append(f"※ LOW実行痕跡(userassist/prefetch)を抑制: {suppressed}件"
                     f"（全件は _all 版／full=True で展開）")
    lines.append("-" * 78)
    lines.append(f"{_pad('日時(JST)', 19)} {_pad('重大度', 8)} {_pad('フェーズ', 18)} 内容")
    lines.append("-" * 78)

    shown = shown_events[:max_rows]
    for ev in shown:
        mark = "*" if ev["suspicious"] else " "
        sev = ev["severity"] + mark
        line = f"{_pad(ev['ts'], 19)} {_pad(sev, 8)} {_pad(ev['phase'], 18)} {ev['summary']}"
        lines.append(line)
    if len(shown_events) > max_rows:
        lines.append(f"... 他 {len(shown_events) - max_rows} 件（表示対象{len(shown_events)}件）")
    lines.append("=" * 78)
    return "\n".join(lines)


def build_timeline_markdown(sections: dict, findings=None, event_logs=None,
                            full: bool = False) -> str:
    """run_analysis から呼ぶ想定: 年表テキストを ``` で囲んだ md を返す。

    TL-A: 呼び出し側は parsed["sections"] と parsed["event_logs"] の両方を
    渡すこと（event_logs を渡さないと着信RDP・サービス導入等が欠落する）。
    T-TL5: full=False（既定）で LOW 実行痕跡を抑制。full=True で全件展開。
    """
    tl = build_timeline(sections, findings, event_logs)
    if not tl.get("events"):
        return "## 感染タイムライン\n\n（タイムスタンプ付きイベントなし）\n"
    body = render_timeline_text(tl, full=full)
    return "## 感染タイムライン\n\n```\n" + body + "\n```\n"


def extract_findings_from_results(analyzed: dict) -> list:
    """analyzed.json から HIGH/MEDIUM 所見の IOC/パス/識別子を集める（不審突合用）。"""
    out = []
    secs = analyzed.get("sections", analyzed)
    if not isinstance(secs, dict):
        return out
    for sd in secs.values():
        if not isinstance(sd, dict):
            continue
        for e in sd.get("entries", []) or []:
            if not isinstance(e, dict):
                continue
            if e.get("score") in ("HIGH", "MEDIUM"):
                for ioc in e.get("iocs", []) or []:
                    if ioc:
                        out.append(str(ioc))
                ident = e.get("identifier", "")
                # identifier 末尾のパス/IPらしき部分も突合候補に。
                # TL-C: 旧 `[A-Za-z]:\\[^\s"]+` は空白で停止し
                #   "C:\Program Files\..." を "C:\Program" に切り詰め、
                #   部分一致で全 Program Files パスへ誤マッチしていた。
                #   拡張子で終わる完全パス（空白を含み得る）を優先抽出し、
                #   無ければ裸IPを拾う。固有性の低い切れ端は
                #   _normalize_findings 側のガードでも併せて除外する。
                m = re.search(
                    r'([A-Za-z]:\\[^"|\r\n]*?\.[A-Za-z0-9]{1,5})(?:["\s]|$)'
                    r'|(\b\d{1,3}(?:\.\d{1,3}){3}\b)',
                    str(ident))
                if m:
                    out.append(m.group(1) or m.group(2))
    return out


if __name__ == "__main__":
    import json
    import sys

    argv = [a for a in sys.argv[1:] if a != "--full"]
    full = "--full" in sys.argv

    if len(argv) < 1:
        print("usage: python timeline.py <parsed_or_analyzed.json> [analyzed.json] [--full]")
        print("  1引数 : その JSON の sections/event_logs からタイムライン生成")
        print("  2引数 : 2つ目(analyzed.json)の HIGH/MEDIUM 所見で不審(*)を標記")
        print("  --full: LOW実行痕跡(userassist/prefetch)も全件表示（既定は抑制）")
        sys.exit(1)

    with open(argv[0], encoding="utf-8") as f:
        data = json.load(f)
    sections = data.get("sections", data)
    event_logs = data.get("event_logs")  # TL-A: 着信RDP/7045/ログ消去の時刻源

    findings = []
    if len(argv) >= 2:
        with open(argv[1], encoding="utf-8") as f:
            findings = extract_findings_from_results(json.load(f))
    else:
        # 同一ファイルが analyzed なら自身から所見抽出
        findings = extract_findings_from_results(data)

    tl = build_timeline(sections, findings, event_logs)
    print(render_timeline_text(tl, full=full))

