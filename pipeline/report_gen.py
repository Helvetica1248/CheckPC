#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
report_gen.py  v2
analyze_section.py の出力と correlate.py の出力を受け取り、
Markdown 形式の最終レポートを生成する。

出力形式:
  report_*.md     — 標準版（HIGH/MEDIUM のみ。LOW は集計行のみ）
  report_*_all.md — 全件版（LOW エントリを全行展開、旧来と同等）

Usage:
    python report_gen.py <analyzed.json> <correlation.json> [-o report.md]
"""

import sys, json, os, argparse, re
from datetime import datetime
from collections import defaultdict

SCORE_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "CLEAN": "⚪"}
SUSPICION_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "NONE": "⚪"}
SCORE_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "CLEAN": 3}

SECTION_LABELS = {
    "persistence_reg":    "永続化レジストリ",
    "association_exe":    "EXE関連付け",
    "uac_bypass":         "UACバイパス痕跡",
    "com_persistence":    "COM永続化",
    "task_106":           "タスク登録イベント (EventID 106)",
    "task_140":           "タスク更新イベント (EventID 140)",
    "task_scheduler":     "タスクスケジューラ",
    "service":            "サービス",
    "directory":          "ディレクトリ / 不審ファイル",
    "dns_cache":          "DNS キャッシュ",
    "netstat":            "ネットワーク接続",
    "prefetch":           "Prefetch",
    "appcompat_cache":    "AppCompatCache (ShimCache)",
    "startup_folder":     "スタートアップフォルダ",
    "active_setup":       "Active Setup",
    "recent_behavior":    "最近使ったファイル",
    "ps_history":         "PowerShell 履歴",
    "wmi":                "WMI",
    "hosts":              "hosts ファイル",
    "psexec":             "PsExec 痕跡",
    "rdp":                "RDP 使用痕跡",
    "rdp_1024":           "RDP 外向き接続ログ (EventID 1024)",
    "rdp_inbound":        "着信 RDP ログオン (EventID 21/1149)",
    "known_tools":        "既知ツール/異常配置/Webシェル (決定論検出)",
    "userassist":         "UserAssist GUI実行痕跡 (T1204)",
    "bits":               "BITS",
    "bits_jobs":          "BITS ジョブ (T1197)",
    "pending_rename":     "PendingFileRenameOperations",
    "defender_quarantine":"Windows Defender 検知・隔離",
    "system_7045":        "新規サービスインストール (EventID 7045)",
    "security_1102":      "セキュリティログクリア (EventID 1102)",
    "system_104":         "システムログクリア (EventID 104)",
    "task_141":           "タスク削除イベント (EventID 141)",
}

# 横断相関の found_in を日本語に変換
SECTION_LABELS_SHORT = {
    "association_exe":    "EXE関連付け",
    "uac_bypass":         "UACバイパス",
    "active_setup":       "Active Setup",
    "com_persistence":    "COM永続化",
    "wmi":                "WMI Consumer",
    "task_106":           "タスク登録(106)",
    "task_140":           "タスク更新(140)",
    "recent_behavior":    "最近の操作",
    "persistence_reg":    "永続化レジストリ",
    "task_scheduler":     "タスクスケジューラ",
    "service":            "サービス",
    "directory":          "不審ファイル",
    "dns_cache":          "DNS",
    "netstat":            "ネットワーク",
    "prefetch":           "Prefetch",
    "appcompat_cache":    "ShimCache",
    "startup_folder":     "スタートアップ",
    "defender_quarantine":"Defender検知",
    "ps_history":         "PS履歴",
    "hosts":              "hostsファイル",
    "system_7045":        "新規サービス",
    "security_1102":      "ログクリア(Sec)",
    "system_104":         "ログクリア(Sys)",
    "rdp_1024":           "RDP接続(1024)",
    "bits_jobs":          "BITSジョブ",
    "task_141":           "タスク削除(141)",
    "rdp_inbound":        "着信RDP",
    "known_tools":        "既知ツール検出",
    "userassist":         "UserAssist実行",
}


def _fmt_datestamp(ds: str) -> str:
    """'2026060414400063' → '2026-06-04 14:40:00'"""
    try:
        s = str(ds)
        if len(s) >= 14:
            return f"{s[0:4]}-{s[4:6]}-{s[6:8]} {s[8:10]}:{s[10:12]}:{s[12:14]}"
    except Exception:
        pass
    return str(ds)


def fmt_score(score: str) -> str:
    return f"{SCORE_EMOJI.get(score, '❓')} **{score}**"


def fmt_list(items: list) -> str:
    if not items:
        return "なし"
    return ", ".join(f"`{i}`" for i in items)


_VT_STATUS_ORDER = {
    "malicious": 0,
    "suspicious": 1,
    # A clean result must never hide an error or an unconfirmed IOC in the
    # same entry.  Error/unknown therefore precede clean for conservative
    # reporting.
    "error": 2,
    "too_many_hits": 3,
    "unknown": 4,
    "clean": 5,
    "not_queried": 6,
}
_VT_STATUS_LABEL = {
    "malicious": "🔴 悪性",
    "suspicious": "🟠 要注意",
    "clean": "🟢 クリーン",
    "too_many_hits": "🟡 候補過多／照合不能",
    "unknown": "❔ 未登録",
    "error": "⚠ エラー／未確認",
    "not_queried": "— 未照合",
}


def _vt_entry_status(vt_results: list) -> str:
    """Return a conservative aggregate VT state for one report entry."""
    if not isinstance(vt_results, list) or not vt_results:
        return "not_queried"
    states = []
    for result in vt_results:
        if not isinstance(result, dict) or result.get("skipped"):
            states.append("not_queried")
            continue
        verdict = str(result.get("verdict", "error") or "error").lower()
        states.append(verdict if verdict in _VT_STATUS_ORDER else "error")
    return min(states or ["not_queried"], key=lambda s: _VT_STATUS_ORDER[s])


def fmt_vt(vt_results: list) -> str:
    if not vt_results:
        return _VT_STATUS_LABEL["not_queried"]
    best  = min(
        vt_results,
        key=lambda r: _VT_STATUS_ORDER.get(
            str(r.get("verdict", "error") or "error").lower(),
            _VT_STATUS_ORDER["error"],
        ),
    )
    verdict     = best.get("verdict", "error")
    pos         = best.get("positives", 0)
    total       = best.get("total", 0)
    vt_url      = best.get("vt_url", "")
    vt_names    = best.get("vt_names", [])[:1]
    vt_err      = best.get("vt_error", "")
    is_filepath = best.get("ioc_type") == "filepath"

    icon_map = {"malicious": "🔴", "suspicious": "🟠", "clean": "🟢",
                "too_many_hits": "🟡", "unknown": "❔", "error": "⚠"}
    icon = ("📎" if is_filepath else "") + icon_map.get(verdict, "❓")

    if verdict in ("malicious", "suspicious"):
        label = f"{pos}/{total}"
        if vt_names:
            label += f" ({vt_names[0].split(':')[0]})"
    elif verdict == "clean":
        label = f"0/{total}"
    elif verdict == "unknown":
        label = "未登録"
    elif verdict == "too_many_hits":
        hits = int(best.get("total_hits", 0) or 0)
        label = f"候補過多 ({hits}件)" if hits else "候補過多／照合不能"
    else:
        label = f"エラー: {vt_err[:24]}" if vt_err else "エラー"

    cell = f"[{icon} {label}]({vt_url})" if vt_url else f"{icon} {label}"
    if is_filepath:
        cell += "†"
    return cell


def _should_show_lolbas(entry: dict) -> str | None:
    """
    LoLBAS を表示すべきか判定して表示文字列を返す。返さない場合は None。

    基準（厳格化）:
      ・score が MEDIUM 以上であること（LOW は付与しない）
      ・かつ reason に実際の不審な用途の記述があること
        （「不審な引数」「非標準パス」「System32外」「encoded」「base64」
          「ダウンロード」「download」「certutil」「IEX」等のキーワード）
      ・Prefetch のみ（引数不明）の場合は付与しない
    """
    lolbas = entry.get("lolbas")
    if not lolbas:
        return None
    score = entry.get("score", "LOW")
    if SCORE_ORDER.get(score, 3) > 1:  # LOW / CLEAN は不可
        return None
    reason = entry.get("reason", "").lower()
    suspicious_keywords = [
        "不審な引数", "非標準パス", "system32外", "encoded", "base64",
        "ダウンロード", "download", "certutil", "iex", "invoke",
        "appdata", "temp\\", "programdata", "url", "-urlcache",
        "decoded", "obfuscat",
    ]
    has_suspicious = any(kw in reason for kw in suspicious_keywords)
    # Prefetch は引数不明なため付与しない
    is_prefetch_only = "pf" in entry.get("identifier", "").lower() and not has_suspicious
    if not has_suspicious or is_prefetch_only:
        return None
    return lolbas


def _semantic_occurrence_count(entry: dict) -> int:
    """Return the raw-observation multiplicity carried by a semantic group."""
    try:
        value = int((entry or {}).get("occurrence_count", 1) or 1)
    except (TypeError, ValueError):
        value = 1
    return max(1, value)


def _display_identifier(entry: dict, sec_name: str) -> str:
    """Render an identifier without hiding Task140 semantic-group multiplicity."""
    identifier = str((entry or {}).get("identifier", "") or "")
    if sec_name == "task_140":
        count = _semantic_occurrence_count(entry)
        if count > 1:
            identifier += f" （同一意味イベント ×{count}件）"
    return identifier


def _aggregate_low_entries(entries: list, sec_name: str) -> list[str]:
    """
    LOW エントリを集計してサマリ行のリストを返す（標準版レポート用）。
    
    グループ化:
      - 外部 443（HTTPS）
      - 外部 80（HTTP）
      - ループバック LISTENING
      - その他 LISTENING
      - その他外部接続
      - VT suspicious / malicious（LOW でも個別展開）
    """
    low_entries = [e for e in entries
                   if isinstance(e, dict) and e.get("score") == "LOW"]
    if not low_entries:
        return []

    lines = []

    # netstat は詳細グループ化
    if sec_name == "netstat":
        groups = defaultdict(list)
        individual = []  # VT suspicious/malicious は個別出力
        for e in low_entries:
            vt_list = e.get("_vt_results", [])
            vt_status = _vt_entry_status(vt_list)
            if vt_status in ("malicious", "suspicious"):
                individual.append(e)
                continue
            ident = e.get("identifier", "")
            if ":443" in ident and "→" in ident:
                groups[("外部 HTTPS (443)", vt_status)].append(ident)
            elif ":80" in ident and "→" in ident:
                groups[("外部 HTTP (80)", vt_status)].append(ident)
            elif "127.0.0.1" in ident and "→" not in ident:
                groups[("ループバック LISTENING", vt_status)].append(ident)
            elif "LISTENING" in ident or ("→" not in ident and "0.0.0.0" in ident):
                groups[("その他 LISTENING", vt_status)].append(ident)
            else:
                groups[("その他外部接続", vt_status)].append(ident)

        lines.append("| スコア | 種別 | 代表アドレス | 件数 | VT |")
        lines.append("|--------|------|--------------|:----:|----|")
        for (grp_label, vt_status), addrs in groups.items():
            rep = addrs[0].split("→")[-1].strip().split(":")[0] if addrs else ""
            if len(addrs) > 1:
                rep += " 他"
            lines.append(
                f"| {fmt_score('LOW')} | {grp_label} | `{rep}` | {len(addrs)} | "
                f"{_VT_STATUS_LABEL[vt_status]} |")
        for e in individual:
            ident  = e.get("identifier", "")
            reason = e.get("reason", "")[:100]
            vt_col = fmt_vt(e.get("_vt_results", []))
            lines.append(f"| {fmt_score('LOW')} | `{ident}` | {reason} | — | {vt_col} |")
    else:
        # netstat 以外は単純集計
        rep_ids = [_display_identifier(e, sec_name) for e in low_entries[:2]]
        rep_str = ", ".join(f"`{r[:56]}`" for r in rep_ids)
        if len(low_entries) > 2:
            rep_str += " 他"
        display_count = (
            sum(_semantic_occurrence_count(e) for e in low_entries)
            if sec_name == "task_140" else len(low_entries)
        )
        lines.append("| スコア | 識別子 | 件数 | VT |")
        lines.append("|--------|--------|:----:|----|")
        lines.append(f"| {fmt_score('LOW')} | {rep_str} | {display_count} | — |")

    return lines


# M-1: 標準版レポートでの MEDIUM 集約（_all 版=full では集約せず全展開）
#   高頻度・低多様性の MEDIUM（例: userassist の DL/デスクトップ実行、directory の
#   一時ファイル）を reason シグネチャ別にまとめ、見づらさを解消する。
#   検出データ自体は不変（entries は保持）で、標準版レポートの表示のみを集約する。
_MED_AGG_MIN = 4   # 同一シグネチャがこの件数以上なら集約（未満は個別展開）

# v3.61: 永続化判定に重要なセクションは MEDIUM を集約せず常に個別展開する。
# 実害事例(HOST-REF-08): task_scheduler の「\Micorsoft Visual Host Sync Update」
# （"Micorsoft" タイポスクワットの永続化タスク）が、同一 reason シグネチャの
# 4件集約により代表表示へ埋もれた。永続化系は1件1件が独立した確認対象のため
# 集約対象から除外する（HIGH は従来から常に全展開・変更なし）。
_MED_AGG_EXCLUDE_SECTIONS = {
    "task_scheduler", "task_140", "startup_folder", "service",
    "persistence_reg", "system_7045", "bits_jobs",
}


def _medium_signature(e: dict) -> str:
    """MEDIUM エントリの集約キー（reason 先頭文を数値・引用符具体値で正規化）。"""
    r = e.get("reason", "") or ""
    sig = re.split(r"[。\n]", r)[0]
    sig = re.sub(r"\d+", "N", sig)
    sig = re.sub(r"[`'\"][^`'\"]*[`'\"]", "…", sig)
    return sig.strip()[:60] or "(理由なし)"


def _medium_has_vt_flag(e: dict) -> bool:
    for r in e.get("_vt_results", []) or []:
        if r.get("verdict") in ("malicious", "suspicious"):
            return True
    return False


def _fmt_dt_jst(raw: str) -> str:
    """時刻文字列を JST 'YYYY-MM-DD HH:MM' へ整形する（v3.60）。
    TZ 正規化は timeline.py の TZ-1 実装（_parse_ts）を再利用:
    UTCマーカー(Z/+00:00)付きは +9h して JST 化、マーカー無しは無変換。
    解釈できない場合は元文字列の先頭16文字をそのまま返す（表示を壊さない）。"""
    try:
        import timeline as _tl
        d = _tl._parse_ts(raw)
        if d:
            return d.strftime("%Y-%m-%d %H:%M")
    except Exception:
        pass
    return (raw or "")[:16]


def _fmt_entry_datetime(e: dict) -> str:
    """エントリの日時セル文字列を返す（v3.60 / Defender検知日付）。
    · datetime_all（複数検知の集約）は初回〜最終の範囲＋件数で表示
    · datetime_kind=="更新" は directory_scan 由来（検知日時ではなく
      ファイル更新日時）のため出所を併記する
    · 日時なしは "—"（列が有効なセクションでの欠損表示）"""
    dts = e.get("datetime_all") or ([e["datetime"]] if e.get("datetime") else [])
    dts = sorted(d for d in dts if d)
    if not dts:
        return "—"
    if len(dts) == 1:
        s = _fmt_dt_jst(dts[0])
    else:
        s = f"{_fmt_dt_jst(dts[0])} 〜 {_fmt_dt_jst(dts[-1])}（{len(dts)}件）"
    if e.get("datetime_kind") == "更新":
        s += "（ファイル更新日時）"
    return s


def _entry_has_datetime(e) -> bool:
    return isinstance(e, dict) and bool(e.get("datetime") or e.get("datetime_all"))


def _aggregate_medium_entries(med_entries: list, sec_name: str,
                              date_col: bool = False):
    """MEDIUM を集約。戻り値: (個別展開する entries, 集約テーブル行のリスト)。

    · VT malicious/suspicious は常に個別展開（取りこぼし防止）。
    · 同一シグネチャが _MED_AGG_MIN 件以上 → 1 行に集約（件数＋代表）。
    · それ未満 → 個別展開に回す。
    · date_col=True（v3.60）: 集約行に日時セルを追加。集約対象の日時が
      あれば初回〜最終の範囲で表示する（Defender検知日付）。
    """
    groups = defaultdict(list)
    individual = []
    for e in med_entries:
        if _medium_has_vt_flag(e):
            individual.append(e)
            continue
        groups[_medium_signature(e)].append(e)

    agg_rows = []
    for sig, es in groups.items():
        if len(es) >= _MED_AGG_MIN:
            reps = ", ".join(f"`{(x.get('identifier','') or '')[:36]}`" for x in es[:2])
            if len(es) > 2:
                reps += " 他"
            row = (
                f"| {fmt_score('MEDIUM')}×{len(es)} | （集約）{sig} "
                f"| 代表: {reps} | — | — | — |"
            )
            if date_col:
                dts = sorted(d for x in es
                             for d in (x.get("datetime_all")
                                       or ([x["datetime"]] if x.get("datetime") else []))
                             if d)
                if not dts:
                    cell = "—"
                elif len(dts) == 1:
                    cell = _fmt_dt_jst(dts[0])
                else:
                    cell = f"{_fmt_dt_jst(dts[0])} 〜 {_fmt_dt_jst(dts[-1])}"
                row += f" {cell} |"
            agg_rows.append(row)
        else:
            individual.extend(es)
    return individual, agg_rows


_RDP_AGG_MIN = 3  # 同一接続元IPからの着信RDPがこの件数以上なら集約（未満は個別展開）


def _extract_rdp_ip(e: dict) -> str:
    """rdp_inbound エントリから接続元IPを抽出する（iocs優先、無ければidentifierから正規表現抽出）。"""
    iocs = e.get("iocs") or []
    if iocs:
        return iocs[0]
    m = re.search(r"接続元[=＝]([0-9a-fA-F.:]+)", e.get("identifier", "") or "")
    return m.group(1) if m else "(接続元不明)"


def _extract_rdp_timestamp(e: dict) -> str:
    m = re.search(r"(\d{4}-\d{2}-\d{2}T[\d:.]+)", e.get("identifier", "") or "")
    return m.group(1) if m else ""


def _extract_rdp_user(e: dict) -> str:
    m = re.search(r"ユーザー[=＝]([^\s]+)", e.get("identifier", "") or "")
    return m.group(1) if m else ""


def _aggregate_rdp_entries(entries: list):
    """rdp_inbound 専用の集約: 同一接続元IPからの着信RDPを、スコア（HIGH/LOW）を
    問わず1行に集約する（_aggregate_medium_entriesと異なり、reasonの数値を
    正規化して曖昧にグルーピングするのではなく、実際のIP値でグルーピングする）。

    実運用で発覚: VM管理基盤ホスト等で同一IPからの着信RDPが数百件記録され、
    HIGHスコアの個別行が延々と並んでレポートの可読性を著しく損なっていた
    （常に個別展開されるHIGHはM-1のMEDIUM集約の対象外だったため）。

    戻り値: (個別展開する entries, 集約テーブル行のリスト)
    """
    groups = defaultdict(list)
    individual = []
    for e in entries:
        if _medium_has_vt_flag(e):
            individual.append(e)
            continue
        groups[_extract_rdp_ip(e)].append(e)

    agg_rows = []
    for ip, es in groups.items():
        if len(es) >= _RDP_AGG_MIN:
            timestamps = sorted(t for t in (_extract_rdp_timestamp(x) for x in es) if t)
            date_range = f"{timestamps[0][:10]}〜{timestamps[-1][:10]}" if timestamps else "?"
            worst_score = min((x.get("score", "LOW") for x in es),
                               key=lambda s: SCORE_ORDER.get(s, 3))
            users = sorted({u for u in (_extract_rdp_user(x) for x in es) if u})
            user_str = ", ".join(users[:3]) + (" 他" if len(users) > 3 else "")
            reason = (es[0].get("reason", "") or "").split("。")[0]
            mitre = fmt_list(es[0].get("mitre", []))
            agg_rows.append(
                f"| {fmt_score(worst_score)}×{len(es)} | （集約）{ip} からの着信RDP {len(es)}件 "
                f"| {reason}。期間: {date_range}／ユーザー: {user_str or '不明'} | `{ip}` | {mitre} | — |"
            )
        else:
            individual.extend(es)
    return individual, agg_rows


def section_entries_md(sec_name: str, sec_data: dict,
                       full: bool = False) -> str:
    """
    1 セクションの評価結果を Markdown テーブルに変換する。

    full=False（標準版）: HIGH/MEDIUM は全件展開、LOW は集計サマリのみ
    full=True （全件版）: LOW も含めて全件展開（旧来の動作）
    """
    if not isinstance(sec_data, dict):
        return ""

    label   = SECTION_LABELS.get(sec_name, sec_name)
    summary = sec_data.get("section_summary", "")
    entries = sec_data.get("entries", [])
    if not isinstance(entries, list):
        return ""
    if sec_name == "directory":
        entries = [
            e for e in entries
            if not (
                isinstance(e, dict)
                and str(e.get("identifier") or "").startswith("⚠ directory: 同型パターン")
            )
        ]

    # rdp_inbound: 標準版(full=False)のみ、同一接続元IPの着信RDPを
    # スコアに関係なく集約する（VM管理基盤ホスト等で同一IPからの接続が
    # 数百件記録され、HIGHが個別展開のまま延々と並ぶ問題への対応）。
    rdp_agg_rows = []
    if sec_name == "rdp_inbound" and not full:
        entries, rdp_agg_rows = _aggregate_rdp_entries(entries)

    hm_entries = [e for e in entries if isinstance(e, dict)
                  and SCORE_ORDER.get(e.get("score", "CLEAN"), 3) <= 1]
    high_entries = [e for e in hm_entries if e.get("score") == "HIGH"]
    med_entries  = [e for e in hm_entries if e.get("score") == "MEDIUM"]
    low_entries = [e for e in entries if isinstance(e, dict)
                   and e.get("score") == "LOW"]

    # v3.60: 日時列（Defender検知日付）。日時を持つエントリが1件でもあれば
    # このセクションのテーブルに「日時(JST)」列を追加する（他セクションは不変）。
    date_col = any(_entry_has_datetime(e) for e in entries)

    # M-1: 標準版は MEDIUM を集約（HIGH は常に全展開）。_all 版(full)は全展開。
    # v3.61: 永続化系セクション（_MED_AGG_EXCLUDE_SECTIONS）は標準版でも
    # 集約せず全件個別展開する。
    med_agg_rows = []
    if full or sec_name in _MED_AGG_EXCLUDE_SECTIONS:
        med_shown = med_entries
    else:
        med_individual, med_agg_rows = _aggregate_medium_entries(
            med_entries, sec_name, date_col=date_col)
        med_shown = med_individual
    hm_shown = high_entries + med_shown

    all_shown = hm_shown + (low_entries if full else [])

    # rc17: Depth2でrawが存在するのに全件がdeferredとなったsectionを
    # 「所見なし」と表示してはならない。選抜前証拠が未評価であることを
    # 標準版・全件版・PDF経路の共通Markdownへ明示する。
    selection_stats = sec_data.get("_selection_stats") or {}
    raw_n = int(selection_stats.get("raw", 0) or 0)
    selected_n = int(selection_stats.get("selected", 0) or 0)
    deterministic_n = int(selection_stats.get("deterministic", 0) or 0)
    deferred_n = int(selection_stats.get("deferred",
                                         selection_stats.get("deferred_by_policy", 0)) or 0)
    all_deferred = (raw_n > 0 and selected_n == 0 and deterministic_n == 0
                    and deferred_n >= raw_n)
    if all_deferred:
        by_reason = selection_stats.get("by_reason") or {}
        reason_parts = []
        for key, value in sorted(by_reason.items()):
            reason_name = str(key).split(":", 1)[1] if str(key).startswith("deferred:") else ""
            if (str(key).startswith("deferred:") and int(value or 0) > 0
                    and not (sec_name == "directory" and reason_name == "signature_diversity")):
                reason_parts.append(f"{reason_name}={int(value)}")
        reasons = " / ".join(reason_parts) if reason_parts else "理由詳細なし"
        budget = int(selection_stats.get("global_budget", 0) or 0)
        planned = int(selection_stats.get("global_planned_output_tokens", 0) or 0)
        return (
            f"<details class=\"sec-deferred\" open><summary>{label}（全件繰延・未評価）</summary>\n\n"
            f"> ⚠ **このセクションには raw 証拠が {raw_n} 件ありますが、Depth2選抜では"
            f"全件が繰延され、LLM評価も決定論評価も行われていません。**\n>\n"
            f"> 選抜={selected_n} / 決定論={deterministic_n} / 繰延={deferred_n}"
            f" / 理由: {reasons}\n"
            + (f"> グローバル計画={planned} tokens / 予算={budget} tokens\n"
               if budget else "")
            + "> **「所見なし」または安全確認済みを意味しません。raw証拠の再確認、"
              "Depth1比較、または予算・選抜条件を調整した再解析が必要です。**\n\n"
            + (f"> 元のsection summary: {summary}\n\n" if summary else "")
            + "</details>\n"
        )

    if (not all_shown and not summary and not med_agg_rows and not rdp_agg_rows
            and not (low_entries and not full)):
        return ""

    # 所見なし（summaryはあるがHIGH/MEDIUM/LOW/集約行が一切無い）の場合は
    # 折りたたみ表示にする（レポート可視性改善: セクション数が多いホストで
    # 「エントリなし」が延々と並び冗長になるのを防ぐ）。
    if not hm_shown and not rdp_agg_rows and not med_agg_rows and not low_entries:
        body = f"> {summary}\n\n" if summary else ""
        return (
            f"<details class=\"sec-empty\"><summary>{label}（所見なし）</summary>\n\n"
            f"{body}*HIGH/MEDIUM/LOW エントリなし*\n\n</details>\n"
        )

    lines = [f"### {label}", ""]
    schema_warnings = sec_data.get("_schema_warnings") or []
    if sec_data.get("schema_degraded") or schema_warnings:
        lines += [
            "> ⚠ **LLM score schema recoveryが発生しました。** 許容外scoreを"
            "MEDIUMへ安全縮退し、原値を`score_raw`へ保存しています。正式回帰では要確認です。",
            "",
        ]
    # 修正(2026-07-11 / v3.58): HIGH/MEDIUM が個別テーブルとして展開される
    # 場合、冒頭の summary（identifier/reasonを40/80文字に切り詰めて連結した
    # もの）は直後のテーブルと内容が完全に重複する上、パスが途中で
    # 切れて読みにくいという指摘があったため省略する。
    # summary が実質的な情報を持つのは、個別展開されない
    # （med_agg_rows/rdp_agg_rows のみで hm_shown が空の）集約表示時のみ。
    if summary and not hm_shown:
        lines += [f"> {summary}", ""]

    if hm_shown or rdp_agg_rows or (full and low_entries):
        lines += [
            "| スコア | 識別子 | 根拠 | IOC | MITRE | VT |" + (" 日時(JST) |" if date_col else ""),
            "|--------|--------|------|-----|-------|----|" + ("-----------|" if date_col else ""),
        ]
        shown = sorted(all_shown if full else hm_shown,
                       key=lambda x: SCORE_ORDER.get(x.get("score", "CLEAN"), 3))
        for e in shown:
            score      = e.get("score", "?")
            identifier = _display_identifier(e, sec_name)
            reason     = e.get("reason", "").replace("\n", " ")[:200]
            iocs       = fmt_list(e.get("iocs", []))
            mitre      = fmt_list(e.get("mitre", []))
            decoded    = e.get("decoded")
            lolbas_str = _should_show_lolbas(e)
            vt_col     = fmt_vt(e.get("_vt_results", []))

            # LoLBAS を reason 列に括弧付記（独立行をやめる）
            if lolbas_str:
                reason = f"{reason}（LoLBAS: {lolbas_str}）"

            lines.append(
                f"| {fmt_score(score)} | `{identifier}` | {reason} | {iocs} | {mitre} | {vt_col} |"
                + (f" {_fmt_entry_datetime(e)} |" if date_col else "")
            )
            if decoded:
                lines.append(f"| | | **デコード**: `{decoded[:200]}` | | | |"
                             + (" |" if date_col else ""))
        # RDP集約行を末尾に付加（rdp_inbound標準版のみ）
        for row in rdp_agg_rows:
            lines.append(row + (" — |" if date_col else ""))
        if rdp_agg_rows:
            n_agg = sum(int(r.split("×")[1].split(" ")[0]) for r in rdp_agg_rows)
            lines.append(
                f"| | *↑ 同一IPからの着信RDP {n_agg}件をIPごとに集約"
                f"（全件は _all 版参照）* | | | | |" + (" |" if date_col else ""))
        # M-1: 集約した MEDIUM 行を表末尾に付加（標準版のみ）
        for row in med_agg_rows:
            lines.append(row)
        if med_agg_rows:
            n_agg = sum(int(r.split("×")[1].split(" ")[0]) for r in med_agg_rows)
            lines.append(
                f"| | *↑ MEDIUM {n_agg}件を集約（全件は _all 版参照）* | | | | |"
                + (" |" if date_col else ""))
    elif med_agg_rows or rdp_agg_rows:
        # HIGH/個別MEDIUM が無く集約行のみの場合もテーブルを出す
        lines += [
            "| スコア | 識別子 | 根拠 | IOC | MITRE | VT |" + (" 日時(JST) |" if date_col else ""),
            "|--------|--------|------|-----|-------|----|" + ("-----------|" if date_col else ""),
        ]
        for row in rdp_agg_rows:
            lines.append(row + (" — |" if date_col else ""))
        if rdp_agg_rows:
            n_agg = sum(int(r.split("×")[1].split(" ")[0]) for r in rdp_agg_rows)
            lines.append(
                f"| | *↑ 同一IPからの着信RDP {n_agg}件をIPごとに集約"
                f"（全件は _all 版参照）* | | | | |" + (" |" if date_col else ""))
        for row in med_agg_rows:
            lines.append(row)
        if med_agg_rows:
            n_agg = sum(int(r.split("×")[1].split(" ")[0]) for r in med_agg_rows)
            lines.append(
                f"| | *↑ MEDIUM {n_agg}件を集約（全件は _all 版参照）* | | | | |"
                + (" |" if date_col else ""))
    elif not low_entries:
        lines.append("*HIGH/MEDIUM/LOW エントリなし*")

    # 標準版: LOW 集計サマリ
    if not full and low_entries:
        if hm_entries:
            lines.append("")
        agg = _aggregate_low_entries(low_entries, sec_name)
        if agg:
            if not hm_entries:
                # テーブルヘッダがまだない場合は集計ヘッダが先頭
                lines += agg
            else:
                # HIGH/MEDIUM テーブルの後ろに LOW 集計を付加
                # ヘッダなし（既にある）で中身だけ
                for row in agg:
                    if not row.startswith("|-----") and not row.startswith("| スコア"):
                        lines.append(row)
                    else:
                        lines.append(row)
    lines.append("")
    return "\n".join(lines)


def _safe_fallback_reason(value: object, limit: int = 200) -> str:
    """Render fallback metadata safely inside a Markdown inline-code span."""
    text = str(value)
    text = "".join(" " if ord(ch) < 32 or ord(ch) == 127 else ch for ch in text)
    text = re.sub(r"\s+", " ", text).strip().replace("`", "'")
    if not text:
        return "<empty>"
    return text[:limit]


def _fmt_vt_summary(vt_summ: dict) -> str:
    """VT 照合結果を1行テキストにまとめる。"""
    if not vt_summ:
        return "—"

    def _scope_summary(label: str, total: int, status: dict,
                       filepath: bool = False) -> str:
        malicious = int(status.get("malicious", 0) or 0)
        suspicious = int(status.get("suspicious", 0) or 0)
        clean = int(status.get("clean", 0) or 0)
        not_found = int(status.get("not_found", status.get("unknown", 0)) or 0)
        too_many = int(status.get("too_many_hits", 0) or 0)
        errors = int(status.get("error", 0) or 0)
        not_queried = int(status.get("not_queried", 0) or 0)
        completed = malicious + suspicious + clean + not_found
        response_label = "代表判定" if filepath else "判定完了"
        parts = [f"{label}: 対象 {total} 件", f"{response_label} {completed} 件"]
        if malicious:
            parts.append(("同名悪性" if filepath else "悪性") + f" {malicious} 件")
        if suspicious:
            parts.append(("同名要注意" if filepath else "要注意") + f" {suspicious} 件")
        if clean:
            parts.append(("同名クリーン" if filepath else "クリーン") + f" {clean} 件")
        if not_found:
            parts.append(f"未登録 {not_found} 件")
        if too_many:
            parts.append(f"候補過多 {too_many} 件")
        if errors:
            parts.append(f"エラー {errors} 件")
        if not_queried:
            parts.append(f"未照合 {not_queried} 件")
        return " / ".join(parts)

    exact = vt_summ.get("exact_status_counts")
    filepath = vt_summ.get("filepath_status_counts")
    if isinstance(exact, dict) and isinstance(filepath, dict):
        exact_total = int(vt_summ.get("exact_total_iocs", sum(exact.values())) or 0)
        filepath_total = int(vt_summ.get("filepath_total_iocs", sum(filepath.values())) or 0)
        scopes = []
        if exact_total or any(exact.values()):
            scopes.append(_scope_summary("正確IOC照合", exact_total, exact, filepath=False))
        if filepath_total or any(filepath.values()):
            scopes.append(_scope_summary("filepath参考検索", filepath_total, filepath, filepath=True))
        return "<br>".join(scopes) if scopes else "実施なし"

    status = vt_summ.get("status_counts")
    if isinstance(status, dict):
        total = int(vt_summ.get("total_iocs", 0) or 0)
        malicious = int(status.get("malicious", 0) or 0)
        suspicious = int(status.get("suspicious", 0) or 0)
        clean = int(status.get("clean", 0) or 0)
        not_found = int(status.get("not_found", status.get("unknown", 0)) or 0)
        too_many = int(status.get("too_many_hits", 0) or 0)
        errors = int(status.get("error", 0) or 0)
        not_queried = int(status.get("not_queried", 0) or 0)
        completed = malicious + suspicious + clean + not_found
        parts = [f"対象 {total} 件", f"API応答 {completed} 件"]
        if malicious:
            parts.append(f"悪性 {malicious} 件")
        if suspicious:
            parts.append(f"要注意 {suspicious} 件")
        if clean:
            parts.append(f"クリーン {clean} 件")
        if not_found:
            parts.append(f"未登録 {not_found} 件")
        if too_many:
            parts.append(f"候補過多 {too_many} 件")
        if errors:
            parts.append(f"エラー {errors} 件")
        if not_queried:
            parts.append(f"未照合 {not_queried} 件")
        return " / ".join(parts)

    # Backward-compatible rendering for pre-rc14 analyzed files.  Legacy
    # summaries cannot distinguish filepath errors from successful searches,
    # so never infer or display a clean count from the residual total.
    parts = []
    total = vt_summ.get("total_iocs", 0)
    if total:
        parts.append(f"対象 {total} 件")
    mal = vt_summ.get("malicious", 0)
    if mal:
        parts.append(f"悪性 {mal} 件")
    clean = vt_summ.get("clean_downgraded", 0)
    if clean:
        parts.append(f"クリーン降格 {clean} 件")
    not_found = vt_summ.get("not_found", 0)
    if not_found:
        parts.append(f"未登録 {not_found} 件")
    errors = vt_summ.get("errors", 0)
    if errors:
        parts.append(f"エラー {errors} 件以上")
    fp = vt_summ.get("filepath_searched", 0)
    fp_mal = vt_summ.get("filepath_malicious_noted", 0)
    if fp:
        parts.append(f"filepath参考 {fp} 件（同名悪性 {fp_mal} 件）")
    if not parts:
        return "実施なし"
    return " / ".join(parts)


# ─────────────────────────────────────────────────────────────
# 決定論フォールバック層（R-3 / R-4）
#
# correlate の infection_suspicion / malware_family は LLM 判断に依存し、
# 揺らぎで None や Unknown を返すことがある（HIGH=0 で suspicion=None、
# 明白な Defender 検知があるのに family=Unknown 等）。known_tools 等と同じく
# 決定論で補完し、レポートに None/Unknown をそのまま出さない安全網とする。
# 取りこぼし防止: LLM が値を出せなかった場合のみ作動し、有効値は上書きしない。
# ─────────────────────────────────────────────────────────────

# Defender 検知名 "Platform:Type/Family!suffix" から Family を抜く。
#   例: Trojan:MSIL/Darkvigil.NWA!MTB → Darkvigil.NWA
#       Adware:Win32/Tnega            → Tnega
#       Trojan:Win32/Cerdigent.A!dha  → Cerdigent.A
_DEFENDER_NAME_RE = re.compile(
    r"^[A-Za-z][\w\-]*:[A-Za-z0-9]+/([A-Za-z0-9][\w\.\-]*?)(?:![\w]+)?$")


def _count_scores(analyzed: dict) -> dict:
    """analyzed の全エントリのスコア別件数を数える。"""
    cnt = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
    for sd in analyzed.get("sections", {}).values():
        if not isinstance(sd, dict):
            continue
        for e in sd.get("entries", []) or []:
            if isinstance(e, dict):
                s = e.get("score")
                if s in cnt:
                    cnt[s] += 1
    return cnt


def derive_suspicion_floor(analyzed: dict) -> str:
    """R-4: HIGH/MEDIUM/LOW 件数から感染嫌疑の決定論的な床を返す。

    LLM が infection_suspicion を出せなかった場合の安全網。所見の存在に
    応じて下限を与える（過小評価＝取りこぼしを防ぐ）。HIGH を捏造はしない。
    """
    c = _count_scores(analyzed)
    if c["HIGH"] > 0:
        return "HIGH"
    if c["MEDIUM"] > 0:
        return "MEDIUM"
    if c["LOW"] > 0:
        return "LOW"
    return "NONE"


def derive_malware_family(analyzed: dict) -> str:
    """R-3: Defender HIGH 検知名（identifier）からファミリー名を決定論抽出する。

    HIGH を優先し、出現頻度の高い順に最大3ファミリーを "/" 連結で返す。
    検知が無ければ空文字。LLM が Unknown/空を返した場合のみ採用する。
    """
    from collections import Counter
    dq = analyzed.get("sections", {}).get("defender_quarantine", {})
    if not isinstance(dq, dict):
        return ""
    fams = Counter()
    for e in dq.get("entries", []) or []:
        if not isinstance(e, dict) or e.get("score") != "HIGH":
            continue
        ident = str(e.get("identifier", "")).strip()
        m = _DEFENDER_NAME_RE.match(ident)
        if m:
            fams[m.group(1)] += 1
    if not fams:
        return ""
    top = [name for name, _ in fams.most_common(3)]
    return " / ".join(top)


def apply_deterministic_fallback(corr: dict, analyzed: dict) -> dict:
    """corr の infection_suspicion / malware_family を決定論で補完（in-place）。

    LLM が None/N/A/Unknown を返した場合のみ作動し、有効値は上書きしない。
    補完した項目は corr['_meta_flags'] にフラグを立てて来歴を残す（冪等）。
    correlate.py / run_analysis.py / report_gen.py から共用する単一実装。
    """
    flags = corr.setdefault("_meta_flags", {})
    susp = corr.get("infection_suspicion")
    if susp in (None, "", "N/A", "null", "None"):
        corr["infection_suspicion"] = derive_suspicion_floor(analyzed)
        flags["suspicion_fallback"] = True
    fam = corr.get("malware_family")
    if not fam or fam in ("Unknown", "unknown", "N/A", "null"):
        derived = derive_malware_family(analyzed)
        if derived:
            corr["malware_family"] = derived
            flags["family_fallback"] = True
    return corr


def _count_wl_suppressed(analyzed: dict) -> int:
    """[任意2] filepath whitelist により CLEAN 降格されたエントリ数を数える。

    CLEAN 降格エントリはレポートに描画されないため、抑制が働いた件数を
    監査目的でヘッダに明示するためのカウント。reason マーカーで判定する。
    """
    n = 0
    for sd in analyzed.get("sections", {}).values():
        if not isinstance(sd, dict):
            continue
        for e in sd.get("entries", []) or []:
            if (isinstance(e, dict) and e.get("score") == "CLEAN"
                    and "WL: CLEAN降格" in str(e.get("reason", ""))):
                n += 1
    return n


def _directory_coverage_notice(analyzed: dict) -> list[str]:
    section = (analyzed.get("sections", {}) or {}).get("directory", {})
    if not isinstance(section, dict):
        return []
    policy = section.get("_directory_policy") or section.get("directory_policy") or {}
    if not isinstance(policy, dict):
        return []
    total = sum(int(v or 0) for v in (policy.get("tier_total") or {}).values())
    selected = sum(int(v or 0) for v in (policy.get("tier_selected") or {}).values())
    deferred = max(0, total - selected)
    if not deferred and not policy.get("coverage_degraded"):
        return []
    reasons = policy.get("deferred_reason_counts") or {}
    # signature_diversity is internal selection accounting.  It is intentionally
    # omitted from the user-facing report because the candidate/evaluated counts
    # already communicate the coverage limitation without repeating an
    # implementation detail.
    reason_text = "、".join(
        f"{key}={int(value or 0)}" for key, value in sorted(reasons.items())
        if key != "signature_diversity" and int(value or 0)
    )
    lines = [
        "---", "## ⚠ directory個別評価カバレッジ", "",
        f"> **候補 {total:,}件中、個別LLM評価 {selected:,}件、未個別評価 {deferred:,}件です。**",
        "> 未個別評価の証拠は削除されておらず、parsed raw索引およびチャットraw検索で確認できます。",
        "> この警告がある場合、レポート記載分だけで端末上のファイル不存在を断定しないでください。",
    ]
    if reason_text:
        lines.append(f"> 繰延理由: {reason_text}")
    lines.append("")
    return lines


def generate_report(analyzed: dict, correlation: dict,
                    full: bool = False) -> str:
    """
    最終 Markdown レポートを生成する。

    full=False（デフォルト）: 標準版（HIGH/MEDIUM のみ展開、LOW は集計）
    full=True              : 全件版（LOW も全行展開）
    """
    meta      = analyzed.get("meta", correlation.get("meta", {}))
    hostname  = meta.get("hostname", "UNKNOWN")
    datestamp = meta.get("datestamp", "")
    checkpc_v = meta.get("checkpc_version", "?")
    depth     = analyzed.get("depth", correlation.get("depth", 2))
    depth_labels = {1: "Quick", 2: "Standard", 3: "Deep", 4: "Exhaustive"}
    now_str   = datetime.now().strftime("%Y-%m-%d %H:%M")
    vt_summ   = analyzed.get("_vt_summary", {})
    wl_suppressed = _count_wl_suppressed(analyzed)   # [任意2] WL抑制件数

    # ── 決定論フォールバック（R-4: suspicion / R-3: family）──────
    # correlate 側で既に補完済みなら _meta_flags が立っている。未補完の
    # 古い correlation.json に対しても、ここで冪等に補完する（防御多重化）。
    correlation = dict(correlation)  # 呼び出し側への副作用を避けるため浅いコピー
    apply_deterministic_fallback(correlation, analyzed)
    suspicion    = correlation.get("infection_suspicion", "N/A")
    summary_text = correlation.get("infection_summary", "")
    malware_fam  = correlation.get("malware_family", "Unknown")
    _flags = correlation.get("_meta_flags", {})
    _susp_fallback = bool(_flags.get("suspicion_fallback"))
    _fam_fallback  = bool(_flags.get("family_fallback"))

    corr_iocs    = correlation.get("correlated_iocs", [])
    timeline     = correlation.get("timeline", [])
    # MITRE dedup + ソート
    mitre_ttps   = sorted(set(correlation.get("mitre_ttps", [])))
    rec_actions  = correlation.get("recommended_actions", [])
    inf_vector   = correlation.get("infection_vector", "")
    apt_sim      = correlation.get("apt_similarity", "")
    evasion      = correlation.get("evasion_techniques", [])
    remediation  = correlation.get("remediation", {})

    lines = []

    # ── ヘッダ ──────────────────────────────────────────────
    report_type = "（全件版）" if full else ""
    lines += [
        f"# マルウェア解析レポート{report_type}",
        "",
        "| 項目 | 値 |",
        "|------|-----|",
        f"| ホスト名          | `{hostname}` |",
        f"| 調査日時          | {_fmt_datestamp(datestamp)} |",
        f"| レポート生成日時   | {now_str} |",
        f"| CheckPC バージョン | {checkpc_v} |",
        f"| パイプライン       | {meta.get('pipeline_version', '?')} / schema {meta.get('analysis_schema_version', '?')} |",
        f"| 解析深度          | {depth} ({depth_labels.get(depth, '?')}) |",
        f"| VT 照合結果       | {_fmt_vt_summary(vt_summ)} |",
        f"| WL抑制（既知正規） | {wl_suppressed} 件を CLEAN 降格（filepath whitelist 一致） |",
        "",
    ]

    # rev12: 「収集品質・解析制約」は最終レポート冒頭から削除。
    # evidence_state自体はanalyzed artifactに保持し、解析・監査情報は失わない。

    _retry = correlation.get("_correlate_retry") or {}
    if correlation.get("output_truncated"):
        lines += [
            "---", "## ⚠ 横断相関出力の制限", "",
            "横断相関出力はモデルの出力上限で打ち切られました。"
            "完結したJSON部分と決定論的補完を使用しています。",
            "IOC・タイムライン・推奨対応が全件ではない可能性があります。", "",
        ]
    elif _retry.get("fallback_applied"):
        _fallback_reason = _safe_fallback_reason(
            _retry.get("fallback_reason") or "unknown")
        lines += [
            "---", "## ⚠ 横断相関フォールバック", "",
            "横断相関LLM結果を取得できなかったため、"
            "本セクションは決定論的フォールバックのみで生成されています。",
            f"原因コード: `{_fallback_reason}`",
        ]
        if "fallback_reason_raw" in _retry and _retry.get("fallback_reason_raw") is not None:
            _fallback_reason_raw = _safe_fallback_reason(_retry.get("fallback_reason_raw"))
            lines += [
                f"元の原因コード: `{_fallback_reason_raw}`",
                "未認識の原因コードを安全な既定値へ縮退しています。",
            ]
        lines += [""]
    elif correlation.get("parse_error"):
        lines += [
            "---", "## ⚠ 横断相関メタデータ不整合", "",
            "相関処理エラーが記録されていますが、"
            "フォールバック状態メタデータが欠落しています。",
            "結果の完全性を確認してください。", "",
        ]

    # ── 感染嫌疑サマリ ───────────────────────────────────────
    sus_emoji = SUSPICION_EMOJI.get(suspicion, "❓")
    _susp_note = "（決定論フォールバック: LLM未判定のため所見件数から算出）" if _susp_fallback else ""
    lines += ["---", f"## {sus_emoji} 感染嫌疑評価: {suspicion}{_susp_note}", ""]
    if summary_text:
        lines += [summary_text, ""]
    if malware_fam and malware_fam != "Unknown":
        _fam_note = "（Defender検知名から決定論抽出）" if _fam_fallback else ""
        lines += [f"**推定マルウェアファミリー**: `{malware_fam}`{_fam_note}", ""]
    if inf_vector:
        lines += [f"**推定感染経路**: {inf_vector}", ""]
    if apt_sim:
        lines += [f"**類似APTグループ**: {apt_sim}", ""]
    if evasion:
        lines += ["**検出回避手法**:", *[f"- {e}" for e in evasion], ""]

    # ── 推奨アクション ───────────────────────────────────────
    if rec_actions or remediation:
        lines += ["---", "## 推奨アクション", ""]
        if remediation:
            phase_labels = {
                "immediate":  "🚨 即時対応（1時間以内）",
                "short_term": "⚡ 短期対応（24時間以内）",
                "long_term":  "📋 長期対応（1週間以内）",
            }
            for phase, items in remediation.items():
                lines.append(f"### {phase_labels.get(phase, phase)}")
                for item in items:
                    lines.append(f"- {item}")
                lines.append("")
        elif rec_actions:
            for item in rec_actions:
                lines.append(f"- {item}")
            lines.append("")

    # ── MITRE ATT&CK（dedup済み）────────────────────────────
    if mitre_ttps:
        lines += [
            "---", "## MITRE ATT&CK TTP", "",
            "| テクニック ID | リンク |",
            "|---------------|--------|",
        ]
        for ttp in mitre_ttps:
            url = f"https://attack.mitre.org/techniques/{ttp.replace('.', '/')}/".rstrip("/") + "/"
            lines.append(f"| `{ttp}` | [{ttp}]({url}) |")
        lines.append("")

    # ── 横断相関 IOC（found_in を日本語化、カテゴリ別グルーピング）──
    if corr_iocs:
        _CATEGORY_LABELS = {
            "external_intrusion":  "🔴 外部侵入の兆候",
            "internal_automation": "🔵 内部の設定変更・自動化ツール",
            "internal_unclear":    "🟠 内部通信・用途不明",
            "unclear":             "⚪ 不明・要確認",
        }
        _CATEGORY_ORDER = ["external_intrusion", "internal_unclear", "unclear", "internal_automation"]
        grouped = defaultdict(list)
        for ioc in corr_iocs:
            cat = ioc.get("category") or "unclear"
            if cat not in _CATEGORY_LABELS:
                cat = "unclear"
            grouped[cat].append(ioc)

        lines += ["---", "## 横断相関 IOC", ""]
        for cat in _CATEGORY_ORDER:
            if cat not in grouped:
                continue
            lines += [
                f"### {_CATEGORY_LABELS[cat]}（{len(grouped[cat])}件）", "",
                "| IOC | 検出セクション | 意味 | 既知サービス |",
                "|-----|----------------|------|--------------|",
            ]
            for ioc in grouped[cat]:
                val = str(ioc.get("ioc", ""))
                port = ioc.get("ioc_port")
                if isinstance(port, int) and 1 <= port <= 65535:
                    val = f"[{val}]:{port}" if ":" in val else f"{val}:{port}"
                found_in = ", ".join(
                    SECTION_LABELS_SHORT.get(s, s)
                    for s in ioc.get("found_in", [])
                )
                sig = ioc.get("significance", "")
                svc = ioc.get("known_service", "") or "—"
                lines.append(f"| `{val}` | {found_in} | {sig} | {svc} |")
            lines.append("")

    # ── タイムライン ──────────────────────────────────────────
    # 方針変更: LLMによる「推定タイムライン」は情報が雑になりやすく
    # レポートの可読性を損なうため、本体には含めず、決定論的な
    # timeline.py出力（別ファイル）への参照のみ示す（実運用の
    # フィードバックにより変更。タイムライン自体の精度改善は別途課題）。
    if timeline:
        lines += [
            "---",
            "## タイムライン",
            "",
            f"推定タイムライン（{len(timeline)}件のイベント）は本レポートには含まれません。"
            "GUIの「📅 タイムライン表示」ボタン、または"
            f"`report_{hostname}_{datestamp}_timeline.md`"
            "（決定論的に抽出された感染タイムライン）を参照してください。",
            "",
        ]

    # ── directory個別評価カバレッジ ─────────────────────────
    lines += _directory_coverage_notice(analyzed)

    # ── セクション別詳細 ─────────────────────────────────────
    lines += ["---", "## セクション別評価詳細", ""]
    section_results = analyzed.get("sections", {})
    for sec_name in [
        "known_tools", "rdp_inbound", "userassist",
        "startup_folder", "defender_quarantine",
        "persistence_reg", "task_scheduler", "service",
        "directory", "dns_cache", "netstat", "prefetch",
        "appcompat_cache", "ps_history",
        "hosts", "system_7045",
        "security_1102", "system_104",
        "rdp_1024", "bits_jobs", "task_141", "psexec",
    ]:
        sec_data = section_results.get(sec_name)
        if sec_data:
            md = section_entries_md(sec_name, sec_data, full=full)
            if md:
                lines.append(md)

    # ── VT filepath 注記 ──────────────────────────────────────
    if (vt_summ.get("filepath_searched", 0) > 0
            or vt_summ.get("filepath_malicious_noted", 0) > 0
            or vt_summ.get("filepath_too_many_hits", 0) > 0):
        lines += [
            "---", "## ⚠ VT ファイルパス照合に関する注意事項", "",
            "本レポートの一部エントリ（📎 マーク付き）は、**VirusTotal Intelligence Search"
            " によるファイル名一致検索**の結果です。",
            "",
            "この照合方式には以下の制限があります：",
            "",
            "- **実際にホスト上に存在するファイルのハッシュは検証していません。**",
            "- VT 上に同名の悪性ファイルが存在するだけで `malicious` と判定される場合があります。",
            "- 正規ファイル（例：公式インストーラ）であっても、同名のマルウェアが VT に登録されていれば"
            "  高い検知率が表示されます。",
            "",
            "**📎 マーク付きのエントリはスコアに反映されていません（参考値のみ）。**",
            "確認が必要な場合は、VT リンク先で実際のファイルの SHA256 を公式ソースと照合してください。",
            "",
        ]
        if vt_summ.get("filepath_too_many_hits", 0) > 0:
            lines += [
                f"> 🟡 ファイル名候補が多すぎて代表値を確定できなかったエントリ: "
                f"{vt_summ['filepath_too_many_hits']} 件",
                "> これはVT未登録ではなく、**候補過多による照合不能**です。",
                "",
            ]
        if vt_summ.get("filepath_malicious_noted", 0) > 0:
            lines += [
                f"> 📎 同名悪性ファイルが VT で検出されたエントリ: "
                f"{vt_summ['filepath_malicious_noted']} 件",
                "",
            ]

    # ── フッタ ───────────────────────────────────────────────
    lines += [
        "---",
        "*本レポートは LLM（Qwen2.5-Coder 32B）による自動解析結果です。*",
        "*最終判断は必ず人間のアナリストが行ってください。*",
        "",
    ]

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="解析結果から Markdown レポートを生成する")
    ap.add_argument("analyzed",    help="analyze_section.py の出力 JSON")
    ap.add_argument("correlation", help="correlate.py の出力 JSON")
    ap.add_argument("--output", "-o", help="出力 Markdown ファイルパス（省略時は自動命名）")
    ap.add_argument("--full", action="store_true",
                    help="全件版（LOW エントリを全行展開）を出力する")
    args = ap.parse_args()

    for path in (args.analyzed, args.correlation):
        if not os.path.exists(path):
            print(f"[ERROR] ファイルが見つかりません: {path}", file=sys.stderr)
            sys.exit(1)

    with open(args.analyzed,    encoding="utf-8") as f:
        analyzed = json.load(f)
    with open(args.correlation, encoding="utf-8") as f:
        correlation = json.load(f)

    meta      = analyzed.get("meta", {})
    hostname  = meta.get("hostname", "UNKNOWN")
    datestamp = meta.get("datestamp", "")
    base_dir  = os.path.dirname(args.analyzed)

    if args.output:
        out_path = args.output
        report   = generate_report(analyzed, correlation, full=args.full)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[report_gen] レポート生成完了: {out_path}")
    else:
        # 標準版
        std_path = os.path.join(base_dir, f"report_{hostname}_{datestamp}.md")
        std_md   = generate_report(analyzed, correlation, full=False)
        with open(std_path, "w", encoding="utf-8") as f:
            f.write(std_md)
        print(f"[report_gen] 標準版: {std_path}")

        # 全件版
        all_path = os.path.join(base_dir, f"report_{hostname}_{datestamp}_all.md")
        all_md   = generate_report(analyzed, correlation, full=True)
        with open(all_path, "w", encoding="utf-8") as f:
            f.write(all_md)
        print(f"[report_gen] 全件版: {all_path}")


if __name__ == "__main__":
    main()
