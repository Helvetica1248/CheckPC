# -*- coding: utf-8 -*-
"""
defender_dir_report.py

Defender検知ログ集約 ＋ 不審フォルダDirectory抽出（16-D / v3.57）

分析官からの要望（DESIGN.md 16-D）を実装したもの。決定論ベース（LLM非依存）で
timeline.py と同じ設計方針を踏襲する。

出力内容:
  ■Defender検知ログ
    ・ファイル   : defender_quarantine（Defender Eventlog 1116由来）の
                   検知ファイルパスを重複排除して列挙
    ・コマンド   : 同じく検知時の Process Name（実行プロセス）を重複排除して列挙
                   （分析官確認: Defender 1116 ログには「添付」的に検知ファイルへ
                   紐づく実行プロセス名が記録されており、これを「コマンド」相当
                   として抽出する）
  ■不審フォルダ
    ・検知ファイルパスの親フォルダを、directory セクション（parse_checkpc.py
      出力）から引き当て、dirコマンド相当のファイル一覧（タイムスタンプ・
      サイズ・ファイル名）を出力する。
    ※ 分析官コメント欄は今回のバージョンでは出力しない（要望により削除）。

制限事項:
  - AMSIスキャン由来の検知（Path が "\\Device\\HarddiskVolumeN\\..." 形式）は
    ドライブレターを持たないため、directory セクションのエントリと照合できない
    場合がある。その場合は「一致するdirectory情報なし」と明示する。
  - directory が CHECKPC_DIR_MAX_LLM の上限超過分（raw_directory.md へ退避された
    分）を含め全件を対象にする（LLM送付対象に絞られる前の parse_checkpc.py
    生パース結果を参照するため、上限の影響を受けない）。
"""

import re
from timeline import _pad, _dwidth  # ベタ打ち整形の共通ヘルパーを流用

# Defenderのpathフィールドに付与される内部プレフィックス
# （analyze_section.py の _QUARANTINE_PATH_PREFIX_RE と同種だが、
#  本モジュールは複数パス（";"区切り）の分割も併せて行うため独自に持つ）
_PATH_PREFIX_RE = re.compile(r"^(?:container)?file:_?|^amsi:_?", re.I)
# 実データ（HOST-REF-11 Event[35]: Trojan:Win32/ComHijackTypeLibScript.A）で確認:
# Path フィールドが "CmdLine:_<実際のコマンドライン>" 形式になる検知がある
# （COM hijack等、ファイルではなくコマンドライン自体を検知した場合）。
# これはファイルパスではなく「コマンド」情報のため区別して抽出する。
_CMDLINE_PREFIX_RE = re.compile(r"^CmdLine:_?", re.I)
# containerfile 形式で末尾に付く埋め込みリソース参照
# 例: "...\\wangmeng.dll->[MSILRES:yfwtkbhj.xxxx]"
_EMBEDDED_RESOURCE_SUFFIX_RE = re.compile(r"->\[[^\]]*\]\s*$")


def _split_defender_path_field(raw_path: str) -> tuple:
    """
    Defenderのpathフィールド（";"区切りで複数値・containerfile/file/amsi/
    CmdLineのプレフィックス付き・埋め込みリソースの->[...]サフィックス付き）を
    (file_paths: list, command_lines: list) に分解する。

    "CmdLine:_..." 形式は実際のファイルパスではなく検知時のコマンドライン
    そのものであるため、ファイルパスとは別に返す（実データで確認済み）。
    重複はこの関数内では除去しない（呼び出し側で全体を通して重複排除する）。
    """
    if not raw_path:
        return [], []
    parts = [p.strip() for p in raw_path.split(";") if p.strip()]
    files, cmds = [], []
    for p in parts:
        if _CMDLINE_PREFIX_RE.match(p):
            cmd = _CMDLINE_PREFIX_RE.sub("", p).strip()
            if cmd:
                cmds.append(cmd)
            continue
        p2 = _PATH_PREFIX_RE.sub("", p)
        p2 = _EMBEDDED_RESOURCE_SUFFIX_RE.sub("", p2).strip()
        if p2:
            files.append(p2)
    return files, cmds


def _fmt_detect_range(dts: list) -> str:
    """検知日時リストを表示用文字列にする（v3.60）。
    1件: 「検知: YYYY-MM-DD HH:MM」
    複数: 「検知: 初回 〜 最終（n件）」（初回＋最終の範囲表示）
    時刻は timeline.py の TZ-1（_parse_ts）で JST へ正規化する。
    日時なしは空文字（行を追加しない）。"""
    dts = sorted(d for d in dts if d)
    if not dts:
        return ""

    def _fmt(raw):
        try:
            import timeline as _tl
            d = _tl._parse_ts(raw)
            if d:
                return d.strftime("%Y-%m-%d %H:%M")
        except Exception:
            pass
        return (raw or "")[:16]

    if len(dts) == 1:
        return f"検知: {_fmt(dts[0])} (JST)"
    return f"検知: {_fmt(dts[0])} 〜 {_fmt(dts[-1])} (JST・{len(dts)}件)"


def _win_dirname(path: str) -> str:
    """Windowsパスの親フォルダを返す（os.path.dirnameはPOSIX区切りも
    解釈してしまうため、バックスラッシュのみを区切りとして扱う）。"""
    idx = path.rfind("\\")
    if idx < 0:
        return ""
    return path[:idx]


def _has_drive_letter(path: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:\\", path))


def _build_folder_index(directory_entries: list) -> dict:
    """directory セクション（parse_directory()出力）から
    フォルダパス(小文字)→エントリlist の索引を構築する。"""
    index = {}
    if not isinstance(directory_entries, list):
        return index
    for e in directory_entries:
        if not isinstance(e, dict):
            continue
        d = e.get("dir", "")
        if not d:
            continue
        index.setdefault(d.lower(), []).append(e)
    return index


def build_defender_dir_report(parsed_json: dict) -> str:
    """
    parsed_json: parse_checkpc.parse() の出力（dict）。
    sections.defender_quarantine と sections.directory を使用する。

    戻り値: run_analysis.py が report_{host}_{ts}_defender_dirs.md として
    そのまま書き出せる Markdown 文字列。
    """
    meta = parsed_json.get("meta", {})
    hostname = meta.get("hostname", "UNKNOWN")
    sections = parsed_json.get("sections", {})
    dq_entries = sections.get("defender_quarantine", [])
    dir_entries = sections.get("directory", [])

    if not isinstance(dq_entries, list):
        dq_entries = []

    # ── ① ユニークな検知ファイルパス・コマンドの収集 ────────────
    # source == "defender_eventlog"（Defender Eventlog 1116由来）のみを対象と
    # する。directory_scan由来（他ベンダAVの検疫フォルダ内ファイル）は
    # 「検知ファイルパス」に相当する情報を持たないため対象外。
    #
    # 「・コマンド」は以下2種を統合する（実データで両方の実例を確認済み）:
    #   (a) Path フィールドが "CmdLine:_..." 形式の場合の実コマンドライン
    #       （例: Trojan:Win32/ComHijackTypeLibScript.A の reg.exe コマンド）
    #   (b) Process Name フィールド（検知時の実行プロセスパス）
    file_paths = []
    seen_files = set()
    commands = []
    seen_commands = set()
    # v3.60: パス/コマンドごとの検知日時（1116イベントの Date:）を収集する。
    # 同一パスが複数イベントで検知された場合も日時を全件保持し、表示時に
    # 初回〜最終の範囲で出す。
    file_dts = {}
    cmd_dts = {}

    for e in dq_entries:
        if not isinstance(e, dict) or e.get("source") != "defender_eventlog":
            continue
        dt = (e.get("datetime") or "").strip()
        files, cmds = _split_defender_path_field(e.get("path", ""))
        for p in files:
            if p not in seen_files:
                seen_files.add(p)
                file_paths.append(p)
            if dt:
                file_dts.setdefault(p, []).append(dt)
        for c in cmds:
            if c not in seen_commands:
                seen_commands.add(c)
                commands.append(c)
            if dt:
                cmd_dts.setdefault(c, []).append(dt)
        proc = (e.get("process_name") or "").strip()
        if proc and proc.lower() != "unknown":
            if proc not in seen_commands:
                seen_commands.add(proc)
                commands.append(proc)
            if dt:
                cmd_dts.setdefault(proc, []).append(dt)

    # ── ② フォルダ索引の構築 ──────────────────────────────────
    folder_index = _build_folder_index(dir_entries)

    # ── ③ 検知ファイルパス→親フォルダの収集（重複排除・順序維持） ──
    folders = []
    seen_folders = set()
    for p in file_paths:
        folder = _win_dirname(p)
        if folder and folder.lower() not in seen_folders:
            seen_folders.add(folder.lower())
            folders.append(folder)

    # ── ④ Markdown組み立て（ベタ打ち・罫線なし） ────────────────
    lines = []
    lines.append("## Defender検知ログ集約 ＋ 不審フォルダDirectory抽出")
    lines.append("")
    lines.append(f"対象ホスト: {hostname}")
    lines.append("")
    lines.append("```")
    lines.append("■Defender検知ログ")
    lines.append("〓" * 20)
    lines.append("・ファイル")
    if file_paths:
        for p in file_paths:
            lines.append(p)
            _dtl = _fmt_detect_range(file_dts.get(p, []))
            if _dtl:
                lines.append(f"  └ {_dtl}")
    else:
        lines.append("（該当なし）")
    lines.append("・コマンド")
    if commands:
        for c in commands:
            lines.append(c)
            _dtl = _fmt_detect_range(cmd_dts.get(c, []))
            if _dtl:
                lines.append(f"  └ {_dtl}")
    else:
        lines.append("（該当なし）")
    lines.append("〓" * 20)
    lines.append("")
    lines.append("■不審フォルダ")
    lines.append("〓" * 20)
    if not folders:
        lines.append("（検知ファイルパスなし、または全てドライブレターを"
                      "持たない形式のため対象フォルダなし）")
    for folder in folders:
        lines.append(f"・{hostname}")
        lines.append(f"  {folder}")
        if not _has_drive_letter(folder):
            lines.append("  ※ ドライブレターを持たないパス形式"
                          "（AMSIスキャン等の内部表現）のため、"
                          "directory セクションとの突合ができません。")
            continue
        entries = folder_index.get(folder.lower(), [])
        if not entries:
            lines.append("  （directory セクションに一致するファイル一覧が"
                          "ありません。対象ホストの解析データを確認してください）")
            continue
        for fe in sorted(entries, key=lambda x: x.get("date", "")):
            date = _pad(fe.get("date", ""), 17)
            size = fe.get("size", "").rjust(14)
            name = fe.get("name", "")
            lines.append(f"  {date} {size}  {name}")
    lines.append("〓" * 20)
    lines.append("```")
    lines.append("")
    return "\n".join(lines)
