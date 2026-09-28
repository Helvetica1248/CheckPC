# -*- coding: utf-8 -*-
"""pdf_export.py — Markdown レポート/タイムラインの PDF 変換（v3.67）

server.py の /result/{job_id}?format=pdf / timeline_pdf から利用される。
日本語フォントは reportlab 内蔵の CID フォント（HeiseiKakuGo-W5）を使うため、
TTF ファイルの配置やネットワークアクセスは不要（オフラインの base117 で動作）。

対応する Markdown 要素（レポート/タイムラインで実際に使われるもの）:
  · 見出し（# / ## / ###）
  · テーブル（| 区切り。ヘッダ行反復・CJK折返し・列幅ヒューリスティック）
  · 通常段落・リスト行・罫線（---）
  · 太字 **x** / インラインコード `x`（装飾は簡略化）
絵文字はCIDフォントにグリフが無いため記号へ写像する。
"""
import io
import re
import html

from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                Table, TableStyle, HRFlowable)

_FONT = "HeiseiKakuGo-W5"
_registered = False


def _ensure_font():
    global _registered
    if not _registered:
        pdfmetrics.registerFont(UnicodeCIDFont(_FONT))
        _registered = True


# 絵文字→記号写像（CIDフォント非収録グリフの置換）
_EMOJI_MAP = {
    "🔴": "●", "🟡": "▲", "🟢": "○", "⚪": "◇", "🔵": "◆",
    "⚠": "▲!", "⚠️": "▲!", "📄": "", "📑": "", "✅": "[OK]", "❌": "[NG]",
}
_EMOJI_STRIP = re.compile(r"[\U0001F000-\U0001FAFF\u2700-\u27BF\uFE0F]")


def _clean(text: str) -> str:
    for k, v in _EMOJI_MAP.items():
        text = text.replace(k, v)
    return _EMOJI_STRIP.sub("", text)


def _inline(text: str) -> str:
    """インライン装飾を Paragraph 用マークアップへ（エスケープ込み）。"""
    text = html.escape(_clean(text))
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = text.replace("`", "")
    return text


def _styles():
    base = dict(fontName=_FONT, wordWrap="CJK")
    return {
        "h1":   ParagraphStyle("h1", fontSize=14, leading=18, spaceAfter=6,
                               spaceBefore=6, **base),
        "h2":   ParagraphStyle("h2", fontSize=12, leading=16, spaceAfter=5,
                               spaceBefore=8, **base),
        "h3":   ParagraphStyle("h3", fontSize=10.5, leading=14, spaceAfter=4,
                               spaceBefore=6, **base),
        "body": ParagraphStyle("body", fontSize=8.5, leading=12, **base),
        "cell": ParagraphStyle("cell", fontSize=6.5, leading=8.5, **base),
        "mono": ParagraphStyle("mono", fontSize=7, leading=10, **base),
    }


def _col_widths(ncols: int, total: float):
    """列幅ヒューリスティック。レポート表（6〜7列: スコア/識別子/根拠/IOC/
    MITRE/VT/日時）は識別子・根拠・IOC を広く取る。それ以外は均等。"""
    if ncols == 7:
        w = [0.9, 2.3, 2.6, 2.1, 0.7, 0.5, 1.1]
    elif ncols == 6:
        w = [0.9, 2.4, 2.8, 2.3, 0.8, 0.6]
    else:
        w = [1.0] * ncols
    s = sum(w)
    return [total * x / s for x in w]


def _table_flow(rows: list, styles, avail_width: float):
    """Markdownテーブル行群を reportlab Table にする。"""
    data = []
    ncols = max(len(r) for r in rows)
    for r in rows:
        cells = [Paragraph(_inline(c), styles["cell"]) for c in r]
        cells += [Paragraph("", styles["cell"])] * (ncols - len(cells))
        data.append(cells)
    t = Table(data, colWidths=_col_widths(ncols, avail_width), repeatRows=1)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.92, 0.92, 0.95)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
    ]))
    return t


def _split_md_table_row(line: str) -> list:
    cells = line.strip().strip("|").split("|")
    return [c.strip() for c in cells]


_SEP_ROW = re.compile(r"^\s*\|?\s*:?-{2,}.*\|")


def md_to_pdf(md_text: str, title: str = "", landscape_mode: bool = None) -> bytes:
    """Markdown 文字列を PDF バイト列へ変換する。
    landscape_mode: None なら「テーブルを含むなら横向き」を自動選択。"""
    _ensure_font()
    styles = _styles()
    lines = (md_text or "").splitlines()
    has_table = any(l.lstrip().startswith("|") for l in lines)
    if landscape_mode is None:
        landscape_mode = has_table
    pagesize = landscape(A4) if landscape_mode else A4
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=pagesize,
                            leftMargin=12 * mm, rightMargin=12 * mm,
                            topMargin=12 * mm, bottomMargin=12 * mm,
                            title=_clean(title or "report"))
    avail = pagesize[0] - 24 * mm

    flow = []
    if title:
        flow.append(Paragraph(_inline(title), styles["h1"]))
        flow.append(Spacer(1, 2 * mm))

    tbl_rows = []
    def _flush_table():
        nonlocal tbl_rows
        if tbl_rows:
            flow.append(_table_flow(tbl_rows, styles, avail))
            flow.append(Spacer(1, 2 * mm))
            tbl_rows = []

    for raw in lines:
        line = raw.rstrip()
        st = line.lstrip()
        if st.startswith("|"):
            if _SEP_ROW.match(st):
                continue        # ヘッダ区切り行はスキップ
            tbl_rows.append(_split_md_table_row(st))
            continue
        _flush_table()
        if not st:
            flow.append(Spacer(1, 1.5 * mm))
            continue
        if st.startswith("### "):
            flow.append(Paragraph(_inline(st[4:]), styles["h3"]))
        elif st.startswith("## "):
            flow.append(Paragraph(_inline(st[3:]), styles["h2"]))
        elif st.startswith("# "):
            flow.append(Paragraph(_inline(st[2:]), styles["h1"]))
        elif st.startswith("---") and set(st) <= {"-"}:
            flow.append(HRFlowable(width="100%", thickness=0.5,
                                   color=colors.grey, spaceAfter=2))
        elif st.startswith("```"):
            continue            # コードフェンスは枠なしで中身をそのまま出す
        else:
            style = styles["mono"] if raw.startswith(("    ", "\t")) else styles["body"]
            flow.append(Paragraph(_inline(line), style))
    _flush_table()
    if not flow:
        flow = [Paragraph("(内容なし)", styles["body"])]
    doc.build(flow)
    return buf.getvalue()
