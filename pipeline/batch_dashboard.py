#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
batch_dashboard.py

複数ホストの解析結果をまとめて閲覧するための横断サマリダッシュボードを
Markdownで生成する。

背景: 多数のホスト（10台以上等）を一括レビューする際、個別のレポート
Markdownを1件ずつ開いて「感染嫌疑・マルウェアファミリ・HIGH/MEDIUM件数」を
手作業で一覧化する必要があり、可視性が低かった（実運用で発覚）。

また、複数ホストに共通して出現するIOC（同じIP・パス等）を横断的に
検出することで、「個別感染」と「基盤構成・共通ツール由来」の切り分けの
材料を提供する。

Usage:
    python batch_dashboard.py <host_dir1> <host_dir2> ... -o dashboard.md
    python batch_dashboard.py --glob "/opt/llm/jobs/*/output/*" -o dashboard.md
"""
import argparse
import glob as globmod
import json
import sys
from collections import defaultdict
from pathlib import Path

from known_infra import identify_known_service

_SUSPICION_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "NONE": 3, "N/A": 4}
_SUSPICION_BADGE = {
    "HIGH": "🔴 HIGH", "MEDIUM": "🟡 MEDIUM", "LOW": "🟢 LOW",
    "NONE": "⚪ NONE", "N/A": "❔ N/A",
}


def _load_json_first(host_dir: Path, patterns: list) -> dict:
    """複数のglobパターンを順に試し、最初に見つかったJSONファイルを読み込む。
    VT後版を優先し、無ければVT前版にフォールバックする。"""
    for pat in patterns:
        cands = sorted(host_dir.rglob(pat))
        if cands:
            try:
                return json.loads(cands[0].read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
    return {}


def collect_host_summary(host_dir: Path) -> dict:
    """1ホスト分のサマリ情報を集める。"""
    corr = _load_json_first(host_dir, ["correlation_*_vt.json", "correlation_*.json"])
    analyzed = _load_json_first(host_dir, ["analyzed_*_vt.json", "analyzed_*.json"])

    hostname = ((analyzed.get("meta") or {}).get("hostname")
                or (corr.get("meta") or {}).get("hostname")
                or host_dir.name)

    high = med = 0
    for sec in (analyzed.get("sections") or {}).values():
        if not isinstance(sec, dict):
            continue
        for e in sec.get("entries", []):
            if not isinstance(e, dict):
                continue
            if e.get("score") == "HIGH":
                high += 1
            elif e.get("score") == "MEDIUM":
                med += 1

    return {
        "hostname": hostname,
        "dir": str(host_dir),
        "infection_suspicion": corr.get("infection_suspicion") or "N/A",
        "malware_family": corr.get("malware_family") or "Unknown",
        "summary": (corr.get("infection_summary") or "").replace("\n", " "),
        "high_count": high,
        "medium_count": med,
        "analyzed": analyzed,
    }


def find_cross_host_iocs(host_summaries: list, min_hosts: int = 2) -> list:
    """複数ホストにまたがって出現するIOC（HIGH/MEDIUMエントリのiocs）を検出する。

    戻り値: [{"value", "hosts": [...], "sections": [...], "known_service": str}, ...]
    件数の多いIOC（＝より多くのホストに共通する）を優先して返す。
    """
    occurrence = defaultdict(lambda: defaultdict(set))  # value -> hostname -> {sections}
    for hs in host_summaries:
        analyzed = hs.get("analyzed") or {}
        for sec_name, sec in (analyzed.get("sections") or {}).items():
            if not isinstance(sec, dict):
                continue
            for e in sec.get("entries", []):
                if not isinstance(e, dict) or e.get("score") not in ("HIGH", "MEDIUM"):
                    continue
                for val in (e.get("iocs") or []):
                    if val:
                        occurrence[val][hs["hostname"]].add(sec_name)

    result = []
    for val, host_map in occurrence.items():
        if len(host_map) >= min_hosts:
            result.append({
                "value": val,
                "hosts": sorted(host_map.keys()),
                "sections": sorted({s for secs in host_map.values() for s in secs}),
                "known_service": identify_known_service(val),
            })
    result.sort(key=lambda x: -len(x["hosts"]))
    return result


def generate_dashboard_md(host_summaries: list, cross_host_iocs: list) -> str:
    n_high = sum(1 for h in host_summaries if h["infection_suspicion"] == "HIGH")
    n_med  = sum(1 for h in host_summaries if h["infection_suspicion"] == "MEDIUM")
    n_low  = sum(1 for h in host_summaries if h["infection_suspicion"] in ("LOW", "NONE"))

    lines = [
        "# バッチ横断サマリダッシュボード", "",
        f"対象ホスト数: {len(host_summaries)}"
        f"（HIGH: {n_high} / MEDIUM: {n_med} / LOW以下: {n_low}）",
        "",
        "---", "", "## ホスト別サマリ", "",
        "| ホスト名 | 感染嫌疑 | マルウェアファミリ | HIGH件数 | MEDIUM件数 | サマリ |",
        "|----------|----------|---------------------|----------|------------|--------|",
    ]
    for h in sorted(host_summaries,
                     key=lambda h: (_SUSPICION_ORDER.get(h["infection_suspicion"], 5),
                                     -h["high_count"])):
        badge = _SUSPICION_BADGE.get(h["infection_suspicion"], h["infection_suspicion"])
        lines.append(
            f"| {h['hostname']} | {badge} | {h['malware_family']} | {h['high_count']} | "
            f"{h['medium_count']} | {h['summary'][:60]} |"
        )
    lines.append("")

    lines += ["---", "", "## 複数ホストで共通するIOC（HIGH/MEDIUM対象）", ""]
    if cross_host_iocs:
        lines += [
            "同一の指標が複数ホストに共通して現れる場合、個別感染よりも"
            "基盤構成・共通ツール（監視エージェント、クラウド基盤IP等）由来の"
            "可能性を検討する材料になります。「既知サービス」列に注記がある"
            "場合は既知のクラウド/インフラサービスIPです（安全性の断定ではありません）。",
            "",
            "| IOC | 該当ホスト数 | 該当ホスト | 検出セクション | 既知サービス |",
            "|-----|-------------|-----------|----------------|--------------|",
        ]
        for c in cross_host_iocs[:100]:
            hosts_str = ", ".join(c["hosts"][:5]) + (" 他" if len(c["hosts"]) > 5 else "")
            svc = c["known_service"] or "—"
            val = c["value"]
            val_disp = val if len(val) <= 90 else val[:90] + "…"
            lines.append(
                f"| `{val_disp}` | {len(c['hosts'])} | {hosts_str} | "
                f"{', '.join(c['sections'])} | {svc} |"
            )
        lines.append("")
    else:
        lines.append("該当なし（2ホスト以上で一致するHIGH/MEDIUM IOCは見つかりませんでした）")
        lines.append("")

    return "\n".join(lines)


def build_dashboard(host_dirs: list, min_hosts: int = 2) -> str:
    """host_dirs（各ホストのrun_dirパスのリスト）からダッシュボードMarkdownを生成する。"""
    host_summaries = [collect_host_summary(Path(d)) for d in host_dirs]
    cross_host_iocs = find_cross_host_iocs(host_summaries, min_hosts=min_hosts)
    return generate_dashboard_md(host_summaries, cross_host_iocs)


def main():
    ap = argparse.ArgumentParser(
        description="複数ホストの解析結果から横断サマリダッシュボードを生成する")
    ap.add_argument("host_dirs", nargs="*",
                     help="各ホストの出力ディレクトリ（run_dir、複数指定可）")
    ap.add_argument("--glob", dest="glob_pattern", default=None,
                     help="ホストディレクトリをglobパターンで指定する場合"
                          "（例: '/opt/llm/jobs/*/output/*'）")
    ap.add_argument("-o", "--output", default="batch_dashboard.md",
                     help="出力先Markdownファイル（既定: batch_dashboard.md）")
    ap.add_argument("--min-hosts", type=int, default=2,
                     help="横断IOCとみなす最小ホスト数（既定: 2）")
    args = ap.parse_args()

    dirs = list(args.host_dirs)
    if args.glob_pattern:
        dirs += [d for d in globmod.glob(args.glob_pattern) if Path(d).is_dir()]
    if not dirs:
        print("エラー: ホストディレクトリが指定されていません", file=sys.stderr)
        sys.exit(1)

    md = build_dashboard(dirs, min_hosts=args.min_hosts)
    Path(args.output).write_text(md, encoding="utf-8")
    print(f"ダッシュボードを出力しました: {args.output}（{len(dirs)}ホスト対象）")


if __name__ == "__main__":
    main()
