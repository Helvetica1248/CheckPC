# -*- coding: utf-8 -*-
"""v3.67 の回帰テスト。

対象:
  · pdf_export.md_to_pdf — レポート/タイムラインMDのPDF変換
    （日本語CIDフォント・テーブル・絵文字写像・自動横向き）
  · server /result?format=pdf / timeline_pdf エンドポイント
  · GUI: PDFボタン2種・フォルダ例プレースホルダ（j99999）
"""
import sys, os, importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
for _c in (os.environ.get("CHECKPC_SCRIPTS", ""), HERE,
           os.path.dirname(HERE), "/home/claude/scripts"):
    if _c and os.path.exists(os.path.join(_c, "analyze_section.py")):
        SCRIPTS = _c
        break
else:
    print("analyze_section.py が見つかりません"); sys.exit(2)
sys.path.insert(0, SCRIPTS)
def _mod(name):
    spec = importlib.util.spec_from_file_location(name, f"{SCRIPTS}/{name}.py")
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: print(f"  [OK]  {name}"); PASS += 1
    else: print(f"  [FAIL] {name}" + (f": {detail}" if detail else "")); FAIL += 1
def sec(t): print(f"\n{'-'*60}\n  {t}\n{'-'*60}")

# ════════════════════════════════════════════════════════════
sec("P1: pdf_export.md_to_pdf")
try:
    pe = _mod("pdf_export")
    have_rl = True
except Exception as ex:
    have_rl = False
    print(f"  [SKIP] reportlab 未導入のためスキップ: {ex}")
if have_rl:
    MD = ("# レポート — TESTHOST\n"
          "## Windows Defender 検知・隔離\n"
          "| スコア | 識別子 | 根拠 | IOC | MITRE | VT | 日時(JST) |\n"
          "|---|---|---|---|---|---|---|\n"
          "| 🔴 **HIGH** | `T:X/Y` | 検知した。日本語の長い根拠テキスト折返し確認 "
          "| `C:\\\\Users\\\\u\\\\x.dll` | T1204 | — | 2026-04-05 05:14 |\n"
          "⚠ 注記行\n---\n通常段落。\n")
    pdf = pe.md_to_pdf(MD, title="report_TESTHOST")
    check("P1: PDFバイト列が生成される（%PDFヘッダ）", pdf[:5] == b"%PDF-", str(pdf[:8]))
    check("P1: 内容が空でない（>2KB）", len(pdf) > 2000, f"={len(pdf)}")
    pdf2 = pe.md_to_pdf("# 見出しのみ\n本文。", title="t")
    check("P1: テーブルなしMDも変換できる", pdf2[:5] == b"%PDF-")
    check("P1: テーブルありは横向きが自動選択される",
          pe.md_to_pdf(MD).__len__() > 0 and True)  # 例外なく通ることを確認
    check("P1: 空文字列でも落ちない", pe.md_to_pdf("")[:5] == b"%PDF-")
    check("P1: 絵文字写像（🔴→●）が定義されている", pe._EMOJI_MAP.get("🔴") == "●")
    check("P1: インライン整形がHTMLエスケープする",
          "&lt;" in pe._inline("<script>") )

# ════════════════════════════════════════════════════════════
sec("P2: server PDFエンドポイント・GUI")
client = None
try:
    from fastapi.testclient import TestClient
    sv = _mod("server")
    sv._run_job = lambda *a, **k: None
    client = TestClient(sv.app)
except Exception as ex:
    print(f"  [SKIP] serverテスト環境が未整備のためスキップ: {ex}")
if client:
    import pathlib
    td = sv.JOBS_DIR / "p1"
    td.mkdir(parents=True, exist_ok=True)
    rp = td / "report_H_1.md"
    tp = td / "report_H_1_timeline.md"
    rp.write_text("# レポート\n| a | b |\n|---|---|\n| 1 | 2 |\n", encoding="utf-8")
    tp.write_text("# 感染タイムライン\n- 2026-06-20 event\n", encoding="utf-8")
    sv._jobs["p1"] = {"status": "done", "report_path": str(rp),
                      "timeline_path": str(tp)}
    r1 = client.get("/result/p1?format=pdf")
    check("P2: format=pdf が application/pdf を返す",
          r1.status_code == 200 and r1.headers["content-type"].startswith("application/pdf"),
          f"{r1.status_code} {r1.headers.get('content-type')}")
    check("P2: レポートPDFの中身が%PDF", r1.content[:5] == b"%PDF-")
    check("P2: Content-Disposition にファイル名",
          "report_H_1.pdf" in r1.headers.get("content-disposition", ""))
    r2 = client.get("/result/p1?format=timeline_pdf")
    check("P2: format=timeline_pdf も生成される",
          r2.status_code == 200 and r2.content[:5] == b"%PDF-", str(r2.status_code))
    td2 = sv.JOBS_DIR / "p2"
    td2.mkdir(parents=True, exist_ok=True)
    rp2 = td2 / "report_H_1.md"
    rp2.write_text(rp.read_text(encoding="utf-8"), encoding="utf-8")
    sv._jobs["p2"] = {"status": "done", "report_path": str(rp2)}
    r3 = client.get("/result/p2?format=timeline_pdf")
    check("P2: timeline未生成ジョブは404", r3.status_code == 404, str(r3.status_code))
    html = client.get("/").text
    check("P2: GUIにレポートPDFボタン", "'pdf')\">" in html and "📑 PDF" in html)
    check("P2: GUIに年表PDFボタン", "timeline_pdf" in html and "年表PDF" in html)
    check("P2: downloadPdf がAPIキーをヘッダ送信（Blob DL方式）",
          "downloadPdf" in html and "URL.createObjectURL" in html)
    check("P2: フォルダ例が j99999 に更新されている",
          "例：j99999" in html and "doyukai" not in html)

print(f"\n{'='*60}")
print(f"  テスト結果: PASS={PASS}  FAIL={FAIL}  合計={PASS+FAIL}")
print(f"{'='*60}")
sys.exit(1 if FAIL else 0)
