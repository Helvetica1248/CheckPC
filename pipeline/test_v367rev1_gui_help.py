#!/usr/bin/env python3
"""v3.67rev1: 一般ユーザー向けGUIヘルプ・システム概念図の回帰テスト。"""
import asyncio
import os
import tempfile
import types
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET

# openai パッケージが無いテスト環境でも server.py の静的ヘルプ部分を
# 検証できるよう、import時に必要な最小スタブだけを用意する。
if "openai" not in __import__("sys").modules:
    openai_stub = types.ModuleType("openai")
    class _OpenAIStub:
        def __init__(self, *args, **kwargs):
            pass
    openai_stub.OpenAI = _OpenAIStub
    __import__("sys").modules["openai"] = openai_stub

# server.py import時のジョブ保存先をテスト用一時領域へ分離する。
_TEST_JOBS = tempfile.TemporaryDirectory()
os.environ["PIPELINE_JOBS_DIR"] = _TEST_JOBS.name

import server  # noqa: E402


class TestGuiHelpV367Rev1(unittest.TestCase):
    def test_guide_file_exists_and_has_required_sections(self):
        text = server.GUIDE_PATH.read_text(encoding="utf-8")
        self.assertIn("GUI 操作ガイド", text)
        self.assertIn("解析開始", text)
        self.assertIn("ジョブ状態", text)
        self.assertIn("Depth 2", text)
        self.assertIn("VirusTotal", text)

    def test_system_concept_svg_is_valid(self):
        self.assertTrue(server.DIAGRAM_PATH.exists(), "system_concept.svg が欠落")
        root = ET.parse(server.DIAGRAM_PATH).getroot()
        self.assertTrue(root.tag.endswith("svg"))
        text = server.DIAGRAM_PATH.read_text(encoding="utf-8")
        self.assertIn("ローカル解析サーバー", text)
        self.assertIn("VirusTotal（任意）", text)
        self.assertIn("ローカル保存領域", text)
        self.assertIn("archive worker", text)
        self.assertIn("検証用ZIP", text)
        self.assertIn("全成果物ZIP", text)
        self.assertIn("Chat Lv.2", text)

    def test_help_guide_endpoint(self):
        response = asyncio.run(server.help_guide())
        self.assertEqual(response.media_type, "text/markdown; charset=utf-8")
        body = response.body.decode("utf-8")
        self.assertIn("CheckPC 解析パイプライン GUI 操作ガイド", body)

    def test_help_diagram_endpoint(self):
        self.assertTrue(server.DIAGRAM_PATH.exists(), "system_concept.svg が欠落")
        response = asyncio.run(server.help_system_concept())
        self.assertEqual(response.media_type, "image/svg+xml")
        self.assertEqual(Path(response.path), server.DIAGRAM_PATH)

    def test_gui_contains_help_controls(self):
        html = server._HTML
        self.assertIn("❓ 使い方・仕組み", html)
        self.assertIn("操作ガイド", html)
        self.assertIn("システム概念図", html)
        self.assertIn('fetch("/help/guide")', html)
        self.assertIn('/help/system-concept.svg', html)
        self.assertIn('id="depthWarning"', html)
        self.assertNotIn("深度2は一部データが未評価になる既知問題", html)
        self.assertIn("Depth 2は再調査・詳細確認向け", html)
        self.assertIn('<details class="job-more"', html)
        self.assertIn("archiveSummaryText", html)

    def test_default_depth_remains_one(self):
        # v3.68: depth 3/4 は GUI から退避（max=4→2）。既定は 1 のまま。
        self.assertIn('id="depthSlider" min="1" max="2" value="1"', server._HTML)
        # v3.68: DEPTH_DESC の文言を Filtered Triage へ更新
        self.assertIn('Filtered Triage', server._HTML)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestGuiHelpV367Rev1)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    failures = len(result.failures) + len(result.errors)
    passed = result.testsRun - failures
    print(f"PASS={passed} FAIL={failures}")
    raise SystemExit(0 if failures == 0 else 1)
