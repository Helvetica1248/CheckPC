#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 rev6: simple static regression for deferred details rendering."""
from __future__ import annotations

import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
SERVER = HERE / "server.py"
PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}" + (f": {detail}" if detail else ""))


text = SERVER.read_text(encoding="utf-8")
start = text.index("function markdownToHtml")
end = text.index("// ── モーダルのリサイズ", start)
renderer = text[start:end]

check(
    "sec-deferred exact opening pattern exists",
    'trimmed.match(/^<details class="sec-deferred" open><summary>(.*)<\\/summary>$/)' in renderer,
)
check(
    "sec-empty existing pattern remains",
    'trimmed.match(/^<details class="sec-empty"><summary>(.*)<\\/summary>$/)' in renderer,
)
check(
    "summary is escaped before output",
    '${escapeHtml(summaryText)}' in renderer,
)
check(
    "deferred details keeps open attribute",
    'const openAttr = deferredDetailsM ? " open" : "";' in renderer,
)
check(
    "closing details requires recognized opener",
    'if (safeDetailsDepth > 0)' in renderer
    and 'safeDetailsDepth -= 1;' in renderer,
)
check(
    "unmatched closing tag is treated as text",
    re.search(
        r'if \(trimmed === "</details>"\).*?else \{\s*para\.push\(line\);',
        renderer,
        re.S,
    ) is not None,
)
check(
    "deferred warning CSS exists",
    ".md-content details.sec-deferred" in text
    and ".md-content details.sec-deferred summary" in text,
)
check(
    "arbitrary event handler is not allowlisted",
    "onclick" not in renderer
    and "onerror" not in renderer,
)

print(f"PASS={PASS} FAIL={FAIL}")
raise SystemExit(0 if FAIL == 0 else 1)
