#!/usr/bin/env python3
"""v3.70 GUI polling-state and header-branding semantic regressions.

The checks intentionally inspect the relevant HTML/JavaScript structures rather
than searching the full source for marker strings.  Four built-in negative
mutations verify that behavior-preserving strings cannot mask broken semantics.
"""
from __future__ import annotations

import argparse
import html as html_lib
import json
import re
from pathlib import Path
from typing import Any, Callable


def _extract_html(server_text: str) -> str:
    match = re.search(r'_HTML\s*=\s*r"""(.*?)"""\n\nif __name__', server_text, re.S)
    return match.group(1) if match else ""


def _extract_balanced_function(source: str, name: str) -> str:
    """Return a JS function body while ignoring braces in strings/comments."""
    match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\([^)]*\)\s*\{{", source)
    if not match:
        return ""
    open_brace = source.find("{", match.start())
    depth = 0
    i = open_brace
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False

    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""

        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue
        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
            else:
                i += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            i += 1
            continue

        if ch == "/" and nxt == "/":
            line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue
        if ch in {"'", '"', "`"}:
            quote = ch
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[open_brace + 1 : i]
        i += 1
    return ""


def _visible_text(fragment: str) -> str:
    fragment = re.sub(r"<!--.*?-->", " ", fragment, flags=re.S)
    fragment = re.sub(r"<script\b.*?</script>", " ", fragment, flags=re.S | re.I)
    fragment = re.sub(r"<style\b.*?</style>", " ", fragment, flags=re.S | re.I)
    fragment = re.sub(r"<[^>]+>", " ", fragment)
    return " ".join(html_lib.unescape(fragment).split())


def audit_server_text(server_text: str) -> dict[str, Any]:
    html = _extract_html(server_text)
    header_match = re.search(r"<header\b[^>]*>(.*?)</header>", html, re.S | re.I)
    header = header_match.group(1) if header_match else ""
    header_visible = _visible_text(header)

    update_body = _extract_balanced_function(html, "updateFolderOptions")
    capture_body = _extract_balanced_function(html, "captureOpenJobMenus")
    restore_body = _extract_balanced_function(html, "restoreOpenJobMenus")
    replace_body = _extract_balanced_function(html, "replaceJobListHtml")
    render_body = _extract_balanced_function(html, "renderJobs")

    details_match = re.search(
        r'<details\s+class="job-more"(?P<attrs>[^>]*)>', html, re.S
    )
    details_attrs = details_match.group("attrs") if details_match else ""

    capture_selector_match = re.search(
        r'querySelectorAll\(\s*"([^"]+)"\s*\)', capture_body
    )
    restore_selector_match = re.search(
        r'querySelectorAll\(\s*"([^"]+)"\s*\)', restore_body
    )
    capture_selector = capture_selector_match.group(1) if capture_selector_match else ""
    restore_selector = restore_selector_match.group(1) if restore_selector_match else ""

    signature_pos = update_body.find("const signature = JSON.stringify(folders);")
    guard_match = re.search(
        r"if\s*\(\s*signature\s*===\s*_folderOptionsSignature\s*\)\s*return\s*;",
        update_body,
    )
    guard_pos = guard_match.start() if guard_match else -1
    pre_guard = update_body[:guard_pos] if guard_pos >= 0 else update_body
    signature_assignments_before_guard = re.findall(
        r"_folderOptionsSignature\s*=(?!=)", pre_guard
    )
    dl_lookup_pos = update_body.find('document.getElementById("folderOptions")')
    dl_rebuild_pos = update_body.find("dl.replaceChildren();")
    sel_lookup_pos = update_body.find('document.getElementById("folderFilter")')
    current_value_pos = update_body.find("const cur = sel.value;")
    sel_rebuild_pos = update_body.find("sel.replaceChildren();")
    restore_value_match = re.search(
        r"if\s*\(\s*Array\.from\(sel\.options\)\.some\([^)]*\)\s*\)\s*sel\.value\s*=\s*cur\s*;",
        update_body,
    )
    restore_value_pos = restore_value_match.start() if restore_value_match else -1
    signature_update_match = re.search(
        r"_folderOptionsSignature\s*=\s*signature\s*;", update_body
    )
    signature_update_pos = signature_update_match.start() if signature_update_match else -1

    details_has_job_id = re.search(
        r'\bdata-job-id\s*=\s*"\$\{escapeHtml\(String\(j\.job_id\)\)\}"',
        details_attrs,
    ) is not None
    selectors_match_attribute = (
        "details.job-more[open][data-job-id]" in capture_selector
        and "details.job-more[data-job-id]" in restore_selector
        and details_has_job_id
    )
    restore_opens_matching_ids = re.search(
        r"if\s*\(\s*openJobIds\.has\(\s*el\.dataset\.jobId\s*\)\s*\)"
        r"\s*(?:\{\s*)?el\.open\s*=\s*true\s*;",
        restore_body,
    ) is not None

    checks: list[tuple[str, bool, str]] = [
        ("HTML template found", bool(html), "embedded _HTML template missing"),
        ("header element found", bool(header_match), "header element missing"),
        (
            "header visible text removes J-CRAT",
            "J-CRAT" not in header_visible,
            f"visible={header_visible!r}",
        ),
        (
            "header visible text keeps Qwen model",
            "Qwen2.5-Coder 32B" in header_visible,
            f"visible={header_visible!r}",
        ),
        (
            "folder signature guard follows signature calculation",
            signature_pos >= 0 and guard_pos > signature_pos,
            f"signature={signature_pos} guard={guard_pos}",
        ),
        (
            "folder signature is not overwritten before guard",
            not signature_assignments_before_guard,
            f"assignments={len(signature_assignments_before_guard)}",
        ),
        (
            "folder DOM lookup and rebuild happen only after guard",
            guard_pos >= 0
            and min(dl_lookup_pos, dl_rebuild_pos, sel_lookup_pos, sel_rebuild_pos) > guard_pos,
            f"guard={guard_pos} dl_lookup={dl_lookup_pos} dl_rebuild={dl_rebuild_pos} "
            f"sel_lookup={sel_lookup_pos} sel_rebuild={sel_rebuild_pos}",
        ),
        (
            "folder selection is captured before select rebuild",
            guard_pos < current_value_pos < sel_rebuild_pos,
            f"guard={guard_pos} current={current_value_pos} rebuild={sel_rebuild_pos}",
        ),
        (
            "folder selection is restored after select rebuild",
            sel_rebuild_pos < restore_value_pos < signature_update_pos,
            f"rebuild={sel_rebuild_pos} restore={restore_value_pos} update={signature_update_pos}",
        ),
        (
            "folder signature updates after all option rebuilding",
            signature_update_pos > max(dl_rebuild_pos, sel_rebuild_pos, restore_value_pos),
            f"signature_update={signature_update_pos}",
        ),
        (
            "job-more details start tag carries stable data-job-id",
            details_has_job_id,
            f"attrs={details_attrs!r}",
        ),
        (
            "capture and restore selectors use the actual data-job-id attribute",
            selectors_match_attribute,
            f"capture={capture_selector!r} restore={restore_selector!r} attrs={details_attrs!r}",
        ),
        (
            "restore opens matching job IDs",
            restore_opens_matching_ids,
            "expected openJobIds.has(el.dataset.jobId) => el.open = true",
        ),
        (
            "renderJobs captures menu state before replacement",
            re.search(
                r"^\s*const\s+openJobIds\s*=\s*captureOpenJobMenus\(\)\s*;",
                render_body,
            ) is not None,
            "captureOpenJobMenus is not the first renderJobs statement",
        ),
        (
            "job list replacement restores open menus after innerHTML",
            0 <= replace_body.find("el.innerHTML = html;")
            < replace_body.find("restoreOpenJobMenus(openJobIds);"),
            "restore is missing or occurs before DOM replacement",
        ),
        (
            "all filtered/grouped paths use state-preserving replacement",
            html.count("replaceJobListHtml(") >= 5,
            f"count={html.count('replaceJobListHtml(')}",
        ),
        (
            "periodic job polling remains enabled",
            "setInterval(loadJobs, 10000);" in html,
            "10-second polling missing",
        ),
        (
            "archive polling refreshes through preserved renderer",
            "job.archives[kind] = state;\n        renderJobs(_lastJobs);" in html,
            "archive poll does not call renderJobs(_lastJobs)",
        ),
    ]

    return {
        "ok": all(condition for _, condition, _ in checks),
        "checks": [
            {"name": name, "ok": condition, "detail": detail}
            for name, condition, detail in checks
        ],
        "facts": {
            "header_visible_text": header_visible,
            "capture_selector": capture_selector,
            "restore_selector": restore_selector,
            "details_attributes": details_attrs.strip(),
        },
    }


def _mutations() -> dict[str, Callable[[str], str]]:
    def signature_guard(text: str) -> str:
        return text.replace(
            "  if (signature === _folderOptionsSignature) return;",
            "  _folderOptionsSignature = null;\n"
            "  if (signature === _folderOptionsSignature) return;",
            1,
        )

    def open_restore(text: str) -> str:
        return text.replace(
            "if (openJobIds.has(el.dataset.jobId)) el.open = true;",
            "if (openJobIds.has(el.dataset.jobId)) el.open = false;",
            1,
        )

    def data_job_id_masked(text: str) -> str:
        mutated = text.replace(
            '<details class="job-more" data-job-id="${escapeHtml(String(j.job_id))}" ${moreOpen}>',
            '<details class="job-more" data-job-key="${escapeHtml(String(j.job_id))}" ${moreOpen}>',
            1,
        )
        return mutated.replace(
            "let _folderOptionsSignature = null;",
            "let _folderOptionsSignature = null;\n"
            '// dead marker only: data-job-id="${escapeHtml(String(j.job_id))}"',
            1,
        )

    def visible_jcrat(text: str) -> str:
        return text.replace(
            '<div class="sub">Qwen2.5-Coder 32B</div>',
            '<div class="sub">Qwen2.5-Coder 32B</div>'
            '<span class="extra-brand">J-CRAT</span>',
            1,
        )

    return {
        "semantic_break_signature_guard": signature_guard,
        "semantic_break_open_restore": open_restore,
        "semantic_break_data_job_id_masked": data_job_id_masked,
        "semantic_add_visible_jcrat_separately": visible_jcrat,
    }


def run_suite(server_path: Path) -> dict[str, Any]:
    server_text = server_path.read_text(encoding="utf-8")
    baseline = audit_server_text(server_text)
    mutation_results = []
    for name, mutate in _mutations().items():
        mutated_text = mutate(server_text)
        changed = mutated_text != server_text
        audit = audit_server_text(mutated_text)
        mutation_results.append(
            {
                "name": name,
                "changed": changed,
                "rejected": changed and not audit["ok"],
                "failed_checks": [
                    row["name"] for row in audit["checks"] if not row["ok"]
                ],
            }
        )
    return {
        "server": str(server_path),
        "baseline": baseline,
        "mutations": mutation_results,
        "ok": baseline["ok"] and all(row["rejected"] for row in mutation_results),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="server.py")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = run_suite(Path(args.server))
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["ok"] else 1

    passed = failed = 0
    for row in result["baseline"]["checks"]:
        if row["ok"]:
            passed += 1
            print(f"[PASS] {row['name']}")
        else:
            failed += 1
            print(f"[FAIL] {row['name']}: {row['detail']}")

    for row in result["mutations"]:
        if row["rejected"]:
            passed += 1
            print(
                f"[PASS] negative mutation rejected: {row['name']} "
                f"({', '.join(row['failed_checks'])})"
            )
        else:
            failed += 1
            print(
                f"[FAIL] negative mutation escaped: {row['name']} "
                f"changed={row['changed']}"
            )

    print(f"PASS={passed} FAIL={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
