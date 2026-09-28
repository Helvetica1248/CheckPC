#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3.70 secret-free .env startup logging regressions."""
from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from budget_profile import active_profile
from vt_post import load_dotenv_simple
from version import (
    ANALYSIS_SCHEMA_VERSION,
    BUDGET_PROFILE_DEFAULT,
    PIPELINE_VERSION,
)

PASS = FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [OK]  {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}: {detail}")


def restore_environment(snapshot: dict[str, str]) -> None:
    os.environ.clear()
    os.environ.update(snapshot)


print("\n--- rc22 identity and unchanged budget ---")
check("pipeline version", PIPELINE_VERSION == "3.70", PIPELINE_VERSION)
check("schema version", ANALYSIS_SCHEMA_VERSION == "2.1", ANALYSIS_SCHEMA_VERSION)
check("profile version", BUDGET_PROFILE_DEFAULT == "v370", BUDGET_PROFILE_DEFAULT)
profile = active_profile().to_dict()
check("Depth2 token budget unchanged", profile.get("d2_output_token_budget") == 75000, profile)
check("Depth2 ratios unchanged", profile.get("ratios") == {
    "risk": 0.65, "fair": 0.25, "novelty": 0.10,
}, profile.get("ratios"))

print("\n--- .env values never appear in startup log ---")
original_env = dict(os.environ)
try:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        fixtures = {
            "VT_PROXY": "http://fixture-user:fixture-proxy-password@192.0.2.10:8486",
            "PIPELINE_AUTH_PBKDF2": "310000$fixture-salt$fixture-pbkdf2-digest",
            "VT_API_KEY": "fixture-api-key-value",
            "ACCESS_TOKEN": "fixture-access-token-value",
            "SESSION_COOKIE": "fixture-session-cookie-value",
            "AUTHORIZATION": "Bearer fixture-authorization-value",
            "BENIGN_SETTING": "fixture-benign-value",
            "QUOTED_VALUE": "fixture-quoted-value",
        }
        env_lines = [
            f"{key}={value}" if key != "QUOTED_VALUE" else f'{key}="{value}"'
            for key, value in fixtures.items()
        ]
        (root / ".env").write_text("\n".join(env_lines) + "\n", encoding="utf-8")

        for key in fixtures:
            os.environ.pop(key, None)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            loaded = load_dotenv_simple(str(root))
        output = buf.getvalue()

        check("all fixture keys loaded", set(loaded) == set(fixtures), loaded)
        check("quoted value decoded", loaded.get("QUOTED_VALUE") == fixtures["QUOTED_VALUE"], loaded)
        check("startup log uses loaded_keys", "loaded_keys=" in output, output)
        check("startup log lists sorted keys", str(sorted(fixtures)) in output, output)
        leaked = [value for value in fixtures.values() if value in output]
        check("no .env value appears in stdout/stderr", not leaked, leaked)
        check("proxy userinfo does not appear", "fixture-proxy-password" not in output, output)
        check("PBKDF2 material does not appear", "fixture-pbkdf2-digest" not in output, output)
        check("benign values are also not logged", "fixture-benign-value" not in output, output)

        # Existing process/shell settings retain priority and are not logged.
        os.environ["VT_PROXY"] = "http://preexisting-user:preexisting-secret@192.0.2.20:8080"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            loaded_again = load_dotenv_simple(str(root))
        output_again = buf.getvalue()
        check("pre-existing variable is not overwritten",
              os.environ["VT_PROXY"].endswith("preexisting-secret@192.0.2.20:8080"),
              os.environ["VT_PROXY"])
        check("pre-existing variable is absent from returned loaded map",
              "VT_PROXY" not in loaded_again, loaded_again)
        check("pre-existing secret is not logged",
              "preexisting-secret" not in output_again, output_again)
finally:
    restore_environment(original_env)

print("\n--- subprocess output is journal-safe ---")
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    secret = "subprocess-journal-secret-value"
    (root / ".env").write_text(
        "VT_PROXY=http://user:" + secret + "@192.0.2.30:8486\n"
        "PIPELINE_AUTH_PBKDF2=310000$subprocess$sensitive-digest\n",
        encoding="utf-8",
    )
    code = (
        "from vt_post import load_dotenv_simple; "
        f"load_dotenv_simple({str(root)!r})"
    )
    env = dict(os.environ)
    env.pop("VT_PROXY", None)
    env.pop("PIPELINE_AUTH_PBKDF2", None)
    cp = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(HERE), env=env,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=30,
    )
    check("subprocess loader exits successfully", cp.returncode == 0, cp.stdout)
    check("journal-like combined output contains no proxy secret", secret not in cp.stdout, cp.stdout)
    check("journal-like output contains no PBKDF2 digest", "sensitive-digest" not in cp.stdout, cp.stdout)
    check("journal-like output retains diagnostic key names",
          "VT_PROXY" in cp.stdout and "PIPELINE_AUTH_PBKDF2" in cp.stdout,
          cp.stdout)

print("\n--- source guard ---")
source = (HERE / "vt_post.py").read_text(encoding="utf-8")
check("legacy masked-value dictionary removed", "masked =" not in source, "masked = remains")
check("loader logs sorted key names", "loaded_keys = sorted(loaded)" in source, "missing key-only logging")
check("loader never formats loaded mapping directly",
      "→ {loaded}" not in source and "→ {masked}" not in source,
      "unsafe mapping formatting remains")

print(f"\nPASS={PASS} FAIL={FAIL}")
raise SystemExit(1 if FAIL else 0)
