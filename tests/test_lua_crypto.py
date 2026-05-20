# SPDX-License-Identifier: GPL-2.0-or-later
"""Lua-level tests for the crypto utility modules.

bigint / rsa / pem are pure Lua and don't need tshark — the cheapest
way to test them is to drive a Lua interpreter directly. We invoke a
small Lua test runner (tests/test_lua_crypto.lua) that exercises each
module against fixed vectors and exits non-zero on failure.

If no `lua` binary is on PATH we skip — the dissector still works
without these tests, they're a development convenience.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DRIVER    = REPO_ROOT / "tests" / "test_lua_crypto.lua"
PLUGIN    = REPO_ROOT / "plugins" / "lua"


def _find_lua():
    for name in ("lua", "lua5.4", "lua5.3"):
        path = shutil.which(name)
        if path:
            return path
    return None


def test_lua_crypto_vectors():
    lua = _find_lua()
    if not lua:
        pytest.skip("lua interpreter not on PATH; skipping pure-Lua tests")
    result = subprocess.run(
        [lua, str(DRIVER), str(PLUGIN)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        pytest.fail(
            f"Lua crypto tests failed (rc={result.returncode}):\n"
            f"--- stdout ---\n{result.stdout}\n"
            f"--- stderr ---\n{result.stderr}\n"
        )
