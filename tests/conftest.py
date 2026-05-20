# SPDX-License-Identifier: GPL-2.0-or-later
"""pytest fixtures shared across dissector tests.

Each test reads a `.pcapng` from tests/fixtures/, runs it through
`tshark -X lua_script:plugins/lua/rockwell_cip.lua -T pdml`, and diffs
the result against an expected PDML file. The expected files live in
tests/expected/ and are checked in.

Regenerate expectations after intentional dissector changes with:
    pytest tests/ --regen
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = REPO_ROOT / "plugins" / "lua" / "rockwell_cip.lua"
FIXTURES = REPO_ROOT / "tests" / "fixtures"
EXPECTED = REPO_ROOT / "tests" / "expected"


def pytest_addoption(parser):
    parser.addoption(
        "--regen",
        action="store_true",
        default=False,
        help="Rewrite tests/expected/*.pdml with current dissector output. "
        "Use after intentional dissector changes; review the diff carefully.",
    )


@pytest.fixture(scope="session")
def tshark_bin() -> str:
    path = shutil.which("tshark")
    if not path:
        pytest.skip("tshark not installed; install wireshark CLI to run these tests")
    return path


@pytest.fixture(scope="session")
def plugin_path() -> pathlib.Path:
    assert PLUGIN.is_file(), f"plugin missing: {PLUGIN}"
    return PLUGIN


def run_tshark(tshark_bin: str, plugin_path: pathlib.Path,
               fixture: pathlib.Path) -> str:
    """Run tshark with our Lua plugin and return PDML output as text."""
    cmd = [
        tshark_bin,
        "-r", str(fixture),
        "-X", f"lua_script:{plugin_path}",
        "-T", "pdml",
        # Disable name resolution so PDML output is stable across runs.
        "-n",
    ]
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return result.stdout


@pytest.fixture
def pdml_for(tshark_bin, plugin_path):
    """Curried: pass a fixture filename, get PDML text back."""
    def _run(name: str) -> str:
        return run_tshark(tshark_bin, plugin_path, FIXTURES / name)
    return _run
