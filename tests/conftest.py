# SPDX-License-Identifier: GPL-2.0-or-later
"""pytest fixtures shared across dissector tests.

By policy this repository ships **no pcap files**. Live capture
material — even sanitised — stays in the developer's local environment,
never in source control.

To run the dissector test suite you must:

  1. Point the env var ROCKWELL_CIP_FIXTURES at a directory holding your
     local `.pcapng` files. Suggested default: ~/.cache/rockwell_cip
  2. Place one `.pcapng` per scenario in that directory. The test names
     match the filename stems (e.g. `handshake_phase12.pcapng` →
     `handshake_phase12.pdml` expected file under tests/expected/).

Each test reads its `.pcapng`, runs it through `tshark -X
lua_script:plugins/lua/rockwell_cip.lua -T pdml`, and diffs the result
against the matching expected PDML file in tests/expected/ (the only
thing checked in is the expected text). Regenerate expectations after
intentional dissector changes with:
    pytest tests/ --regen

When ROCKWELL_CIP_FIXTURES is unset or the directory is missing /
empty, the test suite skips loudly instead of failing.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess

import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = REPO_ROOT / "plugins" / "lua" / "rockwell_cip.lua"
EXPECTED = REPO_ROOT / "tests" / "expected"

# Resolution order for the fixtures directory:
#   1. ROCKWELL_CIP_FIXTURES env var (explicit override)
#   2. ~/.cache/rockwell_cip (default — outside the repo tree)
# Either path may be absent; tests skip cleanly in that case.
_ENV_DIR = os.environ.get("ROCKWELL_CIP_FIXTURES")
FIXTURES = (
    pathlib.Path(_ENV_DIR).expanduser()
    if _ENV_DIR
    else pathlib.Path.home() / ".cache" / "rockwell_cip"
)


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


@pytest.fixture(scope="session")
def fixtures_dir() -> pathlib.Path:
    if not FIXTURES.is_dir():
        pytest.skip(
            f"No fixtures directory at {FIXTURES}. "
            "Set ROCKWELL_CIP_FIXTURES to a directory of local pcaps, "
            "or place pcaps at ~/.cache/rockwell_cip/. "
            "Pcaps are intentionally NOT committed to this repository."
        )
    return FIXTURES


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
def pdml_for(tshark_bin, plugin_path, fixtures_dir):
    """Curried: pass a fixture filename, get PDML text back."""
    def _run(name: str) -> str:
        return run_tshark(tshark_bin, plugin_path, fixtures_dir / name)
    return _run
