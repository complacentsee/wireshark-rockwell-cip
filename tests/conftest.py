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
import re
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


_PDML_HEADER_RE = re.compile(
    r'<pdml version="[^"]*" creator="[^"]*" time="[^"]*" capture_file="[^"]*">'
)
_STYLESHEET_COMMENT_RE = re.compile(r'<!-- You can find pdml2html\.xsl[^>]*-->')


def _normalize_pdml(text: str, fixture_name: str) -> str:
    """Strip volatile bits so the diff stays meaningful across hosts.

    Volatile across machines / runs:
    - The stylesheet-hint comment names a host-specific share path.
    - The <pdml> open tag carries the run timestamp, the tshark version,
      and the absolute capture-file path.
    Frame timestamps inside the body come from the pcap itself and are
    stable across runs of the same input.
    """
    text = _STYLESHEET_COMMENT_RE.sub('', text)
    text = _PDML_HEADER_RE.sub(
        f'<pdml capture_file="{fixture_name}">', text)
    return text


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
        # Two-pass analysis so request/response cross-references (e.g.
        # rockwell_cip.docs.response_in on the request frame, populated
        # only after the matching reply has been seen) render in PDML.
        "-2",
        # Pin protocol preferences to a known clean state so the test
        # output doesn't drift based on whatever the user has set in
        # their personal ~/.config/wireshark/preferences. The carved
        # fixtures were captured with HMAC validation disabled; pinning
        # both key sources empty keeps the goldens stable even if a
        # developer set the RSA key in the GUI for ad-hoc dissection.
        "-o", "rockwell_cip.client_rsa_key_file:",
        "-o", "rockwell_cip.hmac_key:",
        # Force-off the optional zlib-inflate preference (which the
        # user may have enabled in the GUI for upload-body inspection)
        # so the upload_3a_seq golden stays stable.
        "-o", "rockwell_cip.inflate:FALSE",
    ]
    # Pin TZ to UTC so frame.time's local-time `show=` field doesn't
    # vary by host timezone. UTC arrival fields are already stable.
    env = {**os.environ, "TZ": "UTC"}
    result = subprocess.run(cmd, check=True, capture_output=True, text=True,
                            env=env)
    return _normalize_pdml(result.stdout, fixture.name)


@pytest.fixture
def pdml_for(tshark_bin, plugin_path, fixtures_dir):
    """Curried: pass a fixture filename, get PDML text back."""
    def _run(name: str) -> str:
        return run_tshark(tshark_bin, plugin_path, fixtures_dir / name)
    return _run
