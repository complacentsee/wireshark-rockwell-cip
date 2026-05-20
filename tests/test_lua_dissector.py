# SPDX-License-Identifier: GPL-2.0-or-later
"""Dissector-level tests: tshark + Lua plugin → PDML diff vs expected.

Pcaps are NOT committed to this repository. Set the env var
ROCKWELL_CIP_FIXTURES to a directory of local `.pcapng` files (or
populate the default ~/.cache/rockwell_cip/). See tests/conftest.py for
the resolution rules.

Test naming convention (within the fixtures directory):
    <feature>.pcapng       -> input
    tests/expected/<feature>.pdml  -> expected output (committed)

Each test is one fixture. The diff is plain-text so reviewing a failure
is "tail tests/<feature>.pdml.diff" — same workflow as upstream
Wireshark's own dissector test suite.
"""
from __future__ import annotations

import difflib
import os
import pathlib

import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
EXPECTED = REPO_ROOT / "tests" / "expected"

# Re-resolve the fixtures directory at collection time (mirroring
# conftest.py) so parametrize() can enumerate inputs.
_ENV_DIR = os.environ.get("ROCKWELL_CIP_FIXTURES")
_FIXTURES = (
    pathlib.Path(_ENV_DIR).expanduser()
    if _ENV_DIR
    else pathlib.Path.home() / ".cache" / "rockwell_cip"
)


def fixtures_present():
    if not _FIXTURES.is_dir():
        return []
    return sorted(p.name for p in _FIXTURES.glob("*.pcapng"))


@pytest.mark.parametrize("fixture", fixtures_present() or ["__none__"])
def test_pdml_matches_expected(fixture, pdml_for, request):
    if fixture == "__none__":
        pytest.skip(
            f"No pcaps found in {_FIXTURES}. "
            "Pcaps are intentionally NOT committed to this repository — "
            "set ROCKWELL_CIP_FIXTURES to a local directory of "
            "developer-owned pcaps before running this suite."
        )

    actual = pdml_for(fixture)
    stem = fixture.removesuffix(".pcapng")
    expected_path = EXPECTED / f"{stem}.pdml"

    if request.config.getoption("--regen"):
        expected_path.parent.mkdir(parents=True, exist_ok=True)
        expected_path.write_text(actual)
        return

    if not expected_path.exists():
        pytest.fail(
            f"Expected file missing: {expected_path}\n"
            "Run with --regen to create it from current output."
        )

    expected = expected_path.read_text()
    if actual == expected:
        return

    diff = "".join(
        difflib.unified_diff(
            expected.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=str(expected_path),
            tofile=f"{fixture} (actual)",
            n=3,
        )
    )
    # Write the actual output to disk so the diff is easy to re-read
    # without rerunning the test.
    (REPO_ROOT / "tests" / f"{stem}.pdml.actual").write_text(actual)
    (REPO_ROOT / "tests" / f"{stem}.pdml.diff").write_text(diff)
    pytest.fail(
        f"PDML mismatch for {fixture}.\n"
        f"Diff written to tests/{stem}.pdml.diff\n"
        f"Actual output written to tests/{stem}.pdml.actual\n\n"
        f"{diff}"
    )
