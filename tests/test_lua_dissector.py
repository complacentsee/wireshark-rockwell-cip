# SPDX-License-Identifier: GPL-2.0-or-later
"""Dissector-level tests: tshark + Lua plugin → PDML diff vs expected.

Test naming convention:
    tests/fixtures/<feature>.pcapng       -> input
    tests/expected/<feature>.pdml         -> expected output

Each test is one fixture. The diff is plain-text so reviewing a failure
is "tail tests/<feature>.pdml.diff" — same workflow as upstream
Wireshark's own dissector test suite.
"""
from __future__ import annotations

import difflib
import pathlib

import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests" / "fixtures"
EXPECTED = REPO_ROOT / "tests" / "expected"


def fixtures_present():
    return sorted(p.name for p in FIXTURES.glob("*.pcapng"))


@pytest.mark.parametrize("fixture", fixtures_present() or ["__none__"])
def test_pdml_matches_expected(fixture, pdml_for, request):
    if fixture == "__none__":
        pytest.skip(
            "No fixtures committed yet — add tests/fixtures/*.pcapng "
            "with tools/sanitize_pcap.py before running this suite."
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
