# SPDX-License-Identifier: GPL-2.0-or-later
"""End-to-end test for the Path-A KDF crypto path.

Generates a synthetic 1024-bit RSA keypair via openssl, mints a Phase
1-shaped ciphertext (Rockwell little-endian encoding) with Python's
built-in pow(), and drives the Lua rsa/pem modules to confirm the
decrypt recovers the expected plaintext.

Skipped when either `openssl` or `lua` is unavailable. The synthetic
keypair lives in pytest's tmp_path and never touches the repo.
"""
from __future__ import annotations

import pathlib
import re
import shutil
import subprocess
import textwrap

import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN    = REPO_ROOT / "plugins" / "lua"


def _which(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _parse_openssl_rsa_text(text: str) -> dict[str, int]:
    """Extract RSA components from `openssl rsa -text -noout` output."""
    def _hex_block(label: str) -> int:
        m = re.search(rf"{label}:\s*\n((?:    [0-9a-f:]+\n)+)", text)
        if not m:
            raise RuntimeError(f"openssl text missing field: {label}")
        h = re.sub(r"[:\s]", "", m.group(1))
        return int(h, 16)

    out = {
        "n":    _hex_block("modulus"),
        "d":    _hex_block("privateExponent"),
        "p":    _hex_block("prime1"),
        "q":    _hex_block("prime2"),
        "dp":   _hex_block("exponent1"),
        "dq":   _hex_block("exponent2"),
        "qinv": _hex_block("coefficient"),
    }
    em = re.search(r"publicExponent:\s*(\d+)", text)
    if not em:
        raise RuntimeError("openssl text missing publicExponent")
    out["e"] = int(em.group(1))
    return out


@pytest.fixture(scope="module")
def tools():
    openssl = _which("openssl")
    lua     = _which("lua", "lua5.4", "lua5.3")
    if not openssl:
        pytest.skip("openssl not on PATH")
    if not lua:
        pytest.skip("lua interpreter not on PATH")
    return {"openssl": openssl, "lua": lua}


def test_rsa_round_trip(tools, tmp_path):
    """End-to-end: PEM → Lua parse → RSA-decrypt → expected plaintext."""
    pem_path = tmp_path / "synth_rsa.pem"
    # Generate a 1024-bit RSA key in PKCS#1 PEM (BEGIN RSA PRIVATE KEY).
    subprocess.run([tools["openssl"], "genrsa", "-traditional",
                    "-out", str(pem_path), "1024"],
                   check=True, capture_output=True)
    # Re-extract the components so we can build the test vector.
    text = subprocess.check_output(
        [tools["openssl"], "rsa", "-in", str(pem_path),
         "-text", "-noout"], stderr=subprocess.DEVNULL,
    ).decode()
    key = _parse_openssl_rsa_text(text)

    # Plaintext: 128 bytes whose first 64 will become the HMAC key.
    pt = (b"Hello Rockwell, plaintext[0:64] is the HMAC session key. "
          b"This second half rounds out the 128-byte RSA modulus.    ")[:128]
    pt = pt.ljust(128, b"\0")
    assert len(pt) == 128

    # Rockwell encoding: LE int → modexp e → LE bytes.
    pt_int = int.from_bytes(pt, "little")
    assert pt_int < key["n"]
    ct_int = pow(pt_int, key["e"], key["n"])
    ct = ct_int.to_bytes(128, "little")

    # Hand-off files: ciphertext + expected plaintext.
    (tmp_path / "ct.bin").write_bytes(ct)
    (tmp_path / "expected_pt.bin").write_bytes(pt)

    # Lua driver: load PEM, decrypt, compare against expected.
    driver = tmp_path / "drive.lua"
    driver.write_text(textwrap.dedent(f"""\
        package.path = "{PLUGIN}/util/?.lua;" .. package.path
        local pem = require "pem"
        local rsa = require "rsa"
        local key = pem.parse_private_key("{pem_path}")
        local ct  = io.open("{tmp_path}/ct.bin","rb"):read("*a")
        local exp = io.open("{tmp_path}/expected_pt.bin","rb"):read("*a")
        local pt  = rsa.decrypt(ct, key, {{ byte_order = "le", width = 128 }})
        if pt ~= exp then
            io.stderr:write(string.format(
                "decrypt mismatch:\\n  got=%s\\n  exp=%s\\n",
                pt:sub(1,32):gsub("[^%g]", "?"),
                exp:sub(1,32):gsub("[^%g]", "?")))
            os.exit(1)
        end
        io.write("plaintext[0:64] = ", pt:sub(1,64), "\\n")
    """))

    result = subprocess.run(
        [tools["lua"], str(driver)],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        pytest.fail(
            f"Lua RSA round-trip failed (rc={result.returncode}):\n"
            f"--- stdout ---\n{result.stdout}\n"
            f"--- stderr ---\n{result.stderr}\n"
        )
    # Sanity: stdout should echo the expected plaintext prefix.
    assert pt[:64].decode("latin-1") in result.stdout, (
        f"Lua decrypt output didn't include expected plaintext "
        f"prefix:\n{result.stdout}"
    )
