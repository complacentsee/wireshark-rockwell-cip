#!/usr/bin/env python3
"""Derive the Path-A HMAC session key offline.

The dissector can do this automatically when its
`rockwell_cip.client_rsa_key_file` preference points at the client's
RSA private key. This script is the fallback for users who would
rather paste the derived 64-byte key into the existing
`rockwell_cip.hmac_key` preference instead (or who want a one-shot
sanity check that the key matches the captured challenge).

Inputs:
  --key PATH    PEM or DER RSA private key. Same key the Studio
                client used to mint the certificate sent in Phase 1.
  --challenge   128 bytes of Phase 1 reply payload, as hex. Copy from
                Wireshark's rockwell_cip.handshake.challenge field
                (`Apply as Filter > ...`, then "Copy value").

Output: 128 hex chars to stdout — paste verbatim into the dissector's
"HMAC session key (hex)" preference.

The math (mirrors hmac_connect.py:111-122):
  1. RSA-decrypt the challenge with the private key.
  2. Read AND write the integer in little-endian (Rockwell quirk —
     PKCS#1 uses big-endian internally for the key itself, but the
     challenge nonce on the wire is treated LE).
  3. Take plaintext[0:64].

Requires the `cryptography` package OR the `openssl rsautl` binary
fallback for the RSA decrypt step.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys


def _decrypt_with_cryptography(key_pem: bytes, ct_le: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return None
    key = serialization.load_pem_private_key(key_pem, password=None)
    pn  = key.private_numbers()
    n, d = pn.public_numbers.n, pn.d
    ct_int = int.from_bytes(ct_le, "little")
    pt_int = pow(ct_int, d, n)
    return pt_int.to_bytes(128, "little")


def _decrypt_with_openssl(key_path: str, ct_le: bytes) -> bytes:
    """Fallback: parse openssl rsa -text output for n/d, do pow() ourselves.

    `openssl rsautl -decrypt` expects PKCS#1-padded big-endian
    ciphertext, which isn't what we have — Rockwell sends raw LE
    integers. Extract the key components and run textbook pow() in
    Python instead.
    """
    if not shutil.which("openssl"):
        raise RuntimeError(
            "neither `cryptography` Python package nor `openssl` "
            "binary available; install one")
    text = subprocess.check_output(
        ["openssl", "rsa", "-in", key_path, "-text", "-noout"],
        stderr=subprocess.DEVNULL,
    ).decode()

    def _hex(label):
        m = re.search(rf"{label}:\s*\n((?:    [0-9a-f:]+\n)+)", text)
        if not m:
            raise RuntimeError(f"openssl text missing field: {label}")
        return int(re.sub(r"[:\s]", "", m.group(1)), 16)

    n = _hex("modulus")
    d = _hex("privateExponent")
    ct_int = int.from_bytes(ct_le, "little")
    if ct_int >= n:
        raise RuntimeError(
            "ciphertext integer >= modulus — wrong key or byte order")
    pt_int = pow(ct_int, d, n)
    return pt_int.to_bytes(128, "little")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--key", required=True,
                    help="path to client RSA private key (PEM or DER)")
    ap.add_argument("--challenge", required=True,
                    help="128-byte Phase 1 reply payload, as hex")
    args = ap.parse_args()

    hex_in = re.sub(r"[\s:]", "", args.challenge)
    ct = bytes.fromhex(hex_in)
    if len(ct) != 128:
        ap.error(f"challenge must be exactly 128 bytes; got {len(ct)}")

    with open(args.key, "rb") as f:
        key_pem = f.read()

    pt = _decrypt_with_cryptography(key_pem, ct)
    if pt is None:
        pt = _decrypt_with_openssl(args.key, ct)

    if len(pt) != 128:
        print(f"unexpected plaintext length {len(pt)}", file=sys.stderr)
        return 2

    print(pt[:64].hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
