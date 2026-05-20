#!/usr/bin/env python3
"""Sanitize a Rockwell CIP capture before committing it as a test fixture.

Public Wireshark fixtures should not carry live PLC secrets. This tool
takes a `.pcapng` capture and replaces the bytes we care about:

  * The 128-byte challenge nonce in the 0x4C/0x64 Phase-1 reply.
  * The 20-byte SHA-1^20 challenge response in the Phase-2 request.
  * The 20-byte HMAC-SHA1 trailers in every 0x36 / 0xB6 / 0x3A / 0xBA
    signed frame (the trailers are the only spot the session key would
    leak if it were ever leaked; the key itself never travels on the
    wire, but the MACs are derived from it).
  * Controller serial numbers reported by class 0x01 Identity replies
    and class 0x0064 controller-property replies.
  * Any non-ASCII tag value payload from Read Tag Fragmented replies
    (service 0x52) — keeps tag names and structural data, zeros the
    user data.

The sanitizer rewrites the pcap in place to a new file and recomputes
any framing checksums Wireshark relies on.

Usage:
    tools/sanitize_pcap.py source.pcapng tests/fixtures/dest.pcapng

Status: scaffolding. Phase 0 of the wireshark-rockwell-cip plan calls
for fixtures by Day 2; this file is the stub we'll fill in as each
record type lands. Run with --check to verify the input has no PII
patterns left over after sanitisation.
"""
from __future__ import annotations

import argparse
import sys


SCAFFOLD_NOTICE = """\
sanitize_pcap.py — scaffolding only. Implementation lands with Phase 1
fixtures (see CHANGELOG.md). For now this script just verifies the
arguments and exits 0; real sanitisation passes get added one
record-type at a time so each pass can be diffed against a known-good
expectation.
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source", help="Input pcapng")
    ap.add_argument("dest", help="Output pcapng (overwritten if it exists)")
    ap.add_argument(
        "--check",
        action="store_true",
        help="After writing, scan the output for known-PII patterns and "
        "exit non-zero if any are still present.",
    )
    args = ap.parse_args()

    sys.stderr.write(SCAFFOLD_NOTICE)
    sys.stderr.write(f"\n  source: {args.source}\n  dest:   {args.dest}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
