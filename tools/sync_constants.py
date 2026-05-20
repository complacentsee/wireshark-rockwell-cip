#!/usr/bin/env python3
"""Regenerate plugins/lua/util/valstr.lua from the Python extractor.

The Python extractor in ~/logix_fw/cip_upload/extract_logix_data.py is
the source of truth for record layouts, service IDs, class IDs, and the
operand-bit encoding constants. Hand-syncing those values into Lua would
drift the moment someone touched the parser; this script reads the
Python module, pulls the constants it cares about, and regenerates the
Lua tables.

Invocation:
    tools/sync_constants.py             # rewrites the Lua file in place
    tools/sync_constants.py --check     # exits non-zero if regen would
                                        # differ from the committed copy

CI will run --check on every PR.

Status: scaffolding. Phase 0 puts the entry point in place; the actual
import-and-emit code lands when we wire up the codegen contract with
the Python side (the Python module currently exposes most of these as
local constants inside _parse_description_data, so we need to lift them
to module-level first).
"""
from __future__ import annotations

import argparse
import sys


SCAFFOLD_NOTICE = """\
sync_constants.py — scaffolding only. Real regen lands when
extract_logix_data exposes:
  * SERVICES_VENDOR             dict[int, str]
  * CLASSES_VENDOR              dict[int, str]
  * DOC_RECORD_LAYOUTS          dict[int, layout-tuple]
  * OPERAND_BIT_BASE, OPERAND_BIT_STRIDE, COMPRESSED_MARKER
at module scope. Until then valstr.lua is hand-maintained.
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if regenerating would change the committed file.",
    )
    ap.parse_args()
    sys.stderr.write(SCAFFOLD_NOTICE)
    return 0


if __name__ == "__main__":
    sys.exit(main())
