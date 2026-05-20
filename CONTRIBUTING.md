# Contributing to wireshark-rockwell-cip

This is a clean-room reverse-engineering project targeting upstream
Wireshark eventually. Two non-negotiable ground rules first, then the
mechanics.

## Ground rules

**No pcaps in the repository.** Not under `tests/`, not under any new
directory, not "just temporarily." `.gitignore` excludes `*.pcap*`
unconditionally. Capture material — even what you believe to be
sanitised — stays on your machine. Sharing fixtures between developers
is an out-of-band concern.

**No controller-identifying material.** Serials, firmware images, MAC
addresses pulled from a customer site, credentials, signing keys.
Treat the repo as if it were already public.

**License is GPL-2.0-or-later**, matching Wireshark. Every source file
carries an `SPDX-License-Identifier:` line. Add one to anything new.

## Setting up fixtures

Tests need local pcaps. Point pytest at them with either:

```bash
# Either set this env var to any directory
export ROCKWELL_CIP_FIXTURES=/path/to/your/pcaps

# Or use the default location
mkdir -p ~/.cache/rockwell_cip
cp my-capture.pcapng ~/.cache/rockwell_cip/
```

Each fixture filename stem maps to one expected-PDML file in
`tests/expected/`. The plan currently expects:

| Fixture                       | Coverage                                  |
| ----------------------------- | ----------------------------------------- |
| `handshake_phase12.pcapng`    | class 0x64 Phase 1+2 exchange             |
| `upload_3a_seq.pcapng`        | one init+cont+final routine upload        |
| `docs_blob.pcapng`            | multi-record class 0x349 reply, ≥1 zlib   |
| `msgparams_attrs.pcapng`      | class 0x8D GetAttrList replies            |
| `udi_aoi.pcapng`              | a frame with the UDIParameters magic      |

Trim large captures with `editcap` — running the dissector on a 7+ MB
pcap can exhaust memory because the post-dissector fires for every
frame.

```bash
editcap -r big.pcapng ~/.cache/rockwell_cip/upload_3a_seq.pcapng 6709-6720
```

## Running tests

```bash
pytest tests/                    # diff against committed expectations
pytest tests/ --regen            # rewrite tests/expected/*.pdml
```

When fixtures are absent, the suite skips cleanly rather than
failing — that is the supported CI mode.

After `--regen`, **review the diff before committing**. PDML output
is allowed to change for real reasons (new fields, fixed value
strings), but a regen run should never be a silent rubber-stamp.

## Lint

```bash
luacheck plugins/lua/
```

CI runs this on every push. Install via `brew install luacheck` or
`luarocks install luacheck`.

## Dissector contract

`plugins/lua/rockwell_cip.lua` is the master loader. Per-feature
modules under `plugins/lua/lua/` register themselves via a `ctx`
object — they **must not** assign `proto.fields` or `proto.experts`
directly. Wireshark only honours a single assignment per `Proto`, so
the master collects them and assigns once after every module has
registered.

Module skeleton:

```lua
-- SPDX-License-Identifier: GPL-2.0-or-later
local M = {}

function M.register(proto, valstr, ctx)
    local f_thing = ProtoField.uint8("rockwell_cip.foo.thing", "Thing")
    ctx.add_field(f_thing)

    ctx.add_dissect("foo", function(tvb, pinfo, tree)
        -- per-packet work
    end)
end

return M
```

Common-utility code (SHA-1, inflate, session state, value strings)
lives under `plugins/lua/util/` and is `require`-able by any module.

## Commits

- Subject line under 72 chars, imperative mood.
- Body wraps at 72 cols, explains *why* not *what* (the diff shows
  what).
- Every commit ends with the trailer:

  ```
  Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
  ```

  if any portion of the change was AI-assisted. We have used Claude
  Code throughout — leave the trailer in place.

## Documentation

- `docs/protocol-overview.md` — wire-format notes. Update when a new
  layout or service is decoded; flag anything that is hypothetical
  rather than confirmed.
- `docs/upstream-mr.md` — the C-port plan and which modules are
  candidates for the upstream MR.
- `CHANGELOG.md` — keep a running entry under "Unreleased" while
  iterating.
