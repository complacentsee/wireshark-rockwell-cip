# wireshark-rockwell-cip

A Wireshark dissector for Rockwell Automation's vendor-private extensions
to CIP (Common Industrial Protocol), as spoken by Studio 5000 and
ControlLogix firmware v18 through v36.

Status: **early scaffolding** — Phase 1 in progress. See
`docs/protocol-overview.md` for the protocol surface this targets and
`CHANGELOG.md` for what works today.

## What it decodes

Out of the box, Wireshark's `cip` dissector handles the ODVA-standard
services and a few Rockwell extensions, but stops at:

- Service `0x36` / `0xB6` — Studio 5000's HMAC-SHA1 signed CIP wrapper
  (the bulk of v36 traffic).
- Service `0x3A` / `0xBA` — compiled-body upload wrapper used for
  routine XML and AOI source.
- Service `0x5D` — inner service for source / parameter reads, varies by
  `op` value (3 = read routine, 4 = release, 9 = read program body).
- Class `0x0349` — Logix description object. Its response payload is a
  packed sequence of variable-layout records that hold rung comments,
  operand comments, tag descriptions, and member documentation.
- Class `0x0338` — AddOnInstruction definition, including the
  `UDIParameters` blob with the only authoritative source for InOut
  parameter classification on v36.
- Class `0x008D` — MessageParameters attribute attached to MESSAGE-typed
  tags.

This plugin adds typed sub-trees for each of those so they show up in
Wireshark's packet detail pane instead of `<opaque CIP body>`.

## Install

Lua plugin, Wireshark ≥ 4.0.

```bash
# macOS
mkdir -p ~/.local/lib/wireshark/plugins
cp -r plugins/lua/* ~/.local/lib/wireshark/plugins/

# Linux
mkdir -p ~/.local/lib/wireshark/plugins
cp -r plugins/lua/* ~/.local/lib/wireshark/plugins/

# Windows
# Copy plugins/lua/* into  %APPDATA%\Wireshark\plugins\
```

Then `Analyze → Reload Lua Plugins` in Wireshark, or restart it.

`tshark` runs work the same way; you can also point at a checkout
directly:

```bash
tshark -X lua_script:plugins/lua/rockwell_cip.lua -r capture.pcapng
```

## Filters

Once loaded, these display filters become available:

Service 0x36 / 0xB6 — HMAC-signed CIP wrapper:
- `rockwell_cip.signed.service`           — service byte (0x36 / 0xB6)
- `rockwell_cip.signed.seq`               — session sequence number
- `rockwell_cip.signed.hmac`               — raw HMAC-SHA1 trailer bytes
- `rockwell_cip.signed.hmac_status`       — `OK` / `MISMATCH` / `(no key)`

Service 0x3A / 0xBA — compiled-body upload transport:
- `rockwell_cip.upload.state`             — state byte (0x00..0x03 init/cont, more/final)
- `rockwell_cip.upload.token`             — continuation token (req side)
- `rockwell_cip.upload.token_echo`        — token echo (reply side)
- `rockwell_cip.upload.op`                — inner 0x5D op (3 read / 4 release / 9 bulk)
- `rockwell_cip.upload.zlib_offset`       — where the zlib stream starts in the chunk
- `rockwell_cip.upload.inflated_size`     — inflated payload size (when preference enabled)

Class 0x0064 — Path-A handshake:
- `rockwell_cip.handshake.phase`          — Phase 1/2 request/reply
- `rockwell_cip.handshake.challenge`      — 128-byte Phase 1 challenge body
- `rockwell_cip.handshake.response`       — 20-byte Phase 2 response body

Class 0x0349 — description records:
- `rockwell_cip.docs.class_marker`        — target class (0x68 = program, 0x338 = AOI, ...)
- `rockwell_cip.docs.text`                — decoded comment text
- `rockwell_cip.docs.bit_number`          — decoded bit number for operand-bit comments
- `rockwell_cip.docs.compressed`          — true when the body used the 0x8280 zlib marker

Class 0x338 — AOI definition (UDIParameters):
- `rockwell_cip.aoi.param_name`           — UDIParameters entry name
- `rockwell_cip.aoi.param_usage`          — usage direction (Input/Output/InOut/Local)
- `rockwell_cip.aoi.param_vis`            — visibility flags

The `class_attrs` module also adds attribute-name hints for class 0x6C
(Template) and 0x8D (MessageParameters) responses; those show up as
generated sub-trees under the stock CIP tree.

## Pcaps & test fixtures

This repository ships **no pcap files**. Live capture material — even
sanitised — stays in your local environment, never in source control.

To run the dissector test suite (`pytest tests/`), set the env var
`ROCKWELL_CIP_FIXTURES` to a directory of local `.pcapng` files (or
populate the default `~/.cache/rockwell_cip/`). Each fixture maps to a
committed `tests/expected/<name>.pdml` reference output that the suite
diffs against the live `tshark` run. Use `pytest --regen` to refresh
expectations after intentional dissector changes; review the diffs
before committing.

## How this maps to a future Wireshark upstream MR

The `proto-c/` directory holds the C port, structured to compile
stand-alone today and to drop straight into Wireshark's
`epan/dissectors/` tree later. See `docs/upstream-mr.md` for the patch
plan and which extension points get used (no edits to ODVA-standard
paths — only `dissector_add_for_decode_as("cip.vendor_service", ...)`
and `dissector_add_uint("cip.class", ...)`).

## License

GPL-2.0-or-later, matching Wireshark itself. See `LICENSE`.

## Acknowledgements

Built from reverse-engineering notes in the companion
[`logix_fw/cip_upload`](https://github.com/) project's PCAP_FINDINGS.md
and ROUTINE_UPLOAD_V36_FINDINGS.md. The Python extractor in that repo
remains the source-of-truth implementation; this dissector is a
read-only view of the same wire formats.
