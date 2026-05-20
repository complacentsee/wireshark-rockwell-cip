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

- `rockwell_cip.signed.service`           — service code of an HMAC-wrapped CIP request
- `rockwell_cip.signed.seq`               — HMAC trailer sequence number
- `rockwell_cip.body_3a.op`               — `0x5D` op code (3 / 4 / 9)
- `rockwell_cip.body_3a.zlib_size`        — compressed size from the init reply
- `rockwell_cip.doc_record.scope_class`   — embedded scope-path class (`0x68` = program, `0x338` = AOI)
- `rockwell_cip.doc_record.operand`       — operand string for `[N]` / `.N` / `.DATA[0].2` style comments
- `rockwell_cip.udi_param.usage`          — UDI parameter usage (Input/Output/InOut/Local)

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
