# Upstream MR plan

Wireshark accepts vendor-specific dissectors in `epan/dissectors/` —
`packet-cipmotion.c` and `packet-cipsafety.c` are precedent. This
document sketches how the code in this repo gets ported and what hooks
into the stock CIP dissector look like, without touching ODVA-standard
code paths.

## Files in the upstream MR

```
epan/dissectors/packet-rockwell-cip.c     -- one .c per the layout below
epan/dissectors/packet-rockwell-cip.h     -- shared protocol IDs / structs
suite/tests/test_rockwell_cip.py          -- regression tests
docbook/wsug_src/...                      -- user-guide snippet (optional)
```

## Source layout within the .c file

Mirrors `plugins/lua/lua/`:

| Section          | Lines (rough) | Mirrors                          |
|------------------|---------------|----------------------------------|
| Service 0x36     | ~150          | service_36_signed.lua            |
| Service 0x3A+5D  | ~250          | service_3a_upload.lua            |
| Class 0x0349     | ~400          | class_0349_docs.lua              |
| Class 0x0338     | ~200          | class_0338_aoi.lua               |
| Class 0x006C     | ~120          | class_006c_template.lua          |
| Class 0x008D     | ~120          | class_008d_msgparams.lua         |
| Class 0x0064     | ~80           | class_0064_handshake.lua         |
| Registration     | ~80           | rockwell_cip.lua                 |

## Hook points

The stock CIP dissector exposes two dissector tables that vendor
extensions register against. We use both:

```c
/* cip.service: Decode-As table keyed on the outer service byte. */
dissector_add_uint("cip.service", 0x36, rockwell_signed_handle);
dissector_add_uint("cip.service", 0xB6, rockwell_signed_handle);
dissector_add_uint("cip.service", 0x3A, rockwell_body3a_handle);
dissector_add_uint("cip.service", 0xBA, rockwell_body3a_handle);

/* cip.class: claim the Rockwell-private classes for our class
   dissector. Stock cip already handles 0x01 (Identity), 0x6B (Symbol),
   0x6C (Template), etc., generically — we don't override those, we
   only add layers when the path lands inside a Rockwell-only object. */
dissector_add_uint("cip.class", 0x0349, rockwell_class_0349_handle);
dissector_add_uint("cip.class", 0x0338, rockwell_class_0338_handle);
dissector_add_uint("cip.class", 0x008D, rockwell_class_008D_handle);
```

No edits to `packet-cip.c` itself, which keeps the MR self-contained
and approvable.

## Pre-MR checklist

1. Open a Gitlab issue describing what we're adding; reference
   packet-cipmotion / packet-cipsafety as precedent. Wait for a
   maintainer to ack scope.
2. Run `tools/checklicenses.py` and `tools/checkAPIs.pl` from
   Wireshark's tree against the new source — these are CI gates.
3. Ensure all ProtoField names use the project's `<short>.<thing>`
   convention.
4. Make sure expert-info codes are registered and used (Wireshark
   reviewers will flag silent length / format errors).
5. Add a one-paragraph entry to `docbook/wsug_src/Chapter*Plumbing.adoc`
   summarising what's now decoded.
6. Submit as a draft MR first; iterate on reviewer comments before
   marking ready.

## What we explicitly will not change upstream

- `packet-cip.c` itself.
- Any ODVA-standard service or class dissector.
- The build system (CMakeLists changes are limited to adding the new
  source files to `DISSECTOR_SRC`).
- Existing Lua plugins (those are separate from compiled dissectors).
