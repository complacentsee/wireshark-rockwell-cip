# Rockwell vendor-private CIP — protocol overview

This document is the working reference for what the dissector targets.
The authoritative implementation of these formats lives in the
companion repository `logix_fw/cip_upload` (Python extractor and L5X
builder). Anything here is a summary of what's been reverse-engineered
there.

## Transports

### Service 0x36 — HMAC-signed Send

Wraps a standard CIP request so the firmware can verify the sender has
a valid Path-A session. Request layout:

```
0x36                  service
0x02                  path size (2 words)
20 02 24 01           path: class 0x02 (Message Router) inst 1
<inner CIP>           any standard CIP request
<seq u32 LE>          monotonic per session, starts at 1
<HMAC-SHA1 20B>       HMAC over [outer header + inner + seq]
```

Reply is symmetric, service code 0xB6, gen_status / ext_status between
the outer service and the inner CIP reply.

### Service 0x3A — Compiled-body upload

Used to read routine XML and the AOI source blob. Has its own framing
on top of the seq/HMAC trailer:

```
init request:   01 01 00 00 00 00 00 00 [inner 5D pwords path...]
cont request:   01 00 00 00 [token u32 LE]

init reply:     01 <state> 00 00 [len u32][flags 4B]
                [zlib_size u32][raw_size u32][zlib chunk]
cont reply:     01 <state> 00 00 [echoed token u32 LE][zlib chunk]
```

The state byte signals end-of-stream: 0x01/0x00 = more chunks, 0x03/0x02
= final. Token increments by 462 per continuation.

### Service 0x5D — Inner source read

Always carried inside an 0x3A request. The 8-byte arg tail picks the
operation: op=3 reads a single routine, op=4 releases resources, op=9
bulk-reads a program body. Together with the path, this is what tells
the firmware whether we want routine XML or the AOI's UDIParameters
blob.

## Records

### Class 0x0349 — Description blob

The response to service 0x53 on `class 0x0349 / inst 0` is a packed
sequence of variable-layout records. Each record describes one
documentation item — a rung comment, an operand bit comment, a
member description, etc.

Six layout variants observed:

| Layout              | Marker @ | Use                                    |
|---------------------|----------|----------------------------------------|
| 36B                 | +12      | Operand bit comments (class 0x6B)      |
| 38B                 | +14      | Most: programs, AOIs, members, modules |
| OPSTR               | +14+osl  | Array-index operand on tag (`[N]`)     |
| OPSTR_SHORT         | +10+osl  | Compact OPSTR for multi-char bits      |
| 36B SCOPED          | +30      | Bit operand on prog/AOI-scope tag      |
| OPSTR SCOPED        | +28+osl  | Array operand on prog/AOI-scope tag    |

SCOPED variants carry an 18-byte embedded CIP path at +14..+25 that
identifies the target by (scope_class, scope_inst, target_class,
target_inst).

Text body is either raw UTF-8 or zlib-compressed; the latter is signaled
by marker word 0x8280 at the body offset, followed by `dec_size u16`,
2 padding bytes, then the zlib stream.

### Class 0x0338 — AOI definition

GetAttrList exposes name, signature, vendor, revision. The bulk of the
AOI is in the 0x3A/0x5D op=9 response — a zlib stream containing two
TLV-like sections: `UDIChangeHistory` (edit log) and `UDIParameters`
(the parameter list with usage / visibility classification).

`UDIParameters` entries — `entry_size:u16` prefixed, ASCII name
null-terminated at the end:

```
+ 0 u16   entry_size
+ 2 u16   tag_inst_ref
+ 4 u8    type_code (0xC1=BOOL, 0xC4=DINT, 0xF6=DateTime, ...)
+ 5 u8    reserved
+ 6 u32   data_size (always 4)
+10 ...   10 bytes of zeros / metadata
+20 u8    usage_dir   1=Input, 2=Output, 3=InOut, 4=Local
+21 u8    vis_flags   bit 1 = visible, bit 2 = required,
                     0x11 = system, 0x0E = visible+required+InOut
+22 ...   2 padding bytes
+24 ...   null-terminated ASCII name
```

### Operand bit encoding

Class 0x006B operand-bit-comment records use a single u16 to identify
which bit a comment annotates: `bit_field = 12334 + 256*N`, where N is
the bit number (0..63 for LINT, 0..31 for DINT, etc.).

## Handshake

The 0x36 wrapper's HMAC key is established during a two-phase handshake
on class 0x0064 (Logix Controller). The wire format is known; the KDF
(key-derivation function) is not yet reverse-engineered:

1. **Phase 1**: client sends service `0x4B` with a small auth body. PLC
   replies with service `0xCB`; reply CIP body is a u16-LE length prefix
   (`0x0080` = 128) followed by 128 bytes of challenge / nonce material.
2. **Phase 2**: client sends service `0x4C`; CIP body is a u16-LE length
   prefix (`0x0014` = 20) followed by 20 bytes of response material. PLC
   replies with service `0xCC` carrying a small `license_status` ack.

**What's known**: the byte layouts above, captured against
`upload.pcapng` (Studio v36 ↔ ControlLogix).

**What's open**:
- The function that maps the 128-byte challenge to the 64-byte
  HMAC-SHA1 key. SHA-1^N(challenge[0:64]) was an earlier guess; an
  exhaustive search over `N=1..40` and over `{challenge[0:64],
  challenge[64:128], full 128, prefixes 20/32}` produced no match
  against the observed 20-byte Phase 2 response.
- Whether the HMAC key is `challenge[0:64]`, `challenge[64:128]`, or a
  derived value. The Lua dissector caches both halves as candidates and
  tries each against the actual HMAC trailer of the first 0x36 frame on
  the same stream; in `upload.pcapng` neither matches, so the key is
  some transformation we haven't recovered.

Until the KDF is recovered, validate HMACs by supplying a 64-byte key
out-of-band via the `rockwell_cip.hmac_key` preference (128 hex
characters). The dissector then validates every 0x36 / 0xB6 trailer on
every stream and reports OK/MISMATCH per frame.

## Where this isn't enough

- Encrypted CIP (Rockwell roadmap, not seen in current captures) would
  break the plain-text payload assumption. The HMAC bytes would still
  be decodable but the inner CIP would need a key-log mechanism.
- Some classes (0x008D MessageParameters) carry attribute-3 values
  whose meaning depends on the message type (CIP Generic vs PCCC
  Typed Read vs Block Transfer). The dissector decodes the structure
  but won't name every variant without per-message-type tables.
