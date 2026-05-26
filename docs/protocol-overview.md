# Rockwell vendor-private CIP — protocol overview

This document is the working reference for what the dissector targets.
The authoritative implementation of these formats lives in an
out-of-tree Python extractor / L5X builder; anything here is a summary
of what's been reverse-engineered against that reference.

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

### Service 0x37 — Audited mutation Send

Used for any state-changing operation the controller writes to its audit
log: task program-list edits (schedule/unschedule a program), program
delete, online-edit submissions, mode changes, etc. Wraps a standard CIP
request the same way 0x36 does but adds an 8-byte envelope between the
outer-path bytes and the inner CIP request:

```
0x37                  service
0x02                  path size (2 words)
20 02 24 01           path: class 0x02 (Message Router) inst 1
01 03 00 00 <LEN u32 LE>     audited-mutation envelope (LEN = bytes of inner)
<inner CIP>           the actual request (LEN bytes)
<seq u32 LE>          monotonic per session, shares counter with 0x36
<HMAC-SHA1 20B>       HMAC over [outer header + envelope + inner + seq]
```

Reply is symmetric, service code 0xB7, gen_status byte at the standard
offset. On a per-inner failure the outer status is `0x1E` (embedded
service error) and the inner reply (after the envelope) carries the
actual gen_status.

The constant `01 03 00 00` prefix was identical across every captured
0x37 frame across unschedule / reschedule / delete traces; treat as a
fixed marker. The same envelope shape also appears inside some
`0x36`-wrapped `0x4F` requests on Class 0x0349 during the delete
sequence — i.e. it's a per-operation "audited" marker, not strictly
tied to outer service 0x37.

Common inner services seen under 0x37:

| Inner svc | Path                        | Use                                         |
|-----------|-----------------------------|----------------------------------------------|
| 0x35      | Class 0x008E inst 1         | Audit log event write (UTF-16 text, see below) |
| 0x04      | Class 0x0070 inst <task>    | Set_Attribute_List — Task program-list rewrite |
| 0x09      | Class 0x0068 inst <prog>    | Delete program (children cascade)            |
| 0x5C      | Class 0x008E inst 1         | Project path register (used in go-online)    |

Audit log event payload (service 0x35 on Class 0x8E inst 1):

```
35 02 20 8E 24 01     service + path
<subject_chars u16>   char count of the subject text
<UTF-16LE text>       either "<subject>" (subject-only form)
                      or "<subject>#<detail>" (detail form)
[u16 NUL]             present only in the subject-only form
```

Typical subject strings:
* `Changed Program Schedule on Task [ \<TaskName> ]` — paired with a
  detail audit (`Changed Properties of Task [ \<TaskName> ]#Property
  List:    Task Program List`) and a Set_Attribute_List write.
* `Deleted Program [ \<ProgName> ]`
* `Deleted Routine [ \<ProgName>\<RoutName> ]`
* `Deleted Tag [ \<ProgName>\<TagName> ]`

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
on class 0x0064 (Logix Controller):

1. **Phase 1**: client sends service `0x4B` with a small auth body
   (containing the client's certificate). PLC replies with service
   `0xCB`; reply CIP body is a u16-LE length prefix (`0x0080` = 128)
   followed by 128 bytes of `challenge_nonce`. The nonce is the
   CIPHERTEXT of an RSA encryption of a 128-byte plaintext blob with
   the *client's* public key. Reading the nonce in the clear tells you
   nothing.
2. **Phase 2**: client RSA-decrypts the nonce with its private key,
   reading and writing **little-endian** (Rockwell-specific quirk;
   PKCS#1 uses big-endian — easy to get wrong). The HMAC session key
   is `plaintext[0:64]`. The Phase 2 response that unlocks signing is
   `SHA-1^20(plaintext[0:64])` — twenty sequential SHA-1 applications
   starting from the 64-byte key. Client sends service `0x4C`; CIP
   body is a u16-LE length prefix (`0x0014` = 20) followed by the
   20-byte response. PLC replies with service `0xCC` carrying a small
   `license_status` ack and from then on accepts service-0x36 signed
   requests starting at seq=1.

The firmware accepts a second Phase 2 variant (`SHA-1(plaintext[0:20])`)
that grants privileged access without enabling signing. See
`hmac_connect.py` in the out-of-tree Python parser for the
authoritative implementation, including the firmware function
mapping (`FUN_f4190f00`).

### Edit-mode lifecycle (v36)

The audit-log subsystem (Class 0x008E) is dormant after a fresh
Phase 1/2 handshake. The client has to arm it via a six-step bring-up
before mutating operations like program-delete will be accepted. From
`delete_program_from_MainTask_Full.pcapng`:

| # | Wrapper / Inner             | Path                                          | Body                                                    | Notes |
|---|------------------------------|-----------------------------------------------|---------------------------------------------------------|-------|
| 1 | **0x37** / 0x5C             | Class 0x008E inst 1                           | `98 00 00 00 00 00 00 00 <name_chars u16> <UTF-16LE>`   | Project / workstation path register. Returns CIP `0x06` BUSY in practice; the side effect of the call is what arms the state machine. **Must use 0x37 wrapper — 0x36 leaves the controller in a state where step 5 fails.** |
| 2 | 0x36 / **0x4B**             | Class 0x0378 inst 1                           | 16-byte header `01 03 00 00 82 00 00 00 03 00 01 00 01 00 00 00` + three UTF-16 counted strings (user, app, role) | Client registration; reply data = u32 session token. |
| 3 | 0x36 / **0x63**             | Class 0x008E inst 1                           | `<token u32 LE>`                                        | Session token bind / go-online. Pass `0x10` to go offline. |
| 4 | 0x36 / **0x04**             | Class 0x00AC inst 1                           | `<attr_cnt=1 u16><attr=0x0A u16><unix_ts u32>`          | SetAttrList — workstation clock. |
| 5 | 0x36 / **0x4B**             | Class 0x008E/1/Class 0x0074/1 (nested)        | full client certificate (same bytes as Phase 1)         | Claim **global** edit ownership. |
| 6 | 0x36 / **0x55**             | Class 0x008E inst 1                           | (empty)                                                 | Audit log open. Reply data = `<handle u32 LE>`; thread this back into the close call. |

Once step 6 succeeds, the audited-mutation surface is unlocked. A
typical delete then runs:

```
0x36 / 0x4B  Class 0x68/<prog>/0x74/1     claim per-program ownership (00 01)
GetAttrList   Class 0x00AC attr 1          read current edit sequence (u16)
0x36 / 0x4F  Class 0x00AC inst 1          begin txn: <seq u16><type=2 u16>
                                          reply tail has <allocated_id u16><02 00>
0x36 / 0x55  Class 0x008E inst 1          audit log open → handle (u32)
0x37 / 0x35  Class 0x008E inst 1          audit "Deleted Program [\<name>]"
0x36 / 0x09  Class 0x0068 inst <prog>     delete program (controller cascades
                                          all routines, tags, descriptions)
0x36 / 0x59  Class 0x008E inst 1          audit log close: <handle u32 LE>
                                          (BUSY 0x06 here is tolerated)
0x36 / 0x58  Class 0x008E inst 1          finalize (sent twice)
0x36 / 0x4F  Class 0x00AC inst 1          end txn: <allocated_id u16><02 00>
0x36 / 0x4C  Class 0x68/<prog>/0x74/1     release per-program ownership
0x36 / 0x4C  Class 0x008E/1/0x74/1        release global ownership
0x36 / 0x63  Class 0x008E inst 1          go offline (val = 0x10)
```

Studio in `delete_tasks.pcapng` follows the same skeleton but also
emits ~100 individual audits naming every routine and tag inside the
program before the cascading delete; those audits aren't required for
the delete to succeed (the single 0x09 cascades regardless), but they
populate the controller's audit log with per-child entries.

Per-program ownership (step `0x4B on 0x68/<prog>/0x74/1`) sometimes
returns CIP status `0x05` (path destination unknown) — observed
empirically. The delete still works; tolerate the 0x05 and proceed.

### Edit transaction (Class 0x00AC)

`begin` and `end` are both service `0x4F` on Class 0x00AC inst 1 with
body `[<seq u16><type u16>]`. Type is `1` on v21 controllers, `2` on
v36 (which adds the audit-log subsystem on top). The current `seq` is
exposed as attribute 1 (read via GetAttrList before begin). The begin
reply's tail carries the controller-allocated next id (`...<id u16>
<type u16>` at offset `len-4`); use that allocated id for end.

Request ids outside `[1, 0x7FFF]` are rejected with `0xFF` ext
`0x2104`; ids ≤ current `seq` return `0x06` partial-transfer with
`70 08 01 00 …` 32-byte records (one per pending uncommitted txn the
controller is willing to disclose).

### Validating HMACs in the dissector

Two preferences feed the HMAC validator; either is sufficient:

- `rockwell_cip.client_rsa_key_file` — path to the client's RSA
  private key in PEM or DER (PKCS#1) format. When set, the handshake
  module RSA-decrypts every Phase 1 challenge it sees on that stream
  and stashes `plaintext[0:64]` as the session key. No further input
  needed.
- `rockwell_cip.hmac_key` — 128 hex chars of the derived 64-byte
  session key. Use this when you've derived the key out-of-band (e.g.
  via `tools/derive_hmac_key.py`) or have a key from a session whose
  Phase 1 wasn't captured.

The dissector validates every 0x36/0xB6 (and 0x3A/0xBA) trailer using
the resolved key and reports OK/MISMATCH per frame. With neither
preference set, the trailer bytes are still decoded but no verdict is
emitted.

## Where this isn't enough

- Encrypted CIP (Rockwell roadmap, not seen in current captures) would
  break the plain-text payload assumption. The HMAC bytes would still
  be decodable but the inner CIP would need a key-log mechanism.
- Some classes (0x008D MessageParameters) carry attribute-3 values
  whose meaning depends on the message type (CIP Generic vs PCCC
  Typed Read vs Block Transfer). The dissector decodes the structure
  but won't name every variant without per-message-type tables.
