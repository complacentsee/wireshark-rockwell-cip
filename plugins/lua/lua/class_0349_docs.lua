-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- class_0349_docs.lua — Studio 5000 documentation blob (class 0x0349).
--
-- Service 0x53 on class 0x0349 (instance 0) returns the controller's
-- "description database" — every comment a user typed in Studio gets
-- baked into a record here. Records are concatenated in the reply body
-- (typically across many continuation packets); each record has one of
-- six header layouts identified by a class_marker u16 at +0 telling us
-- which kind of entity is being documented.
--
-- Layouts (see logix_fw/cip_upload/extract_logix_data.py for the
-- authoritative parser this dissector mirrors):
--
--   LAYOUT_36 (operand-bit comments on controller-scope tags):
--     +0   u16  class_marker (== target class id, e.g. 0x006B)
--     +2   u16  tag instance
--     +4..+9  zeros
--     +10  u16  bit_field  = 12334 + 256 * bit_number   (controls which
--                                                        bit of the tag
--                                                        this comment
--                                                        annotates)
--     +12  u16  0x007F     (marker)
--     +14  u16  0x0001     (marker)
--     +16  u16  ref_id     (sequential)
--     +18..+31 zeros
--     +32  u16  count       (1 = has text)
--     +34  u16  strlen
--     +36     string data
--
--   LAYOUT_38 (most other classes: 0x0068 programs, 0x006C templates,
--   0x0069 modules, 0x0338 AOIs, 0x0349 self-ref):
--     +0   u16  class_marker
--     +2   u16  instance
--     +4   u16  0x006D constant
--     +6   u16  routine inst / param index / member mid (varies)
--     +8   u16  RegionId low half  (0x0068 rungs only; else 0)
--     +10  u16  RegionId mid       (0x0068 rungs only; else 0)
--     +12  u16  0
--     +14  u16  0x007F
--     +16  u16  0x0001
--     +18  u16  ref_id
--     +20..+33 zeros
--     +34  u16  count
--     +36  u16  strlen
--     +38     string data
--
--   LAYOUT_OPSTR (class 0x006B):
--     +0..+11    class_marker / instance / 8 zero bytes
--     +12  u16   osl  (operand-string length, 1..64)
--     +14..+14+osl  operand bytes (ASCII)
--     +14+osl       remainder identical to LAYOUT_38, all positions
--                   shifted by +osl bytes (marker @ +14+osl,
--                   ref_id @ +18+osl, count @ +34+osl, strlen @ +36+osl,
--                   string data @ +38+osl).
--
--   LAYOUT_OPSTR_SHORT (class 0x006B; compact operand variant, osl >= 3):
--     +0..+7     class_marker / instance / 4 zero bytes
--     +8   u16   osl
--     +10..+10+osl  operand bytes
--     +10+osl       LAYOUT_36 fields shifted by +osl-2 (marker @
--                   +10+osl, ref_id @ +14+osl, count @ +30+osl,
--                   strlen @ +32+osl, string data @ +34+osl).
--
--   LAYOUT_36_SCOPED / LAYOUT_OPSTR_SCOPED (class 0x006B; operand on
--   program/AOI-scope tag): bytes +4..+25 carry an embedded CIP path
--     +4..+13       10 zero bytes
--     +14  u16      scope_class  (must be one of {0x0068, 0x0338, 0x0069})
--     +16  u16      scope_inst
--     +18  u16      target_class (must be 0x006B)
--     +20  u16      target_inst  (the actual tag inst this comment binds to)
--     +22..+25      4 zero bytes
--   then either the LAYOUT_36 tail (downstream offsets shift by +18) or
--   the LAYOUT_OPSTR tail (osl read at +26, operand at +28, marker at
--   +28+osl, downstream offsets shift by +14+osl relative to bare OPSTR).
--
-- The string body can be either raw UTF-8 or zlib-compressed when the
-- first two bytes are 0x8280 LE (the COMPRESSED_MARKER):
--     +str_off+0  u16  0x8280
--     +str_off+2  u16  decompressed size
--     +str_off+4  u16  0x0000 padding
--     +str_off+6  zlib stream  (length = strlen - 6)
-- The strlen field counts the whole compressed body (marker through
-- end-of-zlib).
--
-- ---- Multi-chunk reassembly (Phase C) ----
--
-- Each 0x53 reply carries a fixed-stride PAGE of the description blob:
--     [CIP reply header 4B] [request-echo 8B] [page_data ≤458B (v36)]
-- The Python parser strips the 8B echo and concatenates page_data from
-- every reply into one buffer, then walks records over the join — so
-- records routinely straddle the 458B chunk boundary. The dissector
-- mirrors that: per-conversation `session.docs_stream` carries the
-- accumulator (a Lua string), an ordered `chunks` list mapping each
-- frame's page_data slice to its byte range in the accumulator, and a
-- `frame_results` cache so `tshark -2`'s pass 2 replays without
-- re-ingesting (and so a frame's tree shows complete_in pointing at a
-- later frame where the spanning record finishes).
--
-- A frame whose page_data is entirely the tail of an in-progress record
-- ("continuation frame") emits a small `continuation = true` subtree
-- with `chunk_size` and `complete_in` instead of a records list. The
-- completion frame's records subtree includes the spanning record with
-- byte anchoring for whichever fields fall in the current frame's
-- page_data (fields whose bytes sit in earlier frames are emitted as
-- generated values without a tvb anchor — Wireshark Lua can't anchor
-- across frames).
--
-- Stream end is signalled implicitly by a short page (page_data length
-- < first_page_size), a zero-byte page, or v21's echo[1] == 0x02. After
-- close, the next 0x53/0x349 reply on the same conversation resets the
-- accumulator.

local M = {}

function M.register(proto, valstr, ctx)
    local inflate = require "inflate"
    local session = require "session"

    local f = {}
    f.records       = ProtoField.string("rockwell_cip.docs.records",
        "Description Records")
    f.record        = ProtoField.bytes("rockwell_cip.docs.record",
        "Record", base.SPACE)
    f.class_marker  = ProtoField.uint16("rockwell_cip.docs.class_marker",
        "Class Marker", base.HEX, valstr.doc_record_classes)
    f.instance      = ProtoField.uint16("rockwell_cip.docs.instance",
        "Instance", base.DEC)
    f.ref_id        = ProtoField.uint16("rockwell_cip.docs.ref_id",
        "Reference ID", base.DEC)
    f.routine_inst  = ProtoField.uint16("rockwell_cip.docs.routine_inst",
        "Routine / Param / Member Inst", base.DEC)
    f.bit_field     = ProtoField.uint16("rockwell_cip.docs.bit_field",
        "Bit Field (encoded)", base.HEX)
    f.bit_number    = ProtoField.int32("rockwell_cip.docs.bit_number",
        "Bit Number (decoded from bit_field)", base.DEC)
    f.count         = ProtoField.uint16("rockwell_cip.docs.count",
        "String Count", base.DEC)
    f.strlen        = ProtoField.uint16("rockwell_cip.docs.strlen",
        "String Length", base.DEC)
    f.text          = ProtoField.string("rockwell_cip.docs.text",
        "Text")
    f.compressed    = ProtoField.bool("rockwell_cip.docs.compressed",
        "Compressed (0x8280)")
    f.dec_size      = ProtoField.uint16("rockwell_cip.docs.dec_size",
        "Decompressed Size", base.DEC)
    f.layout        = ProtoField.string("rockwell_cip.docs.layout",
        "Layout")
    f.osl           = ProtoField.uint16("rockwell_cip.docs.osl",
        "Operand String Length", base.DEC)
    f.operand       = ProtoField.string("rockwell_cip.docs.operand",
        "Operand")
    f.scope_class   = ProtoField.uint16("rockwell_cip.docs.scope_class",
        "Scope Class", base.HEX, valstr.classes)
    f.scope_inst    = ProtoField.uint16("rockwell_cip.docs.scope_inst",
        "Scope Instance", base.DEC)
    f.target_class  = ProtoField.uint16("rockwell_cip.docs.target_class",
        "Target Class", base.HEX, valstr.classes)
    f.target_inst   = ProtoField.uint16("rockwell_cip.docs.target_inst",
        "Target Instance", base.DEC)
    f.records_count = ProtoField.uint32("rockwell_cip.docs.records_count",
        "Record Count", base.DEC)
    f.records_skipped = ProtoField.uint32(
        "rockwell_cip.docs.records_skipped",
        "Records Skipped (unparsed layout)", base.DEC)
    -- Reassembly fields. continuation marks a frame whose page_data is
    -- entirely the tail of an in-progress record; chunk_size is that
    -- frame's contribution in bytes; complete_in points at the frame
    -- where the record finishes; chunks_in / first_chunk are emitted on
    -- the completion side and answer "how many frames did this record
    -- span / where did it start".
    f.continuation  = ProtoField.bool("rockwell_cip.docs.continuation",
        "Continuation chunk (no record completes here)")
    f.chunk_size    = ProtoField.uint32("rockwell_cip.docs.chunk_size",
        "Continuation Chunk Size (bytes)", base.DEC)
    f.complete_in   = ProtoField.framenum("rockwell_cip.docs.complete_in",
        "Spanning record completes in", base.NONE, frametype.NONE)
    f.chunks_in     = ProtoField.uint32("rockwell_cip.docs.chunks_in",
        "Chunks spanned by this record", base.DEC)
    f.first_chunk   = ProtoField.framenum("rockwell_cip.docs.first_chunk",
        "Spanning record began in", base.NONE, frametype.NONE)
    -- request_in on the reply works fine; the inverse (response_in on
    -- the request) would require mutating the request frame's tree
    -- after the reply has been seen, which Wireshark's Lua post-
    -- dissector model doesn't support — pass 1 of -2 doesn't expose
    -- fields to Lua, and pass 2 walks frames in order. Users can
    -- pivot request -> reply via the already-populated enip.response_in.
    f.request_in    = ProtoField.framenum("rockwell_cip.docs.request_in",
        "Request In", base.NONE, frametype.REQUEST)

    for _, fld in pairs(f) do ctx.add_field(fld) end

    local expert_compressed = ProtoExpert.new(
        "rockwell_cip.docs.compressed_record",
        "Record body is zlib-compressed (marker 0x8280)",
        expert.group.PROTOCOL, expert.severity.NOTE)
    local expert_unsupported = ProtoExpert.new(
        "rockwell_cip.docs.unsupported_layout",
        "Record layout not yet decoded (OPSTR / SCOPED variant)",
        expert.group.PROTOCOL, expert.severity.NOTE)
    local expert_stream_residue = ProtoExpert.new(
        "rockwell_cip.docs.stream_residue",
        "Stream closed with residual partial-record bytes in the accumulator",
        expert.group.MALFORMED, expert.severity.WARN)
    ctx.add_expert(expert_compressed)
    ctx.add_expert(expert_unsupported)
    ctx.add_expert(expert_stream_residue)

    -- Per-class allow-list of candidate layouts. Mirrors LAYOUTS in
    -- extract_logix_data.py — order matters: more-specific layouts are
    -- tried first so a shorter form doesn't false-match a longer
    -- record's prefix.
    local LAYOUTS_BY_CLASS = {
        [0x0068] = {"LAYOUT_38"},
        [0x0069] = {"LAYOUT_38"},
        [0x006C] = {"LAYOUT_38"},
        [0x0338] = {"LAYOUT_38"},
        [0x0349] = {"LAYOUT_38"},
        [0x006B] = {
            "LAYOUT_OPSTR_SCOPED",
            "LAYOUT_36_SCOPED",
            "LAYOUT_OPSTR",
            "LAYOUT_OPSTR_SHORT",
            "LAYOUT_38",
            "LAYOUT_36",
        },
    }

    -- Scope-class values that pass the SCOPED-layout validator. Mirrors
    -- SCOPE_CLASSES in extract_logix_data.py.
    local SCOPE_CLASSES = {
        [0x0068] = true, [0x0338] = true, [0x0069] = true,
    }

    local MARKER_7F     = 0x007F
    -- NB: the 0x0001 word that follows the 0x007F marker in the
    -- LAYOUT_36 / LAYOUT_38 docstrings is *not* a constant in practice
    -- — for class 0x0349 self-ref records +16 is actually a sequential
    -- per-record id (0x0008, 0x0009, ...) and the 0x0001 sits at +18.
    -- We mirror the Python parser, which validates only the 0x007F
    -- marker + count + strlen + body-printability. Tightening the
    -- match with a second word check would silently drop real records.
    local TARGET_SCOPED = 0x006B

    local OPERAND_BIT_BASE   = valstr.operand_bit_base
    local OPERAND_BIT_STRIDE = valstr.operand_bit_stride

    -- Derived from LAYOUTS_BY_CLASS so adding a class to the allow-list
    -- doesn't require a second update here.
    local DOC_CLASSES = {}
    for k, _ in pairs(LAYOUTS_BY_CLASS) do DOC_CLASSES[k] = true end

    -- Pure-string byte helpers. The walker operates on the conv's
    -- accumulator (a Lua string built by concatenating page_data of
    -- each reply), so it has to read bytes by index rather than by tvb
    -- range. `pos` is 0-based to match the layout docstrings above;
    -- string.byte's 1-based indexing is hidden behind these helpers.
    local function s_byte(s, pos)
        return string.byte(s, pos + 1)
    end

    local function s_u16_le(s, pos)
        return string.byte(s, pos + 1)
             | (string.byte(s, pos + 2) << 8)
    end

    local function s_bytes_all_zero(s, pos, len)
        for i = 0, len - 1 do
            if string.byte(s, pos + i + 1) ~= 0 then return false end
        end
        return true
    end

    local function s_ascii_printable(s, pos, len)
        if len <= 0 then return false end
        for i = 0, len - 1 do
            local c = string.byte(s, pos + i + 1)
            if c < 0x20 or c > 0x7E then return false end
        end
        return true
    end

    local function s_substr(s, pos, len)
        return string.sub(s, pos + 1, pos + len)
    end

    -- Decode the bit_field word at +10 (or shifted equivalent) into a
    -- concrete bit number, returning -1 if it doesn't decode as one.
    local function decode_bit_number(bit_field)
        if bit_field >= OPERAND_BIT_BASE
            and (bit_field - OPERAND_BIT_BASE)
                % OPERAND_BIT_STRIDE == 0 then
            return (bit_field - OPERAND_BIT_BASE) // OPERAND_BIT_STRIDE
        end
        return -1
    end

    -- Tristate return from each try_layout_* / try_record:
    --   * (number consumed, rec, layout)  → validated record at pos
    --   * "short"                         → structurally plausible but
    --                                       bytes [pos..] are partial
    --                                       (real in-progress record)
    --   * nil                             → structural validation
    --                                       failed (garbage at pos)
    -- The "short" path is what lets the multi-chunk walker stop at the
    -- correct boundary instead of sliding through an incomplete record
    -- start and losing it. rec_table carries the per-field offsets the
    -- renderer reads below, so it never has to recompute them from the
    -- layout name.

    local function try_layout_36(s, pos, slen)
        -- Progressive validation: check structural fields as soon as
        -- their bytes are in. A failure short-circuits to nil (garbage
        -- at pos). Only return "short" when no structural mismatch has
        -- been found AND header/body bytes are still partial.
        if pos + 14 > slen then return "short" end
        if s_u16_le(s, pos + 12) ~= MARKER_7F then return nil end
        if pos + 34 > slen then return "short" end
        local count  = s_u16_le(s, pos + 32)
        if count ~= 1 then return nil end
        if pos + 36 > slen then return "short" end
        local strlen = s_u16_le(s, pos + 34)
        if strlen <= 0 or strlen >= 8192 then return nil end
        if pos + 36 + strlen > slen then return "short" end
        local bit_field = s_u16_le(s, pos + 10)
        return 36 + strlen, {
            class_marker  = s_u16_le(s, pos),
            instance      = s_u16_le(s, pos + 2),
            bit_field     = bit_field,
            bit_number    = decode_bit_number(bit_field),
            bit_field_off = 10,
            ref_id_off    = 16,
            count_off     = 32,
            strlen_off    = 34,
            str_off       = 36,
            strlen        = strlen,
            ref_id        = s_u16_le(s, pos + 16),
            count         = count,
        }, "LAYOUT_36"
    end

    local function try_layout_38(s, pos, slen)
        if pos + 16 > slen then return "short" end
        if s_u16_le(s, pos + 14) ~= MARKER_7F then return nil end
        if pos + 36 > slen then return "short" end
        local count  = s_u16_le(s, pos + 34)
        if count ~= 1 then return nil end
        if pos + 38 > slen then return "short" end
        local strlen = s_u16_le(s, pos + 36)
        if strlen <= 0 or strlen >= 8192 then return nil end
        if pos + 38 + strlen > slen then return "short" end
        return 38 + strlen, {
            class_marker = s_u16_le(s, pos),
            instance     = s_u16_le(s, pos + 2),
            sub_inst     = s_u16_le(s, pos + 6),
            sub_inst_off = 6,
            ref_id_off   = 18,
            count_off    = 34,
            strlen_off   = 36,
            str_off      = 38,
            strlen       = strlen,
            ref_id       = s_u16_le(s, pos + 18),
            count        = count,
        }, "LAYOUT_38"
    end

    local function try_layout_opstr(s, pos, slen)
        -- 8 zero bytes at +4..+11, u16 osl at +12, operand at +14.
        if pos + 12 > slen then return "short" end
        if not s_bytes_all_zero(s, pos + 4, 8) then return nil end
        if pos + 14 > slen then return "short" end
        local osl = s_u16_le(s, pos + 12)
        if osl < 1 or osl > 64 then return nil end
        local m_off   = 14 + osl
        local ct_off  = 34 + osl
        local sl_off  = 36 + osl
        local str_off = 38 + osl
        if pos + m_off + 2 > slen then return "short" end
        if s_u16_le(s, pos + m_off) ~= MARKER_7F then return nil end
        if not s_ascii_printable(s, pos + 14, osl) then return nil end
        if pos + ct_off + 2 > slen then return "short" end
        local count  = s_u16_le(s, pos + ct_off)
        if count ~= 1 then return nil end
        if pos + sl_off + 2 > slen then return "short" end
        local strlen = s_u16_le(s, pos + sl_off)
        if strlen <= 0 or strlen >= 8192 then return nil end
        if pos + str_off + strlen > slen then return "short" end
        return str_off + strlen, {
            class_marker = s_u16_le(s, pos),
            instance     = s_u16_le(s, pos + 2),
            osl          = osl,
            osl_off      = 12,
            operand      = s_substr(s, pos + 14, osl),
            operand_off  = 14,
            ref_id_off   = m_off + 4,
            count_off    = ct_off,
            strlen_off   = sl_off,
            str_off      = str_off,
            strlen       = strlen,
            ref_id       = s_u16_le(s, pos + m_off + 4),
            count        = count,
        }, "LAYOUT_OPSTR"
    end

    local function try_layout_opstr_short(s, pos, slen)
        -- 4 zero bytes at +4..+7, u16 osl at +8, operand at +10. osl
        -- must be >= 3; osl <= 2 collides with LAYOUT_36's marker
        -- position and is the LAYOUT_36 bit_field decode's
        -- responsibility (the Python parser handles it that way).
        if pos + 8 > slen then return "short" end
        if not s_bytes_all_zero(s, pos + 4, 4) then return nil end
        if pos + 10 > slen then return "short" end
        local osl = s_u16_le(s, pos + 8)
        if osl < 3 or osl > 64 then return nil end
        local m_off   = 10 + osl
        local ct_off  = 30 + osl
        local sl_off  = 32 + osl
        local str_off = 34 + osl
        if pos + m_off + 2 > slen then return "short" end
        if s_u16_le(s, pos + m_off) ~= MARKER_7F then return nil end
        if not s_ascii_printable(s, pos + 10, osl) then return nil end
        if pos + ct_off + 2 > slen then return "short" end
        local count  = s_u16_le(s, pos + ct_off)
        if count ~= 1 then return nil end
        if pos + sl_off + 2 > slen then return "short" end
        local strlen = s_u16_le(s, pos + sl_off)
        if strlen <= 0 or strlen >= 8192 then return nil end
        if pos + str_off + strlen > slen then return "short" end
        return str_off + strlen, {
            class_marker = s_u16_le(s, pos),
            instance     = s_u16_le(s, pos + 2),
            osl          = osl,
            osl_off      = 8,
            operand      = s_substr(s, pos + 10, osl),
            operand_off  = 10,
            ref_id_off   = m_off + 4,
            count_off    = ct_off,
            strlen_off   = sl_off,
            str_off      = str_off,
            strlen       = strlen,
            ref_id       = s_u16_le(s, pos + m_off + 4),
            count        = count,
        }, "LAYOUT_OPSTR_SHORT"
    end

    -- read_scope returns the scope table on structural validation,
    -- nil on validation failure, or "short" when the 22-byte scope
    -- path bytes aren't fully in yet. Callers propagate the "short"
    -- outcome.
    local function read_scope_tristate(s, pos, slen)
        if pos + 26 > slen then return "short" end
        if not s_bytes_all_zero(s, pos + 4, 10) then return nil end
        local scope_class = s_u16_le(s, pos + 14)
        if not SCOPE_CLASSES[scope_class] then return nil end
        local target_class = s_u16_le(s, pos + 18)
        if target_class ~= TARGET_SCOPED then return nil end
        if not s_bytes_all_zero(s, pos + 22, 4) then return nil end
        return {
            scope_class  = scope_class,
            scope_inst   = s_u16_le(s, pos + 16),
            target_class = target_class,
            target_inst  = s_u16_le(s, pos + 20),
        }
    end

    local function try_layout_36_scoped(s, pos, slen)
        local scope = read_scope_tristate(s, pos, slen)
        if scope == "short" then return "short" end
        if not scope then return nil end
        -- LAYOUT_36 fields shifted by +18 (the embedded scope path
        -- occupies +4..+25, of which the first 6 bytes overlap the
        -- 6-zero pad LAYOUT_36 already had at +4..+9 — net shift +18).
        local bit_field_off = 28  -- 10 + 18
        local m_off         = 30  -- 12 + 18
        local ref_id_off    = 34  -- 16 + 18
        local count_off     = 50  -- 32 + 18
        local sl_off        = 52  -- 34 + 18
        local str_off       = 54  -- 36 + 18
        if pos + m_off + 2 > slen then return "short" end
        if s_u16_le(s, pos + m_off) ~= MARKER_7F then return nil end
        if pos + count_off + 2 > slen then return "short" end
        local count  = s_u16_le(s, pos + count_off)
        if count ~= 1 then return nil end
        if pos + sl_off + 2 > slen then return "short" end
        local strlen = s_u16_le(s, pos + sl_off)
        if strlen <= 0 or strlen >= 8192 then return nil end
        if pos + str_off + strlen > slen then return "short" end
        local bit_field = s_u16_le(s, pos + bit_field_off)
        return str_off + strlen, {
            class_marker  = s_u16_le(s, pos),
            instance      = s_u16_le(s, pos + 2),
            scope         = scope,
            bit_field     = bit_field,
            bit_number    = decode_bit_number(bit_field),
            bit_field_off = bit_field_off,
            ref_id_off    = ref_id_off,
            count_off     = count_off,
            strlen_off    = sl_off,
            str_off       = str_off,
            strlen        = strlen,
            ref_id        = s_u16_le(s, pos + ref_id_off),
            count         = count,
        }, "LAYOUT_36_SCOPED"
    end

    local function try_layout_opstr_scoped(s, pos, slen)
        local scope = read_scope_tristate(s, pos, slen)
        if scope == "short" then return "short" end
        if not scope then return nil end
        if pos + 28 > slen then return "short" end
        -- OPSTR tail starts at +26 (osl) / +28 (operand). Marker at
        -- +28+osl, then LAYOUT_38-like trailer shifted by +14+osl
        -- relative to bare LAYOUT_OPSTR.
        local osl = s_u16_le(s, pos + 26)
        if osl < 1 or osl > 64 then return nil end
        local m_off   = 28 + osl
        local ct_off  = 48 + osl
        local sl_off  = 50 + osl
        local str_off = 52 + osl
        if pos + m_off + 2 > slen then return "short" end
        if s_u16_le(s, pos + m_off) ~= MARKER_7F then return nil end
        if not s_ascii_printable(s, pos + 28, osl) then return nil end
        if pos + ct_off + 2 > slen then return "short" end
        local count  = s_u16_le(s, pos + ct_off)
        if count ~= 1 then return nil end
        if pos + sl_off + 2 > slen then return "short" end
        local strlen = s_u16_le(s, pos + sl_off)
        if strlen <= 0 or strlen >= 8192 then return nil end
        if pos + str_off + strlen > slen then return "short" end
        return str_off + strlen, {
            class_marker = s_u16_le(s, pos),
            instance     = s_u16_le(s, pos + 2),
            scope        = scope,
            osl          = osl,
            osl_off      = 26,
            operand      = s_substr(s, pos + 28, osl),
            operand_off  = 28,
            ref_id_off   = m_off + 4,
            count_off    = ct_off,
            strlen_off   = sl_off,
            str_off      = str_off,
            strlen       = strlen,
            ref_id       = s_u16_le(s, pos + m_off + 4),
            count        = count,
        }, "LAYOUT_OPSTR_SCOPED"
    end

    local LAYOUT_TRY_FNS = {
        LAYOUT_36           = try_layout_36,
        LAYOUT_38           = try_layout_38,
        LAYOUT_OPSTR        = try_layout_opstr,
        LAYOUT_OPSTR_SHORT  = try_layout_opstr_short,
        LAYOUT_36_SCOPED    = try_layout_36_scoped,
        LAYOUT_OPSTR_SCOPED = try_layout_opstr_scoped,
    }

    local function try_record(s, pos, slen)
        if pos + 2 > slen then return "short" end
        local cm = s_u16_le(s, pos)
        local allowed = LAYOUTS_BY_CLASS[cm]
        if not allowed then return nil end
        local any_short = false
        for _, name in ipairs(allowed) do
            local r1, rec, layout = LAYOUT_TRY_FNS[name](s, pos, slen)
            if r1 == "short" then
                any_short = true
            elseif r1 then
                return r1, rec, layout
            end
        end
        if any_short then return "short" end
        return nil
    end

    -- Decode the record's text body straight from the accumulator. The
    -- whole record is in the accumulator by definition (we only mark a
    -- record "complete" once we've seen its last byte). Returns
    -- (text, compressed_bool, dec_size_or_nil) or (nil, false) when the
    -- bounds check fails.
    local function decode_text(accum, rec_pos, rec, slen)
        if rec.strlen == 0 then return "", false end
        local off = rec_pos + rec.str_off
        if off + rec.strlen > slen then return nil, false end
        local body_bytes = s_substr(accum, off, rec.strlen)
        if rec.strlen >= 6 and
           string.byte(body_bytes, 1) == 0x80 and
           string.byte(body_bytes, 2) == 0x82 then
            -- 0x8280 LE = compressed marker. body: [marker u16 LE]
            -- [dec_size u16 LE] [pad u16 LE] [zlib_stream]
            local dec_size = string.byte(body_bytes, 3)
                           | (string.byte(body_bytes, 4) << 8)
            local zlib_stream = body_bytes:sub(7)
            local ok, txt = pcall(inflate.inflate, zlib_stream)
            if ok then
                return txt, true, dec_size
            end
            return "(zlib inflate error)", true, dec_size
        end
        return body_bytes, false
    end

    -- chunks[] index containing accumulator byte `pos` (0-based, end-
    -- exclusive). Linear scan — chunks is ordered and small (hundreds
    -- of frames in the worst observed capture).
    local function chunk_idx_for_pos(chunks, pos)
        for i = #chunks, 1, -1 do
            if chunks[i].accum_off <= pos then return i end
        end
        return nil
    end

    -- Append a chunk to the docs_stream accumulator and walk newly-
    -- completable records from `walk_pos` forward. Updates per-frame
    -- results (current frame + retroactive complete_in / chunks_in on
    -- prior frames whose in-progress records finish here).
    local function ingest_chunk(stream, frame, page_data, page_size_for_close_check)
        local chunk_idx = #stream.chunks + 1
        local chunk = {
            frame     = frame,
            accum_off = #stream.accumulator,
            page_size = #page_data,
        }
        stream.chunks[chunk_idx] = chunk
        stream.accumulator = stream.accumulator .. page_data
        local accum = stream.accumulator
        local slen = #accum

        -- Walk forward over [walk_pos..slen). For each pos:
        --   * try_record returns "short" → bytes [pos..slen) are a
        --     structurally plausible record header whose body isn't
        --     fully in yet. Stop walking; the next chunk's append will
        --     extend the accumulator and we'll resume from `pos`.
        --   * try_record returns a number → record validated; advance.
        --   * try_record returns nil → garbage at pos. If pos's u16
        --     happens to be a known DOC_CLASS, count it as a skipped
        --     record (attribute-value records with count != 1 land
        --     here; the Python parser also ignores them) — attributed
        --     to whichever chunk's byte range covers `pos`. Slide by 1
        --     to resync.
        --
        -- Walks can span chunk boundaries: walk_pos at frame entry may
        -- point into a prior chunk's tail (left over from "short" the
        -- last time around). Stats get attributed per-chunk so a frame
        -- that's actually a true continuation (no records start here,
        -- no skips happen here) is classified as such even when a
        -- skip-heavy later walk passes through bytes in earlier chunks.
        local per_chunk_records = {}   -- chunk_idx -> [completed records]
        local per_chunk_skipped = {}   -- chunk_idx -> skip count
        local function add_record(idx, c)
            per_chunk_records[idx] = per_chunk_records[idx] or {}
            local list = per_chunk_records[idx]
            list[#list + 1] = c
        end
        local function bump_skip(idx)
            per_chunk_skipped[idx] = (per_chunk_skipped[idx] or 0) + 1
        end

        local pos = stream.walk_pos
        local max_records = 4096  -- guardrail
        local total = 0
        while pos < slen and total < max_records do
            local r1, rec, layout = try_record(accum, pos, slen)
            if r1 == "short" then
                break
            elseif r1 then
                local first_idx = chunk_idx_for_pos(stream.chunks, pos)
                                  or chunk_idx
                local last_idx  = chunk_idx_for_pos(stream.chunks,
                                                    pos + r1 - 1)
                                  or chunk_idx
                local completion_chunk = stream.chunks[last_idx]
                -- Cache decoded text + per-completion-chunk relative
                -- offset NOW, while we still have the full record in
                -- the accumulator. The accumulator can be reset later
                -- (carved-fixture gap detection) so the cached record
                -- must not refer back to it.
                local text, compressed, dec_size =
                    decode_text(accum, pos, rec, slen)
                local c = {
                    -- pos relative to the completion chunk's page_data
                    -- (negative if the record starts in an earlier
                    -- chunk; the renderer clamps).
                    rec_off_in_page  = pos - completion_chunk.accum_off,
                    rec_len          = r1,
                    layout           = layout,
                    rec              = rec,
                    first_chunk_frame = stream.chunks[first_idx].frame,
                    chunks_in        = last_idx - first_idx + 1,
                    text             = text,
                    compressed       = compressed,
                    dec_size         = dec_size,
                }
                add_record(last_idx, c)
                -- Retroactively annotate prior chunks' results: they
                -- were previously emitted with continuation=true,
                -- complete_in=nil; now we know the answer.
                for j = first_idx, last_idx - 1 do
                    local prior = stream.frame_results[
                                      stream.chunks[j].frame]
                    if prior then
                        prior.complete_in = stream.chunks[last_idx].frame
                    end
                end
                pos = pos + r1
                total = total + 1
            else
                if pos + 2 <= slen then
                    local cm = s_u16_le(accum, pos)
                    if DOC_CLASSES[cm] then
                        local target_idx =
                            chunk_idx_for_pos(stream.chunks, pos)
                            or chunk_idx
                        bump_skip(target_idx)
                        -- Retroactively bump prior chunks' counters
                        -- too (current chunk's result is built below).
                        if target_idx ~= chunk_idx then
                            local prior = stream.frame_results[
                                              stream.chunks[target_idx].frame]
                            if prior then
                                prior.records_skipped =
                                    (prior.records_skipped or 0) + 1
                                prior.continuation = false
                            end
                        end
                    end
                end
                pos = pos + 1
            end
        end

        stream.walk_pos = pos

        -- Detect a partial-record tail. If walk_pos < slen, then the
        -- bytes [walk_pos..slen) belong to an in-progress record that
        -- will be completed by a future chunk's append.
        local has_tail = stream.walk_pos < slen

        -- Build the current frame's render result. A frame is a "pure
        -- continuation" when no record completes here AND no DOC_CLASS
        -- bytes were skipped within its page_data range — so its
        -- payload is entirely the tail of an in-progress record that
        -- started earlier.
        local local_records = per_chunk_records[chunk_idx] or {}
        local local_skipped = per_chunk_skipped[chunk_idx] or 0
        local result = {
            chunk_idx       = chunk_idx,
            records         = local_records,
            records_skipped = local_skipped,
            continuation    = (#local_records == 0 and local_skipped == 0),
            chunk_size      = #page_data,
            complete_in     = nil,    -- filled retroactively by future ingests
            tail_after      = has_tail,
        }
        stream.frame_results[frame] = result

        -- If this chunk's page_size is shorter than the first page's
        -- (or zero, or v21 echo[1]=0x02), the stream is finished.
        if stream.first_page_size and page_size_for_close_check < stream.first_page_size then
            stream.closed = true
        end

        return result
    end

    local field_cip_service = Field.new("cip.service")
    local field_cip_epath   = Field.new("cip.epath")
    local field_cip_connid  = Field.new("cip.connid")
    -- cip.request_frame is a generated field the stock cip dissector
    -- emits on replies when conversation tracking succeeds. Optional —
    -- not present in older builds — so guard with pcall.
    local ok_rf, field_cip_request_frame = pcall(Field.new, "cip.request_frame")
    if not ok_rf then field_cip_request_frame = nil end

    -- 16-bit class segment for class 0x349: 21 00 49 03 (LE).
    local CLASS_0349_PATH = "\x21\x00\x49\x03"

    local function path_targets_0349(epath_fi)
        if not epath_fi or not epath_fi.range then return false end
        local raw = epath_fi.range:bytes():raw()
        return string.find(raw, CLASS_0349_PATH, 1, true) ~= nil
    end

    -- In a signed-CIP frame the stock cip dissector emits TWO
    -- cip.epath fields (outer Message Router path, then the recursed
    -- inner CIP's path). Field()() returns just the first one, so
    -- iterate over all instances and accept a match anywhere.
    local function any_epath_targets_0349()
        for _, fi in ipairs({field_cip_epath()}) do
            if path_targets_0349(fi) then return true end
        end
        return false
    end

    local function get_signed_seq(pinfo)
        local s = pinfo.private["rockwell_cip.signed.seq"]
        if not s then return nil end
        return tonumber(s)
    end

    local function get_cip_request_frame()
        if not field_cip_request_frame then return nil end
        local fi = field_cip_request_frame()
        return fi and fi.value or nil
    end

    -- Render one record's subtree under `parent`. `page_tvb_range` is
    -- the current frame's page_data tvb range, `page_len` its length.
    -- `c.rec_off_in_page` is the record's first-byte offset within
    -- this page (negative when the record started in an earlier
    -- frame); fields whose bytes fall outside [0, page_len) are
    -- emitted as generated values without a byte anchor (Wireshark
    -- Lua can't anchor a ProtoField to a different frame's tvb).
    local function render_record(parent, c, page_tvb_range, page_len)
        local rec = c.rec
        local layout = c.layout
        local rec_off = c.rec_off_in_page
        local rec_len = c.rec_len

        local function anchor(field_rel_off, field_len)
            local foff = rec_off + field_rel_off
            if foff >= 0 and foff + field_len <= page_len then
                return page_tvb_range(foff, field_len)
            end
            return nil
        end

        local function add_le_u16(tree, field, field_off, raw_value)
            local r = anchor(field_off, 2)
            if r then
                tree:add_le(field, r)
            else
                tree:add(field, raw_value):set_generated()
            end
        end

        -- f.record carries the record's whole-byte span. Anchor to
        -- whichever portion of the record lies in this frame —
        -- typically the tail end for a spanning record.
        local visible_start = math.max(0, rec_off)
        local visible_end   = math.min(page_len, rec_off + rec_len)
        local rt
        if visible_end > visible_start then
            rt = parent:add(f.record,
                page_tvb_range(visible_start,
                               visible_end - visible_start))
        else
            rt = parent:add(f.record, ""):set_generated()
        end

        add_le_u16(rt, f.class_marker, 0, rec.class_marker)
        rt:add(f.layout, layout):set_generated()
        add_le_u16(rt, f.instance, 2, rec.instance)
        if rec.scope then
            add_le_u16(rt, f.scope_class,  14, rec.scope.scope_class)
            add_le_u16(rt, f.scope_inst,   16, rec.scope.scope_inst)
            add_le_u16(rt, f.target_class, 18, rec.scope.target_class)
            add_le_u16(rt, f.target_inst,  20, rec.scope.target_inst)
        end
        if rec.osl then
            add_le_u16(rt, f.osl, rec.osl_off, rec.osl)
            local rng = anchor(rec.operand_off, rec.osl)
            if rng then
                rt:add(f.operand, rng, rec.operand)
            else
                rt:add(f.operand, rec.operand):set_generated()
            end
        end
        if rec.bit_field then
            add_le_u16(rt, f.bit_field, rec.bit_field_off, rec.bit_field)
            if rec.bit_number >= 0 then
                rt:add(f.bit_number, rec.bit_number):set_generated()
            end
        end
        if rec.sub_inst_off then
            add_le_u16(rt, f.routine_inst, rec.sub_inst_off, rec.sub_inst)
        end
        add_le_u16(rt, f.ref_id, rec.ref_id_off, rec.ref_id)
        add_le_u16(rt, f.count,  rec.count_off,  rec.count)
        add_le_u16(rt, f.strlen, rec.strlen_off, rec.strlen)

        if c.compressed then
            rt:add(f.compressed, true):set_generated()
            if c.dec_size then
                rt:add(f.dec_size, c.dec_size):set_generated()
            end
            rt:add_proto_expert_info(expert_compressed)
        end
        if c.text then rt:add(f.text, c.text):set_generated() end

        if c.chunks_in and c.chunks_in > 1 then
            rt:add(f.chunks_in, c.chunks_in):set_generated()
            rt:add(f.first_chunk, c.first_chunk_frame):set_generated()
        end
    end

    local function dissect(tvb, pinfo, tree)
        -- The reply to a class-0x349 read carries no epath of its own,
        -- so we can't self-identify it from the reply bytes. Instead we
        -- track requests (which DO carry the 21 00 49 03 class segment
        -- on cip.epath) and pair them to replies on the same
        -- conversation by signed-CIP seq (preferred) or the stock cip
        -- dissector's conversation tracking (fallback).
        -- field_cip_service() returns the FIRST cip.service instance.
        -- On a signed frame that's the outer 0x36/0xB6 wrapper service;
        -- its range:offset() is in the original frame buffer (which is
        -- what we want, since FieldInfo offsets for fields emitted by
        -- the recursed inner cip dissection are relative to a synthetic
        -- sub-tvb and aren't directly usable here). The outer 0x36/0xB6
        -- and inner 0x53/0xD3 services happen to share directionality
        -- (request services are < 0x80, replies >= 0x80), so the same
        -- svc < 0x80 check works for both signed and non-signed frames.
        local svc_fi = field_cip_service()
        if not svc_fi then return end
        local svc = svc_fi.value

        local seq = get_signed_seq(pinfo)

        if svc < 0x80 then
            -- Request frame. Remember it if it targets class 0x349 so
            -- the eventual reply can be paired to it. We don't annotate
            -- the request frame's tree (see the response_in comment
            -- above the ProtoField declarations).
            if not any_epath_targets_0349() then return end
            session.record_request(pinfo, seq, 0x349)
            return
        end

        -- Reply frame. Pair to its request.
        local req = session.lookup_request(pinfo, seq, get_cip_request_frame())
        if not req or req.class ~= 0x349 then return end
        req.reply_frame = pinfo.number

        local svc_range = svc_fi.range
        if not svc_range then return end
        local cip_start = svc_range:offset()
        local cip_tvb = tvb:range(cip_start)
        -- Reply skeleton: svc(1) rsv(1) gen(1) ext_size(1) body...
        -- On a signed frame Field.new("cip.service") returns the OUTER
        -- 0xB6 service — stock CIP emits cip.service for unknown codes
        -- like 0x36/0xB6 too. cip_tvb(4, ...) therefore skips the
        -- outer 4B header. On a signed frame the body that remains is
        -- [inner CIP header 4B][echo 8B][page_data ...][seq 4B][hmac 20B];
        -- on a non-signed reply (svc 0xD3 directly) it's [echo 8B][page_data ...].
        -- We trim the seq+HMAC trailer on signed, then skip a per-frame
        -- pre-page header (12B signed, 8B non-signed) to reach
        -- page_data — the bytes the Python parser concatenates into
        -- its desc buffer (extract_logix_data.py:1136, ECHO_SIZE=8).
        local cip_end = cip_tvb:len()
        if seq ~= nil then cip_end = cip_end - 24 end
        if cip_end < 4 then return end
        local body = cip_tvb(4, cip_end - 4)
        local body_len = body:len()

        local pre_page = (seq ~= nil) and 12 or 8

        -- v21 close-of-stream marker lives in echo byte[1]. Echo starts
        -- at body[4] on signed frames (after the inner CIP header) and
        -- at body[0] on non-signed. byte[1] of echo is at body[5] /
        -- body[1] respectively.
        local echo_byte_1_off = (seq ~= nil) and 5 or 1
        local close_v21 = (body_len >= echo_byte_1_off + 1
                           and body(echo_byte_1_off, 1):uint() == 0x02)

        local page_tvb_range, page_data
        if body_len > pre_page then
            page_tvb_range = body(pre_page, body_len - pre_page)
            page_data      = page_tvb_range:bytes():raw()
        else
            page_data = ""
        end

        -- Echo of the request's offset field — bytes 4..7 of the echo,
        -- which sits at body[4..11] on signed frames and body[0..7] on
        -- non-signed. The offset is a u32 LE "byte offset into the
        -- description blob this page represents", driven by the client.
        -- When consecutive replies on a conv have offsets that don't
        -- advance by exactly one page, the carved fixture (or a
        -- packet-loss scenario) is missing intermediate pages — the
        -- accumulator's record-spanning math would corrupt records
        -- that straddle the gap. Reset on mismatch.
        local echo_off_base = (seq ~= nil) and 8 or 4
        local req_offset = (body_len >= echo_off_base + 4)
            and body(echo_off_base, 4):le_uint() or nil

        -- Cache check: pass 2 of `tshark -2` re-enters every frame
        -- after pass 1 already ingested it; replay rather than
        -- re-ingest. Same path also covers the case where we're called
        -- on a frame whose stream was reset (closed flag tripped) since
        -- the prior frame_results entry is still valid.
        --
        -- Stream lookup is keyed by cip.connid so two concurrent CIP
        -- connections on the same TCP stream each get their own
        -- accumulator; splicing their pages into one buffer would
        -- corrupt cross-page record assembly at the boundary.
        local connid_fi = field_cip_connid()
        local connid    = connid_fi and connid_fi.value
        local stream = session.docs_stream_get(pinfo, connid)
        local cached = stream and stream.frame_results[pinfo.number]

        if not cached then
            -- Special case: a reply whose body carries nothing beyond
            -- the CIP header + echo (no page_data) AND no stream is in
            -- flight on this conversation is a self-contained "zero
            -- records" reply (the docs_blob fixture). Render it as
            -- records_count=0 without engaging the chunk-assembly
            -- state machine; otherwise it would render as a
            -- "continuation chunk with chunk_size=0" which is
            -- semantically misleading.
            local fresh_zero = (#page_data == 0)
                               and (not stream or stream.closed)
            if not fresh_zero then
                if not stream or stream.closed then
                    stream = session.docs_stream_open(pinfo, connid)
                end
                -- Carved-fixture gap detection: if this reply's echoed
                -- request offset is not exactly first_page_size past
                -- the prior reply's offset, we've lost intermediate
                -- pages; reset the accumulator. (The full-capture path
                -- never trips this since consecutive client requests
                -- advance by stride.)
                if stream.last_req_offset and req_offset
                   and req_offset ~= stream.last_req_offset
                                     + (stream.first_page_size or 0) then
                    stream = session.docs_stream_open(pinfo, connid)
                end
                if not stream.first_page_size then
                    stream.first_page_size = #page_data
                end
                local was_closed = stream.closed
                cached = ingest_chunk(stream, pinfo.number,
                                      page_data, #page_data)
                stream.last_req_offset = req_offset
                if close_v21 then stream.closed = true end
                if #page_data == 0 then stream.closed = true end
                -- Stash "did THIS frame close the stream?" on the
                -- cached result so the malformed-residue expert only
                -- fires on the closing frame, not on every frame in
                -- pass 2 after the stream-level `closed` flag latches.
                cached.closed_here = stream.closed and not was_closed
            else
                cached = {
                    records         = {},
                    records_skipped = 0,
                    continuation    = false,
                    chunk_size      = 0,
                    complete_in     = nil,
                    tail_after      = false,
                    closed_here     = false,
                }
            end
        end

        -- Anchor the subtree to the page_data tvb range when this
        -- frame contributed bytes; fall back to the whole body for
        -- zero-byte pages (stream-close marker / docs_blob's
        -- self-contained zero-record reply).
        local subtree_range = page_tvb_range or body
        local subtree = tree:add(proto, subtree_range,
            "Rockwell description records (class 0x0349)")
        subtree:add(f.request_in, req.req_frame):set_generated()

        if cached.continuation then
            subtree:add(f.continuation, true):set_generated()
            subtree:add(f.chunk_size, cached.chunk_size):set_generated()
            if cached.complete_in then
                subtree:add(f.complete_in, cached.complete_in):set_generated()
            end
            pinfo.cols.info:append(
                string.format(" [docs chunk %dB → completes in %s]",
                              cached.chunk_size,
                              cached.complete_in
                                  and tostring(cached.complete_in)
                                  or "?"))
        else
            -- Render records (if any). Each record's bytes were
            -- assembled in the stream accumulator at ingest time; we
            -- anchor whichever portion sits in this frame's page_data
            -- and emit the rest as generated values. For the fresh-
            -- zero-reply path there's no stream and no chunk; skip the
            -- per-chunk anchoring math.
            for _, c in ipairs(cached.records) do
                render_record(subtree, c, page_tvb_range,
                              cached.chunk_size)
            end
            subtree:add(f.records_count, #cached.records):set_generated()
            subtree:add(f.records_skipped,
                        cached.records_skipped):set_generated()
            if cached.records_skipped > 0 then
                subtree:add_proto_expert_info(expert_unsupported)
            end
            if #cached.records > 0 then
                pinfo.cols.info:append(
                    string.format(" [%d docs records]", #cached.records))
            end
        end

        -- On the stream-closing frame, surface a malformed expert info
        -- when the accumulator still has unparsed bytes (a partial
        -- record we never finished assembling). Helps the analyst spot
        -- captures with truncation or with v21/v36 detection going
        -- wrong. Fires only on the frame that caused the close, not on
        -- every later frame in pass 2 (the stream-level flag latches).
        if cached.closed_here and cached.tail_after then
            subtree:add_proto_expert_info(expert_stream_residue)
        end
    end

    ctx.add_dissect("class_0349_docs", dissect)
end

return M
