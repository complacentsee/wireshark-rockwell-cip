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
-- This dissector walks the body of any CIP reply payload it sees on
-- class 0x0349 (typically service 0x53 / 0xD3). When the inner-CIP
-- recursion from service_36_signed.lua or service_3a_upload.lua emits
-- a cip.class == 0x349 field, we fire and decode records.

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
    ctx.add_expert(expert_compressed)
    ctx.add_expert(expert_unsupported)

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

    local function u16_le(range, off)
        return range(off, 2):le_uint()
    end

    local function bytes_all_zero(body, pos, len)
        for i = 0, len - 1 do
            if body(pos + i, 1):uint() ~= 0 then return false end
        end
        return true
    end

    local function ascii_printable(body, pos, len)
        if len <= 0 then return false end
        for i = 0, len - 1 do
            local c = body(pos + i, 1):uint()
            if c < 0x20 or c > 0x7E then return false end
        end
        return true
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

    -- Read + validate the 22-byte embedded scope path used by the
    -- *_SCOPED variants. Layout (relative to record start):
    --   +4..+13   10 zero bytes
    --   +14 u16   scope_class  (in SCOPE_CLASSES)
    --   +16 u16   scope_inst
    --   +18 u16   target_class (== 0x006B)
    --   +20 u16   target_inst
    --   +22..+25  4 zero bytes
    -- Returns a scope table or nil if any check fails.
    local function read_scope(body, pos)
        if pos + 26 > body:len() then return nil end
        if not bytes_all_zero(body, pos + 4, 10) then return nil end
        local scope_class = u16_le(body, pos + 14)
        if not SCOPE_CLASSES[scope_class] then return nil end
        local target_class = u16_le(body, pos + 18)
        if target_class ~= TARGET_SCOPED then return nil end
        if not bytes_all_zero(body, pos + 22, 4) then return nil end
        return {
            scope_class  = scope_class,
            scope_inst   = u16_le(body, pos + 16),
            target_class = target_class,
            target_inst  = u16_le(body, pos + 20),
        }
    end

    -- Each try_layout_* helper returns (consumed_bytes, rec_table,
    -- layout_name) on success or nil on failure. rec_table carries the
    -- per-field offsets the emission code uses below, so the dissector
    -- never has to recompute them from the layout name.

    local function try_layout_36(body, pos)
        if pos + 36 > body:len() then return nil end
        if u16_le(body, pos + 12) ~= MARKER_7F then return nil end
        local count  = u16_le(body, pos + 32)
        local strlen = u16_le(body, pos + 34)
        if count ~= 1 or strlen <= 0 or strlen >= 8192 then return nil end
        if pos + 36 + strlen > body:len() then return nil end
        local bit_field = u16_le(body, pos + 10)
        return 36 + strlen, {
            class_marker  = u16_le(body, pos),
            instance      = u16_le(body, pos + 2),
            bit_field     = bit_field,
            bit_number    = decode_bit_number(bit_field),
            bit_field_off = 10,
            ref_id_off    = 16,
            count_off     = 32,
            strlen_off    = 34,
            str_off       = 36,
            strlen        = strlen,
        }, "LAYOUT_36"
    end

    local function try_layout_38(body, pos)
        if pos + 38 > body:len() then return nil end
        if u16_le(body, pos + 14) ~= MARKER_7F then return nil end
        local count  = u16_le(body, pos + 34)
        local strlen = u16_le(body, pos + 36)
        if count ~= 1 or strlen <= 0 or strlen >= 8192 then return nil end
        if pos + 38 + strlen > body:len() then return nil end
        return 38 + strlen, {
            class_marker = u16_le(body, pos),
            instance     = u16_le(body, pos + 2),
            sub_inst     = u16_le(body, pos + 6),
            sub_inst_off = 6,
            ref_id_off   = 18,
            count_off    = 34,
            strlen_off   = 36,
            str_off      = 38,
            strlen       = strlen,
        }, "LAYOUT_38"
    end

    local function try_layout_opstr(body, pos)
        -- 8 zero bytes at +4..+11, u16 osl at +12, operand at +14.
        if pos + 14 > body:len() then return nil end
        if not bytes_all_zero(body, pos + 4, 8) then return nil end
        local osl = u16_le(body, pos + 12)
        if osl < 1 or osl > 64 then return nil end
        local m_off  = 14 + osl
        local ct_off = 34 + osl
        local sl_off = 36 + osl
        local str_off = 38 + osl
        if pos + str_off > body:len() then return nil end
        if u16_le(body, pos + m_off) ~= MARKER_7F then return nil end
        local count  = u16_le(body, pos + ct_off)
        local strlen = u16_le(body, pos + sl_off)
        if count ~= 1 or strlen <= 0 or strlen >= 8192 then return nil end
        if pos + str_off + strlen > body:len() then return nil end
        if not ascii_printable(body, pos + 14, osl) then return nil end
        return str_off + strlen, {
            class_marker = u16_le(body, pos),
            instance     = u16_le(body, pos + 2),
            osl          = osl,
            osl_off      = 12,
            operand      = body(pos + 14, osl):string(),
            operand_off  = 14,
            ref_id_off   = m_off + 4,
            count_off    = ct_off,
            strlen_off   = sl_off,
            str_off      = str_off,
            strlen       = strlen,
        }, "LAYOUT_OPSTR"
    end

    local function try_layout_opstr_short(body, pos)
        -- 4 zero bytes at +4..+7, u16 osl at +8, operand at +10. osl
        -- must be >= 3; osl <= 2 collides with LAYOUT_36's marker
        -- position and is the LAYOUT_36 bit_field decode's
        -- responsibility (the Python parser handles it that way).
        if pos + 12 > body:len() then return nil end
        if not bytes_all_zero(body, pos + 4, 4) then return nil end
        local osl = u16_le(body, pos + 8)
        if osl < 3 or osl > 64 then return nil end
        local m_off  = 10 + osl
        local ct_off = 30 + osl
        local sl_off = 32 + osl
        local str_off = 34 + osl
        if pos + str_off > body:len() then return nil end
        if u16_le(body, pos + m_off) ~= MARKER_7F then return nil end
        local count  = u16_le(body, pos + ct_off)
        local strlen = u16_le(body, pos + sl_off)
        if count ~= 1 or strlen <= 0 or strlen >= 8192 then return nil end
        if pos + str_off + strlen > body:len() then return nil end
        if not ascii_printable(body, pos + 10, osl) then return nil end
        return str_off + strlen, {
            class_marker = u16_le(body, pos),
            instance     = u16_le(body, pos + 2),
            osl          = osl,
            osl_off      = 8,
            operand      = body(pos + 10, osl):string(),
            operand_off  = 10,
            ref_id_off   = m_off + 4,
            count_off    = ct_off,
            strlen_off   = sl_off,
            str_off      = str_off,
            strlen       = strlen,
        }, "LAYOUT_OPSTR_SHORT"
    end

    local function try_layout_36_scoped(body, pos)
        local scope = read_scope(body, pos)
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
        if pos + str_off > body:len() then return nil end
        if u16_le(body, pos + m_off) ~= MARKER_7F then return nil end
        local count  = u16_le(body, pos + count_off)
        local strlen = u16_le(body, pos + sl_off)
        if count ~= 1 or strlen <= 0 or strlen >= 8192 then return nil end
        if pos + str_off + strlen > body:len() then return nil end
        local bit_field = u16_le(body, pos + bit_field_off)
        return str_off + strlen, {
            class_marker  = u16_le(body, pos),
            instance      = u16_le(body, pos + 2),
            scope         = scope,
            bit_field     = bit_field,
            bit_number    = decode_bit_number(bit_field),
            bit_field_off = bit_field_off,
            ref_id_off    = ref_id_off,
            count_off     = count_off,
            strlen_off    = sl_off,
            str_off       = str_off,
            strlen        = strlen,
        }, "LAYOUT_36_SCOPED"
    end

    local function try_layout_opstr_scoped(body, pos)
        local scope = read_scope(body, pos)
        if not scope then return nil end
        if pos + 28 > body:len() then return nil end
        -- OPSTR tail starts at +26 (osl) / +28 (operand). Marker at
        -- +28+osl, then LAYOUT_38-like trailer shifted by +14+osl
        -- relative to bare LAYOUT_OPSTR.
        local osl = u16_le(body, pos + 26)
        if osl < 1 or osl > 64 then return nil end
        local m_off   = 28 + osl
        local ct_off  = 48 + osl
        local sl_off  = 50 + osl
        local str_off = 52 + osl
        if pos + str_off > body:len() then return nil end
        if u16_le(body, pos + m_off) ~= MARKER_7F then return nil end
        local count  = u16_le(body, pos + ct_off)
        local strlen = u16_le(body, pos + sl_off)
        if count ~= 1 or strlen <= 0 or strlen >= 8192 then return nil end
        if pos + str_off + strlen > body:len() then return nil end
        if not ascii_printable(body, pos + 28, osl) then return nil end
        return str_off + strlen, {
            class_marker = u16_le(body, pos),
            instance     = u16_le(body, pos + 2),
            scope        = scope,
            osl          = osl,
            osl_off      = 26,
            operand      = body(pos + 28, osl):string(),
            operand_off  = 28,
            ref_id_off   = m_off + 4,
            count_off    = ct_off,
            strlen_off   = sl_off,
            str_off      = str_off,
            strlen       = strlen,
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

    local function try_record(body, pos)
        if pos + 2 > body:len() then return nil end
        local cm = u16_le(body, pos)
        local allowed = LAYOUTS_BY_CLASS[cm]
        if not allowed then return nil end
        for _, name in ipairs(allowed) do
            local consumed, rec, layout = LAYOUT_TRY_FNS[name](body, pos)
            if consumed then return consumed, rec, layout end
        end
        return nil
    end

    local function decode_text(body, rec_pos, rec)
        if rec.strlen == 0 then return "", false end
        local off = rec_pos + rec.str_off
        if off + rec.strlen > body:len() then return nil, false end
        local body_bytes = body(off, rec.strlen):bytes():raw()
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

    local field_cip_service = Field.new("cip.service")
    local field_cip_epath   = Field.new("cip.epath")
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
        -- On a signed frame the cip_tvb still includes the trailing
        -- seq(4) + HMAC(20) bytes — trim them so the record walker
        -- doesn't try to match record headers in HMAC noise. The
        -- presence of pinfo.private["rockwell_cip.signed.seq"] is our
        -- "this frame is signed" signal.
        local cip_end = cip_tvb:len()
        if seq ~= nil then cip_end = cip_end - 24 end
        if cip_end < 4 then return end
        local body = cip_tvb(4, cip_end - 4)

        local subtree = tree:add(proto, body,
            "Rockwell description records (class 0x0349)")
        subtree:add(f.request_in, req.req_frame):set_generated()

        local pos = 0
        local count = 0
        local skipped = 0
        local max_records = 4096    -- guardrail
        while pos < body:len() and count < max_records do
            local consumed, rec, layout = try_record(body, pos)
            if not consumed then
                -- Slide forward by 1 byte and try again. Per-record
                -- alignment isn't padded — we resync at the next
                -- marker. Guard against OOB when there's < 2 bytes left.
                if pos + 2 <= body:len() then
                    local cm = u16_le(body, pos)
                    if DOC_CLASSES[cm] then
                        -- We saw a known class_marker but no candidate
                        -- layout for that class validated. Counted as
                        -- skipped for regression visibility. Common
                        -- residual sources:
                        --   - class 0x0349 attribute-value records
                        --     (count != 1 — not text descriptions; the
                        --     Python parser also ignores these)
                        --   - records whose strlen extends past the
                        --     end of THIS frame's body (true cross-
                        --     packet description records; would need
                        --     TCP reassembly to parse)
                        --   - coincidental marker bytes inside a
                        --     previous record's payload
                        skipped = skipped + 1
                    end
                end
                pos = pos + 1
            else
                local rec_range = body(pos, consumed)
                local rt = subtree:add(f.record, rec_range)
                rt:add_le(f.class_marker, body(pos, 2))
                rt:add(f.layout, layout):set_generated()
                rt:add_le(f.instance,     body(pos + 2, 2))
                if rec.scope then
                    rt:add_le(f.scope_class,  body(pos + 14, 2))
                    rt:add_le(f.scope_inst,   body(pos + 16, 2))
                    rt:add_le(f.target_class, body(pos + 18, 2))
                    rt:add_le(f.target_inst,  body(pos + 20, 2))
                end
                if rec.osl then
                    rt:add_le(f.osl, body(pos + rec.osl_off, 2))
                    rt:add(f.operand,
                           body(pos + rec.operand_off, rec.osl),
                           rec.operand)
                end
                if rec.bit_field then
                    rt:add_le(f.bit_field,
                              body(pos + rec.bit_field_off, 2))
                    if rec.bit_number >= 0 then
                        rt:add(f.bit_number, rec.bit_number):set_generated()
                    end
                end
                if rec.sub_inst_off then
                    rt:add_le(f.routine_inst,
                              body(pos + rec.sub_inst_off, 2))
                end
                rt:add_le(f.ref_id, body(pos + rec.ref_id_off, 2))
                rt:add_le(f.count,  body(pos + rec.count_off, 2))
                rt:add_le(f.strlen, body(pos + rec.strlen_off, 2))

                local text, compressed, dec_size = decode_text(body, pos, rec)
                if compressed then
                    rt:add(f.compressed, true):set_generated()
                    if dec_size then
                        rt:add(f.dec_size, dec_size):set_generated()
                    end
                    rt:add_proto_expert_info(expert_compressed)
                end
                if text then rt:add(f.text, text):set_generated() end

                pos = pos + consumed
                count = count + 1
            end
        end
        subtree:add(f.records_count, count):set_generated()
        -- Always-emit (even when zero) so the golden PDML files have a
        -- stable regression guard against new unsupported layouts
        -- creeping back in. The expert info is still conditional on a
        -- non-zero skip count.
        subtree:add(f.records_skipped, skipped):set_generated()
        if skipped > 0 then
            subtree:add_proto_expert_info(expert_unsupported)
        end
        if count > 0 then
            pinfo.cols.info:append(
                string.format(" [%d docs records]", count))
        end
    end

    ctx.add_dissect("class_0349_docs", dissect)
end

return M
