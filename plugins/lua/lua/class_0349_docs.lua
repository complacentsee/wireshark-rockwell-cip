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
--   LAYOUT_OPSTR / LAYOUT_OPSTR_SHORT / LAYOUT_36_SCOPED /
--   LAYOUT_OPSTR_SCOPED — variants with embedded operand strings
--   and/or scope paths. These shift downstream offsets by 14–18 bytes
--   and are not yet handled by this dissector; we recognise their
--   class_marker but pass them through as "unparsed record".
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
    f.records_count = ProtoField.uint32("rockwell_cip.docs.records_count",
        "Record Count", base.DEC)
    f.records_skipped = ProtoField.uint32(
        "rockwell_cip.docs.records_skipped",
        "Records Skipped (unparsed layout)", base.DEC)

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

    -- Per-class allowed layouts. Mirrors LAYOUTS in extract_logix_data.py.
    -- The dissector only tries LAYOUT_36 / LAYOUT_38 for now — the
    -- OPSTR* variants need operand-string parsing that we haven't
    -- ported yet; they're handled as "unparsed".
    local LAYOUTS_SIMPLE = {
        [0x0068] = "38",
        [0x0069] = "38",
        [0x006C] = "38",
        [0x0338] = "38",
        [0x0349] = "38",
        -- 0x006B is best handled by the layout-detection loop below
        -- because it can be any of 4 layouts.
    }

    local OPERAND_BIT_BASE   = valstr.operand_bit_base
    local OPERAND_BIT_STRIDE = valstr.operand_bit_stride

    local DOC_CLASSES = {
        [0x0068]=true, [0x0069]=true, [0x006B]=true, [0x006C]=true,
        [0x0338]=true, [0x0349]=true,
    }

    local function u16_le(range, off)
        return range(off, 2):le_uint()
    end

    local function try_record(body, pos)
        -- Returns (consumed_bytes, table_with_fields, layout_name) or
        -- (nil, nil, nil) if we can't parse a record here.
        if pos + 38 > body:len() then return nil end
        local cm = u16_le(body, pos)
        if not DOC_CLASSES[cm] then return nil end

        -- Probe LAYOUT_38 first (more common). marker at +14 = 0x007F.
        if pos + 38 <= body:len() then
            local marker_38 = u16_le(body, pos + 14)
            local one_38    = u16_le(body, pos + 16)
            if marker_38 == 0x007F and one_38 == 0x0001 then
                local count  = u16_le(body, pos + 34)
                local strlen = u16_le(body, pos + 36)
                local end_pos = pos + 38 + strlen
                if end_pos <= body:len() then
                    local rec = {
                        class_marker = cm,
                        instance     = u16_le(body, pos + 2),
                        sub_inst     = u16_le(body, pos + 6),
                        ref_id       = u16_le(body, pos + 18),
                        count        = count,
                        strlen       = strlen,
                        str_off      = 38,
                    }
                    return end_pos - pos, rec, "LAYOUT_38"
                end
            end
        end

        -- LAYOUT_36: marker at +12 = 0x007F, +14 = 0x0001
        if pos + 36 <= body:len() then
            local marker_36 = u16_le(body, pos + 12)
            local one_36    = u16_le(body, pos + 14)
            if marker_36 == 0x007F and one_36 == 0x0001 then
                local count  = u16_le(body, pos + 32)
                local strlen = u16_le(body, pos + 34)
                local end_pos = pos + 36 + strlen
                if end_pos <= body:len() then
                    local bit_field = u16_le(body, pos + 10)
                    local bit_num   = -1
                    if bit_field >= OPERAND_BIT_BASE
                        and (bit_field - OPERAND_BIT_BASE)
                            % OPERAND_BIT_STRIDE == 0 then
                        bit_num =
                            (bit_field - OPERAND_BIT_BASE) // OPERAND_BIT_STRIDE
                    end
                    local rec = {
                        class_marker = cm,
                        instance     = u16_le(body, pos + 2),
                        ref_id       = u16_le(body, pos + 16),
                        bit_field    = bit_field,
                        bit_number   = bit_num,
                        count        = count,
                        strlen       = strlen,
                        str_off      = 36,
                    }
                    return end_pos - pos, rec, "LAYOUT_36"
                end
            end
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
    local field_cip_class   = Field.new("cip.class")
    local field_cip_epath   = Field.new("cip.epath")

    -- 16-bit class segment for class 0x349: 21 00 49 03 (LE).
    local CLASS_0349_PATH = "\x21\x00\x49\x03"

    local function path_targets_0349(epath_fi)
        if not epath_fi or not epath_fi.range then return false end
        local raw = epath_fi.range:bytes():raw()
        return string.find(raw, CLASS_0349_PATH, 1, true) ~= nil
    end

    local function dissect(tvb, pinfo, tree)
        -- Class 0x349 is encoded as a 16-bit class segment, which the
        -- stock cip dissector exposes via cip.epath rather than the
        -- 8-bit cip.class field. Check both.
        local class_fi = field_cip_class()
        local hit_8bit = class_fi and class_fi.value == 0x49
                                  and false  -- 0x349 wouldn't fit in 8b
        local hit_16bit = path_targets_0349(field_cip_epath())
        if not hit_8bit and not hit_16bit then return end

        local svc_fi = field_cip_service()
        if not svc_fi then return end
        local svc = svc_fi.value
        -- 0x53 request / 0xD3 reply (read documentation), or other
        -- read services touching 0x349.
        if svc < 0x80 then return end   -- only the REPLY carries records

        local svc_range = svc_fi.range
        if not svc_range then return end
        local cip_start = svc_range:offset()
        local cip_tvb = tvb:range(cip_start)
        -- Reply skeleton: svc(1) rsv(1) gen(1) ext_size(1) body...
        if cip_tvb:len() < 4 then return end
        local body = cip_tvb(4, cip_tvb:len() - 4)

        local subtree = tree:add(proto, body,
            "Rockwell description records (class 0x0349)")

        local pos = 0
        local count = 0
        local skipped = 0
        local max_records = 4096    -- guardrail
        while pos < body:len() and count < max_records do
            local consumed, rec, layout = try_record(body, pos)
            if not consumed then
                -- Slide forward by 1 byte and try again. Per-record
                -- alignment isn't padded — we resync at the next
                -- marker.
                local cm = u16_le(body, pos)
                if DOC_CLASSES[cm] then
                    -- We saw a class marker we should know but the
                    -- layout didn't match either supported one.
                    -- Probably OPSTR / SCOPED variant.
                    skipped = skipped + 1
                end
                pos = pos + 1
            else
                local rec_range = body(pos, consumed)
                local rt = subtree:add(f.record, rec_range)
                rt:add_le(f.class_marker, body(pos, 2))
                rt:add(f.layout, layout):set_generated()
                rt:add_le(f.instance,     body(pos + 2, 2))
                if layout == "LAYOUT_38" then
                    rt:add_le(f.routine_inst, body(pos + 6, 2))
                    rt:add_le(f.ref_id,       body(pos + 18, 2))
                    rt:add_le(f.count,        body(pos + 34, 2))
                    rt:add_le(f.strlen,       body(pos + 36, 2))
                else  -- LAYOUT_36
                    rt:add_le(f.bit_field,    body(pos + 10, 2))
                    if rec.bit_number >= 0 then
                        rt:add(f.bit_number, rec.bit_number):set_generated()
                    end
                    rt:add_le(f.ref_id,       body(pos + 16, 2))
                    rt:add_le(f.count,        body(pos + 32, 2))
                    rt:add_le(f.strlen,       body(pos + 34, 2))
                end

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
        if skipped > 0 then
            subtree:add(f.records_skipped, skipped):set_generated()
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
