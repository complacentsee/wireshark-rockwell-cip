-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- service_36_signed.lua — Studio 5000 v36 HMAC-SHA1 signed CIP wrapper
-- (service 0x36 request / 0xB6 reply).
--
-- Wire layout, signed request:
--     0x36                      service
--     0x02                      path size (2 words)
--     20 02 24 01               path: class 0x02 (Message Router) inst 1
--     <inner CIP>               wrapped request, varies
--     <seq u32 LE>              monotonically increasing per session
--     <HMAC-SHA1 20B>           HMAC over [outer header || inner || seq]
--
-- Reply layout (service 0xB6):
--     0xB6 00 <gen_status> <ext_size_words> [<ext_status words>]
--     <inner CIP reply>
--     <seq u32 LE>
--     <HMAC-SHA1 20B>
--
-- We run as a post-dissector: the stock cip dissector parses the outer
-- service byte and path for us (and stops — it doesn't know what 0x36
-- means). We read those fields back via Field accessors, find the
-- TVB offset of the service byte, and decode the wrapper structure
-- around the inner CIP. Recursing the inner CIP back into the stock
-- dissector is deferred to v0.2 — first we want the wrapper visible.

local M = {}

function M.register(proto, valstr)
    local f = {}

    f.service     = ProtoField.uint8("rockwell_cip.signed.service",
        "Signed Service", base.HEX, valstr.services)
    f.path_size   = ProtoField.uint8("rockwell_cip.signed.path_size",
        "Outer Path Size (words)", base.DEC)
    f.path        = ProtoField.bytes("rockwell_cip.signed.path",
        "Outer Path", base.SPACE)
    f.inner       = ProtoField.bytes("rockwell_cip.signed.inner_cip",
        "Inner CIP (opaque for now)", base.SPACE)
    f.seq         = ProtoField.uint32("rockwell_cip.signed.seq",
        "Session Sequence", base.DEC)
    f.hmac        = ProtoField.bytes("rockwell_cip.signed.hmac",
        "HMAC-SHA1 Trailer", base.SPACE)
    f.gen_status  = ProtoField.uint8("rockwell_cip.signed.gen_status",
        "General Status", base.HEX)
    f.ext_words   = ProtoField.uint8("rockwell_cip.signed.ext_status_words",
        "Extended Status (words)", base.DEC)

    proto.fields = proto.fields or {}
    for _, fld in pairs(f) do
        table.insert(proto.fields, fld)
    end

    -- Field accessor for the stock cip dissector's service byte. The
    -- FieldInfo we read back carries its TvbRange, which is where the
    -- service byte landed in the packet — that's our anchor point for
    -- the rest of the wrapper.
    local field_cip_service = Field.new("cip.service")

    local function dissect(tvb, pinfo, tree)
        local svc_fi = field_cip_service()
        if not svc_fi then return end

        local svc = svc_fi.value
        if svc ~= 0x36 and svc ~= 0xB6 then
            return
        end

        local svc_range = svc_fi.range
        if not svc_range then return end

        local cip_start = svc_range:offset()
        if cip_start + 24 > tvb:len() then return end

        local cip_tvb = tvb:range(cip_start)
        local subtree = tree:add(proto, cip_tvb,
            string.format("Rockwell signed-CIP wrapper (0x%02X)", svc))

        subtree:add(f.service, cip_tvb(0, 1))
        if svc == 0x36 then
            pinfo.cols.info:append(" [Signed Send]")
        else
            pinfo.cols.info:append(" [Signed Reply]")
        end

        local offset = 1
        local trailer = 24       -- 4B seq + 20B HMAC
        local last = cip_tvb:len()
        if last < offset + trailer then return end

        if svc == 0x36 then
            local path_words = cip_tvb(offset, 1):uint()
            subtree:add(f.path_size, cip_tvb(offset, 1))
            offset = offset + 1
            local path_bytes = path_words * 2
            if offset + path_bytes > last - trailer then return end
            subtree:add(f.path, cip_tvb(offset, path_bytes))
            offset = offset + path_bytes
        else
            -- Reply: 0xB6 [0x00 reserved] [gen_status] [ext_size_words]
            offset = offset + 1   -- reserved byte
            if offset >= last - trailer then return end
            subtree:add(f.gen_status, cip_tvb(offset, 1))
            offset = offset + 1
            if offset >= last - trailer then return end
            local ext_words = cip_tvb(offset, 1):uint()
            subtree:add(f.ext_words, cip_tvb(offset, 1))
            offset = offset + 1
            offset = offset + ext_words * 2
            if offset > last - trailer then return end
        end

        local inner_len = last - trailer - offset
        if inner_len > 0 then
            subtree:add(f.inner, cip_tvb(offset, inner_len))
            offset = offset + inner_len
        end

        subtree:add_le(f.seq, cip_tvb(offset, 4))
        offset = offset + 4
        subtree:add(f.hmac, cip_tvb(offset, 20))
    end

    proto.dissector = dissect
    -- 'true' second arg: tell Wireshark we want allfields enabled so
    -- our Field accessor sees the stock cip dissector's output.
    register_postdissector(proto, true)
end

return M
