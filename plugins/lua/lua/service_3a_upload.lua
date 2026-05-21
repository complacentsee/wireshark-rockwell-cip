-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- service_3a_upload.lua — Studio v36 compiled-body upload wrapper
-- (service 0x3A request / 0xBA reply).
--
-- Same outer envelope as 0x36 (Message Router path, seq u32 LE, 20-byte
-- HMAC-SHA1 trailer). The body shape differs in that 0x3A carries a
-- multi-chunk transport: each request/reply pair belongs to either an
-- "init" or a "continuation" phase.
--
-- Wire layout, request (svc 0x3A):
--     0x3A                  service
--     0x02                  path size (2 words)
--     20 02 24 01           path (class 0x02 Message Router, inst 1)
--     <body...>             see below
--     <seq u32 LE>          session sequence
--     <HMAC-SHA1 20B>
--
-- Body shapes:
--   INIT request:        01 01 00 00 00 00 00 00 <inner CIP 0x5D ...>
--   CONTINUATION req:    01 00 00 00 <token u32 LE>
--
-- Reply layout (svc 0xBA):
--     0xBA 00 <gen_status> <ext_size_words> [<ext_status...>]
--     <body...>
--     <seq u32 LE>
--     <HMAC-SHA1 20B>
--
-- Body shapes:
--   INIT reply:          01 <state> 00 00 <~44B header incl. raw_size>
--                        <zlib stream — first 2 bytes 78 9c>
--   CONTINUATION reply:  01 <state> 00 00 <token echo u32 LE> <zlib chunk>
--
-- state byte values:
--   0x00  continuation, more chunks follow
--   0x01  init reply, more chunks follow
--   0x02  continuation, final chunk
--   0x03  init reply, complete in this packet (no continuations)
--
-- Inner CIP service 0x5D body in an INIT request:
--   5D <path_words> <epath> 01 00 00 00 <op u32 LE>
--   op = 3 read, 4 release, 9 read program body bulk.
--
-- HMAC validation: identical to 0x36 (see service_36_signed.lua); the
-- session key is shared across the two wrappers on the same stream.

local M = {}

function M.register(proto, valstr, ctx)
    local sha1    = require "sha1"
    local session = require "session"
    local inflate = require "inflate"

    local f = {}
    f.service       = ProtoField.uint8("rockwell_cip.upload.service",
        "Upload Service", base.HEX, valstr.services)
    f.path_size     = ProtoField.uint8("rockwell_cip.upload.path_size",
        "Outer Path Size (words)", base.DEC)
    f.path          = ProtoField.bytes("rockwell_cip.upload.path",
        "Outer Path", base.SPACE)
    f.gen_status    = ProtoField.uint8("rockwell_cip.upload.gen_status",
        "General Status", base.HEX)
    f.ext_words     = ProtoField.uint8("rockwell_cip.upload.ext_status_words",
        "Extended Status (words)", base.DEC)

    f.phase         = ProtoField.string("rockwell_cip.upload.phase",
        "Transport Phase")
    f.state         = ProtoField.uint8("rockwell_cip.upload.state",
        "State", base.HEX, valstr.body_3a_states)
    f.token         = ProtoField.uint32("rockwell_cip.upload.token",
        "Continuation Token", base.DEC)
    f.token_echo    = ProtoField.uint32("rockwell_cip.upload.token_echo",
        "Token Echo", base.DEC)
    f.init_header   = ProtoField.bytes("rockwell_cip.upload.init_header",
        "INIT Header", base.SPACE)
    f.payload_chunk = ProtoField.bytes("rockwell_cip.upload.payload_chunk",
        "Compiled-body Chunk", base.SPACE)
    f.chunk_header  = ProtoField.bytes("rockwell_cip.upload.chunk_header",
        "Chunk Header (precedes zlib stream)", base.SPACE)
    f.zlib_stream   = ProtoField.bytes("rockwell_cip.upload.zlib_stream",
        "zlib / DEFLATE Stream", base.SPACE)
    f.zlib_offset   = ProtoField.uint16("rockwell_cip.upload.zlib_offset",
        "zlib start offset within chunk", base.DEC)
    f.inflated      = ProtoField.bytes("rockwell_cip.upload.inflated",
        "Inflated Payload (pure-Lua decompress)", base.SPACE)
    f.inflated_size = ProtoField.uint32("rockwell_cip.upload.inflated_size",
        "Inflated Size (bytes)", base.DEC)
    f.inflate_error = ProtoField.string("rockwell_cip.upload.inflate_error",
        "Inflate Error")
    f.inner_5d      = ProtoField.bytes("rockwell_cip.upload.inner_5d",
        "Inner CIP (0x5D)", base.SPACE)
    f.inner_op      = ProtoField.uint32("rockwell_cip.upload.op",
        "Inner 0x5D op", base.DEC, valstr.body_3a_ops)

    f.seq           = ProtoField.uint32("rockwell_cip.upload.seq",
        "Session Sequence", base.DEC)
    f.hmac          = ProtoField.bytes("rockwell_cip.upload.hmac",
        "HMAC-SHA1 Trailer", base.SPACE)
    f.hmac_status   = ProtoField.string("rockwell_cip.upload.hmac_status",
        "HMAC Validation")
    f.hmac_expected = ProtoField.bytes("rockwell_cip.upload.hmac_expected",
        "Expected HMAC", base.SPACE)

    for _, fld in pairs(f) do ctx.add_field(fld) end

    local expert_init_req       = ProtoExpert.new(
        "rockwell_cip.upload.init_req",
        "Upload: INIT request",
        expert.group.PROTOCOL, expert.severity.NOTE)
    local expert_init_reply     = ProtoExpert.new(
        "rockwell_cip.upload.init_reply",
        "Upload: INIT reply",
        expert.group.PROTOCOL, expert.severity.NOTE)
    local expert_cont_req       = ProtoExpert.new(
        "rockwell_cip.upload.cont_req",
        "Upload: continuation request",
        expert.group.PROTOCOL, expert.severity.NOTE)
    local expert_cont_reply     = ProtoExpert.new(
        "rockwell_cip.upload.cont_reply",
        "Upload: continuation reply",
        expert.group.PROTOCOL, expert.severity.NOTE)
    local expert_hmac_ok        = ProtoExpert.new(
        "rockwell_cip.upload.hmac_ok",
        "HMAC trailer verified",
        expert.group.SECURITY, expert.severity.NOTE)
    local expert_hmac_fail      = ProtoExpert.new(
        "rockwell_cip.upload.hmac_fail",
        "HMAC trailer mismatch",
        expert.group.SECURITY, expert.severity.WARN)
    local expert_hmac_unknown   = ProtoExpert.new(
        "rockwell_cip.upload.hmac_unknown",
        "HMAC not validated (no session key available)",
        expert.group.SECURITY, expert.severity.NOTE)
    ctx.add_expert(expert_init_req)
    ctx.add_expert(expert_init_reply)
    ctx.add_expert(expert_cont_req)
    ctx.add_expert(expert_cont_reply)
    ctx.add_expert(expert_hmac_ok)
    ctx.add_expert(expert_hmac_fail)
    ctx.add_expert(expert_hmac_unknown)

    -- Preference: opt-in pure-Lua zlib inflate of single-frame complete
    -- uploads (state 0x03). Disabled by default — multi-frame reassembly
    -- isn't implemented yet, and very large captures can produce many
    -- chunks. Enable to see decoded XML / source bodies inline.
    proto.prefs.inflate = Pref.bool(
        "Inflate single-frame upload chunks",
        false,
        "When set, decompress the zlib stream inside an INIT-reply with "
        .. "state=0x03 (complete in one packet) and add the inflated "
        .. "text as a Wireshark field. Uses a pure-Lua DEFLATE "
        .. "implementation; can be slow on large payloads.")

    local field_cip_service = Field.new("cip.service")
    local field_cip_connid  = Field.new("cip.connid")
    local cip_dis = Dissector.get("cip")

    local function decode_body(body_range, subtree, pinfo, is_reply)
        -- Returns nothing; annotates subtree with the body breakdown.
        if body_range:len() < 4 then return end
        -- The body always starts with a 1B family marker (always 0x01 in
        -- the observed traffic) followed by the state byte.
        local _marker = body_range(0, 1):uint()
        local state   = body_range(1, 1):uint()
        subtree:add(f.state, body_range(1, 1))

        if not is_reply then
            -- Request body.
            if state == 0x01 then
                -- INIT request: marker(1) state(1) pad(2) reserved(4) inner_CIP...
                if body_range:len() < 8 then return end
                subtree:add(f.init_header, body_range(0, 8))
                subtree:add(f.phase, "INIT request"):set_generated()
                pinfo.cols.info:append(" [Upload INIT]")
                subtree:add_proto_expert_info(expert_init_req)
                if body_range:len() > 8 then
                    local inner_range = body_range(8, body_range:len() - 8)
                    subtree:add(f.inner_5d, inner_range)
                    -- The inner is a CIP service 0x5D with an 8-byte
                    -- arg tail. The last 4 bytes are the op u32 LE.
                    if inner_range:len() >= 13 then
                        local op_range =
                            inner_range(inner_range:len() - 4, 4)
                        subtree:add_le(f.inner_op, op_range)
                    end
                    -- Recurse the inner so stock cip renders it as a
                    -- normal CIP request tree.
                    if cip_dis then
                        pcall(function()
                            cip_dis:call(inner_range:tvb(), pinfo,
                                subtree:add(proto, inner_range,
                                    "Inner CIP (decoded)"))
                        end)
                    end
                end
            elseif state == 0x00 then
                -- Continuation request: marker(1) state(1) pad(2) token(4)
                if body_range:len() >= 8 then
                    subtree:add_le(f.token, body_range(4, 4))
                end
                subtree:add(f.phase, "Continuation request"):set_generated()
                pinfo.cols.info:append(" [Upload CONT]")
                subtree:add_proto_expert_info(expert_cont_req)
            end
        else
            -- Reply body.
            -- Reply: marker(1) state(1) pad(2) [token_echo(4) — only
            -- for continuation replies] then zlib chunk OR init header.
            local is_init     = (state == 0x01 or state == 0x03)
            local is_final    = (state == 0x02 or state == 0x03)
            local phase_str   =
                (is_init and "INIT reply" or "Continuation reply")
                .. (is_final and " (final chunk)" or " (more chunks)")
            subtree:add(f.phase, phase_str):set_generated()
            if is_init then
                subtree:add_proto_expert_info(expert_init_reply)
                pinfo.cols.info:append(" [Upload INIT reply]")
            else
                subtree:add_proto_expert_info(expert_cont_reply)
                pinfo.cols.info:append(" [Upload CONT reply]")
            end
            local chunk_off = 4
            if not is_init and body_range:len() >= 8 then
                subtree:add_le(f.token_echo, body_range(4, 4))
                chunk_off = 8
            end
            if body_range:len() > chunk_off then
                local chunk = body_range(chunk_off, body_range:len() - chunk_off)
                subtree:add(f.payload_chunk, chunk)
                -- Locate zlib magic ("78 9c", "78 da", "78 01") anywhere
                -- within the chunk. INIT replies prefix the zlib stream
                -- with a small header (typically 16 B); continuation
                -- replies often start directly with zlib data.
                local clen = chunk:len()
                local zoff = nil
                for i = 0, math.min(clen - 2, 256) do
                    local b0 = chunk(i, 1):uint()
                    if b0 == 0x78 then
                        local b1 = chunk(i + 1, 1):uint()
                        if b1 == 0x9c or b1 == 0xda or b1 == 0x01 then
                            zoff = i
                            break
                        end
                    end
                end
                if zoff then
                    if zoff > 0 then
                        subtree:add(f.chunk_header, chunk(0, zoff))
                    end
                    local zlib_range = chunk(zoff, clen - zoff)
                    subtree:add(f.zlib_stream, zlib_range)
                    subtree:add(f.zlib_offset, zoff):set_generated()
                    -- Inflate gated by preference, and only when this
                    -- INIT reply is complete-in-one-frame (state 0x03).
                    -- Multi-frame reassembly is not wired up yet.
                    if proto.prefs.inflate and state == 0x03 then
                        local zbytes = zlib_range:bytes():raw()
                        local ok, result = pcall(inflate.inflate, zbytes)
                        if ok then
                            -- ProtoField.bytes needs a ByteArray-backed
                            -- Tvb range, not a raw Lua string. Synthesise
                            -- one via the hex encoding.
                            local hex = sha1.to_hex(result)
                            local tvb_buf = ByteArray.new(hex):tvb("inflated")
                            subtree:add(f.inflated, tvb_buf:range())
                                :set_generated()
                            subtree:add(f.inflated_size, #result)
                                :set_generated()
                        else
                            subtree:add(f.inflate_error,
                                tostring(result)):set_generated()
                        end
                    end
                end
            end
        end
    end

    local function dissect(tvb, pinfo, tree)
        local svc_fi = field_cip_service()
        if not svc_fi then return end
        local svc = svc_fi.value
        if svc ~= 0x3A and svc ~= 0xBA then return end

        local svc_range = svc_fi.range
        if not svc_range then return end
        local cip_start = svc_range:offset()
        if cip_start + 24 > tvb:len() then return end

        local cip_tvb = tvb:range(cip_start)
        local last    = cip_tvb:len()
        local trailer = 24                    -- seq u32 + HMAC 20B
        if last < trailer + 1 then return end

        local subtree = tree:add(proto, cip_tvb,
            string.format("Rockwell upload wrapper (0x%02X)", svc))
        subtree:add(f.service, cip_tvb(0, 1))

        local offset = 1
        if svc == 0x3A then
            local path_words = cip_tvb(offset, 1):uint()
            subtree:add(f.path_size, cip_tvb(offset, 1))
            offset = offset + 1
            local pb = path_words * 2
            if offset + pb > last - trailer then return end
            subtree:add(f.path, cip_tvb(offset, pb))
            offset = offset + pb
        else
            offset = offset + 1                -- reserved
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

        local body_len = last - trailer - offset
        if body_len > 0 then
            local body_range = cip_tvb(offset, body_len)
            decode_body(body_range, subtree, pinfo, svc == 0xBA)
            offset = offset + body_len
        end

        pinfo.cols.info:append(
            svc == 0x3A and " [Upload Send]" or " [Upload Reply]")

        local seq_range = cip_tvb(offset, 4)
        subtree:add_le(f.seq, seq_range)
        offset = offset + 4
        local hmac_range = cip_tvb(offset, 20)
        local hmac_tree = subtree:add(f.hmac, hmac_range)

        -- HMAC validation — same scheme as 0x36.
        local mac_end = last - 20
        local body    = cip_tvb(0, mac_end):bytes():raw()
        local got     = hmac_range:bytes():raw()

        local function try_key(k) return sha1.hmac(k, body) == got end

        -- See service_36_signed.lua for the rationale on the multi-key
        -- resolution order — same path here since both wrappers share
        -- the per-CIP-connection HMAC keying.
        local connid_fi = field_cip_connid()
        local connid    = connid_fi and connid_fi.value
        local matched   = false
        local key       = nil

        if connid then
            local cached = session.key_for_connid(pinfo, connid)
            if cached and try_key(cached) then
                matched = true
                key     = cached
            end
        end

        if not matched then
            local eff = session.effective_key(pinfo)
            if eff and try_key(eff) then
                matched = true
                key     = eff
                if connid then
                    session.cache_key_for_connid(pinfo, connid, eff)
                end
            elseif eff then
                key = eff
            end
        end

        if not matched then
            for _, k in ipairs(session.hmac_keys(pinfo)) do
                if try_key(k) then
                    matched = true
                    key     = k
                    if connid then
                        session.cache_key_for_connid(pinfo, connid, k)
                    end
                    break
                end
            end
        end

        if not matched then
            local sess = session.get(pinfo)
            for _, candidate in ipairs(session.candidate_keys(pinfo)) do
                if try_key(candidate) then
                    matched = true
                    key = candidate
                    sess.hmac_key = candidate
                    break
                end
            end
        end
        if matched then
            subtree:add(f.hmac_status, "OK"):set_generated()
            hmac_tree:add_proto_expert_info(expert_hmac_ok)
        elseif key then
            local expected = sha1.hmac(key, body)
            subtree:add(f.hmac_status, "MISMATCH"):set_generated()
            subtree:add(f.hmac_expected,
                ByteArray.new(sha1.to_hex(expected)):tvb("expected hmac"):range())
                :set_generated()
            hmac_tree:add_proto_expert_info(expert_hmac_fail)
            pinfo.cols.info:append(" [BAD HMAC]")
        else
            subtree:add(f.hmac_status,
                "(no key — set rockwell_cip.hmac_key preference)"):set_generated()
            hmac_tree:add_proto_expert_info(expert_hmac_unknown)
        end
    end

    ctx.add_dissect("service_3a_upload", dissect)
end

return M
