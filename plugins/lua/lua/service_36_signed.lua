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
--                               keyed with the Path-A session key
--                               (= the 64-byte plaintext challenge[0:64]
--                                  exchanged during 0x4C/0x64 Phase 1/2).
--
-- Reply layout (service 0xB6):
--     0xB6 00 <gen_status> <ext_size_words> [<ext_status words>]
--     <inner CIP reply>
--     <seq u32 LE>
--     <HMAC-SHA1 20B>
--
-- We run as a post-dissector: read cip.service back from the stock
-- dissector's output, decode the wrapper structure ourselves, recurse
-- the inner CIP back through the built-in 'cip' dissector so it
-- renders as a normal CIP tree, and (when we have the session key
-- — either auto-derived by class_0064_handshake or supplied via the
-- user preference) validate the HMAC trailer.

local M = {}

function M.register(proto, valstr, ctx)
    local sha1    = require "sha1"
    local session = require "session"

    local f = {}
    f.service     = ProtoField.uint8("rockwell_cip.signed.service",
        "Signed Service", base.HEX, valstr.services)
    f.path_size   = ProtoField.uint8("rockwell_cip.signed.path_size",
        "Outer Path Size (words)", base.DEC)
    f.path        = ProtoField.bytes("rockwell_cip.signed.path",
        "Outer Path", base.SPACE)
    f.inner       = ProtoField.bytes("rockwell_cip.signed.inner_cip",
        "Inner CIP", base.SPACE)
    f.seq         = ProtoField.uint32("rockwell_cip.signed.seq",
        "Session Sequence", base.DEC)
    f.hmac        = ProtoField.bytes("rockwell_cip.signed.hmac",
        "HMAC-SHA1 Trailer", base.SPACE)
    f.hmac_status = ProtoField.string("rockwell_cip.signed.hmac_status",
        "HMAC Validation")
    f.hmac_expected = ProtoField.bytes("rockwell_cip.signed.hmac_expected",
        "Expected HMAC", base.SPACE)
    f.gen_status  = ProtoField.uint8("rockwell_cip.signed.gen_status",
        "General Status", base.HEX)
    f.ext_words   = ProtoField.uint8("rockwell_cip.signed.ext_status_words",
        "Extended Status (words)", base.DEC)

    -- Expert info entries — show up in Wireshark's expert-info pane
    -- and the per-frame info column.
    local expert_hmac_ok = ProtoExpert.new(
        "rockwell_cip.signed.hmac_ok",
        "HMAC trailer verified",
        expert.group.SECURITY, expert.severity.NOTE)
    local expert_hmac_fail = ProtoExpert.new(
        "rockwell_cip.signed.hmac_fail",
        "HMAC trailer mismatch",
        expert.group.SECURITY, expert.severity.WARN)
    local expert_hmac_unknown = ProtoExpert.new(
        "rockwell_cip.signed.hmac_unknown",
        "HMAC not validated (no session key available)",
        expert.group.SECURITY, expert.severity.NOTE)

    for _, fld in pairs(f) do ctx.add_field(fld) end
    ctx.add_expert(expert_hmac_ok)
    ctx.add_expert(expert_hmac_fail)
    ctx.add_expert(expert_hmac_unknown)

    -- Preference: 64-byte HMAC session key as hex. When the capture
    -- doesn't contain the Path-A handshake, the user can paste the key
    -- here and we'll use it for HMAC validation.
    proto.prefs.hmac_key = Pref.string(
        "HMAC session key (hex)",
        "",
        "Optional 64-byte HMAC-SHA1 session key, written as 128 hex "
        .. "characters. Used to validate the trailer on every "
        .. "0x36/0xB6 (and 0x3A/0xBA) frame when class_0064_handshake "
        .. "couldn't derive the key automatically (typical when the "
        .. "capture starts mid-session). Get this from a successful "
        .. "Path-A handshake (challenge[0:64]).")

    -- Sync preference into the session module whenever Wireshark reloads
    -- prefs. We don't have a callback for "prefs changed", but checking
    -- on every dissect is cheap.
    local function sync_pref()
        local hex = proto.prefs.hmac_key
        if hex and hex ~= "" then session.set_override(hex)
        else session.set_override(nil) end
    end

    local field_cip_service = Field.new("cip.service")
    local cip_dis = Dissector.get("cip")

    local function dissect(tvb, pinfo, tree)
        sync_pref()

        local svc_fi = field_cip_service()
        if not svc_fi then return end
        local svc = svc_fi.value
        if svc ~= 0x36 and svc ~= 0xB6 then return end

        local svc_range = svc_fi.range
        if not svc_range then return end
        local cip_start = svc_range:offset()
        if cip_start + 24 > tvb:len() then return end

        local cip_tvb = tvb:range(cip_start)
        local subtree = tree:add(proto, cip_tvb,
            string.format("Rockwell signed-CIP wrapper (0x%02X)", svc))
        subtree:add(f.service, cip_tvb(0, 1))
        -- We defer pinfo.cols.info:append until AFTER the inner-CIP
        -- recursion so it doesn't get clobbered by the stock cip
        -- dissector overwriting the info column.

        local offset = 1
        local trailer = 24
        local last = cip_tvb:len()
        if last < offset + trailer then return end

        -- Surface the trailing seq to sibling dissectors via
        -- pinfo.private. We need it available BEFORE we recurse into
        -- the inner cip dissector, because callbacks that fire on the
        -- inner-CIP fields (e.g. class_0349_docs pairing request to
        -- reply) read it. pinfo.private values are string-typed.
        local seq_value = cip_tvb(last - trailer, 4):le_uint()
        pinfo.private["rockwell_cip.signed.seq"] = tostring(seq_value)

        local mac_start = 0
        if svc == 0x36 then
            local path_words = cip_tvb(offset, 1):uint()
            subtree:add(f.path_size, cip_tvb(offset, 1))
            offset = offset + 1
            local path_bytes = path_words * 2
            if offset + path_bytes > last - trailer then return end
            subtree:add(f.path, cip_tvb(offset, path_bytes))
            offset = offset + path_bytes
        else
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
            local inner_range = cip_tvb(offset, inner_len)
            subtree:add(f.inner, inner_range)

            -- Recurse: hand the inner CIP back to Wireshark's stock
            -- dissector so it renders as a normal CIP tree instead of
            -- opaque bytes. We pass the inner range as a Tvb. The
            -- stock dissector adds its own top-level "Common Industrial
            -- Protocol" tree; that's the desired behaviour — the inner
            -- request looks just like an unwrapped one would.
            if cip_dis then
                local inner_tvb = inner_range:tvb()
                local ok = pcall(function()
                    cip_dis:call(inner_tvb, pinfo,
                        subtree:add(proto, inner_range,
                            "Inner CIP (decoded)"))
                end)
                if not ok then
                    -- Don't let a bad inner derail the rest of the frame.
                end
            end
            offset = offset + inner_len
        end

        -- Inner CIP dispatch is done; now safe to tag the info column.
        pinfo.cols.info:append(
            svc == 0x36 and " [Signed Send]" or " [Signed Reply]")

        -- Trailer.
        local seq_range = cip_tvb(offset, 4)
        subtree:add_le(f.seq, seq_range)
        offset = offset + 4
        local hmac_range = cip_tvb(offset, 20)
        local hmac_tree = subtree:add(f.hmac, hmac_range)

        -- HMAC validation. Bytes that participate are everything from
        -- the outer service byte up to and including the seq u32
        -- (cip_tvb[0..mac_end-1]).
        local mac_end = last - 20
        local body = cip_tvb(0, mac_end):bytes():raw()
        local got  = hmac_range:bytes():raw()

        local function try_key(k)
            return sha1.hmac(k, body) == got
        end

        local key = session.effective_key(pinfo)
        local matched = false
        if key and try_key(key) then
            matched = true
        else
            -- Fall back to candidate keys from the handshake.
            -- If one matches, promote it on the session so future
            -- frames use it directly.
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
            -- We had a key (preference or session) but it didn't match.
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

    ctx.add_dissect("service_36_signed", dissect)
end

return M
