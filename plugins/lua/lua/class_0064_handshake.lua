-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- class_0064_handshake.lua — Studio 5000 Path-A authentication handshake
-- (CIP class 0x0064).
--
-- Four messages observed in upload.pcapng (Studio v36 ↔ ControlLogix):
--
--   Phase 1 request:  client → PLC, service 0x4B on class 0x64.
--   Phase 1 reply:    PLC → client, service 0xCB. CIP body starts with
--                     a u16-LE length prefix (0x0080 = 128) followed by
--                     128 bytes of challenge / nonce material.
--   Phase 2 request:  client → PLC, service 0x4C on class 0x64. CIP body
--                     starts with a u16-LE length prefix (0x0014 = 20)
--                     followed by 20 bytes of response material.
--   Phase 2 reply:    PLC → client, service 0xCC. Tiny success ack
--                     (license_status u16 at the tail).
--
-- IMPORTANT — algorithm note:
--   An earlier draft of this dissector claimed the Phase 2 response was
--   SHA-1^20(challenge[0:64]) and that the resulting key was used to
--   HMAC-SHA1-sign every 0x36/0xBA frame. That hypothesis fails against
--   captured bytes (SHA-1^n / HMAC permutations were searched and none
--   match). The actual KDF / signing function is not yet reverse-
--   engineered.
--
--   So this module:
--     * Annotates Phase 1 / Phase 2 messages, breaks out the challenge
--       and response byte ranges as named ProtoFields.
--     * Marks each frame with the role it plays in the handshake.
--     * Caches challenge[0:64] AND challenge[64:128] on the session for
--       service_36_signed.lua to use as candidate HMAC keys; signed
--       only treats them as candidates when the user has NOT supplied
--       a preference key.
--     * Does NOT claim "OK" / "FAIL" verdicts because we can't compute
--       the expected value yet.
--
--   When the algorithm is recovered (likely from a packet trace where
--   the secret can be observed, or from controller firmware), update
--   the dissect() body to compute the expected response and HMAC and
--   wire the corresponding expert info back up.

local M = {}

function M.register(proto, valstr, ctx)
    local session = require "session"

    local f = {}
    f.phase           = ProtoField.string("rockwell_cip.handshake.phase",
        "Handshake Phase")
    f.body_len        = ProtoField.uint16("rockwell_cip.handshake.body_len",
        "Body Length", base.DEC)
    f.challenge       = ProtoField.bytes("rockwell_cip.handshake.challenge",
        "Phase 1 Challenge", base.SPACE)
    f.challenge_lo    = ProtoField.bytes("rockwell_cip.handshake.challenge_lo",
        "challenge[0:64] (candidate HMAC key — unverified)", base.SPACE)
    f.challenge_hi    = ProtoField.bytes("rockwell_cip.handshake.challenge_hi",
        "challenge[64:128]", base.SPACE)
    f.response        = ProtoField.bytes("rockwell_cip.handshake.response",
        "Phase 2 Response", base.SPACE)
    f.license_status  = ProtoField.uint16("rockwell_cip.handshake.license_status",
        "License Status", base.HEX)

    for _, fld in pairs(f) do ctx.add_field(fld) end

    local expert_phase1 = ProtoExpert.new(
        "rockwell_cip.handshake.phase1",
        "Path-A Phase 1: PLC issued challenge",
        expert.group.SECURITY, expert.severity.NOTE)
    local expert_phase2 = ProtoExpert.new(
        "rockwell_cip.handshake.phase2",
        "Path-A Phase 2: client sent response",
        expert.group.SECURITY, expert.severity.NOTE)
    local expert_alg_unknown = ProtoExpert.new(
        "rockwell_cip.handshake.alg_unknown",
        "Auth KDF / response algorithm not yet reverse-engineered",
        expert.group.PROTOCOL, expert.severity.NOTE)
    ctx.add_expert(expert_phase1)
    ctx.add_expert(expert_phase2)
    ctx.add_expert(expert_alg_unknown)

    local field_cip_service = Field.new("cip.service")
    local field_cip_class   = Field.new("cip.class")

    local function dissect(tvb, pinfo, tree)
        local svc_fi = field_cip_service()
        if not svc_fi then return end
        local svc = svc_fi.value
        if svc ~= 0x4B and svc ~= 0xCB
            and svc ~= 0x4C and svc ~= 0xCC then return end

        -- Service codes 0x4B / 0x4C are also used for Get Instance
        -- Attribute List / Read Template — gate on class 0x64.
        local class_fi = field_cip_class()
        if class_fi and class_fi.value ~= 0x64 then return end

        local svc_range = svc_fi.range
        if not svc_range then return end
        local cip_start = svc_range:offset()
        local cip_tvb = tvb:range(cip_start)
        if cip_tvb:len() < 4 then return end
        local subtree = tree:add(proto, cip_tvb, "Rockwell Path-A handshake")

        local sess = session.get(pinfo)

        if svc == 0x4B then
            subtree:add(f.phase, "1 request"):set_generated()
            pinfo.cols.info:append(" [Path-A Phase 1 request]")
        elseif svc == 0xCB then
            -- Reply layout: svc(1) rsv(1) gen(1) ext_size(1) body_len(u16 LE) body
            if cip_tvb:len() < 6 then return end
            local body_len = cip_tvb(4, 2):le_uint()
            subtree:add_le(f.body_len, cip_tvb(4, 2))
            if cip_tvb:len() < 6 + body_len then return end
            if body_len == 128 then
                local challenge_range = cip_tvb(6, 128)
                subtree:add(f.challenge, challenge_range)
                subtree:add(f.challenge_lo, challenge_range:range(0, 64))
                subtree:add(f.challenge_hi, challenge_range:range(64, 64))
                local raw = challenge_range:bytes():raw()
                sess.challenge        = raw
                sess.candidate_key_lo = raw:sub(1, 64)
                sess.candidate_key_hi = raw:sub(65, 128)
            end
            subtree:add(f.phase, "1 reply (challenge)"):set_generated()
            subtree:add_proto_expert_info(expert_phase1)
            subtree:add_proto_expert_info(expert_alg_unknown)
            pinfo.cols.info:append(" [Path-A Phase 1 reply]")
        elseif svc == 0x4C then
            -- Request layout: svc(1) path_size(1) path(path_size*2) body_len(u16 LE) body
            if cip_tvb:len() < 2 then return end
            local path_size = cip_tvb(1, 1):uint()
            local hdr_len = 2 + path_size * 2
            if cip_tvb:len() < hdr_len + 2 then return end
            local body_len = cip_tvb(hdr_len, 2):le_uint()
            subtree:add_le(f.body_len, cip_tvb(hdr_len, 2))
            if cip_tvb:len() >= hdr_len + 2 + body_len then
                subtree:add(f.response, cip_tvb(hdr_len + 2, body_len))
                sess.response = cip_tvb(hdr_len + 2, body_len):bytes():raw()
            end
            subtree:add(f.phase, "2 request (response)"):set_generated()
            subtree:add_proto_expert_info(expert_phase2)
            subtree:add_proto_expert_info(expert_alg_unknown)
            pinfo.cols.info:append(" [Path-A Phase 2 request]")
        elseif svc == 0xCC then
            subtree:add(f.phase, "2 reply (server ack)"):set_generated()
            if cip_tvb:len() >= 2 then
                subtree:add_le(f.license_status,
                    cip_tvb(cip_tvb:len() - 2, 2))
            end
            pinfo.cols.info:append(" [Path-A Phase 2 reply]")
        end
    end

    ctx.add_dissect("class_0064_handshake", dissect)
end

return M
