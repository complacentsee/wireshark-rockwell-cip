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
-- Algorithm (Path-A KDF, recovered from firmware FUN_f4190f00 — see
-- hmac_connect.py:1-49,106-122 in the out-of-tree Python parser for
-- the authoritative reference):
--
--   1. PLC issues 128B `challenge_nonce` — that's the CIPHERTEXT of
--      RSA-encrypting a 128B plaintext blob with the *client*'s public
--      key. Reading the nonce in the clear tells you nothing.
--   2. Client RSA-decrypts with its private key, reading and writing
--      with LITTLE-ENDIAN byte order (Rockwell-specific; PKCS#1 uses
--      big-endian — easy to get wrong).
--   3. The HMAC session key is `plaintext[0:64]`. The Phase 2 response
--      that unlocks signing is `SHA-1^20(plaintext[0:64])` — twenty
--      sequential SHA-1 applications starting from the 64-byte key.
--   4. On Phase 2 success the firmware sets ctx[+0x2FA] = 1, caches K
--      as the session HMAC key, and expects seq starting at 1.
--
-- An earlier draft of this module guessed `SHA-1^20(challenge[0:64])`
-- (i.e. of the ciphertext). That fails — the input has to be the
-- decrypted plaintext, which requires the client's RSA private key.
--
-- Two paths to a derived key:
--   * If the user provides the client RSA private key (the
--     `rockwell_cip.client_rsa_key_file` preference, PEM or DER), we
--     RSA-decrypt the Phase 1 challenge here and stash plaintext[0:64]
--     as the session HMAC key. service_36_signed picks it up from
--     `session.effective_key` with no further wiring.
--   * If the user already derived the key out-of-band (`tools/derive_
--     hmac_key.py` or any other path), they paste it as 128 hex chars
--     into the `rockwell_cip.hmac_key` preference; same downstream.
--
-- This module also:
--   * Annotates Phase 1 / Phase 2 messages with byte ranges for the
--     challenge and response as named ProtoFields.
--   * Caches challenge[0:64] AND challenge[64:128] of the CIPHERTEXT
--     as candidate keys for service_36_signed.lua's fallback path —
--     those candidates rarely match, but they cost ~nothing to try
--     and are useful when the user supplies neither preference but
--     wants a "would-have-worked-if-key-were-trivial" signal.
--   * Does NOT claim "OK" / "FAIL" verdicts on its own — verdicts come
--     from service_36_signed/service_3a_upload, which key off the
--     resolved session key (preference > derived > candidate).

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
    f.derived_hmac    = ProtoField.bytes("rockwell_cip.handshake.derived_hmac_key",
        "Derived HMAC key (plaintext[0:64])", base.SPACE)
    f.kdf_status      = ProtoField.string("rockwell_cip.handshake.kdf_status",
        "Path-A KDF")

    for _, fld in pairs(f) do ctx.add_field(fld) end

    local expert_phase1 = ProtoExpert.new(
        "rockwell_cip.handshake.phase1",
        "Path-A Phase 1: PLC issued challenge",
        expert.group.SECURITY, expert.severity.NOTE)
    local expert_phase2 = ProtoExpert.new(
        "rockwell_cip.handshake.phase2",
        "Path-A Phase 2: client sent response",
        expert.group.SECURITY, expert.severity.NOTE)
    local expert_kdf_ok = ProtoExpert.new(
        "rockwell_cip.handshake.kdf_ok",
        "Path-A KDF: derived HMAC session key from RSA private key",
        expert.group.SECURITY, expert.severity.NOTE)
    local expert_kdf_fail = ProtoExpert.new(
        "rockwell_cip.handshake.kdf_fail",
        "Path-A KDF: RSA decrypt failed (wrong key for this stream?)",
        expert.group.SECURITY, expert.severity.WARN)
    local expert_no_key = ProtoExpert.new(
        "rockwell_cip.handshake.no_key",
        "Path-A KDF: no client RSA private key preference set — "
        .. "HMAC validation will fall back to the rockwell_cip.hmac_key "
        .. "preference if provided",
        expert.group.SECURITY, expert.severity.NOTE)
    ctx.add_expert(expert_phase1)
    ctx.add_expert(expert_phase2)
    ctx.add_expert(expert_kdf_ok)
    ctx.add_expert(expert_kdf_fail)
    ctx.add_expert(expert_no_key)

    -- Preference: client RSA private key (PEM or DER). When set, the
    -- handshake dissector RSA-decrypts each Phase 1 challenge it sees
    -- on this stream, then stashes plaintext[0:64] as the session
    -- HMAC key. service_36_signed.lua / service_3a_upload.lua pick
    -- that up via session.effective_key without further wiring.
    --
    -- See class_0064_handshake.lua's header comment for the protocol
    -- specifics — Rockwell's challenge nonce is LITTLE-ENDIAN on the
    -- wire as an RSA integer, which is opposite of textbook PKCS#1.
    proto.prefs.client_rsa_key_file = Pref.string(
        "Path-A: Client RSA private key file (PEM or DER)",
        "",
        "Path to the client's RSA private key. When set, every Phase "
        .. "1 reply on this conversation is RSA-decrypted to recover "
        .. "the 64-byte HMAC session key (= plaintext[0:64]). PKCS#1 "
        .. "and unencrypted PKCS#8 PEMs are both accepted; the key "
        .. "must be the SAME key the client used to mint the "
        .. "certificate sent in Phase 1, otherwise the decrypt "
        .. "produces garbage. Leave empty to skip the KDF and rely on "
        .. "the rockwell_cip.hmac_key preference (if set) for HMAC "
        .. "verdicts.")

    -- Parsed-key cache. Re-parses when the preference string changes;
    -- the parsed key is reused across all streams on the same Lua run.
    -- A bad path / bad PEM is cached as `false` so we don't retry on
    -- every dissect.
    local rsa, pem, bigint, sha1, modexp_cache
    local cached_key_path = nil
    local cached_key      = nil
    -- SHA-1 of the raw key-file bytes, used as the partition key for
    -- the on-disk modexp cache. Recomputed whenever the preference
    -- path changes; nil if the file couldn't be read.
    local cached_key_hash = nil

    local function load_rsa_key()
        local path = proto.prefs.client_rsa_key_file
        if path == cached_key_path then return cached_key end
        cached_key_path = path
        cached_key_hash = nil
        if not path or path == "" then
            cached_key = nil
            return nil
        end
        -- Lazy-load the heavy modules so dissectors that don't use
        -- the key preference don't pay the load cost.
        rsa          = rsa          or require "rsa"
        pem          = pem          or require "pem"
        bigint       = bigint       or require "bigint"
        sha1         = sha1         or require "sha1"
        modexp_cache = modexp_cache or require "modexp_cache"
        local ok, parsed = pcall(pem.parse_private_key, path)
        if not ok then
            io.stderr:write(string.format(
                "[rockwell_cip] failed to load RSA key from %s: %s\n",
                path, parsed))
            cached_key = false
            return nil
        end
        cached_key      = parsed
        cached_key_hash = modexp_cache.hash_key_file(path)
        return parsed
    end

    -- Decrypt the Phase 1 challenge and stash the resulting HMAC key.
    -- A single ENIP TCP stream can carry many concurrent (and
    -- sequential) CIP connections, each opened by its own Forward
    -- Open + Phase 1 with a fresh challenge nonce — every Phase 1
    -- produces a *different* HMAC key. We append each derived key to
    -- the session's key list; the signed-frame dissectors try them
    -- all and cache the connid→key mapping on first match. Pass-2 of
    -- `tshark -2` (and any frame re-dissect) hits the
    -- keys_by_challenge cache so we don't repeat the ~3s modexp.
    --
    -- Across runs: util/modexp_cache.lua persists derived keys to
    -- ~/.cache/rockwell_cip/hmac_modexp_cache.bin, partitioned by
    -- sha1(key_file_bytes). The first dissect of a capture populates
    -- it; reopens skip the modexp entirely. Cache hits and disk-cache
    -- writes are silent (no extra expert info) because the user-
    -- facing behaviour is identical.
    --
    -- Returns "derived" / "already-set" / "no-key" / "failed".
    local function derive_hmac_key(sess, challenge_bytes, subtree)
        sess.keys_by_challenge = sess.keys_by_challenge or {}
        local cached = sess.keys_by_challenge[challenge_bytes]
        if cached then
            sess.hmac_key = cached
            return "already-set"
        end
        local key = load_rsa_key()
        if not key then return "no-key" end

        -- On-disk cache check before the expensive pure-Lua modexp.
        local disk = cached_key_hash and modexp_cache
            and modexp_cache.lookup(cached_key_hash, challenge_bytes)
        local hmac_key
        if disk then
            hmac_key = disk
        else
            local ok, result = pcall(rsa.decrypt, challenge_bytes, key,
                                     { byte_order = "le", width = 128 })
            if not ok then
                io.stderr:write(string.format(
                    "[rockwell_cip] RSA decrypt failed: %s\n", result))
                return "failed"
            end
            if #result < 64 then return "failed" end
            hmac_key = result:sub(1, 64)
            if cached_key_hash and modexp_cache then
                modexp_cache.store(cached_key_hash, challenge_bytes,
                                   hmac_key)
            end
        end

        sess.keys_by_challenge[challenge_bytes] = hmac_key
        sess.hmac_keys = sess.hmac_keys or {}
        table.insert(sess.hmac_keys, hmac_key)
        sess.hmac_key = hmac_key
        return "derived"
    end

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
            local kdf_status = "skipped (body_len != 128)"
            if body_len == 128 then
                local challenge_range = cip_tvb(6, 128)
                subtree:add(f.challenge, challenge_range)
                subtree:add(f.challenge_lo, challenge_range:range(0, 64))
                subtree:add(f.challenge_hi, challenge_range:range(64, 64))
                local raw = challenge_range:bytes():raw()
                sess.challenge        = raw
                sess.candidate_key_lo = raw:sub(1, 64)
                sess.candidate_key_hi = raw:sub(65, 128)

                -- Attempt the Path-A KDF: RSA-decrypt the challenge with
                -- the configured client private key and stash the
                -- derived session HMAC key (= plaintext[0:64]). No-ops
                -- silently when the preference is unset or the key
                -- already matched a prior frame on this conversation.
                local result = derive_hmac_key(sess, raw, subtree)
                if result == "derived" or result == "already-set" then
                    -- ProtoField.bytes wants a TvbRange, not a raw Lua
                    -- string — synthesize a one-off Tvb from the hex.
                    subtree:add(f.derived_hmac,
                        ByteArray.new(sha1.to_hex(sess.hmac_key))
                            :tvb("derived hmac key"):range()
                    ):set_generated()
                end
                if result == "derived" then
                    subtree:add(f.kdf_status, "derived"):set_generated()
                    subtree:add_proto_expert_info(expert_kdf_ok)
                    kdf_status = "derived"
                elseif result == "already-set" then
                    subtree:add(f.kdf_status, "already-derived"):set_generated()
                    kdf_status = "already-derived"
                elseif result == "no-key" then
                    subtree:add(f.kdf_status,
                        "(no client RSA key set)"):set_generated()
                    subtree:add_proto_expert_info(expert_no_key)
                    kdf_status = "no-key"
                elseif result == "failed" then
                    subtree:add(f.kdf_status, "FAILED"):set_generated()
                    subtree:add_proto_expert_info(expert_kdf_fail)
                    kdf_status = "failed"
                end
            end
            subtree:add(f.phase, "1 reply (challenge)"):set_generated()
            subtree:add_proto_expert_info(expert_phase1)
            pinfo.cols.info:append(string.format(
                " [Path-A Phase 1 reply, KDF: %s]", kdf_status))
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
