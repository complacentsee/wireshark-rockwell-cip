-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- session.lua — per-stream session state for the Rockwell-private CIP
-- dissectors.
--
-- Two dissectors need to share state across packets:
--   1. class_0064_handshake observes Phase 1 (challenge) and Phase 2
--      (response) on class 0x64 and stashes both candidate halves of
--      the challenge as potential HMAC keys.
--   2. service_36_signed needs an HMAC-SHA1 key later to validate the
--      trailer on every 0x36/0xB6 frame.
--
-- A "session" here is a single ENIP TCP stream identified by
-- (src_ip, src_port, dst_ip, dst_port); the canonical-ordered tuple
-- makes request and reply hash to the same bucket.
--
-- Key sources, in priority order:
--   1. User preference (rockwell_cip.hmac_key) — applies to every
--      stream. Use this when the algorithm is known or the key was
--      recovered out-of-band.
--   2. Session-cached key set by service_36_signed after a candidate
--      from the handshake was confirmed to validate at least one HMAC
--      trailer.
-- (No "auto-derive" path is unconditional, because the KDF that turns
-- the 128B challenge into the HMAC key is not yet reverse-engineered.)

local M = {}

local sessions = {}

local function key_for(pinfo)
    local a = tostring(pinfo.src) .. ":" .. pinfo.src_port
    local b = tostring(pinfo.dst) .. ":" .. pinfo.dst_port
    if a < b then return a .. "|" .. b end
    return b .. "|" .. a
end

function M.get(pinfo)
    local k = key_for(pinfo)
    local s = sessions[k]
    if not s then
        s = {
            challenge        = nil,   -- 128B Phase 1 reply body
            candidate_key_lo = nil,   -- challenge[0:64]
            candidate_key_hi = nil,   -- challenge[64:128]
            response         = nil,   -- 20B Phase 2 request body
            hmac_key         = nil,   -- key proven to validate HMACs
                                       -- on this stream (set by signed)
        }
        sessions[k] = s
    end
    return s
end

local override_key = nil

function M.set_override(hex_key)
    if not hex_key or hex_key == "" then
        override_key = nil
        return true
    end
    local sha1 = require "sha1"
    local raw = sha1.from_hex(hex_key)
    if not raw then return false end
    if #raw ~= 64 then return false end
    override_key = raw
    return true
end

function M.override_key()
    return override_key
end

-- Returns the key the dissector should USE for HMAC validation now —
-- preference wins over any session-cached confirmed key.
function M.effective_key(pinfo)
    if override_key then return override_key end
    local s = M.get(pinfo)
    return s.hmac_key
end

-- Returns ordered list of keys to try when no effective_key is known
-- yet (preference unset, no confirmed session key). Empty when the
-- handshake wasn't observed on this stream.
function M.candidate_keys(pinfo)
    local s = M.get(pinfo)
    local out = {}
    if s.candidate_key_lo then table.insert(out, s.candidate_key_lo) end
    if s.candidate_key_hi then table.insert(out, s.candidate_key_hi) end
    return out
end

function M.reset()
    sessions = {}
end

return M
