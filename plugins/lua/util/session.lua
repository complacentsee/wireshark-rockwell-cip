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
            -- HMAC keys derived on this stream. One TCP stream can
            -- carry many concurrent / sequential CIP connections,
            -- each authed by its own Phase 1 with a fresh challenge
            -- nonce, so the set grows over time. The signed-frame
            -- dissectors try every key in `hmac_keys` and cache the
            -- match on `connid_to_key` for O(1) lookup thereafter.
            hmac_key          = nil,   -- most recently derived key
                                        -- (legacy "current key" used
                                        --  as the first candidate)
            hmac_keys         = nil,   -- list of all derived keys for
                                        -- this stream, in observed
                                        -- order; lazily allocated
            keys_by_challenge = nil,   -- challenge_bytes -> key, used
                                        -- by the handshake module to
                                        -- skip the modexp on pass 2
                                        -- of `tshark -2`
            connid_to_key     = nil,   -- cip.connid -> matched key,
                                        -- populated by signed dissect
                                        -- on first verified frame
            pending_requests = {
                by_seq   = {},        -- [signed seq u32] -> req record
                by_frame = {},        -- [req frame number] -> req record
            },
            -- Class 0x0349 paginated-read accumulator state. The 0x53
            -- reply on class 0x349 is a stream of fixed-stride pages
            -- (v36: 458B) whose record bodies routinely straddle page
            -- boundaries — see cip_upload/extract_logix_data.py:1090.
            -- Pagination is driven by the client's request-offset and
            -- there is no per-chunk header on the wire to key off
            -- frame-globally, so each accumulator is scoped to a
            -- (TCP-stream, cip.connid) pair: one TCP stream can carry
            -- multiple concurrent CIP connections, each running its
            -- own 0x349 read, and splicing their pages into one buffer
            -- would corrupt the record walk across the boundary.
            docs_streams     = nil,    -- connid -> stream record;
                                       -- lazily allocated
        }
        sessions[k] = s
    end
    return s
end

-- Stable map key for cip.connid. nil collapses to a single shared
-- "unknown" bucket — that matches pre-E3 behavior for code paths where
-- connid isn't surfaced (older non-signed replies).
local function connid_key(connid)
    if connid == nil then return 0 end
    return connid
end

-- Open (or reset) the per-(conversation, connid) docs accumulator.
-- Called when a 0x349 reply arrives and either no stream is in flight
-- on this connid or the prior stream has been closed. `frame_results`
-- survives the reset so cached per-frame render data from the prior
-- stream isn't lost.
function M.docs_stream_open(pinfo, connid)
    local s = M.get(pinfo)
    s.docs_streams = s.docs_streams or {}
    local key = connid_key(connid)
    local prior = s.docs_streams[key]
    local prior_results = prior and prior.frame_results or {}
    s.docs_streams[key] = {
        -- 1-indexed list of ingested chunks in arrival order:
        --   { frame = u32, accum_off = u32, page_size = u32 }
        chunks          = {},
        -- Concatenated page_data (post 8B echo strip) of every chunk.
        -- Lua string so substring / byte indexing are cheap.
        accumulator     = "",
        -- Bytes [walk_pos..#accumulator) are unparsed — either an
        -- in-progress record's tail or the next record's header.
        walk_pos        = 0,
        -- Page size of the first chunk; used for short-page close.
        first_page_size = nil,
        -- Echoed request page offset of the most recently ingested
        -- chunk. Consecutive contiguous pages advance by page_size
        -- exactly; a different delta means the carved fixture (or
        -- packet loss) skipped intermediate pages and we should reset
        -- the accumulator rather than corrupt cross-chunk records by
        -- splicing non-adjacent bytes.
        last_req_offset = nil,
        -- Set after a short page / zero page / v21 echo[1]=0x02 marker.
        -- Next reply arriving with closed=true triggers another reset.
        closed          = false,
        -- frame_number -> render result. Survives stream reset; pass-2
        -- of `tshark -2` replays from here without re-ingesting.
        frame_results   = prior_results,
    }
    return s.docs_streams[key]
end

-- Fetch the in-flight (or most recently closed) docs stream for this
-- conv + connid, or nil if none has ever been opened.
function M.docs_stream_get(pinfo, connid)
    local s = M.get(pinfo)
    if not s.docs_streams then return nil end
    return s.docs_streams[connid_key(connid)]
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

-- Returns every HMAC key the handshake module has derived on this
-- stream so far. Signed-frame dissectors iterate this list when
-- effective_key() doesn't match (multiple concurrent CIP connections
-- on one TCP stream each carry their own key).
function M.hmac_keys(pinfo)
    local s = M.get(pinfo)
    return s.hmac_keys or {}
end

-- connid -> key lookup. Once a signed frame on connid N validates
-- against key K, every subsequent frame on connid N hits this cache
-- and skips re-trying the whole key list.
function M.key_for_connid(pinfo, connid)
    local s = M.get(pinfo)
    return s.connid_to_key and s.connid_to_key[connid] or nil
end

function M.cache_key_for_connid(pinfo, connid, key)
    local s = M.get(pinfo)
    s.connid_to_key = s.connid_to_key or {}
    s.connid_to_key[connid] = key
end

function M.reset()
    sessions = {}
end

-- Pending-request bookkeeping. Sub-modules that dispatch on a service
-- code only the *request* exposes (e.g. class 0x0349 documentation
-- reads, where the reply has no epath and so can't be self-identified)
-- call record_request on the request frame and lookup_request on the
-- reply. The seq argument is the signed-CIP wrapper sequence number
-- (rockwell_cip.signed.seq) if known — same seq pairs request to reply
-- on the same conversation. frame_hint is the request frame number
-- when known via the stock cip dissector's conversation tracking
-- (cip.request_frame on the reply); used as a fallback when there's no
-- signed wrapper.
function M.record_request(pinfo, seq, target_class)
    local s = M.get(pinfo)
    local frame = pinfo.number
    local existing = (seq and s.pending_requests.by_seq[seq])
        or s.pending_requests.by_frame[frame]
    if existing
       and existing.req_frame == frame
       and existing.class == target_class then
        return existing
    end
    local rec = {
        class       = target_class,
        req_frame   = frame,
        reply_frame = nil,
    }
    if seq then
        s.pending_requests.by_seq[seq] = rec
    end
    s.pending_requests.by_frame[frame] = rec
    return rec
end

function M.lookup_request(pinfo, seq, frame_hint)
    local s = M.get(pinfo)
    if seq then
        local rec = s.pending_requests.by_seq[seq]
        if rec then return rec end
    end
    if frame_hint then
        local rec = s.pending_requests.by_frame[frame_hint]
        if rec then return rec end
    end
    return nil
end

return M
