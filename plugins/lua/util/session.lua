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
            pending_requests = {
                by_seq   = {},        -- [signed seq u32] -> req record
                by_frame = {},        -- [req frame number] -> req record
            },
            -- Class 0x0349 paginated-read accumulator state. The 0x53
            -- reply on class 0x349 is a stream of fixed-stride pages
            -- (v36: 458B) whose record bodies routinely straddle page
            -- boundaries — see cip_upload/extract_logix_data.py:1090.
            -- Reassembly is conv-scoped because pagination is driven by
            -- the client's request-offset and there is no per-chunk
            -- header on the wire to key off frame-globally.
            docs_stream      = nil,
        }
        sessions[k] = s
    end
    return s
end

-- Open (or reset) the per-conversation docs accumulator. Called when a
-- 0x349 reply arrives and either no stream is in flight or the prior
-- stream has been closed. `frame_results` survives the reset so cached
-- per-frame render data from the prior stream isn't lost.
function M.docs_stream_open(pinfo)
    local s = M.get(pinfo)
    local prior_results = s.docs_stream and s.docs_stream.frame_results or {}
    s.docs_stream = {
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
    return s.docs_stream
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
