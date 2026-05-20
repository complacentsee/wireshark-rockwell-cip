-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- modexp_cache.lua — persistent on-disk cache for the Path-A
-- RSA-decrypt result.
--
-- A v36 capture's HMAC validation calls into derive_hmac_key once per
-- distinct Phase-1 challenge nonce; each call is a 1024-bit modexp in
-- pure Lua and takes ~2-3s on a developer laptop. For a typical
-- 12-connection upload trace that's ~30s spent in modexp per dissect
-- pass, paid every time the capture is reopened.
--
-- The modexp output is fully determined by (rsa_private_key,
-- challenge_bytes) — same inputs always produce the same plaintext —
-- so caching it on disk is safe. We key by (sha1(key_file_bytes),
-- challenge) and store the derived 64-byte HMAC key. Subsequent runs
-- of the same capture hit the cache and skip the modexp entirely.
--
-- File format (append-only, fixed-stride records):
--
--   header: "RCM\1" (4B magic) + version u8 + 3B reserved zeros
--   entry:  key_hash (20B SHA-1) + challenge (128B) + derived (64B)
--           = 212 bytes
--
-- Append-only keeps concurrent dissects (two tshark runs against the
-- same capture, or pass 1 / pass 2 of `tshark -2`) from corrupting
-- each other: POSIX guarantees writes < PIPE_BUF (typically 4096B)
-- are atomic, and 212B is well inside that limit. Worst case two
-- runs both compute the same entry and append duplicates; reads
-- still resolve correctly (last hit wins).
--
-- The cache is keyed by the *file bytes*, not the file path, so a
-- key file that's been moved or copied is still recognised. A
-- corrupted or partial trailing record on read is silently
-- truncated; readers stop at the first short record.
--
-- Failure modes are all silent: a missing cache dir, full disk, or
-- read-only filesystem just means we always recompute. The dissector
-- continues to function — only the speedup goes away.

local sha1 = require "sha1"

local M = {}

local CACHE_DIR     = (os.getenv("HOME") or ".") .. "/.cache/rockwell_cip"
local CACHE_FILE    = CACHE_DIR .. "/hmac_modexp_cache.bin"
local MAGIC         = "RCM\1"
local HEADER_LEN    = 8     -- 4B magic + 1B version + 3B reserved
local KEY_HASH_LEN  = 20    -- SHA-1
local CHALLENGE_LEN = 128
local DERIVED_LEN   = 64
local ENTRY_LEN     = KEY_HASH_LEN + CHALLENGE_LEN + DERIVED_LEN

local mem = nil  -- key_hash..challenge -> derived; lazy-loaded

local function load_from_disk()
    if mem ~= nil then return end
    mem = {}
    local f = io.open(CACHE_FILE, "rb")
    if not f then return end
    local hdr = f:read(HEADER_LEN)
    if not hdr or #hdr < HEADER_LEN or hdr:sub(1, 4) ~= MAGIC then
        -- Unknown / corrupt file — leave mem empty so writes
        -- start fresh. We don't unlink: the user might want to
        -- inspect it.
        f:close()
        return
    end
    while true do
        local rec = f:read(ENTRY_LEN)
        if not rec or #rec < ENTRY_LEN then break end
        local k = rec:sub(1, KEY_HASH_LEN + CHALLENGE_LEN)
        local v = rec:sub(KEY_HASH_LEN + CHALLENGE_LEN + 1)
        mem[k] = v
    end
    f:close()
end

-- Make sure the cache file exists with a valid header. Called before
-- the first append. We try mkdir -p via os.execute (sh is universally
-- available on the unixy platforms Wireshark Lua runs on; on Windows
-- the cache silently no-ops since HOME isn't set the same way and
-- io.open below will fail gracefully).
local function ensure_header()
    local f = io.open(CACHE_FILE, "rb")
    if f then f:close() return true end
    os.execute('mkdir -p "' .. CACHE_DIR .. '" 2>/dev/null')
    f = io.open(CACHE_FILE, "wb")
    if not f then return false end
    f:write(MAGIC .. "\0\0\0\0")  -- version 0 reserved, 3 pad bytes
    f:close()
    return true
end

-- Returns the SHA-1 of the raw bytes of `path` (used as the cache
-- partition key for the modexp output). Returns nil on read failure
-- — callers should treat that the same as "cache disabled".
function M.hash_key_file(path)
    if not path or path == "" then return nil end
    local f = io.open(path, "rb")
    if not f then return nil end
    local bytes = f:read("*a")
    f:close()
    if not bytes then return nil end
    return sha1.digest(bytes)
end

-- Look up a previously-derived HMAC key. key_hash is from
-- hash_key_file; challenge is the 128B Phase-1 nonce.
function M.lookup(key_hash, challenge)
    if not key_hash or not challenge then return nil end
    if #challenge ~= CHALLENGE_LEN then return nil end
    load_from_disk()
    return mem[key_hash .. challenge]
end

-- Persist a freshly-derived HMAC key. Silent on any I/O error — the
-- in-memory table is also updated so the rest of this run still
-- benefits even when the disk write fails.
function M.store(key_hash, challenge, derived)
    if not key_hash or not challenge or not derived then return end
    if #key_hash ~= KEY_HASH_LEN
        or #challenge ~= CHALLENGE_LEN
        or #derived ~= DERIVED_LEN then
        return
    end
    load_from_disk()
    local k = key_hash .. challenge
    if mem[k] then return end
    mem[k] = derived
    if not ensure_header() then return end
    local f = io.open(CACHE_FILE, "ab")
    if not f then return end
    f:write(k .. derived)
    f:close()
end

return M
