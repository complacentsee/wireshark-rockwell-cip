-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- sha1.lua — pure-Lua SHA-1 + HMAC-SHA1, sized for Wireshark plugins.
--
-- Wireshark 4.x ships no zlib or crypto bindings to Lua, so we ship our
-- own. Performance is "fine for a packet dissector" — SHA-1 of a few
-- hundred bytes per frame is sub-millisecond on Lua 5.5. Don't reach
-- for this in tight loops.
--
-- API:
--   sha1.digest(bytes)            -> 20-byte raw digest (string)
--   sha1.digest_hex(bytes)        -> 40-char lowercase hex digest
--   sha1.hmac(key, bytes)         -> 20-byte raw HMAC-SHA1
--   sha1.hmac_hex(key, bytes)     -> 40-char lowercase hex HMAC-SHA1
--   sha1.iterate(bytes, n)        -> SHA-1^n(bytes), 20-byte raw
--
-- All `bytes` and `key` parameters are Lua strings. Inputs are treated
-- as bytewise — pass binary data with no surprises.

local M = {}

local bit = {}  -- 32-bit operations on Lua integers
do
    local function band(a, b)        return a & b end
    local function bor (a, b)        return a | b end
    local function bxor(a, b)        return a ~ b end
    local function bnot(a)           return (~a) & 0xFFFFFFFF end
    local function lshift(a, n)      return (a << n) & 0xFFFFFFFF end
    local function rshift(a, n)      return (a >> n) & 0xFFFFFFFF end
    local function rol(a, n)
        a = a & 0xFFFFFFFF
        return ((a << n) | (a >> (32 - n))) & 0xFFFFFFFF
    end
    bit.band, bit.bor, bit.bxor = band, bor, bxor
    bit.bnot, bit.lshift, bit.rshift, bit.rol = bnot, lshift, rshift, rol
end

local function u32_be(s, i)
    -- Read a big-endian uint32 starting at byte i (1-based).
    local b1, b2, b3, b4 = string.byte(s, i, i + 3)
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4
end

local function u32_to_bytes_be(n)
    return string.char(
        (n >> 24) & 0xFF,
        (n >> 16) & 0xFF,
        (n >> 8)  & 0xFF,
        n & 0xFF
    )
end

-- SHA-1 padding: append 0x80, then zeros until length ≡ 56 mod 64,
-- then 8 bytes of big-endian bit length.
local function pad(message)
    local len = #message
    local bit_len = len * 8
    local padding = "\x80"
    local rem = (len + 1) % 64
    local pad_len = (rem <= 56) and (56 - rem) or (120 - rem)
    padding = padding .. string.rep("\0", pad_len)
    padding = padding .. u32_to_bytes_be(0)            -- high 32 bits
    padding = padding .. u32_to_bytes_be(bit_len & 0xFFFFFFFF)
    return message .. padding
end

local function compress_block(state, block, offset)
    local w = {}
    for i = 0, 15 do
        w[i] = u32_be(block, offset + i * 4)
    end
    for i = 16, 79 do
        w[i] = bit.rol(w[i - 3] ~ w[i - 8] ~ w[i - 14] ~ w[i - 16], 1)
    end

    local a, b, c, d, e =
        state[1], state[2], state[3], state[4], state[5]

    for i = 0, 79 do
        local f, k
        if i < 20 then
            f = (b & c) | (bit.bnot(b) & d)
            k = 0x5A827999
        elseif i < 40 then
            f = b ~ c ~ d
            k = 0x6ED9EBA1
        elseif i < 60 then
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else
            f = b ~ c ~ d
            k = 0xCA62C1D6
        end
        local temp = (bit.rol(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
        e = d
        d = c
        c = bit.rol(b, 30)
        b = a
        a = temp
    end

    state[1] = (state[1] + a) & 0xFFFFFFFF
    state[2] = (state[2] + b) & 0xFFFFFFFF
    state[3] = (state[3] + c) & 0xFFFFFFFF
    state[4] = (state[4] + d) & 0xFFFFFFFF
    state[5] = (state[5] + e) & 0xFFFFFFFF
end

function M.digest(message)
    local state = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
    }
    local padded = pad(message)
    -- Each block is 64 bytes; iterate with 1-based offsets.
    for offset = 1, #padded, 64 do
        compress_block(state, padded, offset)
    end
    return u32_to_bytes_be(state[1])
        .. u32_to_bytes_be(state[2])
        .. u32_to_bytes_be(state[3])
        .. u32_to_bytes_be(state[4])
        .. u32_to_bytes_be(state[5])
end

function M.digest_hex(message)
    return (M.digest(message):gsub(".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

-- HMAC-SHA1 per RFC 2104.
local BLOCK_SIZE = 64

function M.hmac(key, message)
    if #key > BLOCK_SIZE then
        key = M.digest(key)
    end
    if #key < BLOCK_SIZE then
        key = key .. string.rep("\0", BLOCK_SIZE - #key)
    end
    local opad, ipad = {}, {}
    for i = 1, BLOCK_SIZE do
        local b = string.byte(key, i)
        opad[i] = string.char(b ~ 0x5C)
        ipad[i] = string.char(b ~ 0x36)
    end
    local inner = M.digest(table.concat(ipad) .. message)
    return M.digest(table.concat(opad) .. inner)
end

function M.hmac_hex(key, message)
    return (M.hmac(key, message):gsub(".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

-- SHA-1^n: iterate n times. Used by the Path-A handshake (Phase 2
-- response is SHA-1^20(challenge[0:64])).
function M.iterate(message, n)
    local result = message
    for _ = 1, n do
        result = M.digest(result)
    end
    return result
end

-- Hex-encode an arbitrary binary string. Not SHA-1 specific but lives
-- here for callers that want to display digest output.
function M.to_hex(bytes)
    return (bytes:gsub(".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

-- Decode an ASCII-hex string back to raw bytes. Tolerant of whitespace
-- and ':' separators. Returns nil if input contains non-hex characters
-- or is odd-length after stripping separators.
function M.from_hex(hex)
    local stripped = (hex or ""):gsub("[%s:]", ""):lower()
    if #stripped == 0 or #stripped % 2 ~= 0 then return nil end
    if stripped:match("[^0-9a-f]") then return nil end
    return (stripped:gsub("..", function(pair)
        return string.char(tonumber(pair, 16))
    end))
end

return M
