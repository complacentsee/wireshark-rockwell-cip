-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- rsa.lua — textbook RSA private-key decryption for the Path-A
-- handshake. Mirrors what hmac_connect.py:111-122 does in three lines
-- of Python: read 128B ciphertext as little-endian, modexp with the
-- private key, emit the plaintext as 128B little-endian.
--
-- Two byte-order quirks worth flagging:
--   1. PKCS#1 stores RSA INTEGERs big-endian (standard ASN.1). pem.lua
--      reads them that way and produces bigints via bigint.from_bytes_be.
--   2. The Rockwell Path-A challenge nonce is LITTLE-ENDIAN when read
--      off the wire as an integer to feed into RSA — a Rockwell-side
--      convention layered ON TOP of standard RSA (hmac_connect.py uses
--      `int.from_bytes(..., "little")` in both directions). We mirror
--      it. Reading BE would silently produce a different ciphertext
--      integer and decrypt to garbage.
-- Mismatch on either is silent corruption: modexp succeeds, returns
-- garbage, downstream HMAC validation fails inscrutably.
--
-- CRT (Chinese Remainder Theorem) decryption is used when the key
-- supplies p / q / dp / dq / qinv (standard PKCS#1 format does). It's
-- ~4x faster than naive c^d mod n because each modexp runs against a
-- half-size modulus. For a 1024-bit key in pure Lua that brings the
-- decrypt from ~tens of seconds down to ~single-digit seconds. The
-- non-CRT path stays available as a fallback for keys missing the
-- CRT parameters.

local bigint = require "bigint"

local M = {}

-- Validate that a parsed key has all the fields we expect.
-- `key` is a table with bigint fields: n, e, d, and optionally
-- p, q, dp, dq, qinv (all PKCS#1 RSAPrivateKey components).
local function validate_key(key)
    if not key.n or not key.d then
        return false, "missing RSA modulus or private exponent"
    end
    return true
end

local function has_crt(key)
    return key.p and key.q and key.dp and key.dq and key.qinv
end

-- Modular subtract: (a - b) mod m. Bigint subtract requires a >= b;
-- when a < b we add m first to keep the value non-negative.
local function mod_sub(a, b, m)
    if bigint.cmp(a, b) >= 0 then
        return bigint.mod(bigint.sub(a, b), m)
    end
    -- a < b: compute a + m - b. Since b < m (we expect b in [0, m)),
    -- (a + m) - b is well-defined and positive.
    return bigint.mod(bigint.sub(bigint.add(a, m), b), m)
end

-- CRT-style decrypt:
--   m1 = c^dp mod p
--   m2 = c^dq mod q
--   h  = qinv * (m1 - m2) mod p
--   m  = m2 + h * q
-- Returns the plaintext bigint.
local function decrypt_crt(c, key)
    local m1 = bigint.modexp(c, key.dp, key.p)
    local m2 = bigint.modexp(c, key.dq, key.q)
    local diff = mod_sub(m1, m2, key.p)
    local h = bigint.mod(bigint.mul(key.qinv, diff), key.p)
    return bigint.add(m2, bigint.mul(h, key.q))
end

-- decrypt(ciphertext_bytes, key, opts) -> plaintext_bytes
--
-- `ciphertext_bytes` is a Lua string of raw bytes — exactly as it sat
-- on the wire (no length prefix, no PKCS#1 padding stripped). `key`
-- is the table produced by pem.parse_private_key. `opts` may set:
--   byte_order = "le" (default — Rockwell) | "be" (textbook RSA)
--   width      = output width in bytes (default = ceil(bitlen(n)/8))
--
-- The output is always a Lua string of exactly `width` bytes.
function M.decrypt(ciphertext_bytes, key, opts)
    opts = opts or {}
    local ok, err = validate_key(key)
    if not ok then error(err) end

    local order = opts.byte_order or "le"
    local c
    if order == "le" then
        c = bigint.from_bytes_le(ciphertext_bytes)
    elseif order == "be" then
        c = bigint.from_bytes_be(ciphertext_bytes)
    else
        error("byte_order must be 'le' or 'be'")
    end

    -- Sanity: ciphertext should be less than n. If it isn't, the key
    -- is wrong for this nonce (or byte order is flipped).
    if bigint.cmp(c, key.n) >= 0 then
        error("RSA ciphertext >= modulus (wrong key or byte order?)")
    end

    local plaintext_int
    if has_crt(key) then
        plaintext_int = decrypt_crt(c, key)
    else
        plaintext_int = bigint.modexp(c, key.d, key.n)
    end

    local width = opts.width
                or math.floor((bigint.bit_length(key.n) + 7) / 8)
    if order == "le" then
        return bigint.to_bytes_le(plaintext_int, width)
    end
    -- BE output: emit LE then reverse.
    local le = bigint.to_bytes_le(plaintext_int, width)
    return string.reverse(le)
end

return M
