-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- bigint.lua — minimal pure-Lua arbitrary-precision unsigned integer
-- arithmetic, sized for 1024-bit RSA (private keys up to ~256 bytes
-- per CRT factor). Used by rsa.lua to decrypt the Path-A handshake
-- challenge — see class_0064_handshake.lua for context.
--
-- Representation: a bigint is a table { n = #limbs, [1] = lsb_limb,
-- [2] = ..., [n] = msb_limb }. Each limb is a 16-bit unsigned integer
-- (range 0..65535). The number zero is { n = 0 }.
--
-- 16-bit limbs keep products inside Lua double-precision (2^32 < 2^53)
-- without overflow tricks, and they make byte-order conversions a
-- two-bytes-per-limb pair. 24-bit limbs would be ~2x faster on mul/mod
-- but require careful overflow accounting; the ~5-second decrypt this
-- library produces runs once per session and isn't worth that
-- complexity.
--
-- Operations exposed:
--   from_int(n), from_bytes_le(s), from_bytes_be(s)
--   to_bytes_le(a, width), to_int(a)   (the latter only when a fits)
--   is_zero(a), cmp(a, b), eq(a, b)
--   add(a, b), sub(a, b)   (sub assumes a >= b)
--   mul(a, b)
--   divmod(a, b), mod(a, b)
--   modexp(base, exp, m)
--   modinv(a, m)   (Bezout-style; used by RSA CRT combine)
--   shl1(a) / shr1(a) helpers used by the bit-walk loops
--
-- The library is internally trusting: callers are expected to pass
-- well-formed bigints (no negative limbs, no stale trailing zeros).
-- All constructor paths produce trimmed values; all arithmetic
-- operations trim before returning.

local M = {}

local LIMB_BITS  = 16
local LIMB_BASE  = 65536
local LIMB_MASK  = 65535
local HALF_BASE  = 32768   -- 1 << 15

local function new_zero() return { n = 0 } end

local function trim(a)
    while a.n > 0 and a[a.n] == 0 do
        a[a.n] = nil
        a.n = a.n - 1
    end
    return a
end

local function copy(a)
    local r = { n = a.n }
    for i = 1, a.n do r[i] = a[i] end
    return r
end

function M.is_zero(a) return a.n == 0 end

function M.from_int(n)
    if n == 0 then return new_zero() end
    local r = { n = 0 }
    local i = 0
    while n > 0 do
        i = i + 1
        r[i] = n & LIMB_MASK
        n = n >> LIMB_BITS
    end
    r.n = i
    return r
end

-- Convert a bigint that fits in a Lua number (~53 bits) back to an
-- int. Errors loudly for larger values; callers should prefer
-- to_bytes_* for those.
function M.to_int(a)
    if a.n == 0 then return 0 end
    if a.n > 3 then
        error(string.format("bigint too large for to_int (n=%d)", a.n))
    end
    local v = 0
    for i = a.n, 1, -1 do v = v * LIMB_BASE + a[i] end
    return v
end

-- bytes[1] = LSB.
function M.from_bytes_le(s)
    local len = #s
    local r = { n = 0 }
    local i = 1
    local idx = 0
    while i <= len do
        local lo = string.byte(s, i)
        local hi = (i + 1 <= len) and string.byte(s, i + 1) or 0
        idx = idx + 1
        r[idx] = lo | (hi << 8)
        i = i + 2
    end
    r.n = idx
    return trim(r)
end

-- bytes[1] = MSB (standard ASN.1 / PKCS#1 INTEGER ordering).
function M.from_bytes_be(s)
    local len = #s
    local r = { n = 0 }
    local idx = 0
    local i = len
    while i >= 1 do
        local lo = string.byte(s, i)
        local hi = (i - 1 >= 1) and string.byte(s, i - 1) or 0
        idx = idx + 1
        r[idx] = lo | (hi << 8)
        i = i - 2
    end
    r.n = idx
    return trim(r)
end

-- Zero-pad / verify-fits and emit bytes little-endian, byte[1] = LSB.
function M.to_bytes_le(a, width)
    local bytes = {}
    for i = 1, width do bytes[i] = 0 end
    for i = 1, a.n do
        local limb = a[i]
        local lo_idx = (i - 1) * 2 + 1
        local hi_idx = lo_idx + 1
        if lo_idx > width then
            if limb ~= 0 then
                error(string.format(
                    "bigint exceeds %d-byte width (limb %d = %d)",
                    width, i, limb))
            end
        else
            bytes[lo_idx] = limb & 0xff
            if hi_idx <= width then
                bytes[hi_idx] = (limb >> 8) & 0xff
            elseif (limb >> 8) ~= 0 then
                error(string.format(
                    "bigint exceeds %d-byte width (high byte of limb %d nonzero)",
                    width, i))
            end
        end
    end
    return string.char(table.unpack(bytes))
end

function M.cmp(a, b)
    if a.n ~= b.n then
        if a.n < b.n then return -1 else return 1 end
    end
    for i = a.n, 1, -1 do
        if a[i] ~= b[i] then
            if a[i] < b[i] then return -1 else return 1 end
        end
    end
    return 0
end

function M.eq(a, b) return M.cmp(a, b) == 0 end

function M.add(a, b)
    local n = math.max(a.n, b.n)
    local r = { n = 0 }
    local carry = 0
    for i = 1, n do
        local s = (a[i] or 0) + (b[i] or 0) + carry
        r[i] = s & LIMB_MASK
        carry = s >> LIMB_BITS
    end
    if carry > 0 then n = n + 1; r[n] = carry end
    r.n = n
    return r
end

-- a - b. Caller's responsibility to ensure a >= b; we panic on borrow.
function M.sub(a, b)
    local r = { n = a.n }
    local borrow = 0
    for i = 1, a.n do
        local d = a[i] - (b[i] or 0) - borrow
        if d < 0 then
            d = d + LIMB_BASE
            borrow = 1
        else
            borrow = 0
        end
        r[i] = d
    end
    if borrow ~= 0 then error("bigint underflow in sub") end
    return trim(r)
end

function M.mul(a, b)
    if a.n == 0 or b.n == 0 then return new_zero() end
    local r = { n = a.n + b.n }
    for i = 1, r.n do r[i] = 0 end
    for i = 1, a.n do
        local ai = a[i]
        if ai ~= 0 then
            local carry = 0
            for j = 1, b.n do
                local s = r[i + j - 1] + ai * b[j] + carry
                r[i + j - 1] = s & LIMB_MASK
                carry = s >> LIMB_BITS
            end
            -- Final carry propagates into r[i + b.n], which may itself
            -- be non-zero from prior iterations — keep propagating.
            local k = i + b.n
            while carry > 0 do
                local s = r[k] + carry
                r[k] = s & LIMB_MASK
                carry = s >> LIMB_BITS
                k = k + 1
            end
        end
    end
    return trim(r)
end

-- Shift left by 1 bit, in place.
local function shl1_inplace(a)
    local carry = 0
    for i = 1, a.n do
        local s = (a[i] << 1) | carry
        a[i] = s & LIMB_MASK
        carry = (s >> LIMB_BITS) & 1
    end
    if carry > 0 then
        a.n = a.n + 1
        a[a.n] = carry
    end
end

-- Shift right by 1 bit, in place.
local function shr1_inplace(a)
    local carry = 0
    for i = a.n, 1, -1 do
        local v = a[i]
        a[i] = (v >> 1) | (carry << (LIMB_BITS - 1))
        carry = v & 1
    end
    trim(a)
end

function M.shl1(a) local r = copy(a); shl1_inplace(r); return r end
function M.shr1(a) local r = copy(a); shr1_inplace(r); return r end

-- Total bit length of a (1-based: zero is 0, one is 1, etc.).
function M.bit_length(a)
    if a.n == 0 then return 0 end
    local top = a[a.n]
    local k = (a.n - 1) * LIMB_BITS
    while top > 0 do
        k = k + 1
        top = top >> 1
    end
    return k
end

-- Test bit i (0-indexed from LSB) of a. Returns 0 or 1.
function M.bit(a, i)
    local limb_idx = (i >> 4) + 1
    if limb_idx > a.n then return 0 end
    return (a[limb_idx] >> (i & 15)) & 1
end

-- Set bit i (0-indexed from LSB) of a in place, growing a if needed.
local function set_bit_inplace(a, i)
    local limb_idx = (i >> 4) + 1
    while a.n < limb_idx do
        a.n = a.n + 1
        a[a.n] = 0
    end
    a[limb_idx] = a[limb_idx] | (1 << (i & 15))
end

-- Binary long division. O(bit_length(a) * a.n) — slow but correct;
-- this is the bottleneck. For the RSA decrypt we drive it through
-- modexp at most ~512 times per CRT factor, so ~1k divmod calls per
-- handshake. Acceptable at ~milliseconds-each interpreter speed.
function M.divmod(a, b)
    if b.n == 0 then error("bigint divmod by zero") end
    if M.cmp(a, b) < 0 then return new_zero(), copy(a) end

    local q = { n = 0 }
    local r = { n = 0 }
    local nbits = M.bit_length(a)
    for i = nbits - 1, 0, -1 do
        shl1_inplace(r)
        if M.bit(a, i) == 1 then
            -- r |= 1
            if r.n == 0 then r.n = 1; r[1] = 1
            else r[1] = r[1] | 1 end
        end
        if M.cmp(r, b) >= 0 then
            r = M.sub(r, b)
            set_bit_inplace(q, i)
        end
    end
    return trim(q), r
end

function M.mod(a, b)
    local _, r = M.divmod(a, b)
    return r
end

-- base^exp mod m. Right-to-left binary modexp.
function M.modexp(base, exp, m)
    if m.n == 0 then error("bigint modexp by zero") end
    if M.cmp(m, M.from_int(1)) == 0 then return new_zero() end
    local result = M.from_int(1)
    local b = M.mod(base, m)
    local e = copy(exp)
    while not M.is_zero(e) do
        if (e[1] & 1) == 1 then
            result = M.mod(M.mul(result, b), m)
        end
        shr1_inplace(e)
        if not M.is_zero(e) then
            b = M.mod(M.mul(b, b), m)
        end
    end
    return result
end

-- Modular inverse of a mod m, via extended Euclidean. Used by RSA CRT
-- combine when the key file omits qinv. Returns nil if a is not
-- coprime to m. Operates on signed magnitudes internally via a flag
-- per coefficient — keeps the implementation in unsigned bigint land.
function M.modinv(a, m)
    -- Extended Euclidean: maintain (old_r, old_s) and (r, s) with
    -- old_r = a*old_s + m*old_t (we don't track t). On termination
    -- old_r is gcd and old_s is the inverse (mod m).
    local old_r, r = copy(a), copy(m)
    local old_s_sign, old_s = 1, M.from_int(1)
    local s_sign, s = 1, M.from_int(0)

    local function signed_add(a_sign, a, b_sign, b)
        -- Returns (sign, magnitude) of a_sign*a + b_sign*b.
        if a_sign == b_sign then
            return a_sign, M.add(a, b)
        end
        -- Opposite signs: subtract smaller from larger.
        local c = M.cmp(a, b)
        if c >= 0 then
            return a_sign, M.sub(a, b)
        end
        return b_sign, M.sub(b, a)
    end

    while not M.is_zero(r) do
        local quot, rem = M.divmod(old_r, r)
        old_r, r = r, rem
        -- new_s = old_s - quot * s
        local qs = M.mul(quot, s)
        local ns_sign, ns_mag =
            signed_add(old_s_sign, old_s, -s_sign, qs)
        old_s_sign, old_s, s_sign, s = s_sign, s, ns_sign, ns_mag
    end

    if M.cmp(old_r, M.from_int(1)) ~= 0 then return nil end
    -- Normalize old_s into [0, m).
    local result_mag = M.mod(old_s, m)
    if old_s_sign < 0 and not M.is_zero(result_mag) then
        result_mag = M.sub(m, result_mag)
    end
    return result_mag
end

return M
