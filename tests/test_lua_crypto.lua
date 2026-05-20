-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- test_lua_crypto.lua — exercises plugins/lua/util/{bigint,rsa,pem}.lua
-- against fixed test vectors. Driven by tests/test_lua_crypto.py via
-- the `lua` CLI; uses os.exit(non-zero) to signal failure.
--
-- Two passes:
--   1) bigint smoke tests against hand-checked small values.
--   2) RSA round-trip against a tiny toy key (p=11, q=13, e=7) so the
--      math is checkable on paper. The full-size 1024-bit round trip
--      is exercised by test_phase_a_kdf.py (which needs openssl to
--      mint a synthetic keypair).

local PLUGIN_DIR = arg[1] or "plugins/lua"
package.path = PLUGIN_DIR .. "/util/?.lua;" .. package.path

local bigint = require "bigint"
local rsa    = require "rsa"
local pem    = require "pem"

local fails = 0
local function check(label, cond, detail)
    if cond then
        print("PASS  " .. label)
    else
        print("FAIL  " .. label .. (detail and (" — " .. detail) or ""))
        fails = fails + 1
    end
end

-- ---- bigint ----------------------------------------------------------

check("from_int(0) == zero", bigint.is_zero(bigint.from_int(0)))
check("from_int(123) round-trip", bigint.to_int(bigint.from_int(123)) == 123)
check("from_int(65536) round-trip", bigint.to_int(bigint.from_int(65536)) == 65536)
check("from_bytes_le LSB-first", bigint.to_int(bigint.from_bytes_le("\x01\x02\x03")) == 0x030201)
check("from_bytes_be MSB-first", bigint.to_int(bigint.from_bytes_be("\x01\x02\x03")) == 0x010203)
check("to_bytes_le pads",
    bigint.to_bytes_le(bigint.from_int(0x42), 4) == "\x42\x00\x00\x00")

local a, b = bigint.from_int(1000000), bigint.from_int(999)
check("add", bigint.to_int(bigint.add(a, b)) == 1000999)
check("sub", bigint.to_int(bigint.sub(a, b)) == 1000000 - 999)
check("mul", bigint.to_int(bigint.mul(a, b)) == 1000000 * 999)
local q, r = bigint.divmod(a, b)
check("divmod q", bigint.to_int(q) == 1000000 // 999)
check("divmod r", bigint.to_int(r) == 1000000 % 999)

-- modexp: 7^13 mod 11 = ?
local function py_pow(base, exp, m)
    local r = 1
    base = base % m
    while exp > 0 do
        if exp & 1 == 1 then r = (r * base) % m end
        base = (base * base) % m
        exp = exp >> 1
    end
    return r
end
check("modexp 7^13 mod 11",
    bigint.to_int(bigint.modexp(bigint.from_int(7), bigint.from_int(13), bigint.from_int(11)))
    == py_pow(7, 13, 11))
check("modexp 65537^65537 mod 1000003",
    bigint.to_int(bigint.modexp(bigint.from_int(65537), bigint.from_int(65537), bigint.from_int(1000003)))
    == py_pow(65537, 65537, 1000003))

-- modinv
check("modinv 3 mod 11 = 4",
    bigint.to_int(bigint.modinv(bigint.from_int(3), bigint.from_int(11))) == 4)
check("modinv 17 mod 101 = 6",
    bigint.to_int(bigint.modinv(bigint.from_int(17), bigint.from_int(101))) == 6)

-- ---- RSA with toy key -----------------------------------------------
-- p=11, q=13, n=143, phi=120, e=7, d=103 (since 7*103=721≡1 mod 120)
-- dp = 103 mod 10 = 3, dq = 103 mod 12 = 7
-- qinv = q^-1 mod p = 13^-1 mod 11 = 2^-1 mod 11 = 6 (2*6=12≡1)
local toy = {
    n    = bigint.from_int(143),
    e    = bigint.from_int(7),
    d    = bigint.from_int(103),
    p    = bigint.from_int(11),
    q    = bigint.from_int(13),
    dp   = bigint.from_int(3),
    dq   = bigint.from_int(7),
    qinv = bigint.from_int(6),
}

-- Pick a plaintext < n, encrypt with e, decrypt with d.
-- pt = 42; ct = 42^7 mod 143 = ?  (let py_pow handle it)
local pt_int = 42
local ct_int = py_pow(pt_int, 7, 143)
-- Encode ct as 1 byte LE; decrypt; verify.
local ct_bytes = string.char(ct_int)
local key_width = 1
local recovered = rsa.decrypt(ct_bytes, toy, { byte_order = "le", width = key_width })
check("toy RSA CRT decrypt", string.byte(recovered) == pt_int,
    string.format("got %d expected %d", string.byte(recovered), pt_int))

-- non-CRT fallback
local toy_no_crt = { n = toy.n, e = toy.e, d = toy.d }
local recovered2 = rsa.decrypt(ct_bytes, toy_no_crt, { byte_order = "le", width = key_width })
check("toy RSA non-CRT decrypt", string.byte(recovered2) == pt_int)

-- ---- PEM/ASN.1 spot check -------------------------------------------
-- Parse a hand-crafted minimal DER (no PEM wrapper). RSAPrivateKey of
-- the toy key above. Hand-build the DER:
--   SEQUENCE { v=0, n=143, e=7, d=103, p=11, q=13, dp=3, dq=7, qinv=6 }
-- All values fit in one byte, so each INTEGER is 02 01 <byte>.
local function int_tlv(byte)
    -- 0x80+ would need a leading 0x00 sign byte; toy values are <0x80.
    return string.char(0x02, 0x01, byte)
end
local der_body = int_tlv(0)   -- version
              .. int_tlv(143) -- n  (>= 0x80, needs sign byte)
                              -- ... but 143 = 0x8F which has the
                              -- top bit set, so we DO need a sign byte
                              -- to keep it positive. Rebuild:
local function int_tlv_pos(v)
    if v >= 0x80 then
        return string.char(0x02, 0x02, 0x00, v)
    end
    return string.char(0x02, 0x01, v)
end
der_body = int_tlv_pos(0) .. int_tlv_pos(143) .. int_tlv_pos(7)
        .. int_tlv_pos(103) .. int_tlv_pos(11) .. int_tlv_pos(13)
        .. int_tlv_pos(3)   .. int_tlv_pos(7)  .. int_tlv_pos(6)
local der = string.char(0x30, #der_body) .. der_body
local parsed = pem.parse_private_key(der)
check("PEM parse: n",    bigint.to_int(parsed.n)    == 143)
check("PEM parse: e",    bigint.to_int(parsed.e)    == 7)
check("PEM parse: d",    bigint.to_int(parsed.d)    == 103)
check("PEM parse: p",    bigint.to_int(parsed.p)    == 11)
check("PEM parse: q",    bigint.to_int(parsed.q)    == 13)
check("PEM parse: qinv", bigint.to_int(parsed.qinv) == 6)

print()
if fails == 0 then
    print("ALL OK")
    os.exit(0)
end
print(string.format("FAILED: %d", fails))
os.exit(1)
