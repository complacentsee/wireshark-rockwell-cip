-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- pem.lua — minimal PEM/DER parser scoped to PKCS#1 (and PKCS#8-wrapped
-- PKCS#1) RSA private keys. Just enough ASN.1 to extract n, e, d, and
-- the CRT components (p, q, dp, dq, qinv) so rsa.lua can decrypt.
--
-- Why this much code: Wireshark doesn't expose libcrypto from Lua, so
-- handing the dissector a PEM file means we parse the file ourselves.
-- The supported shapes:
--
--   -----BEGIN RSA PRIVATE KEY-----            PKCS#1 (direct)
--     base64 of RSAPrivateKey SEQUENCE { v, n, e, d, p, q, dp, dq, qinv }
--   -----END RSA PRIVATE KEY-----
--
--   -----BEGIN PRIVATE KEY-----                PKCS#8 (unencrypted)
--     base64 of PrivateKeyInfo SEQUENCE {
--       version INTEGER,
--       algorithm AlgorithmIdentifier (we ignore — only support RSA),
--       privateKey OCTET STRING (containing RSAPrivateKey DER)
--     }
--   -----END PRIVATE KEY-----
--
-- DER bytes are also accepted directly (no PEM wrapper).
--
-- Encrypted PEM (BEGIN ENCRYPTED PRIVATE KEY) is NOT supported — that
-- would need a passphrase-derived KDF + symmetric decrypt that doesn't
-- belong in a Wireshark dissector. Users with encrypted keys should
-- export an unencrypted copy out-of-band.

local bigint = require "bigint"

local M = {}

-- ---- Base64 decode -----------------------------------------------------

local B64_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64_REV = {}
for i = 1, #B64_ALPHA do
    B64_REV[string.byte(B64_ALPHA, i)] = i - 1
end

local function base64_decode(s)
    -- Strip whitespace.
    s = s:gsub("[%s\r\n]", "")
    -- Strip padding for the bit math; we'll account for it via the
    -- output truncation.
    local pad = 0
    s, pad = s:gsub("=+$", "")
    local out = {}
    local buf, bits = 0, 0
    for i = 1, #s do
        local v = B64_REV[string.byte(s, i)]
        if not v then
            error(string.format("invalid base64 character at offset %d", i))
        end
        buf = (buf << 6) | v
        bits = bits + 6
        while bits >= 8 do
            bits = bits - 8
            out[#out + 1] = string.char((buf >> bits) & 0xff)
        end
    end
    return table.concat(out)
end

-- ---- PEM unwrap --------------------------------------------------------

local function strip_pem(s)
    -- Returns (label, base64_body). If `s` doesn't look like PEM,
    -- returns nil so callers can fall through to raw-DER handling.
    local label, body = s:match("%-%-%-%-%-BEGIN ([^%-]+)%-%-%-%-%-(.-)%-%-%-%-%-END")
    if not label then return nil end
    return label:match("^%s*(.-)%s*$"), body
end

-- ---- ASN.1 DER reader --------------------------------------------------

local function read_length(s, pos)
    local b = string.byte(s, pos)
    pos = pos + 1
    if b < 0x80 then return b, pos end
    local n = b & 0x7f
    if n == 0 then error("ASN.1 indefinite length not supported") end
    if n > 4 then error("ASN.1 length too large") end
    local len = 0
    for _ = 1, n do
        len = (len << 8) | string.byte(s, pos)
        pos = pos + 1
    end
    return len, pos
end

-- Reads a single TLV starting at `pos`. Returns:
--   tag, content_bytes (string), pos_after_TLV
local function read_tlv(s, pos)
    local tag = string.byte(s, pos)
    local len, body_pos = read_length(s, pos + 1)
    local content = s:sub(body_pos, body_pos + len - 1)
    return tag, content, body_pos + len
end

-- Read a SEQUENCE (tag 0x30) and return its body as a string.
local function read_sequence(s, pos)
    local tag, content, next_pos = read_tlv(s, pos)
    if tag ~= 0x30 then
        error(string.format("expected SEQUENCE (0x30), got 0x%02x", tag))
    end
    return content, next_pos
end

-- Read an INTEGER (tag 0x02). DER INTEGERs are big-endian two's
-- complement. Positive values whose top bit is set get a leading 0x00
-- prepended — we strip it.
local function read_integer(s, pos)
    local tag, content, next_pos = read_tlv(s, pos)
    if tag ~= 0x02 then
        error(string.format("expected INTEGER (0x02), got 0x%02x", tag))
    end
    -- Strip a single leading 0x00 sign byte.
    if #content > 1 and string.byte(content, 1) == 0 then
        content = content:sub(2)
    end
    return bigint.from_bytes_be(content), next_pos
end

local function read_octet_string(s, pos)
    local tag, content, next_pos = read_tlv(s, pos)
    if tag ~= 0x04 then
        error(string.format("expected OCTET STRING (0x04), got 0x%02x", tag))
    end
    return content, next_pos
end

-- ---- High-level: parse RSAPrivateKey DER content ----------------------

local function parse_rsa_private_key_der(seq_body)
    -- RSAPrivateKey SEQUENCE: version, n, e, d, p, q, dp, dq, qinv.
    -- Only the two-prime form (version 0) is supported.
    local pos = 1
    local version
    version, pos = read_integer(seq_body, pos)
    if not bigint.is_zero(version) then
        error("only RSAPrivateKey version 0 (two-prime) is supported")
    end
    local n;    n,    pos = read_integer(seq_body, pos)
    local e;    e,    pos = read_integer(seq_body, pos)
    local d;    d,    pos = read_integer(seq_body, pos)
    local p;    p,    pos = read_integer(seq_body, pos)
    local q;    q,    pos = read_integer(seq_body, pos)
    local dp;   dp,   pos = read_integer(seq_body, pos)
    local dq;   dq,   pos = read_integer(seq_body, pos)
    local qinv; qinv, pos = read_integer(seq_body, pos)
    return {
        n = n, e = e, d = d,
        p = p, q = q,
        dp = dp, dq = dq, qinv = qinv,
    }
end

-- Detect and unwrap a PKCS#8 PrivateKeyInfo SEQUENCE wrapping a
-- PKCS#1 RSAPrivateKey OCTET STRING. The AlgorithmIdentifier OID is
-- not verified — any unencrypted PKCS#8 with an OCTET STRING payload
-- that itself parses as RSAPrivateKey is accepted.
local function unwrap_pkcs8(seq_body)
    local pos = 1
    -- Skip version INTEGER.
    _, pos = read_integer(seq_body, pos)
    -- Skip AlgorithmIdentifier SEQUENCE.
    _, pos = read_sequence(seq_body, pos)
    -- PrivateKey OCTET STRING, contains a DER-encoded RSAPrivateKey.
    local octet
    octet, _ = read_octet_string(seq_body, pos)
    return (read_sequence(octet, 1))
end

-- ---- Public entry point -----------------------------------------------

-- Parse a key from raw PEM text, DER bytes, or a file path.
-- Returns the key table (n, e, d, p, q, dp, dq, qinv as bigints).
function M.parse_private_key(input)
    -- If it looks like a file path that exists, slurp it.
    if input and not input:find("%-%-%-%-%-")
                    and not input:match("^%[ASN.1%]")
                    and #input < 1024 then
        local f = io.open(input, "rb")
        if f then
            input = f:read("*a")
            f:close()
        end
    end

    local der
    local label, body = strip_pem(input)
    if label then
        der = base64_decode(body)
    else
        der = input
    end

    -- Top-level SEQUENCE.
    local seq_body = read_sequence(der, 1)
    -- Try PKCS#1 first: first INTEGER is version (0).
    -- Heuristic: peek the SEQUENCE body's first byte after its header.
    -- If the SECOND TLV is also a SEQUENCE (AlgorithmIdentifier), it's
    -- PKCS#8; otherwise it's PKCS#1.
    local _, after_first = read_integer(seq_body, 1)
    local second_tag = string.byte(seq_body, after_first)
    if second_tag == 0x30 then
        seq_body = unwrap_pkcs8(seq_body)
    end
    return parse_rsa_private_key_der(seq_body)
end

return M
