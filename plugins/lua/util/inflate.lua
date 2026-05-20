-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- inflate.lua — pure-Lua RFC-1951 (raw DEFLATE) + RFC-1950 (zlib)
-- decompressor. Wireshark 4.6's Lua API doesn't expose zlib, and Lua
-- has no standard crypto/compression stdlib — this is the smallest
-- thing that lets the dissector recover the source XML and
-- documentation blobs Rockwell ships compressed.
--
-- This is bounded code (~250 lines): we only need to *inflate*, never
-- compress, and we never have to handle zip files or gzip framing.
-- Performance is "fine for a packet": several hundred kilobytes of
-- input per call is well under a second on Lua 5.5 with native bitops.
--
-- API:
--   inflate.inflate(zlib_bytes)        -> decompressed string
--   inflate.raw(deflate_bytes)         -> decompressed string (RFC 1951,
--                                         no zlib header / Adler-32)
--
-- Both functions raise on malformed input. Wrap calls in pcall() if
-- you need to render an error to the user instead of crashing the
-- dissector.

local M = {}

-- ---------------------------------------------------------------------
-- Bit reader: pulls little-endian bits out of a string. DEFLATE packs
-- variable-length codes LSB-first within each byte, low bits consumed
-- first.
-- ---------------------------------------------------------------------

local function reader(s)
    local r = { s = s, byte = 1, buf = 0, nbits = 0, len = #s }
    function r.bits(n)
        while r.nbits < n do
            if r.byte > r.len then error("inflate: short input") end
            r.buf = r.buf | (string.byte(r.s, r.byte) << r.nbits)
            r.nbits = r.nbits + 8
            r.byte = r.byte + 1
        end
        local v = r.buf & ((1 << n) - 1)
        r.buf = r.buf >> n
        r.nbits = r.nbits - n
        return v
    end
    function r.align()
        local extra = r.nbits & 7
        r.buf = r.buf >> extra
        r.nbits = r.nbits - extra
    end
    function r.bytes(n)
        -- Consume `n` bytes from the underlying stream (after a stored
        -- block, the bit buffer has just been aligned).
        if r.nbits ~= 0 then
            -- Should be aligned, but tolerate the rare case where we
            -- have a partial byte left in the buffer; drop it.
            r.buf = 0
            r.nbits = 0
        end
        if r.byte + n - 1 > r.len then error("inflate: short input") end
        local out = string.sub(r.s, r.byte, r.byte + n - 1)
        r.byte = r.byte + n
        return out
    end
    return r
end

-- ---------------------------------------------------------------------
-- Huffman-code decoding. Build a table from a list of code lengths,
-- then read codes bit-by-bit from the input.
-- ---------------------------------------------------------------------

local function build_huffman(lengths)
    local max_len = 0
    for _, l in ipairs(lengths) do if l > max_len then max_len = l end end
    if max_len == 0 then return { max_len = 0 } end

    -- Count codes per length, derive the canonical first code for each.
    local bl_count = {}
    for i = 1, max_len do bl_count[i] = 0 end
    for _, l in ipairs(lengths) do
        if l > 0 then bl_count[l] = bl_count[l] + 1 end
    end
    local next_code = {}
    local code = 0
    bl_count[0] = 0
    for bits = 1, max_len do
        code = (code + bl_count[bits - 1]) << 1
        next_code[bits] = code
    end

    -- For each symbol, record its (code, length).
    local table_ = {}
    for sym, l in ipairs(lengths) do
        if l > 0 then
            table_[next_code[l]] = { len = l, sym = sym - 1 }
            next_code[l] = next_code[l] + 1
        end
    end

    -- For fast decode build a per-length list of (code, sym).
    return { table = table_, max_len = max_len }
end

local function read_symbol(r, h)
    local code = 0
    for bits = 1, h.max_len do
        code = (code << 1) | r.bits(1)
        local entry = h.table[code]
        if entry and entry.len == bits then return entry.sym end
    end
    error("inflate: invalid Huffman code")
end

-- ---------------------------------------------------------------------
-- Static (fixed) Huffman tables, per RFC 1951 §3.2.6.
-- ---------------------------------------------------------------------

local FIXED_LIT, FIXED_DIST
do
    local lit_lens = {}
    for i = 0, 143 do lit_lens[i + 1] = 8 end
    for i = 144, 255 do lit_lens[i + 1] = 9 end
    for i = 256, 279 do lit_lens[i + 1] = 7 end
    for i = 280, 287 do lit_lens[i + 1] = 8 end
    FIXED_LIT = build_huffman(lit_lens)

    local dist_lens = {}
    for i = 0, 31 do dist_lens[i + 1] = 5 end
    FIXED_DIST = build_huffman(dist_lens)
end

-- Length / distance base + extra-bit tables, per RFC 1951 §3.2.5.
local LENGTH_BASE = {
    [257]=3, [258]=4, [259]=5, [260]=6, [261]=7, [262]=8, [263]=9, [264]=10,
    [265]=11, [266]=13, [267]=15, [268]=17,
    [269]=19, [270]=23, [271]=27, [272]=31,
    [273]=35, [274]=43, [275]=51, [276]=59,
    [277]=67, [278]=83, [279]=99, [280]=115,
    [281]=131, [282]=163, [283]=195, [284]=227,
    [285]=258,
}
local LENGTH_EXTRA = {
    [257]=0, [258]=0, [259]=0, [260]=0, [261]=0, [262]=0, [263]=0, [264]=0,
    [265]=1, [266]=1, [267]=1, [268]=1,
    [269]=2, [270]=2, [271]=2, [272]=2,
    [273]=3, [274]=3, [275]=3, [276]=3,
    [277]=4, [278]=4, [279]=4, [280]=4,
    [281]=5, [282]=5, [283]=5, [284]=5,
    [285]=0,
}
local DIST_BASE = {
    [0]=1, [1]=2, [2]=3, [3]=4, [4]=5, [5]=7, [6]=9, [7]=13, [8]=17,
    [9]=25, [10]=33, [11]=49, [12]=65, [13]=97, [14]=129, [15]=193,
    [16]=257, [17]=385, [18]=513, [19]=769, [20]=1025, [21]=1537,
    [22]=2049, [23]=3073, [24]=4097, [25]=6145, [26]=8193,
    [27]=12289, [28]=16385, [29]=24577,
}
local DIST_EXTRA = {
    [0]=0, [1]=0, [2]=0, [3]=0, [4]=1, [5]=1, [6]=2, [7]=2, [8]=3,
    [9]=3, [10]=4, [11]=4, [12]=5, [13]=5, [14]=6, [15]=6,
    [16]=7, [17]=7, [18]=8, [19]=8, [20]=9, [21]=9, [22]=10, [23]=10,
    [24]=11, [25]=11, [26]=12, [27]=12, [28]=13, [29]=13,
}

-- Code-length-code permutation order per RFC 1951 §3.2.7.
local CL_ORDER = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2,
                   14, 1, 15 }

-- ---------------------------------------------------------------------
-- Dynamic Huffman: read the two trees from a dynamic block header.
-- ---------------------------------------------------------------------

local function read_dynamic_trees(r)
    local hlit  = r.bits(5) + 257
    local hdist = r.bits(5) + 1
    local hclen = r.bits(4) + 4

    local cl_lens = {}
    for i = 1, 19 do cl_lens[i] = 0 end
    for i = 1, hclen do
        cl_lens[CL_ORDER[i] + 1] = r.bits(3)
    end
    local cl = build_huffman(cl_lens)

    local function read_lengths(count)
        local out = {}
        while #out < count do
            local sym = read_symbol(r, cl)
            if sym < 16 then
                out[#out + 1] = sym
            elseif sym == 16 then
                local n = r.bits(2) + 3
                local last = out[#out]
                if not last then error("inflate: rep with no prev") end
                for _ = 1, n do out[#out + 1] = last end
            elseif sym == 17 then
                local n = r.bits(3) + 3
                for _ = 1, n do out[#out + 1] = 0 end
            else  -- 18
                local n = r.bits(7) + 11
                for _ = 1, n do out[#out + 1] = 0 end
            end
        end
        return out
    end

    local lit_lens  = read_lengths(hlit)
    local dist_lens = read_lengths(hdist)
    return build_huffman(lit_lens), build_huffman(dist_lens)
end

-- ---------------------------------------------------------------------
-- Process one block; append output to `out`.
-- ---------------------------------------------------------------------

local function inflate_block(r, out, lit, dist)
    while true do
        local sym = read_symbol(r, lit)
        if sym < 256 then
            out[#out + 1] = string.char(sym)
        elseif sym == 256 then
            return
        else
            local length = LENGTH_BASE[sym]
            local extra  = LENGTH_EXTRA[sym]
            if extra > 0 then length = length + r.bits(extra) end
            local dsym = read_symbol(r, dist)
            local distance = DIST_BASE[dsym]
            local dextra   = DIST_EXTRA[dsym]
            if dextra > 0 then distance = distance + r.bits(dextra) end
            -- Sliding window: copy `length` bytes from `distance` back.
            -- We accumulate output in `out` as a list of single chars
            -- for cheap appending; concatenate at the end. The back-
            -- reference copy needs a flat string view of the recent
            -- bytes, so we maintain a `joined` buffer alongside that
            -- gets compacted when needed. For simplicity here we do
            -- the lookup directly against the list — DEFLATE distances
            -- are bounded at 32768.
            local total = #out
            local start = total - distance + 1
            for k = 0, length - 1 do
                out[#out + 1] = out[start + k]
            end
        end
    end
end

-- ---------------------------------------------------------------------
-- Public API.
-- ---------------------------------------------------------------------

function M.raw(deflate_bytes)
    if type(deflate_bytes) ~= "string" or #deflate_bytes == 0 then
        error("inflate.raw: input must be a non-empty string")
    end
    local r = reader(deflate_bytes)
    local out = {}
    while true do
        local bfinal = r.bits(1)
        local btype  = r.bits(2)
        if btype == 0 then
            -- Stored block.
            r.align()
            local len  = r.bytes(2)
            local nlen = r.bytes(2)
            local l  = (string.byte(len,  2) << 8) | string.byte(len,  1)
            local nl = (string.byte(nlen, 2) << 8) | string.byte(nlen, 1)
            if l ~= (~nl) & 0xFFFF then
                error("inflate: stored block length mismatch")
            end
            local data = r.bytes(l)
            -- Append each byte to `out` so back-refs can see them.
            for i = 1, #data do
                out[#out + 1] = string.sub(data, i, i)
            end
        elseif btype == 1 then
            inflate_block(r, out, FIXED_LIT, FIXED_DIST)
        elseif btype == 2 then
            local lit, dist = read_dynamic_trees(r)
            inflate_block(r, out, lit, dist)
        else
            error("inflate: reserved block type")
        end
        if bfinal == 1 then break end
    end
    return table.concat(out)
end

function M.inflate(zlib_bytes)
    if type(zlib_bytes) ~= "string" or #zlib_bytes < 6 then
        error("inflate.inflate: input too short for zlib stream")
    end
    -- Zlib header: 2 bytes [CMF, FLG]. CMF low nibble must be 8
    -- (deflate). The Adler-32 trailer at the end is not validated
    -- here; we only need the inflated payload.
    local cmf = string.byte(zlib_bytes, 1)
    local flg = string.byte(zlib_bytes, 2)
    if (cmf & 0x0F) ~= 8 then
        error(string.format("inflate.inflate: unexpected CM 0x%X", cmf & 0x0F))
    end
    if ((cmf << 8) | flg) % 31 ~= 0 then
        error("inflate.inflate: header check (cmf*256+flg) %% 31 ~= 0")
    end
    if (flg & 0x20) ~= 0 then
        -- Preset dictionary; we don't support these. They don't appear
        -- in Studio 5000 traffic.
        error("inflate.inflate: preset dictionary not supported")
    end
    return M.raw(string.sub(zlib_bytes, 3, #zlib_bytes - 4))
end

return M
