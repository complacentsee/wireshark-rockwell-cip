-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- valstr.lua — value-string tables for Rockwell-private CIP services,
-- classes, and enum-like fields. Kept in one place so the Python
-- extractor in the companion logix_fw/cip_upload repo can drive
-- regeneration via tools/sync_constants.py.

local M = {}

-- CIP service codes used in Studio 5000 ↔ ControlLogix traffic that
-- aren't already named by Wireshark's stock cip dissector.
M.services = {
    [0x36] = "Signed Send (HMAC-SHA1 wrap)",
    [0xB6] = "Signed Send Reply",
    [0x3A] = "Compiled Body Upload (Studio v36)",
    [0xBA] = "Compiled Body Upload Reply",
    [0x4B] = "Get Instance Attribute List",
    [0x4C] = "Read Template / Routine Body",
    [0x4F] = "Read Source (v21 RLL/AOI)",
    [0x52] = "Read Tag Fragmented / Read Routine",
    [0x53] = "Read Documentation",
    [0x5D] = "Read Source (v36 inner)",
}

-- CIP class IDs Studio touches that aren't standard ODVA classes.
M.classes = {
    [0x0064] = "Logix Controller / pka Handshake",
    [0x0068] = "Program Object",
    [0x0069] = "Module / Property Object",
    [0x006A] = "Extended Properties Object",
    [0x006B] = "Symbol (Tag) Object",
    [0x006C] = "Template (UDT/AOI definition)",
    [0x006D] = "Routine Object",
    [0x008D] = "Message Parameters Object",
    [0x0338] = "AddOnInstruction Definition",
    [0x0349] = "Documentation Object (description blob)",
}

-- 0x5D inner-service op codes carried in the 8-byte arg tail.
M.body_3a_ops = {
    [3] = "Read Source",
    [4] = "Release",
    [9] = "Read Program Body (bulk)",
}

-- 0x3A application-data state byte semantics. Same byte covers init
-- replies and continuation replies — disambiguated by context.
M.body_3a_states = {
    [0x00] = "Continuation, more chunks coming",
    [0x01] = "Init reply, more chunks coming",
    [0x02] = "Continuation, final chunk",
    [0x03] = "Init reply, final chunk",
}

-- UDIParameters usage_dir byte (offset +20 in each entry record).
M.udi_usage = {
    [1] = "Input",
    [2] = "Output",
    [3] = "InOut",
    [4] = "Local",
}

-- UDIParameters vis_flags byte (offset +21). Bitfield, but a few
-- well-known combinations are worth labelling directly.
M.udi_vis_flags = {
    [0x00] = "Hidden",
    [0x06] = "Visible + Required",
    [0x0E] = "Visible + Required + InOut",
    [0x11] = "System (EnableIn/EnableOut)",
    [0x14] = "Visible + Optional",
}

-- Class 0x0349 description record class markers (the 16-bit value at
-- offset +0 of each record).
M.doc_record_classes = {
    [0x0068] = "Program scope (rung comment / prog-tag desc)",
    [0x0069] = "Module description",
    [0x006B] = "Tag (operand or whole-tag description)",
    [0x006C] = "Template member description",
    [0x0338] = "AOI scope (param/routine/rung description)",
    [0x0349] = "Self-reference (metadata)",
}

-- Class 0x006B operand encodings. The bit_field word at +10 encodes a
-- bit number as 12334 + 256*N — this is the constant we landed on after
-- pcap analysis.
M.operand_bit_base = 12334
M.operand_bit_stride = 256

-- Compressed-payload marker for description records. Indicates the
-- record body is a zlib stream rather than raw UTF-8.
M.compressed_marker = 0x8280

return M
