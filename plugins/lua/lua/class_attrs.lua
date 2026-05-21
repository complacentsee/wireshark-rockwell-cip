-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- class_attrs.lua — attribute-name + payload-marker annotations for
-- vendor-specific CIP classes whose stock-Wireshark coverage is just
-- "0xNNNN (Unknown)".
--
-- Classes handled:
--
--   0x006C  Template (UDT / AOI structure definition)
--           Attribute map for the GetAttrList path used during a
--           normal upload:
--             1  Template Handle (u32)
--             2  Member Count    (u16)
--             4  Struct Size     (u32)  -- in-memory layout size
--             5  Template Name   (UTF-8, null-terminated, w/ ";n" encoded
--                                 type-suffix tail)
--           Attribute IDs 6..15 are probed during research but their
--           meanings are not yet known; we tag them as "(reserved /
--           research)".
--
--   0x0338  AddOnInstruction Definition
--           Used in two ways:
--             * As a target class in 0x349 description records (handled
--               by class_0349_docs.lua).
--             * As an embedded payload format: AOI source blobs contain
--               a "UDIParameters\0" magic followed by a TLV that lists
--               the AOI's parameter definitions. We detect the magic
--               inside ANY frame the post-dissector sees and surface
--               the parameter list as a sub-tree.
--
--   0x008D  Message Parameters (controller-side state of MSG tags)
--           Attribute map matches the L5X <MessageParameters> tag:
--             2   MessageType    (u8)
--             3   AttributeWidth (u8)  -- inferred; affects ServiceCode
--             6   RemoteElement  (u16-len + UTF-8)
--             9   ConnectedFlag  (u8)
--             0A  ConnectionPath (UTF-8 string)
--             0F  CommTypeCode   (u8)
--             10  RequestedLength
--             1F  LargePacketUsage
--             23  ServiceCode    (u16)
--             24  ObjectType     (u16)
--             25  TargetObject / Instance (u32)
--             26  AttributeNumber (u16)
--             29  LocalIndex     (u16)
--
-- The annotation strategy is purely additive: we read cip.class +
-- cip.attribute from the stock dissector's emitted fields and append a
-- "Rockwell attribute hint" sub-tree with the friendly name. The user
-- still sees Wireshark's regular tree.

local M = {}

local TEMPLATE_ATTRS = {
    [1] = "Template Handle (u32)",
    [2] = "Member Count (u16)",
    [4] = "Struct Size (u32)",
    [5] = "Template Name (string)",
    [6] = "(reserved / research)",
    [7] = "(reserved / research)",
    [8] = "(reserved / research)",
    [9] = "(reserved / research)",
    [10] = "(reserved / research)",
    [11] = "(reserved / research)",
    [12] = "(reserved / research)",
    [13] = "(reserved / research)",
    [14] = "(reserved / research)",
    [15] = "(reserved / research)",
}

local MSGPARAMS_ATTRS = {
    [0x02] = "MessageType",
    [0x03] = "AttributeWidth",
    [0x06] = "RemoteElement (u16-len + UTF-8)",
    [0x09] = "ConnectedFlag",
    [0x0A] = "ConnectionPath (UTF-8)",
    [0x0F] = "CommTypeCode",
    [0x10] = "RequestedLength",
    [0x1F] = "LargePacketUsage",
    [0x23] = "ServiceCode (u16)",
    [0x24] = "ObjectType (u16)",
    [0x25] = "TargetObject / Instance (u32)",
    [0x26] = "AttributeNumber (u16)",
    [0x29] = "LocalIndex (u16)",
}

local AOI_RLL_MAGIC = "UDIParameters\0"

function M.register(proto, valstr, ctx)
    local f = {}
    f.template_attr = ProtoField.string(
        "rockwell_cip.template.attr_name",
        "Template Attribute (class 0x6C)")
    f.msgparams_attr = ProtoField.string(
        "rockwell_cip.msgparams.attr_name",
        "MessageParameters Attribute (class 0x8D)")
    f.udi_magic = ProtoField.bytes(
        "rockwell_cip.aoi.udi_magic",
        "UDIParameters magic", base.SPACE)
    f.udi_offset = ProtoField.uint32(
        "rockwell_cip.aoi.udi_offset",
        "UDIParameters offset within frame", base.DEC)
    f.udi_param_count = ProtoField.uint32(
        "rockwell_cip.aoi.param_count",
        "UDIParameters Count", base.DEC)
    f.udi_total_size = ProtoField.uint32(
        "rockwell_cip.aoi.total_size",
        "UDIParameters Total Size", base.DEC)
    f.udi_param = ProtoField.string(
        "rockwell_cip.aoi.param",
        "UDI Parameter")
    f.udi_param_name = ProtoField.string(
        "rockwell_cip.aoi.param_name",
        "Name")
    f.udi_param_type = ProtoField.uint8(
        "rockwell_cip.aoi.param_type",
        "Type Code", base.HEX)
    f.udi_param_usage = ProtoField.uint8(
        "rockwell_cip.aoi.param_usage",
        "Usage Direction", base.DEC, valstr.udi_usage)
    f.udi_param_vis = ProtoField.uint8(
        "rockwell_cip.aoi.param_vis",
        "Visibility Flags", base.HEX, valstr.udi_vis_flags)
    f.udi_param_inst = ProtoField.uint16(
        "rockwell_cip.aoi.param_inst",
        "Backing Tag Instance", base.DEC)

    for _, fld in pairs(f) do ctx.add_field(fld) end

    local field_cip_class    = Field.new("cip.class")
    local field_cip_attr     = Field.new("cip.attribute")

    local function annotate_attrs(_tvb, _pinfo, tree)
        local cl_fi = field_cip_class()
        if not cl_fi then return end
        local class = cl_fi.value
        if class ~= 0x6C and class ~= 0x8D then return end

        local attr_fi = field_cip_attr()
        if not attr_fi then return end
        local attr = attr_fi.value
        local map  = (class == 0x6C) and TEMPLATE_ATTRS or MSGPARAMS_ATTRS
        local name = map[attr]
        if not name then return end

        local subtree = tree:add(proto, attr_fi.range,
            string.format("Rockwell attribute hint (class 0x%X)", class))
        if class == 0x6C then
            subtree:add(f.template_attr,
                string.format("attr 0x%02X = %s", attr, name)):set_generated()
        else
            subtree:add(f.msgparams_attr,
                string.format("attr 0x%02X = %s", attr, name)):set_generated()
        end
    end

    local function decode_udi(buf, magic_off, subtree)
        -- buf is a raw Lua string (the whole tvb). Header at +14 after
        -- the magic: [section_type u16][version u16][param_count u32]
        -- [total_size u32]. Then `param_count` parameter records.
        local hdr = magic_off + 14   -- 0-based
        if hdr + 12 > #buf then return end
        local function u16(p) return string.byte(buf, p + 1)
                                 | (string.byte(buf, p + 2) << 8) end
        local function u32(p) return string.byte(buf, p + 1)
                                 | (string.byte(buf, p + 2) << 8)
                                 | (string.byte(buf, p + 3) << 16)
                                 | (string.byte(buf, p + 4) << 24) end
        local pcount = u32(hdr + 4)
        local tsize  = u32(hdr + 8)
        if pcount == 0 or pcount > 500 then return end
        subtree:add(f.udi_param_count, pcount):set_generated()
        subtree:add(f.udi_total_size,  tsize):set_generated()

        local pos = hdr + 12
        for i = 1, pcount do
            if pos + 24 > #buf then break end
            local entry_size = u16(pos)
            if entry_size < 25 or pos + entry_size > #buf then break end
            local type_code = string.byte(buf, pos + 5)
            local tag_inst  = u16(pos + 2)
            local usage     = string.byte(buf, pos + 21)
            local vis       = string.byte(buf, pos + 22)
            -- Name at pos+24 null-terminated within entry_size.
            local name_start = pos + 24
            local name_end   = string.find(buf, "\0", name_start + 1, true)
            if not name_end or name_end > pos + entry_size then
                name_end = pos + entry_size
            end
            local name = string.sub(buf, name_start + 1, name_end - 1)

            local entry_tree = subtree:add(f.udi_param,
                string.format("[%d] %s", i, name))
            entry_tree:add(f.udi_param_name, name):set_generated()
            entry_tree:add(f.udi_param_type, type_code):set_generated()
            entry_tree:add(f.udi_param_inst, tag_inst):set_generated()
            entry_tree:add(f.udi_param_usage, usage):set_generated()
            entry_tree:add(f.udi_param_vis, vis):set_generated()

            pos = pos + entry_size
        end
    end

    local function detect_udi(tvb, pinfo, tree)
        -- Scan for the magic in this frame; report it if present.
        local buf = tvb:bytes():raw()
        local pos = string.find(buf, AOI_RLL_MAGIC, 1, true)
        if not pos then return end
        -- pos is 1-based; convert to 0-based for Tvb addressing.
        local off = pos - 1
        local subtree = tree:add(proto, tvb:range(off, 14),
            "Rockwell AOI UDIParameters")
        subtree:add(f.udi_magic, tvb:range(off, 14))
        subtree:add(f.udi_offset, off):set_generated()
        pinfo.cols.info:append(" [UDIParameters]")
        decode_udi(buf, off, subtree)
    end

    local function dissect(tvb, pinfo, tree)
        annotate_attrs(tvb, pinfo, tree)
        detect_udi(tvb, pinfo, tree)
    end

    ctx.add_dissect("class_attrs", dissect)
end

return M
