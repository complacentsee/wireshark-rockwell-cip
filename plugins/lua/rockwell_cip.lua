-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- rockwell_cip.lua — master plugin loader for the Rockwell-private CIP
-- extensions dissector. Each per-feature sub-module under lua/ adds
-- ProtoFields to the single 'rockwell_cip' proto (so all display
-- filters share the namespace) and registers a dissect callback the
-- master dispatches in order.
--
-- Wireshark loads .lua files at the plugin directory's top level. We
-- expose siblings via package.path so sub-modules and shared utils can
-- `require` each other.

local plugin_dir = debug.getinfo(1, "S").source
    :sub(2)
    :match("^(.*[/\\])")
if plugin_dir then
    package.path = plugin_dir .. "lua/?.lua;"
                .. plugin_dir .. "util/?.lua;"
                .. package.path
end

local proto = Proto("rockwell_cip",
                    "Rockwell Automation CIP vendor extensions")

local valstr = require "valstr"

-- Sub-module contract:
--   mod.register(proto, valstr, ctx)  -- one call per module
--   ctx.add_field(fld)    -> appends ProtoField; the master assigns
--                            proto.fields ONCE after all modules ran
--                            (Wireshark only honours a single
--                            proto.fields assignment per Proto, so
--                            modules cannot append in place)
--   ctx.add_expert(e)     -> same for ProtoExpert / proto.experts
--   ctx.add_dissect(name, fn) -> appends a per-packet callback to a
--                                chain the master dispatches in order
local all_fields  = {}
local all_experts = {}
local callbacks   = {}

local ctx = {
    add_field   = function(fld) table.insert(all_fields,  fld) end,
    add_expert  = function(e)   table.insert(all_experts, e)   end,
    add_dissect = function(name, fn)
        table.insert(callbacks, { name = name, fn = fn })
    end,
}

local modules = {
    "class_0064_handshake",   -- run first so the HMAC key is cached
                              -- before signed/upload modules look it up
    "service_36_signed",
    "service_3a_upload",
    "class_0349_docs",
    "class_attrs",        -- 0x6C / 0x8D attribute names, 0x338 UDIParameters
    -- Future sub-modules; uncomment when added.
    -- "class_0349_docs",
    -- "class_0338_aoi",
    -- "class_006c_template",
    -- "class_008d_msgparams",
}

for _, name in ipairs(modules) do
    local ok, mod = pcall(require, name)
    if not ok then
        io.stderr:write(string.format(
            "[rockwell_cip] failed to load %s: %s\n", name, mod))
    elseif type(mod) == "table" and type(mod.register) == "function" then
        local rok, rerr = pcall(mod.register, proto, valstr, ctx)
        if not rok then
            io.stderr:write(string.format(
                "[rockwell_cip] %s.register() failed: %s\n", name, rerr))
        end
    end
end

-- Single assignment per Proto. After this, Wireshark allocates the
-- field IDs and the proto is frozen w.r.t. field schema.
proto.fields  = all_fields
proto.experts = all_experts

-- Master dissector: invoke each sub-module's dissect in turn. We don't
-- short-circuit — every callback may want to annotate the same frame
-- (e.g. the handshake module and the signed module both react to
-- different service codes, but both can see every packet).
function proto.dissector(tvb, pinfo, tree)
    for _, cb in ipairs(callbacks) do
        local ok, err = pcall(cb.fn, tvb, pinfo, tree)
        if not ok then
            io.stderr:write(string.format(
                "[rockwell_cip] %s.dissect failed: %s\n", cb.name, err))
        end
    end
end

register_postdissector(proto, true)

return proto
