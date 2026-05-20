-- SPDX-License-Identifier: GPL-2.0-or-later
--
-- rockwell_cip.lua — master loader for the Rockwell-private CIP
-- extensions plugin. Pulls in one sub-module per service / class so the
-- on-disk layout mirrors how the C port (see proto-c/) would be split
-- into translation units.
--
-- Wireshark loads any .lua file under its plugins directory at startup,
-- so this file lives at the plugin root and 'requires' siblings via
-- relative paths.

-- Make sibling directories importable. Wireshark adds the plugin's own
-- directory to the Lua path, so we just need to nudge it for our
-- sub-directories. Layout:
--   plugins/lua/rockwell_cip.lua    -- this file
--   plugins/lua/lua/<module>.lua    -- sub-module files
--   plugins/lua/util/<helper>.lua   -- shared helpers (valstr, …)
local plugin_dir = debug.getinfo(1, "S").source
    :sub(2)                  -- strip the leading "@"
    :match("^(.*[/\\])")     -- drop the filename
if plugin_dir then
    package.path = plugin_dir .. "lua/?.lua;"
                .. plugin_dir .. "util/?.lua;"
                .. package.path
end

-- Load the shared bits first so sub-modules can pull from them.
local valstr = require "valstr"

-- The protocol stub. Each sub-module attaches its fields to this proto
-- so display filters get a single namespace ("rockwell_cip.*"). The
-- dissector function itself is a no-op — sub-modules register
-- themselves as Decode-As / heuristic handlers off the existing 'cip'
-- dissector.
local proto = Proto("rockwell_cip",
                    "Rockwell Automation CIP vendor extensions")

-- Sub-modules: each returns a register(proto, valstr) function so all
-- ProtoField allocation stays under our single proto.
local modules = {
    "service_36_signed",
    -- Future phases — uncomment as each lands so the load fails loud
    -- when the file is missing rather than silently skipping it.
    -- "service_3a_upload",
    -- "class_0349_docs",
    -- "class_0338_aoi",
    -- "class_006c_template",
    -- "class_008d_msgparams",
    -- "class_0064_handshake",
}

for _, name in ipairs(modules) do
    local ok, mod = pcall(require, name)
    if not ok then
        -- Don't kill the whole plugin if one sub-module has a typo.
        -- tshark surfaces this in stderr; Wireshark surfaces it in the
        -- Lua console.
        io.stderr:write(string.format(
            "[rockwell_cip] failed to load %s: %s\n", name, mod))
    elseif type(mod) == "table" and type(mod.register) == "function" then
        mod.register(proto, valstr)
    end
end

-- Expose the proto so users can `lua_script1:capture.lua` chains etc.
return proto
