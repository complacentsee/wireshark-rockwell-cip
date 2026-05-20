-- SPDX-License-Identifier: GPL-2.0-or-later
-- luacheck config for the Wireshark Lua plugin.
std = "max"

read_globals = {
    "Proto", "ProtoField", "ProtoExpert",
    "Dissector", "DissectorTable",
    "Field", "Tvb", "ByteArray",
    "Pref",
    "base", "expert",
    "register_postdissector",
    "UInt64", "Int64",
}

-- Per-packet dissector code naturally has tight loops with locals
-- that aren't all used on every path.
ignore = {"212/_.*"}   -- unused arg names starting with underscore

files["plugins/lua/rockwell_cip.lua"] = {}
