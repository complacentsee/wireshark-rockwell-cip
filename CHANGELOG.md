# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Repository skeleton, GPL-2.0-or-later license, .gitignore.
- Plugin master loader (`plugins/lua/rockwell_cip.lua`).
- Value-string tables for Rockwell-private CIP services and classes
  (`plugins/lua/util/valstr.lua`).
- `tools/sync_constants.py` — codegen that pulls service / class / record
  layout constants from `logix_fw/cip_upload/extract_logix_data.py`,
  preventing drift between the Python extractor and this dissector.
- `tools/sanitize_pcap.py` — fixture sanitiser; strips controller serial
  numbers, HMAC keys, and tag-value payloads before committing capture
  fixtures.
- `tests/conftest.py` + `tests/test_lua_dissector.py` — pytest harness
  that runs `tshark` with the plugin and diffs PDML against expected.
