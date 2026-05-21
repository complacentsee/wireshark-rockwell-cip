# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Repository skeleton, GPL-2.0-or-later license, .gitignore.
- Plugin master loader (`plugins/lua/rockwell_cip.lua`); each per-feature
  sub-module registers fields, experts, and a dissect callback via a
  shared `ctx` so the master assigns `proto.fields` exactly once.
- Per-feature sub-modules:
  - `class_0064_handshake` — Phase 1/2 message decomposition; caches
    challenge[0:64] / [64:128] as HMAC-key candidates. When the user
    sets the `rockwell_cip.client_rsa_key_file` preference, RSA-
    decrypts each Phase 1 challenge (LE byte order, Rockwell quirk),
    stashes plaintext[0:64] as the session HMAC key, and surfaces
    `derived_hmac_key` + `kdf_status` fields. service_36_signed and
    service_3a_upload then validate every trailer with no further
    user input.
  - `service_36_signed` — 0x36/0xB6 wrapper, inner CIP recursion, HMAC
    validation against preference + handshake candidates.
  - `service_3a_upload` — 0x3A/0xBA wrapper with state enum, chunk-
    header / zlib split, single-frame inflate behind a preference.
  - `class_0349_docs` — six-layout description-record walker with
    multi-chunk reassembly: paginated 0x53 replies (v36 stride 458B)
    have their page_data concatenated per-conversation so records that
    straddle the chunk boundary decode correctly; continuation frames
    surface `continuation=true` + `chunk_size` + `complete_in`, and
    completion-side records gain `chunks_in` + `first_chunk`. Gap
    detection on the echoed request-offset resets the accumulator when
    a carved/dropped capture skips intermediate pages.
  - `class_attrs` — class 0x6C / 0x8D attribute name hints,
    UDIParameters magic detection.
- Shared utilities under `plugins/lua/util/`:
  - `sha1` — pure-Lua SHA-1 + HMAC-SHA1 (verified vs RFC 2202).
  - `inflate` — pure-Lua RFC-1951/1950.
  - `session` — per-stream state keyed by canonical conv tuple.
  - `bigint` — minimal arbitrary-precision unsigned integer (add /
    sub / mul / divmod / modexp / modinv), 16-bit limbs, sized for
    1024-bit RSA. Drives the Path-A KDF.
  - `rsa` — textbook RSA private-key decryption with CRT speedup
    and Rockwell little-endian byte ordering. Backed by `bigint`.
  - `pem` — minimal PEM/DER parser for PKCS#1 RSAPrivateKey and
    unencrypted PKCS#8 wrappers. Just enough ASN.1 to feed `rsa`.
- Value-string tables for Rockwell-private CIP services and classes
  (`plugins/lua/util/valstr.lua`).
- `tools/sync_constants.py` — codegen scaffold that will pull service /
  class / record layout constants from the out-of-tree Python
  extractor (`extract_logix_data.py`) once the Python side exports
  them at module scope.
- `tools/derive_hmac_key.py` — offline derivation of the Path-A 64B
  session HMAC key for users who'd rather paste it into the existing
  `rockwell_cip.hmac_key` preference than configure the RSA-key path.
  Same math as the in-dissector KDF; works with either `cryptography`
  or `openssl` on PATH.
- `tests/conftest.py` + `tests/test_lua_dissector.py` — pytest harness
  that runs `tshark` with the plugin and diffs PDML against expected.
  Pins TZ=UTC and normalises the volatile PDML header so diffs stay
  meaningful across hosts.
- `tests/test_lua_crypto.{py,lua}` — fixed-vector tests for bigint /
  rsa / pem against hand-checked small values plus a toy RSA key.
- `tests/test_phase_a_kdf.py` — synthetic 1024-bit RSA round-trip:
  openssl mints a keypair, Python builds a Rockwell-LE ciphertext,
  Lua decrypts it back to the expected plaintext. Skipped when either
  `openssl` or `lua` is missing.
- `tests/expected/*.pdml` — committed reference output for the carved
  fixtures (handshake_phase12, upload_3a_seq, docs_blob). Regenerate
  with `pytest --regen` after intentional dissector changes.
- `CONTRIBUTING.md` — ground rules (no-pcaps policy, license,
  no-controller-identifying-material) plus the contributor mechanics
  (fixture setup, test workflow, dissector contract, commit style).
- `plugins/lua/.luacheckrc` — Wireshark Lua globals + project lint
  rules in one place; CI's `luacheck` step picks it up automatically.
