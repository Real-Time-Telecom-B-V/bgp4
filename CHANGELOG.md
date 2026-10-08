# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the crate follows
the rules in [VERSIONING.md](VERSIONING.md).

## [Unreleased]

### Added

- Repository scaffold: CI (fmt, clippy, tests), dependency policy
  (`cargo-deny`), release workflow, and the RFC compliance table.
- `wire`: message header, KEEPALIVE and NOTIFICATION codec. Header validation
  follows RFC 4271 section 6.1, and every decode error yields the NOTIFICATION
  to send. Error subcodes of RFC 4271, 4486, 5492, 6608, 8538 and 9234 are
  named, unknown ones are kept as received. Shutdown communication (RFC 9003)
  is supported on Administrative Shutdown and Administrative Reset.
- `wire`: OPEN codec with capabilities (RFC 5492): multiprotocol, route
  refresh and 4-octet AS, with AS_TRANS in the fixed field for AS numbers
  above 65535 (RFC 6793). Capabilities the crate does not interpret are kept
  byte for byte. Version, hold time and identifier are checked as RFC 4271
  section 6.2 and RFC 6286 require.
