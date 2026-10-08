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
- `wire`: UPDATE codec for IPv4 unicast: withdrawn routes, NLRI, and the
  ORIGIN, AS_PATH (all four segment types, 2 and 4 octet AS numbers),
  NEXT_HOP, MULTI_EXIT_DISC, LOCAL_PREF, ATOMIC_AGGREGATE and AGGREGATOR
  attributes. Optional transitive attributes the crate does not interpret are
  kept byte for byte and marked partial. Malformed attributes are handled per
  RFC 7606: treat-as-withdraw or attribute discard where the RFC allows it,
  a session reset only where it does not. The encoder derives flags and
  lengths, orders attributes by type code, and refuses an announcement
  without its mandatory attributes.
- Criterion bench for UPDATE encode and decode.
