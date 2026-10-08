# bgp4

A pure-Rust BGP-4 speaker library.

> **Status: early development.** Nothing is published to crates.io yet and the
> API is not stable. See [docs/COMPLIANCE.md](docs/COMPLIANCE.md) for what is
> implemented.

## What it is for

`bgp4` lets a network service peer with a router as a customer edge: it holds
BGP sessions, announces the prefixes the application tells it to, and hands
learned routes to the application. Typical use is a service that should attract
traffic only while it can actually serve it.

It is a speaker, not a router:

- eBGP, iBGP and confederation sessions, IPv4 and IPv6 unicast.
- Per-session identity: local ASN, remote ASN, addresses, timers, policy.
- Conservative defaults. Nothing is announced or accepted without explicit
  policy.
- No Internet-scale RIB, no VPN address families, no forwarding, no
  configuration file format. Those belong to the router or to the application.

## Design

The crate is layered so that the codec and the state machine can be tested
without a socket:

| Module | Responsibility | I/O |
| --- | --- | --- |
| `wire` | Encode and decode messages, attributes and NLRI | None |
| `fsm` | RFC 4271 state machine: events in, actions out | None, time is injected |
| `session` | TCP, socket options, timers, framing | async |
| `rib`, `policy` | Per-peer tables, best path, filters | None |
| `speaker` | Owns peers and tables, public handle, event stream | async |

Encoders are validated against an independent decoder (Wireshark) and decoders
against bytes produced by independent implementations, never by round-trip
alone.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo deny check
```

## License

MIT. See [LICENSE](LICENSE).
