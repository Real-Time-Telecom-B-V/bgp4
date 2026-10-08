# Versioning

`bgp4` follows [Semantic Versioning 2.0.0](https://semver.org/).

**bgp4 is a library, so its public Rust API _is_ the contract.** Everything
reachable as `pub` from the crate root is covered.

Until `1.0.0` the crate is in initial development: a `0.y.0` release may break
the API, and a `0.y.z` release may not.

## The git tag is the source of truth

`Cargo.toml`'s `version` is set to match the release tag, and the release
workflow's `verify-version` job **refuses to publish** if they disagree. To
release, bump `version`, commit, tag `vX.Y.Z`, and push the tag. The tag push
publishes the crate (and the GitHub Release) at `X.Y.Z`.

## The rule (from 1.0.0)

**MAJOR (`X.0.0`)** breaks the public API:

- Remove / rename / change the signature of a `pub` item.
- Change documented behavior in a way that breaks existing callers.
- Removals happen only **one minor after** a deprecation.

**MINOR (`x.Y.0`)** adds in a backward-compatible way:

- New `pub` items (functions, methods, message or attribute support, config knobs).
- **Deprecations**: mark deprecated, keep it working (removal is the next major).
- An MSRV bump (called out in the changelog).

**PATCH (`x.y.Z`)** fixes in a backward-compatible way:

- Bug fixes, performance improvements, behavior-neutral dependency bumps.
- **RFC conformance corrections**, *even when they change observable wire
  behavior.* The contract is "standards-compliant", so a correction toward the
  RFCs listed in `docs/COMPLIANCE.md` is a fix, not a break. **Document it
  loudly in the changelog.**

## Pre-releases

`X.Y.Z-rc.N` for validation before a stable tag. The crates.io "newest" pointer
advances only on stable releases.
