//! A pure-Rust BGP-4 speaker library.
//!
//! The crate is being built in layers so that the codec and the state machine
//! are testable without a socket. See `docs/COMPLIANCE.md` for what is
//! implemented against which RFC.

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod wire;
