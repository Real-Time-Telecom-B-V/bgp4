//! The body of an UPDATE, without the header in the way of the fuzzer.
//!
//! The first octet picks the session context. An UPDATE that decodes has had
//! the RFC 7606 repairs applied, so it must encode again or be refused with
//! an error, never panic.

#![no_main]

mod context;

use bgp4::wire::Update;
use bytes::{Bytes, BytesMut};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((selector, body)) = data.split_first() else {
        return;
    };
    let context = context::context(*selector);
    let mut buffer = BytesMut::new();
    match Update::decode(Bytes::copy_from_slice(body), context) {
        Ok(decoded) => {
            let _ = decoded.update.encode(context, &mut buffer);
            let _ = decoded.update.encode_split(context, &mut buffer);
        }
        Err(error) => {
            let _ = error.notification().encode(&mut buffer);
        }
    }
});
