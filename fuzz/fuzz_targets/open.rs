//! The body of an OPEN, without the header in the way of the fuzzer.

#![no_main]

use bgp4::wire::Open;
use bytes::{Bytes, BytesMut};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buffer = BytesMut::new();
    match Open::decode(Bytes::copy_from_slice(data)) {
        Ok(open) => {
            let _ = open.autonomous_system();
            let _ = open.encode(&mut buffer);
        }
        Err(error) => {
            let _ = error.notification().encode(&mut buffer);
        }
    }
});
