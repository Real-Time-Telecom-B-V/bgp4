//! A whole message of any type, as a session would hand it to the codec.
//!
//! The first octet picks the session context, the rest is the frame. Decoding
//! must never panic, and whatever decodes must be safe to encode again.

#![no_main]

mod context;

use bgp4::wire::{Header, Message};
use bytes::{Bytes, BytesMut};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((selector, frame)) = data.split_first() else {
        return;
    };
    let context = context::context(*selector);
    let _ = Header::decode(frame);
    let mut buffer = BytesMut::new();
    match Message::decode(Bytes::copy_from_slice(frame), context) {
        Ok(Message::Open(open)) => {
            let _ = open.encode(&mut buffer);
        }
        Ok(Message::Update(decoded)) => {
            let _ = decoded.update.encode(context, &mut buffer);
            let _ = decoded.update.encode_split(context, &mut buffer);
        }
        Ok(Message::Notification(notification)) => {
            let _ = notification.shutdown_communication();
            let _ = notification.encode(&mut buffer);
        }
        Ok(Message::Keepalive) => {}
        Ok(Message::RouteRefresh(route_refresh)) => route_refresh.encode(&mut buffer),
        Err(error) => {
            // The reaction to a bad message must itself be sendable.
            let _ = error.notification().encode(&mut buffer);
        }
    }
});
