//! Decoder tests against bytes that FRR and BIRD put on the wire.
//!
//! The vectors under `tests/vectors/` are produced by
//! `scripts/vectors/capture.sh`, and the values asserted here come from the
//! router configurations in that directory, not from this crate.

use std::fs;
use std::path::PathBuf;

use bgp4::wire::{
    CeaseError, ErrorCode, Header, Keepalive, MessageType, Notification, OpenError, HEADER_LENGTH,
};
use bytes::Bytes;

fn vector_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn decode_hex(text: &str) -> Vec<u8> {
    let text = text.trim();
    assert!(text.len().is_multiple_of(2), "odd number of hex digits");
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex digit"))
        .collect()
}

fn load(name: &str) -> Vec<u8> {
    let path = vector_directory().join(name);
    decode_hex(&fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path:?}: {error}")))
}

/// Every captured vector as (file name, bytes).
fn all_vectors() -> Vec<(String, Vec<u8>)> {
    let mut vectors = Vec::new();
    for entry in fs::read_dir(vector_directory()).expect("vector directory") {
        let name = entry
            .expect("entry")
            .file_name()
            .into_string()
            .expect("name");
        if name.ends_with(".hex") {
            let bytes = load(&name);
            vectors.push((name, bytes));
        }
    }
    assert!(vectors.len() >= 10, "vector set looks incomplete");
    vectors
}

fn body(message: &[u8]) -> Bytes {
    Bytes::copy_from_slice(&message[HEADER_LENGTH..])
}

#[test]
fn every_captured_header_decodes_to_the_type_and_length_on_the_wire() {
    for (name, bytes) in all_vectors() {
        let header = Header::decode(&bytes)
            .unwrap_or_else(|error| panic!("{name}: {error}"))
            .unwrap_or_else(|| panic!("{name}: header incomplete"));
        assert_eq!(usize::from(header.length()), bytes.len(), "{name}");
        let expected = match name.rsplit('-').next().expect("suffix") {
            "open.hex" => MessageType::Open,
            "update.hex" => MessageType::Update,
            "notification.hex" => MessageType::Notification,
            "keepalive.hex" => MessageType::Keepalive,
            other => panic!("{name}: unexpected suffix {other}"),
        };
        assert_eq!(header.message_type(), expected, "{name}");
    }
}

#[test]
fn every_captured_keepalive_decodes() {
    let mut seen = 0;
    for (name, bytes) in all_vectors() {
        if name.ends_with("keepalive.hex") {
            assert_eq!(Keepalive::decode(body(&bytes)), Ok(Keepalive), "{name}");
            seen += 1;
        }
    }
    assert!(seen >= 2, "expected keepalives from both implementations");
}

#[test]
fn frr_administrative_shutdown_with_communication() {
    let bytes = load("frr-shutdown-20-frr-notification.hex");
    let notification = Notification::decode(body(&bytes)).expect("decode");
    assert_eq!(
        notification.error(),
        ErrorCode::Cease(CeaseError::AdministrativeShutdown)
    );
    assert_eq!(
        notification.shutdown_communication(),
        Some("maintenance window")
    );
}

#[test]
fn bird_administrative_shutdown_with_communication() {
    let bytes = load("bird-disable-17-bird-notification.hex");
    let notification = Notification::decode(body(&bytes)).expect("decode");
    assert_eq!(
        notification.error(),
        ErrorCode::Cease(CeaseError::AdministrativeShutdown)
    );
    assert_eq!(notification.shutdown_communication(), Some("planned work"));
}

#[test]
fn bird_bad_peer_as_carries_the_offending_as_number() {
    let bytes = load("wrong-peer-as-02-bird-notification.hex");
    let notification = Notification::decode(body(&bytes)).expect("decode");
    assert_eq!(notification.error(), ErrorCode::Open(OpenError::BadPeerAs));
    // FRR is AS 64496 in scripts/vectors/frr.conf; BIRD reports it in 4 octets.
    assert_eq!(notification.data().as_ref(), 64496u32.to_be_bytes());
    assert_eq!(notification.shutdown_communication(), None);
}
