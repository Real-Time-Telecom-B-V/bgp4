//! Decoder tests against bytes that FRR and BIRD put on the wire.
//!
//! The vectors under `tests/vectors/` are produced by
//! `scripts/vectors/capture.sh`, and the values asserted here come from the
//! router configurations in that directory, not from this crate.

use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use bgp4::wire::{
    AddressFamily, AsPath, Capability, CeaseError, ErrorCode, Header, Ipv4Prefix, Keepalive,
    MessageType, Notification, Open, OpenError, Origin, Update, UpdateContext, HEADER_LENGTH,
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
        let expected = if name.contains("-open-") {
            MessageType::Open
        } else if name.contains("-update-") {
            MessageType::Update
        } else if name.contains("-notification-") {
            MessageType::Notification
        } else if name.contains("-keepalive-") {
            MessageType::Keepalive
        } else {
            panic!("{name}: unexpected message type in the file name")
        };
        assert_eq!(header.message_type(), expected, "{name}");
    }
}

#[test]
fn every_captured_keepalive_decodes() {
    let mut seen = 0;
    for (name, bytes) in all_vectors() {
        if name.contains("-keepalive-") {
            assert_eq!(Keepalive::decode(body(&bytes)), Ok(Keepalive), "{name}");
            seen += 1;
        }
    }
    assert!(seen >= 2, "expected keepalives from both implementations");
}

#[test]
fn frr_administrative_shutdown_with_communication() {
    let bytes = load("frr-shutdown-frr-notification-01.hex");
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
    let bytes = load("bird-disable-bird-notification-01.hex");
    let notification = Notification::decode(body(&bytes)).expect("decode");
    assert_eq!(
        notification.error(),
        ErrorCode::Cease(CeaseError::AdministrativeShutdown)
    );
    assert_eq!(notification.shutdown_communication(), Some("planned work"));
}

#[test]
fn bird_bad_peer_as_carries_the_offending_as_number() {
    let bytes = load("wrong-peer-as-bird-notification-01.hex");
    let notification = Notification::decode(body(&bytes)).expect("decode");
    assert_eq!(notification.error(), ErrorCode::Open(OpenError::BadPeerAs));
    // FRR is AS 64496 in scripts/vectors/frr.conf; BIRD reports it in 4 octets.
    assert_eq!(notification.data().as_ref(), 64496u32.to_be_bytes());
    assert_eq!(notification.shutdown_communication(), None);
}

const IPV4_UNICAST: Capability = Capability::Multiprotocol(AddressFamily::IPV4_UNICAST);
const IPV6_UNICAST: Capability = Capability::Multiprotocol(AddressFamily::IPV6_UNICAST);

fn open(name: &str) -> Open {
    let bytes = load(name);
    Open::decode(body(&bytes)).unwrap_or_else(|error| panic!("{name}: {error}"))
}

#[test]
fn every_captured_open_decodes() {
    let mut seen = 0;
    for (name, bytes) in all_vectors() {
        if name.contains("-open-") {
            let open = Open::decode(body(&bytes)).unwrap_or_else(|error| panic!("{name}: {error}"));
            // Both routers are configured with a hold time of 9 seconds.
            assert_eq!(open.hold_time(), 9, "{name}");
            seen += 1;
        }
    }
    assert!(seen >= 8, "expected OPENs from every scenario");
}

#[test]
fn frr_open() {
    let open = open("frr-shutdown-frr-open-01.hex");
    assert_eq!(open.autonomous_system(), 64496);
    assert_eq!(open.my_autonomous_system(), 64496);
    assert_eq!(open.bgp_identifier(), Ipv4Addr::new(192, 0, 2, 1));
    for expected in [
        IPV4_UNICAST,
        IPV6_UNICAST,
        Capability::RouteRefresh,
        Capability::FourOctetAutonomousSystem(64496),
    ] {
        assert!(open.capabilities().contains(&expected), "{expected:?}");
    }
    // FRR announces its host name in capability 73, which this crate does not
    // interpret. It has to survive untouched: length octet, name, empty domain.
    let host_name = open
        .capabilities()
        .iter()
        .find_map(|capability| match capability {
            Capability::Unknown { code: 73, value } => Some(value.clone()),
            _ => None,
        })
        .expect("capability 73");
    assert_eq!(host_name.as_ref(), b"\x08bgp4-frr\x00");
}

#[test]
fn bird_open() {
    let open = open("frr-shutdown-bird-open-01.hex");
    assert_eq!(open.autonomous_system(), 64497);
    assert_eq!(open.my_autonomous_system(), 64497);
    assert_eq!(open.bgp_identifier(), Ipv4Addr::new(192, 0, 2, 2));
    for expected in [
        IPV4_UNICAST,
        IPV6_UNICAST,
        Capability::RouteRefresh,
        Capability::FourOctetAutonomousSystem(64497),
    ] {
        assert!(open.capabilities().contains(&expected), "{expected:?}");
    }
}

#[test]
fn bird_open_under_a_four_octet_as_number_uses_as_trans() {
    let open = open("four-octet-as-bird-open-01.hex");
    assert_eq!(open.my_autonomous_system(), 23456);
    assert_eq!(open.autonomous_system(), 65550);
}

const FOUR_OCTET: UpdateContext = UpdateContext::new(true);

fn update(name: &str) -> Update {
    let bytes = load(name);
    let decoded =
        Update::decode(body(&bytes), FOUR_OCTET).unwrap_or_else(|error| panic!("{name}: {error}"));
    assert_eq!(decoded.errors, [], "{name}");
    decoded.update
}

fn prefix(a: u8, b: u8, c: u8, d: u8, length: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(a, b, c, d), length).expect("valid prefix")
}

/// The update among `<scenario>-<sender>-update-NN.hex` that announces `wanted`.
fn update_announcing(scenario: &str, sender: &str, wanted: Ipv4Prefix) -> Update {
    let stem = format!("{scenario}-{sender}-update-");
    let mut found = Vec::new();
    for (name, _) in all_vectors() {
        if name.starts_with(&stem) {
            let update = update(&name);
            if update.announced.contains(&wanted) {
                found.push(update);
            }
        }
    }
    assert_eq!(found.len(), 1, "{stem}*: updates announcing {wanted}");
    found.remove(0)
}

#[test]
fn every_captured_update_decodes_without_a_single_error() {
    let mut seen = 0;
    for (name, _) in all_vectors() {
        if name.contains("-update-") {
            update(&name);
            seen += 1;
        }
    }
    assert!(seen >= 20, "expected updates from every scenario");
}

/// scripts/vectors/frr.conf: network 198.51.100.0/24, exported with metric 50,
/// one AS prepended, and three kinds of communities.
#[test]
fn frr_announcement() {
    let update = update_announcing("frr-shutdown", "frr", prefix(198, 51, 100, 0, 24));
    assert_eq!(update.announced, [prefix(198, 51, 100, 0, 24)]);
    assert!(update.withdrawn.is_empty());
    let attributes = &update.attributes;
    assert_eq!(attributes.origin, Some(Origin::Igp));
    assert_eq!(attributes.as_path, Some(AsPath::sequence([64496, 64496])));
    assert_eq!(attributes.next_hop, Some(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(attributes.multi_exit_discriminator, Some(50));
    assert_eq!(attributes.local_preference, None);
    assert!(!attributes.atomic_aggregate);
    assert_eq!(attributes.aggregator, None);

    // COMMUNITIES (8), EXTENDED COMMUNITIES (16) and LARGE_COMMUNITY (32) are
    // optional transitive attributes this crate does not interpret yet. They
    // have to come through byte for byte, marked partial.
    let unknown: Vec<(u8, bool, &[u8])> = attributes
        .unknown
        .iter()
        .map(|attribute| {
            (
                attribute.type_code(),
                attribute.partial(),
                attribute.value().as_ref(),
            )
        })
        .collect();
    assert_eq!(
        unknown,
        [
            // In the order FRR sends them, which is not ascending.
            // 64496:100
            (8, true, &[0xfb, 0xf0, 0x00, 0x64][..]),
            // 64496:1:2
            (32, true, &[0, 0, 0xfb, 0xf0, 0, 0, 0, 1, 0, 0, 0, 2][..]),
            // rt 64496:1, a 2-octet AS route target
            (16, true, &[0x00, 0x02, 0xfb, 0xf0, 0, 0, 0, 1][..]),
        ]
    );
}

/// scripts/vectors/bird.conf: static 203.0.113.0/24, exported with MED 70.
#[test]
fn bird_announcement() {
    let update = update_announcing("frr-shutdown", "bird", prefix(203, 0, 113, 0, 24));
    let attributes = &update.attributes;
    assert_eq!(attributes.origin, Some(Origin::Igp));
    assert_eq!(attributes.as_path, Some(AsPath::sequence([64497])));
    assert_eq!(attributes.next_hop, Some(Ipv4Addr::new(192, 0, 2, 2)));
    assert_eq!(attributes.multi_exit_discriminator, Some(70));
    let unknown: Vec<u8> = attributes
        .unknown
        .iter()
        .map(|attribute| attribute.type_code())
        .collect();
    assert_eq!(unknown, [8, 32]);
}

/// FRR passes BIRD's route back with its own AS in front, prepended once more
/// by the export route map.
#[test]
fn frr_readvertises_the_route_it_learned() {
    let update = update_announcing("frr-shutdown", "frr", prefix(203, 0, 113, 0, 24));
    assert_eq!(
        update.attributes.as_path,
        Some(AsPath::sequence([64496, 64496, 64497]))
    );
}

#[test]
fn bird_as_path_under_a_four_octet_as_number() {
    let update = update_announcing("four-octet-as", "bird", prefix(203, 0, 113, 0, 24));
    assert_eq!(update.attributes.as_path, Some(AsPath::sequence([65550])));
}

#[test]
fn end_of_rib_marker_is_an_empty_update() {
    let mut seen = 0;
    for (name, bytes) in all_vectors() {
        if name.contains("-update-") && bytes.len() == HEADER_LENGTH + 4 {
            assert_eq!(update(&name), Update::default(), "{name}");
            seen += 1;
        }
    }
    assert!(seen >= 2, "expected an end-of-RIB marker from each side");
}
