//! Decoder tests against bytes that FRR and BIRD put on the wire.
//!
//! The vectors under `tests/vectors/` are produced by
//! `scripts/vectors/capture.sh`, and the values asserted here come from the
//! router configurations in that directory, not from this crate.

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use bgp4::wire::{
    AddressFamily, AsPath, Capability, CeaseError, Community, ErrorCode, ExtendedCommunity, Header,
    Ipv4Prefix, Ipv6NextHop, Ipv6Prefix, Keepalive, LargeCommunity, MessageType, Notification,
    Open, OpenError, Origin, SessionType, Update, UpdateContext, HEADER_LENGTH,
};
use bgp4::wire::{Message, RouteRefresh, RouteRefreshSubtype};
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

/// Every captured vector as (file name, bytes), sorted by file name.
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
    // Directory order is up to the file system. Sorted by name, the messages
    // of one sender and type are in the order they were sent.
    vectors.sort();
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
        } else if name.contains("-route-refresh-") {
            MessageType::RouteRefresh
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

const FOUR_OCTET: UpdateContext = UpdateContext::new(true, SessionType::External);
const TWO_OCTET: UpdateContext = UpdateContext::new(false, SessionType::External);

/// In the `two-octet-session` scenario BIRD does not announce the 4-octet AS
/// capability, so AS numbers on that session are 2 octets wide.
fn context(name: &str) -> UpdateContext {
    if name.starts_with("two-octet-session-") {
        TWO_OCTET
    } else {
        FOUR_OCTET
    }
}

fn update(name: &str) -> Update {
    let bytes = load(name);
    let decoded = Update::decode(body(&bytes), context(name))
        .unwrap_or_else(|error| panic!("{name}: {error}"));
    assert_eq!(decoded.errors, [], "{name}");
    decoded.update
}

fn prefix(a: u8, b: u8, c: u8, d: u8, length: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(a, b, c, d), length).expect("valid prefix")
}

/// The one update among `<scenario>-<sender>-update-NN.hex` that `matches`
/// picks. A router may send the same route twice, so duplicates are folded.
fn the_update(scenario: &str, sender: &str, matches: impl Fn(&Update) -> bool) -> Update {
    let stem = format!("{scenario}-{sender}-update-");
    let mut found: Vec<Update> = Vec::new();
    for (name, _) in all_vectors() {
        if name.starts_with(&stem) {
            let update = update(&name);
            if matches(&update) && !found.contains(&update) {
                found.push(update);
            }
        }
    }
    assert_eq!(found.len(), 1, "{stem}*: {found:?}");
    found.remove(0)
}

fn update_announcing(scenario: &str, sender: &str, wanted: Ipv4Prefix) -> Update {
    the_update(scenario, sender, |update| {
        update.announced.contains(&wanted)
    })
}

fn update_announcing_ipv6(scenario: &str, sender: &str, wanted: Ipv6Prefix) -> Update {
    the_update(scenario, sender, |update| {
        update.ipv6_announced.contains(&wanted)
    })
}

fn ipv6_prefix(address: &str, length: u8) -> Ipv6Prefix {
    Ipv6Prefix::new(address.parse().expect("address"), length).expect("valid prefix")
}

fn ipv6(address: &str) -> Ipv6Addr {
    address.parse().expect("address")
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

    // set community 64496:100, set extcommunity rt 64496:1 (a 2-octet AS
    // route target is type 0x00, subtype 0x02), set large-community 64496:1:2.
    assert_eq!(attributes.communities, [Community::new(64496, 100)]);
    assert_eq!(
        attributes.extended_communities,
        [ExtendedCommunity([0x00, 0x02, 0xfb, 0xf0, 0, 0, 0, 1])]
    );
    assert_eq!(
        attributes.large_communities,
        [LargeCommunity {
            global_administrator: 64496,
            local_data_1: 1,
            local_data_2: 2
        }]
    );
    assert!(attributes.unknown.is_empty());
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
    // bgp_community.add((64497, 200)); bgp_large_community.add((64497, 1, 2));
    assert_eq!(attributes.communities, [Community::new(64497, 200)]);
    assert_eq!(
        attributes.large_communities,
        [LargeCommunity {
            global_administrator: 64497,
            local_data_1: 1,
            local_data_2: 2
        }]
    );
    assert!(attributes.extended_communities.is_empty());
    assert!(attributes.unknown.is_empty());
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

/// scripts/vectors/frr.conf: network 2001:db8:100::/48 in the IPv6 unicast
/// family of the same session. The next hop is the address the capture script
/// gives the FRR container, with the link-local address of its fixed MAC.
#[test]
fn frr_ipv6_announcement() {
    let update = update_announcing_ipv6("frr-shutdown", "frr", ipv6_prefix("2001:db8:100::", 48));
    assert_eq!(update.ipv6_announced, [ipv6_prefix("2001:db8:100::", 48)]);
    assert!(update.ipv6_withdrawn.is_empty());
    assert!(update.announced.is_empty());
    assert_eq!(
        update.ipv6_next_hop,
        Some(Ipv6NextHop {
            global: ipv6("2001:db8:0:1::11"),
            link_local: Some(ipv6("fe80::200:5eff:fe00:5301")),
        })
    );
    let attributes = &update.attributes;
    assert_eq!(attributes.origin, Some(Origin::Igp));
    assert_eq!(attributes.as_path, Some(AsPath::sequence([64496, 64496])));
    assert_eq!(attributes.next_hop, None);
    assert_eq!(attributes.multi_exit_discriminator, Some(50));
    assert_eq!(attributes.communities, [Community::new(64496, 100)]);
}

/// scripts/vectors/bird.conf: static 2001:db8:200::/48.
#[test]
fn bird_ipv6_announcement() {
    let update = update_announcing_ipv6("frr-shutdown", "bird", ipv6_prefix("2001:db8:200::", 48));
    assert_eq!(
        update.ipv6_next_hop,
        Some(Ipv6NextHop {
            global: ipv6("2001:db8:0:1::12"),
            link_local: Some(ipv6("fe80::200:5eff:fe00:5302")),
        })
    );
    assert_eq!(update.attributes.as_path, Some(AsPath::sequence([64497])));
    assert_eq!(update.attributes.multi_exit_discriminator, Some(70));
}

/// With `enable as4 off` BIRD sends no 4-octet AS capability, and the AS
/// number comes from the 2-octet field.
#[test]
fn bird_open_without_the_four_octet_capability() {
    let open = open("two-octet-session-bird-open-01.hex");
    assert!(!open
        .capabilities()
        .iter()
        .any(|capability| matches!(capability, Capability::FourOctetAutonomousSystem(_))));
    assert_eq!(open.autonomous_system(), 64497);
}

/// The capture script adds `set as-path prepend 65550 64496` to FRR's export
/// route map for this scenario, and FRR puts its own AS in front. Toward a
/// peer without 4-octet AS numbers it sends AS_TRANS in AS_PATH and the real
/// path in AS4_PATH; the decoder has to put the two back together.
#[test]
fn frr_as4_path_is_merged_back_into_the_path() {
    let update = update_announcing("two-octet-session", "frr", prefix(198, 51, 100, 0, 24));
    assert_eq!(
        update.attributes.as_path,
        Some(AsPath::sequence([64496, 65550, 64496]))
    );
    assert!(update.attributes.unknown.is_empty());

    let readvertised = update_announcing("two-octet-session", "frr", prefix(203, 0, 113, 0, 24));
    assert_eq!(
        readvertised.attributes.as_path,
        Some(AsPath::sequence([64496, 65550, 64496, 64497]))
    );
}

#[test]
fn bird_two_octet_as_path() {
    let update = update_announcing("two-octet-session", "bird", prefix(203, 0, 113, 0, 24));
    assert_eq!(update.attributes.as_path, Some(AsPath::sequence([64497])));
}

fn route_refreshes(sender: &str) -> Vec<RouteRefresh> {
    let stem = format!("frr-shutdown-{sender}-route-refresh-");
    all_vectors()
        .into_iter()
        .filter(|(name, _)| name.starts_with(&stem))
        .map(|(name, bytes)| {
            RouteRefresh::decode(body(&bytes)).unwrap_or_else(|error| panic!("{name}: {error}"))
        })
        .collect()
}

fn refresh(address_family: AddressFamily, subtype: RouteRefreshSubtype) -> RouteRefresh {
    RouteRefresh {
        address_family,
        subtype,
    }
}

/// The capture script runs `clear bgp ipv4 unicast 192.0.2.2 soft in` on FRR
/// and `reload in peer` on BIRD. Both routers negotiated enhanced route
/// refresh with each other, so each answers the other's request by marking
/// the beginning and the end of the refresh.
#[test]
fn route_refresh_requests_and_markers() {
    let frr = route_refreshes("frr");
    let bird = route_refreshes("bird");
    let request = RouteRefreshSubtype::Request;
    let begin = RouteRefreshSubtype::BeginOfRefresh;
    let end = RouteRefreshSubtype::EndOfRefresh;

    // FRR asks for IPv4 unicast only, BIRD for both families.
    let requests = |messages: &[RouteRefresh]| -> Vec<AddressFamily> {
        messages
            .iter()
            .filter(|message| message.subtype == request)
            .map(|message| message.address_family)
            .collect()
    };
    assert_eq!(requests(&frr), [AddressFamily::IPV4_UNICAST]);
    assert_eq!(
        requests(&bird),
        [AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST]
    );

    // Each answers what the other asked for.
    for family in [AddressFamily::IPV4_UNICAST, AddressFamily::IPV6_UNICAST] {
        assert!(frr.contains(&refresh(family, begin)), "{family:?}");
        assert!(frr.contains(&refresh(family, end)), "{family:?}");
    }
    assert!(bird.contains(&refresh(AddressFamily::IPV4_UNICAST, begin)));
    assert!(bird.contains(&refresh(AddressFamily::IPV4_UNICAST, end)));
    assert!(!bird.contains(&refresh(AddressFamily::IPV6_UNICAST, begin)));
}

/// Every captured message goes through the one entry point a session uses,
/// and comes out as the variant its file name says.
#[test]
fn every_captured_message_decodes_through_the_single_entry_point() {
    for (name, bytes) in all_vectors() {
        let message = Message::decode(Bytes::copy_from_slice(&bytes), context(&name))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let matches = match message {
            Message::Open(_) => name.contains("-open-"),
            Message::Update(decoded) => {
                assert_eq!(decoded.errors, [], "{name}");
                name.contains("-update-")
            }
            Message::Notification(_) => name.contains("-notification-"),
            Message::Keepalive => name.contains("-keepalive-"),
            Message::RouteRefresh(_) => name.contains("-route-refresh-"),
        };
        assert!(matches, "{name}");
    }
}
