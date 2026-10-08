//! Encoder tests: what this crate emits is handed to Wireshark's BGP
//! dissector, and the fields it reads back are asserted.
//!
//! A round-trip through our own decoder would share any bug with the encoder;
//! Wireshark does not. A field that comes back empty or a `[Malformed]` flag is
//! an encoder bug.
//!
//! Needs `text2pcap` and `tshark`. Without them the tests are skipped with a
//! message, unless `BGP4_REQUIRE_WIRESHARK` is set (CI sets it), in which case
//! they fail.

use std::fs;
use std::process::Command;

use std::net::Ipv4Addr;

use bgp4::wire::{
    AddressFamily, Aggregator, AsPath, AsPathSegment, Capability, CeaseError, Community, ErrorCode,
    ExtendedCommunity, FiniteStateMachineError, Header, Ipv4Prefix, Keepalive, LargeCommunity,
    Notification, Open, OpenError, Origin, PathAttributes, SegmentKind, SessionType,
    UnknownAttribute, Update, UpdateContext,
};
use bytes::{Bytes, BytesMut};

fn wireshark_available() -> bool {
    let present = |program: &str| {
        Command::new(program)
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    };
    if present("text2pcap") && present("tshark") {
        return true;
    }
    if std::env::var_os("BGP4_REQUIRE_WIRESHARK").is_some() {
        panic!("BGP4_REQUIRE_WIRESHARK is set but text2pcap/tshark are not installed");
    }
    eprintln!("SKIPPED: text2pcap/tshark not installed, encoder not validated");
    false
}

/// Dissect one BGP message and return the requested fields, in order.
fn dissect(name: &str, message: &[u8], fields: &[&str]) -> Vec<String> {
    // The system temporary directory, not the target directory: a confined
    // tshark (AppArmor, snap) is often not allowed to read under $HOME.
    let directory = std::env::temp_dir().join(format!("bgp4-wireshark-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("create scratch directory");
    let dump = directory.join(format!("{name}.txt"));
    let capture = directory.join(format!("{name}.pcap"));

    let hex: Vec<String> = message.iter().map(|octet| format!("{octet:02x}")).collect();
    fs::write(&dump, format!("000000 {}\n", hex.join(" "))).expect("write hex dump");

    let converted = Command::new("text2pcap")
        .args(["-q", "-T", "179,179"])
        .arg(&dump)
        .arg(&capture)
        .output()
        .expect("run text2pcap");
    assert!(
        converted.status.success(),
        "text2pcap failed: {converted:?}"
    );

    let mut command = Command::new("tshark");
    command
        .arg("-r")
        .arg(&capture)
        .args(["-T", "fields", "-E", "separator=|"]);
    for field in fields.iter().chain(&["_ws.malformed"]) {
        command.args(["-e", field]);
    }
    let output = command.output().expect("run tshark");
    assert!(output.status.success(), "tshark failed: {output:?}");
    let _ = fs::remove_file(&dump);
    let _ = fs::remove_file(&capture);

    let line = String::from_utf8(output.stdout).expect("utf-8 from tshark");
    let mut values: Vec<String> = line
        .trim_end_matches('\n')
        .split('|')
        .map(str::to_owned)
        .collect();
    assert_eq!(
        values.len(),
        fields.len() + 1,
        "unexpected output: {line:?}"
    );
    let malformed = values.pop().expect("malformed column");
    assert_eq!(malformed, "", "Wireshark flagged the message as malformed");
    values
}

fn encode(notification: &Notification) -> Vec<u8> {
    let mut buffer = BytesMut::new();
    notification.encode(&mut buffer).expect("encode");
    buffer.to_vec()
}

#[test]
fn keepalive() {
    if !wireshark_available() {
        return;
    }
    let mut buffer = BytesMut::new();
    Keepalive.encode(&mut buffer);
    let fields = dissect("keepalive", &buffer, &["bgp.type", "bgp.length"]);
    assert_eq!(fields, ["4", "19"]);
}

#[test]
fn cease_administrative_shutdown_with_communication() {
    if !wireshark_available() {
        return;
    }
    let notification =
        Notification::administrative_shutdown("maintenance window").expect("communication fits");
    let fields = dissect(
        "cease_shutdown",
        &encode(&notification),
        &[
            "bgp.type",
            "bgp.length",
            "bgp.notify.major_error",
            "bgp.notify.minor_error_cease",
            "bgp.notify.communication_length",
            "bgp.notify.communication",
        ],
    );
    assert_eq!(fields, ["3", "40", "6", "2", "18", "maintenance window"]);
}

#[test]
fn cease_administrative_reset_with_communication() {
    if !wireshark_available() {
        return;
    }
    let notification = Notification::administrative_reset("new policy").expect("fits");
    let fields = dissect(
        "cease_reset",
        &encode(&notification),
        &[
            "bgp.notify.major_error",
            "bgp.notify.minor_error_cease",
            "bgp.notify.communication",
        ],
    );
    assert_eq!(fields, ["6", "4", "new policy"]);
}

#[test]
fn cease_without_data() {
    if !wireshark_available() {
        return;
    }
    let notification = Notification::new(
        ErrorCode::Cease(CeaseError::ConnectionCollisionResolution),
        Bytes::new(),
    );
    let fields = dissect(
        "cease_collision",
        &encode(&notification),
        &[
            "bgp.length",
            "bgp.notify.major_error",
            "bgp.notify.minor_error_cease",
        ],
    );
    assert_eq!(fields, ["21", "6", "7"]);
}

#[test]
fn open_error_bad_peer_as() {
    if !wireshark_available() {
        return;
    }
    let notification = Notification::new(
        ErrorCode::Open(OpenError::BadPeerAs),
        Bytes::copy_from_slice(&64496u32.to_be_bytes()),
    );
    let fields = dissect(
        "open_bad_peer_as",
        &encode(&notification),
        &[
            "bgp.notify.major_error",
            "bgp.notify.minor_error_open",
            "bgp.notify.error_open.bad_peer_as",
        ],
    );
    assert_eq!(fields, ["2", "2", "64496"]);
}

#[test]
fn hold_timer_expired() {
    if !wireshark_available() {
        return;
    }
    let notification = Notification::new(ErrorCode::HoldTimerExpired, Bytes::new());
    let fields = dissect(
        "hold_timer_expired",
        &encode(&notification),
        &["bgp.notify.major_error", "bgp.notify.minor_error_expired"],
    );
    assert_eq!(fields, ["4", "0"]);
}

#[test]
fn finite_state_machine_error() {
    if !wireshark_available() {
        return;
    }
    let notification = Notification::new(
        ErrorCode::FiniteStateMachine(FiniteStateMachineError::UnexpectedMessageInOpenConfirm),
        Bytes::new(),
    );
    let fields = dissect(
        "fsm_error",
        &encode(&notification),
        &["bgp.notify.major_error", "bgp.notify.minor_error_state"],
    );
    assert_eq!(fields, ["5", "2"]);
}

/// The notification derived from a header decode error is itself well formed:
/// the reaction to a bad length is a Bad Message Length carrying that length.
#[test]
fn notification_for_a_bad_message_length() {
    if !wireshark_available() {
        return;
    }
    let mut bad = vec![0xff; 16];
    bad.extend_from_slice(&[0x00, 0x12, 0x04]); // KEEPALIVE claiming 18 octets
    let error = Header::decode(&bad).expect_err("length below the minimum");
    let fields = dissect(
        "bad_message_length",
        &encode(&error.notification()),
        &[
            "bgp.notify.major_error",
            "bgp.notify.minor_error",
            "bgp.notify.minor_data",
        ],
    );
    assert_eq!(fields, ["1", "2", "0012"]);
}

fn encode_open(open: &Open) -> Vec<u8> {
    let mut buffer = BytesMut::new();
    open.encode(&mut buffer).expect("encode");
    buffer.to_vec()
}

const OPEN_FIELDS: [&str; 9] = [
    "bgp.type",
    "bgp.open.version",
    "bgp.open.myas",
    "bgp.open.holdtime",
    "bgp.open.identifier",
    "bgp.cap.type",
    "bgp.cap.mp.afi",
    "bgp.cap.mp.safi",
    "bgp.cap.4as",
];

#[test]
fn open_with_a_two_octet_as_number() {
    if !wireshark_available() {
        return;
    }
    let open = Open::new(
        64496,
        90,
        Ipv4Addr::new(192, 0, 2, 1),
        vec![
            Capability::Multiprotocol(AddressFamily::IPV4_UNICAST),
            Capability::Multiprotocol(AddressFamily::IPV6_UNICAST),
            Capability::RouteRefresh,
        ],
    );
    let fields = dissect("open_two_octet", &encode_open(&open), &OPEN_FIELDS);
    assert_eq!(
        fields,
        [
            "1",
            "4",
            "64496",
            "90",
            "192.0.2.1",
            "1,1,2,65",
            "1,2",
            "1,1",
            "64496"
        ]
    );
}

#[test]
fn open_with_a_four_octet_as_number_puts_as_trans_in_the_fixed_field() {
    if !wireshark_available() {
        return;
    }
    let open = Open::new(
        65550,
        0,
        Ipv4Addr::new(198, 51, 100, 7),
        vec![Capability::Multiprotocol(AddressFamily::IPV6_UNICAST)],
    );
    let fields = dissect("open_four_octet", &encode_open(&open), &OPEN_FIELDS);
    assert_eq!(
        fields,
        [
            "1",
            "4",
            "23456",
            "0",
            "198.51.100.7",
            "1,65",
            "2",
            "1",
            "65550"
        ]
    );
}

#[test]
fn open_carries_an_unknown_capability_untouched() {
    if !wireshark_available() {
        return;
    }
    let open = Open::new(
        64496,
        90,
        Ipv4Addr::new(192, 0, 2, 1),
        vec![Capability::Unknown {
            code: 200,
            value: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
        }],
    );
    let fields = dissect(
        "open_unknown_capability",
        &encode_open(&open),
        &["bgp.cap.type", "bgp.cap.length", "bgp.cap.unknown"],
    );
    assert_eq!(fields, ["200,65", "4,4", "deadbeef"]);
}

fn encode_update(update: &Update, context: UpdateContext) -> Vec<u8> {
    let mut buffer = BytesMut::new();
    update.encode(context, &mut buffer).expect("encode");
    buffer.to_vec()
}

fn prefix(a: u8, b: u8, c: u8, d: u8, length: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(a, b, c, d), length).expect("valid prefix")
}

#[test]
fn update_with_every_base_attribute() {
    if !wireshark_available() {
        return;
    }
    let mut attributes = PathAttributes::default();
    attributes.origin = Some(Origin::Incomplete);
    attributes.as_path = Some(AsPath::sequence([64496, 65550]));
    attributes.next_hop = Some(Ipv4Addr::new(192, 0, 2, 1));
    attributes.multi_exit_discriminator = Some(50);
    attributes.local_preference = Some(200);
    attributes.atomic_aggregate = true;
    attributes.aggregator = Some(Aggregator {
        autonomous_system: 65551,
        address: Ipv4Addr::new(192, 0, 2, 9),
    });
    let update = Update {
        withdrawn: vec![prefix(192, 0, 2, 128, 25)],
        attributes,
        announced: vec![prefix(198, 51, 100, 0, 24), prefix(203, 0, 113, 64, 26)],
    };
    let fields = dissect(
        "update_base",
        &encode_update(&update, UpdateContext::new(true, SessionType::Internal)),
        &[
            "bgp.type",
            "bgp.withdrawn_prefix",
            "bgp.nlri_prefix",
            "bgp.prefix_length",
            "bgp.update.path_attribute.type_code",
            "bgp.update.path_attribute.flags",
            "bgp.update.path_attribute.origin",
            "bgp.update.path_attribute.as_path_segment.type",
            "bgp.update.path_attribute.as_path_segment.as4",
            "bgp.update.path_attribute.next_hop",
            "bgp.update.path_attribute.multi_exit_disc",
            "bgp.update.path_attribute.local_pref",
            "bgp.update.path_attribute.aggregator_as",
            "bgp.update.path_attribute.aggregator_origin",
        ],
    );
    assert_eq!(
        fields,
        [
            "2",
            "192.0.2.128",
            "198.51.100.0,203.0.113.64",
            "25,24,26",
            "1,2,3,4,5,6,7",
            // well-known transitive, MED optional, AGGREGATOR optional transitive
            "0x40,0x40,0x40,0x80,0x40,0x40,0xc0",
            "2",
            "2",
            "64496,65550",
            "192.0.2.1",
            "50",
            "200",
            "65551",
            "192.0.2.9",
        ]
    );
}

#[test]
fn update_with_two_octet_as_numbers_and_every_segment_kind() {
    if !wireshark_available() {
        return;
    }
    let mut attributes = PathAttributes::default();
    attributes.origin = Some(Origin::Igp);
    attributes.as_path = Some(AsPath {
        segments: vec![
            AsPathSegment {
                kind: SegmentKind::ConfederationSequence,
                autonomous_systems: vec![64500],
            },
            AsPathSegment {
                kind: SegmentKind::ConfederationSet,
                autonomous_systems: vec![64501, 64502],
            },
            AsPathSegment {
                kind: SegmentKind::Sequence,
                autonomous_systems: vec![64496],
            },
            AsPathSegment {
                kind: SegmentKind::Set,
                autonomous_systems: vec![64497, 64498],
            },
        ],
    });
    attributes.next_hop = Some(Ipv4Addr::new(192, 0, 2, 1));
    let update = Update {
        withdrawn: Vec::new(),
        attributes,
        announced: vec![prefix(198, 51, 100, 0, 24)],
    };
    let fields = dissect(
        "update_two_octet",
        &encode_update(&update, UpdateContext::new(false, SessionType::External)),
        &[
            "bgp.update.path_attribute.as_path_segment.type",
            "bgp.update.path_attribute.as_path_segment.length",
            "bgp.update.path_attribute.as_path_segment.as2",
        ],
    );
    assert_eq!(
        fields,
        ["3,4,2,1", "1,2,1,2", "64500,64501,64502,64496,64497,64498"]
    );
}

#[test]
fn update_with_an_unknown_attribute_longer_than_255_octets() {
    if !wireshark_available() {
        return;
    }
    let mut attributes = PathAttributes::default();
    attributes.origin = Some(Origin::Igp);
    attributes.as_path = Some(AsPath::default());
    attributes.next_hop = Some(Ipv4Addr::new(192, 0, 2, 1));
    attributes
        .unknown
        .push(UnknownAttribute::new(200, Bytes::from(vec![0xab; 300])));
    attributes.unknown.push(UnknownAttribute::forwarded(
        201,
        Bytes::from_static(&[1, 2, 3]),
    ));
    let update = Update {
        withdrawn: Vec::new(),
        attributes,
        announced: vec![prefix(198, 51, 100, 0, 24)],
    };
    let fields = dissect(
        "update_unknown",
        &encode_update(&update, UpdateContext::new(true, SessionType::External)),
        &[
            "bgp.update.path_attribute.type_code",
            "bgp.update.path_attribute.flags",
            "bgp.update.path_attribute.length",
            "bgp.nlri_prefix",
        ],
    );
    // Optional transitive with extended length, then optional transitive partial.
    assert_eq!(
        fields,
        [
            "1,2,3,200,201",
            "0x40,0x40,0x40,0xd0,0xe0",
            "1,0,4,300,3",
            "198.51.100.0"
        ]
    );
}

#[test]
fn update_that_only_withdraws() {
    if !wireshark_available() {
        return;
    }
    let update = Update {
        // Not a /24 followed by the default route: `18 c6 33 64 00` also reads
        // as a 4-octet path identifier and 0.0.0.0/0, and Wireshark's ADD-PATH
        // heuristic picks that reading when there is no OPEN to go by.
        withdrawn: vec![prefix(198, 51, 100, 0, 24), prefix(203, 0, 113, 128, 25)],
        ..Update::default()
    };
    let fields = dissect(
        "update_withdraw",
        &encode_update(&update, UpdateContext::new(true, SessionType::External)),
        &[
            "bgp.length",
            "bgp.update.withdrawn_routes.length",
            "bgp.withdrawn_prefix",
            "bgp.prefix_length",
            "bgp.update.path_attributes.length",
        ],
    );
    assert_eq!(
        fields,
        ["32", "9", "198.51.100.0,203.0.113.128", "24,25", "0"]
    );
}

#[test]
fn update_toward_an_internal_peer_with_communities_and_reflection_attributes() {
    if !wireshark_available() {
        return;
    }
    let mut attributes = PathAttributes::default();
    attributes.origin = Some(Origin::Igp);
    attributes.as_path = Some(AsPath::default());
    attributes.next_hop = Some(Ipv4Addr::new(192, 0, 2, 1));
    attributes.local_preference = Some(100);
    attributes.communities = vec![Community::new(64496, 100), Community::BLACKHOLE];
    attributes.originator_id = Some(Ipv4Addr::new(192, 0, 2, 7));
    attributes.cluster_list = vec![Ipv4Addr::new(192, 0, 2, 8), Ipv4Addr::new(192, 0, 2, 9)];
    attributes.extended_communities = vec![ExtendedCommunity([0x00, 0x02, 0xfb, 0xf0, 0, 0, 0, 1])];
    attributes.large_communities = vec![LargeCommunity {
        global_administrator: 65550,
        local_data_1: 1,
        local_data_2: 2,
    }];
    attributes.only_to_customer = Some(65551);
    let update = Update {
        withdrawn: Vec::new(),
        attributes,
        announced: vec![prefix(198, 51, 100, 0, 24)],
    };
    let fields = dissect(
        "update_communities",
        &encode_update(&update, UpdateContext::new(true, SessionType::Internal)),
        &[
            "bgp.update.path_attribute.type_code",
            "bgp.update.path_attribute.flags",
            "bgp.update.path_attribute.community_as",
            "bgp.update.path_attribute.community_value",
            "bgp.update.path_attribute.community_wellknown",
            "bgp.update.path_attribute.originator_id",
            "bgp.path_attribute.cluster_id",
            "bgp.ext_com.value_as2",
            "bgp.ext_com.value_an4",
            "bgp.large_communities.ga",
            "bgp.large_communities.ldp1",
            "bgp.large_communities.ldp2",
            "bgp.update.path_attribute.otc",
        ],
    );
    assert_eq!(
        fields,
        [
            "1,2,3,5,8,9,10,16,32,35",
            "0x40,0x40,0x40,0x40,0xc0,0x80,0x80,0xc0,0xc0,0xc0",
            "64496",
            "100",
            "0xffff029a",
            "192.0.2.7",
            "192.0.2.8,192.0.2.9",
            "64496",
            "1",
            "65550",
            "1",
            "2",
            "65551",
        ]
    );
}
