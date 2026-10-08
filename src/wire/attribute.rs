//! Path attributes of an UPDATE (RFC 4271 section 4.3 and 5), decoded with
//! the error handling of RFC 7606.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, Bytes, BytesMut};

use super::as_path::{put_autonomous_system, AsPath, AS_TRANS};
use super::community::{Community, ExtendedCommunity, LargeCommunity};
use super::error::{DecodeError, DecodeErrorReason, EncodeError};
use super::nlri::{Ipv6NextHop, Ipv6Prefix};
use super::notification::UpdateError;
use super::reader::Reader;
use super::update::{SessionType, UpdateContext};

const FLAG_OPTIONAL: u8 = 0x80;
const FLAG_TRANSITIVE: u8 = 0x40;
const FLAG_PARTIAL: u8 = 0x20;
const FLAG_EXTENDED_LENGTH: u8 = 0x10;

/// Address Family Identifier of IPv6 and Subsequent Address Family Identifier
/// of unicast (RFC 4760).
const IPV6: u16 = 2;
const UNICAST: u8 = 1;

pub(crate) const ORIGIN: u8 = 1;
pub(crate) const AS_PATH: u8 = 2;
pub(crate) const NEXT_HOP: u8 = 3;
const MULTI_EXIT_DISCRIMINATOR: u8 = 4;
pub(crate) const LOCAL_PREFERENCE: u8 = 5;
const ATOMIC_AGGREGATE: u8 = 6;
const AGGREGATOR: u8 = 7;
const COMMUNITIES: u8 = 8;
const ORIGINATOR_ID: u8 = 9;
const CLUSTER_LIST: u8 = 10;
const MP_REACH_NLRI: u8 = 14;
const MP_UNREACH_NLRI: u8 = 15;
const EXTENDED_COMMUNITIES: u8 = 16;
const AS4_PATH: u8 = 17;
const AS4_AGGREGATOR: u8 = 18;
const LARGE_COMMUNITY: u8 = 32;
const ONLY_TO_CUSTOMER: u8 = 35;

/// The Optional and Transitive bits an attribute this crate interprets must
/// carry, or `None` for a type it does not interpret.
fn expected_flags(type_code: u8) -> Option<u8> {
    match type_code {
        ORIGIN | AS_PATH | NEXT_HOP | LOCAL_PREFERENCE | ATOMIC_AGGREGATE => Some(FLAG_TRANSITIVE),
        MULTI_EXIT_DISCRIMINATOR
        | ORIGINATOR_ID
        | CLUSTER_LIST
        | MP_REACH_NLRI
        | MP_UNREACH_NLRI => Some(FLAG_OPTIONAL),
        AGGREGATOR | COMMUNITIES | EXTENDED_COMMUNITIES | LARGE_COMMUNITY | ONLY_TO_CUSTOMER
        | AS4_PATH | AS4_AGGREGATOR => Some(FLAG_OPTIONAL | FLAG_TRANSITIVE),
        _ => None,
    }
}

/// The ORIGIN attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// The route is interior to the originating AS.
    Igp,
    /// The route was learned through EGP.
    Egp,
    /// The route was learned by some other means.
    Incomplete,
}

impl Origin {
    fn code(self) -> u8 {
        match self {
            Origin::Igp => 0,
            Origin::Egp => 1,
            Origin::Incomplete => 2,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Origin::Igp),
            1 => Some(Origin::Egp),
            2 => Some(Origin::Incomplete),
            _ => None,
        }
    }
}

/// The AGGREGATOR attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Aggregator {
    /// The AS that formed the aggregate.
    pub autonomous_system: u32,
    /// The speaker that formed the aggregate.
    pub address: Ipv4Addr,
}

/// An optional transitive attribute this crate does not interpret.
///
/// Its value is carried byte for byte, so a consumer can pass a learned route
/// on without losing what it does not understand.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownAttribute {
    type_code: u8,
    partial: bool,
    value: Bytes,
}

impl UnknownAttribute {
    /// An attribute this speaker originates. The Partial bit is clear.
    pub fn new(type_code: u8, value: Bytes) -> Self {
        Self {
            type_code,
            partial: false,
            value,
        }
    }

    /// An attribute received from a peer and passed on without being
    /// understood. RFC 4271 section 5 requires the Partial bit in that case,
    /// and this is what the decoder produces.
    pub fn forwarded(type_code: u8, value: Bytes) -> Self {
        Self {
            type_code,
            partial: true,
            value,
        }
    }

    /// The attribute type code.
    pub fn type_code(&self) -> u8 {
        self.type_code
    }

    /// Whether the Partial bit is set when the attribute is sent.
    pub fn partial(&self) -> bool {
        self.partial
    }

    /// The attribute value.
    pub fn value(&self) -> &Bytes {
        &self.value
    }
}

/// The path attributes of a route.
///
/// More fields will be added as the crate learns more attributes, so build
/// one from [`PathAttributes::default`] and set what is needed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PathAttributes {
    /// ORIGIN. Mandatory when the UPDATE announces a route.
    pub origin: Option<Origin>,
    /// AS_PATH. Mandatory when the UPDATE announces a route.
    pub as_path: Option<AsPath>,
    /// NEXT_HOP. Mandatory when the UPDATE announces an IPv4 route.
    pub next_hop: Option<Ipv4Addr>,
    /// MULTI_EXIT_DISC.
    pub multi_exit_discriminator: Option<u32>,
    /// LOCAL_PREF.
    pub local_preference: Option<u32>,
    /// ATOMIC_AGGREGATE.
    pub atomic_aggregate: bool,
    /// AGGREGATOR.
    pub aggregator: Option<Aggregator>,
    /// COMMUNITIES (RFC 1997). Empty when the attribute is absent.
    pub communities: Vec<Community>,
    /// ORIGINATOR_ID (RFC 4456). Only on internal sessions.
    pub originator_id: Option<Ipv4Addr>,
    /// CLUSTER_LIST (RFC 4456), nearest reflector first. Empty when the
    /// attribute is absent. Only on internal sessions.
    pub cluster_list: Vec<Ipv4Addr>,
    /// EXTENDED COMMUNITIES (RFC 4360). Empty when the attribute is absent.
    pub extended_communities: Vec<ExtendedCommunity>,
    /// LARGE_COMMUNITY (RFC 8092). Empty when the attribute is absent.
    pub large_communities: Vec<LargeCommunity>,
    /// Only-to-Customer (RFC 9234): the AS that marked the route.
    pub only_to_customer: Option<u32>,
    /// Optional transitive attributes the crate does not interpret.
    pub unknown: Vec<UnknownAttribute>,
}

/// What the decoder did about a malformed attribute (RFC 7606 section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttributeErrorAction {
    /// Every route of the UPDATE was turned into a withdrawal.
    TreatAsWithdraw,
    /// The attribute was dropped and the rest of the UPDATE kept.
    AttributeDiscard,
}

/// A malformed attribute that did not cost the session.
///
/// The codec has already applied the action. The caller logs this at error
/// level together with the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributeError {
    /// The attribute at fault, when the error can be pinned on one.
    pub type_code: Option<u8>,
    /// Offset of the attribute, from the start of the message.
    pub offset: usize,
    /// What the decoder did about it.
    pub action: AttributeErrorAction,
    /// The RFC 4271 error subcode that describes the problem.
    pub subcode: UpdateError,
}

/// The IPv6 unicast routes of an UPDATE, which travel inside the
/// MP_REACH_NLRI and MP_UNREACH_NLRI attributes (RFC 4760).
#[derive(Debug, Default)]
pub(crate) struct Ipv6Routes {
    pub(crate) next_hop: Option<Ipv6NextHop>,
    pub(crate) announced: Vec<Ipv6Prefix>,
    pub(crate) withdrawn: Vec<Ipv6Prefix>,
}

/// What the Path Attributes field held.
#[derive(Debug)]
pub(crate) struct DecodedAttributes {
    pub(crate) attributes: PathAttributes,
    pub(crate) ipv6: Ipv6Routes,
    /// The UPDATE has to be treated as a withdrawal.
    pub(crate) treat_as_withdraw: bool,
}

impl PathAttributes {
    /// Decode the Path Attributes field.
    ///
    /// `Err` is reserved for the cases where RFC 7606 still asks for a
    /// session reset.
    pub(crate) fn decode(
        mut reader: Reader,
        context: UpdateContext,
        errors: &mut Vec<AttributeError>,
    ) -> Result<DecodedAttributes, DecodeError> {
        let mut attributes = PathAttributes::default();
        let mut ipv6 = Ipv6Routes::default();
        let mut as4_path = None;
        let mut as4_aggregator = None;
        let mut treat_as_withdraw = false;
        let mut seen = [false; 256];

        while !reader.is_empty() {
            let offset = reader.offset();
            let whole = reader.rest();
            let mut withdraw =
                |errors: &mut Vec<AttributeError>, type_code: Option<u8>, subcode: UpdateError| {
                    errors.push(AttributeError {
                        type_code,
                        offset,
                        action: AttributeErrorAction::TreatAsWithdraw,
                        subcode,
                    });
                    treat_as_withdraw = true;
                };

            // RFC 7606 section 4: an attribute header or value that does not
            // fit in what is left of the field is treat-as-withdraw, and
            // nothing after it can be trusted.
            let Some((flags, type_code, value)) = read_attribute(&mut reader) else {
                withdraw(errors, None, UpdateError::MalformedAttributeList);
                break;
            };

            // RFC 7606 section 3.g: of an attribute that appears more than
            // once, all but the first are discarded.
            if std::mem::replace(&mut seen[usize::from(type_code)], true) {
                // Except for the multiprotocol attributes, where a second one
                // leaves no way to tell which routes are meant: session reset.
                if matches!(type_code, MP_REACH_NLRI | MP_UNREACH_NLRI) {
                    return Err(DecodeError::new(
                        DecodeErrorReason::MalformedAttributeList,
                        offset,
                    ));
                }
                errors.push(AttributeError {
                    type_code: Some(type_code),
                    offset,
                    action: AttributeErrorAction::AttributeDiscard,
                    subcode: UpdateError::MalformedAttributeList,
                });
                continue;
            }

            if matches!(type_code, MP_REACH_NLRI | MP_UNREACH_NLRI) {
                let raw = whole.slice(..reader.offset() - offset);
                let value_offset = reader.offset() - value.len();
                let understood =
                    decode_multiprotocol(type_code, value, value_offset, offset, raw, &mut ipv6)?;
                if !understood {
                    // An address family this crate does not speak, and so
                    // never negotiated: the attribute is ignored.
                    errors.push(AttributeError {
                        type_code: Some(type_code),
                        offset,
                        action: AttributeErrorAction::AttributeDiscard,
                        subcode: UpdateError::OptionalAttributeError,
                    });
                } else if flags & (FLAG_OPTIONAL | FLAG_TRANSITIVE) != FLAG_OPTIONAL {
                    // The routes were found, so RFC 7606 section 3.c applies.
                    withdraw(errors, Some(type_code), UpdateError::AttributeFlagsError);
                }
                continue;
            }

            let Some(expected) = expected_flags(type_code) else {
                if flags & FLAG_OPTIONAL == 0 {
                    let raw = whole.slice(..reader.offset() - offset);
                    return Err(DecodeError::with_data(
                        DecodeErrorReason::UnrecognizedWellKnownAttribute { type_code },
                        offset,
                        raw,
                    ));
                }
                // Optional non-transitive attributes that are not understood
                // are quietly ignored (RFC 4271 section 5).
                if flags & FLAG_TRANSITIVE != 0 {
                    attributes
                        .unknown
                        .push(UnknownAttribute::forwarded(type_code, value));
                }
                continue;
            };

            // RFC 7606 sections 7.5, 7.9 and 7.10: these attributes have no
            // meaning on an external session and are discarded there, whatever
            // they look like.
            if context.session_type == SessionType::External
                && matches!(type_code, LOCAL_PREFERENCE | ORIGINATOR_ID | CLUSTER_LIST)
            {
                errors.push(AttributeError {
                    type_code: Some(type_code),
                    offset,
                    action: AttributeErrorAction::AttributeDiscard,
                    subcode: UpdateError::Unspecific,
                });
                continue;
            }

            // RFC 7606 section 3.c.
            if flags & (FLAG_OPTIONAL | FLAG_TRANSITIVE) != expected {
                withdraw(errors, Some(type_code), UpdateError::AttributeFlagsError);
                continue;
            }

            let mut value_reader = Reader::new(value.clone(), 0);
            match type_code {
                ORIGIN => match (
                    value.len(),
                    value.first().copied().and_then(Origin::from_code),
                ) {
                    (1, Some(origin)) => attributes.origin = Some(origin),
                    (1, None) => {
                        withdraw(errors, Some(type_code), UpdateError::InvalidOriginAttribute);
                    }
                    _ => {
                        withdraw(errors, Some(type_code), UpdateError::AttributeLengthError);
                    }
                },
                AS_PATH => match AsPath::decode(value, context.four_octet_autonomous_systems) {
                    // RFC 5065 section 5: confederation segments from a peer
                    // outside the confederation make the path malformed.
                    Some(as_path)
                        if context.session_type == SessionType::External
                            && as_path.has_confederation_segments() =>
                    {
                        withdraw(errors, Some(type_code), UpdateError::MalformedAsPath);
                    }
                    Some(as_path) => attributes.as_path = Some(as_path),
                    None => {
                        withdraw(errors, Some(type_code), UpdateError::MalformedAsPath);
                    }
                },
                NEXT_HOP
                | MULTI_EXIT_DISCRIMINATOR
                | LOCAL_PREFERENCE
                | ORIGINATOR_ID
                | ONLY_TO_CUSTOMER => match (value.len(), value_reader.u32()) {
                    (4, Some(number)) => match type_code {
                        NEXT_HOP => attributes.next_hop = Some(Ipv4Addr::from(number)),
                        MULTI_EXIT_DISCRIMINATOR => {
                            attributes.multi_exit_discriminator = Some(number)
                        }
                        LOCAL_PREFERENCE => attributes.local_preference = Some(number),
                        ORIGINATOR_ID => attributes.originator_id = Some(Ipv4Addr::from(number)),
                        _ => attributes.only_to_customer = Some(number),
                    },
                    _ => {
                        withdraw(errors, Some(type_code), UpdateError::AttributeLengthError);
                    }
                },
                // Lists of fixed-size entries. An empty list or a length that is
                // not a multiple of the entry size is treat-as-withdraw
                // (RFC 7606 sections 7.8, 7.10, 7.14 and RFC 8092 section 5).
                COMMUNITIES | CLUSTER_LIST | EXTENDED_COMMUNITIES | LARGE_COMMUNITY => {
                    let entry_length = match type_code {
                        EXTENDED_COMMUNITIES => 8,
                        LARGE_COMMUNITY => 12,
                        _ => 4,
                    };
                    if value.is_empty() || !value.len().is_multiple_of(entry_length) {
                        withdraw(errors, Some(type_code), UpdateError::OptionalAttributeError);
                        continue;
                    }
                    for entry in value.chunks_exact(entry_length) {
                        match type_code {
                            COMMUNITIES => {
                                if let Some(number) = be_u32(entry) {
                                    attributes.communities.push(Community(number));
                                }
                            }
                            CLUSTER_LIST => {
                                if let Some(number) = be_u32(entry) {
                                    attributes.cluster_list.push(Ipv4Addr::from(number));
                                }
                            }
                            EXTENDED_COMMUNITIES => {
                                if let Ok(octets) = <[u8; 8]>::try_from(entry) {
                                    attributes
                                        .extended_communities
                                        .push(ExtendedCommunity(octets));
                                }
                            }
                            _ => {
                                if let (
                                    Some(global_administrator),
                                    Some(local_data_1),
                                    Some(local_data_2),
                                ) = (
                                    be_u32(&entry[..4]),
                                    be_u32(&entry[4..8]),
                                    be_u32(&entry[8..]),
                                ) {
                                    let community = LargeCommunity {
                                        global_administrator,
                                        local_data_1,
                                        local_data_2,
                                    };
                                    // RFC 8092 section 5: duplicates are removed.
                                    if !attributes.large_communities.contains(&community) {
                                        attributes.large_communities.push(community);
                                    }
                                }
                            }
                        }
                    }
                }
                // RFC 6793 section 4.1: a speaker that negotiated 4-octet AS
                // numbers discards these two when it receives them.
                AS4_PATH | AS4_AGGREGATOR if context.four_octet_autonomous_systems => {
                    errors.push(AttributeError {
                        type_code: Some(type_code),
                        offset,
                        action: AttributeErrorAction::AttributeDiscard,
                        subcode: UpdateError::Unspecific,
                    });
                }
                // RFC 6793 section 6: a malformed AS4_PATH is discarded.
                AS4_PATH => match AsPath::decode(value, true) {
                    Some(path) => as4_path = Some(path),
                    None => errors.push(AttributeError {
                        type_code: Some(type_code),
                        offset,
                        action: AttributeErrorAction::AttributeDiscard,
                        subcode: UpdateError::MalformedAsPath,
                    }),
                },
                AS4_AGGREGATOR if value.len() == 8 => {
                    if let (Some(autonomous_system), Some(address)) =
                        (value_reader.u32(), value_reader.u32())
                    {
                        as4_aggregator = Some(Aggregator {
                            autonomous_system,
                            address: Ipv4Addr::from(address),
                        });
                    }
                }
                // RFC 7606 sections 7.6 and 7.7: these two are discarded, not
                // treated as a withdrawal.
                ATOMIC_AGGREGATE if value.is_empty() => attributes.atomic_aggregate = true,
                AGGREGATOR
                    if value.len() == aggregator_length(context.four_octet_autonomous_systems) =>
                {
                    let autonomous_system = if context.four_octet_autonomous_systems {
                        value_reader.u32()
                    } else {
                        value_reader.u16().map(u32::from)
                    };
                    if let (Some(autonomous_system), Some(address)) =
                        (autonomous_system, value_reader.u32())
                    {
                        attributes.aggregator = Some(Aggregator {
                            autonomous_system,
                            address: Ipv4Addr::from(address),
                        });
                    }
                }
                _ => errors.push(AttributeError {
                    type_code: Some(type_code),
                    offset,
                    action: AttributeErrorAction::AttributeDiscard,
                    subcode: UpdateError::AttributeLengthError,
                }),
            }
        }

        // RFC 6793 section 4.2.3: on a 2-octet session the real AS numbers
        // travel in AS4_PATH and AS4_AGGREGATOR.
        if !context.four_octet_autonomous_systems {
            let mut use_as4_path = true;
            if let (Some(aggregator), Some(wide)) = (attributes.aggregator, as4_aggregator) {
                if aggregator.autonomous_system == u32::from(AS_TRANS) {
                    attributes.aggregator = Some(wide);
                } else {
                    // Some speaker on the way aggregated without knowing
                    // AS4_PATH. Both AS4 attributes are then out of date.
                    use_as4_path = false;
                }
            }
            if let (true, Some(as4_path)) = (use_as4_path, as4_path) {
                attributes.as_path = attributes
                    .as_path
                    .take()
                    .map(|as_path| as_path.merged_with_as4_path(as4_path));
            }
        }

        Ok(DecodedAttributes {
            attributes,
            ipv6,
            treat_as_withdraw,
        })
    }

    /// Append the Path Attributes field, IPv6 routes included: flags and
    /// lengths are derived here.
    pub(crate) fn encode(
        &self,
        context: UpdateContext,
        ipv6_next_hop: Option<Ipv6NextHop>,
        ipv6_announced: &[Ipv6Prefix],
        ipv6_withdrawn: &[Ipv6Prefix],
        buffer: &mut BytesMut,
    ) -> Result<(), EncodeError> {
        let four_octet = context.four_octet_autonomous_systems;
        let mut encoded: Vec<(u8, u8, BytesMut)> = Vec::new();

        if !ipv6_announced.is_empty() {
            let next_hop = ipv6_next_hop.ok_or(EncodeError::MissingIpv6NextHop)?;
            let mut value = BytesMut::new();
            value.put_u16(IPV6);
            value.put_u8(UNICAST);
            value.put_u8(if next_hop.link_local.is_some() {
                32
            } else {
                16
            });
            value.put_slice(&next_hop.global.octets());
            if let Some(link_local) = next_hop.link_local {
                value.put_slice(&link_local.octets());
            }
            value.put_u8(0);
            for prefix in ipv6_announced {
                prefix.encode(&mut value);
            }
            encoded.push((MP_REACH_NLRI, FLAG_OPTIONAL, value));
        }
        if !ipv6_withdrawn.is_empty() {
            let mut value = BytesMut::new();
            value.put_u16(IPV6);
            value.put_u8(UNICAST);
            for prefix in ipv6_withdrawn {
                prefix.encode(&mut value);
            }
            encoded.push((MP_UNREACH_NLRI, FLAG_OPTIONAL, value));
        }

        // What the receiver would discard on an external session is not sent
        // there in the first place.
        if context.session_type == SessionType::External {
            let not_allowed = [
                (LOCAL_PREFERENCE, self.local_preference.is_some()),
                (ORIGINATOR_ID, self.originator_id.is_some()),
                (CLUSTER_LIST, !self.cluster_list.is_empty()),
            ];
            for (type_code, present) in not_allowed {
                if present {
                    return Err(EncodeError::AttributeNotAllowed { type_code });
                }
            }
        }

        if let Some(origin) = self.origin {
            let mut value = BytesMut::new();
            value.put_u8(origin.code());
            encoded.push((ORIGIN, FLAG_TRANSITIVE, value));
        }
        if let Some(as_path) = &self.as_path {
            let mut value = BytesMut::new();
            as_path.encode(four_octet, &mut value)?;
            encoded.push((AS_PATH, FLAG_TRANSITIVE, value));
            // RFC 6793 section 4.2.2: AS_PATH went out with AS_TRANS in place
            // of what does not fit, so the real path goes along in AS4_PATH.
            if !four_octet && as_path.needs_four_octets() {
                let mut wide = BytesMut::new();
                as_path
                    .without_confederation_segments()
                    .encode(true, &mut wide)?;
                encoded.push((AS4_PATH, FLAG_OPTIONAL | FLAG_TRANSITIVE, wide));
            }
        }
        if let Some(next_hop) = self.next_hop {
            let mut value = BytesMut::new();
            value.put_slice(&next_hop.octets());
            encoded.push((NEXT_HOP, FLAG_TRANSITIVE, value));
        }
        if let Some(multi_exit_discriminator) = self.multi_exit_discriminator {
            let mut value = BytesMut::new();
            value.put_u32(multi_exit_discriminator);
            encoded.push((MULTI_EXIT_DISCRIMINATOR, FLAG_OPTIONAL, value));
        }
        if let Some(local_preference) = self.local_preference {
            let mut value = BytesMut::new();
            value.put_u32(local_preference);
            encoded.push((LOCAL_PREFERENCE, FLAG_TRANSITIVE, value));
        }
        if self.atomic_aggregate {
            encoded.push((ATOMIC_AGGREGATE, FLAG_TRANSITIVE, BytesMut::new()));
        }
        if let Some(aggregator) = self.aggregator {
            let mut value = BytesMut::new();
            put_autonomous_system(aggregator.autonomous_system, four_octet, &mut value);
            value.put_slice(&aggregator.address.octets());
            encoded.push((AGGREGATOR, FLAG_OPTIONAL | FLAG_TRANSITIVE, value));
            if !four_octet && aggregator.autonomous_system > u32::from(u16::MAX) {
                let mut wide = BytesMut::new();
                wide.put_u32(aggregator.autonomous_system);
                wide.put_slice(&aggregator.address.octets());
                encoded.push((AS4_AGGREGATOR, FLAG_OPTIONAL | FLAG_TRANSITIVE, wide));
            }
        }
        if !self.communities.is_empty() {
            let mut value = BytesMut::new();
            for community in &self.communities {
                value.put_u32(community.0);
            }
            encoded.push((COMMUNITIES, FLAG_OPTIONAL | FLAG_TRANSITIVE, value));
        }
        if let Some(originator_id) = self.originator_id {
            let mut value = BytesMut::new();
            value.put_slice(&originator_id.octets());
            encoded.push((ORIGINATOR_ID, FLAG_OPTIONAL, value));
        }
        if !self.cluster_list.is_empty() {
            let mut value = BytesMut::new();
            for cluster_id in &self.cluster_list {
                value.put_slice(&cluster_id.octets());
            }
            encoded.push((CLUSTER_LIST, FLAG_OPTIONAL, value));
        }
        if !self.extended_communities.is_empty() {
            let mut value = BytesMut::new();
            for community in &self.extended_communities {
                value.put_slice(&community.0);
            }
            encoded.push((EXTENDED_COMMUNITIES, FLAG_OPTIONAL | FLAG_TRANSITIVE, value));
        }
        if !self.large_communities.is_empty() {
            let mut value = BytesMut::new();
            for community in &self.large_communities {
                value.put_u32(community.global_administrator);
                value.put_u32(community.local_data_1);
                value.put_u32(community.local_data_2);
            }
            encoded.push((LARGE_COMMUNITY, FLAG_OPTIONAL | FLAG_TRANSITIVE, value));
        }
        if let Some(only_to_customer) = self.only_to_customer {
            let mut value = BytesMut::new();
            value.put_u32(only_to_customer);
            encoded.push((ONLY_TO_CUSTOMER, FLAG_OPTIONAL | FLAG_TRANSITIVE, value));
        }
        for unknown in &self.unknown {
            if expected_flags(unknown.type_code).is_some() {
                return Err(EncodeError::AttributeTypeIsInterpreted {
                    type_code: unknown.type_code,
                });
            }
            let mut flags = FLAG_OPTIONAL | FLAG_TRANSITIVE;
            if unknown.partial {
                flags |= FLAG_PARTIAL;
            }
            encoded.push((unknown.type_code, flags, BytesMut::from(&unknown.value[..])));
        }

        // Ascending order of type code, except that RFC 7606 section 5.1 wants
        // the multiprotocol attributes first, so a receiver finds the routes
        // before anything that might be malformed.
        encoded.sort_by_key(|(type_code, _, _)| {
            (
                !matches!(*type_code, MP_REACH_NLRI | MP_UNREACH_NLRI),
                *type_code,
            )
        });
        for pair in encoded.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(EncodeError::DuplicateAttribute {
                    type_code: pair[0].0,
                });
            }
        }

        for (type_code, mut flags, value) in encoded {
            if let Ok(length) = u8::try_from(value.len()) {
                buffer.put_u8(flags);
                buffer.put_u8(type_code);
                buffer.put_u8(length);
            } else {
                // Longer than any message can be: let the caller report it as such.
                let length =
                    u16::try_from(value.len()).map_err(|_| EncodeError::MessageTooLong {
                        length: value.len(),
                    })?;
                flags |= FLAG_EXTENDED_LENGTH;
                buffer.put_u8(flags);
                buffer.put_u8(type_code);
                buffer.put_u16(length);
            }
            buffer.put_slice(&value);
        }
        Ok(())
    }
}

fn aggregator_length(four_octet: bool) -> usize {
    if four_octet {
        8
    } else {
        6
    }
}

/// Read one attribute: flags, type code and value.
fn read_attribute(reader: &mut Reader) -> Option<(u8, u8, Bytes)> {
    let flags = reader.u8()?;
    let type_code = reader.u8()?;
    let length = if flags & FLAG_EXTENDED_LENGTH != 0 {
        usize::from(reader.u16()?)
    } else {
        usize::from(reader.u8()?)
    };
    let value = reader.take(length)?;
    Some((flags, type_code, value))
}

/// The first four octets of `octets` as a big-endian number.
fn be_u32(octets: &[u8]) -> Option<u32> {
    octets
        .first_chunk::<4>()
        .map(|chunk| u32::from_be_bytes(*chunk))
}

/// Decode MP_REACH_NLRI or MP_UNREACH_NLRI into `ipv6`.
///
/// `Ok(false)` when the attribute is for another address family than IPv6
/// unicast. An error is always a session reset: when the attribute cannot be
/// parsed its routes cannot be found, so treat-as-withdraw is not possible
/// (RFC 7606 sections 5.3 and 7.11).
fn decode_multiprotocol(
    type_code: u8,
    value: Bytes,
    value_offset: usize,
    attribute_offset: usize,
    raw: Bytes,
    ipv6: &mut Ipv6Routes,
) -> Result<bool, DecodeError> {
    let malformed = || {
        DecodeError::with_data(
            DecodeErrorReason::MalformedMultiprotocolAttribute { type_code },
            attribute_offset,
            raw.clone(),
        )
    };
    let invalid_network =
        |offset: usize| DecodeError::new(DecodeErrorReason::InvalidNetworkField, offset);

    let mut reader = Reader::new(value, value_offset);
    let identifier = reader.u16().ok_or_else(malformed)?;
    let subsequent_identifier = reader.u8().ok_or_else(malformed)?;
    if (identifier, subsequent_identifier) != (IPV6, UNICAST) {
        return Ok(false);
    }

    if type_code == MP_UNREACH_NLRI {
        ipv6.withdrawn = Ipv6Prefix::decode_all(&mut reader).map_err(invalid_network)?;
        return Ok(true);
    }

    let next_hop_length = reader.u8().ok_or_else(malformed)?;
    let mut next_hop = reader
        .sub_reader(usize::from(next_hop_length))
        .ok_or_else(malformed)?;
    let global = next_hop.u128().map(Ipv6Addr::from);
    let link_local = next_hop.u128().map(Ipv6Addr::from);
    ipv6.next_hop = match (next_hop_length, global, link_local) {
        (16, Some(global), None) => Some(Ipv6NextHop {
            global,
            link_local: None,
        }),
        (32, Some(global), Some(link_local)) => Some(Ipv6NextHop {
            global,
            link_local: Some(link_local),
        }),
        _ => return Err(malformed()),
    };
    let _reserved = reader.u8().ok_or_else(malformed)?;
    ipv6.announced = Ipv6Prefix::decode_all(&mut reader).map_err(invalid_network)?;
    Ok(true)
}
