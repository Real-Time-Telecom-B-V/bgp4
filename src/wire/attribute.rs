//! Path attributes of an UPDATE (RFC 4271 section 4.3 and 5), decoded with
//! the error handling of RFC 7606.

use std::net::Ipv4Addr;

use bytes::{BufMut, Bytes, BytesMut};

use super::as_path::{put_autonomous_system, AsPath};
use super::error::{DecodeError, DecodeErrorReason, EncodeError};
use super::notification::UpdateError;
use super::reader::Reader;
use super::update::UpdateContext;

const FLAG_OPTIONAL: u8 = 0x80;
const FLAG_TRANSITIVE: u8 = 0x40;
const FLAG_PARTIAL: u8 = 0x20;
const FLAG_EXTENDED_LENGTH: u8 = 0x10;

pub(crate) const ORIGIN: u8 = 1;
pub(crate) const AS_PATH: u8 = 2;
pub(crate) const NEXT_HOP: u8 = 3;
const MULTI_EXIT_DISCRIMINATOR: u8 = 4;
const LOCAL_PREFERENCE: u8 = 5;
const ATOMIC_AGGREGATE: u8 = 6;
const AGGREGATOR: u8 = 7;

/// The Optional and Transitive bits an attribute this crate interprets must
/// carry, or `None` for a type it does not interpret.
fn expected_flags(type_code: u8) -> Option<u8> {
    match type_code {
        ORIGIN | AS_PATH | NEXT_HOP | LOCAL_PREFERENCE | ATOMIC_AGGREGATE => Some(FLAG_TRANSITIVE),
        MULTI_EXIT_DISCRIMINATOR => Some(FLAG_OPTIONAL),
        AGGREGATOR => Some(FLAG_OPTIONAL | FLAG_TRANSITIVE),
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

impl PathAttributes {
    /// Decode the Path Attributes field.
    ///
    /// Returns the attributes and whether the UPDATE has to be treated as a
    /// withdrawal. `Err` is reserved for the cases where RFC 7606 still asks
    /// for a session reset.
    pub(crate) fn decode(
        mut reader: Reader,
        context: UpdateContext,
        errors: &mut Vec<AttributeError>,
    ) -> Result<(PathAttributes, bool), DecodeError> {
        let mut attributes = PathAttributes::default();
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
                errors.push(AttributeError {
                    type_code: Some(type_code),
                    offset,
                    action: AttributeErrorAction::AttributeDiscard,
                    subcode: UpdateError::MalformedAttributeList,
                });
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
                    Some(as_path) => attributes.as_path = Some(as_path),
                    None => {
                        withdraw(errors, Some(type_code), UpdateError::MalformedAsPath);
                    }
                },
                NEXT_HOP | MULTI_EXIT_DISCRIMINATOR | LOCAL_PREFERENCE => {
                    match (value.len(), value_reader.u32()) {
                        (4, Some(number)) => match type_code {
                            NEXT_HOP => attributes.next_hop = Some(Ipv4Addr::from(number)),
                            MULTI_EXIT_DISCRIMINATOR => {
                                attributes.multi_exit_discriminator = Some(number)
                            }
                            _ => attributes.local_preference = Some(number),
                        },
                        _ => {
                            withdraw(errors, Some(type_code), UpdateError::AttributeLengthError);
                        }
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

        Ok((attributes, treat_as_withdraw))
    }

    /// Append the Path Attributes field: flags and lengths are derived here,
    /// and attributes go out in ascending order of type code.
    pub(crate) fn encode(
        &self,
        context: UpdateContext,
        buffer: &mut BytesMut,
    ) -> Result<(), EncodeError> {
        let four_octet = context.four_octet_autonomous_systems;
        let mut encoded: Vec<(u8, u8, BytesMut)> = Vec::new();

        if let Some(origin) = self.origin {
            let mut value = BytesMut::new();
            value.put_u8(origin.code());
            encoded.push((ORIGIN, FLAG_TRANSITIVE, value));
        }
        if let Some(as_path) = &self.as_path {
            let mut value = BytesMut::new();
            as_path.encode(four_octet, &mut value)?;
            encoded.push((AS_PATH, FLAG_TRANSITIVE, value));
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
            put_autonomous_system(aggregator.autonomous_system, four_octet, &mut value)?;
            value.put_slice(&aggregator.address.octets());
            encoded.push((AGGREGATOR, FLAG_OPTIONAL | FLAG_TRANSITIVE, value));
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

        encoded.sort_by_key(|(type_code, _, _)| *type_code);
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
