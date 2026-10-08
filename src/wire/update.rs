//! UPDATE (RFC 4271 section 4.3), with the revised error handling of RFC 7606.

use bytes::{BufMut, Bytes, BytesMut};

use super::attribute::{
    AttributeError, AttributeErrorAction, DecodedAttributes, PathAttributes, AS_PATH,
    LOCAL_PREFERENCE, NEXT_HOP, ORIGIN,
};
use super::error::{DecodeError, DecodeErrorReason, EncodeError};
use super::header::{Header, MessageType, HEADER_LENGTH};
use super::nlri::{Ipv4Prefix, Ipv6NextHop, Ipv6Prefix};
use super::notification::UpdateError;
use super::reader::Reader;

/// What kind of peer is on the other end of the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionType {
    /// The peer is in the same AS.
    Internal,
    /// The peer is in another member AS of the same confederation (RFC 5065).
    ConfederationExternal,
    /// The peer is in another AS, outside any confederation of ours.
    External,
}

/// What is known about the session and changes how an UPDATE is read and
/// written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct UpdateContext {
    /// Both speakers announced the 4-octet AS capability (RFC 6793), so AS
    /// numbers in AS_PATH and AGGREGATOR are 4 octets wide.
    pub four_octet_autonomous_systems: bool,
    /// The kind of peer. Several attributes are valid only toward some kinds.
    pub session_type: SessionType,
}

impl UpdateContext {
    /// A context for a session of the given kind, with or without 4-octet AS
    /// numbers.
    pub const fn new(four_octet_autonomous_systems: bool, session_type: SessionType) -> Self {
        Self {
            four_octet_autonomous_systems,
            session_type,
        }
    }
}

/// An UPDATE message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Update {
    /// IPv4 routes that are withdrawn.
    pub withdrawn: Vec<Ipv4Prefix>,
    /// The attributes shared by every announced route.
    pub attributes: PathAttributes,
    /// IPv4 routes that are announced.
    pub announced: Vec<Ipv4Prefix>,
    /// IPv6 routes that are withdrawn (MP_UNREACH_NLRI).
    pub ipv6_withdrawn: Vec<Ipv6Prefix>,
    /// The next hop of the announced IPv6 routes (MP_REACH_NLRI).
    pub ipv6_next_hop: Option<Ipv6NextHop>,
    /// IPv6 routes that are announced (MP_REACH_NLRI).
    pub ipv6_announced: Vec<Ipv6Prefix>,
}

/// An UPDATE as decoded, together with what had to be repaired on the way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedUpdate {
    /// The message, with the RFC 7606 actions already applied: a
    /// treat-as-withdraw has moved every announced route to the withdrawn
    /// ones and emptied the attributes, and a discarded attribute is absent.
    pub update: Update,
    /// Every malformed attribute that was handled without resetting the
    /// session. Empty for a well-formed message.
    pub errors: Vec<AttributeError>,
}

impl Update {
    /// Decode the body of an UPDATE, that is, what follows the header.
    ///
    /// `Err` means the session has to be reset. That happens only where
    /// RFC 7606 leaves no alternative: the fields cannot be told apart, a
    /// prefix cannot be parsed, or a well-known attribute is not recognised.
    /// Everything else comes back as `Ok` with [`DecodedUpdate::errors`] set.
    pub fn decode(body: Bytes, context: UpdateContext) -> Result<DecodedUpdate, DecodeError> {
        if body.len() < 4 {
            let length = u16::try_from(HEADER_LENGTH + body.len()).unwrap_or(u16::MAX);
            return Err(DecodeError::new(
                DecodeErrorReason::BadMessageLength { length },
                16,
            ));
        }
        let mut reader = Reader::new(body, HEADER_LENGTH);
        let malformed_list =
            |offset: usize| DecodeError::new(DecodeErrorReason::MalformedAttributeList, offset);
        let invalid_network =
            |offset: usize| DecodeError::new(DecodeErrorReason::InvalidNetworkField, offset);

        let offset = reader.offset();
        let withdrawn_length = reader.u16().ok_or_else(|| malformed_list(offset))?;
        let mut withdrawn_reader = reader
            .sub_reader(usize::from(withdrawn_length))
            .ok_or_else(|| malformed_list(offset))?;

        let offset = reader.offset();
        let attributes_length = reader.u16().ok_or_else(|| malformed_list(offset))?;
        let attributes_reader = reader
            .sub_reader(usize::from(attributes_length))
            .ok_or_else(|| malformed_list(offset))?;

        let mut withdrawn =
            Ipv4Prefix::decode_all(&mut withdrawn_reader).map_err(invalid_network)?;
        let mut announced = Ipv4Prefix::decode_all(&mut reader).map_err(invalid_network)?;

        let mut errors = Vec::new();
        let DecodedAttributes {
            mut attributes,
            mut ipv6,
            mut treat_as_withdraw,
        } = PathAttributes::decode(attributes_reader, context, &mut errors)?;

        // RFC 7606 section 3.d: a missing mandatory attribute is
        // treat-as-withdraw. They are mandatory only when a route is announced.
        if !treat_as_withdraw && (!announced.is_empty() || !ipv6.announced.is_empty()) {
            let missing = [
                (ORIGIN, attributes.origin.is_none()),
                (AS_PATH, attributes.as_path.is_none()),
                // NEXT_HOP is for the IPv4 routes; IPv6 ones carry their own.
                (
                    NEXT_HOP,
                    !announced.is_empty() && attributes.next_hop.is_none(),
                ),
                // RFC 4271 section 5.1.5: mandatory toward internal peers.
                (
                    LOCAL_PREFERENCE,
                    context.session_type == SessionType::Internal
                        && attributes.local_preference.is_none(),
                ),
            ];
            for (type_code, absent) in missing {
                if absent {
                    errors.push(AttributeError {
                        type_code: Some(type_code),
                        offset,
                        action: AttributeErrorAction::TreatAsWithdraw,
                        subcode: UpdateError::MissingWellKnownAttribute,
                    });
                    treat_as_withdraw = true;
                }
            }
        }

        if treat_as_withdraw {
            withdrawn.append(&mut announced);
            ipv6.withdrawn.append(&mut ipv6.announced);
            ipv6.next_hop = None;
            attributes = PathAttributes::default();
        }

        Ok(DecodedUpdate {
            update: Update {
                withdrawn,
                attributes,
                announced,
                ipv6_withdrawn: ipv6.withdrawn,
                ipv6_next_hop: ipv6.next_hop,
                ipv6_announced: ipv6.announced,
            },
            errors,
        })
    }

    /// Append the whole message, header included, to `buffer`.
    ///
    /// Refuses to write an UPDATE that a receiver would have to repair: one
    /// that announces a route without ORIGIN, AS_PATH and its next hop (and
    /// LOCAL_PREF toward an internal peer), or that carries toward an external
    /// peer an attribute that has no meaning there. Nothing
    /// is written when the message cannot be encoded or does not fit.
    pub fn encode(&self, context: UpdateContext, buffer: &mut BytesMut) -> Result<(), EncodeError> {
        if !self.announced.is_empty() || !self.ipv6_announced.is_empty() {
            let mandatory = [
                (ORIGIN, self.attributes.origin.is_none()),
                (AS_PATH, self.attributes.as_path.is_none()),
                (
                    NEXT_HOP,
                    !self.announced.is_empty() && self.attributes.next_hop.is_none(),
                ),
                (
                    LOCAL_PREFERENCE,
                    context.session_type == SessionType::Internal
                        && self.attributes.local_preference.is_none(),
                ),
            ];
            for (type_code, absent) in mandatory {
                if absent {
                    return Err(EncodeError::MissingMandatoryAttribute { type_code });
                }
            }
        }

        let mut withdrawn = BytesMut::new();
        for prefix in &self.withdrawn {
            prefix.encode(&mut withdrawn);
        }
        let mut attributes = BytesMut::new();
        self.attributes.encode(
            context,
            self.ipv6_next_hop,
            &self.ipv6_announced,
            &self.ipv6_withdrawn,
            &mut attributes,
        )?;
        let mut announced = BytesMut::new();
        for prefix in &self.announced {
            prefix.encode(&mut announced);
        }

        let body_length = 4 + withdrawn.len() + attributes.len() + announced.len();
        let too_long = EncodeError::MessageTooLong {
            length: HEADER_LENGTH + body_length,
        };
        let withdrawn_length = u16::try_from(withdrawn.len()).map_err(|_| too_long)?;
        let attributes_length = u16::try_from(attributes.len()).map_err(|_| too_long)?;

        Header::encode(MessageType::Update, body_length, buffer)?;
        buffer.put_u16(withdrawn_length);
        buffer.put_slice(&withdrawn);
        buffer.put_u16(attributes_length);
        buffer.put_slice(&attributes);
        buffer.put_slice(&announced);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::wire::{
        Aggregator, AsPath, Community, ErrorCode, ExtendedCommunity, LargeCommunity, Origin,
        UnknownAttribute, MAXIMUM_MESSAGE_LENGTH,
    };

    const FOUR_OCTET: UpdateContext = UpdateContext::new(true, SessionType::External);
    const TWO_OCTET: UpdateContext = UpdateContext::new(false, SessionType::External);
    const INTERNAL: UpdateContext = UpdateContext::new(false, SessionType::Internal);

    const ORIGIN_IGP: &[u8] = &[0x40, 1, 1, 0];
    /// AS_SEQUENCE of 64496, 2 octets wide.
    const AS_PATH_64496: &[u8] = &[0x40, 2, 4, 2, 1, 0xfb, 0xf0];
    const NEXT_HOP_192_0_2_1: &[u8] = &[0x40, 3, 4, 192, 0, 2, 1];
    /// 198.51.100.0/24
    const NLRI: &[u8] = &[24, 198, 51, 100];

    fn prefix() -> Ipv4Prefix {
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24).expect("valid")
    }

    fn body(withdrawn: &[u8], attributes: &[&[u8]], announced: &[u8]) -> Bytes {
        let attributes = attributes.concat();
        let mut body = BytesMut::new();
        body.put_u16(withdrawn.len() as u16);
        body.put_slice(withdrawn);
        body.put_u16(attributes.len() as u16);
        body.put_slice(&attributes);
        body.put_slice(announced);
        body.freeze()
    }

    fn decode(attributes: &[&[u8]]) -> DecodedUpdate {
        decode_on(TWO_OCTET, attributes)
    }

    fn decode_on(context: UpdateContext, attributes: &[&[u8]]) -> DecodedUpdate {
        Update::decode(body(&[], attributes, NLRI), context).expect("no session reset")
    }

    /// Asserts the message was turned into a withdrawal of the one route and
    /// returns the errors.
    fn withdrawn(attributes: &[&[u8]]) -> Vec<AttributeError> {
        withdrawn_on(TWO_OCTET, attributes)
    }

    fn withdrawn_on(context: UpdateContext, attributes: &[&[u8]]) -> Vec<AttributeError> {
        let decoded = decode_on(context, attributes);
        assert_eq!(decoded.update.withdrawn, [prefix()]);
        assert!(decoded.update.announced.is_empty());
        assert_eq!(decoded.update.attributes, PathAttributes::default());
        decoded.errors
    }

    fn withdraw_error(
        type_code: Option<u8>,
        offset: usize,
        subcode: UpdateError,
    ) -> AttributeError {
        AttributeError {
            type_code,
            offset,
            action: AttributeErrorAction::TreatAsWithdraw,
            subcode,
        }
    }

    #[test]
    fn a_well_formed_update() {
        let decoded = Update::decode(
            body(
                &[16, 203, 0],
                &[
                    ORIGIN_IGP,
                    AS_PATH_64496,
                    NEXT_HOP_192_0_2_1,
                    &[0x80, 4, 4, 0, 0, 0, 50],
                    &[0x40, 5, 4, 0, 0, 0, 200],
                    &[0x40, 6, 0],
                    &[0xc0, 7, 6, 0xfb, 0xf1, 192, 0, 2, 9],
                ],
                NLRI,
            ),
            INTERNAL,
        )
        .expect("valid");
        assert_eq!(decoded.errors, []);
        let update = decoded.update;
        assert_eq!(
            update.withdrawn,
            [Ipv4Prefix::new(Ipv4Addr::new(203, 0, 0, 0), 16).expect("valid")]
        );
        assert_eq!(update.announced, [prefix()]);
        assert_eq!(update.attributes.origin, Some(Origin::Igp));
        assert_eq!(update.attributes.as_path, Some(AsPath::sequence([64496])));
        assert_eq!(
            update.attributes.next_hop,
            Some(Ipv4Addr::new(192, 0, 2, 1))
        );
        assert_eq!(update.attributes.multi_exit_discriminator, Some(50));
        assert_eq!(update.attributes.local_preference, Some(200));
        assert!(update.attributes.atomic_aggregate);
        assert_eq!(
            update.attributes.aggregator,
            Some(Aggregator {
                autonomous_system: 64497,
                address: Ipv4Addr::new(192, 0, 2, 9)
            })
        );
    }

    #[test]
    fn extended_length_is_read_as_two_octets() {
        let decoded = decode(&[&[0x50, 1, 0, 1, 2], AS_PATH_64496, NEXT_HOP_192_0_2_1]);
        assert_eq!(decoded.errors, []);
        assert_eq!(decoded.update.attributes.origin, Some(Origin::Incomplete));
    }

    #[test]
    fn wrong_flags_on_an_interpreted_attribute_are_treat_as_withdraw() {
        // ORIGIN marked optional; MED marked transitive.
        assert_eq!(
            withdrawn(&[&[0xc0, 1, 1, 0], AS_PATH_64496, NEXT_HOP_192_0_2_1]),
            [withdraw_error(
                Some(1),
                23,
                UpdateError::AttributeFlagsError
            )]
        );
        assert_eq!(
            withdrawn(&[
                ORIGIN_IGP,
                AS_PATH_64496,
                NEXT_HOP_192_0_2_1,
                &[0xc0, 4, 4, 0, 0, 0, 1]
            ]),
            [withdraw_error(
                Some(4),
                41,
                UpdateError::AttributeFlagsError
            )]
        );
    }

    #[test]
    fn the_partial_bit_is_not_grounds_for_rejection() {
        let decoded = decode(&[&[0x60, 1, 1, 0], AS_PATH_64496, NEXT_HOP_192_0_2_1]);
        assert_eq!(decoded.errors, []);
        assert_eq!(decoded.update.announced, [prefix()]);
    }

    #[test]
    fn malformed_origin() {
        assert_eq!(
            withdrawn(&[&[0x40, 1, 1, 3], AS_PATH_64496, NEXT_HOP_192_0_2_1]),
            [withdraw_error(
                Some(1),
                23,
                UpdateError::InvalidOriginAttribute
            )]
        );
        assert_eq!(
            withdrawn(&[&[0x40, 1, 2, 0, 0], AS_PATH_64496, NEXT_HOP_192_0_2_1]),
            [withdraw_error(
                Some(1),
                23,
                UpdateError::AttributeLengthError
            )]
        );
        assert_eq!(
            withdrawn(&[&[0x40, 1, 0], AS_PATH_64496, NEXT_HOP_192_0_2_1]),
            [withdraw_error(
                Some(1),
                23,
                UpdateError::AttributeLengthError
            )]
        );
    }

    #[test]
    fn malformed_as_path() {
        assert_eq!(
            withdrawn(&[ORIGIN_IGP, &[0x40, 2, 2, 2, 0], NEXT_HOP_192_0_2_1]),
            [withdraw_error(Some(2), 27, UpdateError::MalformedAsPath)]
        );
    }

    #[test]
    fn wrong_length_of_a_four_octet_attribute() {
        for (attribute, type_code) in [
            (&[0x40, 3, 3, 192, 0, 2][..], 3),
            (&[0x80, 4, 5, 0, 0, 0, 0, 1][..], 4),
        ] {
            // The malformed attribute, then a good NEXT_HOP unless NEXT_HOP is
            // the one under test, which would make it a repeated attribute.
            let mut attributes = vec![ORIGIN_IGP, AS_PATH_64496, attribute];
            if type_code != 3 {
                attributes.push(NEXT_HOP_192_0_2_1);
            }
            let errors = withdrawn(&attributes);
            assert_eq!(
                errors,
                [withdraw_error(
                    Some(type_code),
                    34,
                    UpdateError::AttributeLengthError
                )],
                "type {type_code}"
            );
        }
    }

    #[test]
    fn wrong_length_of_local_pref_from_an_internal_peer() {
        assert_eq!(
            withdrawn_on(
                INTERNAL,
                &[ORIGIN_IGP, AS_PATH_64496, &[0x40, 5, 0], NEXT_HOP_192_0_2_1]
            ),
            [withdraw_error(
                Some(5),
                34,
                UpdateError::AttributeLengthError
            )]
        );
    }

    #[test]
    fn local_pref_is_mandatory_from_an_internal_peer_only() {
        let attributes: &[&[u8]] = &[ORIGIN_IGP, AS_PATH_64496, NEXT_HOP_192_0_2_1];
        let errors = withdrawn_on(INTERNAL, attributes);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].type_code, Some(5));
        assert_eq!(errors[0].subcode, UpdateError::MissingWellKnownAttribute);

        for session_type in [SessionType::External, SessionType::ConfederationExternal] {
            let decoded = decode_on(UpdateContext::new(false, session_type), attributes);
            assert_eq!(decoded.errors, [], "{session_type:?}");
            assert_eq!(decoded.update.announced, [prefix()]);
        }
    }

    const LOCAL_PREF_200: &[u8] = &[0x40, 5, 4, 0, 0, 0, 200];
    const ORIGINATOR_ID: &[u8] = &[0x80, 9, 4, 192, 0, 2, 7];
    const CLUSTER_LIST: &[u8] = &[0x80, 10, 8, 192, 0, 2, 8, 192, 0, 2, 9];

    #[test]
    fn internal_only_attributes_are_discarded_from_an_external_peer() {
        // Well formed or not makes no difference there (RFC 7606 section 7.5,
        // 7.9, 7.10).
        for attributes in [
            [LOCAL_PREF_200, ORIGINATOR_ID, CLUSTER_LIST],
            [
                &[0x40, 5, 1, 0][..],
                &[0x80, 9, 0][..],
                &[0x80, 10, 3, 1, 2, 3][..],
            ],
        ] {
            let mut all = vec![ORIGIN_IGP, AS_PATH_64496, NEXT_HOP_192_0_2_1];
            all.extend_from_slice(&attributes);
            let decoded = decode(&all);
            assert_eq!(decoded.update.announced, [prefix()]);
            assert_eq!(decoded.update.attributes.local_preference, None);
            assert_eq!(decoded.update.attributes.originator_id, None);
            assert!(decoded.update.attributes.cluster_list.is_empty());
            let discarded: Vec<(Option<u8>, AttributeErrorAction)> = decoded
                .errors
                .iter()
                .map(|error| (error.type_code, error.action))
                .collect();
            assert_eq!(
                discarded,
                [
                    (Some(5), AttributeErrorAction::AttributeDiscard),
                    (Some(9), AttributeErrorAction::AttributeDiscard),
                    (Some(10), AttributeErrorAction::AttributeDiscard),
                ]
            );
        }
    }

    #[test]
    fn reflection_attributes_from_an_internal_peer() {
        let decoded = decode_on(
            INTERNAL,
            &[
                ORIGIN_IGP,
                AS_PATH_64496,
                NEXT_HOP_192_0_2_1,
                LOCAL_PREF_200,
                ORIGINATOR_ID,
                CLUSTER_LIST,
            ],
        );
        assert_eq!(decoded.errors, []);
        assert_eq!(
            decoded.update.attributes.originator_id,
            Some(Ipv4Addr::new(192, 0, 2, 7))
        );
        assert_eq!(
            decoded.update.attributes.cluster_list,
            [Ipv4Addr::new(192, 0, 2, 8), Ipv4Addr::new(192, 0, 2, 9)]
        );
    }

    #[test]
    fn malformed_reflection_attributes_from_an_internal_peer_are_treat_as_withdraw() {
        for (attribute, type_code, subcode) in [
            (
                &[0x80, 9, 3, 1, 2, 3][..],
                9,
                UpdateError::AttributeLengthError,
            ),
            (&[0x80, 10, 0][..], 10, UpdateError::OptionalAttributeError),
            (
                &[0x80, 10, 5, 1, 2, 3, 4, 5][..],
                10,
                UpdateError::OptionalAttributeError,
            ),
        ] {
            assert_eq!(
                withdrawn_on(
                    INTERNAL,
                    &[
                        ORIGIN_IGP,
                        AS_PATH_64496,
                        NEXT_HOP_192_0_2_1,
                        LOCAL_PREF_200,
                        attribute
                    ]
                ),
                [withdraw_error(Some(type_code), 48, subcode)],
                "type {type_code}"
            );
        }
    }

    #[test]
    fn communities_of_all_three_kinds_and_only_to_customer() {
        let decoded = decode(&[
            ORIGIN_IGP,
            AS_PATH_64496,
            NEXT_HOP_192_0_2_1,
            // 64496:100 and NO_EXPORT
            &[0xc0, 8, 8, 0xfb, 0xf0, 0, 100, 0xff, 0xff, 0xff, 0x01],
            // A route target, 2-octet AS 64496, value 1.
            &[0xc0, 16, 8, 0, 2, 0xfb, 0xf0, 0, 0, 0, 1],
            // 65550:1:2, twice.
            &[
                0xc0, 32, 24, 0, 1, 0, 14, 0, 0, 0, 1, 0, 0, 0, 2, 0, 1, 0, 14, 0, 0, 0, 1, 0, 0,
                0, 2,
            ],
            // Only-to-Customer, marked by AS 64496.
            &[0xc0, 35, 4, 0, 0, 0xfb, 0xf0],
        ]);
        assert_eq!(decoded.errors, []);
        let attributes = decoded.update.attributes;
        assert_eq!(
            attributes.communities,
            [Community::new(64496, 100), Community::NO_EXPORT]
        );
        assert_eq!(
            attributes.extended_communities,
            [ExtendedCommunity([0, 2, 0xfb, 0xf0, 0, 0, 0, 1])]
        );
        // RFC 8092 section 5: the duplicate is removed.
        assert_eq!(
            attributes.large_communities,
            [LargeCommunity {
                global_administrator: 65550,
                local_data_1: 1,
                local_data_2: 2
            }]
        );
        assert_eq!(attributes.only_to_customer, Some(64496));
        assert!(attributes.unknown.is_empty());
    }

    #[test]
    fn malformed_community_attributes_are_treat_as_withdraw() {
        for (attribute, type_code, subcode) in [
            (&[0xc0, 8, 0][..], 8, UpdateError::OptionalAttributeError),
            (
                &[0xc0, 8, 3, 1, 2, 3][..],
                8,
                UpdateError::OptionalAttributeError,
            ),
            (&[0xc0, 16, 0][..], 16, UpdateError::OptionalAttributeError),
            (
                &[0xc0, 16, 7, 1, 2, 3, 4, 5, 6, 7][..],
                16,
                UpdateError::OptionalAttributeError,
            ),
            (&[0xc0, 32, 0][..], 32, UpdateError::OptionalAttributeError),
            (
                &[0xc0, 32, 11, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11][..],
                32,
                UpdateError::OptionalAttributeError,
            ),
            (
                &[0xc0, 35, 3, 1, 2, 3][..],
                35,
                UpdateError::AttributeLengthError,
            ),
            (&[0xc0, 35, 0][..], 35, UpdateError::AttributeLengthError),
        ] {
            assert_eq!(
                withdrawn(&[ORIGIN_IGP, AS_PATH_64496, NEXT_HOP_192_0_2_1, attribute]),
                [withdraw_error(Some(type_code), 41, subcode)],
                "type {type_code}"
            );
        }
    }

    /// AS_CONFED_SEQUENCE of 64500, then AS_SEQUENCE of 64496.
    const AS_PATH_WITH_CONFEDERATION: &[u8] = &[0x40, 2, 8, 3, 1, 0xfb, 0xf4, 2, 1, 0xfb, 0xf0];

    #[test]
    fn confederation_segments_are_malformed_from_an_external_peer_only() {
        let attributes: &[&[u8]] = &[ORIGIN_IGP, AS_PATH_WITH_CONFEDERATION, NEXT_HOP_192_0_2_1];
        assert_eq!(
            withdrawn(attributes),
            [withdraw_error(Some(2), 27, UpdateError::MalformedAsPath)]
        );
        let confederation = UpdateContext::new(false, SessionType::ConfederationExternal);
        let decoded = decode_on(confederation, attributes);
        assert_eq!(decoded.errors, []);
        assert!(decoded
            .update
            .attributes
            .as_path
            .is_some_and(|path| path.has_confederation_segments()));
    }

    #[test]
    fn malformed_atomic_aggregate_and_aggregator_are_only_discarded() {
        let decoded = decode(&[
            ORIGIN_IGP,
            AS_PATH_64496,
            NEXT_HOP_192_0_2_1,
            &[0x40, 6, 1, 0],
            &[0xc0, 7, 8, 0, 0, 0xfb, 0xf1, 192, 0, 2, 9],
        ]);
        assert_eq!(decoded.update.announced, [prefix()]);
        assert!(!decoded.update.attributes.atomic_aggregate);
        assert_eq!(decoded.update.attributes.aggregator, None);
        assert_eq!(decoded.update.attributes.origin, Some(Origin::Igp));
        let discard = |type_code, offset| AttributeError {
            type_code: Some(type_code),
            offset,
            action: AttributeErrorAction::AttributeDiscard,
            subcode: UpdateError::AttributeLengthError,
        };
        assert_eq!(decoded.errors, [discard(6, 41), discard(7, 45)]);
    }

    #[test]
    fn aggregator_width_follows_the_session() {
        let attributes: &[&[u8]] = &[
            ORIGIN_IGP,
            &[0x40, 2, 6, 2, 1, 0, 0, 0xfb, 0xf0],
            NEXT_HOP_192_0_2_1,
            &[0xc0, 7, 8, 0, 1, 0, 14, 192, 0, 2, 9],
        ];
        let decoded = Update::decode(body(&[], attributes, NLRI), FOUR_OCTET).expect("valid");
        assert_eq!(decoded.errors, []);
        assert_eq!(
            decoded.update.attributes.aggregator,
            Some(Aggregator {
                autonomous_system: 65550,
                address: Ipv4Addr::new(192, 0, 2, 9)
            })
        );
    }

    #[test]
    fn of_a_repeated_attribute_the_first_is_kept() {
        let decoded = decode(&[
            ORIGIN_IGP,
            &[0x40, 1, 1, 2],
            AS_PATH_64496,
            NEXT_HOP_192_0_2_1,
        ]);
        assert_eq!(decoded.update.attributes.origin, Some(Origin::Igp));
        assert_eq!(decoded.update.announced, [prefix()]);
        assert_eq!(
            decoded.errors,
            [AttributeError {
                type_code: Some(1),
                offset: 27,
                action: AttributeErrorAction::AttributeDiscard,
                subcode: UpdateError::MalformedAttributeList,
            }]
        );
    }

    #[test]
    fn a_missing_mandatory_attribute_is_treat_as_withdraw() {
        let errors = withdrawn(&[ORIGIN_IGP, AS_PATH_64496]);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].type_code, Some(3));
        assert_eq!(errors[0].subcode, UpdateError::MissingWellKnownAttribute);

        let all_missing = withdrawn(&[]);
        let missing: Vec<Option<u8>> = all_missing.iter().map(|error| error.type_code).collect();
        assert_eq!(missing, [Some(1), Some(2), Some(3)]);
    }

    #[test]
    fn mandatory_attributes_are_not_required_without_an_announcement() {
        let decoded =
            Update::decode(body(&[24, 198, 51, 100], &[], &[]), TWO_OCTET).expect("valid");
        assert_eq!(decoded.errors, []);
        assert_eq!(decoded.update.withdrawn, [prefix()]);

        let decoded = Update::decode(body(&[], &[ORIGIN_IGP], &[]), TWO_OCTET).expect("valid");
        assert_eq!(decoded.errors, []);
        assert_eq!(decoded.update.attributes.origin, Some(Origin::Igp));
    }

    #[test]
    fn an_attribute_running_past_the_field_is_treat_as_withdraw() {
        // NEXT_HOP claims 9 octets, 4 are left in the attributes field.
        assert_eq!(
            withdrawn(&[ORIGIN_IGP, AS_PATH_64496, &[0x40, 3, 9, 192, 0, 2, 1]]),
            [withdraw_error(
                None,
                34,
                UpdateError::MalformedAttributeList
            )]
        );
        // A single octet is left where an attribute header should be.
        assert_eq!(
            withdrawn(&[ORIGIN_IGP, AS_PATH_64496, NEXT_HOP_192_0_2_1, &[0x40]]),
            [withdraw_error(
                None,
                41,
                UpdateError::MalformedAttributeList
            )]
        );
    }

    #[test]
    fn unknown_optional_attributes() {
        let decoded = decode(&[
            ORIGIN_IGP,
            AS_PATH_64496,
            NEXT_HOP_192_0_2_1,
            &[0x80, 99, 2, 1, 2],
            &[0xc0, 100, 2, 3, 4],
        ]);
        assert_eq!(decoded.errors, []);
        assert_eq!(
            decoded.update.attributes.unknown,
            [UnknownAttribute::forwarded(
                100,
                Bytes::from_static(&[3, 4])
            )]
        );
    }

    #[test]
    fn an_unrecognised_well_known_attribute_resets_the_session() {
        let attribute: &[u8] = &[0x40, 99, 2, 0xaa, 0xbb];
        let error = Update::decode(
            body(&[], &[ORIGIN_IGP, attribute, AS_PATH_64496], NLRI),
            TWO_OCTET,
        )
        .expect_err("session reset");
        assert_eq!(
            error.reason(),
            DecodeErrorReason::UnrecognizedWellKnownAttribute { type_code: 99 }
        );
        assert_eq!(error.offset(), 27);
        let notification = error.notification();
        assert_eq!(
            notification.error(),
            ErrorCode::Update(UpdateError::UnrecognizedWellKnownAttribute)
        );
        // RFC 4271 section 6.3: the data is the attribute, type, length and value.
        assert_eq!(notification.data().as_ref(), attribute);
    }

    #[test]
    fn a_reset_wins_over_an_earlier_treat_as_withdraw() {
        let result = Update::decode(
            body(&[], &[&[0x40, 1, 1, 9], &[0x40, 99, 0]], NLRI),
            TWO_OCTET,
        );
        assert!(result.is_err());
    }

    #[test]
    fn lengths_that_do_not_fit_the_message_reset_the_session() {
        // Withdrawn Routes Length runs past the end.
        let error =
            Update::decode(Bytes::from_static(&[0, 9, 0, 0]), TWO_OCTET).expect_err("reset");
        assert_eq!(error.reason(), DecodeErrorReason::MalformedAttributeList);
        assert_eq!(error.offset(), 19);
        // Total Path Attribute Length runs past the end.
        let error =
            Update::decode(Bytes::from_static(&[0, 0, 0, 9, 1]), TWO_OCTET).expect_err("reset");
        assert_eq!(error.reason(), DecodeErrorReason::MalformedAttributeList);
        assert_eq!(error.offset(), 21);
        // No room for the Total Path Attribute Length at all.
        let error =
            Update::decode(Bytes::from_static(&[0, 2, 8, 10]), TWO_OCTET).expect_err("reset");
        assert_eq!(error.reason(), DecodeErrorReason::MalformedAttributeList);
        assert_eq!(
            error.notification().error(),
            ErrorCode::Update(UpdateError::MalformedAttributeList)
        );
    }

    #[test]
    fn a_prefix_that_cannot_be_parsed_resets_the_session() {
        let attributes: &[&[u8]] = &[ORIGIN_IGP, AS_PATH_64496, NEXT_HOP_192_0_2_1];
        let error = Update::decode(body(&[], attributes, &[33, 1, 2, 3, 4, 5]), TWO_OCTET)
            .expect_err("reset");
        assert_eq!(error.reason(), DecodeErrorReason::InvalidNetworkField);
        assert_eq!(error.offset(), 41);
        assert_eq!(
            error.notification().error(),
            ErrorCode::Update(UpdateError::InvalidNetworkField)
        );

        let error =
            Update::decode(body(&[24, 198], &[], &[]), TWO_OCTET).expect_err("short withdrawal");
        assert_eq!(error.reason(), DecodeErrorReason::InvalidNetworkField);
        assert_eq!(error.offset(), 21);
    }

    #[test]
    fn a_body_too_short_for_the_two_lengths_is_a_bad_message_length() {
        let error = Update::decode(Bytes::from_static(&[0, 0, 0]), TWO_OCTET).expect_err("short");
        assert_eq!(
            error.reason(),
            DecodeErrorReason::BadMessageLength { length: 22 }
        );
    }

    fn announcement() -> Update {
        let attributes = PathAttributes {
            origin: Some(Origin::Igp),
            as_path: Some(AsPath::sequence([64496])),
            next_hop: Some(Ipv4Addr::new(192, 0, 2, 1)),
            ..PathAttributes::default()
        };
        Update {
            attributes,
            announced: vec![prefix()],
            ..Update::default()
        }
    }

    fn encode(update: &Update) -> Result<Vec<u8>, EncodeError> {
        encode_on(TWO_OCTET, update)
    }

    fn encode_on(context: UpdateContext, update: &Update) -> Result<Vec<u8>, EncodeError> {
        let mut buffer = BytesMut::new();
        update.encode(context, &mut buffer)?;
        Ok(buffer.to_vec())
    }

    #[test]
    fn internal_only_attributes_are_refused_toward_an_external_peer() {
        let mut with_local_pref = announcement();
        with_local_pref.attributes.local_preference = Some(100);
        let mut with_originator = announcement();
        with_originator.attributes.originator_id = Some(Ipv4Addr::new(192, 0, 2, 7));
        let mut with_cluster_list = announcement();
        with_cluster_list.attributes.cluster_list = vec![Ipv4Addr::new(192, 0, 2, 8)];
        for (update, type_code) in [
            (with_local_pref, 5),
            (with_originator, 9),
            (with_cluster_list, 10),
        ] {
            assert_eq!(
                encode(&update),
                Err(EncodeError::AttributeNotAllowed { type_code })
            );
        }
    }

    #[test]
    fn an_announcement_toward_an_internal_peer_needs_local_pref() {
        let mut update = announcement();
        assert_eq!(
            encode_on(INTERNAL, &update),
            Err(EncodeError::MissingMandatoryAttribute { type_code: 5 })
        );
        update.attributes.local_preference = Some(100);
        assert!(encode_on(INTERNAL, &update).is_ok());
        // Toward another member AS of the confederation it is allowed but
        // not required.
        let confederation = UpdateContext::new(false, SessionType::ConfederationExternal);
        assert!(encode_on(confederation, &update).is_ok());
        assert!(encode_on(confederation, &announcement()).is_ok());
    }

    #[test]
    fn an_announcement_without_a_mandatory_attribute_is_refused() {
        for type_code in [1, 2, 3] {
            let mut update = announcement();
            match type_code {
                1 => update.attributes.origin = None,
                2 => update.attributes.as_path = None,
                _ => update.attributes.next_hop = None,
            }
            assert_eq!(
                encode(&update),
                Err(EncodeError::MissingMandatoryAttribute { type_code })
            );
        }
    }

    #[test]
    fn unknown_attributes_cannot_shadow_or_repeat() {
        let mut update = announcement();
        update
            .attributes
            .unknown
            .push(UnknownAttribute::new(4, Bytes::new()));
        assert_eq!(
            encode(&update),
            Err(EncodeError::AttributeTypeIsInterpreted { type_code: 4 })
        );

        let mut update = announcement();
        for _ in 0..2 {
            update
                .attributes
                .unknown
                .push(UnknownAttribute::new(200, Bytes::new()));
        }
        assert_eq!(
            encode(&update),
            Err(EncodeError::DuplicateAttribute { type_code: 200 })
        );
    }

    #[test]
    fn attributes_go_out_in_ascending_order_of_type_code() {
        let mut update = announcement();
        update.attributes.local_preference = Some(1);
        update
            .attributes
            .unknown
            .push(UnknownAttribute::new(200, Bytes::new()));
        update
            .attributes
            .unknown
            .push(UnknownAttribute::new(100, Bytes::new()));
        let wire = encode_on(INTERNAL, &update).expect("valid");
        let decoded =
            Update::decode(Bytes::copy_from_slice(&wire[HEADER_LENGTH..]), INTERNAL).expect("ok");
        let order: Vec<u8> = decoded
            .update
            .attributes
            .unknown
            .iter()
            .map(|attribute| attribute.type_code())
            .collect();
        assert_eq!(order, [100, 200]);
        // ORIGIN first: flags, type code.
        assert_eq!(&wire[HEADER_LENGTH + 4..HEADER_LENGTH + 6], [0x40, 1]);
    }

    #[test]
    fn a_message_past_the_maximum_is_refused() {
        let mut update = announcement();
        // Header 19, the two lengths 4, attributes 18: 41 octets, then 4 per
        // /24 prefix.
        update.announced = vec![prefix(); (MAXIMUM_MESSAGE_LENGTH - 41) / 4];
        assert_eq!(encode(&update).map(|wire| wire.len()), Ok(4093));
        update.announced.push(prefix());
        assert_eq!(
            encode(&update),
            Err(EncodeError::MessageTooLong { length: 4097 })
        );
    }

    /// MP_REACH_NLRI for IPv6 unicast: next hop 2001:db8:0:1::11, one route
    /// 2001:db8:100::/48.
    const MP_REACH: &[u8] = &[
        0x80, 14, 28, 0, 2, 1, 16, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x11,
        0, 48, 0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00,
    ];
    /// MP_UNREACH_NLRI for IPv6 unicast: 2001:db8:300::/48.
    const MP_UNREACH: &[u8] = &[
        0x80, 15, 10, 0, 2, 1, 48, 0x20, 0x01, 0x0d, 0xb8, 0x03, 0x00,
    ];

    fn ipv6_prefix(address: &str) -> Ipv6Prefix {
        Ipv6Prefix::new(address.parse().expect("address"), 48).expect("valid")
    }

    fn decode_without_nlri(
        context: UpdateContext,
        attributes: &[&[u8]],
    ) -> Result<DecodedUpdate, DecodeError> {
        Update::decode(body(&[], attributes, &[]), context)
    }

    #[test]
    fn ipv6_routes_with_a_global_next_hop_only() {
        let decoded = decode_without_nlri(
            TWO_OCTET,
            &[MP_REACH, MP_UNREACH, ORIGIN_IGP, AS_PATH_64496],
        )
        .expect("valid");
        assert_eq!(decoded.errors, []);
        let update = decoded.update;
        assert_eq!(update.ipv6_announced, [ipv6_prefix("2001:db8:100::")]);
        assert_eq!(update.ipv6_withdrawn, [ipv6_prefix("2001:db8:300::")]);
        assert_eq!(
            update.ipv6_next_hop,
            Some(Ipv6NextHop {
                global: "2001:db8:0:1::11".parse().expect("address"),
                link_local: None,
            })
        );
        // NEXT_HOP is not required: there is no IPv4 route.
        assert_eq!(update.attributes.next_hop, None);
    }

    #[test]
    fn ipv6_routes_still_need_origin_and_as_path() {
        let decoded = decode_without_nlri(TWO_OCTET, &[MP_REACH, AS_PATH_64496]).expect("no reset");
        assert_eq!(decoded.errors.len(), 1);
        assert_eq!(decoded.errors[0].type_code, Some(1));
        assert_eq!(
            decoded.errors[0].subcode,
            UpdateError::MissingWellKnownAttribute
        );
        // Treat-as-withdraw reaches the IPv6 routes too.
        assert!(decoded.update.ipv6_announced.is_empty());
        assert_eq!(
            decoded.update.ipv6_withdrawn,
            [ipv6_prefix("2001:db8:100::")]
        );
        assert_eq!(decoded.update.ipv6_next_hop, None);
    }

    #[test]
    fn wrong_flags_on_a_multiprotocol_attribute_are_treat_as_withdraw() {
        let mut transitive = MP_REACH.to_vec();
        transitive[0] = 0xc0;
        let decoded =
            decode_without_nlri(TWO_OCTET, &[&transitive, ORIGIN_IGP, AS_PATH_64496]).expect("ok");
        assert_eq!(
            decoded.errors,
            [withdraw_error(
                Some(14),
                23,
                UpdateError::AttributeFlagsError
            )]
        );
        assert_eq!(
            decoded.update.ipv6_withdrawn,
            [ipv6_prefix("2001:db8:100::")]
        );
    }

    #[test]
    fn a_multiprotocol_attribute_that_cannot_be_parsed_resets_the_session() {
        // Next hop length 17; next hop running past the attribute; no room
        // for the address family.
        let bad_next_hop_length: &[u8] = &[
            0x80, 14, 22, 0, 2, 1, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let short_next_hop: &[u8] = &[0x80, 14, 6, 0, 2, 1, 16, 0, 0];
        let no_family: &[u8] = &[0x80, 15, 2, 0, 2];
        for (attribute, type_code) in [
            (bad_next_hop_length, 14),
            (short_next_hop, 14),
            (no_family, 15),
        ] {
            let error = decode_without_nlri(TWO_OCTET, &[ORIGIN_IGP, attribute])
                .expect_err("session reset");
            assert_eq!(
                error.reason(),
                DecodeErrorReason::MalformedMultiprotocolAttribute { type_code }
            );
            assert_eq!(error.offset(), 27);
            let notification = error.notification();
            assert_eq!(
                notification.error(),
                ErrorCode::Update(UpdateError::OptionalAttributeError)
            );
            assert_eq!(notification.data().as_ref(), attribute);
        }
    }

    #[test]
    fn an_ipv6_prefix_that_cannot_be_parsed_resets_the_session() {
        let attribute: &[u8] = &[0x80, 15, 4, 0, 2, 1, 129];
        let error = decode_without_nlri(TWO_OCTET, &[attribute]).expect_err("session reset");
        assert_eq!(error.reason(), DecodeErrorReason::InvalidNetworkField);
        assert_eq!(error.offset(), 29);
    }

    #[test]
    fn a_repeated_multiprotocol_attribute_resets_the_session() {
        let error =
            decode_without_nlri(TWO_OCTET, &[MP_UNREACH, MP_UNREACH]).expect_err("session reset");
        assert_eq!(error.reason(), DecodeErrorReason::MalformedAttributeList);
        assert_eq!(error.offset(), 36);
    }

    #[test]
    fn a_multiprotocol_attribute_for_another_family_is_ignored() {
        // IPv4 multicast (1/2), which this crate never negotiates.
        let attribute: &[u8] = &[0x80, 15, 5, 0, 1, 2, 8, 10];
        let decoded = decode_without_nlri(TWO_OCTET, &[attribute]).expect("no reset");
        assert_eq!(decoded.update, Update::default());
        assert_eq!(
            decoded.errors,
            [AttributeError {
                type_code: Some(15),
                offset: 23,
                action: AttributeErrorAction::AttributeDiscard,
                subcode: UpdateError::OptionalAttributeError,
            }]
        );
    }

    #[test]
    fn ipv6_routes_cannot_be_announced_without_a_next_hop() {
        let mut update = announcement();
        update.ipv6_announced = vec![ipv6_prefix("2001:db8:100::")];
        assert_eq!(encode(&update), Err(EncodeError::MissingIpv6NextHop));
    }

    /// AS_SEQUENCE of 64496 then AS_TRANS, 2 octets wide.
    const AS_PATH_WITH_AS_TRANS: &[u8] = &[0x40, 2, 6, 2, 2, 0xfb, 0xf0, 0x5b, 0xa0];
    /// AS4_PATH: AS_SEQUENCE of 64496, 65550.
    const AS4_PATH: &[u8] = &[0xc0, 17, 10, 2, 2, 0, 0, 0xfb, 0xf0, 0, 1, 0, 14];
    /// AGGREGATOR with AS_TRANS, and the AS4_AGGREGATOR that names AS 65551.
    const AGGREGATOR_AS_TRANS: &[u8] = &[0xc0, 7, 6, 0x5b, 0xa0, 192, 0, 2, 9];
    const AS4_AGGREGATOR: &[u8] = &[0xc0, 18, 8, 0, 1, 0, 15, 192, 0, 2, 9];

    #[test]
    fn as4_attributes_restore_the_path_and_the_aggregator() {
        let decoded = decode(&[
            ORIGIN_IGP,
            AS_PATH_WITH_AS_TRANS,
            NEXT_HOP_192_0_2_1,
            AGGREGATOR_AS_TRANS,
            AS4_PATH,
            AS4_AGGREGATOR,
        ]);
        assert_eq!(decoded.errors, []);
        let attributes = decoded.update.attributes;
        assert_eq!(attributes.as_path, Some(AsPath::sequence([64496, 65550])));
        assert_eq!(
            attributes.aggregator,
            Some(Aggregator {
                autonomous_system: 65551,
                address: Ipv4Addr::new(192, 0, 2, 9)
            })
        );
        assert!(attributes.unknown.is_empty());
    }

    #[test]
    fn an_aggregator_that_is_not_as_trans_voids_both_as4_attributes() {
        // RFC 6793 section 4.2.3: a speaker without AS4 support aggregated on
        // the way, so AS4_PATH no longer describes the route.
        let decoded = decode(&[
            ORIGIN_IGP,
            AS_PATH_WITH_AS_TRANS,
            NEXT_HOP_192_0_2_1,
            &[0xc0, 7, 6, 0xfb, 0xf1, 192, 0, 2, 9],
            AS4_PATH,
            AS4_AGGREGATOR,
        ]);
        assert_eq!(decoded.errors, []);
        let attributes = decoded.update.attributes;
        assert_eq!(attributes.as_path, Some(AsPath::sequence([64496, 23456])));
        assert_eq!(
            attributes
                .aggregator
                .map(|aggregator| aggregator.autonomous_system),
            Some(64497)
        );
    }

    #[test]
    fn malformed_as4_attributes_are_discarded() {
        let decoded = decode(&[
            ORIGIN_IGP,
            AS_PATH_WITH_AS_TRANS,
            NEXT_HOP_192_0_2_1,
            AGGREGATOR_AS_TRANS,
            &[0xc0, 17, 3, 2, 2, 0],
            &[0xc0, 18, 6, 0, 1, 0, 15, 192, 0],
        ]);
        assert_eq!(decoded.update.announced, [prefix()]);
        assert_eq!(
            decoded.update.attributes.as_path,
            Some(AsPath::sequence([64496, 23456]))
        );
        let discarded: Vec<(Option<u8>, AttributeErrorAction, UpdateError)> = decoded
            .errors
            .iter()
            .map(|error| (error.type_code, error.action, error.subcode))
            .collect();
        assert_eq!(
            discarded,
            [
                (
                    Some(17),
                    AttributeErrorAction::AttributeDiscard,
                    UpdateError::MalformedAsPath
                ),
                (
                    Some(18),
                    AttributeErrorAction::AttributeDiscard,
                    UpdateError::AttributeLengthError
                ),
            ]
        );
    }

    #[test]
    fn as4_attributes_are_discarded_on_a_four_octet_session() {
        let decoded = Update::decode(
            body(
                &[],
                &[
                    ORIGIN_IGP,
                    &[0x40, 2, 6, 2, 1, 0, 0, 0xfb, 0xf0],
                    NEXT_HOP_192_0_2_1,
                    AS4_PATH,
                    AS4_AGGREGATOR,
                ],
                NLRI,
            ),
            FOUR_OCTET,
        )
        .expect("no reset");
        assert_eq!(
            decoded.update.attributes.as_path,
            Some(AsPath::sequence([64496]))
        );
        assert_eq!(decoded.update.attributes.aggregator, None);
        let discarded: Vec<Option<u8>> =
            decoded.errors.iter().map(|error| error.type_code).collect();
        assert_eq!(discarded, [Some(17), Some(18)]);
    }

    #[test]
    fn as4_path_is_sent_only_when_an_as_number_needs_it() {
        let type_codes = |update: &Update| -> Vec<u8> {
            let wire = encode(update).expect("valid");
            let mut reader = Reader::new(Bytes::copy_from_slice(&wire), 0);
            reader.take(HEADER_LENGTH + 4).expect("fixed part");
            let mut seen = Vec::new();
            // Three short attributes, then whatever follows up to the NLRI.
            while reader.remaining() > NLRI.len() {
                let _flags = reader.u8().expect("flags");
                seen.push(reader.u8().expect("type code"));
                let length = reader.u8().expect("length");
                reader.take(usize::from(length)).expect("value");
            }
            seen
        };
        let mut update = announcement();
        assert_eq!(type_codes(&update), [1, 2, 3]);
        update.attributes.as_path = Some(AsPath::sequence([64496, 65550]));
        assert_eq!(type_codes(&update), [1, 2, 3, 17]);
    }
}
