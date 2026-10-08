//! UPDATE (RFC 4271 section 4.3), with the revised error handling of RFC 7606.

use bytes::{BufMut, Bytes, BytesMut};

use super::attribute::{
    AttributeError, AttributeErrorAction, PathAttributes, AS_PATH, NEXT_HOP, ORIGIN,
};
use super::error::{DecodeError, DecodeErrorReason, EncodeError};
use super::header::{Header, MessageType, HEADER_LENGTH};
use super::nlri::Ipv4Prefix;
use super::notification::UpdateError;
use super::reader::Reader;

/// What was negotiated on the session and changes how an UPDATE is read and
/// written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct UpdateContext {
    /// Both speakers announced the 4-octet AS capability (RFC 6793), so AS
    /// numbers in AS_PATH and AGGREGATOR are 4 octets wide.
    pub four_octet_autonomous_systems: bool,
}

impl UpdateContext {
    /// A context for a session with or without 4-octet AS numbers.
    pub const fn new(four_octet_autonomous_systems: bool) -> Self {
        Self {
            four_octet_autonomous_systems,
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
        let (mut attributes, mut treat_as_withdraw) =
            PathAttributes::decode(attributes_reader, context, &mut errors)?;

        // RFC 7606 section 3.d: a missing mandatory attribute is
        // treat-as-withdraw. They are mandatory only when a route is announced.
        if !treat_as_withdraw && !announced.is_empty() {
            let missing = [
                (ORIGIN, attributes.origin.is_none()),
                (AS_PATH, attributes.as_path.is_none()),
                (NEXT_HOP, attributes.next_hop.is_none()),
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
            attributes = PathAttributes::default();
        }

        Ok(DecodedUpdate {
            update: Update {
                withdrawn,
                attributes,
                announced,
            },
            errors,
        })
    }

    /// Append the whole message, header included, to `buffer`.
    ///
    /// Refuses to write an UPDATE that a receiver would have to repair: one
    /// that announces a route without ORIGIN, AS_PATH and NEXT_HOP. Nothing
    /// is written when the message cannot be encoded or does not fit.
    pub fn encode(&self, context: UpdateContext, buffer: &mut BytesMut) -> Result<(), EncodeError> {
        if !self.announced.is_empty() {
            let mandatory = [
                (ORIGIN, self.attributes.origin.is_none()),
                (AS_PATH, self.attributes.as_path.is_none()),
                (NEXT_HOP, self.attributes.next_hop.is_none()),
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
        self.attributes.encode(context, &mut attributes)?;
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
        Aggregator, AsPath, ErrorCode, Origin, UnknownAttribute, MAXIMUM_MESSAGE_LENGTH,
    };

    const FOUR_OCTET: UpdateContext = UpdateContext::new(true);
    const TWO_OCTET: UpdateContext = UpdateContext::new(false);

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
        Update::decode(body(&[], attributes, NLRI), TWO_OCTET).expect("no session reset")
    }

    /// Asserts the message was turned into a withdrawal of the one route and
    /// returns the errors.
    fn withdrawn(attributes: &[&[u8]]) -> Vec<AttributeError> {
        let decoded = decode(attributes);
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
            TWO_OCTET,
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
            (&[0x40, 5, 0][..], 5),
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
            withdrawn: Vec::new(),
            attributes,
            announced: vec![prefix()],
        }
    }

    fn encode(update: &Update) -> Result<Vec<u8>, EncodeError> {
        let mut buffer = BytesMut::new();
        update.encode(TWO_OCTET, &mut buffer)?;
        Ok(buffer.to_vec())
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
        let wire = encode(&update).expect("valid");
        let decoded =
            Update::decode(Bytes::copy_from_slice(&wire[HEADER_LENGTH..]), TWO_OCTET).expect("ok");
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
}
