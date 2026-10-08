//! OPEN (RFC 4271 section 4.2) with its capabilities (RFC 5492).

use std::net::Ipv4Addr;

use bytes::{BufMut, Bytes, BytesMut};

use super::capability::Capability;
use super::error::{DecodeError, DecodeErrorReason, EncodeError};
use super::header::{Header, MessageType, HEADER_LENGTH};
use super::reader::Reader;

/// The only protocol version there is.
const VERSION: u8 = 4;

/// Stands in for a 4-octet AS number in the 2-octet field (RFC 6793).
const AS_TRANS: u16 = 23456;

/// Optional parameter type of the capabilities parameter (RFC 5492).
const CAPABILITIES_PARAMETER: u8 = 2;

/// Octets of an OPEN body before the optional parameters.
const FIXED_BODY_LENGTH: usize = 10;

/// The optional parameters length is a single octet.
const MAXIMUM_OPTIONAL_PARAMETERS_LENGTH: usize = 255;

/// An OPEN message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    my_autonomous_system: u16,
    hold_time: u16,
    bgp_identifier: Ipv4Addr,
    capabilities: Vec<Capability>,
}

impl Open {
    /// An OPEN for a speaker with the given AS number.
    ///
    /// The 4-octet AS capability is always added, as RFC 6793 asks of every
    /// speaker that supports it, and an AS number that does not fit in 2
    /// octets is replaced by AS_TRANS in the fixed field. A 4-octet AS
    /// capability passed in `capabilities` is dropped in favour of that one.
    pub fn new(
        autonomous_system: u32,
        hold_time: u16,
        bgp_identifier: Ipv4Addr,
        capabilities: Vec<Capability>,
    ) -> Self {
        let mut capabilities: Vec<Capability> = capabilities
            .into_iter()
            .filter(|capability| !matches!(capability, Capability::FourOctetAutonomousSystem(_)))
            .collect();
        capabilities.push(Capability::FourOctetAutonomousSystem(autonomous_system));
        Self {
            my_autonomous_system: u16::try_from(autonomous_system).unwrap_or(AS_TRANS),
            hold_time,
            bgp_identifier,
            capabilities,
        }
    }

    /// The speaker's AS number: the one in the 4-octet AS capability when
    /// present, the 2-octet field otherwise.
    pub fn autonomous_system(&self) -> u32 {
        self.capabilities
            .iter()
            .find_map(|capability| match capability {
                Capability::FourOctetAutonomousSystem(autonomous_system) => {
                    Some(*autonomous_system)
                }
                _ => None,
            })
            .unwrap_or(u32::from(self.my_autonomous_system))
    }

    /// The 2-octet "My Autonomous System" field as it is on the wire.
    pub fn my_autonomous_system(&self) -> u16 {
        self.my_autonomous_system
    }

    /// The proposed hold time in seconds. Zero means no keepalives.
    pub fn hold_time(&self) -> u16 {
        self.hold_time
    }

    /// The BGP identifier.
    pub fn bgp_identifier(&self) -> Ipv4Addr {
        self.bgp_identifier
    }

    /// Every capability of the message, in wire order.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Decode the body of an OPEN, that is, what follows the header.
    ///
    /// Checks the rules a receiver must enforce on the message alone
    /// (RFC 4271 section 6.2, RFC 6286): version, hold time, a non-zero
    /// identifier and well-formed optional parameters. Whether the AS number
    /// is the expected one is for the session to decide.
    pub fn decode(body: Bytes) -> Result<Open, DecodeError> {
        if body.len() < FIXED_BODY_LENGTH {
            let length = u16::try_from(HEADER_LENGTH + body.len()).unwrap_or(u16::MAX);
            return Err(DecodeError::new(
                DecodeErrorReason::BadMessageLength { length },
                16,
            ));
        }
        let mut reader = Reader::new(body, HEADER_LENGTH);
        let malformed = |offset: usize| DecodeError::new(DecodeErrorReason::MalformedOpen, offset);

        let offset = reader.offset();
        let version = reader.u8().ok_or_else(|| malformed(offset))?;
        if version != VERSION {
            return Err(DecodeError::new(
                DecodeErrorReason::UnsupportedVersionNumber { version },
                offset,
            ));
        }

        let offset = reader.offset();
        let my_autonomous_system = reader.u16().ok_or_else(|| malformed(offset))?;

        let offset = reader.offset();
        let hold_time = reader.u16().ok_or_else(|| malformed(offset))?;
        if hold_time == 1 || hold_time == 2 {
            return Err(DecodeError::new(
                DecodeErrorReason::UnacceptableHoldTime { hold_time },
                offset,
            ));
        }

        let offset = reader.offset();
        let bgp_identifier = reader.u32().ok_or_else(|| malformed(offset))?;
        if bgp_identifier == 0 {
            return Err(DecodeError::new(
                DecodeErrorReason::BadBgpIdentifier,
                offset,
            ));
        }

        let offset = reader.offset();
        let optional_parameters_length = reader.u8().ok_or_else(|| malformed(offset))?;
        if usize::from(optional_parameters_length) != reader.remaining() {
            return Err(malformed(offset));
        }

        let mut capabilities = Vec::new();
        while !reader.is_empty() {
            let offset = reader.offset();
            let parameter_type = reader.u8().ok_or_else(|| malformed(offset))?;
            let parameter_length = reader.u8().ok_or_else(|| malformed(offset))?;
            let mut parameter = reader
                .sub_reader(usize::from(parameter_length))
                .ok_or_else(|| malformed(offset))?;
            if parameter_type != CAPABILITIES_PARAMETER {
                return Err(DecodeError::new(
                    DecodeErrorReason::UnsupportedOptionalParameter { parameter_type },
                    offset,
                ));
            }
            while !parameter.is_empty() {
                let offset = parameter.offset();
                let code = parameter.u8().ok_or_else(|| malformed(offset))?;
                let length = parameter.u8().ok_or_else(|| malformed(offset))?;
                let value = parameter
                    .take(usize::from(length))
                    .ok_or_else(|| malformed(offset))?;
                capabilities
                    .push(Capability::decode(code, value).ok_or_else(|| malformed(offset))?);
            }
        }

        Ok(Open {
            my_autonomous_system,
            hold_time,
            bgp_identifier: Ipv4Addr::from(bgp_identifier),
            capabilities,
        })
    }

    /// Append the whole message, header included, to `buffer`.
    ///
    /// All capabilities go into one optional parameter, as RFC 5492
    /// recommends. Nothing is written when the message cannot be encoded.
    pub fn encode(&self, buffer: &mut BytesMut) -> Result<(), EncodeError> {
        if self.hold_time == 1 || self.hold_time == 2 {
            return Err(EncodeError::UnacceptableHoldTime {
                hold_time: self.hold_time,
            });
        }
        if self.bgp_identifier.is_unspecified() {
            return Err(EncodeError::ZeroBgpIdentifier);
        }

        let mut capabilities = BytesMut::new();
        for capability in &self.capabilities {
            capability.encode(&mut capabilities)?;
        }
        let optional_parameters_length = if capabilities.is_empty() {
            0
        } else {
            2 + capabilities.len()
        };
        let too_long = EncodeError::OptionalParametersTooLong {
            length: optional_parameters_length,
        };
        if optional_parameters_length > MAXIMUM_OPTIONAL_PARAMETERS_LENGTH {
            return Err(too_long);
        }
        let optional_parameters_length_octet =
            u8::try_from(optional_parameters_length).map_err(|_| too_long)?;

        Header::encode(
            MessageType::Open,
            FIXED_BODY_LENGTH + optional_parameters_length,
            buffer,
        )?;
        buffer.put_u8(VERSION);
        buffer.put_u16(self.my_autonomous_system);
        buffer.put_u16(self.hold_time);
        buffer.put_slice(&self.bgp_identifier.octets());
        buffer.put_u8(optional_parameters_length_octet);
        if !capabilities.is_empty() {
            buffer.put_u8(CAPABILITIES_PARAMETER);
            // Two less than a value that was just checked to fit in an octet.
            buffer.put_u8(optional_parameters_length_octet - 2);
            buffer.put_slice(&capabilities);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{AddressFamily, ErrorCode, OpenError};

    /// Version 4, AS 64496, hold time 90, identifier 192.0.2.1, then the
    /// given optional parameters.
    fn body(optional_parameters: &[u8]) -> Vec<u8> {
        let mut body = vec![4, 0xfb, 0xf0, 0, 90, 192, 0, 2, 1];
        body.push(optional_parameters.len() as u8);
        body.extend_from_slice(optional_parameters);
        body
    }

    fn decode(body: &[u8]) -> Result<Open, DecodeError> {
        Open::decode(Bytes::copy_from_slice(body))
    }

    fn failure(body: &[u8]) -> (DecodeErrorReason, usize) {
        let error = decode(body).expect_err("must be rejected");
        (error.reason(), error.offset())
    }

    #[test]
    fn without_optional_parameters() {
        let open = decode(&body(&[])).expect("valid");
        assert_eq!(open.autonomous_system(), 64496);
        assert_eq!(open.hold_time(), 90);
        assert_eq!(open.bgp_identifier(), Ipv4Addr::new(192, 0, 2, 1));
        assert!(open.capabilities().is_empty());
    }

    #[test]
    fn capabilities_spread_over_several_parameters_are_collected_in_order() {
        let open = decode(&body(&[
            2, 6, 1, 4, 0, 1, 0, 1, // multiprotocol, IPv4 unicast
            2, 2, 2, 0, // route refresh
            2, 8, 65, 4, 0, 1, 0, 14, 99, 0, // 4-octet AS 65550, then unknown 99
        ]))
        .expect("valid");
        assert_eq!(
            open.capabilities(),
            [
                Capability::Multiprotocol(AddressFamily::IPV4_UNICAST),
                Capability::RouteRefresh,
                Capability::FourOctetAutonomousSystem(65550),
                Capability::Unknown {
                    code: 99,
                    value: Bytes::new()
                },
            ]
        );
        assert_eq!(open.autonomous_system(), 65550);
        assert_eq!(open.my_autonomous_system(), 64496);
    }

    #[test]
    fn version_other_than_4_reports_the_supported_version() {
        let mut bytes = body(&[]);
        bytes[0] = 3;
        let error = decode(&bytes).expect_err("version 3");
        assert_eq!(
            error.reason(),
            DecodeErrorReason::UnsupportedVersionNumber { version: 3 }
        );
        assert_eq!(error.offset(), 19);
        let notification = error.notification();
        assert_eq!(
            notification.error(),
            ErrorCode::Open(OpenError::UnsupportedVersionNumber)
        );
        assert_eq!(notification.data().as_ref(), [0, 4]);
    }

    #[test]
    fn hold_times_of_one_and_two_seconds_are_unacceptable() {
        for hold_time in [1u8, 2] {
            let mut bytes = body(&[]);
            bytes[3] = 0;
            bytes[4] = hold_time;
            assert_eq!(
                failure(&bytes),
                (
                    DecodeErrorReason::UnacceptableHoldTime {
                        hold_time: u16::from(hold_time)
                    },
                    22
                )
            );
        }
        for hold_time in [0u8, 3] {
            let mut bytes = body(&[]);
            bytes[3] = 0;
            bytes[4] = hold_time;
            assert!(decode(&bytes).is_ok(), "hold time {hold_time}");
        }
    }

    #[test]
    fn a_zero_identifier_is_bad() {
        let mut bytes = body(&[]);
        bytes[5..9].copy_from_slice(&[0, 0, 0, 0]);
        let error = decode(&bytes).expect_err("zero identifier");
        assert_eq!(error.reason(), DecodeErrorReason::BadBgpIdentifier);
        assert_eq!(error.offset(), 24);
        assert_eq!(
            error.notification().error(),
            ErrorCode::Open(OpenError::BadBgpIdentifier)
        );
    }

    #[test]
    fn an_optional_parameter_other_than_capabilities_is_unsupported() {
        let error = decode(&body(&[1, 2, 0xaa, 0xbb])).expect_err("authentication parameter");
        assert_eq!(
            error.reason(),
            DecodeErrorReason::UnsupportedOptionalParameter { parameter_type: 1 }
        );
        assert_eq!(error.offset(), 29);
        assert_eq!(
            error.notification().error(),
            ErrorCode::Open(OpenError::UnsupportedOptionalParameter)
        );
    }

    #[test]
    fn malformed_optional_parameters() {
        // Optional parameters length disagrees with what follows.
        let mut longer = body(&[2, 2, 2, 0]);
        longer[9] = 5;
        assert_eq!(failure(&longer), (DecodeErrorReason::MalformedOpen, 28));
        let mut shorter = body(&[2, 2, 2, 0]);
        shorter[9] = 3;
        assert_eq!(failure(&shorter), (DecodeErrorReason::MalformedOpen, 28));

        // Parameter length runs past the end.
        assert_eq!(
            failure(&body(&[2, 9, 2, 0])),
            (DecodeErrorReason::MalformedOpen, 29)
        );
        // Parameter header cut short.
        assert_eq!(failure(&body(&[2])), (DecodeErrorReason::MalformedOpen, 29));
        // Capability length runs past the end of its parameter.
        assert_eq!(
            failure(&body(&[2, 4, 2, 0, 99, 5])),
            (DecodeErrorReason::MalformedOpen, 33)
        );
        // A capability this crate interprets, with the wrong length.
        assert_eq!(
            failure(&body(&[2, 5, 65, 3, 0, 0, 1])),
            (DecodeErrorReason::MalformedOpen, 31)
        );
    }

    #[test]
    fn a_malformed_open_is_answered_with_the_unspecific_subcode() {
        let error = decode(&body(&[2])).expect_err("malformed");
        let notification = error.notification();
        assert_eq!(notification.error(), ErrorCode::Open(OpenError::Unspecific));
        assert!(notification.data().is_empty());
    }

    #[test]
    fn a_body_shorter_than_the_fixed_part_is_a_bad_message_length() {
        let error = decode(&[4, 0xfb, 0xf0]).expect_err("too short");
        assert_eq!(
            error.reason(),
            DecodeErrorReason::BadMessageLength { length: 22 }
        );
    }

    #[test]
    fn new_replaces_a_caller_supplied_four_octet_capability() {
        let open = Open::new(
            65550,
            90,
            Ipv4Addr::new(192, 0, 2, 1),
            vec![
                Capability::FourOctetAutonomousSystem(64496),
                Capability::RouteRefresh,
            ],
        );
        assert_eq!(
            open.capabilities(),
            [
                Capability::RouteRefresh,
                Capability::FourOctetAutonomousSystem(65550)
            ]
        );
        assert_eq!(open.my_autonomous_system(), 23456);
        assert_eq!(open.autonomous_system(), 65550);
    }

    #[test]
    fn encode_refuses_what_a_receiver_would_reject() {
        let mut buffer = BytesMut::new();
        for hold_time in [1, 2] {
            let open = Open::new(64496, hold_time, Ipv4Addr::new(192, 0, 2, 1), Vec::new());
            assert_eq!(
                open.encode(&mut buffer),
                Err(EncodeError::UnacceptableHoldTime { hold_time })
            );
        }
        let open = Open::new(64496, 90, Ipv4Addr::UNSPECIFIED, Vec::new());
        assert_eq!(
            open.encode(&mut buffer),
            Err(EncodeError::ZeroBgpIdentifier)
        );
        assert!(buffer.is_empty());
    }

    #[test]
    fn capabilities_that_do_not_fit_in_one_parameter_are_refused() {
        // 6 octets for the 4-octet AS capability, 2 for the parameter header.
        let fits = Capability::Unknown {
            code: 200,
            value: Bytes::from(vec![0; 245]),
        };
        let open = Open::new(64496, 90, Ipv4Addr::new(192, 0, 2, 1), vec![fits]);
        let mut buffer = BytesMut::new();
        assert_eq!(open.encode(&mut buffer), Ok(()));
        assert_eq!(buffer.len(), HEADER_LENGTH + FIXED_BODY_LENGTH + 255);

        let one_more = Capability::Unknown {
            code: 200,
            value: Bytes::from(vec![0; 246]),
        };
        let open = Open::new(64496, 90, Ipv4Addr::new(192, 0, 2, 1), vec![one_more]);
        let mut buffer = BytesMut::new();
        assert_eq!(
            open.encode(&mut buffer),
            Err(EncodeError::OptionalParametersTooLong { length: 256 })
        );
        assert!(buffer.is_empty());
    }
}
