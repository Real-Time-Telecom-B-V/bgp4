//! Capabilities carried in the OPEN message (RFC 5492).

use bytes::{BufMut, Bytes, BytesMut};

use super::error::EncodeError;
use super::reader::Reader;

const MULTIPROTOCOL: u8 = 1;
const ROUTE_REFRESH: u8 = 2;
const FOUR_OCTET_AUTONOMOUS_SYSTEM: u8 = 65;

/// An address family and subsequent address family pair (RFC 4760).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressFamily {
    /// The Address Family Identifier.
    pub identifier: u16,
    /// The Subsequent Address Family Identifier.
    pub subsequent_identifier: u8,
}

impl AddressFamily {
    /// IPv4 unicast.
    pub const IPV4_UNICAST: AddressFamily = AddressFamily {
        identifier: 1,
        subsequent_identifier: 1,
    };

    /// IPv6 unicast.
    pub const IPV6_UNICAST: AddressFamily = AddressFamily {
        identifier: 2,
        subsequent_identifier: 1,
    };
}

/// One capability of an OPEN message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Capability {
    /// Multiprotocol extensions for one address family (RFC 4760).
    Multiprotocol(AddressFamily),
    /// Route refresh (RFC 2918).
    RouteRefresh,
    /// Support for 4-octet AS numbers, with the speaker's own (RFC 6793).
    FourOctetAutonomousSystem(u32),
    /// A capability this crate does not interpret, kept byte for byte.
    Unknown {
        /// The capability code.
        code: u8,
        /// The capability value as received.
        value: Bytes,
    },
}

impl Capability {
    /// Decode one capability from its code and value.
    ///
    /// `None` when a capability this crate interprets has a value of the
    /// wrong length.
    pub(crate) fn decode(code: u8, value: Bytes) -> Option<Capability> {
        let length = value.len();
        let mut reader = Reader::new(value.clone(), 0);
        match (code, length) {
            (MULTIPROTOCOL, 4) => {
                let identifier = reader.u16()?;
                let _reserved = reader.u8()?;
                let subsequent_identifier = reader.u8()?;
                Some(Capability::Multiprotocol(AddressFamily {
                    identifier,
                    subsequent_identifier,
                }))
            }
            (ROUTE_REFRESH, 0) => Some(Capability::RouteRefresh),
            (FOUR_OCTET_AUTONOMOUS_SYSTEM, 4) => {
                reader.u32().map(Capability::FourOctetAutonomousSystem)
            }
            (MULTIPROTOCOL | ROUTE_REFRESH | FOUR_OCTET_AUTONOMOUS_SYSTEM, _) => None,
            _ => Some(Capability::Unknown { code, value }),
        }
    }

    /// Append the capability as code, length and value.
    pub(crate) fn encode(&self, buffer: &mut BytesMut) -> Result<(), EncodeError> {
        match self {
            Capability::Multiprotocol(family) => {
                buffer.put_u8(MULTIPROTOCOL);
                buffer.put_u8(4);
                buffer.put_u16(family.identifier);
                buffer.put_u8(0);
                buffer.put_u8(family.subsequent_identifier);
            }
            Capability::RouteRefresh => {
                buffer.put_u8(ROUTE_REFRESH);
                buffer.put_u8(0);
            }
            Capability::FourOctetAutonomousSystem(autonomous_system) => {
                buffer.put_u8(FOUR_OCTET_AUTONOMOUS_SYSTEM);
                buffer.put_u8(4);
                buffer.put_u32(*autonomous_system);
            }
            Capability::Unknown { code, value } => {
                let length =
                    u8::try_from(value.len()).map_err(|_| EncodeError::CapabilityTooLong {
                        code: *code,
                        length: value.len(),
                    })?;
                buffer.put_u8(*code);
                buffer.put_u8(length);
                buffer.put_slice(value);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_capabilities_with_a_wrong_length_are_rejected() {
        for (code, value) in [
            (MULTIPROTOCOL, &[0, 1, 0][..]),
            (MULTIPROTOCOL, &[0, 1, 0, 1, 0][..]),
            (ROUTE_REFRESH, &[0][..]),
            (FOUR_OCTET_AUTONOMOUS_SYSTEM, &[0, 0, 1][..]),
            (FOUR_OCTET_AUTONOMOUS_SYSTEM, &[][..]),
        ] {
            assert_eq!(
                Capability::decode(code, Bytes::copy_from_slice(value)),
                None,
                "code {code}"
            );
        }
    }

    #[test]
    fn the_reserved_octet_of_multiprotocol_is_ignored() {
        assert_eq!(
            Capability::decode(MULTIPROTOCOL, Bytes::from_static(&[0, 2, 0xff, 1])),
            Some(Capability::Multiprotocol(AddressFamily::IPV6_UNICAST))
        );
    }

    #[test]
    fn an_unknown_capability_longer_than_255_octets_cannot_be_encoded() {
        let capability = Capability::Unknown {
            code: 200,
            value: Bytes::from(vec![0; 256]),
        };
        let mut buffer = BytesMut::new();
        assert_eq!(
            capability.encode(&mut buffer),
            Err(EncodeError::CapabilityTooLong {
                code: 200,
                length: 256
            })
        );
        assert!(buffer.is_empty());
    }
}
