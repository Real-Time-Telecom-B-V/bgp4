//! ROUTE-REFRESH (RFC 2918), with the subtypes of RFC 7313.

use bytes::{BufMut, Bytes, BytesMut};

use super::capability::AddressFamily;
use super::error::{DecodeError, DecodeErrorReason};
use super::header::{Header, MessageType, HEADER_LENGTH};
use super::reader::Reader;

/// Length of a ROUTE-REFRESH body: address family, subtype, subsequent
/// address family.
const BODY_LENGTH: usize = 4;

/// What a ROUTE-REFRESH message means.
///
/// RFC 2918 has only the request and calls this octet reserved. RFC 7313
/// gives it a meaning between speakers that both announced enhanced route
/// refresh. The crate does not announce that capability, but reads the octet
/// faithfully so that a marker is never mistaken for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteRefreshSubtype {
    /// Send your routes for this address family again.
    Request,
    /// The routes that follow are a refresh (RFC 7313).
    BeginOfRefresh,
    /// The refresh is complete (RFC 7313).
    EndOfRefresh,
    /// A value this crate has no name for.
    Other(u8),
}

impl RouteRefreshSubtype {
    fn code(self) -> u8 {
        match self {
            RouteRefreshSubtype::Request => 0,
            RouteRefreshSubtype::BeginOfRefresh => 1,
            RouteRefreshSubtype::EndOfRefresh => 2,
            RouteRefreshSubtype::Other(code) => code,
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            0 => RouteRefreshSubtype::Request,
            1 => RouteRefreshSubtype::BeginOfRefresh,
            2 => RouteRefreshSubtype::EndOfRefresh,
            other => RouteRefreshSubtype::Other(other),
        }
    }
}

/// A ROUTE-REFRESH message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteRefresh {
    /// The address family the message is about.
    pub address_family: AddressFamily,
    /// Request or marker.
    pub subtype: RouteRefreshSubtype,
}

impl RouteRefresh {
    /// A request to send the routes of `address_family` again.
    pub fn request(address_family: AddressFamily) -> Self {
        Self {
            address_family,
            subtype: RouteRefreshSubtype::Request,
        }
    }

    /// Decode the body of a ROUTE-REFRESH, that is, what follows the header.
    pub fn decode(body: Bytes) -> Result<RouteRefresh, DecodeError> {
        let length = u16::try_from(HEADER_LENGTH + body.len()).unwrap_or(u16::MAX);
        let bad_length = || DecodeError::new(DecodeErrorReason::BadMessageLength { length }, 16);
        if body.len() != BODY_LENGTH {
            return Err(bad_length());
        }
        let mut reader = Reader::new(body, HEADER_LENGTH);
        let identifier = reader.u16().ok_or_else(bad_length)?;
        let subtype = reader.u8().ok_or_else(bad_length)?;
        let subsequent_identifier = reader.u8().ok_or_else(bad_length)?;
        Ok(RouteRefresh {
            address_family: AddressFamily {
                identifier,
                subsequent_identifier,
            },
            subtype: RouteRefreshSubtype::from_code(subtype),
        })
    }

    /// Append the whole message, header included, to `buffer`.
    pub fn encode(&self, buffer: &mut BytesMut) {
        Header::write(
            MessageType::RouteRefresh,
            (HEADER_LENGTH + BODY_LENGTH) as u16,
            buffer,
        );
        buffer.put_u16(self.address_family.identifier);
        buffer.put_u8(self.subtype.code());
        buffer.put_u8(self.address_family.subsequent_identifier);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_for_ipv6_unicast() {
        let mut buffer = BytesMut::new();
        RouteRefresh::request(AddressFamily::IPV6_UNICAST).encode(&mut buffer);
        // RFC 2918 section 3: AFI, reserved, SAFI after the header.
        assert_eq!(&buffer[16..], [0, 23, 5, 0, 2, 0, 1]);
        assert_eq!(
            RouteRefresh::decode(buffer.freeze().slice(HEADER_LENGTH..)),
            Ok(RouteRefresh::request(AddressFamily::IPV6_UNICAST))
        );
    }

    #[test]
    fn subtypes_are_kept() {
        for (code, subtype) in [
            (0, RouteRefreshSubtype::Request),
            (1, RouteRefreshSubtype::BeginOfRefresh),
            (2, RouteRefreshSubtype::EndOfRefresh),
            (200, RouteRefreshSubtype::Other(200)),
        ] {
            let decoded =
                RouteRefresh::decode(Bytes::copy_from_slice(&[0, 1, code, 1])).expect("valid");
            assert_eq!(decoded.subtype, subtype);
            let mut buffer = BytesMut::new();
            decoded.encode(&mut buffer);
            assert_eq!(buffer[HEADER_LENGTH + 2], code);
        }
    }

    #[test]
    fn any_other_body_length_is_a_bad_message_length() {
        for (body, length) in [(&[0, 1, 0][..], 22), (&[0, 1, 0, 1, 0][..], 24)] {
            let error =
                RouteRefresh::decode(Bytes::copy_from_slice(body)).expect_err("wrong length");
            assert_eq!(
                error.reason(),
                DecodeErrorReason::BadMessageLength { length }
            );
        }
    }
}
