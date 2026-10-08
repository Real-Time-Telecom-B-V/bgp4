//! KEEPALIVE: a header and nothing else (RFC 4271 section 4.4).

use bytes::{Bytes, BytesMut};

use super::error::{DecodeError, DecodeErrorReason};
use super::header::{Header, MessageType, HEADER_LENGTH};

/// A KEEPALIVE message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keepalive;

impl Keepalive {
    /// Decode the body of a KEEPALIVE, which must be empty.
    pub fn decode(body: Bytes) -> Result<Keepalive, DecodeError> {
        if body.is_empty() {
            return Ok(Keepalive);
        }
        let length = u16::try_from(HEADER_LENGTH + body.len()).unwrap_or(u16::MAX);
        Err(DecodeError::new(
            DecodeErrorReason::BadMessageLength { length },
            16,
        ))
    }

    /// Append the whole message, header included, to `buffer`.
    pub fn encode(&self, buffer: &mut BytesMut) {
        Header::write(MessageType::Keepalive, HEADER_LENGTH as u16, buffer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_to_the_19_octets_of_rfc_4271() {
        let mut buffer = BytesMut::new();
        Keepalive.encode(&mut buffer);
        let mut expected = vec![0xff; 16];
        expected.extend_from_slice(&[0x00, 0x13, 0x04]);
        assert_eq!(buffer.as_ref(), expected);
    }

    #[test]
    fn a_body_is_a_bad_message_length() {
        let error = Keepalive::decode(Bytes::from_static(&[0])).expect_err("body not allowed");
        assert_eq!(
            error.reason(),
            DecodeErrorReason::BadMessageLength { length: 20 }
        );
    }
}
