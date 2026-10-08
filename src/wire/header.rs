//! The fixed 19-octet message header (RFC 4271 section 4.1).

use bytes::{BufMut, BytesMut};

use super::error::{DecodeError, DecodeErrorReason, EncodeError};

/// Length of the message header in octets.
pub const HEADER_LENGTH: usize = 19;

/// Largest message RFC 4271 allows, header included.
pub const MAXIMUM_MESSAGE_LENGTH: usize = 4096;

const MARKER_LENGTH: usize = 16;
const LENGTH_OFFSET: usize = 16;
const TYPE_OFFSET: usize = 18;

/// The message types this crate knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// OPEN (RFC 4271).
    Open,
    /// UPDATE (RFC 4271).
    Update,
    /// NOTIFICATION (RFC 4271).
    Notification,
    /// KEEPALIVE (RFC 4271).
    Keepalive,
    /// ROUTE-REFRESH (RFC 2918).
    RouteRefresh,
}

impl MessageType {
    /// The value of the type octet.
    pub fn code(self) -> u8 {
        match self {
            MessageType::Open => 1,
            MessageType::Update => 2,
            MessageType::Notification => 3,
            MessageType::Keepalive => 4,
            MessageType::RouteRefresh => 5,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(MessageType::Open),
            2 => Some(MessageType::Update),
            3 => Some(MessageType::Notification),
            4 => Some(MessageType::Keepalive),
            5 => Some(MessageType::RouteRefresh),
            _ => None,
        }
    }

    /// Whether a message of this type may have the given total length.
    ///
    /// Minimums are from RFC 4271 section 6.1 (OPEN 29, UPDATE 23,
    /// NOTIFICATION 21, KEEPALIVE exactly 19) and RFC 2918 section 3
    /// (ROUTE-REFRESH exactly 23).
    fn accepts_length(self, length: usize) -> bool {
        if length > MAXIMUM_MESSAGE_LENGTH {
            return false;
        }
        match self {
            MessageType::Open => length >= 29,
            MessageType::Update => length >= 23,
            MessageType::Notification => length >= 21,
            MessageType::Keepalive => length == 19,
            MessageType::RouteRefresh => length == 23,
        }
    }
}

/// A validated message header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    length: u16,
    message_type: MessageType,
}

impl Header {
    /// Decode the header at the start of `bytes`.
    ///
    /// Returns `Ok(None)` while fewer than [`HEADER_LENGTH`] octets are
    /// available, so a session can call this on its read buffer as data
    /// arrives. Once it returns a header, the message is complete when the
    /// buffer holds [`Header::length`] octets.
    ///
    /// Checks run in the order of RFC 4271 section 6.1: marker, length, type.
    pub fn decode(bytes: &[u8]) -> Result<Option<Header>, DecodeError> {
        let Some(header) = bytes.first_chunk::<HEADER_LENGTH>() else {
            return Ok(None);
        };
        if let Some(offset) = header[..MARKER_LENGTH]
            .iter()
            .position(|octet| *octet != 0xff)
        {
            return Err(DecodeError::new(
                DecodeErrorReason::ConnectionNotSynchronized,
                offset,
            ));
        }
        let length = u16::from_be_bytes([header[LENGTH_OFFSET], header[LENGTH_OFFSET + 1]]);
        let bad_length = || {
            DecodeError::new(
                DecodeErrorReason::BadMessageLength { length },
                LENGTH_OFFSET,
            )
        };
        if !(HEADER_LENGTH..=MAXIMUM_MESSAGE_LENGTH).contains(&usize::from(length)) {
            return Err(bad_length());
        }
        let code = header[TYPE_OFFSET];
        let message_type = MessageType::from_code(code).ok_or_else(|| {
            DecodeError::new(
                DecodeErrorReason::BadMessageType { message_type: code },
                TYPE_OFFSET,
            )
        })?;
        if !message_type.accepts_length(usize::from(length)) {
            return Err(bad_length());
        }
        Ok(Some(Header {
            length,
            message_type,
        }))
    }

    /// Length of the whole message in octets, header included.
    pub fn length(&self) -> u16 {
        self.length
    }

    /// Length of what follows the header.
    pub fn body_length(&self) -> usize {
        usize::from(self.length) - HEADER_LENGTH
    }

    /// The message type.
    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// Write the header of a message whose body is `body_length` octets long.
    pub(crate) fn encode(
        message_type: MessageType,
        body_length: usize,
        buffer: &mut BytesMut,
    ) -> Result<(), EncodeError> {
        let length = HEADER_LENGTH.saturating_add(body_length);
        let too_long = EncodeError::MessageTooLong { length };
        if !message_type.accepts_length(length) {
            return Err(too_long);
        }
        let length = u16::try_from(length).map_err(|_| too_long)?;
        Self::write(message_type, length, buffer);
        Ok(())
    }

    /// Write a header as given. The caller vouches for `length`.
    pub(crate) fn write(message_type: MessageType, length: u16, buffer: &mut BytesMut) {
        buffer.reserve(usize::from(length));
        buffer.put_bytes(0xff, MARKER_LENGTH);
        buffer.put_u16(length);
        buffer.put_u8(message_type.code());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(length: u16, message_type: u8) -> Vec<u8> {
        let mut bytes = vec![0xff; MARKER_LENGTH];
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.push(message_type);
        bytes
    }

    fn reason(bytes: &[u8]) -> (DecodeErrorReason, usize) {
        let error = Header::decode(bytes).expect_err("must be rejected");
        (error.reason(), error.offset())
    }

    #[test]
    fn incomplete_header_is_not_an_error() {
        let bytes = header(19, 4);
        for available in 0..HEADER_LENGTH {
            assert_eq!(Header::decode(&bytes[..available]), Ok(None));
        }
    }

    #[test]
    fn keepalive_header() {
        let decoded = Header::decode(&header(19, 4))
            .expect("valid")
            .expect("complete");
        assert_eq!(decoded.message_type(), MessageType::Keepalive);
        assert_eq!(decoded.length(), 19);
        assert_eq!(decoded.body_length(), 0);
    }

    #[test]
    fn trailing_octets_of_the_next_message_are_ignored() {
        let mut bytes = header(19, 4);
        bytes.extend_from_slice(&[0xff, 0xff, 0x00]);
        let decoded = Header::decode(&bytes).expect("valid").expect("complete");
        assert_eq!(decoded.length(), 19);
    }

    #[test]
    fn marker_must_be_all_ones() {
        for position in 0..MARKER_LENGTH {
            let mut bytes = header(19, 4);
            bytes[position] = 0xfe;
            assert_eq!(
                reason(&bytes),
                (DecodeErrorReason::ConnectionNotSynchronized, position)
            );
        }
    }

    #[test]
    fn marker_is_checked_before_length_and_type() {
        let mut bytes = header(5000, 99);
        bytes[0] = 0;
        assert_eq!(
            reason(&bytes),
            (DecodeErrorReason::ConnectionNotSynchronized, 0)
        );
    }

    #[test]
    fn length_below_the_header_and_above_the_maximum() {
        for length in [0, 18, 4097, u16::MAX] {
            assert_eq!(
                reason(&header(length, 2)),
                (DecodeErrorReason::BadMessageLength { length }, 16)
            );
        }
    }

    #[test]
    fn length_is_checked_before_type() {
        assert_eq!(
            reason(&header(18, 99)),
            (DecodeErrorReason::BadMessageLength { length: 18 }, 16)
        );
    }

    #[test]
    fn unknown_types() {
        for message_type in [0, 6, 255] {
            assert_eq!(
                reason(&header(19, message_type)),
                (DecodeErrorReason::BadMessageType { message_type }, 18)
            );
        }
    }

    #[test]
    fn per_type_length_bounds() {
        // (type octet, accepted lengths, rejected lengths)
        let cases: [(u8, &[u16], &[u16]); 5] = [
            (1, &[29, 4096], &[19, 28]),
            (2, &[23, 4096], &[19, 22]),
            (3, &[21, 4096], &[19, 20]),
            (4, &[19], &[20, 4096]),
            (5, &[23], &[19, 22, 24]),
        ];
        for (message_type, accepted, rejected) in cases {
            for length in accepted {
                assert!(
                    Header::decode(&header(*length, message_type)).is_ok(),
                    "type {message_type} length {length}"
                );
            }
            for length in rejected {
                assert_eq!(
                    reason(&header(*length, message_type)),
                    (DecodeErrorReason::BadMessageLength { length: *length }, 16),
                    "type {message_type}"
                );
            }
        }
    }

    #[test]
    fn encode_rejects_a_body_past_the_maximum() {
        let mut buffer = BytesMut::new();
        assert_eq!(
            Header::encode(MessageType::Notification, 4078, &mut buffer),
            Err(EncodeError::MessageTooLong { length: 4097 })
        );
        assert!(buffer.is_empty());
    }
}
