//! Errors of the wire codec.

use std::fmt;

use bytes::Bytes;

use super::notification::{ErrorCode, MessageHeaderError, Notification};

/// Why a message could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeErrorReason {
    /// The marker is not all ones (RFC 4271 section 6.1).
    ConnectionNotSynchronized,
    /// The length field is outside what the message type allows, or the body
    /// handed to a decoder does not match it. Carries the length in question.
    BadMessageLength {
        /// The length of the whole message, header included.
        length: u16,
    },
    /// The type field holds a value this crate does not know.
    BadMessageType {
        /// The type octet as received.
        message_type: u8,
    },
}

/// A message that could not be decoded, and what to tell the peer about it.
///
/// The codec does not log: it has no notion of which peer the bytes came from.
/// The caller logs this error together with the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeError {
    reason: DecodeErrorReason,
    offset: usize,
}

impl DecodeError {
    pub(crate) fn new(reason: DecodeErrorReason, offset: usize) -> Self {
        Self { reason, offset }
    }

    /// Why decoding failed.
    pub fn reason(&self) -> DecodeErrorReason {
        self.reason
    }

    /// Offset of the offending octet, counted from the start of the message.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The NOTIFICATION the session must send before closing the connection.
    pub fn notification(&self) -> Notification {
        match self.reason {
            DecodeErrorReason::ConnectionNotSynchronized => Notification::new(
                ErrorCode::MessageHeader(MessageHeaderError::ConnectionNotSynchronized),
                Bytes::new(),
            ),
            DecodeErrorReason::BadMessageLength { length } => Notification::new(
                ErrorCode::MessageHeader(MessageHeaderError::BadMessageLength),
                Bytes::copy_from_slice(&length.to_be_bytes()),
            ),
            DecodeErrorReason::BadMessageType { message_type } => Notification::new(
                ErrorCode::MessageHeader(MessageHeaderError::BadMessageType),
                Bytes::copy_from_slice(&[message_type]),
            ),
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.reason {
            DecodeErrorReason::ConnectionNotSynchronized => {
                write!(formatter, "marker is not all ones")?
            }
            DecodeErrorReason::BadMessageLength { length } => {
                write!(formatter, "bad message length {length}")?
            }
            DecodeErrorReason::BadMessageType { message_type } => {
                write!(formatter, "bad message type {message_type}")?
            }
        }
        write!(formatter, " at offset {}", self.offset)
    }
}

impl std::error::Error for DecodeError {}

/// A message that cannot be put on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// The encoded message would exceed the 4096 octets of RFC 4271.
    MessageTooLong {
        /// The length the message would have had, header included.
        length: usize,
    },
    /// A shutdown communication is limited to 255 octets of UTF-8 (RFC 9003).
    ShutdownCommunicationTooLong {
        /// The length of the rejected text in octets.
        length: usize,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::MessageTooLong { length } => {
                write!(formatter, "message of {length} octets exceeds the maximum")
            }
            EncodeError::ShutdownCommunicationTooLong { length } => write!(
                formatter,
                "shutdown communication of {length} octets exceeds 255"
            ),
        }
    }
}

impl std::error::Error for EncodeError {}
