//! Errors of the wire codec.

use std::fmt;

use bytes::Bytes;

use super::notification::{ErrorCode, MessageHeaderError, Notification, OpenError, UpdateError};

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
    /// An OPEN with a version other than 4.
    UnsupportedVersionNumber {
        /// The version octet as received.
        version: u8,
    },
    /// An OPEN proposing a hold time of 1 or 2 seconds.
    UnacceptableHoldTime {
        /// The hold time as received.
        hold_time: u16,
    },
    /// An OPEN with a BGP identifier of zero (RFC 6286).
    BadBgpIdentifier,
    /// An OPEN with an optional parameter other than capabilities.
    UnsupportedOptionalParameter {
        /// The parameter type as received.
        parameter_type: u8,
    },
    /// An OPEN whose optional parameters or capabilities cannot be parsed.
    MalformedOpen,
    /// An UPDATE whose Withdrawn Routes Length or Total Path Attribute Length
    /// does not fit the message, so its fields cannot be told apart.
    MalformedAttributeList,
    /// An UPDATE with a prefix that cannot be parsed.
    InvalidNetworkField,
    /// An UPDATE with a well-known attribute this crate does not recognise.
    UnrecognizedWellKnownAttribute {
        /// The attribute type code.
        type_code: u8,
    },
}

/// A message that could not be decoded, and what to tell the peer about it.
///
/// The codec does not log: it has no notion of which peer the bytes came from.
/// The caller logs this error together with the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    reason: DecodeErrorReason,
    offset: usize,
    data: Bytes,
}

impl DecodeError {
    pub(crate) fn new(reason: DecodeErrorReason, offset: usize) -> Self {
        Self::with_data(reason, offset, Bytes::new())
    }

    /// An error whose NOTIFICATION quotes part of the offending message.
    pub(crate) fn with_data(reason: DecodeErrorReason, offset: usize, data: Bytes) -> Self {
        Self {
            reason,
            offset,
            data,
        }
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
            // The data is the largest version this speaker supports, in 2 octets.
            DecodeErrorReason::UnsupportedVersionNumber { .. } => Notification::new(
                ErrorCode::Open(OpenError::UnsupportedVersionNumber),
                Bytes::from_static(&[0, 4]),
            ),
            DecodeErrorReason::UnacceptableHoldTime { .. } => Notification::new(
                ErrorCode::Open(OpenError::UnacceptableHoldTime),
                Bytes::new(),
            ),
            DecodeErrorReason::BadBgpIdentifier => {
                Notification::new(ErrorCode::Open(OpenError::BadBgpIdentifier), Bytes::new())
            }
            DecodeErrorReason::UnsupportedOptionalParameter { .. } => Notification::new(
                ErrorCode::Open(OpenError::UnsupportedOptionalParameter),
                Bytes::new(),
            ),
            // RFC 4271 section 6.2: a recognised but malformed optional
            // parameter is reported with subcode 0.
            DecodeErrorReason::MalformedOpen => {
                Notification::new(ErrorCode::Open(OpenError::Unspecific), Bytes::new())
            }
            DecodeErrorReason::MalformedAttributeList => Notification::new(
                ErrorCode::Update(UpdateError::MalformedAttributeList),
                Bytes::new(),
            ),
            DecodeErrorReason::InvalidNetworkField => Notification::new(
                ErrorCode::Update(UpdateError::InvalidNetworkField),
                Bytes::new(),
            ),
            // RFC 4271 section 6.3: the data is the unrecognised attribute.
            DecodeErrorReason::UnrecognizedWellKnownAttribute { .. } => Notification::new(
                ErrorCode::Update(UpdateError::UnrecognizedWellKnownAttribute),
                self.data.clone(),
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
            DecodeErrorReason::UnsupportedVersionNumber { version } => {
                write!(formatter, "unsupported version {version}")?
            }
            DecodeErrorReason::UnacceptableHoldTime { hold_time } => {
                write!(formatter, "unacceptable hold time {hold_time}")?
            }
            DecodeErrorReason::BadBgpIdentifier => write!(formatter, "bad BGP identifier")?,
            DecodeErrorReason::UnsupportedOptionalParameter { parameter_type } => {
                write!(formatter, "unsupported optional parameter {parameter_type}")?
            }
            DecodeErrorReason::MalformedOpen => write!(formatter, "malformed OPEN")?,
            DecodeErrorReason::MalformedAttributeList => {
                write!(formatter, "malformed attribute list")?
            }
            DecodeErrorReason::InvalidNetworkField => write!(formatter, "invalid network field")?,
            DecodeErrorReason::UnrecognizedWellKnownAttribute { type_code } => {
                write!(formatter, "unrecognized well-known attribute {type_code}")?
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
    /// A hold time of 1 or 2 seconds, which every receiver must reject.
    UnacceptableHoldTime {
        /// The rejected hold time.
        hold_time: u16,
    },
    /// A BGP identifier of zero, which every receiver must reject.
    ZeroBgpIdentifier,
    /// The capabilities do not fit in the 255 octets of optional parameters.
    OptionalParametersTooLong {
        /// The length the optional parameters would have had.
        length: usize,
    },
    /// The value of a capability is longer than 255 octets.
    CapabilityTooLong {
        /// The capability code.
        code: u8,
        /// The length of the rejected value.
        length: usize,
    },
    /// An AS path segment without AS numbers.
    EmptyAsPathSegment,
    /// An AS_SET or AS_CONFED_SET of more than 255 AS numbers.
    AsSetTooLong {
        /// The number of AS numbers in the set.
        length: usize,
    },
    /// An AS number above 65535 on a session without 4-octet AS numbers.
    AutonomousSystemNeedsFourOctets {
        /// The AS number that does not fit.
        autonomous_system: u32,
    },
    /// An UPDATE that announces a route without a mandatory attribute.
    MissingMandatoryAttribute {
        /// The type code of the absent attribute.
        type_code: u8,
    },
    /// An unknown attribute with a type code the crate interprets itself.
    AttributeTypeIsInterpreted {
        /// The type code.
        type_code: u8,
    },
    /// The same attribute type more than once.
    DuplicateAttribute {
        /// The type code.
        type_code: u8,
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
            EncodeError::UnacceptableHoldTime { hold_time } => {
                write!(formatter, "hold time of {hold_time} seconds is not allowed")
            }
            EncodeError::ZeroBgpIdentifier => write!(formatter, "BGP identifier is zero"),
            EncodeError::OptionalParametersTooLong { length } => write!(
                formatter,
                "optional parameters of {length} octets exceed 255"
            ),
            EncodeError::CapabilityTooLong { code, length } => write!(
                formatter,
                "capability {code} value of {length} octets exceeds 255"
            ),
            EncodeError::EmptyAsPathSegment => write!(formatter, "AS path segment is empty"),
            EncodeError::AsSetTooLong { length } => {
                write!(formatter, "AS set of {length} AS numbers exceeds 255")
            }
            EncodeError::AutonomousSystemNeedsFourOctets { autonomous_system } => write!(
                formatter,
                "AS {autonomous_system} needs a session with 4-octet AS numbers"
            ),
            EncodeError::MissingMandatoryAttribute { type_code } => write!(
                formatter,
                "announcement without mandatory attribute {type_code}"
            ),
            EncodeError::AttributeTypeIsInterpreted { type_code } => write!(
                formatter,
                "attribute {type_code} cannot be given as an unknown attribute"
            ),
            EncodeError::DuplicateAttribute { type_code } => {
                write!(formatter, "attribute {type_code} appears more than once")
            }
        }
    }
}

impl std::error::Error for EncodeError {}
