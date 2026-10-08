//! NOTIFICATION (RFC 4271 section 4.5) and its error codes.

use bytes::{BufMut, Bytes, BytesMut};

use super::error::{DecodeError, DecodeErrorReason, EncodeError};
use super::header::{Header, MessageType, HEADER_LENGTH};

/// Defines the subcodes of one error code. Subcode 0 is `Unspecific`, and a
/// value this crate has no name for is kept in `Other`.
macro_rules! subcodes {
    (
        $(#[$documentation:meta])*
        $name:ident { $($(#[$variant_documentation:meta])* $variant:ident = $value:literal,)* }
    ) => {
        $(#[$documentation])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $name {
            /// Subcode 0: no more specific subcode applies.
            Unspecific,
            $($(#[$variant_documentation])* $variant,)*
            /// A subcode this crate has no name for.
            Other(u8),
        }

        impl $name {
            /// The value of the subcode octet.
            pub fn subcode(self) -> u8 {
                match self {
                    $name::Unspecific => 0,
                    $($name::$variant => $value,)*
                    $name::Other(subcode) => subcode,
                }
            }

            fn from_subcode(subcode: u8) -> Self {
                match subcode {
                    0 => $name::Unspecific,
                    $($value => $name::$variant,)*
                    other => $name::Other(other),
                }
            }
        }
    };
}

subcodes! {
    /// Message Header Error subcodes (RFC 4271 section 6.1).
    MessageHeaderError {
        /// The marker is not all ones.
        ConnectionNotSynchronized = 1,
        /// The length field is out of bounds for the message type.
        BadMessageLength = 2,
        /// The type field is not recognised.
        BadMessageType = 3,
    }
}

subcodes! {
    /// OPEN Message Error subcodes (RFC 4271 section 6.2, RFC 5492, RFC 9234).
    OpenError {
        /// The version is not supported.
        UnsupportedVersionNumber = 1,
        /// The autonomous system number is not the expected one.
        BadPeerAs = 2,
        /// The BGP identifier is not acceptable.
        BadBgpIdentifier = 3,
        /// An optional parameter is not recognised.
        UnsupportedOptionalParameter = 4,
        /// The proposed hold time is not acceptable.
        UnacceptableHoldTime = 6,
        /// A required capability is missing from the peer's OPEN (RFC 5492).
        UnsupportedCapability = 7,
        /// The roles of the two speakers do not match (RFC 9234).
        RoleMismatch = 11,
    }
}

subcodes! {
    /// UPDATE Message Error subcodes (RFC 4271 section 6.3).
    UpdateError {
        /// The attribute list as a whole cannot be parsed.
        MalformedAttributeList = 1,
        /// A well-known attribute is not recognised.
        UnrecognizedWellKnownAttribute = 2,
        /// A mandatory well-known attribute is absent.
        MissingWellKnownAttribute = 3,
        /// The flags of an attribute conflict with its type.
        AttributeFlagsError = 4,
        /// The length of an attribute conflicts with its type.
        AttributeLengthError = 5,
        /// ORIGIN has an undefined value.
        InvalidOriginAttribute = 6,
        /// NEXT_HOP is not a valid address.
        InvalidNextHopAttribute = 8,
        /// An optional attribute is recognised but its value is wrong.
        OptionalAttributeError = 9,
        /// An NLRI field is syntactically incorrect.
        InvalidNetworkField = 10,
        /// AS_PATH is syntactically incorrect.
        MalformedAsPath = 11,
    }
}

subcodes! {
    /// Finite State Machine Error subcodes (RFC 6608).
    FiniteStateMachineError {
        /// An unexpected message arrived in the OpenSent state.
        UnexpectedMessageInOpenSent = 1,
        /// An unexpected message arrived in the OpenConfirm state.
        UnexpectedMessageInOpenConfirm = 2,
        /// An unexpected message arrived in the Established state.
        UnexpectedMessageInEstablished = 3,
    }
}

subcodes! {
    /// Cease subcodes (RFC 4486, RFC 8538).
    CeaseError {
        /// The peer sent more prefixes than configured.
        MaximumNumberOfPrefixesReached = 1,
        /// The session is shut down administratively.
        AdministrativeShutdown = 2,
        /// The peer was removed from the configuration.
        PeerDeconfigured = 3,
        /// The session is reset administratively.
        AdministrativeReset = 4,
        /// The connection is rejected after it was accepted.
        ConnectionRejected = 5,
        /// Another configuration change requires the session to close.
        OtherConfigurationChange = 6,
        /// This connection lost collision resolution.
        ConnectionCollisionResolution = 7,
        /// The speaker ran out of resources.
        OutOfResources = 8,
        /// The session must not be held up by graceful restart (RFC 8538).
        HardReset = 9,
    }
}

/// The error code and subcode of a NOTIFICATION.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// Code 1.
    MessageHeader(MessageHeaderError),
    /// Code 2.
    Open(OpenError),
    /// Code 3.
    Update(UpdateError),
    /// Code 4. It has no subcodes.
    HoldTimerExpired,
    /// Code 5.
    FiniteStateMachine(FiniteStateMachineError),
    /// Code 6.
    Cease(CeaseError),
    /// A code this crate has no name for.
    Other {
        /// The error code octet.
        code: u8,
        /// The error subcode octet.
        subcode: u8,
    },
}

impl ErrorCode {
    /// The error code octet and the error subcode octet.
    pub fn code_and_subcode(self) -> (u8, u8) {
        match self {
            ErrorCode::MessageHeader(subcode) => (1, subcode.subcode()),
            ErrorCode::Open(subcode) => (2, subcode.subcode()),
            ErrorCode::Update(subcode) => (3, subcode.subcode()),
            ErrorCode::HoldTimerExpired => (4, 0),
            ErrorCode::FiniteStateMachine(subcode) => (5, subcode.subcode()),
            ErrorCode::Cease(subcode) => (6, subcode.subcode()),
            ErrorCode::Other { code, subcode } => (code, subcode),
        }
    }

    fn from_code_and_subcode(code: u8, subcode: u8) -> Self {
        match code {
            1 => ErrorCode::MessageHeader(MessageHeaderError::from_subcode(subcode)),
            2 => ErrorCode::Open(OpenError::from_subcode(subcode)),
            3 => ErrorCode::Update(UpdateError::from_subcode(subcode)),
            4 => ErrorCode::HoldTimerExpired,
            5 => ErrorCode::FiniteStateMachine(FiniteStateMachineError::from_subcode(subcode)),
            6 => ErrorCode::Cease(CeaseError::from_subcode(subcode)),
            _ => ErrorCode::Other { code, subcode },
        }
    }
}

/// Longest shutdown communication RFC 9003 allows, in octets.
const MAXIMUM_SHUTDOWN_COMMUNICATION_LENGTH: usize = 255;

/// A NOTIFICATION message.
///
/// The code and subcode octets are kept exactly as they were on the wire, so a
/// notification from a peer that uses values unknown to this crate is still
/// reported faithfully. [`Notification::error`] gives the typed view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    code: u8,
    subcode: u8,
    data: Bytes,
}

impl Notification {
    /// A notification with the given error and diagnostic data.
    pub fn new(error: ErrorCode, data: Bytes) -> Self {
        let (code, subcode) = error.code_and_subcode();
        Self {
            code,
            subcode,
            data,
        }
    }

    /// Cease / Administrative Shutdown, with a shutdown communication for the
    /// peer's operator (RFC 9003). An empty text sends no data at all.
    pub fn administrative_shutdown(communication: &str) -> Result<Self, EncodeError> {
        Self::cease_with_communication(CeaseError::AdministrativeShutdown, communication)
    }

    /// Cease / Administrative Reset, with a shutdown communication for the
    /// peer's operator (RFC 9003). An empty text sends no data at all.
    pub fn administrative_reset(communication: &str) -> Result<Self, EncodeError> {
        Self::cease_with_communication(CeaseError::AdministrativeReset, communication)
    }

    fn cease_with_communication(
        subcode: CeaseError,
        communication: &str,
    ) -> Result<Self, EncodeError> {
        let too_long = EncodeError::ShutdownCommunicationTooLong {
            length: communication.len(),
        };
        if communication.len() > MAXIMUM_SHUTDOWN_COMMUNICATION_LENGTH {
            return Err(too_long);
        }
        let length = u8::try_from(communication.len()).map_err(|_| too_long)?;
        let mut data = BytesMut::new();
        if length > 0 {
            data.put_u8(length);
            data.put_slice(communication.as_bytes());
        }
        Ok(Self::new(ErrorCode::Cease(subcode), data.freeze()))
    }

    /// The typed error code and subcode.
    pub fn error(&self) -> ErrorCode {
        ErrorCode::from_code_and_subcode(self.code, self.subcode)
    }

    /// The error code octet as it was on the wire.
    pub fn code(&self) -> u8 {
        self.code
    }

    /// The error subcode octet as it was on the wire.
    pub fn subcode(&self) -> u8 {
        self.subcode
    }

    /// The diagnostic data.
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// The shutdown communication of an Administrative Shutdown or
    /// Administrative Reset (RFC 9003).
    ///
    /// `None` when the notification is of another kind, carries no text, or
    /// carries one that is not well formed. RFC 9003 section 2 says a
    /// malformed communication is not an error of the session, so it is
    /// simply not reported here; the raw octets remain in [`Notification::data`].
    pub fn shutdown_communication(&self) -> Option<&str> {
        match self.error() {
            ErrorCode::Cease(
                CeaseError::AdministrativeShutdown | CeaseError::AdministrativeReset,
            ) => {}
            _ => return None,
        }
        let (length, text) = self.data.split_first()?;
        if usize::from(*length) != text.len() || text.is_empty() {
            return None;
        }
        std::str::from_utf8(text).ok()
    }

    /// Decode the body of a NOTIFICATION, that is, what follows the header.
    pub fn decode(mut body: Bytes) -> Result<Notification, DecodeError> {
        if body.len() < 2 {
            let length = u16::try_from(HEADER_LENGTH + body.len()).unwrap_or(u16::MAX);
            return Err(DecodeError::new(
                DecodeErrorReason::BadMessageLength { length },
                16,
            ));
        }
        let data = body.split_off(2);
        Ok(Notification {
            code: body[0],
            subcode: body[1],
            data,
        })
    }

    /// Append the whole message, header included, to `buffer`.
    ///
    /// Nothing is written when the message would be too long.
    pub fn encode(&self, buffer: &mut BytesMut) -> Result<(), EncodeError> {
        Header::encode(MessageType::Notification, 2 + self.data.len(), buffer)?;
        buffer.put_u8(self.code);
        buffer.put_u8(self.subcode);
        buffer.put_slice(&self.data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(body: &[u8]) -> Notification {
        Notification::decode(Bytes::copy_from_slice(body)).expect("decode")
    }

    #[test]
    fn every_named_subcode_maps_to_its_rfc_value() {
        let cases = [
            (
                ErrorCode::MessageHeader(MessageHeaderError::Unspecific),
                (1, 0),
            ),
            (
                ErrorCode::MessageHeader(MessageHeaderError::ConnectionNotSynchronized),
                (1, 1),
            ),
            (
                ErrorCode::MessageHeader(MessageHeaderError::BadMessageLength),
                (1, 2),
            ),
            (
                ErrorCode::MessageHeader(MessageHeaderError::BadMessageType),
                (1, 3),
            ),
            (ErrorCode::Open(OpenError::UnsupportedVersionNumber), (2, 1)),
            (ErrorCode::Open(OpenError::BadPeerAs), (2, 2)),
            (ErrorCode::Open(OpenError::BadBgpIdentifier), (2, 3)),
            (
                ErrorCode::Open(OpenError::UnsupportedOptionalParameter),
                (2, 4),
            ),
            (ErrorCode::Open(OpenError::UnacceptableHoldTime), (2, 6)),
            (ErrorCode::Open(OpenError::UnsupportedCapability), (2, 7)),
            (ErrorCode::Open(OpenError::RoleMismatch), (2, 11)),
            (
                ErrorCode::Update(UpdateError::MalformedAttributeList),
                (3, 1),
            ),
            (
                ErrorCode::Update(UpdateError::UnrecognizedWellKnownAttribute),
                (3, 2),
            ),
            (
                ErrorCode::Update(UpdateError::MissingWellKnownAttribute),
                (3, 3),
            ),
            (ErrorCode::Update(UpdateError::AttributeFlagsError), (3, 4)),
            (ErrorCode::Update(UpdateError::AttributeLengthError), (3, 5)),
            (
                ErrorCode::Update(UpdateError::InvalidOriginAttribute),
                (3, 6),
            ),
            (
                ErrorCode::Update(UpdateError::InvalidNextHopAttribute),
                (3, 8),
            ),
            (
                ErrorCode::Update(UpdateError::OptionalAttributeError),
                (3, 9),
            ),
            (ErrorCode::Update(UpdateError::InvalidNetworkField), (3, 10)),
            (ErrorCode::Update(UpdateError::MalformedAsPath), (3, 11)),
            (ErrorCode::HoldTimerExpired, (4, 0)),
            (
                ErrorCode::FiniteStateMachine(FiniteStateMachineError::UnexpectedMessageInOpenSent),
                (5, 1),
            ),
            (
                ErrorCode::FiniteStateMachine(
                    FiniteStateMachineError::UnexpectedMessageInOpenConfirm,
                ),
                (5, 2),
            ),
            (
                ErrorCode::FiniteStateMachine(
                    FiniteStateMachineError::UnexpectedMessageInEstablished,
                ),
                (5, 3),
            ),
            (
                ErrorCode::Cease(CeaseError::MaximumNumberOfPrefixesReached),
                (6, 1),
            ),
            (ErrorCode::Cease(CeaseError::AdministrativeShutdown), (6, 2)),
            (ErrorCode::Cease(CeaseError::PeerDeconfigured), (6, 3)),
            (ErrorCode::Cease(CeaseError::AdministrativeReset), (6, 4)),
            (ErrorCode::Cease(CeaseError::ConnectionRejected), (6, 5)),
            (
                ErrorCode::Cease(CeaseError::OtherConfigurationChange),
                (6, 6),
            ),
            (
                ErrorCode::Cease(CeaseError::ConnectionCollisionResolution),
                (6, 7),
            ),
            (ErrorCode::Cease(CeaseError::OutOfResources), (6, 8)),
            (ErrorCode::Cease(CeaseError::HardReset), (6, 9)),
        ];
        for (error, (code, subcode)) in cases {
            assert_eq!(error.code_and_subcode(), (code, subcode), "{error:?}");
            assert_eq!(decode(&[code, subcode]).error(), error, "{code}/{subcode}");
        }
    }

    #[test]
    fn unknown_code_and_subcode_are_kept_as_received() {
        let unknown_code = decode(&[200, 7, 0xde, 0xad]);
        assert_eq!(
            unknown_code.error(),
            ErrorCode::Other {
                code: 200,
                subcode: 7
            }
        );
        assert_eq!(unknown_code.data().as_ref(), [0xde, 0xad]);

        let unknown_subcode = decode(&[6, 200]);
        assert_eq!(
            unknown_subcode.error(),
            ErrorCode::Cease(CeaseError::Other(200))
        );

        // Hold Timer Expired has no subcodes, but a peer may still send one.
        let hold_timer = decode(&[4, 9]);
        assert_eq!(hold_timer.error(), ErrorCode::HoldTimerExpired);
        assert_eq!(hold_timer.subcode(), 9);
    }

    #[test]
    fn a_body_without_code_and_subcode_is_a_bad_message_length() {
        for (body, length) in [(&[][..], 19), (&[6][..], 20)] {
            let error = Notification::decode(Bytes::copy_from_slice(body)).expect_err("too short");
            assert_eq!(
                error.reason(),
                DecodeErrorReason::BadMessageLength { length }
            );
            assert_eq!(error.offset(), 16);
        }
    }

    #[test]
    fn data_at_the_maximum_fits_and_one_more_octet_does_not() {
        let largest = Notification::new(ErrorCode::HoldTimerExpired, Bytes::from(vec![0; 4075]));
        let mut buffer = BytesMut::new();
        assert_eq!(largest.encode(&mut buffer), Ok(()));
        assert_eq!(buffer.len(), 4096);

        let too_large = Notification::new(ErrorCode::HoldTimerExpired, Bytes::from(vec![0; 4076]));
        let mut buffer = BytesMut::new();
        assert_eq!(
            too_large.encode(&mut buffer),
            Err(EncodeError::MessageTooLong { length: 4097 })
        );
        assert!(buffer.is_empty());
    }

    #[test]
    fn shutdown_communication_length_limits() {
        let longest = "x".repeat(255);
        let notification = Notification::administrative_shutdown(&longest).expect("255 fits");
        assert_eq!(notification.data().len(), 256);
        assert_eq!(
            notification.shutdown_communication(),
            Some(longest.as_str())
        );

        assert_eq!(
            Notification::administrative_reset(&"x".repeat(256)),
            Err(EncodeError::ShutdownCommunicationTooLong { length: 256 })
        );
    }

    #[test]
    fn empty_shutdown_communication_sends_no_data() {
        let notification = Notification::administrative_shutdown("").expect("empty fits");
        assert!(notification.data().is_empty());
        assert_eq!(notification.shutdown_communication(), None);
    }

    #[test]
    fn malformed_shutdown_communication_is_not_reported() {
        // Length octet says 5, three octets follow.
        assert_eq!(
            decode(&[6, 2, 5, b'a', b'b', b'c']).shutdown_communication(),
            None
        );
        // Zero length: no communication follows.
        assert_eq!(decode(&[6, 2, 0]).shutdown_communication(), None);
        // Not UTF-8.
        assert_eq!(
            decode(&[6, 4, 2, 0xff, 0xfe]).shutdown_communication(),
            None
        );
        // Well formed, but not a subcode that carries a communication.
        assert_eq!(
            decode(&[6, 3, 2, b'o', b'k']).shutdown_communication(),
            None
        );
    }
}
