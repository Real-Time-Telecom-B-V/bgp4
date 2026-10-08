//! One entry point for decoding whatever message arrives.

use bytes::Bytes;

use super::error::{DecodeError, DecodeErrorReason};
use super::header::{Header, MessageType, HEADER_LENGTH};
use super::keepalive::Keepalive;
use super::notification::Notification;
use super::open::Open;
use super::route_refresh::RouteRefresh;
use super::update::{DecodedUpdate, Update, UpdateContext};

/// A decoded message of any type.
///
/// This is the receive side only. To send, use the `encode` of the message
/// type itself.
// UPDATE is by far the largest variant and by far the most frequent message.
// Boxing it would put an allocation on the path that matters.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// OPEN.
    Open(Open),
    /// UPDATE, with what RFC 7606 had the decoder repair.
    Update(DecodedUpdate),
    /// NOTIFICATION.
    Notification(Notification),
    /// KEEPALIVE.
    Keepalive,
    /// ROUTE-REFRESH.
    RouteRefresh(RouteRefresh),
}

impl Message {
    /// Decode one whole message, header included.
    ///
    /// `frame` must hold exactly one message: use [`Header::decode`] on the
    /// read buffer to learn where it ends. `context` matters for UPDATE only.
    pub fn decode(frame: Bytes, context: UpdateContext) -> Result<Message, DecodeError> {
        let available = u16::try_from(frame.len()).unwrap_or(u16::MAX);
        let bad_length =
            |length: u16| DecodeError::new(DecodeErrorReason::BadMessageLength { length }, 16);
        let header = Header::decode(&frame)?.ok_or_else(|| bad_length(available))?;
        if usize::from(header.length()) != frame.len() {
            return Err(bad_length(header.length()));
        }
        let body = frame.slice(HEADER_LENGTH..);
        Ok(match header.message_type() {
            MessageType::Open => Message::Open(Open::decode(body)?),
            MessageType::Update => Message::Update(Update::decode(body, context)?),
            MessageType::Notification => Message::Notification(Notification::decode(body)?),
            MessageType::Keepalive => {
                Keepalive::decode(body)?;
                Message::Keepalive
            }
            MessageType::RouteRefresh => Message::RouteRefresh(RouteRefresh::decode(body)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;
    use crate::wire::SessionType;

    const CONTEXT: UpdateContext = UpdateContext::new(true, SessionType::External);

    #[test]
    fn a_keepalive() {
        let mut buffer = BytesMut::new();
        Keepalive.encode(&mut buffer);
        assert_eq!(
            Message::decode(buffer.freeze(), CONTEXT),
            Ok(Message::Keepalive)
        );
    }

    #[test]
    fn header_errors_come_through() {
        let mut bytes = vec![0xff; 16];
        bytes.extend_from_slice(&[0, 19, 9]);
        let error = Message::decode(Bytes::from(bytes), CONTEXT).expect_err("unknown type");
        assert_eq!(
            error.reason(),
            DecodeErrorReason::BadMessageType { message_type: 9 }
        );
    }

    #[test]
    fn a_frame_that_is_not_exactly_one_message_is_refused() {
        let mut buffer = BytesMut::new();
        Keepalive.encode(&mut buffer);
        Keepalive.encode(&mut buffer);
        let two = buffer.freeze();
        let error = Message::decode(two.clone(), CONTEXT).expect_err("two messages");
        assert_eq!(
            error.reason(),
            DecodeErrorReason::BadMessageLength { length: 19 }
        );
        let error = Message::decode(two.slice(..10), CONTEXT).expect_err("half a header");
        assert_eq!(
            error.reason(),
            DecodeErrorReason::BadMessageLength { length: 10 }
        );
    }
}
