//! The wire codec: BGP messages to and from bytes.
//!
//! Nothing in this module performs I/O or keeps state. Decoding never panics
//! on any input, and every [`DecodeError`] names the NOTIFICATION the session
//! has to send in reaction to it.

mod capability;
mod error;
mod header;
mod keepalive;
mod notification;
mod open;
mod reader;

pub use capability::{AddressFamily, Capability};
pub use error::{DecodeError, DecodeErrorReason, EncodeError};
pub use header::{Header, MessageType, HEADER_LENGTH, MAXIMUM_MESSAGE_LENGTH};
pub use keepalive::Keepalive;
pub use notification::{
    CeaseError, ErrorCode, FiniteStateMachineError, MessageHeaderError, Notification, OpenError,
    UpdateError,
};
pub use open::Open;
