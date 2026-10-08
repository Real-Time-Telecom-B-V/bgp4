//! The wire codec: BGP messages to and from bytes.
//!
//! Nothing in this module performs I/O or keeps state. Decoding never panics
//! on any input, and every [`DecodeError`] names the NOTIFICATION the session
//! has to send in reaction to it.

mod as_path;
mod attribute;
mod capability;
mod error;
mod header;
mod keepalive;
mod nlri;
mod notification;
mod open;
mod reader;
mod update;

pub use as_path::{AsPath, AsPathSegment, SegmentKind};
pub use attribute::{
    Aggregator, AttributeError, AttributeErrorAction, Origin, PathAttributes, UnknownAttribute,
};
pub use capability::{AddressFamily, Capability};
pub use error::{DecodeError, DecodeErrorReason, EncodeError};
pub use header::{Header, MessageType, HEADER_LENGTH, MAXIMUM_MESSAGE_LENGTH};
pub use keepalive::Keepalive;
pub use nlri::Ipv4Prefix;
pub use notification::{
    CeaseError, ErrorCode, FiniteStateMachineError, MessageHeaderError, Notification, OpenError,
    UpdateError,
};
pub use open::Open;
pub use update::{DecodedUpdate, Update, UpdateContext};
