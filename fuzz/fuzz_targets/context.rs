//! Shared by the targets that decode UPDATE messages.

use bgp4::wire::{SessionType, UpdateContext};

/// Every combination of AS number width and session type, picked by the low
/// bits of one input octet so the fuzzer explores all six.
pub fn context(selector: u8) -> UpdateContext {
    let session_type = match (selector >> 1) % 3 {
        0 => SessionType::Internal,
        1 => SessionType::ConfederationExternal,
        _ => SessionType::External,
    };
    UpdateContext::new(selector & 1 == 1, session_type)
}
