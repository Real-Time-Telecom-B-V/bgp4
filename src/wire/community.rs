//! The three community attributes: standard (RFC 1997), extended (RFC 4360)
//! and large (RFC 8092).

use std::fmt;

/// A standard community (RFC 1997): 32 bits, by convention an AS number and
/// a value of 16 bits each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Community(pub u32);

impl Community {
    /// Routes carrying it must not leave the AS, or the confederation
    /// (RFC 1997).
    pub const NO_EXPORT: Community = Community(0xFFFF_FF01);
    /// Routes carrying it must not be advertised to any peer (RFC 1997).
    pub const NO_ADVERTISE: Community = Community(0xFFFF_FF02);
    /// Routes carrying it must not leave the member AS (RFC 1997).
    pub const NO_EXPORT_SUBCONFED: Community = Community(0xFFFF_FF03);
    /// Asks the receiver to move traffic away before the session closes
    /// (RFC 8326).
    pub const GRACEFUL_SHUTDOWN: Community = Community(0xFFFF_0000);
    /// Asks the receiver to discard traffic to the prefix (RFC 7999).
    pub const BLACKHOLE: Community = Community(0xFFFF_029A);

    /// The community `autonomous_system:value`.
    pub const fn new(autonomous_system: u16, value: u16) -> Self {
        // Widening casts: `From` is not usable in a const fn.
        Community(((autonomous_system as u32) << 16) | value as u32)
    }

    /// The high 16 bits.
    pub const fn autonomous_system(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// The low 16 bits.
    pub const fn value(self) -> u16 {
        (self.0 & 0xFFFF) as u16
    }
}

impl fmt::Display for Community {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.autonomous_system(), self.value())
    }
}

/// An extended community (RFC 4360): 8 octets, carried as they are. The crate
/// does not interpret them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExtendedCommunity(pub [u8; 8]);

/// A large community (RFC 8092): three 32-bit numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LargeCommunity {
    /// The Global Administrator, normally an AS number.
    pub global_administrator: u32,
    /// Local Data Part 1.
    pub local_data_1: u32,
    /// Local Data Part 2.
    pub local_data_2: u32,
}

impl fmt::Display for LargeCommunity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}",
            self.global_administrator, self.local_data_1, self.local_data_2
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_values() {
        // RFC 1997: 0xFFFFFF01 to 0xFFFFFF03. RFC 8326: 65535:0. RFC 7999: 65535:666.
        assert_eq!(Community::NO_EXPORT, Community::new(65535, 65281));
        assert_eq!(Community::NO_ADVERTISE, Community::new(65535, 65282));
        assert_eq!(Community::NO_EXPORT_SUBCONFED, Community::new(65535, 65283));
        assert_eq!(Community::GRACEFUL_SHUTDOWN, Community::new(65535, 0));
        assert_eq!(Community::BLACKHOLE, Community::new(65535, 666));
    }

    #[test]
    fn halves_and_display() {
        let community = Community::new(64496, 100);
        assert_eq!(community.0, 0xFBF0_0064);
        assert_eq!(community.autonomous_system(), 64496);
        assert_eq!(community.value(), 100);
        assert_eq!(community.to_string(), "64496:100");
        let large = LargeCommunity {
            global_administrator: 65550,
            local_data_1: 1,
            local_data_2: 2,
        };
        assert_eq!(large.to_string(), "65550:1:2");
    }
}
