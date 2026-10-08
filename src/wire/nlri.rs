//! IPv4 prefixes as they appear in the Withdrawn Routes and NLRI fields
//! (RFC 4271 section 4.3).

use std::fmt;
use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};

use super::reader::Reader;

/// An IPv4 prefix. Bits past the prefix length are always zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4Prefix {
    address: Ipv4Addr,
    length: u8,
}

impl Ipv4Prefix {
    /// A prefix of `length` bits. Bits of `address` past the length are
    /// cleared. `None` when the length exceeds 32.
    pub fn new(address: Ipv4Addr, length: u8) -> Option<Self> {
        if length > 32 {
            return None;
        }
        let mask = u32::MAX.checked_shl(32 - u32::from(length)).unwrap_or(0);
        Some(Self {
            address: Ipv4Addr::from(u32::from(address) & mask),
            length,
        })
    }

    /// The network address.
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// The prefix length in bits.
    pub fn length(&self) -> u8 {
        self.length
    }

    /// Octets needed to carry a prefix of `length` bits.
    fn octets(length: u8) -> usize {
        usize::from(length).div_ceil(8)
    }

    /// Append the prefix as a length octet and the minimum number of octets.
    pub(crate) fn encode(&self, buffer: &mut BytesMut) {
        buffer.put_u8(self.length);
        buffer.put_slice(&self.address.octets()[..Self::octets(self.length)]);
    }

    /// Decode prefixes until the reader is exhausted.
    ///
    /// On a length above 32 or a prefix cut short, returns the offset of the
    /// length octet at fault.
    pub(crate) fn decode_all(reader: &mut Reader) -> Result<Vec<Ipv4Prefix>, usize> {
        let mut prefixes = Vec::new();
        while !reader.is_empty() {
            let offset = reader.offset();
            let length = reader.u8().ok_or(offset)?;
            if length > 32 {
                return Err(offset);
            }
            let present = reader.take(Self::octets(length)).ok_or(offset)?;
            let mut octets = [0u8; 4];
            octets[..present.len()].copy_from_slice(&present);
            prefixes.push(Ipv4Prefix::new(Ipv4Addr::from(octets), length).ok_or(offset)?);
        }
        Ok(prefixes)
    }
}

impl fmt::Display for Ipv4Prefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.address, self.length)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn decode(bytes: &[u8]) -> Result<Vec<Ipv4Prefix>, usize> {
        Ipv4Prefix::decode_all(&mut Reader::new(Bytes::copy_from_slice(bytes), 100))
    }

    fn prefix(a: u8, b: u8, c: u8, d: u8, length: u8) -> Ipv4Prefix {
        Ipv4Prefix::new(Ipv4Addr::new(a, b, c, d), length).expect("valid")
    }

    #[test]
    fn host_bits_are_cleared() {
        assert_eq!(prefix(198, 51, 100, 77, 24), prefix(198, 51, 100, 0, 24));
        assert_eq!(prefix(198, 51, 100, 77, 0), prefix(0, 0, 0, 0, 0));
        assert_eq!(
            prefix(198, 51, 100, 77, 32).address(),
            Ipv4Addr::new(198, 51, 100, 77)
        );
        assert_eq!(
            prefix(198, 51, 100, 255, 25).address(),
            Ipv4Addr::new(198, 51, 100, 128)
        );
        assert_eq!(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 33), None);
    }

    #[test]
    fn each_length_uses_the_minimum_number_of_octets() {
        // The examples follow RFC 4271 section 4.3: length in bits, then
        // only as many octets as the length needs.
        let cases: [(Ipv4Prefix, &[u8]); 6] = [
            (prefix(0, 0, 0, 0, 0), &[0]),
            (prefix(192, 0, 0, 0, 8), &[8, 192]),
            (prefix(192, 0, 0, 0, 9), &[9, 192, 0]),
            (prefix(198, 51, 100, 0, 24), &[24, 198, 51, 100]),
            (prefix(198, 51, 100, 128, 25), &[25, 198, 51, 100, 128]),
            (prefix(198, 51, 100, 7, 32), &[32, 198, 51, 100, 7]),
        ];
        for (prefix, wire) in cases {
            let mut buffer = BytesMut::new();
            prefix.encode(&mut buffer);
            assert_eq!(buffer.as_ref(), wire, "{prefix}");
            assert_eq!(decode(wire), Ok(vec![prefix]), "{prefix}");
        }
    }

    #[test]
    fn several_prefixes_in_a_row() {
        assert_eq!(
            decode(&[24, 198, 51, 100, 0, 16, 203, 0]),
            Ok(vec![
                prefix(198, 51, 100, 0, 24),
                prefix(0, 0, 0, 0, 0),
                prefix(203, 0, 0, 0, 16)
            ])
        );
    }

    #[test]
    fn trailing_bits_set_by_the_peer_are_ignored() {
        assert_eq!(
            decode(&[20, 198, 51, 0xff]),
            Ok(vec![prefix(198, 51, 240, 0, 20)])
        );
    }

    #[test]
    fn a_length_above_32_or_a_short_prefix_reports_the_length_octet() {
        assert_eq!(decode(&[33, 1, 2, 3, 4, 5]), Err(100));
        assert_eq!(decode(&[24, 198, 51]), Err(100));
        assert_eq!(decode(&[8, 10, 24, 198]), Err(102));
    }

    #[test]
    fn displays_in_the_usual_notation() {
        assert_eq!(prefix(198, 51, 100, 0, 24).to_string(), "198.51.100.0/24");
    }
}
