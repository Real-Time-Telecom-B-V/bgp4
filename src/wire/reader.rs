//! A bounds-checked cursor that knows where in the message it stands.

use bytes::{Buf, Bytes};

/// Reads big-endian fields off a [`Bytes`] and tracks the offset from the
/// start of the message, so a decode error can say where it happened.
///
/// Every read returns `None` instead of panicking when too few octets remain.
#[derive(Debug)]
pub(crate) struct Reader {
    bytes: Bytes,
    offset: usize,
}

impl Reader {
    /// A reader over `bytes`, whose first octet sits at `offset` in the message.
    pub(crate) fn new(bytes: Bytes, offset: usize) -> Self {
        Self { bytes, offset }
    }

    /// Offset of the next unread octet, from the start of the message.
    pub(crate) fn offset(&self) -> usize {
        self.offset
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Everything not yet read, without consuming it.
    pub(crate) fn rest(&self) -> Bytes {
        self.bytes.clone()
    }

    /// The next `count` octets, without copying them.
    pub(crate) fn take(&mut self, count: usize) -> Option<Bytes> {
        if count > self.bytes.len() {
            return None;
        }
        self.offset += count;
        Some(self.bytes.split_to(count))
    }

    /// A reader over the next `count` octets that keeps counting offsets
    /// from the start of the message.
    pub(crate) fn sub_reader(&mut self, count: usize) -> Option<Reader> {
        let offset = self.offset;
        self.take(count).map(|bytes| Reader::new(bytes, offset))
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|mut bytes| bytes.get_u8())
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|mut bytes| bytes.get_u16())
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        self.take(4).map(|mut bytes| bytes.get_u32())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_fields_and_tracks_the_offset() {
        let mut reader = Reader::new(Bytes::from_static(&[1, 0, 2, 0, 0, 0, 3, 9, 9]), 19);
        assert_eq!(reader.u8(), Some(1));
        assert_eq!(reader.u16(), Some(2));
        assert_eq!(reader.u32(), Some(3));
        assert_eq!(reader.offset(), 26);
        assert_eq!(reader.remaining(), 2);
        let mut inner = reader.sub_reader(2).expect("two octets remain");
        assert_eq!(inner.offset(), 26);
        assert_eq!(inner.u8(), Some(9));
        assert_eq!(inner.offset(), 27);
        assert!(reader.is_empty());
        assert_eq!(reader.offset(), 28);
    }

    #[test]
    fn a_short_read_consumes_nothing() {
        let mut reader = Reader::new(Bytes::from_static(&[1, 2, 3]), 0);
        assert_eq!(reader.u32(), None);
        assert!(reader.take(4).is_none());
        assert!(reader.sub_reader(4).is_none());
        assert_eq!(reader.offset(), 0);
        assert_eq!(reader.u16(), Some(0x0102));
        assert_eq!(reader.u16(), None);
        assert_eq!(reader.u8(), Some(3));
        assert_eq!(reader.u8(), None);
    }
}
