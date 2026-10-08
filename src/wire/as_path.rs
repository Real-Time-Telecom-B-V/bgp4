//! The AS_PATH attribute (RFC 4271 section 4.3, RFC 5065, RFC 6793).

use bytes::{BufMut, Bytes, BytesMut};

use super::error::EncodeError;
use super::reader::Reader;

/// A segment holds at most this many AS numbers: its count is one octet.
const MAXIMUM_SEGMENT_LENGTH: usize = 255;

/// The four kinds of path segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SegmentKind {
    /// AS_SET: an unordered set of AS numbers.
    Set,
    /// AS_SEQUENCE: an ordered list of AS numbers.
    Sequence,
    /// AS_CONFED_SEQUENCE: an ordered list of member AS numbers (RFC 5065).
    ConfederationSequence,
    /// AS_CONFED_SET: an unordered set of member AS numbers (RFC 5065).
    ConfederationSet,
}

impl SegmentKind {
    fn code(self) -> u8 {
        match self {
            SegmentKind::Set => 1,
            SegmentKind::Sequence => 2,
            SegmentKind::ConfederationSequence => 3,
            SegmentKind::ConfederationSet => 4,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(SegmentKind::Set),
            2 => Some(SegmentKind::Sequence),
            3 => Some(SegmentKind::ConfederationSequence),
            4 => Some(SegmentKind::ConfederationSet),
            _ => None,
        }
    }
}

/// One segment of an AS path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AsPathSegment {
    /// What kind of segment this is.
    pub kind: SegmentKind,
    /// The AS numbers, first on the wire first.
    pub autonomous_systems: Vec<u32>,
}

/// An AS path. An empty path is what a speaker sends for a route it
/// originates toward an internal peer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct AsPath {
    /// The segments, first on the wire first.
    pub segments: Vec<AsPathSegment>,
}

impl AsPath {
    /// A path of one AS_SEQUENCE, or an empty path when there are no AS
    /// numbers.
    pub fn sequence(autonomous_systems: impl IntoIterator<Item = u32>) -> Self {
        let autonomous_systems: Vec<u32> = autonomous_systems.into_iter().collect();
        if autonomous_systems.is_empty() {
            return Self::default();
        }
        Self {
            segments: vec![AsPathSegment {
                kind: SegmentKind::Sequence,
                autonomous_systems,
            }],
        }
    }

    /// Whether the path has an AS_CONFED_SEQUENCE or AS_CONFED_SET segment.
    pub fn has_confederation_segments(&self) -> bool {
        self.segments.iter().any(|segment| {
            matches!(
                segment.kind,
                SegmentKind::ConfederationSequence | SegmentKind::ConfederationSet
            )
        })
    }

    /// The length of the path as the decision process counts it (RFC 4271
    /// section 9.1.2.2, RFC 5065 section 5.3): one per AS in a sequence, one
    /// for a whole set, nothing for confederation segments.
    pub fn path_length(&self) -> usize {
        self.segments
            .iter()
            .map(|segment| match segment.kind {
                SegmentKind::Sequence => segment.autonomous_systems.len(),
                SegmentKind::Set => 1,
                SegmentKind::ConfederationSequence | SegmentKind::ConfederationSet => 0,
            })
            .sum()
    }

    /// Whether any AS number of the path needs more than 2 octets.
    pub(crate) fn needs_four_octets(&self) -> bool {
        self.segments
            .iter()
            .flat_map(|segment| &segment.autonomous_systems)
            .any(|autonomous_system| *autonomous_system > u32::from(u16::MAX))
    }

    /// The path without its confederation segments, which is what goes into
    /// AS4_PATH (RFC 6793 section 3).
    pub(crate) fn without_confederation_segments(&self) -> AsPath {
        AsPath {
            segments: self
                .segments
                .iter()
                .filter(|segment| matches!(segment.kind, SegmentKind::Sequence | SegmentKind::Set))
                .cloned()
                .collect(),
        }
    }

    /// Rebuild the real path from an AS_PATH received on a 2-octet session and
    /// the AS4_PATH that came with it (RFC 6793 section 4.2.3).
    ///
    /// The AS_PATH is as long as the AS4_PATH or longer, by the speakers that
    /// did not know AS4_PATH and prepended only to AS_PATH. Those leading AS
    /// numbers are kept and the AS4_PATH follows. An AS4_PATH that is longer
    /// than the AS_PATH is ignored.
    pub(crate) fn merged_with_as4_path(self, as4_path: AsPath) -> AsPath {
        // RFC 6793 section 6: confederation segments do not belong in
        // AS4_PATH and are dropped from it.
        let as4_path = as4_path.without_confederation_segments();
        let own = self.path_length();
        let wide = as4_path.path_length();
        if own < wide {
            return self;
        }
        let mut keep = own - wide;
        let mut segments: Vec<AsPathSegment> = Vec::new();
        for mut segment in self.segments {
            match segment.kind {
                SegmentKind::ConfederationSequence | SegmentKind::ConfederationSet => {}
                _ if keep == 0 => break,
                SegmentKind::Set => keep -= 1,
                SegmentKind::Sequence => {
                    segment.autonomous_systems.truncate(keep);
                    keep -= segment.autonomous_systems.len();
                }
            }
            segments.push(segment);
        }
        for segment in as4_path.segments {
            match segments.last_mut() {
                Some(last)
                    if last.kind == SegmentKind::Sequence
                        && segment.kind == SegmentKind::Sequence =>
                {
                    last.autonomous_systems.extend(segment.autonomous_systems)
                }
                _ => segments.push(segment),
            }
        }
        AsPath { segments }
    }

    /// Decode the attribute value. `None` when it is malformed: an unknown
    /// segment type, an empty segment, or a segment cut short (RFC 7606
    /// section 7.2).
    pub(crate) fn decode(value: Bytes, four_octet: bool) -> Option<AsPath> {
        let mut reader = Reader::new(value, 0);
        let mut segments = Vec::new();
        while !reader.is_empty() {
            let kind = SegmentKind::from_code(reader.u8()?)?;
            let count = reader.u8()?;
            if count == 0 {
                return None;
            }
            let mut autonomous_systems = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                autonomous_systems.push(if four_octet {
                    reader.u32()?
                } else {
                    u32::from(reader.u16()?)
                });
            }
            segments.push(AsPathSegment {
                kind,
                autonomous_systems,
            });
        }
        Some(AsPath { segments })
    }

    /// Append the attribute value.
    ///
    /// A sequence of more than 255 AS numbers is split over several segments.
    /// A set cannot be split without changing its meaning, so a larger one is
    /// an error, as is an empty segment.
    pub(crate) fn encode(
        &self,
        four_octet: bool,
        buffer: &mut BytesMut,
    ) -> Result<(), EncodeError> {
        for segment in &self.segments {
            if segment.autonomous_systems.is_empty() {
                return Err(EncodeError::EmptyAsPathSegment);
            }
            let ordered = matches!(
                segment.kind,
                SegmentKind::Sequence | SegmentKind::ConfederationSequence
            );
            if !ordered && segment.autonomous_systems.len() > MAXIMUM_SEGMENT_LENGTH {
                return Err(EncodeError::AsSetTooLong {
                    length: segment.autonomous_systems.len(),
                });
            }
            for chunk in segment.autonomous_systems.chunks(MAXIMUM_SEGMENT_LENGTH) {
                buffer.put_u8(segment.kind.code());
                // `chunks` never yields more than 255 elements.
                buffer.put_u8(u8::try_from(chunk.len()).unwrap_or(u8::MAX));
                for autonomous_system in chunk {
                    put_autonomous_system(*autonomous_system, four_octet, buffer);
                }
            }
        }
        Ok(())
    }
}

/// Stands in for an AS number that does not fit in 2 octets (RFC 6793).
pub(crate) const AS_TRANS: u16 = 23456;

/// Append one AS number in the width the session negotiated. On a 2-octet
/// session a number that does not fit is replaced by AS_TRANS.
pub(crate) fn put_autonomous_system(
    autonomous_system: u32,
    four_octet: bool,
    buffer: &mut BytesMut,
) {
    if four_octet {
        buffer.put_u32(autonomous_system);
    } else {
        buffer.put_u16(u16::try_from(autonomous_system).unwrap_or(AS_TRANS));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(bytes: &[u8], four_octet: bool) -> Option<AsPath> {
        AsPath::decode(Bytes::copy_from_slice(bytes), four_octet)
    }

    fn encode(path: &AsPath, four_octet: bool) -> Result<Vec<u8>, EncodeError> {
        let mut buffer = BytesMut::new();
        path.encode(four_octet, &mut buffer)?;
        Ok(buffer.to_vec())
    }

    #[test]
    fn an_empty_value_is_an_empty_path() {
        assert_eq!(decode(&[], true), Some(AsPath::default()));
        assert_eq!(encode(&AsPath::default(), true), Ok(Vec::new()));
        assert_eq!(AsPath::sequence([]), AsPath::default());
    }

    #[test]
    fn two_octet_and_four_octet_widths() {
        let path = AsPath::sequence([64496, 64497]);
        assert_eq!(encode(&path, false), Ok(vec![2, 2, 0xfb, 0xf0, 0xfb, 0xf1]));
        assert_eq!(
            encode(&path, true),
            Ok(vec![2, 2, 0, 0, 0xfb, 0xf0, 0, 0, 0xfb, 0xf1])
        );
        assert_eq!(
            decode(&[2, 2, 0xfb, 0xf0, 0xfb, 0xf1], false),
            Some(path.clone())
        );
        assert_eq!(
            decode(&[2, 2, 0, 0, 0xfb, 0xf0, 0, 0, 0xfb, 0xf1], true),
            Some(path)
        );
    }

    #[test]
    fn every_segment_kind() {
        let wire = [
            3, 1, 0xfb, 0xf4, 4, 1, 0xfb, 0xf5, 2, 1, 0xfb, 0xf0, 1, 1, 0xfb, 0xf1,
        ];
        let path = decode(&wire, false).expect("valid");
        let kinds: Vec<SegmentKind> = path.segments.iter().map(|segment| segment.kind).collect();
        assert_eq!(
            kinds,
            [
                SegmentKind::ConfederationSequence,
                SegmentKind::ConfederationSet,
                SegmentKind::Sequence,
                SegmentKind::Set
            ]
        );
        assert_eq!(encode(&path, false), Ok(wire.to_vec()));
    }

    #[test]
    fn malformed_values() {
        // Unknown segment type.
        assert_eq!(decode(&[0, 1, 0xfb, 0xf0], false), None);
        assert_eq!(decode(&[5, 1, 0xfb, 0xf0], false), None);
        // Segment of zero AS numbers.
        assert_eq!(decode(&[2, 0], false), None);
        // Segment cut short.
        assert_eq!(decode(&[2, 2, 0xfb, 0xf0], false), None);
        assert_eq!(decode(&[2, 1, 0, 0, 0xfb], true), None);
        // Segment header cut short.
        assert_eq!(decode(&[2], false), None);
        // A 2-octet path read as 4 octets does not line up.
        assert_eq!(decode(&[2, 1, 0xfb, 0xf0], true), None);
    }

    #[test]
    fn a_long_sequence_is_split_and_a_long_set_is_refused() {
        let long = AsPath::sequence(std::iter::repeat_n(64496, 256));
        let wire = encode(&long, false).expect("split");
        assert_eq!(wire.len(), 2 + 255 * 2 + 2 + 2);
        assert_eq!(&wire[..2], [2, 255]);
        assert_eq!(&wire[2 + 255 * 2..2 + 255 * 2 + 2], [2, 1]);

        let set = AsPath {
            segments: vec![AsPathSegment {
                kind: SegmentKind::Set,
                autonomous_systems: vec![64496; 256],
            }],
        };
        assert_eq!(
            encode(&set, false),
            Err(EncodeError::AsSetTooLong { length: 256 })
        );
    }

    #[test]
    fn an_empty_segment_is_refused() {
        let path = AsPath {
            segments: vec![AsPathSegment {
                kind: SegmentKind::Sequence,
                autonomous_systems: Vec::new(),
            }],
        };
        assert_eq!(encode(&path, true), Err(EncodeError::EmptyAsPathSegment));
    }

    #[test]
    fn a_four_octet_as_number_becomes_as_trans_on_a_two_octet_session() {
        assert_eq!(
            encode(&AsPath::sequence([64496, 65550]), false),
            Ok(vec![2, 2, 0xfb, 0xf0, 0x5b, 0xa0])
        );
        assert!(AsPath::sequence([64496, 65550]).needs_four_octets());
        assert!(!AsPath::sequence([64496, 65535]).needs_four_octets());
    }

    fn segment(kind: SegmentKind, autonomous_systems: &[u32]) -> AsPathSegment {
        AsPathSegment {
            kind,
            autonomous_systems: autonomous_systems.to_vec(),
        }
    }

    #[test]
    fn path_length_counts_a_set_once_and_confederation_segments_not_at_all() {
        let path = AsPath {
            segments: vec![
                segment(SegmentKind::ConfederationSequence, &[64500, 64501]),
                segment(SegmentKind::ConfederationSet, &[64502]),
                segment(SegmentKind::Sequence, &[64496, 64497, 64498]),
                segment(SegmentKind::Set, &[64499, 64503]),
            ],
        };
        assert_eq!(path.path_length(), 4);
        assert_eq!(AsPath::default().path_length(), 0);
    }

    #[test]
    fn merging_an_as4_path_of_the_same_length_replaces_the_path() {
        let merged = AsPath::sequence([64496, 23456, 64497])
            .merged_with_as4_path(AsPath::sequence([64496, 65550, 64497]));
        assert_eq!(merged, AsPath::sequence([64496, 65550, 64497]));
    }

    #[test]
    fn merging_keeps_what_old_speakers_prepended() {
        // Two speakers without AS4_PATH support prepended 64510 and 64511.
        let merged = AsPath::sequence([64511, 64510, 23456, 64497])
            .merged_with_as4_path(AsPath::sequence([65550, 64497]));
        assert_eq!(merged, AsPath::sequence([64511, 64510, 65550, 64497]));
    }

    #[test]
    fn an_as4_path_longer_than_the_path_is_ignored() {
        let path = AsPath::sequence([23456, 64497]);
        let merged = path
            .clone()
            .merged_with_as4_path(AsPath::sequence([65551, 65550, 64497]));
        assert_eq!(merged, path);
    }

    #[test]
    fn merging_keeps_leading_confederation_segments_and_counts_sets_once() {
        let path = AsPath {
            segments: vec![
                segment(SegmentKind::ConfederationSequence, &[64500]),
                segment(SegmentKind::Sequence, &[64511, 23456]),
                segment(SegmentKind::Set, &[23456, 64497]),
            ],
        };
        // The AS4_PATH covers the last AS of the sequence and the set, and
        // wrongly carries a confederation segment of its own.
        let as4_path = AsPath {
            segments: vec![
                segment(SegmentKind::ConfederationSequence, &[64509]),
                segment(SegmentKind::Sequence, &[65550]),
                segment(SegmentKind::Set, &[65551, 64497]),
            ],
        };
        assert_eq!(
            path.merged_with_as4_path(as4_path),
            AsPath {
                segments: vec![
                    segment(SegmentKind::ConfederationSequence, &[64500]),
                    segment(SegmentKind::Sequence, &[64511, 65550]),
                    segment(SegmentKind::Set, &[65551, 64497]),
                ],
            }
        );
    }
}
