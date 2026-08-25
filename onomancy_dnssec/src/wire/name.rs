//! Canonical DNS owner names.
//!
//! ```text
//! wire:  3 w w w  6 e x p e d e  3 w t f  0
//!        └┬┘└─┬─┘ └┬┘└───┬────┘ └┬┘└─┬─┘ └┴─ root
//!         │  label │   label     │  label
//!         └ length └ length      └ length
//! ```
//!
//! Canonical form (RFC 4034 §6.2): **uncompressed** (no `0xC0`
//! pointers — a pointer in signed data would make the signature target
//! ambiguous) and **lowercase** ASCII letters. Both are enforced at
//! parse: reject, never normalize.

use alloc::vec::Vec;
use core::{cmp::Ordering, fmt, str::FromStr};

use onomancy_core::{
    name::dns::DnsName,
    wire::{Reader, WireError},
};

/// Maximum total length of a name on the wire (labels + lengths +
/// root), per RFC 1035 §3.1.
pub const MAX_WIRE_LEN: usize = 255;

/// Maximum length of a single label.
pub const MAX_LABEL_LEN: usize = 63;

/// The wire tag bits marking a compression pointer (never canonical).
const POINTER_MASK: u8 = 0b1100_0000;

/// The service label every Onomancy DNS record lives under.
const SERVICE_LABEL: &[u8] = b"_onomancy";

/// A canonical (uncompressed, lowercase) DNS owner name.
///
/// Labels are raw octet strings — DNS labels are binary-safe, and
/// underscore service labels are ordinary here even though hostname
/// grammar (`DnsName`) would reject them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Name {
    labels: Vec<Vec<u8>>,
}

impl Name {
    /// Read one canonical wire-form name.
    ///
    /// # Errors
    ///
    /// Returns [`ParseNameError`] on compression pointers, uppercase
    /// ASCII (canonical form is lowercase — reject, never normalize),
    /// overlong labels or names, or truncation.
    pub fn read(reader: &mut Reader<'_>) -> Result<Self, ParseNameError> {
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut wire_len = 1; // the root byte

        loop {
            let [len] = reader.take_array::<1>()?;

            if len == 0 {
                return Ok(Self { labels });
            }

            if len & POINTER_MASK != 0 {
                // 0b11: compression pointer; 0b01/0b10: reserved.
                return Err(ParseNameError::NotCanonical {
                    reason: "compression pointer or reserved label type",
                });
            }

            if usize::from(len) > MAX_LABEL_LEN {
                return Err(ParseNameError::LabelTooLong { len });
            }

            wire_len += 1 + usize::from(len);
            if wire_len > MAX_WIRE_LEN {
                return Err(ParseNameError::NameTooLong);
            }

            let label = reader.take(usize::from(len))?;

            if label.iter().any(u8::is_ascii_uppercase) {
                return Err(ParseNameError::NotCanonical {
                    reason: "uppercase ASCII in canonical form",
                });
            }

            labels.push(label.to_vec());
        }
    }

    /// The `_onomancy.<hostname>` owner name a binding lives under.
    #[must_use]
    pub fn onomancy_owner(hostname: &DnsName) -> Self {
        let mut labels: Vec<Vec<u8>> = Vec::with_capacity(1);
        labels.push(SERVICE_LABEL.to_vec());
        labels.extend(hostname.as_str().split('.').map(|l| l.as_bytes().to_vec()));

        Self { labels }
    }

    /// Build a name from raw labels — crate-internal, for callers
    /// whose labels are already valid (existing names, the wildcard
    /// `*`).
    pub(crate) const fn from_labels(labels: Vec<Vec<u8>>) -> Self {
        Self { labels }
    }

    /// Append the canonical wire form.
    pub fn write(&self, buf: &mut Vec<u8>) {
        for label in &self.labels {
            // Labels are ≤ 63 by construction (parse or hostname
            // grammar), so the cast is total.
            #[allow(clippy::cast_possible_truncation)]
            buf.push(label.len() as u8);
            buf.extend_from_slice(label);
        }
        buf.push(0);
    }

    /// The labels, leftmost (most specific) first.
    #[must_use]
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// The root name has zero labels.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    /// Whether `self` is `other` or an ancestor of it (the zone-cut
    /// walk's descent check). The root is an ancestor of everything.
    #[must_use]
    pub fn is_ancestor_or_self_of(&self, other: &Self) -> bool {
        self.labels.len() <= other.labels.len()
            && self
                .labels
                .iter()
                .rev()
                .zip(other.labels.iter().rev())
                .all(|(a, b)| a == b)
    }

    /// RFC 4034 §6.1 canonical ordering: compare label-by-label from
    /// the RIGHT (root end), each label as raw octets. This is the
    /// order NSEC ranges are defined over.
    #[must_use]
    pub fn canonical_cmp(&self, other: &Self) -> Ordering {
        let mut left = self.labels.iter().rev();
        let mut right = other.labels.iter().rev();

        loop {
            match (left.next(), right.next()) {
                (None, None) => return Ordering::Equal,
                (None, Some(_)) => return Ordering::Less,
                (Some(_), None) => return Ordering::Greater,
                (Some(a), Some(b)) => match a.cmp(b) {
                    Ordering::Equal => (),
                    unequal @ (Ordering::Less | Ordering::Greater) => return unequal,
                },
            }
        }
    }
}

impl fmt::Display for Name {
    /// Dotted text, printable ASCII verbatim and everything else as
    /// RFC 1035 `\DDD` escapes. Diagnostics only — never a wire form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }

        let mut first = true;
        for label in &self.labels {
            if !first {
                f.write_str(".")?;
            }
            first = false;

            for &byte in label {
                if byte.is_ascii_graphic() && byte != b'.' && byte != b'\\' {
                    write!(f, "{}", char::from(byte))?;
                } else {
                    write!(f, "\\{byte:03}")?;
                }
            }
        }

        Ok(())
    }
}

/// Parse a textual name for tests and anchors: dotted, ASCII, already
/// lowercase.
impl FromStr for Name {
    type Err = ParseNameError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text == "." {
            return Ok(Self { labels: Vec::new() });
        }

        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut wire_len = 1;

        for label in text.trim_end_matches('.').split('.') {
            if label.is_empty() || label.len() > MAX_LABEL_LEN {
                return Err(ParseNameError::LabelTooLong {
                    len: u8::try_from(label.len()).unwrap_or(u8::MAX),
                });
            }
            if label.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(ParseNameError::NotCanonical {
                    reason: "uppercase ASCII in canonical form",
                });
            }

            wire_len += 1 + label.len();
            if wire_len > MAX_WIRE_LEN {
                return Err(ParseNameError::NameTooLong);
            }

            labels.push(label.as_bytes().to_vec());
        }

        Ok(Self { labels })
    }
}

/// The bytes were not a canonical wire-form name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseNameError {
    /// A label length exceeded 63 octets.
    #[error("label of {len} octets; labels are at most 63")]
    LabelTooLong {
        /// The declared length.
        len: u8,
    },

    /// The whole name exceeded 255 wire octets.
    #[error("name exceeds 255 wire octets")]
    NameTooLong,

    /// The bytes are legal DNS but not the canonical form signatures
    /// are computed over. Reject, never normalize.
    #[error("not canonical wire form: {reason}")]
    NotCanonical {
        /// What was non-canonical.
        reason: &'static str,
    },

    /// The input ended inside the name.
    #[error(transparent)]
    Truncated(#[from] WireError),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use alloc::format;

    fn read_all(bytes: &[u8]) -> Result<Name, ParseNameError> {
        let mut reader = Reader::new(bytes).expect("under cap");
        let name = Name::read(&mut reader)?;
        reader.finish().map_err(ParseNameError::Truncated)?;
        Ok(name)
    }

    #[test]
    fn reads_a_canonical_name() {
        let name = read_all(b"\x09_onomancy\x06expede\x03wtf\x00").expect("canonical");
        assert_eq!(name.labels().len(), 3);
        assert_eq!(format!("{name}"), "_onomancy.expede.wtf");
    }

    #[test]
    fn write_read_roundtrip() {
        let name: Name = "_onomancy.expede.wtf".parse().expect("parses");
        let mut buf = Vec::new();
        name.write(&mut buf);
        assert_eq!(read_all(&buf).expect("own encoding"), name);
    }

    #[test]
    fn onomancy_owner_prepends_the_service_label() {
        let hostname = DnsName::parse("expede.wtf").expect("valid");
        let owner = Name::onomancy_owner(&hostname);
        assert_eq!(format!("{owner}"), "_onomancy.expede.wtf");
    }

    #[test]
    fn compression_pointers_are_rejected() {
        assert!(matches!(
            read_all(b"\x03www\xC0\x0C"),
            Err(ParseNameError::NotCanonical { .. })
        ));
    }

    #[test]
    fn uppercase_is_rejected_not_normalized() {
        assert!(matches!(
            read_all(b"\x06EXPEDE\x03wtf\x00"),
            Err(ParseNameError::NotCanonical { .. })
        ));
    }

    #[test]
    fn root_is_a_lone_zero_byte() {
        let root = read_all(b"\x00").expect("root");
        assert!(root.is_root());
        assert_eq!(format!("{root}"), ".");
    }

    #[test]
    fn ancestry_walks_from_the_root_end() {
        let zone: Name = "expede.wtf".parse().expect("parses");
        let owner: Name = "_onomancy.expede.wtf".parse().expect("parses");
        let other: Name = "_onomancy.example.com".parse().expect("parses");
        let root = Name { labels: Vec::new() };

        assert!(zone.is_ancestor_or_self_of(&owner));
        assert!(!owner.is_ancestor_or_self_of(&zone));
        assert!(!zone.is_ancestor_or_self_of(&other));
        assert!(root.is_ancestor_or_self_of(&owner));
        assert!(owner.is_ancestor_or_self_of(&owner));
    }

    #[test]
    fn canonical_ordering_is_by_reversed_labels() {
        // RFC 4034 §6.1's worked example ordering.
        let example: Name = "example".parse().expect("parses");
        let a_example: Name = "a.example".parse().expect("parses");
        let yljkjljk: Name = "yljkjljk.a.example".parse().expect("parses");
        let z_example: Name = "z.example".parse().expect("parses");

        assert_eq!(example.canonical_cmp(&a_example), Ordering::Less);
        assert_eq!(a_example.canonical_cmp(&yljkjljk), Ordering::Less);
        assert_eq!(yljkjljk.canonical_cmp(&z_example), Ordering::Less);
        assert_eq!(example.canonical_cmp(&example), Ordering::Equal);
    }

    mod props {
        use super::*;

        /// Wire roundtrip: any parsed name re-encodes to the exact
        /// input bytes (canonical form has one spelling).
        #[test]
        fn read_write_byte_identity() {
            bolero::check!().with_type::<Vec<u8>>().for_each(|bytes| {
                let mut reader = Reader::new(bytes).expect("under cap");
                if let Ok(name) = Name::read(&mut reader) {
                    let consumed = bytes.len() - reader.remaining();
                    let mut rewritten = Vec::new();
                    name.write(&mut rewritten);
                    assert_eq!(rewritten, bytes[..consumed], "one spelling per name");
                }
            });
        }

        /// Canonical ordering is a total order consistent with
        /// equality, and ancestry agrees with it (an ancestor never
        /// sorts after its descendant).
        #[test]
        fn ordering_is_consistent() {
            bolero::check!()
                .with_type::<(Vec<Vec<u8>>, Vec<Vec<u8>>)>()
                .for_each(|(a, b)| {
                    let sanitize = |labels: &Vec<Vec<u8>>| Name {
                        labels: labels
                            .iter()
                            .take(4)
                            .map(|l| {
                                l.iter()
                                    .take(8)
                                    .map(u8::to_ascii_lowercase)
                                    .collect::<Vec<u8>>()
                            })
                            .filter(|l| !l.is_empty())
                            .collect(),
                    };

                    let left = sanitize(a);
                    let right = sanitize(b);

                    assert_eq!(left.canonical_cmp(&right) == Ordering::Equal, left == right);
                    assert_eq!(
                        left.canonical_cmp(&right),
                        right.canonical_cmp(&left).reverse()
                    );

                    if left.is_ancestor_or_self_of(&right) {
                        assert_ne!(left.canonical_cmp(&right), Ordering::Greater);
                    }
                });
        }
    }
}
