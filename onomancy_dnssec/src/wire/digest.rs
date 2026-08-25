//! DS digest vocabulary: digest type codes and typed digests.
//!
//! The codes are DNS's, not ours: the IANA DS digest-type registry.

use core::fmt;

/// A DS digest-type code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DigestType(pub u8);

impl DigestType {
    /// SHA-256 (2) — the only type this implementation computes;
    /// everything else fails validation (the D13 doctrine applied to
    /// digests).
    pub const SHA256: Self = Self(2);

    /// Whether this implementation can compute the digest.
    #[must_use]
    pub const fn supported(self) -> bool {
        matches!(self, Self::SHA256)
    }
}

impl fmt::Display for DigestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SHA256 => f.write_str("SHA-256"),
            Self(code) => write!(f, "DIGEST{code}"),
        }
    }
}

/// A computed SHA-256 DS digest: exactly 32 bytes, by type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// The digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for Sha256Digest {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// A digest whose [`DigestType`] is DERIVED from its payload, never
/// stored beside it — the tag and the bytes cannot disagree, and only
/// supported digest kinds are representable (D13 as a type: an
/// unsupported trust anchor is not rejected, it cannot be written
/// down). One variant today; SHA-384 support would be a new variant,
/// not a new field.
///
/// The wire-side [`Ds`] view deliberately keeps `(DigestType, bytes)`
/// loose: DS `RRset`s in the wild legally carry digest types we cannot
/// compute, and validators pick a supported sibling — the wire
/// reflects the wire; THIS type is for digests *we* computed or
/// vouch for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DsDigest {
    /// SHA-256 (DS digest type 2).
    Sha256(Sha256Digest),
}

impl DsDigest {
    /// The wire code for this digest's kind — total, because every
    /// representable digest is a supported one.
    #[must_use]
    pub const fn digest_type(&self) -> DigestType {
        match self {
            Self::Sha256(_) => DigestType::SHA256,
        }
    }

    /// Whether a wire-carried `(type, bytes)` pair equals this digest.
    #[must_use]
    pub fn matches_wire(&self, digest_type: DigestType, wire_digest: &[u8]) -> bool {
        self.digest_type() == digest_type
            && match self {
                Self::Sha256(digest) => *digest.as_bytes() == *wire_digest,
            }
    }
}

impl From<Sha256Digest> for DsDigest {
    fn from(digest: Sha256Digest) -> Self {
        Self::Sha256(digest)
    }
}
