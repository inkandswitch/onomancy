//! Typed DS digests: computed commitments to an owner-qualified
//! DNSKEY.

use onomancy_core::digest::Digest;

use crate::wire::digest_type::DigestType;

use super::sha256::Sha256;

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
    Sha256(Digest<Sha256, OwnedDnskey>),
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

impl From<Digest<Sha256, OwnedDnskey>> for DsDigest {
    fn from(digest: Digest<Sha256, OwnedDnskey>) -> Self {
        Self::Sha256(digest)
    }
}

/// Marker: RFC 4509's DS preimage — the owner name (canonical wire
/// form) followed by the DNSKEY rdata. Not any single unit's encoding,
/// which is why the digest is indexed by this marker rather than by
/// [`Dnskey`](super::dnskey::Dnskey) itself.
pub struct OwnedDnskey;
