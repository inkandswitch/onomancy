//! Trust anchors: where every walk starts.
//!
//! Anchors are held in DS form — a digest commitment to a root-zone
//! DNSKEY — exactly as IANA publishes them. The validator takes an
//! anchor **set**, never a single anchor: RFC 5011-style KSK rollovers
//! overlap for months, and gossiped chains must verify on either side
//! of the boundary, so both KSKs ship during an overlap (and the
//! superseded one is removed by a release, the slow-trust-anchor
//! cadence the design assumes).

use alloc::{vec, vec::Vec};

use crate::{
    crypto,
    wire::{
        algorithm::Algorithm,
        digest::{DsDigest, Sha256Digest},
        dnskey::Dnskey,
        name::Name,
    },
};

/// A DS-form trust anchor: a digest commitment to a zone key.
///
/// The digest's type tag is carried BY the [`DsDigest`] value, never
/// beside it — an anchor with an unsupported digest kind, or a
/// tag/payload mismatch, is unrepresentable rather than rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchor {
    /// The committed key's algorithm.
    pub algorithm: Algorithm,
    /// The digest, tagged by construction.
    pub digest: DsDigest,
    /// The committed key's tag (a selector hint, never a security
    /// check).
    pub key_tag: u16,
    /// The zone the anchor is for (the root, for the IANA anchors).
    pub zone: Name,
}

impl TrustAnchor {
    /// Whether this anchor commits to `key` at `owner`.
    #[must_use]
    pub fn matches(&self, owner: &Name, key: &Dnskey) -> bool {
        self.zone == *owner
            && self.algorithm == key.algorithm()
            && self.digest == DsDigest::from(crypto::ds_digest(owner, key))
    }
}

/// The IANA root KSK anchors, as published at
/// <https://data.iana.org/root-anchors/root-anchors.xml>.
///
/// Both the 2017 and 2024 KSKs ship while the 2024 rollover overlap
/// lasts.
#[must_use]
pub fn iana_root_anchors() -> Vec<TrustAnchor> {
    let root = Name::from_labels(Vec::new());

    let ksk_2017 = TrustAnchor {
        algorithm: Algorithm::RSA_SHA256,
        digest: DsDigest::Sha256(Sha256Digest::from(hex_to_bytes(
            b"E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
        ))),
        key_tag: 20326,
        zone: root.clone(),
    };

    let ksk_2024 = TrustAnchor {
        algorithm: Algorithm::RSA_SHA256,
        digest: DsDigest::Sha256(Sha256Digest::from(hex_to_bytes(
            b"683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
        ))),
        key_tag: 38696,
        zone: root,
    };

    vec![ksk_2017, ksk_2024]
}

/// Decode a 64-char uppercase-hex constant into 32 bytes. Const-input
/// helper: inputs are the compile-time IANA digests above, so
/// malformed hex is a source bug, surfaced by the tests below.
const fn hex_to_bytes(hex: &[u8; 64]) -> [u8; 32] {
    const fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'A'..=b'F' => byte - b'A' + 10,
            b'a'..=b'f' => byte - b'a' + 10,
            _ => 0,
        }
    }

    let mut bytes = [0u8; 32];
    let mut index = 0;
    while index < 32 {
        // Statically in-bounds: index < 32 over [u8; 32] and [u8; 64].
        #[allow(clippy::indexing_slicing)]
        {
            bytes[index] = (nibble(hex[index * 2]) << 4) | nibble(hex[index * 2 + 1]);
        }
        index += 1;
    }
    bytes
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::wire::digest::DigestType;

    #[test]
    fn iana_anchors_are_well_formed() {
        let anchors = iana_root_anchors();
        assert_eq!(anchors.len(), 2);

        for anchor in &anchors {
            assert!(anchor.zone.is_root());
            assert_eq!(anchor.digest.digest_type(), DigestType::SHA256);
            assert_eq!(anchor.algorithm, Algorithm::RSA_SHA256);
        }

        let tags: Vec<u16> = anchors.iter().map(|a| a.key_tag).collect();
        assert_eq!(tags, [20326, 38696]);
    }

    #[test]
    fn hex_decoding_roundtrips_known_bytes() {
        let decoded =
            hex_to_bytes(b"E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D");
        assert_eq!(decoded[0], 0xE0);
        assert_eq!(decoded[1], 0x6D);
        assert_eq!(decoded[31], 0x8D);
    }
}
