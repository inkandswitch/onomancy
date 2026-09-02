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

use onomancy_core::digest::Digest;

use crate::{
    crypto::{self, ds_digest::DsDigest},
    wire::{algorithm::Algorithm, dnskey::Dnskey, name::Name},
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
        digest: DsDigest::Sha256(Digest::from_bytes(hex_to_bytes(
            b"E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
        ))),
        key_tag: 20326,
        zone: root.clone(),
    };

    let ksk_2024 = TrustAnchor {
        algorithm: Algorithm::RSA_SHA256,
        digest: DsDigest::Sha256(Digest::from_bytes(hex_to_bytes(
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
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::{crypto::ds_digest, wire::digest_type::DigestType};
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    /// The published root KSK public keys, from the root zone DNSKEY
    /// `RRset` (flags 257, protocol 3, algorithm 8) — independent
    /// data the shipped anchor constants must answer to.
    const KSK_2017_KEY: &str = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq\
                                7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnI\
                                DdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb\
                                9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTId\
                                sIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qih\
                                ylGa8subX2Nn6UwNR1AkUTV74bU=";

    const KSK_2024_KEY: &str = "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyG\
                                wCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8\
                                e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/\
                                dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGO\
                                HOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2\
                                vaF18UYH9Z9GNUUeayffKC73PYc=";

    /// The published KSK's DNSKEY RDATA: 257 3 8 <key>.
    fn ksk_rdata(key_base64: &str) -> Vec<u8> {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&257u16.to_be_bytes());
        rdata.push(3);
        rdata.push(Algorithm::RSA_SHA256.code());
        rdata.extend_from_slice(&BASE64.decode(key_base64).expect("published key decodes"));
        rdata
    }

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

    /// The shipped constants answer to the PUBLISHED root keys: each
    /// anchor's tag is what RFC 4034 Appendix B computes over the
    /// real RDATA, and `matches` accepts the real key at the root.
    /// This is the cross-implementation check the self-referential
    /// constants cannot provide for themselves.
    #[test]
    fn anchors_match_the_published_root_ksks() {
        let root = Name::from_labels(Vec::new());
        let anchors = iana_root_anchors();

        for (anchor, key_base64) in anchors.iter().zip([KSK_2017_KEY, KSK_2024_KEY]) {
            let key = Dnskey::parse(&ksk_rdata(key_base64)).expect("published RDATA parses");
            assert_eq!(key.key_tag(), anchor.key_tag, "published tag agrees");
            assert!(
                anchor.matches(&root, &key),
                "anchor {} must commit to its published key",
                anchor.key_tag
            );
        }

        // And they are not interchangeable: each anchor commits to
        // exactly its own key.
        let ksk_2024 = Dnskey::parse(&ksk_rdata(KSK_2024_KEY)).expect("parses");
        assert!(!anchors[0].matches(&root, &ksk_2024));
    }

    /// Every conjunct of `matches` bites: right key at the right
    /// owner passes; wrong owner, wrong algorithm, and a flipped
    /// digest byte each fail on their own.
    #[test]
    fn matching_requires_zone_algorithm_and_digest_together() {
        // An Ed25519 zone key at expede.wtf, anchored by its own DS
        // digest (the pattern from crypto::ds_digest_commits…).
        let mut key_rdata = Vec::new();
        key_rdata.extend_from_slice(&0x0100u16.to_be_bytes());
        key_rdata.push(3);
        key_rdata.push(Algorithm::ED25519.code());
        key_rdata.extend_from_slice(&[7; 32]);
        let key = Dnskey::parse(&key_rdata).expect("valid DNSKEY");

        let owner: Name = "expede.wtf".parse().expect("parses");
        let anchor = TrustAnchor {
            algorithm: Algorithm::ED25519,
            digest: DsDigest::from(ds_digest(&owner, &key)),
            key_tag: key.key_tag(),
            zone: owner.clone(),
        };

        assert!(anchor.matches(&owner, &key));

        // (a) A different owner fails (the digest recommits to it).
        let other: Name = "attack.wtf".parse().expect("parses");
        assert!(!anchor.matches(&other, &key));

        // (b) An algorithm disagreement fails on its own conjunct.
        let mismatched = TrustAnchor {
            algorithm: Algorithm::RSA_SHA256,
            ..anchor.clone()
        };
        assert!(!mismatched.matches(&owner, &key));

        // (c) One flipped digest byte fails.
        let mut flipped_bytes = *ds_digest(&owner, &key).as_bytes();
        flipped_bytes[0] ^= 0x01;
        let flipped = TrustAnchor {
            digest: DsDigest::Sha256(Digest::from_bytes(flipped_bytes)),
            ..anchor
        };
        assert!(!flipped.matches(&owner, &key));
    }

    mod props {
        use super::*;

        /// Round trip through the const hex decoder: uppercase-hex
        /// spellings of arbitrary bytes decode back to those bytes.
        /// (The `_ => 0` nibble fallback is unreachable from valid
        /// hex; the published-KSK cross-check above would catch a
        /// corrupted constant that silently decoded through it.)
        #[test]
        fn hex_decoding_roundtrips_all_byte_values() {
            bolero::check!().with_type::<[u8; 32]>().for_each(|bytes| {
                // Both digit alphabets: the anchor constants happen to
                // be uppercase, but the decoder accepts either case and
                // the lowercase arm must not rot.
                for digits in [b"0123456789ABCDEF", b"0123456789abcdef"] {
                    let mut hex = [0u8; 64];
                    for (index, byte) in bytes.iter().enumerate() {
                        hex[index * 2] = digits[usize::from(byte >> 4)];
                        hex[index * 2 + 1] = digits[usize::from(byte & 0x0F)];
                    }

                    assert_eq!(hex_to_bytes(&hex), *bytes);
                }
            });
        }
    }
}
