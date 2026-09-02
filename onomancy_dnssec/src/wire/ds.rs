//! The DS RDATA view: delegation-signer digests at zone cuts.
//!
//! The layout is DNS's, not ours: RFC 4034 §5.1.
//!
//! A DS in the parent zone commits to a child-zone DNSKEY:
//! `digest = H(owner name ‖ DNSKEY RDATA)`.

use alloc::vec::Vec;

use onomancy_core::wire::{Reader, WireError};

use super::{algorithm::Algorithm, digest_type::DigestType};

/// A parsed DS RDATA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ds {
    algorithm: Algorithm,
    digest: Vec<u8>,
    digest_type: DigestType,
    key_tag: u16,
}

impl Ds {
    /// Strictly parse one DS RDATA (full consumption).
    ///
    /// # Errors
    ///
    /// Returns [`ParseDsError`] on truncation or an empty digest.
    pub fn parse(rdata: &[u8]) -> Result<Self, ParseDsError> {
        let mut reader = Reader::new(rdata)?;

        let key_tag = u16::from_be_bytes(reader.take_array::<2>()?);
        let [algorithm] = reader.take_array::<1>()?;
        let [digest_type] = reader.take_array::<1>()?;
        let digest = reader.take(reader.remaining())?.to_vec();

        if digest.is_empty() {
            return Err(ParseDsError::EmptyDigest);
        }

        Ok(Self {
            algorithm: Algorithm::new(algorithm),
            digest,
            digest_type: DigestType::new(digest_type),
            key_tag,
        })
    }

    /// The key tag of the committed DNSKEY (a selector hint).
    #[must_use]
    pub const fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// The committed key's algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The digest algorithm.
    #[must_use]
    pub const fn digest_type(&self) -> DigestType {
        self.digest_type
    }

    /// The digest bytes.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

/// The bytes were not a valid DS RDATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseDsError {
    /// A DS with no digest commits to nothing.
    #[error("empty DS digest")]
    EmptyDigest,

    /// The fixed fields were truncated.
    #[error(transparent)]
    Truncated(#[from] WireError),
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn parses_the_fields() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&38696u16.to_be_bytes());
        rdata.push(8); // RSASHA256
        rdata.push(2); // SHA-256
        rdata.extend_from_slice(&[0xCD; 32]);

        let ds = Ds::parse(&rdata).expect("parses");
        assert_eq!(ds.key_tag(), 38696);
        assert_eq!(ds.algorithm(), Algorithm::RSA_SHA256);
        assert_eq!(ds.digest_type(), DigestType::SHA256);
        assert_eq!(ds.digest().len(), 32);
    }

    #[test]
    fn empty_digests_are_rejected() {
        let rdata = vec![0x00, 0x01, 8, 2];
        assert!(matches!(Ds::parse(&rdata), Err(ParseDsError::EmptyDigest)));
    }

    #[test]
    fn truncated_headers_are_rejected() {
        assert!(matches!(
            Ds::parse(&[0x00, 0x01, 8]),
            Err(ParseDsError::Truncated(_))
        ));
    }

    /// Parse-don't-validate layering: a SHA-256 DS with a wrong-width
    /// digest PARSES here (the wire reflects the wire) and fails
    /// downstream at `DsDigest::matches_wire`, which arbitrates.
    #[test]
    fn wrong_width_digests_parse_then_fail_to_match() {
        use crate::crypto::ds_digest::DsDigest;
        use onomancy_core::digest::Digest;

        let mut rdata = Vec::new();
        rdata.extend_from_slice(&38696u16.to_be_bytes());
        rdata.push(8);
        rdata.push(2);
        rdata.extend_from_slice(&[0xCD; 31]); // one byte short

        let ds = Ds::parse(&rdata).expect("the frame is legal DNS");
        assert_eq!(ds.digest().len(), 31);

        let computed = DsDigest::Sha256(Digest::from_bytes([0xCD; 32]));
        assert!(
            !computed.matches_wire(ds.digest_type(), ds.digest()),
            "a 31-byte digest can never equal a 32-byte commitment"
        );
    }
}
