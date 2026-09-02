//! The cryptographic operations: per-algorithm signature
//! verification and the DS digest check. Signed-data construction
//! (RFC 4035 §5.3.2) lives with [`Rrsig`](crate::wire::rrsig::Rrsig).
//!
//! # Algorithms
//!
//! RSA/SHA-256 (8), ECDSA P-256/SHA-256 (13), Ed25519 (15). Anything
//! else fails verification — unsupported is invalid ✗, never
//! insecure-but-ok.

pub mod ds_digest;
pub mod sha256;

use alloc::vec::Vec;
use onomancy_core::digest::Digest;
use p256::ecdsa::signature::Verifier as _;
use sha2::Digest as _;

use self::{
    ds_digest::{DsDigest, OwnedDnskey},
    sha256::Sha256,
};
use crate::wire::{
    algorithm::Algorithm, digest_type::DigestType, dnskey::Dnskey, ds::Ds, name::Name,
};

/// Verify one raw signature under one algorithm.
///
/// # Errors
///
/// Returns [`VerifyError`] on unsupported algorithms, malformed
/// key material, or a failed verification.
pub fn verify_signature(
    algorithm: Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    match algorithm {
        Algorithm::ED25519 => verify_ed25519(public_key, message, signature),
        Algorithm::ECDSA_P256_SHA256 => verify_p256(public_key, message, signature),
        Algorithm::RSA_SHA256 => verify_rsa_sha256(public_key, message, signature),
        unsupported => Err(VerifyError::UnsupportedAlgorithm(unsupported)),
    }
}

/// RFC 8080: the key is the raw 32-byte point; the signature is 64
/// bytes.
fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
    let key_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| VerifyError::MalformedKey)?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| VerifyError::MalformedKey)?;

    let signature_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| VerifyError::BadSignature)?;

    key.verify_strict(
        message,
        &ed25519_dalek::Signature::from_bytes(&signature_bytes),
    )
    .map_err(|_| VerifyError::BadSignature)
}

/// RFC 6605: the key is the uncompressed point WITHOUT the 0x04
/// prefix (64 bytes); the signature is `r ‖ s` (64 bytes).
fn verify_p256(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
    if public_key.len() != 64 {
        return Err(VerifyError::MalformedKey);
    }

    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(public_key);

    let key =
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| VerifyError::MalformedKey)?;
    let signature =
        p256::ecdsa::Signature::from_slice(signature).map_err(|_| VerifyError::BadSignature)?;

    key.verify(message, &signature)
        .map_err(|_| VerifyError::BadSignature)
}

/// RFC 3110/5702: the key is `exponent-length ‖ exponent ‖ modulus`
/// (length is one byte, or zero followed by a two-byte length);
/// PKCS#1 v1.5 over SHA-256.
fn verify_rsa_sha256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let (exponent, modulus) = split_rsa_key(public_key)?;

    let key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(modulus),
        rsa::BigUint::from_bytes_be(exponent),
    )
    .map_err(|_| VerifyError::MalformedKey)?;

    let hashed = sha2::Sha256::digest(message);

    key.verify(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &hashed, signature)
        .map_err(|_| VerifyError::BadSignature)
}

/// Split an RFC 3110 RSA key blob into (exponent, modulus).
fn split_rsa_key(blob: &[u8]) -> Result<(&[u8], &[u8]), VerifyError> {
    let (&first, rest) = blob.split_first().ok_or(VerifyError::MalformedKey)?;

    let (exponent_len, rest) = if first == 0 {
        let (len_bytes, rest) = rest.split_at_checked(2).ok_or(VerifyError::MalformedKey)?;
        let len_array: [u8; 2] = len_bytes
            .try_into()
            .map_err(|_| VerifyError::MalformedKey)?;
        (usize::from(u16::from_be_bytes(len_array)), rest)
    } else {
        (usize::from(first), rest)
    };

    if exponent_len == 0 {
        return Err(VerifyError::MalformedKey);
    }

    let (exponent, modulus) = rest
        .split_at_checked(exponent_len)
        .ok_or(VerifyError::MalformedKey)?;

    if modulus.is_empty() {
        return Err(VerifyError::MalformedKey);
    }

    Ok((exponent, modulus))
}

/// The SHA-256 DS digest for a DNSKEY at an owner name:
/// `H(owner canonical wire ‖ DNSKEY RDATA)`.
#[must_use]
pub fn ds_digest(owner: &Name, key: &Dnskey) -> Digest<Sha256, OwnedDnskey> {
    let mut input = Vec::new();
    owner.write(&mut input);
    input.extend_from_slice(key.rdata());

    Digest::hash(&input)
}

/// Whether a DS record commits to this DNSKEY at this owner.
///
/// # Errors
///
/// Returns [`VerifyError::UnsupportedDigest`] for digest types this
/// implementation cannot compute (invalid ✗, never insecure) and
/// [`VerifyError::DsMismatch`] when the digest simply differs.
pub fn ds_matches(owner: &Name, key: &Dnskey, ds: &Ds) -> Result<(), VerifyError> {
    if ds.digest_type() != DigestType::SHA256 {
        return Err(VerifyError::UnsupportedDigest(ds.digest_type()));
    }

    if ds.algorithm() != key.algorithm() {
        return Err(VerifyError::AlgorithmMismatch {
            key: key.algorithm(),
            signature: ds.algorithm(),
        });
    }

    let computed = DsDigest::from(ds_digest(owner, key));
    if computed.matches_wire(ds.digest_type(), ds.digest()) {
        Ok(())
    } else {
        Err(VerifyError::DsMismatch)
    }
}

/// A signature or digest check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    /// Key and signature (or DS) disagree about the algorithm.
    #[error("algorithm mismatch: key {key}, signature {signature}")]
    AlgorithmMismatch {
        /// The key's algorithm.
        key: Algorithm,
        /// The signature's (or DS's) claimed algorithm.
        signature: Algorithm,
    },

    /// The signature did not verify (or was structurally malformed —
    /// deliberately indistinguishable).
    #[error("signature does not verify")]
    BadSignature,

    /// The DS digest does not match the key.
    #[error("DS digest does not match the DNSKEY")]
    DsMismatch,

    /// The RRSIG claims more labels than the owner has.
    #[error("RRSIG label count {signature} exceeds owner labels {owner}")]
    LabelCount {
        /// Owner label count.
        owner: usize,
        /// RRSIG label count.
        signature: usize,
    },

    /// The key material could not be decoded for its algorithm.
    #[error("malformed key material")]
    MalformedKey,

    /// The key's ZONE flag is cleared: it must not verify zone data.
    #[error("DNSKEY is not a zone key")]
    NotAZoneKey,

    /// An algorithm this implementation cannot verify — invalid,
    /// never insecure-but-ok.
    #[error("unsupported algorithm {0}")]
    UnsupportedAlgorithm(Algorithm),

    /// The same rule for digests: a DS digest type this implementation cannot
    /// compute.
    #[error("unsupported DS digest type {0}")]
    UnsupportedDigest(DigestType),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

    /// RFC 4035 §5.3.2 signed data for one A record, hand-assembled
    /// for the RFC 5702/6605 worked examples (owner
    /// `www.example.net.`, signer `example.net.`, TTL 3600).
    fn rfc_signed_data(
        algorithm: Algorithm,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        address: [u8; 4],
    ) -> Vec<u8> {
        let mut message = Vec::new();
        // RRSIG preamble: covered A(1), algorithm, labels 3, orig TTL.
        message.extend_from_slice(&1u16.to_be_bytes());
        message.push(algorithm.code());
        message.push(3);
        message.extend_from_slice(&3600u32.to_be_bytes());
        message.extend_from_slice(&expiration.to_be_bytes());
        message.extend_from_slice(&inception.to_be_bytes());
        message.extend_from_slice(&key_tag.to_be_bytes());
        message.extend_from_slice(b"\x07example\x03net\x00");
        // The one A record in canonical form.
        message.extend_from_slice(b"\x03www\x07example\x03net\x00");
        message.extend_from_slice(&1u16.to_be_bytes()); // type A
        message.extend_from_slice(&1u16.to_be_bytes()); // class IN
        message.extend_from_slice(&3600u32.to_be_bytes());
        message.extend_from_slice(&4u16.to_be_bytes());
        message.extend_from_slice(&address);
        message
    }

    /// RFC 5702 §6.1: a genuine RSA/SHA-256 signature made by another
    /// implementation — the algorithm of the actual DNS root zone.
    /// A wiring bug (wrong hash, wrong padding, exponent/modulus
    /// swapped) fails closed and would brick every real-root
    /// validation; this is the test that notices.
    #[test]
    fn the_rfc5702_rsa_sha256_vector_verifies() {
        let key_blob = BASE64
            .decode(
                "AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36Bponcwtk\
                 Z4cAgtvd4Qs8PkxUdp6p/DlUmObdk=",
            )
            .expect("published key decodes");
        let signature = BASE64
            .decode(
                "kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85m\
                 wlMgNEacFYK/lPtPiVYP4bwg==",
            )
            .expect("published signature decodes");

        // 20300101000000 / 20000101000000 as epoch seconds; tag 9033;
        // www.example.net. A 192.0.2.91.
        let message = rfc_signed_data(
            Algorithm::RSA_SHA256,
            1_893_456_000,
            946_684_800,
            9033,
            [192, 0, 2, 91],
        );

        assert_eq!(
            verify_signature(Algorithm::RSA_SHA256, &key_blob, &message, &signature),
            Ok(())
        );

        // One flipped message byte fails as BadSignature, never panics.
        let mut tampered = message;
        tampered[0] ^= 0x01;
        assert_eq!(
            verify_signature(Algorithm::RSA_SHA256, &key_blob, &tampered, &signature),
            Err(VerifyError::BadSignature)
        );
    }

    /// RFC 6605 §6.1: a genuine ECDSA P-256 signature — pins the two
    /// hand-rolled format details (the 0x04 SEC1 prefix prepend and
    /// fixed-width `r ‖ s` parsing).
    #[test]
    fn the_rfc6605_p256_vector_verifies() {
        let key_blob = BASE64
            .decode(
                "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNc\
                 P+e+MAnLr+Wi9xMWyQLc8NAA==",
            )
            .expect("published key decodes");
        let signature = BASE64
            .decode(
                "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZo\
                 LBLlUzGGus7ZwmwWep666VCw==",
            )
            .expect("published signature decodes");

        // 20100909100439 / 20100812100439 as epoch seconds; tag 55648;
        // www.example.net. A 192.0.2.1.
        let message = rfc_signed_data(
            Algorithm::ECDSA_P256_SHA256,
            1_284_026_679,
            1_281_607_479,
            55648,
            [192, 0, 2, 1],
        );

        assert_eq!(
            verify_signature(
                Algorithm::ECDSA_P256_SHA256,
                &key_blob,
                &message,
                &signature
            ),
            Ok(())
        );

        // Bit flip → BadSignature.
        let mut tampered = message.clone();
        tampered[0] ^= 0x01;
        assert_eq!(
            verify_signature(
                Algorithm::ECDSA_P256_SHA256,
                &key_blob,
                &tampered,
                &signature
            ),
            Err(VerifyError::BadSignature)
        );

        // A 65-byte key (0x04 already prepended) is malformed — the
        // DNS form is exactly the 64-byte point.
        let mut prefixed = alloc::vec![0x04];
        prefixed.extend_from_slice(&key_blob);
        assert_eq!(
            verify_signature(
                Algorithm::ECDSA_P256_SHA256,
                &prefixed,
                &message,
                &signature
            ),
            Err(VerifyError::MalformedKey)
        );
    }

    /// The malformed-input arms of the Ed25519 path: a wrong-width
    /// key is `MalformedKey`; a wrong-width signature is deliberately
    /// indistinguishable from a failed one.
    #[test]
    fn ed25519_malformed_inputs_have_their_documented_shapes() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();

        assert_eq!(
            verify_signature(Algorithm::ED25519, &key.as_bytes()[..31], b"m", &[0; 64]),
            Err(VerifyError::MalformedKey)
        );
        assert_eq!(
            verify_signature(Algorithm::ED25519, key.as_bytes(), b"m", &[0; 63]),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn unsupported_algorithms_are_invalid_not_insecure() {
        assert_eq!(
            verify_signature(Algorithm::new(253), &[], b"m", &[]),
            Err(VerifyError::UnsupportedAlgorithm(Algorithm::new(253)))
        );
    }

    /// The two invalid-✗ policy arms of `ds_matches`: an unsupported
    /// digest type and a key/DS algorithm disagreement are both their
    /// own refusals, never insecure-but-ok.
    #[test]
    fn ds_matching_refuses_unsupported_digests_and_mismatched_algorithms() {
        let mut key_rdata = Vec::new();
        key_rdata.extend_from_slice(&0x0100u16.to_be_bytes());
        key_rdata.push(3);
        key_rdata.push(Algorithm::ED25519.code());
        key_rdata.extend_from_slice(&[7; 32]);
        let key = Dnskey::parse(&key_rdata).expect("valid DNSKEY");
        let owner: Name = "expede.wtf".parse().expect("parses");

        // SHA-384 (type 4): representable on the wire, uncomputable here.
        let mut sha384_ds = Vec::new();
        sha384_ds.extend_from_slice(&key.key_tag().to_be_bytes());
        sha384_ds.push(Algorithm::ED25519.code());
        sha384_ds.push(4);
        sha384_ds.extend_from_slice(&[0xAA; 48]);
        let ds = Ds::parse(&sha384_ds).expect("parses");
        assert_eq!(
            ds_matches(&owner, &key, &ds),
            Err(VerifyError::UnsupportedDigest(DigestType::new(4)))
        );

        // A DS claiming a different key algorithm.
        let mut rsa_ds = Vec::new();
        rsa_ds.extend_from_slice(&key.key_tag().to_be_bytes());
        rsa_ds.push(Algorithm::RSA_SHA256.code());
        rsa_ds.push(DigestType::SHA256.code());
        rsa_ds.extend_from_slice(ds_digest(&owner, &key).as_bytes());
        let ds = Ds::parse(&rsa_ds).expect("parses");
        assert_eq!(
            ds_matches(&owner, &key, &ds),
            Err(VerifyError::AlgorithmMismatch {
                key: Algorithm::ED25519,
                signature: Algorithm::RSA_SHA256
            })
        );
    }

    #[test]
    fn ds_digest_commits_to_owner_and_key() {
        // DNSKEY: ZONE flag, protocol 3, ED25519, any 32-byte point.
        let mut key_rdata = Vec::new();
        key_rdata.extend_from_slice(&0x0100u16.to_be_bytes());
        key_rdata.push(3);
        key_rdata.push(Algorithm::ED25519.code());
        key_rdata.extend_from_slice(&[7; 32]);
        let key = Dnskey::parse(&key_rdata).expect("valid DNSKEY");
        let owner: Name = "expede.wtf".parse().expect("parses");

        let mut ds_rdata = Vec::new();
        ds_rdata.extend_from_slice(&key.key_tag().to_be_bytes());
        ds_rdata.push(Algorithm::ED25519.code());
        ds_rdata.push(DigestType::SHA256.code());
        ds_rdata.extend_from_slice(ds_digest(&owner, &key).as_bytes());
        let ds = Ds::parse(&ds_rdata).expect("parses");

        ds_matches(&owner, &key, &ds).expect("digest matches");

        // A different owner must not match.
        let other: Name = "attack.wtf".parse().expect("parses");
        assert_eq!(ds_matches(&other, &key, &ds), Err(VerifyError::DsMismatch));
    }

    #[test]
    fn rsa_key_blob_splitting_handles_both_length_forms() {
        // Short form: 1-byte exponent length.
        let (e, m) = split_rsa_key(&[3, 1, 0, 1, 0xAA, 0xBB]).expect("short form");
        assert_eq!(e, &[1, 0, 1]);
        assert_eq!(m, &[0xAA, 0xBB]);

        // Long form: zero marker + 2-byte length.
        let mut blob = vec![0u8, 1, 2];
        blob.extend_from_slice(&[9; 258]);
        blob.extend_from_slice(&[0xCC; 4]);
        let (e, m) = split_rsa_key(&blob).expect("long form");
        assert_eq!(e.len(), 258);
        assert_eq!(m, &[0xCC; 4]);

        assert!(split_rsa_key(&[]).is_err());
        assert!(split_rsa_key(&[5, 1, 2]).is_err(), "exponent overrun");

        // Zero-length exponents and empty moduli are refused too.
        assert_eq!(
            split_rsa_key(&[0, 0, 0, 9, 9]),
            Err(VerifyError::MalformedKey),
            "zero exponent length"
        );
        assert_eq!(
            split_rsa_key(&[2, 1, 1]),
            Err(VerifyError::MalformedKey),
            "empty modulus"
        );
    }

    mod props {
        use super::*;

        /// `split_rsa_key` is total, and on success the split is an
        /// exact partition: header + exponent + modulus = blob.
        #[test]
        fn rsa_key_splitting_partitions_the_blob() {
            bolero::check!().with_type::<Vec<u8>>().for_each(|blob| {
                if let Ok((exponent, modulus)) = split_rsa_key(blob) {
                    assert!(!exponent.is_empty());
                    assert!(!modulus.is_empty());

                    let header_len = if blob[0] == 0 { 3 } else { 1 };
                    assert_eq!(header_len + exponent.len() + modulus.len(), blob.len());
                }
            });
        }
    }
}
