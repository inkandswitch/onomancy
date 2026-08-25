//! The signature glue: canonical signed-data construction, per-algorithm
//! verification, and the DS digest check.
//!
//! # The Signed Data (RFC 4035 §5.3.2)
//!
//! ```text
//! signed_data = RRSIG preamble (verbatim RDATA before the signature)
//!             ‖ for each RR, sorted by RDATA (RFC 4034 §6.3):
//!                 signed owner ‖ type ‖ class ‖ ORIGINAL TTL
//!                 ‖ RDLENGTH ‖ RDATA
//! ```
//!
//! Two deliberate reconstructions happen here and nowhere else:
//! the received TTL is replaced by the RRSIG's original TTL, and a
//! wildcard-expanded owner is collapsed back to its `*.<suffix>` form
//! (the RRSIG label count says so — and the same count is D14's
//! trigger for demanding a no-closer-match proof upstream).
//!
//! # Algorithms (D13)
//!
//! RSA/SHA-256 (8), ECDSA P-256/SHA-256 (13), Ed25519 (15). Anything
//! else fails verification — unsupported is invalid ✗, never
//! insecure-but-ok.

use alloc::{vec, vec::Vec};
use core::cmp::Ordering;
use p256::ecdsa::signature::Verifier as _;
use sha2::{Digest as _, Sha256};

use crate::{
    link::Link,
    wire::{
        algorithm::Algorithm,
        digest::{DigestType, DsDigest, Sha256Digest},
        dnskey::Dnskey,
        ds::Ds,
        name::Name,
        record::CLASS_IN,
        rrsig::Rrsig,
    },
};

/// Verify one RRSIG over a link's `RRset` with one DNSKEY.
///
/// Pure: bytes and parsed views in, verdict out. Key selection
/// (matching key tags, trying rollover siblings) is the walk's job;
/// this function answers for exactly one (signature, key) pair.
///
/// # Errors
///
/// Returns [`VerifyError`] when the algorithm is unsupported or
/// mismatched, the key is not a zone key, the signed-owner
/// reconstruction is impossible, the key bytes are malformed, or the
/// signature simply does not verify.
pub fn verify_rrsig(link: &Link, rrsig: &Rrsig, key: &Dnskey) -> Result<(), VerifyError> {
    if !key.is_zone_key() {
        // RFC 4034 §2.1.1: a cleared ZONE bit MUST NOT verify RRsets.
        return Err(VerifyError::NotAZoneKey);
    }

    if key.algorithm() != rrsig.algorithm() {
        return Err(VerifyError::AlgorithmMismatch {
            key: key.algorithm(),
            signature: rrsig.algorithm(),
        });
    }

    let message = signed_data(link, rrsig)?;
    verify_signature(
        rrsig.algorithm(),
        key.public_key(),
        &message,
        rrsig.signature(),
    )
}

/// Construct the RFC 4035 §5.3.2 signed data for one (link, RRSIG)
/// pair.
///
/// # Errors
///
/// Returns [`VerifyError::LabelCount`] when the RRSIG label count
/// exceeds the owner's (no valid reconstruction exists).
pub fn signed_data(link: &Link, rrsig: &Rrsig) -> Result<Vec<u8>, VerifyError> {
    let signed_owner = signed_owner(link.owner(), rrsig)?;

    let mut owner_wire = Vec::new();
    signed_owner.write(&mut owner_wire);

    // Canonical RRset order: RDATA as left-justified octet strings,
    // ascending, duplicates dropped (RFC 4034 §6.3).
    let mut rdatas: Vec<&[u8]> = link.rrset().iter().map(|r| r.rdata.as_slice()).collect();
    rdatas.sort_unstable();
    rdatas.dedup();

    let mut message = rrsig.preamble().to_vec();

    for rdata in rdatas {
        message.extend_from_slice(&owner_wire);
        message.extend_from_slice(&link.rtype().0.to_be_bytes());
        message.extend_from_slice(&CLASS_IN.to_be_bytes());
        message.extend_from_slice(&rrsig.original_ttl().to_be_bytes());
        // RDATA length fits u16: it was framed from a u16 RDLENGTH.
        message.extend_from_slice(&u16::try_from(rdata.len()).unwrap_or(u16::MAX).to_be_bytes());
        message.extend_from_slice(rdata);
    }

    Ok(message)
}

/// Reconstruct the signed owner name: the owner itself, or its
/// wildcard source when the RRSIG label count says the answer was
/// expanded (`labels < owner labels` ⇒ `*.<rightmost labels>`).
fn signed_owner(owner: &Name, rrsig: &Rrsig) -> Result<Name, VerifyError> {
    let owner_labels = owner.labels().len();
    let signed_labels = usize::from(rrsig.labels());

    match signed_labels.cmp(&owner_labels) {
        Ordering::Equal => Ok(owner.clone()),
        Ordering::Less => {
            let mut labels: Vec<Vec<u8>> = vec![b"*".to_vec()];
            labels.extend(
                owner
                    .labels()
                    .iter()
                    .skip(owner_labels - signed_labels)
                    .cloned(),
            );
            Ok(Name::from_labels(labels))
        }
        Ordering::Greater => Err(VerifyError::LabelCount {
            owner: owner_labels,
            signature: signed_labels,
        }),
    }
}

/// Verify one raw signature under one algorithm.
///
/// # Errors
///
/// Returns [`VerifyError`] on unsupported algorithms (D13), malformed
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

    let hashed = Sha256::digest(message);

    key.verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &hashed, signature)
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
pub fn ds_digest(owner: &Name, key: &Dnskey) -> Sha256Digest {
    let mut input = Vec::new();
    owner.write(&mut input);
    input.extend_from_slice(key.rdata());

    Sha256Digest::from(<[u8; 32]>::from(Sha256::digest(&input)))
}

/// Whether a DS record commits to this DNSKEY at this owner.
///
/// # Errors
///
/// Returns [`VerifyError::UnsupportedDigest`] for digest types this
/// implementation cannot compute (invalid ✗ per the D13 doctrine) and
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

    /// D13: an algorithm this implementation cannot verify — invalid,
    /// never insecure-but-ok.
    #[error("unsupported algorithm {0}")]
    UnsupportedAlgorithm(Algorithm),

    /// D13 for digests: a DS digest type this implementation cannot
    /// compute.
    #[error("unsupported DS digest type {0}")]
    UnsupportedDigest(DigestType),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::wire::{record::Record, rr_type::RrType};
    use alloc::format;
    use ed25519_dalek::Signer as _;
    use onomancy_core::certificate::chain::ChainLink;

    /// Build a TXT link signed for real with a test Ed25519 zone key.
    fn signed_link(rdatas: &[&[u8]], owner: &str, labels: u8) -> (Link, Dnskey) {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);

        // DNSKEY: ZONE flag, protocol 3, ED25519.
        let mut key_rdata = Vec::new();
        key_rdata.extend_from_slice(&0x0100u16.to_be_bytes());
        key_rdata.push(3);
        key_rdata.push(Algorithm::ED25519.0);
        key_rdata.extend_from_slice(signing.verifying_key().as_bytes());
        let dnskey = Dnskey::parse(&key_rdata).expect("valid DNSKEY");

        let owner_name: Name = owner.parse().expect("parses");

        // RRSIG preamble (unsigned yet): covered/alg/labels/ttl/
        // windows/tag/signer.
        let mut preamble = Vec::new();
        preamble.extend_from_slice(&RrType::TXT.0.to_be_bytes());
        preamble.push(Algorithm::ED25519.0);
        preamble.push(labels);
        preamble.extend_from_slice(&900u32.to_be_bytes());
        preamble.extend_from_slice(&1_755_600_000u32.to_be_bytes());
        preamble.extend_from_slice(&1_754_000_000u32.to_be_bytes());
        preamble.extend_from_slice(&dnskey.key_tag().to_be_bytes());
        preamble.extend_from_slice(b"\x06expede\x03wtf\x00");

        // Construct the signed data by the same rules and sign it.
        let mut sorted: Vec<&[u8]> = rdatas.to_vec();
        sorted.sort_unstable();
        sorted.dedup();

        let mut message = preamble.clone();
        let signed_name: Name = if usize::from(labels) < owner_name.labels().len() {
            format!(
                "*.{}",
                owner
                    .split('.')
                    .skip(owner_name.labels().len() - usize::from(labels))
                    .collect::<Vec<_>>()
                    .join(".")
            )
            .parse()
            .expect("wildcard form parses")
        } else {
            owner_name.clone()
        };
        let mut owner_wire = Vec::new();
        signed_name.write(&mut owner_wire);

        for rdata in &sorted {
            message.extend_from_slice(&owner_wire);
            message.extend_from_slice(&RrType::TXT.0.to_be_bytes());
            message.extend_from_slice(&CLASS_IN.to_be_bytes());
            message.extend_from_slice(&900u32.to_be_bytes());
            message.extend_from_slice(&u16::try_from(rdata.len()).expect("small").to_be_bytes());
            message.extend_from_slice(rdata);
        }

        let signature = signing.sign(&message);

        let mut rrsig_rdata = preamble;
        rrsig_rdata.extend_from_slice(&signature.to_bytes());

        // Frame the link: data records (received TTL differs from the
        // original on purpose) + the RRSIG.
        let mut bytes = Vec::new();
        for rdata in rdatas {
            Record {
                owner: owner_name.clone(),
                rtype: RrType::TXT,
                class: CLASS_IN,
                ttl: 42, // received TTL ≠ original: must not matter
                rdata: rdata.to_vec(),
            }
            .write(&mut bytes);
        }
        Record {
            owner: owner_name,
            rtype: RrType::RRSIG,
            class: CLASS_IN,
            ttl: 42,
            rdata: rrsig_rdata,
        }
        .write(&mut bytes);

        let link = Link::parse(&ChainLink::from(bytes)).expect("link parses");
        (link, dnskey)
    }

    #[test]
    fn ed25519_rrsig_verifies_end_to_end() {
        let (link, key) = signed_link(&[b"\x04test"], "_onomancy.expede.wtf", 3);
        let rrsig = &link.signatures()[0];

        verify_rrsig(&link, rrsig, &key).expect("genuine signature verifies");
    }

    #[test]
    fn rrset_order_does_not_matter_but_content_does() {
        // Two records, framed in the order NOT matching canonical
        // RDATA order: canonical sorting must fix it.
        let (link, key) = signed_link(&[b"\x02zz", b"\x02aa"], "_onomancy.expede.wtf", 3);
        verify_rrsig(&link, &link.signatures()[0], &key).expect("order-insensitive");

        // A different RRset under the same signature must fail.
        let (tampered, _) = signed_link(&[b"\x02zz", b"\x02ab"], "_onomancy.expede.wtf", 3);
        assert_eq!(
            verify_rrsig(&tampered, &link.signatures()[0], &key),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn wildcard_expansion_reconstructs_the_signed_owner() {
        // Signed as *.expede.wtf (labels=2), answered at the full
        // owner name.
        let (link, key) = signed_link(&[b"\x04test"], "_onomancy.expede.wtf", 2);
        verify_rrsig(&link, &link.signatures()[0], &key).expect("wildcard reconstruction");
    }

    #[test]
    fn excess_label_counts_are_rejected() {
        let (link, key) = signed_link(&[b"\x04test"], "_onomancy.expede.wtf", 3);
        let mut preamble = link.signatures()[0].preamble().to_vec();
        preamble[3] = 9; // labels byte
        preamble.extend_from_slice(link.signatures()[0].signature());
        let forged = Rrsig::parse(&preamble).expect("frame parses");

        assert!(matches!(
            verify_rrsig(&link, &forged, &key),
            Err(VerifyError::LabelCount { .. })
        ));
    }

    #[test]
    fn non_zone_keys_never_verify() {
        let (link, key) = signed_link(&[b"\x04test"], "_onomancy.expede.wtf", 3);
        let mut rdata = key.rdata().to_vec();
        rdata[0] = 0;
        rdata[1] = 0; // clear ZONE
        let revoked = Dnskey::parse(&rdata).expect("parses");

        assert_eq!(
            verify_rrsig(&link, &link.signatures()[0], &revoked),
            Err(VerifyError::NotAZoneKey)
        );
    }

    #[test]
    fn unsupported_algorithms_are_invalid_not_insecure() {
        assert!(matches!(
            verify_signature(Algorithm(253), &[], b"m", &[]),
            Err(VerifyError::UnsupportedAlgorithm(Algorithm(253)))
        ));
    }

    #[test]
    fn ds_digest_commits_to_owner_and_key() {
        let (_, key) = signed_link(&[b"\x04test"], "_onomancy.expede.wtf", 3);
        let owner: Name = "expede.wtf".parse().expect("parses");

        let mut ds_rdata = Vec::new();
        ds_rdata.extend_from_slice(&key.key_tag().to_be_bytes());
        ds_rdata.push(Algorithm::ED25519.0);
        ds_rdata.push(DigestType::SHA256.0);
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
    }
}
