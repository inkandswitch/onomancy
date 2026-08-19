//! The successor statement (`ONS\x00`): document migration under one
//! hostname.
//!
//! # Wire Format
//!
//! ```text
//! ┌─────────┬─────────────────┬───────────────┬────────┬──────────────┬───────────┬──────────────┐
//! │ ONS\x00 │ predecessor_doc │ successor_doc │ signer │ hostname     │ signature │ carriage     │
//! │   4B    │      32B        │     32B       │  32B   │ len + bytes  │   64B     │ count+entries│
//! └─────────┴─────────────────┴───────────────┴────────┴──────────────┴───────────┴──────────────┘
//!  └───────────────────── signed (fields 0–5) ─────────────────────────┘
//! ```
//!
//! The hostname is inside the signature, deliberately: migration is
//! per-name, and an unscoped proof could be replayed under a different
//! name to disguise capture as continuity.
//!
//! The unit is [`Signed<Succession>`](crate::signed::Signed) plus its
//! authority carriage; decoded units rederive their canonical bytes
//! ([`encode`](SuccessorStatement::encode)) rather than retaining them.

use alloc::vec::Vec;
use core::hash::{Hash, Hasher};
use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::{
    delegation::{self, DelegationBytes},
    digest::Digest,
    name::{
        dns::{CanonicalDnsNameError, DnsName},
        doc::DocAnchor,
    },
    signed::{Malformed, Payload, Signed},
    wire::{self, Reader, WireError},
};

/// The signed fields: `predecessor_doc` names `successor_doc` as its
/// continuation under `hostname`, attested by a delegated admin key of
/// the *predecessor* document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Succession {
    predecessor_doc: DocAnchor,
    successor_doc: DocAnchor,
    signer: VerifyingKey,
    hostname: DnsName,
}

impl Payload for Succession {
    const TAG: [u8; 4] = *b"ONS\x00";

    type Error = DecodeSuccessorError;

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.predecessor_doc.verifying_key().as_bytes());
        buf.extend_from_slice(self.successor_doc.verifying_key().as_bytes());
        buf.extend_from_slice(self.signer.as_bytes());
        wire::put_varint(buf, self.hostname.as_str().len() as u64);
        buf.extend_from_slice(self.hostname.as_str().as_bytes());
    }

    fn decode_fields(reader: &mut Reader<'_>) -> Result<Self, DecodeSuccessorError> {
        let predecessor_doc = DocAnchor::from(read_key(reader, FieldName::PredecessorDoc)?);
        let successor_doc = DocAnchor::from(read_key(reader, FieldName::SuccessorDoc)?);
        let signer = read_key(reader, FieldName::Signer)?;

        let hostname_len = reader.bounded_len(1)?;
        let hostname = DnsName::from_canonical(reader.take(hostname_len)?)?;

        Ok(Self {
            predecessor_doc,
            successor_doc,
            signer,
            hostname,
        })
    }

    fn signer(&self) -> &VerifyingKey {
        &self.signer
    }
}

/// A decoded, signature-checked successor statement unit:
/// [`Signed<Succession>`] traveling with its authority carriage.
///
/// The signature is bytes-level truth only: whether the signer speaks
/// for the predecessor document is the carriage's claim, checked by
/// Keyhive verification, not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuccessorStatement {
    digest: Digest<SuccessorStatement>,
    signed: Signed<Succession>,
    authority: Vec<DelegationBytes>,
}

impl SuccessorStatement {
    /// Strictly decode one self-contained unit, verifying its
    /// signature against the received bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeSuccessorError`] on a foreign or future format
    /// tag, key bytes that are not curve points, a non-canonical
    /// hostname (decoders reject rather than normalize), any framing
    /// violation, trailing bytes, or a signature that does not
    /// validate.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeSuccessorError> {
        let mut reader = Reader::new(bytes)?;
        let signed = Signed::decode_from(bytes, &mut reader)?;
        let authority = delegation::read_entries(&mut reader)?;
        reader.finish()?;

        Ok(Self {
            digest: Digest::hash(bytes),
            signed,
            authority,
        })
    }

    /// Construct and sign a successor statement with a delegated admin
    /// key of the predecessor document.
    #[must_use]
    pub fn sign(
        predecessor_doc: &DocAnchor,
        successor_doc: &DocAnchor,
        hostname: &DnsName,
        signer: &SigningKey,
        authority: Vec<DelegationBytes>,
    ) -> Self {
        let signed_unit = Signed::sign(
            Succession {
                predecessor_doc: *predecessor_doc,
                successor_doc: *successor_doc,
                signer: signer.verifying_key(),
                hostname: hostname.clone(),
            },
            signer,
        );

        let mut bytes = Vec::new();
        signed_unit.encode_into(&mut bytes);
        delegation::write_entries(&mut bytes, &authority);

        Self {
            digest: Digest::hash(&bytes),
            signed: signed_unit,
            authority,
        }
    }

    /// Rederive the canonical wire bytes: `encode(decode(b)) = b`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.signed.encode_into(&mut bytes);
        delegation::write_entries(&mut bytes, &self.authority);

        bytes
    }

    /// The typed digest of the unit's canonical bytes, computed over
    /// the received (or built) bytes and cached; erase via `.into()`
    /// for the store-level `ContentHash`.
    #[must_use]
    pub const fn digest(&self) -> Digest<SuccessorStatement> {
        self.digest
    }

    /// The unit's signer — a delegated admin key of the predecessor
    /// document, per the carriage's (Keyhive-checked) claim.
    #[must_use]
    pub const fn signer(&self) -> &VerifyingKey {
        &self.signed.payload().signer
    }

    /// The document being migrated away from.
    #[must_use]
    pub const fn predecessor_doc(&self) -> &DocAnchor {
        &self.signed.payload().predecessor_doc
    }

    /// The document continuing the identity.
    #[must_use]
    pub const fn successor_doc(&self) -> &DocAnchor {
        &self.signed.payload().successor_doc
    }

    /// The hostname this migration proof is scoped to. Certificates
    /// MUST check it against their own hostname.
    #[must_use]
    pub const fn hostname(&self) -> &DnsName {
        &self.signed.payload().hostname
    }

    /// The authority carriage: verbatim `Signed<Delegation>` entries,
    /// awaiting Keyhive verification (roots at
    /// [`predecessor_doc`](Self::predecessor_doc), terminates at the
    /// signer, admin-held delegating hop).
    #[must_use]
    pub fn authority(&self) -> &[DelegationBytes] {
        &self.authority
    }
}

impl Hash for SuccessorStatement {
    /// By digest, which the canonical bytes determine.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}

/// Read one 32-byte field as an ed25519 verifying key.
fn read_key(
    reader: &mut Reader<'_>,
    field: FieldName,
) -> Result<VerifyingKey, DecodeSuccessorError> {
    let bytes: [u8; 32] = reader.take_array()?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| DecodeSuccessorError::NotACurvePoint { field })
}

/// Which fixed-width key field a decode error pinpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldName {
    /// Field 1: the document being migrated away from.
    PredecessorDoc,
    /// Field 2: the continuing document.
    SuccessorDoc,
    /// Field 3: the delegated admin key that signed.
    Signer,
}

/// The bytes were not a canonical, validly signed `ONS\x00` unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeSuccessorError {
    /// The hostname bytes were not the canonical spelling of a DNS
    /// name. Decoders reject rather than normalize.
    #[error("hostname: {0}")]
    Hostname(#[from] CanonicalDnsNameError),

    /// The signed skeleton failed: wrong tag (cross-tag confusion) or
    /// an invalid signature.
    #[error(transparent)]
    Malformed(#[from] Malformed),

    /// A key field was not a valid curve point.
    #[error("successor statement field {field:?} is not an ed25519 key")]
    NotACurvePoint {
        /// The offending field.
        field: FieldName,
    },

    /// A framing violation: truncation, length overrun, trailing
    /// bytes, size cap, or a bad varint.
    #[error(transparent)]
    Wire(#[from] WireError),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use alloc::vec;

    fn doc(seed: u8) -> DocAnchor {
        DocAnchor::from(SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    fn host() -> DnsName {
        DnsName::parse("expede.wtf").expect("valid")
    }

    fn sample() -> SuccessorStatement {
        SuccessorStatement::sign(
            &doc(1),
            &doc(2),
            &host(),
            &SigningKey::from_bytes(&[3; 32]),
            vec![DelegationBytes::from(vec![0xCD; 7])],
        )
    }

    fn signed_len(statement: &SuccessorStatement) -> usize {
        statement.signed.signed_region().len()
    }

    #[test]
    fn sign_encode_decode_roundtrips_to_identical_bytes() {
        let statement = sample();
        let bytes = statement.encode();

        let decoded = SuccessorStatement::decode(&bytes).expect("own encoding decodes");
        assert_eq!(statement, decoded);
        assert_eq!(bytes, decoded.encode(), "encode ∘ decode = identity");
        assert_eq!(statement.digest(), decoded.digest());

        assert_eq!(decoded.predecessor_doc(), &doc(1));
        assert_eq!(decoded.successor_doc(), &doc(2));
        assert_eq!(decoded.hostname(), &host());
    }

    #[test]
    fn cross_tag_confusion_fails_at_decode() {
        let mut bytes = sample().encode();
        bytes[..4].copy_from_slice(b"ONR\x00");
        assert!(matches!(
            SuccessorStatement::decode(&bytes),
            Err(DecodeSuccessorError::Malformed(Malformed::WrongTag { got, .. }))
                if got == *b"ONR\x00"
        ));
    }

    #[test]
    fn non_canonical_hostnames_are_rejected_not_normalized() {
        // Uppercase one hostname byte: framing still parses, but the
        // bytes are not canonical (grammar check precedes signature).
        let mut bytes = sample().encode();

        let needle = b"expede.wtf";
        let at = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("hostname present");
        bytes[at] = b'E';

        assert!(matches!(
            SuccessorStatement::decode(&bytes),
            Err(DecodeSuccessorError::Hostname(
                CanonicalDnsNameError::NotCanonical
            ))
        ));
    }

    #[test]
    fn hostname_tampering_fails_the_signature() {
        // Same-length, still-canonical hostname swap must be caught by
        // the signature check at decode.
        let mut bytes = sample().encode();

        let needle = b"expede.wtf";
        let at = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("hostname present");
        bytes[at..at + needle.len()].copy_from_slice(b"attack.wtf");

        assert!(matches!(
            SuccessorStatement::decode(&bytes),
            Err(DecodeSuccessorError::Malformed(Malformed::InvalidSignature))
        ));
    }

    mod props {
        use super::*;

        /// Byte identity: sign → encode → decode → encode.
        #[test]
        fn encode_decode_byte_identity() {
            bolero::check!()
                .with_type::<(u8, u8, u8, Vec<Vec<u8>>)>()
                .for_each(|(a, b, c, blobs)| {
                    let authority: Vec<DelegationBytes> =
                        blobs.iter().cloned().map(DelegationBytes::from).collect();

                    let statement = SuccessorStatement::sign(
                        &doc(*a),
                        &doc(*b),
                        &host(),
                        &SigningKey::from_bytes(&[*c; 32]),
                        authority.clone(),
                    );
                    let bytes = statement.encode();

                    let decoded = SuccessorStatement::decode(&bytes).expect("own encoding decodes");
                    assert_eq!(statement, decoded);
                    assert_eq!(bytes, decoded.encode(), "byte identity");
                    assert_eq!(decoded.authority(), authority.as_slice());
                });
        }

        /// Any bit flip inside the signed region kills the unit at
        /// decode.
        #[test]
        fn signed_region_is_tamper_evident() {
            bolero::check!()
                .with_type::<(usize, u8)>()
                .for_each(|(at, mask)| {
                    let statement = sample();
                    let mut bytes = statement.encode();
                    let at = at % signed_len(&statement);
                    let mask = if *mask == 0 { 1 } else { *mask };

                    bytes[at] ^= mask;

                    assert!(
                        SuccessorStatement::decode(&bytes).is_err(),
                        "tampered signed region must not decode"
                    );
                });
        }
    }
}
