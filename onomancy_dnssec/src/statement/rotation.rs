//! The rotation statement (`ONR\x00`): Gₙ is replaced by Gₙ₊₁.
//!
//! # Wire Format
//!
//! | # | Field             | Type            | Width  | Notes                             | Signed |
//! |---|-------------------|-----------------|--------|-----------------------------------|--------|
//! | 0 | tag               | magic bytes     | 4B     | `ONR\x00`                         | yes    |
//! | 1 | `root_doc`        | ed25519 vk      | 32B    | document whose generation rotates | yes    |
//! | 2 | `replaced`        | ed25519 vk      | 32B    | Gₙ, the generation key retired    | yes    |
//! | 3 | `successor`       | ed25519 vk      | 32B    | Gₙ₊₁; also the signer             | yes    |
//! | 4 | `signature`       | ed25519         | 64B    | by `successor` over fields 0–3    | —      |
//! | 5 | `authority_count` | bijou64         | varies |                                   | no     |
//! | 6 | `authority`       | entry list      | varies | len-prefixed carriage entries     | no     |
//!
//! No hostname appears, deliberately: a revoked generation must die
//! across every name bound to the document in one ceremony, and
//! `root_doc` inside the signature prevents cross-document lineage
//! replay under key reuse.
//!
//! The unit is [`Signed<Rotation>`](onomancy_core::signed::Signed) plus its
//! authority carriage; decoded units rederive their canonical bytes
//! ([`encode`](RotationStatement::encode)) rather than retaining them.

use alloc::vec::Vec;
use core::hash::{Hash, Hasher};
use ed25519_dalek::{SigningKey, VerifyingKey};

use onomancy_core::{
    anchor::doc::DocAnchor,
    delegation_chain::DelegationChain,
    digest::{Blake3, Digest},
    signed::{
        Signed,
        payload::{Malformed, Payload},
    },
    wire::{self, OversizeUnit, Reader, WireError},
};

use crate::txt::generation_key::GenerationKey;

/// A decoded, signature-checked rotation statement unit:
/// [`Signed<Rotation>`] traveling with its authority carriage.
///
/// The signature is bytes-level truth only: whether the signer speaks
/// for the document is the carriage's claim, checked by Keyhive
/// verification (`AuthorityVerifier`), not here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationStatement {
    digest: Digest<Blake3, RotationStatement>,
    signed: Signed<Rotation>,
    authority: DelegationChain,
}

impl RotationStatement {
    /// Strictly decode one self-contained unit, verifying its
    /// signature against the received bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeRotationError`] on a foreign or future format
    /// tag (cross-tag confusion fails here, by design), key bytes that
    /// are not curve points, any framing violation, trailing bytes, or
    /// a signature that does not validate.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeRotationError> {
        let mut reader = Reader::new(bytes)?;
        let signed = Signed::decode_from(bytes, &mut reader)?;
        let authority = DelegationChain::decode(&mut reader)?;
        reader.finish()?;

        Ok(Self {
            digest: Digest::hash(bytes),
            signed,
            authority,
        })
    }

    /// Construct and sign a rotation statement. The signer IS the
    /// successor generation key.
    ///
    /// # Errors
    ///
    /// Returns [`OversizeUnit`] when the unit would exceed the 1 MiB
    /// cap — encoders MUST NOT build units their own decoders reject.
    pub fn sign(
        root_doc: &DocAnchor,
        replaced: &GenerationKey,
        successor: &SigningKey,
        authority: DelegationChain,
    ) -> Result<Self, OversizeUnit> {
        let signed = Signed::sign(
            Rotation {
                root_doc: *root_doc,
                replaced: *replaced,
                successor: GenerationKey::from(successor.verifying_key()),
            },
            successor,
        )
        .unwrap_or_else(|_| unreachable!("the rotation names this signer's verifying key"));

        let mut bytes = Vec::new();
        signed.encode_into(&mut bytes);
        authority.encode_into(&mut bytes);
        wire::check_unit_len(bytes.len())?;

        Ok(Self {
            digest: Digest::hash(&bytes),
            signed,
            authority,
        })
    }

    /// Rederive the canonical wire bytes: `encode(decode(b)) = b`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.signed.encode_into(&mut bytes);
        self.authority.encode_into(&mut bytes);

        bytes
    }

    /// The typed digest of the unit's canonical bytes, computed over
    /// the received (or built) bytes and cached; erase via `.into()`
    /// for the store-level form via [`erase`](onomancy_core::digest::Digest::erase).
    #[must_use]
    pub const fn digest(&self) -> Digest<Blake3, RotationStatement> {
        self.digest
    }

    /// The document whose generation is rotating.
    #[must_use]
    pub const fn root_doc(&self) -> &DocAnchor {
        &self.signed.payload().root_doc
    }

    /// The retired generation key Gₙ.
    #[must_use]
    pub const fn replaced(&self) -> &GenerationKey {
        &self.signed.payload().replaced
    }

    /// The successor generation key Gₙ₊₁ — also the unit's signer.
    #[must_use]
    pub const fn successor(&self) -> &GenerationKey {
        &self.signed.payload().successor
    }

    /// The authority carriage: verbatim `Signed<Delegation>` entries,
    /// awaiting Keyhive verification (roots at
    /// [`root_doc`](Self::root_doc), terminates at
    /// [`successor`](Self::successor), admin-held delegating hop).
    #[must_use]
    pub const fn authority(&self) -> &DelegationChain {
        &self.authority
    }
}

impl Hash for RotationStatement {
    /// By digest, which the canonical bytes determine.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}

/// The signed fields: `root_doc`'s generation `replaced` (Gₙ) is
/// retired in favor of `successor` (Gₙ₊₁), attested by the successor
/// key itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rotation {
    root_doc: DocAnchor,
    replaced: GenerationKey,
    successor: GenerationKey,
}

impl Payload for Rotation {
    const TAG: [u8; 4] = *b"ONR\x00";

    type Error = DecodeRotationError;

    fn encode_fields(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.root_doc.verifying_key().as_bytes());
        buf.extend_from_slice(self.replaced.verifying_key().as_bytes());
        buf.extend_from_slice(self.successor.verifying_key().as_bytes());
    }

    fn decode_fields(reader: &mut Reader<'_>) -> Result<Self, DecodeRotationError> {
        Ok(Self {
            root_doc: DocAnchor::from(read_key(reader, FieldName::RootDoc)?),
            replaced: GenerationKey::from(read_key(reader, FieldName::Replaced)?),
            successor: GenerationKey::from(read_key(reader, FieldName::Successor)?),
        })
    }

    /// The signer IS the successor generation key.
    fn signer(&self) -> &VerifyingKey {
        self.successor.verifying_key()
    }
}

/// Read one 32-byte field as an ed25519 verifying key.
fn read_key(
    reader: &mut Reader<'_>,
    field: FieldName,
) -> Result<VerifyingKey, DecodeRotationError> {
    let bytes: [u8; 32] = reader.take_array()?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| DecodeRotationError::NotACurvePoint { field })
}

/// Which fixed-width key field a decode error pinpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldName {
    /// Field 1: the rotating document.
    RootDoc,
    /// Field 2: Gₙ.
    Replaced,
    /// Field 3: Gₙ₊₁ / signer.
    Successor,
}

/// The bytes were not a canonical, validly signed `ONR\x00` unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeRotationError {
    /// The signed skeleton failed: wrong tag (cross-tag confusion) or
    /// an invalid signature.
    #[error(transparent)]
    Malformed(#[from] Malformed),

    /// A key field was not a valid curve point.
    #[error("rotation statement field {field:?} is not an ed25519 key")]
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
    use onomancy_core::delegation_chain::SignedDelegationBytes;

    /// Signed-region length: tag + three keys.
    const SIGNED_LEN: usize = 4 + 32 + 32 + 32;

    fn doc(seed: u8) -> DocAnchor {
        DocAnchor::from(SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    fn gen_key(seed: u8) -> GenerationKey {
        GenerationKey::from(SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    fn sample() -> RotationStatement {
        RotationStatement::sign(
            &doc(1),
            &gen_key(2),
            &SigningKey::from_bytes(&[3; 32]),
            DelegationChain::from(vec![SignedDelegationBytes::from(vec![0xAB; 5])]),
        )
        .expect("under the unit cap")
    }

    #[test]
    fn sign_encode_decode_roundtrips_to_identical_bytes() {
        let statement = sample();
        let bytes = statement.encode();

        let decoded = RotationStatement::decode(&bytes).expect("own encoding decodes");
        assert_eq!(statement, decoded);
        assert_eq!(bytes, decoded.encode(), "encode ∘ decode = identity");
        assert_eq!(statement.digest(), decoded.digest());

        assert_eq!(decoded.root_doc(), &doc(1));
        assert_eq!(decoded.replaced(), &gen_key(2));
        assert_eq!(decoded.successor(), &gen_key(3));
    }

    #[test]
    fn cross_tag_confusion_fails_at_decode() {
        let mut bytes = sample().encode();
        bytes[..4].copy_from_slice(b"ONS\x00");
        assert!(matches!(
            RotationStatement::decode(&bytes),
            Err(DecodeRotationError::Malformed(Malformed::WrongTag { got, .. }))
                if got == *b"ONS\x00"
        ));
    }

    #[test]
    fn invalid_signatures_are_undecodable() {
        let mut bytes = sample().encode();
        bytes[SIGNED_LEN] ^= 0x01; // first signature byte

        assert!(matches!(
            RotationStatement::decode(&bytes),
            Err(DecodeRotationError::Malformed(Malformed::InvalidSignature))
        ));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = sample().encode();
        bytes.push(0);
        assert!(matches!(
            RotationStatement::decode(&bytes),
            Err(DecodeRotationError::Wire(WireError::TrailingBytes {
                extra: 1
            }))
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
                    let authority: DelegationChain = blobs
                        .iter()
                        .cloned()
                        .map(SignedDelegationBytes::from)
                        .collect();

                    let statement = RotationStatement::sign(
                        &doc(*a),
                        &gen_key(*b),
                        &SigningKey::from_bytes(&[*c; 32]),
                        authority.clone(),
                    )
                    .expect("under the unit cap");
                    let bytes = statement.encode();

                    let decoded = RotationStatement::decode(&bytes).expect("own encoding decodes");
                    assert_eq!(statement, decoded);
                    assert_eq!(bytes, decoded.encode(), "byte identity");
                    assert_eq!(decoded.authority(), &authority);
                });
        }

        /// Any bit flip inside the signed region kills the unit at
        /// decode: strictness catches it, or the signature does.
        #[test]
        fn signed_region_is_tamper_evident() {
            bolero::check!()
                .with_type::<(usize, u8)>()
                .for_each(|(at, mask)| {
                    let statement = sample();
                    let mut bytes = statement.encode();
                    let at = at % SIGNED_LEN;
                    let mask = if *mask == 0 { 1 } else { *mask };

                    bytes[at] ^= mask;

                    assert!(
                        RotationStatement::decode(&bytes).is_err(),
                        "tampered signed region must not decode"
                    );
                });
        }
    }
}
