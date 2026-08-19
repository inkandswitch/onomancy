//! The signed-unit core: tag → fields → signature, verified at decode.
//!
//! The Keyhive/subduction `Signed<T>` pattern: every Onomancy signed
//! artifact — certificate, rotation statement, successor statement —
//! shares one skeleton, and this module implements it exactly once:
//!
//! ```text
//! ┌────────────┬───────────────────┬───────────┬──────────────────┐
//! │ P::TAG  4B │ P::encode_fields  │ signature │ unit-specific    │
//! │            │                   │    64B    │ unsigned tail    │
//! └────────────┴───────────────────┴───────────┴──────────────────┘
//!  └───────── signed region ──────┘             (carriage/attached,
//!                                                owned by the unit)
//! ```
//!
//! The signature is verified against the **received** bytes during
//! decoding — a unit that fails is undecodable, so holding a
//! `Signed<P>` is holding the proof. Unsigned tails deliberately stay
//! out of this abstraction: the statements' authority carriage and the
//! certificate's attached region have genuinely different shapes and
//! lifecycles, and two variants do not justify a `Tail` trait.

use alloc::vec::Vec;
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::wire::{Reader, WireError};

/// The fields inside a unit's signature.
pub trait Payload: Sized {
    /// The 4-byte schema tag (3 ASCII + version byte) that leads the
    /// signed region and domain-separates this unit kind.
    const TAG: [u8; 4];

    /// The unit's public decode-error type; signature and framing
    /// failures from the shared skeleton convert into it.
    type Error: From<WireError> + From<Malformed>;

    /// Append the payload fields (everything between tag and
    /// signature) in canonical order.
    fn encode_fields(&self, buf: &mut Vec<u8>);

    /// Strictly decode the payload fields. Decoders reject, never
    /// normalize.
    ///
    /// # Errors
    ///
    /// Returns the unit's decode error on any non-canonical or
    /// malformed field.
    fn decode_fields(reader: &mut Reader<'_>) -> Result<Self, Self::Error>;

    /// The key this unit's signature must verify under. For most
    /// units an explicit field; for rotation statements, the successor
    /// key itself.
    fn signer(&self) -> &VerifyingKey;
}

/// A shared-skeleton failure, converted into each unit's own error
/// type via `Payload::Error: From<Malformed>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Malformed {
    /// The signature over the signed region did not validate against
    /// the received bytes: the unit is undecodable, not merely
    /// unverified.
    #[error("signature does not validate over the signed region")]
    InvalidSignature,

    /// The unit does not begin with the expected tag — possibly
    /// another artifact's bytes offered where this unit was expected.
    #[error("expected tag {expected:?}, got {got:?}")]
    WrongTag {
        /// The tag this unit kind requires.
        expected: [u8; 4],
        /// The four bytes found.
        got: [u8; 4],
    },
}

/// A signature-checked payload: tag, fields, and the signature that
/// validated over their received bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Signed<P: Payload> {
    payload: P,
    signature: Signature,
}

impl<P: Payload> Signed<P> {
    /// Decode the signed skeleton from the front of `bytes` via
    /// `reader` (positioned at the start), verifying the signature
    /// against the received bytes. The reader is left at the unit's
    /// unsigned tail.
    pub(crate) fn decode_from(bytes: &[u8], reader: &mut Reader<'_>) -> Result<Self, P::Error> {
        let tag: [u8; 4] = reader.take_array().map_err(P::Error::from)?;
        if tag != P::TAG {
            return Err(Malformed::WrongTag {
                expected: P::TAG,
                got: tag,
            }
            .into());
        }

        let payload = P::decode_fields(reader)?;

        let signed_len = bytes.len() - reader.remaining();
        let signature = Signature::from_bytes(&reader.take_array().map_err(P::Error::from)?);

        // Verified against the RECEIVED bytes, while we hold them —
        // never against a re-encoding.
        let signed_region = bytes.get(..signed_len).unwrap_or_default();
        if payload
            .signer()
            .verify_strict(signed_region, &signature)
            .is_err()
        {
            return Err(Malformed::InvalidSignature.into());
        }

        Ok(Self { payload, signature })
    }

    /// Sign a payload. Crate-internal: unit constructors build the
    /// payload from the signing key's verifying key, so a
    /// payload-vs-key mismatch is unrepresentable at the public API.
    pub(crate) fn sign(payload: P, key: &SigningKey) -> Self {
        let mut region = Vec::new();
        region.extend_from_slice(&P::TAG);
        payload.encode_fields(&mut region);

        Self {
            signature: key.sign(&region),
            payload,
        }
    }

    /// Append the canonical signed skeleton (tag, fields, signature).
    pub(crate) fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&P::TAG);
        self.payload.encode_fields(buf);
        buf.extend_from_slice(&self.signature.to_bytes());
    }

    /// The rederived signed region (tag + fields): the signature
    /// target.
    #[must_use]
    pub fn signed_region(&self) -> Vec<u8> {
        let mut region = Vec::new();
        region.extend_from_slice(&P::TAG);
        self.payload.encode_fields(&mut region);
        region
    }

    /// The signature-checked fields.
    #[must_use]
    pub const fn payload(&self) -> &P {
        &self.payload
    }

    /// The signature over the signed region.
    #[must_use]
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl<P: Payload + fmt::Debug> fmt::Debug for Signed<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signed")
            .field("payload", &self.payload)
            .field("signature", &self.signature)
            .finish()
    }
}
