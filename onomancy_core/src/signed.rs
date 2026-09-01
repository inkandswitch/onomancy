//! The signed-unit core: tag → fields → signature, verified at decode.
//!
//! The Keyhive/subduction `Signed<T>` pattern: every Onomancy signed
//! artifact shares one skeleton, and this module implements it
//! exactly once:
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
//! out of this abstraction: downstream unit kinds attach tails of
//! genuinely different shapes and lifecycles, and a handful of
//! variants does not justify a `Tail` trait.

use alloc::vec::Vec;
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey};

use crate::wire::Reader;

pub mod payload;

use self::payload::{Malformed, Payload};

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
    ///
    /// # Errors
    ///
    /// Returns the payload's own error for malformed fields, a bad
    /// tag, or a signature that does not verify.
    pub fn decode_from(bytes: &[u8], reader: &mut Reader<'_>) -> Result<Self, P::Error> {
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
    pub fn sign(payload: P, key: &SigningKey) -> Self {
        let region = Self::signable_region(&payload);

        Self {
            signature: key.sign(&region),
            payload,
        }
    }

    /// The bytes a signature must cover, for a payload not yet signed.
    ///
    /// This exists so a holder of the signing key can produce the
    /// signature **outside** this crate — a browser signing with a key
    /// its runtime already holds, where handing the key to a
    /// serializer would be the one thing worth avoiding.
    ///
    /// Shares its body with [`Self::sign`] and [`Self::signed_region`]
    /// deliberately. The three must agree byte for byte or every
    /// externally-signed unit verifies nowhere, and the failure would
    /// present as a bad key rather than as a layout disagreement.
    /// Calling one function is a stronger guarantee than testing three
    /// for equality.
    #[must_use]
    pub fn signable_region(payload: &P) -> Vec<u8> {
        let mut region = Vec::new();
        region.extend_from_slice(&P::TAG);
        payload.encode_fields(&mut region);

        region
    }

    /// Assemble from a payload and a signature produced elsewhere.
    ///
    /// The verifying key is **not** a parameter: [`Payload::signer`]
    /// already carries it, and accepting a second copy would allow a
    /// disagreement between them that has no correct resolution.
    ///
    /// The signature is verified here rather than trusted. Every
    /// `Signed` in this crate holds a signature that validated over
    /// its own bytes — [`Self::decode_from`] maintains it on the way
    /// in — and a constructor that skipped the check would make the
    /// type's central invariant conditional on who built the value.
    ///
    /// # Errors
    ///
    /// Returns [`Malformed::InvalidSignature`] when the signature does
    /// not verify under the payload's own signer.
    pub fn try_from_parts(payload: P, signature: Signature) -> Result<Self, Malformed> {
        let region = Self::signable_region(&payload);

        if payload.signer().verify_strict(&region, &signature).is_err() {
            return Err(Malformed::InvalidSignature);
        }

        Ok(Self { payload, signature })
    }

    /// Append the canonical signed skeleton (tag, fields, signature).
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&P::TAG);
        self.payload.encode_fields(buf);
        buf.extend_from_slice(&self.signature.to_bytes());
    }

    /// The rederived signed region (tag + fields): the signature
    /// target.
    #[must_use]
    pub fn signed_region(&self) -> Vec<u8> {
        Self::signable_region(&self.payload)
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
