//! The payload contract a signed unit wraps.

use alloc::vec::Vec;

use ed25519_dalek::VerifyingKey;

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

    /// The key this unit's signature must verify under — an explicit
    /// field on most units, derived from the payload on some.
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
