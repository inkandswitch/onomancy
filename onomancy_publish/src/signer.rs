//! The signing capability: keys enter ceremonies through this and
//! nothing else.
//!
//! Ceremonies take a `Signer` as their last ingredient so intent can
//! be assembled keylessly and the key surfaces only at the edge —
//! matching the operational shape (cold admin keys come out for
//! genuine ceremonies only; refresh never needs one).

use ed25519_dalek::{SigningKey, VerifyingKey};

/// A held signing key, wrapped so call sites say what they are doing.
///
/// v0 is a plain in-memory key; the shape leaves room for an agent or
/// hardware-backed implementation behind the same surface later.
#[derive(Debug)]
pub struct Signer {
    key: SigningKey,
}

impl Signer {
    /// Wrap a held key.
    #[must_use]
    pub const fn new(key: SigningKey) -> Self {
        Self { key }
    }

    /// The verifying key this signer authenticates as.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// The underlying signing key, for the codec `sign` constructors.
    #[must_use]
    pub(crate) const fn key(&self) -> &SigningKey {
        &self.key
    }
}

impl From<SigningKey> for Signer {
    fn from(key: SigningKey) -> Self {
        Self::new(key)
    }
}
