//! The attested generation key (`g=`).

use ed25519_dalek::VerifyingKey;

/// The current generation key: the attested chokepoint that certificate
/// delegation chains must thread as an authority-carrying hop.
///
/// A distinct newtype from [`DocAnchor`](crate::name::doc::DocAnchor)
/// on purpose — generation keys and document IDs are both ed25519
/// keys, and confusing them is exactly the kind of bug newtypes exist
/// to make unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenerationKey(VerifyingKey);

impl GenerationKey {
    /// The underlying verifying key.
    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.0
    }
}

impl From<VerifyingKey> for GenerationKey {
    fn from(key: VerifyingKey) -> Self {
        Self(key)
    }
}
