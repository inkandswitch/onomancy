//! The attested generation key (`g=`).

use core::{cmp::Ordering, fmt};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::VerifyingKey;

/// The current generation key: the attested chokepoint that certificate
/// delegation chains must thread as an authority-carrying hop.
///
/// A distinct newtype from [`DocAnchor`](onomancy_core::anchor::doc::DocAnchor)
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

/// The wire spelling: canonical padded base64 of the key bytes, as
/// the `g=` field carries it.
impl fmt::Display for GenerationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&BASE64.encode(self.0.as_bytes()))
    }
}

impl PartialOrd for GenerationKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GenerationKey {
    /// By key bytes, matching `DocAnchor`'s convention.
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}
