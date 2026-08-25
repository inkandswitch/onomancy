//! The DS digest-type code.
//!
//! The codes are DNS's, not ours: the IANA DS digest-type registry.

use core::fmt;

/// A DS digest-type code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DigestType(pub u8);

impl DigestType {
    /// SHA-256 (2) — the only type this implementation computes;
    /// everything else fails validation (the D13 doctrine applied to
    /// digests).
    pub const SHA256: Self = Self(2);

    /// Whether this implementation can compute the digest.
    #[must_use]
    pub const fn supported(self) -> bool {
        matches!(self, Self::SHA256)
    }
}

impl fmt::Display for DigestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SHA256 => f.write_str("SHA-256"),
            Self(code) => write!(f, "DIGEST{code}"),
        }
    }
}
