//! DNSSEC security algorithm codes.
//!
//! Onomancy's D13 rule: an **unsupported algorithm is invalid ✗**,
//! never insecure-but-ok — RFC 4035's treat-unknown-as-insecure
//! behavior would be an algorithm-downgrade path for a KSK-rooted
//! binding, so this crate inverts it.

use core::fmt;

/// A security algorithm code (RFC 4034 Appendix A registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Algorithm(pub u8);

impl Algorithm {
    /// ECDSA Curve P-256 with SHA-256 (13).
    pub const ECDSA_P256_SHA256: Self = Self(13);
    /// Ed25519 (15).
    pub const ED25519: Self = Self(15);
    /// RSA/SHA-256 (8).
    pub const RSA_SHA256: Self = Self(8);

    /// Whether this implementation can verify signatures under the
    /// algorithm. Everything else fails validation (D13).
    #[must_use]
    pub const fn supported(self) -> bool {
        matches!(
            self,
            Self::RSA_SHA256 | Self::ECDSA_P256_SHA256 | Self::ED25519
        )
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::ECDSA_P256_SHA256 => f.write_str("ECDSAP256SHA256"),
            Self::ED25519 => f.write_str("ED25519"),
            Self::RSA_SHA256 => f.write_str("RSASHA256"),
            Self(code) => write!(f, "ALG{code}"),
        }
    }
}
