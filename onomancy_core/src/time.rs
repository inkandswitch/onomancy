//! Time newtypes: seconds and milliseconds are different types.
//!
//! Certificate `issued_at` fields are seconds since the Unix epoch;
//! TXT serials follow a millisecond convention. Mixing the two is a
//! real reviewed-against bug class, so the units are distinct types
//! rather than a comment.

use core::fmt;

/// Seconds since the Unix epoch (UTC).
///
/// The certificate's `issued_at` unit. Signer-claimed — the weakest
/// rung of the comparison ladder, never load-bearing for security.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct UnixSeconds(u64);

impl UnixSeconds {
    /// The numeric value.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.0
    }
}

impl From<u64> for UnixSeconds {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<UnixSeconds> for u64 {
    fn from(seconds: UnixSeconds) -> Self {
        seconds.0
    }
}

impl fmt::Display for UnixSeconds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}s", self.0)
    }
}
