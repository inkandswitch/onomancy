//! Content addressing: BLAKE3-256 over verbatim wire bytes.

use core::fmt;

/// The content hash of a store item: BLAKE3-256 over the item's exact
/// wire bytes.
///
/// Judgment-document entries reference store items by content hash, so
/// the hash MUST be computed over verbatim bytes — never re-encoded or
/// normalized forms. Two certificates differing only in their attached
/// regions are the *same certificate* but *different store items*, and
/// they hash differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    /// Hash an item's verbatim wire bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    /// The raw hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for ContentHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for ContentHash {
    /// Lowercase hex, for logs and diagnostics (not a wire form).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod props {
        use super::*;
        use alloc::vec::Vec;

        /// Injective in practice: distinct bytes, distinct hashes
        /// (collision = broken BLAKE3, not broken code).
        #[test]
        fn verbatim_bytes_hash_stably() {
            bolero::check!().with_type::<Vec<u8>>().for_each(|bytes| {
                assert_eq!(ContentHash::of(bytes), ContentHash::of(bytes));

                let mut extended = bytes.clone();
                extended.push(0);
                assert_ne!(ContentHash::of(bytes), ContentHash::of(&extended));
            });
        }
    }
}
