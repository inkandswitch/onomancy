//! Typed content digests: `Digest<Certificate>` is not
//! `Digest<RotationStatement>`.
//!
//! The Keyhive/subduction pattern: a BLAKE3-256 digest carrying a
//! phantom marker for the unit type it addresses, so digests of
//! different artifact kinds are different types and cannot be swapped
//! by accident. The unit-agnostic form — what decisions-document
//! entries and reset exclusion sets hold, since they reference store
//! items of any kind — is [`ContentHash`](crate::content_hash::ContentHash),
//! obtained by erasure (`.into()`).
//!
//! Digests are computed over an item's **canonical wire bytes** — at
//! decode over the received bytes, at signing over the built bytes —
//! never over re-encoded or normalized forms.

use core::{any, cmp::Ordering, fmt, hash::Hash, marker::PhantomData};

use crate::content_hash::ContentHash;

/// A BLAKE3-256 digest of one `T` unit's canonical wire bytes.
pub struct Digest<T: ?Sized> {
    bytes: [u8; 32],
    _unit: PhantomData<fn() -> T>,
}

impl<T: ?Sized> Digest<T> {
    /// Digest a unit's canonical wire bytes.
    #[must_use]
    pub fn hash(canonical_bytes: &[u8]) -> Self {
        Self {
            bytes: *blake3::hash(canonical_bytes).as_bytes(),
            _unit: PhantomData,
        }
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl<T: ?Sized> From<Digest<T>> for ContentHash {
    /// Erase the unit type: the store-level content hash.
    fn from(digest: Digest<T>) -> Self {
        Self::from(digest.bytes)
    }
}

// Manual impls: the phantom must not impose bounds on `T`.

impl<T: ?Sized> Clone for Digest<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> Copy for Digest<T> {}

impl<T: ?Sized> PartialEq for Digest<T> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<T: ?Sized> Eq for Digest<T> {}

impl<T: ?Sized> PartialOrd for Digest<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: ?Sized> Ord for Digest<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl<T: ?Sized> Hash for Digest<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<T: ?Sized> fmt::Debug for Digest<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest<{}>({self})", any::type_name::<T>())
    }
}

impl<T: ?Sized> fmt::Display for Digest<T> {
    /// Lowercase hex, for logs and diagnostics (not a wire form).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.bytes {
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UnitA;
    struct UnitB;

    #[test]
    fn digests_of_equal_bytes_agree_within_a_type() {
        assert_eq!(
            Digest::<UnitA>::hash(b"payload"),
            Digest::<UnitA>::hash(b"payload")
        );
        assert_ne!(
            Digest::<UnitA>::hash(b"payload"),
            Digest::<UnitA>::hash(b"other")
        );
    }

    #[test]
    fn erasure_preserves_the_bytes() {
        let typed_a = Digest::<UnitA>::hash(b"payload");
        let typed_b = Digest::<UnitB>::hash(b"payload");

        // Different types (cannot even be compared directly); same
        // bytes after erasure — the store addresses items uniformly.
        let erased_a = ContentHash::from(typed_a);
        let erased_b = ContentHash::from(typed_b);
        assert_eq!(erased_a, erased_b);
    }
}
