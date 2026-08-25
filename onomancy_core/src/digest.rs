//! Typed content digests: a digest of one unit kind is not a digest
//! of another.
//!
//! The Keyhive/subduction pattern, indexed twice: a digest carries a
//! marker for the hash algorithm that produced it AND for the unit
//! type it addresses, so digests of different artifact kinds — or the
//! same kind under different hash functions — are different types and
//! cannot be swapped by accident. Onomancy's own units always use
//! [`Blake3`]; other algorithms exist only where an external protocol
//! demands them, and live with the crate that speaks that protocol.
//!
//! The unit-agnostic form — what decisions-document entries and reset
//! exclusion sets hold, since they reference store items of any kind
//! (including items the local replica has never held) — is
//! `Digest<Blake3, [u8]>`: a hash of verbatim bytes, claiming no unit
//! type. It is obtained by deliberate [`erasure`](Digest::erase) from
//! typed `Blake3` digests only; there is no path back without
//! decoding actual bytes and re-hashing.
//!
//! Digests are computed over an item's **canonical wire bytes** — at
//! decode over the received bytes, at signing over the built bytes —
//! never over re-encoded or normalized forms.

use core::{any, cmp::Ordering, fmt, hash::Hash, marker::PhantomData};

/// An `A` digest of one `T` unit's canonical wire bytes.
pub struct Digest<A: HashAlgorithm, T: ?Sized> {
    bytes: [u8; 32],
    _marker: PhantomData<fn() -> (A, T)>,
}

impl<A: HashAlgorithm, T: ?Sized> Digest<A, T> {
    /// Digest a unit's canonical wire bytes.
    #[must_use]
    pub fn hash(canonical_bytes: &[u8]) -> Self {
        Self {
            bytes: A::hash(canonical_bytes),
            _marker: PhantomData,
        }
    }

    /// Adopt an externally computed digest verbatim (e.g. one parsed
    /// from a trust-anchor line or built by a streaming hasher).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes,
            _marker: PhantomData,
        }
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl<T: ?Sized> Digest<Blake3, T> {
    /// Erase the unit type: the store-level content identity over
    /// verbatim bytes. `Blake3` only — the store's addressing is
    /// single-algorithm by design.
    ///
    /// Two units differing only in unsigned attachments are the *same
    /// unit* but *different store items*, and their erased digests
    /// differ.
    #[must_use]
    pub const fn erase(self) -> Digest<Blake3, [u8]> {
        Digest {
            bytes: self.bytes,
            _marker: PhantomData,
        }
    }
}

// Manual impls: the phantoms must not impose bounds on `A` or `T`.

impl<A: HashAlgorithm, T: ?Sized> Clone for Digest<A, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A: HashAlgorithm, T: ?Sized> Copy for Digest<A, T> {}

impl<A: HashAlgorithm, T: ?Sized> PartialEq for Digest<A, T> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl<A: HashAlgorithm, T: ?Sized> Eq for Digest<A, T> {}

impl<A: HashAlgorithm, T: ?Sized> PartialOrd for Digest<A, T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<A: HashAlgorithm, T: ?Sized> Ord for Digest<A, T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl<A: HashAlgorithm, T: ?Sized> Hash for Digest<A, T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

impl<A: HashAlgorithm, T: ?Sized> fmt::Debug for Digest<A, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Digest<{}, {}>({self})",
            any::type_name::<A>(),
            any::type_name::<T>()
        )
    }
}

impl<A: HashAlgorithm, T: ?Sized> fmt::Display for Digest<A, T> {
    /// Lowercase hex, for logs and diagnostics (not a wire form).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.bytes {
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, A: HashAlgorithm, T: ?Sized> arbitrary::Arbitrary<'a> for Digest<A, T> {
    fn arbitrary(unstructured: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_bytes(unstructured.arbitrary()?))
    }
}

/// A hash function a [`Digest`] can be indexed by.
///
/// Implementors are zero-sized markers ([`Blake3`] here; externally
/// mandated algorithms live with the code that speaks them). Every algorithm
/// in use emits 32 bytes; if a wider one ever arrives (SHA-384 DS
/// digests would be the candidate), the width moves into the trait
/// then — not speculatively now.
pub trait HashAlgorithm {
    /// Hash one contiguous input.
    fn hash(input: &[u8]) -> [u8; 32];
}

/// BLAKE3-256: the hash for everything onomancy addresses itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Blake3;

impl HashAlgorithm for Blake3 {
    fn hash(input: &[u8]) -> [u8; 32] {
        *blake3::hash(input).as_bytes()
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
            Digest::<Blake3, UnitA>::hash(b"payload"),
            Digest::<Blake3, UnitA>::hash(b"payload")
        );
        assert_ne!(
            Digest::<Blake3, UnitA>::hash(b"payload"),
            Digest::<Blake3, UnitA>::hash(b"other")
        );
    }

    #[test]
    fn erasure_preserves_the_bytes() {
        let typed_a = Digest::<Blake3, UnitA>::hash(b"payload");
        let typed_b = Digest::<Blake3, UnitB>::hash(b"payload");

        // Different types (cannot even be compared directly); same
        // bytes after erasure — the store addresses items uniformly.
        assert_eq!(typed_a.erase(), typed_b.erase());
    }

    mod props {
        use alloc::vec::Vec;

        use super::*;

        /// Injective in practice: distinct bytes, distinct hashes
        /// (collision = broken BLAKE3, not broken code).
        #[test]
        fn verbatim_bytes_hash_stably() {
            bolero::check!().with_type::<Vec<u8>>().for_each(|bytes| {
                let erased = Digest::<Blake3, [u8]>::hash(bytes);
                assert_eq!(erased, Digest::<Blake3, [u8]>::hash(bytes));
                assert_eq!(*erased.as_bytes(), <Blake3 as HashAlgorithm>::hash(bytes));
            });
        }
    }
}
