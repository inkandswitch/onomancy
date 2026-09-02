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

    /// The manual `PartialEq` (phantom-bound workaround) actually
    /// compares bytes: an `eq → true` mutation dies on the negative.
    #[test]
    fn digests_of_equal_bytes_agree_within_a_type() {
        assert_ne!(
            Digest::<Blake3, UnitA>::hash(b"payload"),
            Digest::<Blake3, UnitA>::hash(b"other")
        );
    }

    /// Known-answer pin: erased digests are PLAIN BLAKE3-256, no
    /// keying, no derivation, no domain separation. Every store
    /// address in the system silently changes if this moves — an
    /// interop contract, pinned against the published vector rather
    /// than against our own delegation one hop away.
    #[test]
    fn blake3_known_answer_pins_the_algorithm() {
        // BLAKE3("") from the official test vectors.
        const EMPTY: [u8; 32] = [
            0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
            0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
            0xe4, 0x1f, 0x32, 0x62,
        ];

        let digest = Digest::<Blake3, [u8]>::hash(b"");
        assert_eq!(*digest.as_bytes(), EMPTY);

        // Display is the lowercase hex of exactly those bytes.
        assert_eq!(
            alloc::string::ToString::to_string(&digest),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
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
        use core::{
            cmp::Ordering,
            hash::{Hash, Hasher},
        };

        use super::*;

        /// Captures written bytes so `Hash` coverage is observable
        /// without committing to any hasher's mixing function.
        #[derive(Default)]
        struct RecordingHasher {
            bytes: Vec<u8>,
        }

        impl Hasher for RecordingHasher {
            fn finish(&self) -> u64 {
                self.bytes.len() as u64
            }

            fn write(&mut self, bytes: &[u8]) {
                self.bytes.extend_from_slice(bytes);
            }
        }

        /// The manual `Eq`/`Ord`/`Hash`/`from_bytes` impls agree with
        /// each other and with raw byte order.
        #[test]
        fn manual_impls_agree_with_byte_order() {
            bolero::check!()
                .with_type::<([u8; 32], [u8; 32])>()
                .for_each(|(a, b)| {
                    let da = Digest::<Blake3, UnitA>::from_bytes(*a);
                    let db = Digest::<Blake3, UnitA>::from_bytes(*b);

                    assert_eq!(da.as_bytes(), a, "from_bytes is verbatim");
                    assert_eq!((da == db), (da.cmp(&db) == Ordering::Equal));
                    assert_eq!(da.cmp(&db), a.cmp(b), "digest order is byte order");
                    assert_eq!(da.cmp(&db), db.cmp(&da).reverse());
                    assert_eq!(
                        da.partial_cmp(&db),
                        Some(da.cmp(&db)),
                        "partial order agrees with the total order"
                    );

                    assert!(
                        !format!("{da:?}").is_empty(),
                        "debug output renders something"
                    );

                    // The manual `Hash` must feed the bytes to the
                    // hasher: the recorded stream carries the digest
                    // bytes themselves.
                    let mut sink = RecordingHasher::default();
                    da.hash(&mut sink);
                    assert!(
                        sink.bytes.ends_with(a),
                        "hash covers the digest bytes (modulo the slice length prefix)"
                    );
                });
        }
    }
}
