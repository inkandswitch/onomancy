//! Verbatim Keyhive `Signed<Delegation>` bytes and their framing.
//!
//! Onomancy carries delegation proofs — the authority carriage every
//! signed unit attaches or embeds — as length-prefixed, otherwise
//! **opaque** blobs of Keyhive's own wire encoding. This codec never
//! re-encodes, canonicalizes, or introspects them; they are
//! interpreted only by Keyhive verification (the `AuthorityVerifier`
//! seam, implemented in `onomancy_keyhive`).
//!
//! ```text
//! count as bijou64
//! repeat count times:
//!     entry_len as bijou64
//!     entry_len bytes: verbatim Keyhive Signed<Delegation>
//! ```

use alloc::vec::Vec;

use crate::wire::{self, Reader, WireError};

/// An authority carriage: verbatim Keyhive `Signed<Delegation>` units,
/// doc root → signer, opaque at this layer.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct DelegationChain(Vec<SignedDelegationBytes>);

impl DelegationChain {
    /// Decode a standalone count-prefixed carriage (the framing used
    /// for carriage FILES — e.g. the dev bridge's `<anchor>.carriage`).
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] on truncation, length overrun, or
    /// trailing bytes.
    pub fn read_framed(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes)?;
        let chain = Self::decode(&mut reader)?;
        reader.finish()?;
        Ok(chain)
    }

    /// Encode as a standalone count-prefixed carriage (see
    /// [`read_framed`](Self::read_framed)).
    pub fn write_framed(&self, buf: &mut Vec<u8>) {
        self.encode_into(buf);
    }

    /// Decode one count-prefixed entry list from a unit in progress.
    ///
    /// Entries are collected without a count-sized pre-allocation: the
    /// wire-minimum entry is one byte, but each decoded entry costs a
    /// `Vec` header, so trusting the declared count would let a small
    /// unit reserve outsized memory before the first entry fails.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] on truncated or over-cap entry framing.
    pub fn decode(reader: &mut Reader<'_>) -> Result<Self, WireError> {
        let count = reader.bounded_len(1)?;
        let mut entries = Vec::new();

        for _ in 0..count {
            let len = reader.bounded_len(1)?;
            entries.push(SignedDelegationBytes(reader.take(len)?.to_vec()));
        }

        Ok(Self(entries))
    }

    /// Append as one count-prefixed entry list.
    pub fn encode_into(&self, buf: &mut Vec<u8>) {
        wire::put_varint(buf, self.0.len() as u64);

        for entry in &self.0 {
            wire::put_varint(buf, entry.0.len() as u64);
            buf.extend_from_slice(&entry.0);
        }
    }

    /// The carriage entries, doc root → signer.
    #[must_use]
    pub fn entries(&self) -> &[SignedDelegationBytes] {
        &self.0
    }

    /// The number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the carriage is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<SignedDelegationBytes>> for DelegationChain {
    fn from(entries: Vec<SignedDelegationBytes>) -> Self {
        Self(entries)
    }
}

impl FromIterator<SignedDelegationBytes> for DelegationChain {
    fn from_iter<I: IntoIterator<Item = SignedDelegationBytes>>(entries: I) -> Self {
        Self(entries.into_iter().collect())
    }
}

/// One verbatim Keyhive `Signed<Delegation>` unit, opaque at this layer.
///
/// Semantic checks — that a chain roots at the right document,
/// terminates at the right signer, and holds admin access at the
/// delegating hop — belong to Keyhive verification, not this codec.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SignedDelegationBytes(Vec<u8>);

impl SignedDelegationBytes {
    /// The verbatim Keyhive wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SignedDelegationBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// A count the input cannot back fails before any entry
    /// allocation — the "trust the count" mutation the decode doc
    /// comment warns about.
    #[test]
    fn hostile_counts_are_rejected_before_allocation() {
        let mut bytes = Vec::new();
        wire::put_varint(&mut bytes, 5); // declares 5 entries, provides 0

        assert!(matches!(
            DelegationChain::read_framed(&bytes),
            Err(WireError::LengthOverrun {
                declared: 5,
                have: 0
            })
        ));
    }

    mod props {
        use super::*;

        #[test]
        fn entry_list_roundtrip() {
            bolero::check!()
                .with_type::<Vec<Vec<u8>>>()
                .for_each(|blobs| {
                    let chain = DelegationChain::from(
                        blobs
                            .iter()
                            .cloned()
                            .map(SignedDelegationBytes::from)
                            .collect::<Vec<_>>(),
                    );

                    let mut buf = Vec::new();
                    chain.encode_into(&mut buf);

                    let mut reader = Reader::new(&buf).expect("under cap");
                    let decoded =
                        DelegationChain::decode(&mut reader).expect("own encoding decodes");
                    reader.finish().expect("fully consumed");

                    assert_eq!(chain, decoded);
                });
        }

        /// The framed (file-format) entry points roundtrip, and the
        /// one behavior `read_framed` adds over `decode` — trailing
        /// bytes are rejected — holds for every chain.
        #[test]
        fn framed_roundtrip_rejects_trailing_bytes() {
            bolero::check!()
                .with_type::<Vec<Vec<u8>>>()
                .for_each(|blobs| {
                    let chain: DelegationChain = blobs
                        .iter()
                        .cloned()
                        .map(SignedDelegationBytes::from)
                        .collect();

                    let mut buf = Vec::new();
                    chain.write_framed(&mut buf);
                    assert_eq!(DelegationChain::read_framed(&buf), Ok(chain));

                    buf.push(0);
                    assert_eq!(
                        DelegationChain::read_framed(&buf),
                        Err(WireError::TrailingBytes { extra: 1 })
                    );
                });
        }
    }
}
