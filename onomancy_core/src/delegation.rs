//! Verbatim Keyhive `Signed<Delegation>` bytes and their framing.
//!
//! Onomancy carries delegation proofs — the certificate's
//! `delegation_chain` and every statement's authority carriage — as
//! length-prefixed, otherwise **opaque** blobs of Keyhive's own wire
//! encoding. This codec never re-encodes, canonicalizes, or introspects
//! them; they are interpreted only by Keyhive verification (the
//! `AuthorityVerifier` seam, implemented in `onomancy_keyhive`).
//!
//! ```text
//! count as bijou64
//! repeat count times:
//!     entry_len as bijou64
//!     entry_len bytes: verbatim Keyhive Signed<Delegation>
//! ```

use alloc::vec::Vec;

use crate::wire::{self, Reader, WireError};

/// One verbatim Keyhive `Signed<Delegation>` unit, opaque at this layer.
///
/// Semantic checks — that a chain roots at the right document,
/// terminates at the right signer, and holds admin access at the
/// delegating hop — belong to Keyhive verification, not this codec.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct DelegationBytes(Vec<u8>);

impl DelegationBytes {
    /// The verbatim Keyhive wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for DelegationBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Decode a standalone count-prefixed carriage (the framing used for
/// carriage FILES — e.g. the dev bridge's `<anchor>.carriage`).
///
/// # Errors
///
/// Returns [`WireError`] on truncation, length overrun, or trailing
/// bytes.
pub fn read_framed(bytes: &[u8]) -> Result<Vec<DelegationBytes>, WireError> {
    let mut reader = Reader::new(bytes)?;
    let entries = read_entries(&mut reader)?;
    reader.finish()?;
    Ok(entries)
}

/// Encode a standalone count-prefixed carriage (see [`read_framed`]).
pub fn write_framed(entries: &[DelegationBytes], buf: &mut Vec<u8>) {
    write_entries(buf, entries);
}

/// Decode one count-prefixed entry list.
///
/// Entries are collected without a count-sized pre-allocation: the
/// wire-minimum entry is one byte, but each decoded entry costs a
/// `Vec` header, so trusting the declared count would let a small unit
/// reserve outsized memory before the first entry fails.
pub(crate) fn read_entries(reader: &mut Reader<'_>) -> Result<Vec<DelegationBytes>, WireError> {
    let count = reader.bounded_len(1)?;
    let mut entries = Vec::new();

    for _ in 0..count {
        let len = reader.bounded_len(1)?;
        entries.push(DelegationBytes(reader.take(len)?.to_vec()));
    }

    Ok(entries)
}

/// Append one count-prefixed entry list.
pub(crate) fn write_entries(buf: &mut Vec<u8>, entries: &[DelegationBytes]) {
    wire::put_varint(buf, entries.len() as u64);

    for entry in entries {
        wire::put_varint(buf, entry.0.len() as u64);
        buf.extend_from_slice(&entry.0);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    mod props {
        use super::*;

        #[test]
        fn entry_list_roundtrip() {
            bolero::check!()
                .with_type::<Vec<Vec<u8>>>()
                .for_each(|blobs| {
                    let entries: Vec<DelegationBytes> =
                        blobs.iter().cloned().map(DelegationBytes::from).collect();

                    let mut buf = Vec::new();
                    write_entries(&mut buf, &entries);

                    let mut reader = Reader::new(&buf).expect("under cap");
                    let decoded = read_entries(&mut reader).expect("own encoding decodes");
                    reader.finish().expect("fully consumed");

                    assert_eq!(entries, decoded);
                });
        }
    }
}
