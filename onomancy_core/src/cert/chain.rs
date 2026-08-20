//! DNSSEC chain framing: length-prefixed, verbatim DNS wire bytes.
//!
//! ```text
//! chain_count as bijou64
//! repeat chain_count times:
//!     link_len as bijou64
//!     link_len bytes: DNS wire format
//! ```
//!
//! Each link is the RFC 4034 canonical wire form of one `RRset` together
//! with its RRSIG(s) — the same bytes DNSSEC signature validation is
//! defined over. This codec adds framing only; it never re-encodes DNS
//! data. Links are ordered from the root zone toward the owner name
//! (`_onomancy.<name>`), covering every zone cut and indirection en
//! route; NSEC/NSEC3 denial-of-existence records, where present, are
//! links like any other.
//!
//! Validation — walking the chain from the verifier's own trust anchor
//! — is `onomancy_dnssec`'s job, behind the `ChainValidator` seam.

use alloc::vec::Vec;

use crate::wire::{self, Reader, WireError};

/// One chain link: verbatim RFC 4034 canonical wire bytes of an `RRset`
/// plus its RRSIG(s). Opaque at this layer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ChainLink(Vec<u8>);

impl ChainLink {
    /// The verbatim DNS wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for ChainLink {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// A framed DNSSEC chain, root zone → owner name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct DnssecChain(Vec<ChainLink>);

impl DnssecChain {
    /// The links, root-first.
    #[must_use]
    pub fn links(&self) -> &[ChainLink] {
        &self.0
    }

    /// Decode a standalone framed chain (the inverse of
    /// [`write_framed`](Self::write_framed)), consuming the whole
    /// input — the byte form fixtures and bare chain-refresh items
    /// travel in.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] on truncation, length overrun, trailing
    /// bytes, or the unit size cap.
    pub fn read_framed(bytes: &[u8]) -> Result<Self, WireError> {
        let mut reader = Reader::new(bytes)?;
        let chain = Self::read(&mut reader)?;
        reader.finish()?;

        Ok(chain)
    }

    /// Decode one count-prefixed chain. No count-sized pre-allocation:
    /// see `delegation::read_entries` for the rationale.
    pub(crate) fn read(reader: &mut Reader<'_>) -> Result<Self, WireError> {
        let count = reader.bounded_len(1)?;
        let mut links = Vec::new();

        for _ in 0..count {
            let len = reader.bounded_len(1)?;
            links.push(ChainLink(reader.take(len)?.to_vec()));
        }

        Ok(Self(links))
    }

    /// Append this chain's count-prefixed framing — also the byte
    /// form a bare chain-refresh store item is content-addressed by.
    pub fn write_framed(&self, buf: &mut Vec<u8>) {
        wire::put_varint(buf, self.0.len() as u64);

        for link in &self.0 {
            wire::put_varint(buf, link.0.len() as u64);
            buf.extend_from_slice(&link.0);
        }
    }
}

impl From<Vec<ChainLink>> for DnssecChain {
    fn from(links: Vec<ChainLink>) -> Self {
        Self(links)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    mod props {
        use super::*;

        #[test]
        fn chain_framing_roundtrip() {
            bolero::check!()
                .with_type::<Vec<Vec<u8>>>()
                .for_each(|blobs| {
                    let chain = DnssecChain::from(
                        blobs
                            .iter()
                            .cloned()
                            .map(ChainLink::from)
                            .collect::<Vec<_>>(),
                    );

                    let mut buf = Vec::new();
                    chain.write_framed(&mut buf);

                    let mut reader = Reader::new(&buf).expect("under cap");
                    let decoded = DnssecChain::read(&mut reader).expect("own encoding decodes");
                    reader.finish().expect("fully consumed");

                    assert_eq!(chain, decoded);
                });
        }
    }
}
