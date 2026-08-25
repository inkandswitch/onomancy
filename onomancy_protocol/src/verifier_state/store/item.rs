//! One store item: an exact byte unit, identified by content hash.

use alloc::vec::Vec;

use onomancy_core::{
    certificate::{Certificate, chain::DnssecChain},
    content_hash::ContentHash,
    name::dns::DnsName,
    statement::{rotation::RotationStatement, successor::SuccessorStatement},
};

/// One store item: an exact byte unit, identified by content hash.
///
/// Deliberately no absence-proof item: negative proofs are out of the
/// protocol at v0.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Item {
    /// A bare chain refresh ingested without its certificate. Its
    /// zone-state `issued_at` component is zero, sorting below an
    /// equal-window, equal-serial certificate item.
    ChainRefresh {
        /// The hostname the refreshed chain binds.
        hostname: DnsName,
        /// The refreshed chain.
        chain: DnssecChain,
    },

    /// A binding record: one (certificate, attached chain) unit as
    /// ingested. Re-attaching a fresher chain produces a *new* item.
    Record(Certificate),

    /// A rotation statement — document-scoped.
    Rotation(RotationStatement),

    /// A successor statement — hostname-scoped (the hostname is inside
    /// its signature).
    Successor(SuccessorStatement),
}

impl Item {
    /// The item's content hash.
    ///
    /// Certificate and statement units hash their verbatim wire bytes
    /// (the spec's content-addressing rule). Chain-refresh items —
    /// which have no self-describing unit encoding — hash a
    /// **domain-separated** composite of kind tag, hostname, and chain
    /// framing: without the tag and hostname, differently-labeled
    /// wrappers of one chain would collide, and set-union dedup would
    /// let whichever spelling arrived first silently suppress the
    /// others — an order-dependent evidence drop.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        match self {
            Self::Record(certificate) => certificate.digest().into(),
            Self::Rotation(statement) => statement.digest().into(),
            Self::Successor(statement) => statement.digest().into(),
            Self::ChainRefresh { hostname, chain } => chain_item_hash(b'R', hostname, chain),
        }
    }
}

/// Domain-separated hash for the two chain-item kinds.
fn chain_item_hash(kind: u8, hostname: &DnsName, chain: &DnssecChain) -> ContentHash {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"ono-chain-item/");
    buf.push(kind);
    buf.push(0);
    buf.extend_from_slice(hostname.as_str().as_bytes());
    buf.push(0);
    chain.write_framed(&mut buf);

    ContentHash::of(&buf)
}
