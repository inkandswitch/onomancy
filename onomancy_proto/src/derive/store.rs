//! The store: a grow-only set of self-authenticating items.
//!
//! Items are accepted from **anyone** — records carry their own proof,
//! so ingestion costs no trust and sync is plain set union. The user's
//! own decisions live elsewhere (the judgment document); no derived
//! state ever enters the store.

use alloc::vec::Vec;

use onomancy_core::{
    cert::{chain::DnssecChain, Certificate},
    collections::Set,
    content_hash::ContentHash,
    name::dns::DnsName,
    statement::{rotation::RotationStatement, successor::SuccessorStatement},
};

/// One store item: an exact byte unit, identified by content hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Item {
    /// A proven-absence record: a chain whose leaf is an NSEC/NSEC3
    /// denial for the hostname's `_onomancy` owner name.
    Absence {
        /// The hostname whose binding is denied.
        hostname: DnsName,
        /// The denial chain.
        chain: DnssecChain,
    },

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
    /// (the spec's content-addressing rule). Chain items — which have
    /// no self-describing unit encoding — hash a **domain-separated**
    /// composite of kind tag, hostname, and chain framing: without the
    /// tag and hostname, `Absence{h, X}` and `ChainRefresh{h', X}`
    /// would collide, and set-union dedup would let whichever spelling
    /// arrived first silently suppress the others — an order-dependent
    /// evidence drop.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        match self {
            Self::Record(certificate) => certificate.digest().into(),
            Self::Rotation(statement) => statement.digest().into(),
            Self::Successor(statement) => statement.digest().into(),
            Self::Absence { hostname, chain } => chain_item_hash(b'A', hostname, chain),
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

/// The grow-only record store. Union-merged, deduplicated by content
/// hash; insertion order is deliberately unobservable to `derive`.
#[derive(Debug, Clone, Default)]
pub struct Store {
    items: Vec<Item>,
    seen: Set<ContentHash>,
}

impl Store {
    /// Ingest one item. Union semantics: re-inserting an already-held
    /// item is a no-op, and no input is ever refused.
    pub fn insert(&mut self, item: Item) {
        if self.seen.insert(item.content_hash()) {
            self.items.push(item);
        }
    }

    /// All held items, in an order `derive` MUST NOT depend on.
    #[must_use]
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// Union another store into this one.
    pub fn union(&mut self, other: &Self) {
        for item in &other.items {
            self.insert(item.clone());
        }
    }
}

impl FromIterator<Item> for Store {
    fn from_iter<I: IntoIterator<Item = Item>>(items: I) -> Self {
        let mut store = Self::default();
        for item in items {
            store.insert(item);
        }
        store
    }
}
