//! The store: a grow-only set of self-authenticating items.
//!
//! Items are accepted from **anyone** — records carry their own proof,
//! so ingestion costs no trust and sync is plain set union. The user's
//! own decisions live elsewhere (the decision document); no derived
//! state ever enters the store.

use alloc::vec::Vec;

pub mod item;

use self::item::Item;

use onomancy_core::{
    collections::Set,
    digest::{Blake3, Digest},
};

/// The grow-only record store. Union-merged, deduplicated by content
/// hash; insertion order is deliberately unobservable to `derive`.
#[derive(Debug, Clone, Default)]
pub struct Store {
    items: Vec<Item>,
    seen: Set<Digest<Blake3, [u8]>>,
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
