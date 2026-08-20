//! In-memory namestores: test doubles and small-tool substrates.
//!
//! Following the `MemorySigner` precedent: a public, dependency-free
//! implementation of the trait seams, useful for conformance tests
//! downstream as well as in this crate.

use alloc::vec::Vec;
use core::cell::Cell;

use onomancy_core::{
    collections::Map,
    name::{doc::DocAnchor, segment::Segment},
};

use super::namestore::{Namestore, Replicas};

/// A flat in-memory namestore.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryNamestore {
    entries: Map<Vec<Segment>, DocAnchor>,
}

impl MemoryNamestore {
    /// Add one entry, builder-style. Keys are paths — already-parsed
    /// segments, so non-conforming keys (E6) are unrepresentable here.
    #[must_use]
    pub fn with(mut self, path: &[Segment], target: DocAnchor) -> Self {
        self.entries.insert(path.to_vec(), target);
        self
    }
}

impl Namestore for MemoryNamestore {
    fn reference(&self, path: &[Segment]) -> Option<DocAnchor> {
        self.entries.get(path).copied()
    }
}

/// An in-memory replica set, optionally counting loads (for the
/// structural-termination property).
#[derive(Debug, Clone, Default)]
pub struct MemoryReplicas {
    replicas: Map<DocAnchor, MemoryNamestore>,
    loads: Option<Cell<usize>>,
}

impl MemoryReplicas {
    /// A replica set that counts how many loads the walk performs.
    #[must_use]
    pub fn counting() -> Self {
        Self {
            replicas: Map::default(),
            loads: Some(Cell::new(0)),
        }
    }

    /// Add one replica, builder-style.
    #[must_use]
    pub fn with(mut self, id: DocAnchor, store: MemoryNamestore) -> Self {
        self.replicas.insert(id, store);
        self
    }

    /// How many loads have been performed (always 0 unless constructed
    /// via [`counting`](Self::counting)).
    #[must_use]
    pub fn loads(&self) -> usize {
        self.loads.as_ref().map_or(0, Cell::get)
    }
}

impl Replicas for MemoryReplicas {
    type Namestore = MemoryNamestore;

    fn replica(&self, target: &DocAnchor) -> Option<MemoryNamestore> {
        if let Some(counter) = &self.loads {
            counter.set(counter.get() + 1);
        }
        self.replicas.get(target).cloned()
    }
}
