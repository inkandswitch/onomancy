//! In-memory namestores: test doubles and small-tool substrates.
//!
//! Following the `MemorySigner` precedent: a public, dependency-free
//! implementation of the trait seams, useful for conformance tests
//! downstream as well as in this crate.

use alloc::vec::Vec;
use core::cell::Cell;

use onomancy_core::{anchor::doc::DocAnchor, collections::Map, name::segment::Segment};

use super::namestore::{Authority, Namestore, Replicas, Vouched};

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
    replicas: Map<DocAnchor, Vouched<MemoryNamestore>>,
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

    /// Add one replica at the dev-bridge grade
    /// ([`Authority::TrustedSubstrate`]), builder-style.
    #[must_use]
    pub fn with(self, id: DocAnchor, store: MemoryNamestore) -> Self {
        self.with_vouched(id, store, Authority::TrustedSubstrate)
    }

    /// Add one replica at an explicit grade, builder-style.
    #[must_use]
    pub fn with_vouched(
        mut self,
        id: DocAnchor,
        store: MemoryNamestore,
        authority: Authority,
    ) -> Self {
        self.replicas.insert(id, Vouched::new(store, authority));
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

    fn replica(&self, target: &DocAnchor) -> Option<Vouched<MemoryNamestore>> {
        if let Some(counter) = &self.loads {
            counter.set(counter.get() + 1);
        }
        self.replicas.get(target).cloned()
    }
}
