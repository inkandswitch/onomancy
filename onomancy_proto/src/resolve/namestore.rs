//! The namestore trait seams the walk reads through.

use onomancy_core::name::{doc::DocAnchor, segment::Segment};

/// A flat map from paths to namestore references — the substrate
/// contract of the Namestore Model.
///
/// Implementations MUST treat non-conforming keys (empty, `.`, or `..`
/// segments; `#`; leading or trailing `/`) as absent during matching
/// (spec condition E6): `reference` simply never returns them.
///
/// Conflict handling (E7) is the substrate's: concurrent writes to one
/// key MUST already be resolved to the deterministic winner by the time
/// `reference` answers. Surfacing the losers is a reporting concern
/// layered above this seam, not part of the walk.
pub trait Namestore {
    /// The reference stored at exactly this path, if any.
    ///
    /// `path` is always non-empty. Matching is whole-segment,
    /// byte-for-byte — never substring.
    fn reference(&self, path: &[Segment]) -> Option<DocAnchor>;
}

/// Access to locally-replicated namestores, by self-certifying
/// reference.
///
/// This is a seam, not a fetcher: `replica` answers from what is
/// *already local*, and `None` means "not replicated here" — which the
/// walk reports as `UnsyncedTarget`, the designed outcome under
/// partition. An implementation that performs network IO behind this
/// trait is violating its contract, not fulfilling it.
pub trait Replicas {
    /// The namestore representation this source yields.
    type Namestore: Namestore;

    /// The locally-available namestore for `target`, if replicated.
    fn replica(&self, target: &DocAnchor) -> Option<Self::Namestore>;
}
