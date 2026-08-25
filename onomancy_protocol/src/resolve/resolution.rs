//! The outcome of a walk.

use onomancy_core::name::doc::DocAnchor;

use super::namestore::Authority;

/// What became of a resolution attempt.
///
/// `Partial` is the designed norm under partition, not an error: the
/// walked prefix was valid, and the reason says what is missing.
/// There is deliberately no `Failed` variant yet — the walk itself is
/// total over well-formed inputs, and anchor-layer failures happen
/// before it begins.
#[allow(clippy::large_enum_variant)] // `N` is generic; the size estimate is meaningless
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution<N> {
    /// The walk consumed every segment; here is the final namestore.
    Resolved {
        /// The namestore the name resolves to.
        target: N,
        /// The WEAKEST [`Authority`] grade crossed on the way — the
        /// root's and every hop's, folded by min. Callers MUST
        /// surface it: a resolution is only as vouched as its
        /// weakest document.
        authority: Authority,
    },

    /// The walk stopped early. `consumed` counts the segments
    /// successfully walked before the stop.
    Partial {
        /// How many input segments were consumed.
        consumed: usize,
        /// Why the walk stopped.
        reason: PartialReason,
    },
}

/// Why a walk stopped early (spec conditions E1 and E2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartialReason {
    /// No key in the current namestore matches the remaining segments
    /// (E1). Greedy matching never backtracks, so this outcome stands
    /// even when a shorter key could have led elsewhere.
    DanglingSegment,

    /// The matched reference's namestore is not locally replicated
    /// (E2) — unavailable, not wrong.
    UnsyncedTarget {
        /// The reference whose replica is missing.
        target: DocAnchor,
    },
}
