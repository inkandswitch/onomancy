//! The zone-editing seam: how a [`Plan`](crate::plan::Plan)'s DNS ops
//! reach an actual zone.
//!
//! Executors are dumb by design — a human with a dashboard, an RFC
//! 2136 update, a provider API adapter, a zone-file rewriter. The
//! planner never learns which; correctness is checked afterward by
//! the ordinary verifier (postconditions), not trusted to the editor.

use core::future::Future;

use crate::plan::DnsOp;

/// Applies zone edits. IO lives behind this seam and nowhere else in
/// the publisher.
///
/// The future is deliberately not `Send`-bound, matching the other
/// seams (Wasm-hosted editors are `!Send`).
pub trait ZoneEditor {
    /// Editor-side failure: API errors, auth, IO. Never a validity
    /// verdict.
    type Error: core::error::Error;

    /// Apply one operation to the zone.
    fn apply(&mut self, op: &DnsOp) -> impl Future<Output = Result<(), Self::Error>>;
}
