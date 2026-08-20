//! The decisions view: the user's decisions, read from their private
//! decision document.
//!
//! Decisions lives in a user-private Keyhive document (authentication =
//! write delegation, privacy = E2EE, sync = replication, undo = CRDT
//! editing). This module is the *data-shape contract* the derivation
//! reads — the substrate carries the bytes; `onomancy_keyhive`
//! implements the view over a real document.

use alloc::{string::String, vec::Vec};

use onomancy_core::{
    collections::{Map, Set},
    content_hash::ContentHash,
    name::{dns::DnsName, doc::DocAnchor},
};

/// A claim: an alleged name recorded at introduction. Feeds divergence
/// badges only; MUST NOT affect acceptance. Immutable provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The alleged hostname.
    pub hostname: DnsName,
    /// The document the introduction attached it to.
    pub document: DocAnchor,
    /// Free-form introduction provenance (the schema's optional
    /// `note`).
    pub note: Option<String>,
}

/// An acceptance: a deliberate user choice of a document for a
/// hostname, with receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acceptance {
    /// The accepted document.
    pub document: DocAnchor,
    /// Content hashes of the records relied on — non-empty; every
    /// cited item a record for this hostname, at least one attesting
    /// `document`. An acceptance citing an excluded item is inert; one
    /// citing an absent item is not-yet-evaluable.
    pub cited: Set<ContentHash>,
}

/// The decision document's state, as read at derivation time.
///
/// `acceptances` may carry multiple concurrent values per hostname
/// (the substrate's MV conflict); the derivation resolves them by the
/// receipts rule, surfacing the loser.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Decisions {
    /// Per-hostname acceptances (usually one; several = MV conflict).
    pub acceptances: Map<DnsName, Vec<Acceptance>>,
    /// Introduction claims, append-only.
    pub claims: Vec<Claim>,
    /// Per-hostname exclusion sets: content hashes of items that
    /// contribute to no derivation output at their natural scope.
    pub resets: Map<DnsName, Set<ContentHash>>,
}
