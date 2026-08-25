//! The namestore trait seams the walk reads through.
//!
//! > [!WARNING]
//! > Document AUTHORITY is graded, not yet fully checkable: no grade
//! > shipped today proves the document's content was authored by the
//! > anchor's delegates. Full verification waits on upstream
//! > (Automerge op signing; verified ingest à la
//! > automerge-repo-keyhive). The [`Authority`] grade exists so that
//! > gap is typed, surfaced in every verdict, and closable by an
//! > impl swap — never silently assumed away.

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

    /// The locally-available namestore for `target`, if replicated,
    /// with the strongest [`Authority`] grade the substrate can
    /// honestly claim for it.
    fn replica(&self, target: &DocAnchor) -> Option<Vouched<Self::Namestore>>;
}

/// How a replica's standing for its anchor was established — ordered
/// weakest-first, so [`Ord::min`] is the walk's weakest-link fold.
///
/// A grade is the substrate's explicit claim: the type forces every
/// replica to state one, and the walk carries the weakest grade it
/// crossed into the outcome, where callers MUST surface it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Authority {
    /// Nothing checked: the substrate is trusted outright (dev
    /// bridges, demos). The weakest grade — and today's default.
    TrustedSubstrate,

    /// The document's authority carriage is a genuine delegation
    /// graph rooted at the anchor — but content authorship is NOT
    /// checkable yet (no signed ops), so the bytes themselves remain
    /// the substrate's word.
    CarriageVerified,
}

impl Authority {
    /// The grade's stable verdict label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::TrustedSubstrate => "trusted-substrate",
            Self::CarriageVerified => "carriage-verified",
        }
    }
}

/// A namestore together with the [`Authority`] grade it was vouched
/// at — the walk's per-hop evidence unit. Constructing one is an
/// explicit claim; there is no ungraded path into the walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vouched<N> {
    namestore: N,
    authority: Authority,
}

impl<N> Vouched<N> {
    /// Vouch for `namestore` at `authority`.
    #[must_use]
    pub const fn new(namestore: N, authority: Authority) -> Self {
        Self {
            namestore,
            authority,
        }
    }

    /// The vouched namestore.
    #[must_use]
    pub const fn namestore(&self) -> &N {
        &self.namestore
    }

    /// The grade this namestore was vouched at.
    #[must_use]
    pub const fn authority(&self) -> Authority {
        self.authority
    }

    /// Split into parts (the walk consumes both).
    #[must_use]
    pub fn into_parts(self) -> (N, Authority) {
        (self.namestore, self.authority)
    }
}
