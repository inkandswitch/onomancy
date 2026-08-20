//! The derivation's per-hostname output vocabulary.
//!
//! The container — [`VerifierState`](super::VerifierState) — lives
//! with its impls in the parent module; this module holds what it is
//! made of. State is what the derivation returns; **events are
//! diffs** between states — surfacing is the caller's obligation,
//! computed by comparing outputs, never a side channel of the
//! derivation itself.

use alloc::vec::Vec;

use onomancy_core::{
    freshness::ChainWindow,
    name::doc::DocAnchor,
    txt::{generation_key::GenerationKey, serial::Serial},
};

/// The derived state for one hostname.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostState {
    /// The accepted binding, if any. Empty while contested.
    pub accepted: Option<AcceptedBinding>,

    /// Contested state: zone equivocation or receipt-tied acceptances.
    /// Surfaced; resolved only by stronger evidence or an acceptance.
    pub contested: bool,

    /// Claims and pins that disagree with the accepted binding.
    pub divergence: Vec<Divergence>,

    /// The accepted record's serial — the one ratchet definition.
    pub effective_serial: Option<Serial>,

    /// Lineage forks: competing valid statements or chain-shape
    /// violations, per document. Surfaced, never auto-resolved.
    pub forks: Vec<Fork>,

    /// Acceptance documents outranked under the receipts rule: the
    /// receipts contest's losers, surfaced (stage 5: "the loser is
    /// surfaced"). Badge, never a prompt.
    pub losing_acceptances: Vec<DocAnchor>,

    /// Candidates quarantined by the pending doctrine: stale, unproven
    /// challengers to the incumbent. Badge, never a prompt.
    pub pending: Vec<DocAnchor>,

    /// Succession-proof forks (D16): one predecessor with competing
    /// valid successor statements. Surfaced, never traversed by
    /// incumbency extension or eligibility.
    pub succession_forks: Vec<SuccessionFork>,

    /// Tenure of the accepted document: the span of its records'
    /// chain-window evidence in this store. Grades the severity of a
    /// later unproven displacement.
    pub tenure: Option<ChainWindow>,
}

/// An accepted (document, generation) binding with its grade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedBinding {
    /// How continuity from the acceptance-backed document was
    /// established.
    pub continuity: ContinuityGrade,
    /// The bound root document.
    pub document: DocAnchor,
    /// The attested generation key of the winning record.
    pub generation: GenerationKey,
    /// Confirmed (fresh support) or provisional.
    pub grade: BindingGrade,
}

/// How the accepted document connects to the acceptance-backed one —
/// per-hop proof grading (dns-anchor, Bridging History Gaps). A
/// bridged continuity verdict MUST be distinguishable from a
/// directly-proven one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ContinuityGrade {
    /// No succession proof was consulted: the accepted document is
    /// the acceptance-backed document itself, or no acceptance exists
    /// to depart from.
    #[default]
    Unmoved,

    /// Directly proven: one fully-checked hop departs the
    /// acceptance-backed document — fresh support there, and the
    /// statement's carriage threads its last-known generation.
    Proven,

    /// Continuity holds only through provisional hops: a multi-hop
    /// bridge, or a departing hop without fresh support or generation
    /// threading. Caps the binding grade at provisional and carries
    /// the opportunistic re-check obligation.
    Bridged,

    /// The accepted document displaced the incumbent with no proof
    /// path at all — a surfaced, unproven binding change (B4).
    Unproven,
}

/// How well-supported the accepted binding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BindingGrade {
    /// Supported by fresh ✓ evidence.
    Confirmed,

    /// Supported only by stale evidence (including sole-candidate
    /// first contact) or provisional bridge hops: MUST NOT anchor a
    /// fully-checked bridge hop; carries the opportunistic re-check
    /// obligation.
    Provisional,
}

/// A decisions claim or pinned target that disagrees with the accepted
/// binding — a badge input for the divergence/re-pin flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Divergence {
    /// What the disagreeing side alleges.
    pub alleged: DocAnchor,
    /// Where the disagreement came from.
    pub source: DivergenceSource,
}

/// Which kind of evidence disagrees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DivergenceSource {
    /// An introduction claim in the decision document.
    Claim,

    /// A petname pin whose target no longer matches.
    Pin,
}

/// A lineage fork: provable equivocation over a document's generation
/// history. Insider-grade, surfaced, never silently resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fork {
    /// The document whose lineage forked.
    pub document: DocAnchor,
    /// The generation at which the fork is anchored.
    pub at: GenerationKey,
}

/// A succession-proof fork (D16): competing valid successor statements
/// from one predecessor document. Provable equivocation — surfaced,
/// never auto-resolved, and it stops proof-graph traversal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SuccessionFork {
    /// The document both statements migrate away from.
    pub predecessor: DocAnchor,
    /// The competing claimed successors, sorted.
    pub successors: Vec<DocAnchor>,
}
