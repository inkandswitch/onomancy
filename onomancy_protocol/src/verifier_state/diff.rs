//! Events are diffs: the surfacing doctrine as a type.
//!
//! State is what `derive` returns; when a store update or the passage
//! of time changes the output, implementations MUST surface the
//! difference. [`VerifierState::diff`] computes exactly that difference,
//! and every [`EventKind`] carries its events-vs-states class:
//! event-class changes (binding moves, ratchet resets, forks,
//! unbinding) may prompt; badge-class changes (pending, contested,
//! provisional, divergence) MUST NOT — "silently" means "without a
//! prompt," never "invisibly."

use alloc::vec::Vec;

use onomancy_core::{
    collections::Set,
    name::{dns::DnsName, doc::DocAnchor},
    txt::serial::Serial,
};

use super::output::{BindingGrade, Divergence, Fork, HostState, SuccessionFork};

/// One surfaced change at one hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The hostname whose state changed.
    pub hostname: DnsName,
    /// What changed.
    pub kind: EventKind,
}

/// What changed, tagged with its surfacing class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    // ————— event-class: may prompt —————
    /// The accepted document changed (including appearing or being
    /// masked by contested). Graded by the displaced binding's tenure
    /// at the UI layer.
    BindingChanged {
        /// The previously accepted document, if any.
        from: Option<DocAnchor>,
        /// The now-accepted document, if any.
        to: Option<DocAnchor>,
    },

    /// A newly surfaced lineage fork: provable equivocation over a
    /// generation. Insider-grade.
    LineageForkSurfaced(Fork),

    /// The effective serial moved DOWN for the same document — legal
    /// only via fresh evidence (D4a), and always surfaced.
    RatchetReset {
        /// The previous effective serial.
        from: Serial,
        /// The new, lower effective serial.
        to: Serial,
    },

    /// A newly surfaced succession fork (D16): competing valid
    /// successor statements from one predecessor.
    SuccessionForkSurfaced(SuccessionFork),

    // ————— badge-class: MUST NOT prompt —————
    /// The hostname left the contested state.
    ContestedCleared,

    /// The hostname entered the contested state (zone equivocation or
    /// receipt-tied acceptances, B13).
    ContestedEntered,

    /// A divergence badge cleared.
    DivergenceCleared(Divergence),

    /// A claim or pin now disagrees with the accepted binding.
    DivergenceSurfaced(Divergence),

    /// The accepted binding's grade moved (confirmed ⇄ provisional).
    GradeChanged {
        /// The previous grade.
        from: BindingGrade,
        /// The new grade.
        to: BindingGrade,
    },

    /// A pending candidate's badge cleared (confirmed or refuted —
    /// B2/B3).
    PendingCleared(DocAnchor),

    /// A stale, unproven challenger entered quarantine (B1).
    PendingSurfaced(DocAnchor),
}

impl EventKind {
    /// Whether this change belongs to the event class (may prompt) or
    /// the badge class (must not).
    #[must_use]
    pub const fn may_prompt(&self) -> bool {
        match self {
            Self::BindingChanged { .. }
            | Self::LineageForkSurfaced(_)
            | Self::RatchetReset { .. }
            | Self::SuccessionForkSurfaced(_) => true,

            Self::ContestedCleared
            | Self::ContestedEntered
            | Self::DivergenceCleared(_)
            | Self::DivergenceSurfaced(_)
            | Self::GradeChanged { .. }
            | Self::PendingCleared(_)
            | Self::PendingSurfaced(_) => false,
        }
    }
}

/// The fixed-order change list for one hostname —
/// [`VerifierState::diff`](super::VerifierState::diff)'s per-host
/// worker.
pub(super) fn host_diff(before: &HostState, after: &HostState) -> Vec<EventKind> {
    let mut kinds = Vec::new();

    // Binding movement (document identity, not grade).
    let from = before.accepted.map(|binding| binding.document);
    let to = after.accepted.map(|binding| binding.document);
    if from != to {
        kinds.push(EventKind::BindingChanged { from, to });
    }

    // Ratchet reset: same document, serial moved down.
    if let (Some(prior), Some(current)) = (before.accepted, after.accepted)
        && prior.document == current.document
        && let (Some(old), Some(new)) = (before.effective_serial, after.effective_serial)
        && new < old
    {
        kinds.push(EventKind::RatchetReset { from: old, to: new });
    }

    // Grade movement on an unchanged document.
    if let (Some(prior), Some(current)) = (before.accepted, after.accepted)
        && prior.document == current.document
        && prior.grade != current.grade
    {
        kinds.push(EventKind::GradeChanged {
            from: prior.grade,
            to: current.grade,
        });
    }

    // Forks: newly surfaced only — forks are permanent history, so a
    // fork present in both derivations is old news.
    for fork in new_items(&before.forks, &after.forks) {
        kinds.push(EventKind::LineageForkSurfaced(fork));
    }
    for fork in new_items(&before.succession_forks, &after.succession_forks) {
        kinds.push(EventKind::SuccessionForkSurfaced(fork));
    }

    // Contested transitions.
    match (before.contested, after.contested) {
        (false, true) => kinds.push(EventKind::ContestedEntered),
        (true, false) => kinds.push(EventKind::ContestedCleared),
        _ => (),
    }

    // Pending set changes, per candidate.
    let prior_pending: Set<DocAnchor> = before.pending.iter().copied().collect();
    let current_pending: Set<DocAnchor> = after.pending.iter().copied().collect();
    for candidate in &after.pending {
        if !prior_pending.contains(candidate) {
            kinds.push(EventKind::PendingSurfaced(*candidate));
        }
    }
    for candidate in &before.pending {
        if !current_pending.contains(candidate) {
            kinds.push(EventKind::PendingCleared(*candidate));
        }
    }

    // Divergence badge changes.
    for divergence in new_items(&before.divergence, &after.divergence) {
        kinds.push(EventKind::DivergenceSurfaced(divergence));
    }
    for divergence in new_items(&after.divergence, &before.divergence) {
        kinds.push(EventKind::DivergenceCleared(divergence));
    }

    kinds
}

/// Items in `after` that are not in `before` (both small and sorted).
fn new_items<T: Clone + PartialEq>(before: &[T], after: &[T]) -> Vec<T> {
    after
        .iter()
        .filter(|item| !before.contains(item))
        .cloned()
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::verifier_state::{VerifierState, output::AcceptedBinding};
    use onomancy_core::collections::Map;

    fn host() -> DnsName {
        DnsName::parse("expede.wtf").expect("valid")
    }

    fn doc(seed: u8) -> DocAnchor {
        DocAnchor::from(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    fn generation(seed: u8) -> onomancy_core::txt::generation_key::GenerationKey {
        onomancy_core::txt::generation_key::GenerationKey::from(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key(),
        )
    }

    fn derivation(state: HostState) -> VerifierState {
        let mut hosts = Map::default();
        hosts.insert(host(), state);
        VerifierState { hosts }
    }

    fn accepted(doc_seed: u8, serial: u64, grade: BindingGrade) -> HostState {
        HostState {
            accepted: Some(AcceptedBinding {
                document: doc(doc_seed),
                generation: generation(doc_seed + 10),
                grade,
            }),
            effective_serial: Some(Serial::from(serial)),
            ..HostState::default()
        }
    }

    #[test]
    fn binding_changes_and_ratchet_resets_are_event_class() {
        let before = derivation(accepted(1, 100, BindingGrade::Confirmed));
        let moved = derivation(accepted(2, 200, BindingGrade::Confirmed));

        let events = moved.diff(&before);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].kind, EventKind::BindingChanged { .. }));
        assert!(events[0].kind.may_prompt());

        // Same document, serial moved down: a ratchet reset.
        let reset = derivation(accepted(1, 7, BindingGrade::Confirmed));
        let events = reset.diff(&before);
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].kind,
            EventKind::RatchetReset { from, to }
                if from == Serial::from(100) && to == Serial::from(7)
        ));
    }

    #[test]
    fn badges_never_prompt() {
        let before = derivation(HostState::default());
        let after = derivation(HostState {
            contested: true,
            pending: vec![doc(3)],
            ..HostState::default()
        });

        let events = after.diff(&before);
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| !event.kind.may_prompt()));
    }

    #[test]
    fn identical_derivations_produce_no_events() {
        let derivation = derivation(accepted(1, 100, BindingGrade::Provisional));
        assert!(derivation.diff(&derivation).is_empty());
    }

    #[test]
    fn forks_fire_only_when_newly_surfaced() {
        let fork = Fork {
            document: doc(1),
            at: generation(11),
        };
        let with_fork = derivation(HostState {
            forks: vec![fork],
            ..HostState::default()
        });

        assert_eq!(with_fork.diff(&derivation(HostState::default())).len(), 1);
        assert!(with_fork.diff(&with_fork).is_empty(), "old news");
    }
}
