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

use onomancy_core::{anchor::doc::DocAnchor, collections::Set};
use onomancy_dnssec::{dns_name::DnsName, txt::serial::Serial};

use super::binding_state::{BindingGrade, BindingState, Divergence, Fork, SuccessionFork};

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
    /// only via fresh evidence, and always surfaced.
    SerialRegression {
        /// The previous effective serial.
        from: Serial,
        /// The new, lower effective serial.
        to: Serial,
    },

    /// A newly surfaced succession fork: competing valid
    /// successor statements from one predecessor.
    SuccessionForkSurfaced(SuccessionFork),

    /// The hostname left the contested state.
    ContestedCleared,

    /// The hostname entered the contested state (zone equivocation or
    /// receipt-tied acceptances).
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

    /// A losing acceptance's badge cleared (its receipts now win, or
    /// the acceptance left the decisions).
    LosingAcceptanceCleared(DocAnchor),

    /// An acceptance document was outranked under the receipts rule
    /// (stage 5: "the loser is surfaced").
    LosingAcceptanceSurfaced(DocAnchor),

    /// A pending candidate's badge cleared (confirmed or refuted —
    /// eligibility and refutation rules).
    PendingCleared(DocAnchor),

    /// A stale, unproven challenger entered quarantine.
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
            | Self::SerialRegression { .. }
            | Self::SuccessionForkSurfaced(_) => true,

            Self::ContestedCleared
            | Self::ContestedEntered
            | Self::DivergenceCleared(_)
            | Self::DivergenceSurfaced(_)
            | Self::GradeChanged { .. }
            | Self::LosingAcceptanceCleared(_)
            | Self::LosingAcceptanceSurfaced(_)
            | Self::PendingCleared(_)
            | Self::PendingSurfaced(_) => false,
        }
    }
}

/// The fixed-order change list for one hostname —
/// [`VerifierState::diff`](super::VerifierState::diff)'s per-host
/// worker.
pub(super) fn host_diff(before: &BindingState, after: &BindingState) -> Vec<EventKind> {
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
        kinds.push(EventKind::SerialRegression { from: old, to: new });
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

    // Losing-acceptance badge changes, per document.
    for document in new_items(&before.losing_acceptances, &after.losing_acceptances) {
        kinds.push(EventKind::LosingAcceptanceSurfaced(document));
    }
    for document in new_items(&after.losing_acceptances, &before.losing_acceptances) {
        kinds.push(EventKind::LosingAcceptanceCleared(document));
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
    use crate::verifier::state::{
        VerifierState,
        binding_state::{AcceptedBinding, ContinuityGrade},
    };
    use alloc::vec;
    use onomancy_core::collections::Map;

    fn host() -> DnsName {
        DnsName::parse("expede.wtf").expect("valid")
    }

    fn doc(seed: u8) -> DocAnchor {
        DocAnchor::from(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    fn generation(seed: u8) -> onomancy_dnssec::txt::generation_key::GenerationKey {
        onomancy_dnssec::txt::generation_key::GenerationKey::from(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key(),
        )
    }

    fn derivation(state: BindingState) -> VerifierState {
        let mut bindings = Map::default();
        bindings.insert(host(), state);
        VerifierState { bindings }
    }

    fn accepted(doc_seed: u8, serial: u64, grade: BindingGrade) -> BindingState {
        BindingState {
            accepted: Some(AcceptedBinding {
                continuity: ContinuityGrade::default(),
                document: doc(doc_seed),
                generation: generation(doc_seed + 10),
                grade,
            }),
            effective_serial: Some(Serial::from(serial)),
            ..BindingState::default()
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
            EventKind::SerialRegression { from, to }
                if from == Serial::from(100) && to == Serial::from(7)
        ));
    }

    #[test]
    fn badges_never_prompt() {
        let before = derivation(BindingState::default());
        let after = derivation(BindingState {
            contested: true,
            losing_acceptances: vec![doc(4)],
            pending: vec![doc(3)],
            ..BindingState::default()
        });

        let events = after.diff(&before);
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|event| !event.kind.may_prompt()));
        assert!(events.iter().any(|event| matches!(
            event.kind,
            EventKind::LosingAcceptanceSurfaced(document) if document == doc(4)
        )));

        // The badge clears symmetrically.
        let cleared = before.diff(&after);
        assert!(cleared.iter().any(|event| matches!(
            event.kind,
            EventKind::LosingAcceptanceCleared(document) if document == doc(4)
        )));
    }

    /// FIXME №6: entering contested-mask double-reports — the
    /// prompt-class `BindingChanged { Some → None }` rides alongside
    /// the badge-class `ContestedEntered`, though surfacing doctrine
    /// says the mask transition should not prompt. This test pins
    /// CURRENT behavior so the fix flips a visible assertion instead
    /// of changing silent behavior.
    #[test]
    fn entering_contested_mask_double_reports_pinning_fixme_6() {
        let before = derivation(accepted(1, 100, BindingGrade::Confirmed));
        let masked = derivation(BindingState {
            contested: true,
            ..BindingState::default()
        });

        let events = masked.diff(&before);

        assert!(
            events
                .iter()
                .any(|event| event.kind == EventKind::ContestedEntered),
            "the badge is the intended surfacing"
        );
        // FIXME №6: should NOT be emitted on a pure mask transition.
        assert!(
            events.iter().any(|event| event.kind
                == EventKind::BindingChanged {
                    from: Some(doc(1)),
                    to: None,
                }
                && event.kind.may_prompt()),
            "FIXME №6 current behavior: the mask co-emits a \
             prompt-class binding change"
        );
    }

    #[test]
    fn serials_moving_up_or_across_documents_never_regress() {
        // Upward move, same document: routine ratchet progress —
        // silence.
        let before = derivation(accepted(1, 100, BindingGrade::Confirmed));
        let up = derivation(accepted(1, 200, BindingGrade::Confirmed));
        assert!(
            up.diff(&before).is_empty(),
            "serials moving up are not events"
        );

        // Document move with a numerically lower serial: the ratchet
        // is per-document, so this is a binding change and nothing
        // else — a regression event across documents would misread
        // unrelated serial spaces as a rollback.
        let moved = derivation(accepted(2, 7, BindingGrade::Confirmed));
        let events = moved.diff(&before);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].kind, EventKind::BindingChanged { .. }));
    }

    #[test]
    fn contested_clearing_is_a_badge() {
        let contested = derivation(BindingState {
            contested: true,
            ..BindingState::default()
        });
        let settled = derivation(BindingState::default());

        let events = settled.diff(&contested);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::ContestedCleared);
        assert!(!events[0].kind.may_prompt());
    }

    #[test]
    fn pending_transitions_are_badges_both_ways() {
        let quiet = derivation(BindingState::default());
        let pending = derivation(BindingState {
            pending: vec![doc(3)],
            ..BindingState::default()
        });

        let surfaced = pending.diff(&quiet);
        assert_eq!(surfaced.len(), 1);
        assert_eq!(surfaced[0].kind, EventKind::PendingSurfaced(doc(3)));
        assert!(!surfaced[0].kind.may_prompt());

        let cleared = quiet.diff(&pending);
        assert_eq!(cleared.len(), 1);
        assert_eq!(cleared[0].kind, EventKind::PendingCleared(doc(3)));
        assert!(!cleared[0].kind.may_prompt());
    }

    #[test]
    fn succession_forks_fire_once_like_lineage_forks() {
        let fork = SuccessionFork {
            predecessor: doc(1),
            successors: vec![doc(2), doc(3)],
        };
        let with_fork = derivation(BindingState {
            succession_forks: vec![fork.clone()],
            ..BindingState::default()
        });

        let events = with_fork.diff(&derivation(BindingState::default()));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::SuccessionForkSurfaced(fork));
        assert!(events[0].kind.may_prompt(), "forks are event-class");
        assert!(with_fork.diff(&with_fork).is_empty(), "old news");
    }

    #[test]
    fn divergence_transitions_are_badges_both_ways() {
        let divergence = Divergence {
            alleged: doc(9),
            source: super::super::binding_state::DivergenceSource::Pin,
        };
        let quiet = derivation(accepted(1, 100, BindingGrade::Confirmed));
        let diverged = derivation(BindingState {
            divergence: vec![divergence],
            ..accepted(1, 100, BindingGrade::Confirmed)
        });

        let surfaced = diverged.diff(&quiet);
        assert_eq!(surfaced.len(), 1);
        assert_eq!(surfaced[0].kind, EventKind::DivergenceSurfaced(divergence));
        assert!(!surfaced[0].kind.may_prompt());

        let cleared = quiet.diff(&diverged);
        assert_eq!(cleared.len(), 1);
        assert_eq!(cleared[0].kind, EventKind::DivergenceCleared(divergence));
        assert!(!cleared[0].kind.may_prompt());
    }

    #[test]
    fn forks_fire_only_when_newly_surfaced() {
        let fork = Fork {
            document: doc(1),
            at: generation(11),
        };
        let with_fork = derivation(BindingState {
            forks: vec![fork],
            ..BindingState::default()
        });

        assert_eq!(
            with_fork.diff(&derivation(BindingState::default())).len(),
            1
        );
        assert!(with_fork.diff(&with_fork).is_empty(), "old news");
    }

    mod props {
        use super::*;
        use crate::verifier::state::binding_state::DivergenceSource;

        /// The compact seed tuple behind [`arb_state`]: accepted
        /// binding, contested flag, (pending, losing, divergence)
        /// counts, fork seed.
        type StateSeed = (Option<(u8, u64, bool)>, bool, (u8, u8, u8), u8);

        /// One arbitrary `BindingState` from compact seeds — every
        /// field populated so the properties range over the whole
        /// event vocabulary.
        fn arb_state(seed: &StateSeed) -> BindingState {
            let (accepted_seed, contested, (pending_n, losing_n, divergence_n), fork_seed) = seed;

            let accepted_binding = accepted_seed.map(|(doc_seed, serial, confirmed)| {
                accepted(
                    doc_seed % 4,
                    serial % 64,
                    if confirmed {
                        BindingGrade::Confirmed
                    } else {
                        BindingGrade::Provisional
                    },
                )
            });

            BindingState {
                accepted: accepted_binding.as_ref().and_then(|s| s.accepted),
                contested: *contested,
                divergence: (0..divergence_n % 3)
                    .map(|i| Divergence {
                        alleged: doc(20 + i),
                        source: if i % 2 == 0 {
                            DivergenceSource::Claim
                        } else {
                            DivergenceSource::Pin
                        },
                    })
                    .collect(),
                effective_serial: accepted_binding.and_then(|s| s.effective_serial),
                forks: (0..fork_seed % 3)
                    .map(|i| Fork {
                        document: doc(i % 2),
                        at: generation(30 + i),
                    })
                    .collect(),
                losing_acceptances: (0..losing_n % 3).map(|i| doc(10 + i)).collect(),
                pending: (0..pending_n % 3).map(|i| doc(5 + i)).collect(),
                succession_forks: if fork_seed % 5 == 0 {
                    vec![SuccessionFork {
                        predecessor: doc(1),
                        successors: vec![doc(2), doc(3)],
                    }]
                } else {
                    vec![]
                },
                tenure: None,
            }
        }

        /// `diff(a, a) == []` for EVERY state, not one example: a
        /// derivation compared with itself surfaces nothing.
        #[test]
        fn diff_of_identical_states_is_empty() {
            bolero::check!().with_type::<StateSeed>().for_each(|seed| {
                let state = derivation(arb_state(seed));
                assert!(state.diff(&state).is_empty());
            });
        }

        /// Reversing a diff produces the duals: badges surface ⇄
        /// clear, binding changes and grade moves flip their
        /// endpoints — while fork surfacing and serial regressions
        /// are one-directional (fork removal and serial progress are
        /// silent).
        #[test]
        fn diff_reversal_produces_event_duals() {
            bolero::check!()
                .with_type::<(StateSeed, StateSeed)>()
                .for_each(|(before_seed, after_seed)| {
                    let before = derivation(arb_state(before_seed));
                    let after = derivation(arb_state(after_seed));

                    let forward: Vec<EventKind> =
                        after.diff(&before).into_iter().map(|e| e.kind).collect();
                    let backward: Vec<EventKind> =
                        before.diff(&after).into_iter().map(|e| e.kind).collect();

                    for kind in &forward {
                        match kind {
                            EventKind::BindingChanged { from, to } => assert!(
                                backward.contains(&EventKind::BindingChanged {
                                    from: *to,
                                    to: *from,
                                }),
                                "binding changes reverse"
                            ),
                            EventKind::GradeChanged { from, to } => assert!(
                                backward.contains(&EventKind::GradeChanged {
                                    from: *to,
                                    to: *from,
                                }),
                                "grade moves reverse"
                            ),
                            EventKind::ContestedEntered => {
                                assert!(backward.contains(&EventKind::ContestedCleared));
                            }
                            EventKind::ContestedCleared => {
                                assert!(backward.contains(&EventKind::ContestedEntered));
                            }
                            EventKind::PendingSurfaced(d) => {
                                assert!(backward.contains(&EventKind::PendingCleared(*d)));
                            }
                            EventKind::PendingCleared(d) => {
                                assert!(backward.contains(&EventKind::PendingSurfaced(*d)));
                            }
                            EventKind::LosingAcceptanceSurfaced(d) => {
                                assert!(backward.contains(&EventKind::LosingAcceptanceCleared(*d)));
                            }
                            EventKind::LosingAcceptanceCleared(d) => {
                                assert!(
                                    backward.contains(&EventKind::LosingAcceptanceSurfaced(*d))
                                );
                            }
                            EventKind::DivergenceSurfaced(d) => {
                                assert!(backward.contains(&EventKind::DivergenceCleared(*d)));
                            }
                            EventKind::DivergenceCleared(d) => {
                                assert!(backward.contains(&EventKind::DivergenceSurfaced(*d)));
                            }
                            // One-directional kinds: their removal /
                            // reversal is silent, never an event.
                            EventKind::LineageForkSurfaced(fork) => assert!(
                                !backward.contains(&EventKind::LineageForkSurfaced(*fork)),
                                "fork removal is silent"
                            ),
                            EventKind::SuccessionForkSurfaced(fork) => assert!(
                                !backward
                                    .contains(&EventKind::SuccessionForkSurfaced(fork.clone())),
                                "fork removal is silent"
                            ),
                            EventKind::SerialRegression { .. } => assert!(
                                !backward
                                    .iter()
                                    .any(|k| matches!(k, EventKind::SerialRegression { .. })),
                                "serial progress is silent"
                            ),
                        }
                    }
                });
        }
    }
}
