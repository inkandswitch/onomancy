//! Conformance scenarios for `VerifierState::compute(store, now, decisions)`:
//! each test pins one row of the specs' condition tables (binding-cache
//! Conditions; dns-anchor dispositions), named for the behavior it pins,
//! plus the permutation-determinism property.

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use onomancy_core::{
    anchor::doc::DocAnchor,
    collections::{Map, Set},
    time::UnixSeconds,
};
use onomancy_dnssec::txt::serial::Serial;
use testresult::TestResult;

use onomancy_protocol::{
    test_utils::{
        Binding, binding, binding_at, binding_carrying, doc, generation, host, host2, rotation,
        succession,
    },
    verifier::state::{
        VerifierState,
        binding_state::{BindingGrade, BindingState, ContinuityGrade, DivergenceSource},
        decisions::{Acceptance, Claim, Decisions},
        diff::EventKind,
        memory::{authority::MemoryAuthority, validator::MemoryValidator},
        store::{Store, item::Item},
    },
};

const NOW: u64 = 1_755_000_000;

/// Serial deferral bound (5 minutes, ms convention) — mirrors the
/// derivation's private `SKEW_MS` for the boundary scenarios.
const SKEW_MS: u64 = 5 * 60 * 1000;

fn run(bindings: &[&Binding], decisions: &Decisions, extra: Vec<Item>) -> BindingState {
    derive_full(bindings, decisions, extra)
        .bindings
        .get(&host())
        .cloned()
        .unwrap_or_default()
}

/// The full derivation, for scenarios that diff two states or read
/// more than one hostname. Bindings register under their own
/// certificate hostname, so multi-host fixtures need no extra setup.
fn derive_full(bindings: &[&Binding], decisions: &Decisions, extra: Vec<Item>) -> VerifierState {
    let mut validator = MemoryValidator::default();
    let mut store = Store::default();

    for b in bindings {
        validator = validator.with(b.cert.hostname().clone(), &b.chain, b.proof.clone());
        store.insert(Item::Record(b.cert.clone()));
    }
    for item in extra {
        store.insert(item);
    }

    VerifierState::compute(
        &store,
        UnixSeconds::from(NOW),
        decisions,
        &Map::default(),
        &validator,
        &MemoryAuthority::default(),
    )
}

/// Nothing survived: the FULL default state — rejection is
/// distinguishable from contested-masking (which also blanks
/// `accepted`, but sets `contested` and may leave forks standing).
fn assert_rejected(state: &BindingState) {
    assert_eq!(
        *state,
        BindingState::default(),
        "rejected evidence must leave no residue at all"
    );
}

/// Contested-masked: the output is blanked BY the contest — the
/// other way `accepted` reads `None`.
fn assert_masked(state: &BindingState) {
    assert!(state.contested, "masking requires a standing contest");
    assert!(state.accepted.is_none(), "contested output is empty");
    assert!(
        state.effective_serial.is_none(),
        "a masked output carries no serial"
    );
}

fn accept(document: DocAnchor, cited: &Binding) -> Decisions {
    let mut acceptances = Map::default();
    let mut set = Set::default();
    set.insert(cited.cert.digest().erase());
    acceptances.insert(
        host(),
        vec![Acceptance {
            document,
            cited: set,
        }],
    );

    Decisions {
        acceptances,
        ..Decisions::default()
    }
}

#[test]
fn sole_fresh_record_is_accepted_confirmed() -> TestResult {
    // Fresh window covering NOW.
    let b = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50)?;
    let state = run(&[&b], &Decisions::default(), vec![]);

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(1));
    assert_eq!(accepted.generation, generation(11));
    assert_eq!(accepted.grade, BindingGrade::Confirmed);
    assert_eq!(state.effective_serial, Some(Serial::from(100)));
    assert!(!state.contested && state.pending.is_empty());
    Ok(())
}

#[test]
fn sole_stale_first_contact_is_provisional_incumbent() -> TestResult {
    // Sole candidate, only stale evidence.
    let b = binding(1, 11, 1, 100, (NOW - 5000, NOW - 1000), 50)?;
    let state = run(&[&b], &Decisions::default(), vec![]);

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(1), "the sole candidate is the one");
    assert_eq!(accepted.grade, BindingGrade::Provisional);
    assert_eq!(state.effective_serial, Some(Serial::from(100)));
    assert!(!state.contested && state.pending.is_empty());
    Ok(())
}

#[test]
fn stale_unproven_challenger_is_pending_never_displacing() -> TestResult {
    // Acceptance-backed incumbent (doc 1), stale challenger (doc 2)
    // with a strictly later zone-state key and no proof.
    let incumbent = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50)?;
    let challenger = binding(2, 22, 2, 999, (NOW - 1500, NOW - 100), 60)?;

    let state = run(
        &[&incumbent, &challenger],
        &accept(doc(1), &incumbent),
        vec![],
    );

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(1), "incumbent stands");
    assert_eq!(state.pending, vec![doc(2)], "challenger quarantined");
    assert!(!state.contested, "never displaces — and never masks either");
    Ok(())
}

#[test]
fn fresh_challenger_is_eligible_and_displaces() -> TestResult {
    let incumbent = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50)?;
    let challenger = binding(2, 22, 2, 999, (NOW - 100, NOW + 1000), 60)?;

    let state = run(
        &[&incumbent, &challenger],
        &accept(doc(1), &incumbent),
        vec![],
    );

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(2), "fresh evidence is eligible");
    assert_eq!(accepted.grade, BindingGrade::Confirmed);
    assert_eq!(
        accepted.continuity,
        ContinuityGrade::Unproven,
        "displacement without a proof path is surfaced as unproven — \
         the grade that gates the use-time MUST-prompt (B4)"
    );
    assert!(state.pending.is_empty());
    Ok(())
}

#[test]
fn a_b2_displacement_emits_a_binding_change_in_the_diff() -> TestResult {
    // B2's spec text: "output changes; binding-change event in the
    // diff". Derived states, not handcrafted ones: the incumbent
    // stands alone, then the fresh challenger arrives.
    let incumbent = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50)?;
    let challenger = binding(2, 22, 2, 999, (NOW - 100, NOW + 1000), 60)?;

    let decisions = accept(doc(1), &incumbent);
    let before = derive_full(&[&incumbent], &decisions, vec![]);
    let after = derive_full(&[&incumbent, &challenger], &decisions, vec![]);

    let events = after.diff(&before);
    assert!(
        events.iter().any(|event| event.hostname == host()
            && event.kind
                == EventKind::BindingChanged {
                    from: Some(doc(1)),
                    to: Some(doc(2)),
                }),
        "the displacement is an event-class binding change: {events:?}"
    );
    Ok(())
}

#[test]
fn succession_proof_makes_a_stale_challenger_eligible() -> TestResult {
    let incumbent = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50)?;
    let challenger = binding(2, 22, 2, 999, (NOW - 1500, NOW - 100), 60)?;

    // A valid successor statement doc1 → doc2 for this hostname.
    let state = run(
        &[&incumbent, &challenger],
        &accept(doc(1), &incumbent),
        vec![Item::Successor(succession(1, 2, 9)?)],
    );

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(2), "proof chains from incumbent");
    assert_eq!(
        accepted.continuity,
        ContinuityGrade::Bridged,
        "the departing document has no fresh support: provisional hop"
    );
    assert!(state.pending.is_empty());
    Ok(())
}

#[test]
fn directly_proven_migration_is_confirmed() -> TestResult {
    // Fresh departure, one hop, generation on-path: the fully-checked
    // case. Continuity is directly proven and the fresh terminus
    // confirms.
    let incumbent = binding(1, 11, 1, 100, (NOW - 5000, NOW + 1000), 50)?;
    let successor = binding(2, 22, 2, 200, (NOW - 1000, NOW + 2000), 60)?;

    let state = run(
        &[&incumbent, &successor],
        &accept(doc(1), &incumbent),
        vec![Item::Successor(succession(1, 2, 9)?)],
    );

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(2));
    assert_eq!(accepted.continuity, ContinuityGrade::Proven);
    assert_eq!(accepted.grade, BindingGrade::Confirmed);
    Ok(())
}

#[test]
fn bridged_departure_caps_the_grade_at_provisional() -> TestResult {
    // The departing document has only STALE support, so the hop
    // cannot be fully checked — and a bridged verdict caps the grade
    // even though the terminus itself has fresh, DNSSEC-vouched
    // evidence. A bridged verdict under eclipse is exactly what a
    // history-forging attacker wants a verifier to sit on.
    let incumbent = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50)?;
    let successor = binding(2, 22, 2, 200, (NOW - 1000, NOW + 2000), 60)?;

    let state = run(
        &[&incumbent, &successor],
        &accept(doc(1), &incumbent),
        vec![Item::Successor(succession(1, 2, 9)?)],
    );

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(2));
    assert_eq!(accepted.continuity, ContinuityGrade::Bridged);
    assert_eq!(
        accepted.grade,
        BindingGrade::Provisional,
        "fresh terminus evidence does not launder a provisional hop"
    );
    Ok(())
}

#[test]
fn multi_hop_bridges_are_always_provisional() -> TestResult {
    // R → S → T with everything fresh: only the hop departing the
    // accepted binding can ever be fully checked — the S → T hop has
    // no generation-key memory to check attestation against, so the
    // verdict is bridged and the binding provisional.
    let origin = binding(1, 11, 1, 100, (NOW - 5000, NOW + 1000), 50)?;
    let terminus = binding(3, 33, 2, 300, (NOW - 1000, NOW + 2000), 60)?;

    let state = run(
        &[&origin, &terminus],
        &accept(doc(1), &origin),
        vec![
            Item::Successor(succession(1, 2, 9)?),
            Item::Successor(succession(2, 3, 9)?),
        ],
    );

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(3), "incumbency extends along proofs");
    assert_eq!(accepted.continuity, ContinuityGrade::Bridged);
    assert_eq!(accepted.grade, BindingGrade::Provisional);
    assert!(state.pending.is_empty(), "proven history is never pending");
    Ok(())
}

#[test]
fn fresh_record_with_lower_serial_wins_and_resets_the_ratchet() -> TestResult {
    // Same document: stale record with a huge serial, fresh record
    // with a small one. Fresh wins rung 0; effective serial follows
    // the WINNER (the downward move is the surfaced ratchet reset).
    let stale_high = binding(1, 11, 1, 999, (NOW - 5000, NOW - 1000), 50)?;
    let fresh_low = binding(1, 11, 2, 7, (NOW - 500, NOW + 500), 60)?;

    let state = run(&[&stale_high, &fresh_low], &Decisions::default(), vec![]);

    assert_eq!(state.effective_serial, Some(Serial::from(7)));
    assert_eq!(
        state.accepted.expect("accepted").grade,
        BindingGrade::Confirmed
    );
    assert_eq!(
        state.tenure,
        Some(onomancy_protocol::test_utils::window(NOW - 5000, NOW + 500)),
        "tenure spans the document's evidence: earliest inception to \
         latest window end"
    );
    Ok(())
}

#[test]
fn a_derived_ratchet_reset_surfaces_as_serial_regression() -> TestResult {
    // The diff the test above's name promises, from DERIVED states:
    // stale-high alone, then the fresh-low record arrives. The serial
    // moves 999 → 7 (event-class), and the same transition carries
    // the grade move provisional → confirmed (badge-class).
    let stale_high = binding(1, 11, 1, 999, (NOW - 5000, NOW - 1000), 50)?;
    let fresh_low = binding(1, 11, 2, 7, (NOW - 500, NOW + 500), 60)?;

    let before = derive_full(&[&stale_high], &Decisions::default(), vec![]);
    let after = derive_full(&[&stale_high, &fresh_low], &Decisions::default(), vec![]);

    let events = after.diff(&before);
    assert!(
        events.iter().any(|event| {
            event.kind
                == EventKind::SerialRegression {
                    from: Serial::from(999),
                    to: Serial::from(7),
                }
                && event.kind.may_prompt()
        }),
        "the downward serial is the surfaced ratchet reset: {events:?}"
    );
    assert!(
        events.iter().any(|event| {
            event.kind
                == EventKind::GradeChanged {
                    from: BindingGrade::Provisional,
                    to: BindingGrade::Confirmed,
                }
                && !event.kind.may_prompt()
        }),
        "the grade move rides the same diff, badge-class: {events:?}"
    );
    Ok(())
}

#[test]
fn zone_equivocation_is_contested_with_empty_output() -> TestResult {
    // Two unconnected documents, both stale, equal (window_end,
    // serial) — issued_at differs but MUST NOT resolve it.
    let a = binding(1, 11, 1, 100, (NOW - 5000, NOW - 1000), 50)?;
    let b = binding(2, 22, 2, 100, (NOW - 5000, NOW - 1000), 99)?;

    let state = run(&[&a, &b], &Decisions::default(), vec![]);

    assert_masked(&state);
    Ok(())
}

#[test]
fn stale_candidates_with_ordered_keys_pick_the_later_provisionally() -> TestResult {
    // Equivocation is narrow: strictly ordered windows are NOT contested.
    let earlier = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50)?;
    let later = binding(2, 22, 2, 100, (NOW - 4000, NOW - 1000), 50)?;

    let state = run(&[&earlier, &later], &Decisions::default(), vec![]);

    assert!(!state.contested);
    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(2), "later zone state wins");
    assert_eq!(accepted.grade, BindingGrade::Provisional);
    Ok(())
}

#[test]
fn fresh_record_with_generation_off_path_is_rejected() -> TestResult {
    let b = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50)?;

    let mut validator = MemoryValidator::default().with(host(), &b.chain, b.proof.clone());
    let _ = &mut validator;
    let mut store = Store::default();
    store.insert(Item::Record(b.cert.clone()));

    let derivation = VerifierState::compute(
        &store,
        UnixSeconds::from(NOW),
        &Decisions::default(),
        &Map::default(),
        &validator,
        &MemoryAuthority::default().off_path(&generation(11)),
    );

    let state = derivation
        .bindings
        .get(&host())
        .cloned()
        .unwrap_or_default();
    assert_rejected(&state);
    Ok(())
}

#[test]
fn a_reset_excludes_the_challenger() -> TestResult {
    let incumbent = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50)?;
    let poison = binding(2, 22, 2, 999, (NOW - 100, NOW + 1000), 60)?;

    // A fresh challenger would displace — but it is excluded.
    let mut decisions = accept(doc(1), &incumbent);
    let mut excluded = Set::default();
    excluded.insert(poison.cert.digest().erase());
    decisions.resets.insert(host(), excluded);

    let state = run(&[&incumbent, &poison], &decisions, vec![]);

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(1), "excluded evidence is inert");
    assert!(state.pending.is_empty(), "excluded ≠ pending");
    Ok(())
}

#[test]
fn outranked_acceptances_surface_as_losers() -> TestResult {
    // Two acceptances for different documents: the receipts rule
    // picks the one whose cited records carry the greater zone-state
    // key — and the loser is surfaced, never silently dropped.
    let older = binding(1, 11, 1, 100, (NOW - 9000, NOW - 5000), 10)?;
    let newer = binding(2, 22, 2, 200, (NOW - 4000, NOW - 1000), 20)?;

    let mut decisions = accept(doc(1), &older);
    let mut cited = Set::default();
    cited.insert(newer.cert.digest().erase());
    decisions
        .acceptances
        .get_mut(&host())
        .expect("acceptance entry for the test hostname")
        .push(Acceptance {
            document: doc(2),
            cited,
        });

    let state = run(&[&older, &newer], &decisions, vec![]);

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(2), "greater receipts win");
    assert_eq!(
        state.losing_acceptances,
        vec![doc(1)],
        "the outranked acceptance is surfaced"
    );
    assert!(!state.contested, "an outranked loser is not a tie");
    Ok(())
}

#[test]
fn far_future_serials_are_deferred() -> TestResult {
    // Serial (ms convention) more than 5 minutes past NOW.
    let poisoned = binding(
        1,
        11,
        1,
        NOW * 1000 + 6 * 60 * 1000,
        (NOW - 1000, NOW + 1000),
        50,
    )?;

    let state = run(&[&poisoned], &Decisions::default(), vec![]);
    assert_rejected(&state);
    Ok(())
}

#[test]
fn divergent_claims_badge_but_do_not_move_bindings() -> TestResult {
    let b = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50)?;

    let decisions = Decisions {
        claims: vec![Claim {
            hostname: host(),
            document: doc(3),
            note: None,
        }],
        ..Decisions::default()
    };

    let state = run(&[&b], &decisions, vec![]);

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(1), "claims never move bindings");
    assert_eq!(state.divergence.len(), 1);
    assert_eq!(state.divergence[0].alleged, doc(3));
    assert_eq!(
        state.divergence[0].source,
        DivergenceSource::Claim,
        "the badge names its source — a claim, not a pin"
    );
    Ok(())
}

/// The protected prefix and fork repair: rewinds stay rejected
/// through forks, and convergence merges settle the lineage.
mod protected_prefix_and_fork_repair {
    use super::*;

    #[test]
    fn the_protected_prefix_survives_a_fork() -> TestResult {
        // Lineage G11→G12→G13, then a fork at G13 (→G14 and →G15).
        // A stale record attesting the PROTECTED G11 is still a provable
        // rewind — the fork buys no immunity below the fork point — while
        // a record attesting fork-implicated G14 survives, surfaced.
        let rewind = binding(1, 11, 1, 50, (NOW - 9000, NOW - 5000), 10)?;
        let branch = binding(1, 14, 2, 60, (NOW - 4000, NOW - 1000), 20)?;

        let lineage = vec![
            Item::Rotation(rotation(1, 11, 12)?),
            Item::Rotation(rotation(1, 12, 13)?),
            Item::Rotation(rotation(1, 13, 14)?),
            Item::Rotation(rotation(1, 13, 15)?),
        ];

        let state = run(&[&rewind, &branch], &Decisions::default(), lineage);

        let accepted = state.accepted.expect("branch record survives");
        assert_eq!(
            accepted.generation,
            generation(14),
            "rewind rejected, branch kept"
        );
        assert!(
            state.forks.iter().any(|f| f.at == generation(13)),
            "the fork is surfaced"
        );
        Ok(())
    }

    #[test]
    fn lineage_descent_orders_within_a_document_before_the_key() -> TestResult {
        // Fork at G11 (→G12, →G13): the rewind rejection is suspended
        // for the implicated suffix, so records attesting the fork point
        // and a branch both survive to stage 5 — where rung 1's
        // same-document half must order them. The branch record wins on
        // signed descent despite a LOWER zone-state key; the serial is
        // only a tiebreak when lineage is silent.
        let at_fork = binding(1, 11, 1, 200, (NOW - 5000, NOW - 1000), 90)?;
        let on_branch = binding(1, 12, 2, 50, (NOW - 6000, NOW - 2000), 10)?;

        let lineage = vec![
            Item::Rotation(rotation(1, 11, 12)?),
            Item::Rotation(rotation(1, 11, 13)?),
        ];

        let state = run(&[&at_fork, &on_branch], &Decisions::default(), lineage);

        let accepted = state.accepted.expect("accepted");
        assert_eq!(
            accepted.generation,
            generation(12),
            "descent outranks the zone-state key"
        );
        assert_eq!(
            state.effective_serial,
            Some(Serial::from(50)),
            "the descendant record's serial, not the fork point's"
        );
        assert!(
            state.forks.iter().any(|f| f.at == generation(11)),
            "the fork is still surfaced"
        );
        Ok(())
    }

    #[test]
    fn cross_branch_records_fall_back_to_the_key_deterministically() -> TestResult {
        // Records on the two branches of the same fork: descent orders
        // neither over the other (incomparable lineage is never
        // evidence), so rung 2's key decides — deterministically — while
        // the fork stays surfaced.
        let branch_a = binding(1, 12, 1, 50, (NOW - 6000, NOW - 2000), 10)?;
        let branch_b = binding(1, 13, 2, 200, (NOW - 5000, NOW - 1000), 90)?;

        let lineage = vec![
            Item::Rotation(rotation(1, 11, 12)?),
            Item::Rotation(rotation(1, 11, 13)?),
        ];

        let state = run(&[&branch_a, &branch_b], &Decisions::default(), lineage);

        let accepted = state.accepted.expect("accepted");
        assert_eq!(accepted.generation, generation(13), "higher key wins");
        assert!(
            state.forks.iter().any(|f| f.at == generation(11)),
            "picking a branch record never resolves the fork"
        );
        Ok(())
    }

    #[test]
    fn fork_repair_by_convergence_merge_settles_the_lineage() -> TestResult {
        // Same fork, repaired: both branch heads retire into fresh G16
        // (a double-successor MERGE — legal, only G16's holder can mint
        // it). Single head again: retired branches rejoin the protected
        // prefix, the current generation is accepted, the historical fork
        // stays surfaced.
        let stale_branch = binding(1, 14, 1, 50, (NOW - 9000, NOW - 5000), 10)?;
        let current = binding(1, 16, 2, 60, (NOW - 1000, NOW + 1000), 20)?;

        let lineage = vec![
            Item::Rotation(rotation(1, 11, 12)?),
            Item::Rotation(rotation(1, 12, 13)?),
            Item::Rotation(rotation(1, 13, 14)?),
            Item::Rotation(rotation(1, 13, 15)?),
            Item::Rotation(rotation(1, 14, 16)?),
            Item::Rotation(rotation(1, 15, 16)?),
        ];

        let state = run(&[&stale_branch, &current], &Decisions::default(), lineage);

        let accepted = state.accepted.expect("current generation accepted");
        assert_eq!(accepted.generation, generation(16));
        assert_eq!(
            state.effective_serial,
            Some(Serial::from(60)),
            "retired branch record is rewind-rejected post-repair"
        );
        assert!(
            state.forks.iter().any(|f| f.at == generation(13)),
            "repair converges heads; it never launders the fork"
        );
        Ok(())
    }

    #[test]
    fn unauthorized_statements_have_no_lineage_effect() -> TestResult {
        // The rotation's carriage fails authority verification: it must
        // be discarded entirely — no rewind rejection, no fork evidence.
        let old_gen = binding(1, 11, 1, 50, (NOW - 1000, NOW + 1000), 10)?;

        let mut validator =
            MemoryValidator::default().with(host(), &old_gen.chain, old_gen.proof.clone());
        let _ = &mut validator;
        let mut store = Store::default();
        store.insert(Item::Record(old_gen.cert.clone()));
        store.insert(Item::Rotation(rotation(1, 11, 12)?));

        let derivation = VerifierState::compute(
            &store,
            UnixSeconds::from(NOW),
            &Decisions::default(),
            &Map::default(),
            &validator,
            &MemoryAuthority::default().deny(doc(1), generation(12).verifying_key()),
        );

        let state = derivation
            .bindings
            .get(&host())
            .cloned()
            .unwrap_or_default();
        let accepted = state.accepted.expect("old generation still accepted");
        assert_eq!(
            accepted.generation,
            generation(11),
            "no rewind rejection from garbage"
        );
        assert!(state.forks.is_empty(), "never fork evidence either");
        Ok(())
    }
}

/// Extraction closure under resets: excluding a carrier excludes what
/// it carried, unless an unexcluded item independently carries it.
mod extraction_closure_under_resets {
    use super::*;

    #[test]
    fn statements_survive_resets_via_independent_carriers() -> TestResult {
        // Rotation R (G11→G12) is carried by BOTH cert A and cert B.
        // Excluding only A leaves R in force via B; excluding both
        // removes it — and neither outcome depends on insertion order.
        let statement = rotation(1, 11, 12)?;
        let carrier_a = binding_carrying(
            1,
            12,
            1,
            50,
            (NOW - 5000, NOW - 1000),
            10,
            vec![statement.clone()],
        )?;
        let carrier_b = binding_carrying(
            1,
            12,
            2,
            60,
            (NOW - 4000, NOW - 500),
            20,
            vec![statement.clone()],
        )?;
        let rewind = binding(1, 11, 3, 70, (NOW - 3000, NOW - 200), 30)?;

        let reset_a = {
            let mut decisions = Decisions::default();
            let mut excluded = Set::default();
            excluded.insert(carrier_a.cert.digest().erase());
            decisions.resets.insert(host(), excluded);
            decisions
        };

        let state = run(&[&carrier_a, &carrier_b, &rewind], &reset_a, vec![]);
        let accepted = state.accepted.expect("accepted");
        assert_eq!(
            accepted.generation,
            generation(12),
            "R survives via the non-excluded carrier: the rewind stays rejected"
        );

        let reset_both = {
            let mut decisions = Decisions::default();
            let mut excluded = Set::default();
            excluded.insert(carrier_a.cert.digest().erase());
            excluded.insert(carrier_b.cert.digest().erase());
            decisions.resets.insert(host(), excluded);
            decisions
        };

        let state = run(&[&carrier_a, &carrier_b, &rewind], &reset_both, vec![]);
        let accepted = state.accepted.expect("accepted");
        assert_eq!(
            accepted.generation,
            generation(11),
            "excluding every carrier excludes the extracted statement"
        );
        Ok(())
    }
}

/// Succession forks: competing valid successor statements stop
/// incumbency extension and eligibility, surfaced.
mod succession_fork_isolation {
    use super::*;

    #[test]
    fn succession_forks_surface_and_stop_eligibility() -> TestResult {
        // Two valid successor statements from doc1: →doc2 and →doc3.
        // Provable equivocation: surfaced, and NEITHER branch can ride
        // the forked proof graph past the incumbent.
        let incumbent = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50)?;
        let branch_x = binding(2, 22, 2, 999, (NOW - 1500, NOW - 100), 60)?;
        let branch_y = binding(3, 33, 3, 998, (NOW - 1500, NOW - 100), 60)?;

        let proofs = vec![
            Item::Successor(succession(1, 2, 21)?),
            Item::Successor(succession(1, 3, 22)?),
        ];

        let state = run(
            &[&incumbent, &branch_x, &branch_y],
            &accept(doc(1), &incumbent),
            proofs,
        );

        let accepted = state.accepted.expect("accepted");
        assert_eq!(
            accepted.document,
            doc(1),
            "a forked proof graph confers no eligibility"
        );
        assert_eq!(state.succession_forks.len(), 1);
        assert_eq!(state.succession_forks[0].predecessor, doc(1));
        assert_eq!(
            state.pending,
            vec![doc(2), doc(3)],
            "both unproven branches badge pending — these two, exactly"
        );
        Ok(())
    }
}

mod props {
    use super::*;

    /// Lehmer-code permutation: decode `code` into an arbitrary
    /// reordering of `items` (Fisher–Yates driven by the code
    /// digits). Reversal and rotation only ever explore `2n` of the
    /// `n!` orders; this reaches all of them.
    fn permute<T: Clone>(items: &[T], code: &[u8]) -> Vec<T> {
        let mut pool: Vec<T> = items.to_vec();
        let mut out = Vec::with_capacity(pool.len());

        for (i, _) in items.iter().enumerate() {
            let digit = usize::from(*code.get(i % code.len().max(1)).unwrap_or(&0));
            let pick = digit % pool.len();
            out.push(pool.remove(pick));
        }

        out
    }

    /// Verification target 7: the derivation is a function of the
    /// evidence SET — any permutation (reversal, rotation, and an
    /// arbitrary Lehmer-coded shuffle) of store insertion order
    /// yields identical output, and the diff between two permuted
    /// derivations is empty. The pool includes carried statements,
    /// standalone statements, resets, acceptances, a bare chain
    /// refresh, a second hostname, and pins — the inputs that made
    /// the first implementation order-dependent, plus the cross-host
    /// interference surfaces.
    #[test]
    #[allow(clippy::too_many_lines)] // one property, one pool: splitting hides the scenario
    fn derivation_is_insertion_order_insensitive() {
        bolero::check!()
            .with_type::<(Vec<(u8, u8, u64, u64, bool)>, usize, Vec<u8>)>()
            .for_each(|(specs, rotate_by, lehmer)| {
                let bindings: Vec<Binding> = specs
                    .iter()
                    .take(6)
                    .enumerate()
                    .map(|(i, (doc_seed, serial, from, span, fresh))| {
                        let from = NOW - 10_000 + (from % 9_000);
                        let to = if *fresh {
                            NOW + 1 + (span % 1000)
                        } else {
                            from + (span % 1000)
                        };
                        #[allow(clippy::cast_possible_truncation)]
                        let tag = i as u8;
                        binding(
                            doc_seed % 3,
                            (doc_seed % 3) + 10,
                            tag,
                            u64::from(*serial),
                            (from, to),
                            u64::from(*serial) % 97,
                        )
                        .expect("under the unit cap")
                    })
                    .collect();

                if bindings.is_empty() {
                    return;
                }

                let mut validator = MemoryValidator::default();
                for b in &bindings {
                    validator = validator.with(host(), &b.chain, b.proof.clone());
                }

                // Decisions: an acceptance PLUS a reset excluding one
                // carrier — exclusion closure is where order
                // dependence hid the first time.
                let mut decisions = accept(doc(specs[0].0 % 3), &bindings[0]);
                let mut excluded = Set::default();
                excluded.insert(bindings[bindings.len() - 1].cert.digest().erase());
                decisions.resets.insert(host(), excluded);

                // The item pool: records, a statement carried by TWO
                // of them, the same statement standalone, and a
                // succession proof.
                let carried = rotation(specs[0].0 % 3, 40, 41).expect("under the unit cap");
                let carrier_x = binding_carrying(
                    specs[0].0 % 3,
                    (specs[0].0 % 3) + 10,
                    100,
                    7,
                    (NOW - 8000, NOW - 7000),
                    1,
                    vec![carried.clone()],
                )
                .expect("under the unit cap");
                let carrier_y = binding_carrying(
                    specs[0].0 % 3,
                    (specs[0].0 % 3) + 10,
                    101,
                    8,
                    (NOW - 8000, NOW - 6900),
                    2,
                    vec![carried.clone()],
                )
                .expect("under the unit cap");
                validator = validator
                    .with(host(), &carrier_x.chain, carrier_x.proof.clone())
                    .with(host(), &carrier_y.chain, carrier_y.proof.clone());

                // Cross-host interference surface: a binding at a
                // second hostname, plus a bare refresh rider for the
                // first one.
                let elsewhere = binding_at(
                    host2(),
                    (specs[0].0 % 3) + 4,
                    (specs[0].0 % 3) + 14,
                    102,
                    9,
                    (NOW - 2000, NOW + 2000),
                    3,
                )
                .expect("under the unit cap");
                let refreshed = binding(
                    specs[0].0 % 3,
                    (specs[0].0 % 3) + 10,
                    103,
                    11,
                    (NOW - 1500, NOW + 1500),
                    4,
                )
                .expect("under the unit cap");
                validator = validator
                    .with(host2(), &elsewhere.chain, elsewhere.proof.clone())
                    .with(host(), &refreshed.chain, refreshed.proof.clone());

                let mut pins = Map::default();
                pins.insert(host(), vec![doc(7)]);
                pins.insert(host2(), vec![doc((specs[0].0 % 3) + 4)]);

                let mut items: Vec<Item> = bindings
                    .iter()
                    .map(|b| Item::Record(b.cert.clone()))
                    .collect();
                items.extend([
                    Item::Record(carrier_x.cert.clone()),
                    Item::Record(carrier_y.cert.clone()),
                    Item::Record(elsewhere.cert.clone()),
                    Item::ChainRefresh {
                        hostname: host(),
                        chain: refreshed.chain.clone(),
                    },
                    Item::Rotation(carried),
                    Item::Rotation(rotation(specs[0].0 % 3, 41, 42).expect("under the unit cap")),
                    Item::Successor(
                        succession(specs[0].0 % 3, (specs[0].0 % 3) + 1, 45)
                            .expect("under the unit cap"),
                    ),
                ]);

                let forward: Store = items.iter().cloned().collect();
                let reversed: Store = items.iter().rev().cloned().collect();
                let rotated: Store = {
                    let mid = rotate_by % items.len();
                    items[mid..]
                        .iter()
                        .chain(items[..mid].iter())
                        .cloned()
                        .collect()
                };
                let shuffled: Store = permute(&items, lehmer).into_iter().collect();

                let run = |store: &Store| {
                    VerifierState::compute(
                        store,
                        UnixSeconds::from(NOW),
                        &decisions,
                        &pins,
                        &validator,
                        &MemoryAuthority::default(),
                    )
                };

                let baseline = run(&forward);
                assert_eq!(baseline, run(&reversed), "reversal changed the verdict");
                assert_eq!(baseline, run(&rotated), "rotation changed the verdict");

                let shuffled_state = run(&shuffled);
                assert_eq!(
                    baseline, shuffled_state,
                    "an arbitrary permutation changed the verdict"
                );
                assert!(
                    baseline.diff(&shuffled_state).is_empty(),
                    "permutations of one store must diff to nothing"
                );
            });
    }
}

/// Seam parity: certificate signers face the same authority check as
/// statement signers.
mod certificate_signer_authority {
    use super::*;

    #[test]
    fn unauthorized_certificate_signers_contribute_nothing() -> TestResult {
        // Same shape as the statement rule: a certificate whose signer the
        // authority refuses for its own document is discarded entirely —
        // no binding evidence, no accepted state. Vacuous under the
        // permissive default; the check that makes delegation graphs bite.
        let b = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50)?;

        let validator = MemoryValidator::default().with(host(), &b.chain, b.proof.clone());
        let mut store = Store::default();
        store.insert(Item::Record(b.cert.clone()));

        let derivation = VerifierState::compute(
            &store,
            UnixSeconds::from(NOW),
            &Decisions::default(),
            &Map::default(),
            &validator,
            // The certificate names its own signer — deny exactly that
            // key, not a re-derivation of the factory's seed scheme.
            &MemoryAuthority::default().deny(doc(1), b.cert.signer()),
        );

        let state = derivation
            .bindings
            .get(&host())
            .cloned()
            .unwrap_or_default();
        assert_rejected(&state);
        Ok(())
    }
}

/// Bare chain refreshes corroborate a certificate-backed document;
/// they never create candidacy on their own (binding-cache, The
/// Store).
mod refresh_corroboration {
    use super::*;

    #[test]
    fn a_bare_chain_refresh_alone_is_not_a_binding() -> TestResult {
        // The zone's word is one direction, and neither direction
        // alone is a binding (dns-anchor, Verification). A store holding
        // exactly one bare refresh — no certificate anywhere — must
        // derive no accepted binding, however valid the chain.
        let b = binding(1, 2, 7, 100, (NOW - 1_000, NOW + 100_000), NOW - 10)?;

        let validator = MemoryValidator::default().with(host(), &b.chain, b.proof.clone());
        let mut store = Store::default();
        store.insert(Item::ChainRefresh {
            hostname: host(),
            chain: b.chain.clone(),
        });

        let state = VerifierState::compute(
            &store,
            UnixSeconds::from(NOW),
            &Decisions::default(),
            &Map::default(),
            &validator,
            &MemoryAuthority::default(),
        )
        .bindings
        .get(&host())
        .cloned()
        .unwrap_or_default();

        assert_eq!(
            state.accepted, None,
            "a bare chain refresh must never make a document a candidate"
        );
        assert!(!state.contested, "absence of candidates is not a contest");
        Ok(())
    }

    #[test]
    fn a_bare_chain_refresh_corroborates_a_certificate_backed_document() -> TestResult {
        // The other half: the refresh's real job. A stale certificate
        // supplies candidacy (the document's direction, proven once); a
        // fresh bare refresh supplies the zone's current word — together
        // they confirm, where the certificate alone would only be
        // provisional.
        let lapsed = binding(1, 2, 7, 100, (NOW - 200_000, NOW - 50_000), NOW - 150_000)?;
        let fresh = binding(1, 2, 8, 150, (NOW - 1_000, NOW + 100_000), NOW - 10)?;

        let validator = MemoryValidator::default()
            .with(host(), &lapsed.chain, lapsed.proof.clone())
            .with(host(), &fresh.chain, fresh.proof.clone());

        let mut store = Store::default();
        store.insert(Item::Record(lapsed.cert.clone()));
        store.insert(Item::ChainRefresh {
            hostname: host(),
            chain: fresh.chain.clone(),
        });

        let state = VerifierState::compute(
            &store,
            UnixSeconds::from(NOW),
            &Decisions::default(),
            &Map::default(),
            &validator,
            &MemoryAuthority::default(),
        )
        .bindings
        .get(&host())
        .cloned()
        .unwrap_or_default();

        let accepted = state
            .accepted
            .expect("the certificate-backed document is accepted");
        assert_eq!(accepted.document, doc(1));
        assert_eq!(
            accepted.grade,
            BindingGrade::Confirmed,
            "the refresh's fresh window is what confirms"
        );
        assert_eq!(
            state.effective_serial,
            Some(Serial::from(150)),
            "the fresh refresh row is the document's ladder-best record"
        );
        Ok(())
    }

    #[test]
    fn a_refresh_never_revives_an_off_path_certificate() -> TestResult {
        // Corroboration across the stage boundary: the hostname's only
        // certificate is FRESH with an off-path generation — the
        // generation rules MUST reject it — and a fresh bare refresh
        // attests the same
        // document. The refresh is the zone's word alone; it must not
        // relaunder the document into candidacy, and its own path input
        // is judged against validated carriages, never assumed.
        let b = binding(1, 2, 7, 100, (NOW - 1_000, NOW + 100_000), NOW - 10)?;
        let refresh = binding(1, 2, 8, 150, (NOW - 1_000, NOW + 100_000), NOW - 5)?;

        let validator = MemoryValidator::default()
            .with(host(), &b.chain, b.proof.clone())
            .with(host(), &refresh.chain, refresh.proof.clone());
        let authority = MemoryAuthority::default().off_path(&generation(2));

        let mut store = Store::default();
        store.insert(Item::Record(b.cert.clone()));
        store.insert(Item::ChainRefresh {
            hostname: host(),
            chain: refresh.chain.clone(),
        });

        let state = VerifierState::compute(
            &store,
            UnixSeconds::from(NOW),
            &Decisions::default(),
            &Map::default(),
            &validator,
            &authority,
        )
        .bindings
        .get(&host())
        .cloned()
        .unwrap_or_default();

        assert_rejected(&state);
        Ok(())
    }

    #[test]
    fn a_refresh_never_revives_a_rewound_certificate() -> TestResult {
        // The rewind flavour: the settled
        // rotation G2→G3 puts G2 in the protected prefix, so the stale
        // certificate attesting G2 is rejected at stage 4. The fresh
        // bare refresh attests G3 — the CURRENT generation, on-path,
        // unprotected — so the refresh row itself survives every
        // stage-4 rule, and only the stage-5 candidacy restriction
        // (certificate-attested survivors) stands between the zone's
        // word and a Confirmed binding. This is the case the stage-2
        // filter alone cannot carry.
        let statement = rotation(1, 2, 3)?;
        let old = binding(1, 2, 7, 100, (NOW - 90_000, NOW - 50_000), 40)?;
        let refresh = binding(1, 3, 8, 150, (NOW - 1_000, NOW + 100_000), NOW - 5)?;

        let validator = MemoryValidator::default()
            .with(host(), &old.chain, old.proof.clone())
            .with(host(), &refresh.chain, refresh.proof.clone());

        let mut store = Store::default();
        store.insert(Item::Record(old.cert.clone()));
        store.insert(Item::Rotation(statement));
        store.insert(Item::ChainRefresh {
            hostname: host(),
            chain: refresh.chain.clone(),
        });

        let state = VerifierState::compute(
            &store,
            UnixSeconds::from(NOW),
            &Decisions::default(),
            &Map::default(),
            &validator,
            &MemoryAuthority::default(),
        )
        .bindings
        .get(&host())
        .cloned()
        .unwrap_or_default();

        assert_rejected(&state);
        Ok(())
    }

    #[test]
    fn a_refresh_cannot_swap_the_accepted_generation_off_path() -> TestResult {
        // The generation-swap: the document
        // IS a candidate — its certificate survives, stale, attesting
        // G2 on-path — and the zone then publishes a fresh record for a
        // NEW generation G9 that lies on no validated carriage's path.
        // A bare refresh carries that record. Its path input must be
        // judged against the validated carriages (off-path ⇒ fresh
        // reject), never assumed: otherwise the fresh refresh row
        // becomes the document's ladder-best record and the accepted
        // binding silently carries a generation key no carriage was
        // ever checked against.
        let cert = binding(1, 2, 7, 100, (NOW - 90_000, NOW - 50_000), 40)?;
        let refresh = binding(1, 9, 8, 150, (NOW - 1_000, NOW + 100_000), NOW - 5)?;

        let validator = MemoryValidator::default()
            .with(host(), &cert.chain, cert.proof.clone())
            .with(host(), &refresh.chain, refresh.proof.clone());
        let authority = MemoryAuthority::default().off_path(&generation(9));

        let mut store = Store::default();
        store.insert(Item::Record(cert.cert.clone()));
        store.insert(Item::ChainRefresh {
            hostname: host(),
            chain: refresh.chain.clone(),
        });

        let state = VerifierState::compute(
            &store,
            UnixSeconds::from(NOW),
            &Decisions::default(),
            &Map::default(),
            &validator,
            &authority,
        )
        .bindings
        .get(&host())
        .cloned()
        .unwrap_or_default();

        let accepted = state
            .accepted
            .expect("the certificate-backed document stands");
        assert_eq!(
            accepted.generation,
            generation(2),
            "the accepted generation must be the certificate-attested one"
        );
        assert_eq!(
            accepted.grade,
            BindingGrade::Provisional,
            "an off-path fresh refresh confers no fresh support"
        );
        Ok(())
    }

    #[test]
    fn equal_key_junk_never_blanks_an_acceptance_backed_incumbent() -> TestResult {
        // Pending and contested together: an acceptance-backed
        // incumbent, plus two stale, unproven, unconnected candidates
        // whose zone-state keys are fully equal. One junk record is a
        // pending badge; two junk records must not become a contest that
        // masks the binding — the candidate contest requires no standing
        // incumbent, and pending challengers never displace one, however
        // many arrive or how late their keys read.
        let incumbent = binding(1, 2, 1, 100, (NOW - 90_000, NOW - 50_000), 40)?;
        let junk_a = binding(2, 3, 2, 200, (NOW - 80_000, NOW - 40_000), 50)?;
        let junk_b = binding(3, 4, 3, 200, (NOW - 80_000, NOW - 40_000), 50)?;

        let state = run(
            &[&incumbent, &junk_a, &junk_b],
            &accept(doc(1), &incumbent),
            vec![],
        );

        assert!(
            !state.contested,
            "ineligible ties are pending, never a contest"
        );
        let accepted = state.accepted.expect("the incumbent stands");
        assert_eq!(accepted.document, doc(1));
        assert_eq!(
            state.pending,
            vec![doc(2), doc(3)],
            "both challengers badge pending"
        );
        Ok(())
    }

    #[test]
    fn a_dual_publish_refresh_does_not_contest_its_own_hostname() -> TestResult {
        // A bare refresh of an RRset carrying TWO records
        // for one document (serials 100 and 150) — the spec's sanctioned
        // migration shape. Within one item the highest serial is the
        // zone's word, exactly as the certificate path reads it; a
        // publisher doing what the spec recommends must not render their
        // own name contested.
        let cert = binding(1, 2, 7, 100, (NOW - 90_000, NOW - 50_000), 40)?;
        let refresh = binding(1, 2, 8, 150, (NOW - 1_000, NOW + 100_000), NOW - 5)?;

        let dual = onomancy_dnssec::chain_proof::ChainProof {
            records: vec![
                onomancy_dnssec::txt::record::TxtRecord::new(
                    Serial::from(100),
                    onomancy_protocol::test_utils::generation(2),
                    doc(1),
                ),
                onomancy_dnssec::txt::record::TxtRecord::new(
                    Serial::from(150),
                    onomancy_protocol::test_utils::generation(2),
                    doc(1),
                ),
            ],
            window: refresh.proof.window,
        };

        let validator = MemoryValidator::default()
            .with(host(), &cert.chain, cert.proof.clone())
            .with(host(), &refresh.chain, dual);

        let mut store = Store::default();
        store.insert(Item::Record(cert.cert.clone()));
        store.insert(Item::ChainRefresh {
            hostname: host(),
            chain: refresh.chain.clone(),
        });

        let state = VerifierState::compute(
            &store,
            UnixSeconds::from(NOW),
            &Decisions::default(),
            &Map::default(),
            &validator,
            &MemoryAuthority::default(),
        )
        .bindings
        .get(&host())
        .cloned()
        .unwrap_or_default();

        assert!(
            !state.contested,
            "dual-publish is sanctioned, not a contest"
        );
        let accepted = state.accepted.expect("the document stands");
        assert_eq!(accepted.document, doc(1));
        assert_eq!(accepted.grade, BindingGrade::Confirmed);
        assert_eq!(
            state.effective_serial,
            Some(Serial::from(150)),
            "the higher serial is the zone's word"
        );
        Ok(())
    }

    #[test]
    fn an_acceptance_citing_a_dual_publish_refresh_holds() -> TestResult {
        // One cited ITEM can legally yield several
        // evidence rows — a bare refresh of a migration RRset carries one
        // row per document. A receipt-shape check that counts rows
        // against cited hashes silently voids exactly those receipts,
        // reverting the hostname to ladder-maximal incumbency. The check
        // must be per item.
        let cert_one = binding(1, 2, 1, 100, (NOW - 90_000, NOW - 50_000), 40)?;
        let challenger = binding(2, 3, 2, 200, (NOW - 80_000, NOW - 40_000), 50)?;
        let refresh = binding(1, 2, 8, 150, (NOW - 80_000, NOW - 40_000), 45)?;

        // The refresh's RRset dual-publishes ACROSS documents: one record
        // each for doc(1) and doc(2) — two evidence rows, one item hash.
        let dual = onomancy_dnssec::chain_proof::ChainProof {
            records: vec![
                onomancy_dnssec::txt::record::TxtRecord::new(
                    Serial::from(150),
                    onomancy_protocol::test_utils::generation(2),
                    doc(1),
                ),
                onomancy_dnssec::txt::record::TxtRecord::new(
                    Serial::from(150),
                    onomancy_protocol::test_utils::generation(3),
                    doc(2),
                ),
            ],
            window: refresh.proof.window,
        };

        let refresh_item = Item::ChainRefresh {
            hostname: host(),
            chain: refresh.chain.clone(),
        };

        let mut cited = Set::default();
        cited.insert(refresh_item.content_hash());
        let mut acceptances = Map::default();
        acceptances.insert(
            host(),
            vec![Acceptance {
                document: doc(1),
                cited,
            }],
        );
        let decisions = Decisions {
            acceptances,
            ..Decisions::default()
        };

        let validator = MemoryValidator::default()
            .with(host(), &cert_one.chain, cert_one.proof.clone())
            .with(host(), &challenger.chain, challenger.proof.clone())
            .with(host(), &refresh.chain, dual);

        let mut store = Store::default();
        store.insert(Item::Record(cert_one.cert.clone()));
        store.insert(Item::Record(challenger.cert.clone()));
        store.insert(refresh_item);

        let state = VerifierState::compute(
            &store,
            UnixSeconds::from(NOW),
            &decisions,
            &Map::default(),
            &validator,
            &MemoryAuthority::default(),
        )
        .bindings
        .get(&host())
        .cloned()
        .unwrap_or_default();

        assert!(!state.contested);
        let accepted = state
            .accepted
            .expect("the acceptance-backed incumbent stands");
        assert_eq!(
            accepted.document,
            doc(1),
            "a well-formed receipt must not be voided by a row count"
        );
        assert_eq!(state.pending, vec![doc(2)], "the challenger badges pending");
        Ok(())
    }
}

/// Fresh rewinds and the monotone-generation clock: corroborated
/// rewinds are rejected, the uncorroborated residual contests.
mod fresh_rewinds {
    use super::*;

    #[test]
    fn a_corroborated_rewind_is_rejected_even_fresh() -> TestResult {
        // Settled lineage G2→G3, and the zone was OBSERVED running on G3
        // (a held record attests it). A fresh chain now attesting the
        // retired G2 is a corroborated rewind: the zone's own attested
        // history moved forward and is attesting backward — 2-vs-1
        // against the fresh chain, whose minting required exactly the
        // zone control the rewind attacker holds. Rejected regardless of
        // freshness, with the fork surfaced so the owner learns their
        // zone is publishing a retired key. The name keeps resolving at
        // the honest generation on its stale support.
        let honest = binding(1, 3, 1, 100, (NOW - 9_000, NOW - 5_000), 20)?;
        let rewind = binding(1, 2, 2, 200, (NOW - 1_000, NOW + 1_000), 90)?;

        let state = run(
            &[&honest, &rewind],
            &Decisions::default(),
            vec![Item::Rotation(rotation(1, 2, 3)?)],
        );

        let accepted = state.accepted.expect("the honest generation stands");
        assert_eq!(accepted.generation, generation(3), "the rewind is rejected");
        assert_eq!(
            accepted.grade,
            BindingGrade::Provisional,
            "stale support only — the fresh chain was the attacker's"
        );
        assert!(!state.contested, "corroboration resolves it; no contest");
        assert!(
            state.forks.iter().any(|f| f.at == generation(2)),
            "the rewind attempt is surfaced as a fork"
        );
        Ok(())
    }

    #[test]
    fn an_uncorroborated_fresh_rewind_derives_contested() -> TestResult {
        // The residual 1-vs-1: a valid statement claims G2→G3, but no
        // held record EVER attested G3 — the fresh chain attesting G2 is
        // either an honest zone under a forged kill-switch statement, or
        // a rewind racing ahead of gossip (or a slow zone mid-rotation).
        // Indistinguishable from the evidence, so neither side wins
        // silently: contested, output masked, resolution falls to pins
        // and the use-time prompt; repair is the convergence merge.
        let rewind = binding(1, 2, 2, 200, (NOW - 1_000, NOW + 1_000), 90)?;

        let state = run(
            &[&rewind],
            &Decisions::default(),
            vec![Item::Rotation(rotation(1, 2, 3)?)],
        );

        assert_masked(&state);
        assert!(
            state.forks.iter().any(|f| f.at == generation(2)),
            "and surfaced"
        );
        Ok(())
    }
}

/// The two deferral causes and the skew boundary (stage 2: exclude
/// and defer).
mod deferral {
    use super::*;

    #[test]
    fn not_yet_begun_windows_are_deferred() -> TestResult {
        // The second `is_deferred` branch: a chain whose window has
        // not begun is evidence not yet in force — not stale, not
        // considered, nothing derived from it.
        let early = binding(1, 11, 1, 100, (NOW + 1000, NOW + 2000), 50)?;

        let state = run(&[&early], &Decisions::default(), vec![]);
        assert_rejected(&state);
        Ok(())
    }

    #[test]
    fn the_skew_boundary_is_closed_at_exactly_skew() -> TestResult {
        // Serials are compared in the millisecond convention against
        // `now·1000 + SKEW`: exactly at the bound is considered;
        // one past it defers. The `>` vs `>=` mutation lives here.
        let at_bound = binding(1, 11, 1, NOW * 1000 + SKEW_MS, (NOW - 1000, NOW + 1000), 50)?;
        let state = run(&[&at_bound], &Decisions::default(), vec![]);
        assert_eq!(
            state
                .accepted
                .expect("exactly at the bound is in force")
                .document,
            doc(1)
        );

        let past_bound = binding(
            1,
            11,
            2,
            NOW * 1000 + SKEW_MS + 1,
            (NOW - 1000, NOW + 1000),
            50,
        )?;
        let state = run(&[&past_bound], &Decisions::default(), vec![]);
        assert_rejected(&state);
        Ok(())
    }
}

/// Spec row B3: a pending candidate is refuted by fresh evidence for
/// the accepted binding — the badge clears without a prompt.
mod spec_row_b3 {
    use super::*;

    // FIXME(spec B3): the pending badge does NOT clear when fresh
    // evidence for the accepted binding refutes the challenger — the
    // pending filter quarantines every stale, unproven, non-incumbent
    // candidate unconditionally, so `PendingCleared` never fires on
    // refutation. Spec row B3 says it must. This test pins CURRENT
    // behavior so the eventual fix flips a visible assertion instead
    // of changing silent behavior.
    #[test]
    fn pending_survives_refuting_fresh_evidence_pinning_the_b3_gap() -> TestResult {
        let incumbent = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50)?;
        let challenger = binding(2, 22, 2, 999, (NOW - 1500, NOW - 100), 60)?;
        let decisions = accept(doc(1), &incumbent);

        let before = derive_full(&[&incumbent, &challenger], &decisions, vec![]);
        let pending_before = before
            .bindings
            .get(&host())
            .expect("derived")
            .pending
            .clone();
        assert_eq!(
            pending_before,
            vec![doc(2)],
            "B1: the challenger quarantines"
        );

        // Fresh evidence for the ACCEPTED binding arrives: rung 0 now
        // refutes the challenger's later-key claim outright.
        let refuting = binding(1, 11, 3, 120, (NOW - 500, NOW + 500), 70)?;
        let after = derive_full(&[&incumbent, &challenger, &refuting], &decisions, vec![]);
        let state = after.bindings.get(&host()).expect("derived").clone();

        assert_eq!(
            state.accepted.expect("incumbent confirmed").grade,
            BindingGrade::Confirmed
        );

        // The spec-conformant assertions, inverted to pin the gap:
        assert_eq!(
            state.pending,
            vec![doc(2)],
            "FIXME(spec B3): should be empty — refuted challengers must \
             leave quarantine"
        );
        let events = after.diff(&before);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e.kind, EventKind::PendingCleared(_))),
            "FIXME(spec B3): should emit PendingCleared(doc 2), \
             badge-class"
        );
        Ok(())
    }
}

/// Spec row B6, the derivation-side half: claims are retained
/// provenance — a matching claim diverges nothing, and a claim keeps
/// its hostname in the universe.
mod spec_row_b6 {
    use super::*;

    #[test]
    fn a_claim_matching_the_accepted_binding_diverges_nothing() -> TestResult {
        let b = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50)?;

        let decisions = Decisions {
            claims: vec![Claim {
                hostname: host(),
                document: doc(1), // matches the verified record
                note: None,
            }],
            ..Decisions::default()
        };

        let state = run(&[&b], &decisions, vec![]);
        assert_eq!(state.accepted.expect("accepted").document, doc(1));
        assert!(
            state.divergence.is_empty(),
            "the verified record takes display precedence; the \
             retained claim agrees, so no badge"
        );
        Ok(())
    }

    #[test]
    fn a_claim_alone_keeps_its_hostname_in_the_universe() {
        // No records anywhere: the claimed hostname must still get a
        // derived (empty) state — claims are a universe input, so a
        // caller can observe "claimed but unverified" as a hostname
        // with no accepted binding rather than as a missing key.
        let decisions = Decisions {
            claims: vec![Claim {
                hostname: host(),
                document: doc(3),
                note: None,
            }],
            ..Decisions::default()
        };

        let derivation = derive_full(&[], &decisions, vec![]);
        let state = derivation
            .bindings
            .get(&host())
            .expect("the claimed hostname is in the universe");
        assert_eq!(*state, BindingState::default());
    }

    #[test]
    fn a_claim_keeps_contributing_after_a_verified_record_arrives() -> TestResult {
        // The claim is retained provenance: when the verified record
        // later disagrees, the OLD claim must still badge — it was
        // never consumed by the earlier agreement.
        let first = binding(3, 33, 1, 100, (NOW - 9000, NOW - 5000), 40)?;
        let displacing = binding(1, 11, 2, 200, (NOW - 500, NOW + 500), 60)?;

        let decisions = Decisions {
            claims: vec![Claim {
                hostname: host(),
                document: doc(3),
                note: None,
            }],
            ..Decisions::default()
        };

        // While the record agrees with the claim: no divergence.
        let state = run(&[&first], &decisions, vec![]);
        assert!(state.divergence.is_empty());

        // A fresh record for another document displaces: the retained
        // claim now diverges from the new accepted binding.
        let state = run(&[&first, &displacing], &decisions, vec![]);
        assert_eq!(state.accepted.expect("accepted").document, doc(1));
        assert_eq!(state.divergence.len(), 1);
        assert_eq!(state.divergence[0].alleged, doc(3));
        assert_eq!(state.divergence[0].source, DivergenceSource::Claim);
        Ok(())
    }
}

/// Spec row B8, the cross-hostname half: rotation exclusions are
/// document-scoped (a reset at ANY hostname excludes the statement
/// everywhere), while record exclusions stay hostname-scoped.
mod spec_row_b8_cross_hostname {
    use super::*;

    #[test]
    fn a_reset_at_another_hostname_excludes_a_rotation_everywhere() -> TestResult {
        // Settled lineage G11→G12 makes G11 protected: the stale
        // higher-key record attesting G11 is rewind-rejected and the
        // G12 record wins. Excluding the rotation FROM A RESET AT A
        // DIFFERENT HOSTNAME must lift that protection here too —
        // rotation statements are document-scoped, and a user who
        // reset the statement's evidence anywhere meant it everywhere.
        let statement = rotation(1, 11, 12)?;
        let old_gen = binding(1, 11, 1, 200, (NOW - 5000, NOW - 1000), 90)?;
        let new_gen = binding(1, 12, 2, 50, (NOW - 6000, NOW - 2000), 10)?;

        let with_statement = run(
            &[&old_gen, &new_gen],
            &Decisions::default(),
            vec![Item::Rotation(statement.clone())],
        );
        assert_eq!(
            with_statement.accepted.expect("accepted").generation,
            generation(12),
            "fixture sanity: with the rotation in force, the rewind is \
             rejected and descent orders G12 first"
        );

        // The reset lives at host2 — a hostname with no evidence at
        // all — and names the rotation statement.
        let mut resets = Map::default();
        let mut excluded = Set::default();
        excluded.insert(Item::Rotation(statement.clone()).content_hash());
        resets.insert(host2(), excluded);
        let decisions = Decisions {
            resets,
            ..Decisions::default()
        };

        let state = run(
            &[&old_gen, &new_gen],
            &decisions,
            vec![Item::Rotation(statement)],
        );
        assert_eq!(
            state.accepted.expect("accepted").generation,
            generation(11),
            "the exclusion crossed hostnames: no lineage, no rewind \
             rule, the higher key wins"
        );
        Ok(())
    }

    #[test]
    fn record_exclusions_never_leak_across_hostnames() -> TestResult {
        // The inverse scope rule: a reset at host2 naming a RECORD
        // held for host() must not exclude it there — record
        // exclusions apply at their natural (hostname) scope.
        let b = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50)?;

        let mut resets = Map::default();
        let mut excluded = Set::default();
        excluded.insert(b.cert.digest().erase());
        resets.insert(host2(), excluded);
        let decisions = Decisions {
            resets,
            ..Decisions::default()
        };

        let state = run(&[&b], &decisions, vec![]);
        assert_eq!(
            state.accepted.expect("accepted").document,
            doc(1),
            "a reset at another hostname does not touch this one's \
             records"
        );
        Ok(())
    }
}

/// Spec row B11: a fork implicating provisional support demotes and
/// surfaces.
mod spec_row_b11 {
    use super::*;

    #[test]
    fn a_fork_implicating_provisional_support_stays_demoted_and_surfaces() -> TestResult {
        // Provisional (stale-supported) binding on G12 under settled
        // G11→G12. A competing statement G11→G13 then implicates the
        // accepted generation. The output must not firm up or move
        // silently: it stays provisional (demoted), the record
        // survives (fork territory is surfaced, never silently
        // rejected), and the fork rides the diff as an event-class
        // change.
        let rec = binding(1, 12, 1, 100, (NOW - 5000, NOW - 2000), 50)?;
        let settled = vec![Item::Rotation(rotation(1, 11, 12)?)];
        let forked = vec![
            Item::Rotation(rotation(1, 11, 12)?),
            Item::Rotation(rotation(1, 11, 13)?),
        ];

        let before = derive_full(&[&rec], &Decisions::default(), settled);
        let before_state = before.bindings.get(&host()).expect("derived");
        assert_eq!(
            before_state.accepted.expect("accepted").grade,
            BindingGrade::Provisional,
            "fixture sanity: stale support is provisional"
        );
        assert!(before_state.forks.is_empty());

        let after = derive_full(&[&rec], &Decisions::default(), forked);
        let state = after.bindings.get(&host()).expect("derived");

        let accepted = state
            .accepted
            .expect("fork territory is surfaced, not blanked");
        assert_eq!(accepted.generation, generation(12));
        assert_eq!(
            accepted.grade,
            BindingGrade::Provisional,
            "the output stays demoted while the fork stands"
        );
        assert!(
            state.forks.iter().any(|f| f.at == generation(11)),
            "the implicating fork is surfaced"
        );

        let events = after.diff(&before);
        assert!(
            events.iter().any(|event| matches!(
                event.kind,
                EventKind::LineageForkSurfaced(fork) if fork.at == generation(11)
            )),
            "the fork's arrival is an event in the derived diff: {events:?}"
        );
        Ok(())
    }
}

/// Spec row B13, second half: acceptances with zone-state-equal
/// receipts for different documents are contested.
mod receipt_tie_contest {
    use super::*;

    #[test]
    fn zone_state_equal_receipts_for_different_documents_contest() -> TestResult {
        // Two acceptances, each citing a record whose zone-state key
        // is FULLY equal to the other's — the user's own records
        // disagree, and no tiebreak may pick one silently.
        let a = binding(1, 11, 1, 100, (NOW - 5000, NOW - 1000), 50)?;
        let b = binding(2, 22, 2, 100, (NOW - 5000, NOW - 1000), 50)?;

        let mut decisions = accept(doc(1), &a);
        let mut cited = Set::default();
        cited.insert(b.cert.digest().erase());
        decisions
            .acceptances
            .get_mut(&host())
            .expect("acceptance entry")
            .push(Acceptance {
                document: doc(2),
                cited,
            });

        let state = run(&[&a, &b], &decisions, vec![]);

        assert_masked(&state);
        assert!(
            state.losing_acceptances.is_empty(),
            "receipt ties are the contest itself, never losers"
        );
        Ok(())
    }
}

/// Acceptance evaluability: not-held receipts wait, excluded receipts
/// are inert, malformed receipts contribute nothing.
mod acceptance_evaluability {
    use super::*;

    /// The fixture: an older acceptance-backed incumbent and a newer
    /// stale challenger. When the acceptance is IN FORCE the incumbent
    /// stands; whenever it is not, the ladder-maximal challenger wins.
    fn contested_pair() -> Result<(Binding, Binding), onomancy_core::wire::OversizeUnit> {
        Ok((
            binding(1, 11, 1, 100, (NOW - 9000, NOW - 5000), 10)?,
            binding(2, 22, 2, 200, (NOW - 4000, NOW - 1000), 20)?,
        ))
    }

    fn acceptance_for(
        document: DocAnchor,
        cited: Set<onomancy_core::digest::Digest<onomancy_core::digest::Blake3, [u8]>>,
    ) -> Decisions {
        let mut acceptances = Map::default();
        acceptances.insert(host(), vec![Acceptance { document, cited }]);
        Decisions {
            acceptances,
            ..Decisions::default()
        }
    }

    #[test]
    fn the_control_shape_holds_the_incumbent() -> TestResult {
        // Sanity for the module's fixture: with a well-formed,
        // fully-held receipt the incumbent stands and the challenger
        // is pending.
        let (incumbent, challenger) = contested_pair()?;
        let state = run(
            &[&incumbent, &challenger],
            &accept(doc(1), &incumbent),
            vec![],
        );
        assert_eq!(state.accepted.expect("accepted").document, doc(1));
        assert_eq!(state.pending, vec![doc(2)]);
        Ok(())
    }

    #[test]
    fn an_acceptance_citing_a_not_held_item_is_not_yet_evaluable() -> TestResult {
        // The receipt names an item this store has never seen: the
        // acceptance waits (not-yet-evaluable), so no incumbency —
        // the ladder-maximal challenger wins on its later key.
        let (incumbent, challenger) = contested_pair()?;
        let never_held = binding(1, 11, 9, 999, (NOW - 100, NOW + 100), 99)?;

        let mut cited = Set::default();
        cited.insert(never_held.cert.digest().erase());
        let state = run(
            &[&incumbent, &challenger],
            &acceptance_for(doc(1), cited),
            vec![],
        );

        assert_eq!(
            state.accepted.expect("accepted").document,
            doc(2),
            "an unevaluable acceptance confers no incumbency"
        );
        Ok(())
    }

    #[test]
    fn an_acceptance_citing_a_reset_excluded_item_is_inert() -> TestResult {
        // The receipt is held but reset-excluded: the acceptance is
        // inert (B8's closure includes the receipts that relied on
        // the excluded evidence).
        let (incumbent, challenger) = contested_pair()?;

        let mut decisions = accept(doc(1), &incumbent);
        let mut excluded = Set::default();
        excluded.insert(incumbent.cert.digest().erase());
        decisions.resets.insert(host(), excluded);

        let state = run(&[&incumbent, &challenger], &decisions, vec![]);
        assert_eq!(
            state.accepted.expect("accepted").document,
            doc(2),
            "an inert acceptance confers no incumbency — and the \
             excluded record itself is gone too"
        );
        Ok(())
    }

    #[test]
    fn an_acceptance_citing_a_non_record_item_is_malformed() -> TestResult {
        // The cited item is HELD — but it is a rotation statement,
        // not a record. Receipt shape requires records; malformed
        // receipts contribute nothing.
        let (incumbent, challenger) = contested_pair()?;
        let statement = rotation(7, 71, 72)?;

        let mut cited = Set::default();
        cited.insert(incumbent.cert.digest().erase());
        cited.insert(Item::Rotation(statement.clone()).content_hash());

        let state = run(
            &[&incumbent, &challenger],
            &acceptance_for(doc(1), cited),
            vec![Item::Rotation(statement)],
        );

        assert_eq!(
            state.accepted.expect("accepted").document,
            doc(2),
            "a receipt citing a non-record item is void"
        );
        Ok(())
    }

    #[test]
    fn an_acceptance_citing_another_hostnames_record_is_malformed() -> TestResult {
        // Every cited item must be a record for THIS hostname: a
        // receipt reaching across hostnames is malformed, however
        // genuine the foreign record.
        let (incumbent, challenger) = contested_pair()?;
        let foreign = binding_at(host2(), 1, 11, 9, 300, (NOW - 4000, NOW - 1000), 30)?;

        let mut cited = Set::default();
        cited.insert(incumbent.cert.digest().erase());
        cited.insert(foreign.cert.digest().erase());

        let state = run(
            &[&incumbent, &challenger, &foreign],
            &acceptance_for(doc(1), cited),
            vec![],
        );

        assert_eq!(
            state.accepted.expect("accepted").document,
            doc(2),
            "a cross-hostname receipt is void"
        );
        Ok(())
    }

    #[test]
    fn an_acceptance_whose_receipts_never_attest_its_document_is_malformed() -> TestResult {
        // At least one cited record must attest the acceptance's own
        // document: accepting doc(5) on the strength of doc(1)'s
        // records is a shape error, not a choice.
        let (incumbent, challenger) = contested_pair()?;

        let mut cited = Set::default();
        cited.insert(incumbent.cert.digest().erase());
        let state = run(
            &[&incumbent, &challenger],
            &acceptance_for(doc(5), cited),
            vec![],
        );

        assert_eq!(
            state.accepted.expect("accepted").document,
            doc(2),
            "receipts that never attest the accepted document are void"
        );
        Ok(())
    }
}

/// Pins: divergence badges and hostname-universe inclusion (the
/// derivation's fourth input).
mod pins {
    use super::*;

    fn derive_with_pins(
        bindings: &[&Binding],
        pins: &Map<onomancy_dnssec::dns_name::DnsName, Vec<DocAnchor>>,
    ) -> VerifierState {
        let mut validator = MemoryValidator::default();
        let mut store = Store::default();
        for b in bindings {
            validator = validator.with(b.cert.hostname().clone(), &b.chain, b.proof.clone());
            store.insert(Item::Record(b.cert.clone()));
        }

        VerifierState::compute(
            &store,
            UnixSeconds::from(NOW),
            &Decisions::default(),
            pins,
            &validator,
            &MemoryAuthority::default(),
        )
    }

    #[test]
    fn a_pin_disagreeing_with_the_accepted_binding_badges_pin_divergence() -> TestResult {
        let b = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50)?;

        let mut pins = Map::default();
        pins.insert(host(), vec![doc(9)]);

        let derivation = derive_with_pins(&[&b], &pins);
        let state = derivation.bindings.get(&host()).expect("derived");

        assert_eq!(state.accepted.expect("accepted").document, doc(1));
        assert_eq!(state.divergence.len(), 1);
        assert_eq!(state.divergence[0].alleged, doc(9));
        assert_eq!(
            state.divergence[0].source,
            DivergenceSource::Pin,
            "the badge names its source — a pin, not a claim"
        );
        Ok(())
    }

    #[test]
    fn a_matching_pin_diverges_nothing() -> TestResult {
        let b = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50)?;

        let mut pins = Map::default();
        pins.insert(host(), vec![doc(1)]);

        let derivation = derive_with_pins(&[&b], &pins);
        let state = derivation.bindings.get(&host()).expect("derived");
        assert!(state.divergence.is_empty());
        Ok(())
    }

    #[test]
    fn a_pin_alone_keeps_its_hostname_in_the_universe() {
        // Pin-driven universe inclusion: a pinned hostname with no
        // evidence at all still derives a (default) state.
        let mut pins = Map::default();
        pins.insert(host2(), vec![doc(4)]);

        let derivation = derive_with_pins(&[], &pins);
        let state = derivation
            .bindings
            .get(&host2())
            .expect("the pinned hostname is in the universe");
        assert_eq!(*state, BindingState::default());
    }
}

/// Multi-hostname derivation: per-host isolation and deterministic
/// diff ordering — the suite's two-hostname fixtures.
mod multi_hostname {
    use super::*;

    #[test]
    fn hostnames_derive_in_isolation() -> TestResult {
        // Different documents bound at different hostnames, one
        // derivation: each hostname sees exactly its own evidence.
        let at_one = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50)?;
        let at_two = binding_at(host2(), 2, 22, 2, 999, (NOW - 1000, NOW + 1000), 60)?;

        let derivation = derive_full(&[&at_one, &at_two], &Decisions::default(), vec![]);

        let one = derivation.bindings.get(&host()).expect("host 1 derived");
        assert_eq!(one.accepted.expect("accepted").document, doc(1));
        assert_eq!(one.effective_serial, Some(Serial::from(100)));
        assert!(one.pending.is_empty(), "host2's evidence never leaks in");

        let two = derivation.bindings.get(&host2()).expect("host 2 derived");
        assert_eq!(two.accepted.expect("accepted").document, doc(2));
        assert_eq!(two.effective_serial, Some(Serial::from(999)));
        assert!(two.pending.is_empty(), "host1's evidence never leaks in");
        Ok(())
    }

    #[test]
    fn a_contest_at_one_hostname_never_masks_another() -> TestResult {
        // Zone equivocation at host(): masked there, untouched at
        // host2().
        let a = binding(1, 11, 1, 100, (NOW - 5000, NOW - 1000), 50)?;
        let b = binding(2, 22, 2, 100, (NOW - 5000, NOW - 1000), 99)?;
        let elsewhere = binding_at(host2(), 3, 33, 3, 100, (NOW - 1000, NOW + 1000), 50)?;

        let derivation = derive_full(&[&a, &b, &elsewhere], &Decisions::default(), vec![]);

        assert_masked(derivation.bindings.get(&host()).expect("derived"));
        let two = derivation.bindings.get(&host2()).expect("derived");
        assert!(!two.contested);
        assert_eq!(two.accepted.expect("accepted").document, doc(3));
        Ok(())
    }

    #[test]
    fn diff_events_arrive_in_sorted_hostname_order() -> TestResult {
        // "example.org" < "expede.wtf": the diff's hostname ordering
        // is deterministic regardless of map iteration order.
        let at_one = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50)?;
        let at_two = binding_at(host2(), 2, 22, 2, 200, (NOW - 1000, NOW + 1000), 60)?;

        let before = derive_full(&[], &Decisions::default(), vec![]);
        let after = derive_full(&[&at_one, &at_two], &Decisions::default(), vec![]);

        let events = after.diff(&before);
        let hostnames: Vec<_> = events.iter().map(|e| e.hostname.clone()).collect();
        let mut sorted = hostnames.clone();
        sorted.sort_unstable();
        assert_eq!(hostnames, sorted, "events sort by hostname");
        assert!(hostnames.contains(&host()) && hostnames.contains(&host2()));
        Ok(())
    }
}
