//! Conformance scenarios for `VerifierState::compute(store, now, judgment)`, tagged
//! with the binding-cache spec's condition table (B1, B12, B13, …) and
//! the DNS-anchor decision rows (D4a, D10, D12/D12a), plus the
//! permutation-determinism property (verification target 7).

#![allow(clippy::expect_used, clippy::indexing_slicing)]

use onomancy_core::{
    collections::{Map, Set},
    name::doc::DocAnchor,
    time::UnixSeconds,
    txt::serial::Serial,
};
use testresult::TestResult;

use onomancy_protocol::{
    test_utils::{Binding, binding, binding_carrying, doc, generation, host, rotation, succession},
    verifier_state::{
        VerifierState,
        judgment::{Acceptance, Claim, Judgment},
        memory::{MemoryAuthority, MemoryValidator},
        output::{BindingGrade, ContinuityGrade, HostState},
        store::{Item, Store},
    },
};

const NOW: u64 = 1_755_000_000;

fn run(bindings: &[&Binding], judgment: &Judgment, extra: Vec<Item>) -> HostState {
    let mut validator = MemoryValidator::default();
    let mut store = Store::default();

    for b in bindings {
        validator = validator.with(host(), &b.chain, b.proof.clone());
        store.insert(Item::Record(b.cert.clone()));
    }
    for item in extra {
        store.insert(item);
    }

    let derivation = VerifierState::compute(
        &store,
        UnixSeconds::from(NOW),
        judgment,
        &Map::default(),
        &validator,
        &MemoryAuthority::default(),
    );

    derivation.hosts.get(&host()).cloned().unwrap_or_default()
}

fn accept(document: DocAnchor, cited: &Binding) -> Judgment {
    let mut acceptances = Map::default();
    let mut set = Set::default();
    set.insert(cited.cert.digest().into());
    acceptances.insert(
        host(),
        vec![Acceptance {
            document,
            cited: set,
        }],
    );

    Judgment {
        acceptances,
        ..Judgment::default()
    }
}

#[test]
fn sole_fresh_record_is_accepted_confirmed() -> TestResult {
    // Fresh window covering NOW.
    let b = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50)?;
    let state = run(&[&b], &Judgment::default(), vec![]);

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
    // B10: sole candidate, only stale evidence.
    let b = binding(1, 11, 1, 100, (NOW - 5000, NOW - 1000), 50)?;
    let state = run(&[&b], &Judgment::default(), vec![]);

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.grade, BindingGrade::Provisional);
    Ok(())
}

#[test]
fn b1_stale_unproven_challenger_is_pending_never_displacing() -> TestResult {
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
    Ok(())
}

#[test]
fn b2_fresh_challenger_is_eligible_and_displaces() -> TestResult {
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
    assert!(state.pending.is_empty());
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
    // Fresh departure, one hop, threading intact: the fully-checked
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
fn d4a_fresh_record_with_lower_serial_wins_and_resets_the_ratchet() -> TestResult {
    // Same document: stale record with a huge serial, fresh record
    // with a small one. Fresh wins rung 0; effective serial follows
    // the WINNER (the downward move is the surfaced ratchet reset).
    let stale_high = binding(1, 11, 1, 999, (NOW - 5000, NOW - 1000), 50)?;
    let fresh_low = binding(1, 11, 2, 7, (NOW - 500, NOW + 500), 60)?;

    let state = run(&[&stale_high, &fresh_low], &Judgment::default(), vec![]);

    assert_eq!(state.effective_serial, Some(Serial::from(7)));
    assert_eq!(
        state.accepted.expect("accepted").grade,
        BindingGrade::Confirmed
    );
    Ok(())
}

#[test]
fn b13_zone_equivocation_is_contested_with_empty_output() -> TestResult {
    // Two unconnected documents, both stale, equal (window_end,
    // serial) — issued_at differs but MUST NOT resolve it.
    let a = binding(1, 11, 1, 100, (NOW - 5000, NOW - 1000), 50)?;
    let b = binding(2, 22, 2, 100, (NOW - 5000, NOW - 1000), 99)?;

    let state = run(&[&a, &b], &Judgment::default(), vec![]);

    assert!(state.contested);
    assert!(state.accepted.is_none(), "contested output is empty");
    assert!(state.effective_serial.is_none());
    Ok(())
}

#[test]
fn stale_candidates_with_ordered_keys_pick_the_later_provisionally() -> TestResult {
    // The narrowed B13: strictly ordered windows are NOT contested.
    let earlier = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50)?;
    let later = binding(2, 22, 2, 100, (NOW - 4000, NOW - 1000), 50)?;

    let state = run(&[&earlier, &later], &Judgment::default(), vec![]);

    assert!(!state.contested);
    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(2), "later zone state wins");
    assert_eq!(accepted.grade, BindingGrade::Provisional);
    Ok(())
}

#[test]
fn d10_fresh_record_not_threading_g_is_rejected() -> TestResult {
    let b = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50)?;

    let mut validator = MemoryValidator::default().with(host(), &b.chain, b.proof.clone());
    let _ = &mut validator;
    let mut store = Store::default();
    store.insert(Item::Record(b.cert.clone()));

    let derivation = VerifierState::compute(
        &store,
        UnixSeconds::from(NOW),
        &Judgment::default(),
        &Map::default(),
        &validator,
        &MemoryAuthority::default().without_thread(&generation(11)),
    );

    let state = derivation.hosts.get(&host()).cloned().unwrap_or_default();
    assert!(state.accepted.is_none(), "D10 rejects the record");
    Ok(())
}

#[test]
fn b8_reset_excludes_the_challenger() -> TestResult {
    let incumbent = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50)?;
    let poison = binding(2, 22, 2, 999, (NOW - 100, NOW + 1000), 60)?;

    // Fresh challenger would displace (see B2) — but it is excluded.
    let mut judgment = accept(doc(1), &incumbent);
    let mut excluded = Set::default();
    excluded.insert(poison.cert.digest().into());
    judgment.resets.insert(host(), excluded);

    let state = run(&[&incumbent, &poison], &judgment, vec![]);

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

    let mut judgment = accept(doc(1), &older);
    let mut cited = Set::default();
    cited.insert(newer.cert.digest().into());
    judgment
        .acceptances
        .get_mut(&host())
        .expect("acceptance entry for the test hostname")
        .push(Acceptance {
            document: doc(2),
            cited,
        });

    let state = run(&[&older, &newer], &judgment, vec![]);

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

    let state = run(&[&poisoned], &Judgment::default(), vec![]);
    assert!(state.accepted.is_none(), "deferred, not considered");
    Ok(())
}

#[test]
fn divergent_claims_badge_but_do_not_move_bindings() -> TestResult {
    let b = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50)?;

    let judgment = Judgment {
        claims: vec![Claim {
            hostname: host(),
            document: doc(3),
            note: None,
        }],
        ..Judgment::default()
    };

    let state = run(&[&b], &judgment, vec![]);

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(1), "claims never move bindings");
    assert_eq!(state.divergence.len(), 1);
    assert_eq!(state.divergence[0].alleged, doc(3));
    Ok(())
}

// ───── ADR-042: the protected prefix and fork repair ─────

#[test]
fn d12_protected_prefix_survives_a_fork() -> TestResult {
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

    let state = run(&[&rewind, &branch], &Judgment::default(), lineage);

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
    // Fork at G11 (→G12, →G13): D12's hard rejection is suspended
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

    let state = run(&[&at_fork, &on_branch], &Judgment::default(), lineage);

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

    let state = run(&[&branch_a, &branch_b], &Judgment::default(), lineage);

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

    let state = run(&[&stale_branch, &current], &Judgment::default(), lineage);

    let accepted = state.accepted.expect("current generation accepted");
    assert_eq!(accepted.generation, generation(16));
    assert_eq!(
        state.effective_serial,
        Some(Serial::from(60)),
        "retired branch record is D12-rejected post-repair"
    );
    assert!(
        state.forks.iter().any(|f| f.at == generation(13)),
        "repair converges heads; it never launders the fork"
    );
    Ok(())
}

#[test]
fn b9_unauthorized_statements_have_no_lineage_effect() -> TestResult {
    // The rotation's carriage fails authority verification: it must
    // be discarded entirely — no D12, no fork evidence.
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
        &Judgment::default(),
        &Map::default(),
        &validator,
        &MemoryAuthority::default().deny(doc(1), generation(12).verifying_key()),
    );

    let state = derivation.hosts.get(&host()).cloned().unwrap_or_default();
    let accepted = state.accepted.expect("old generation still accepted");
    assert_eq!(accepted.generation, generation(11), "no D12 from garbage");
    assert!(state.forks.is_empty(), "never fork evidence either");
    Ok(())
}

// ───── review fix #1: extraction closure under resets ─────

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
        let mut judgment = Judgment::default();
        let mut excluded = Set::default();
        excluded.insert(carrier_a.cert.digest().into());
        judgment.resets.insert(host(), excluded);
        judgment
    };

    let state = run(&[&carrier_a, &carrier_b, &rewind], &reset_a, vec![]);
    let accepted = state.accepted.expect("accepted");
    assert_eq!(
        accepted.generation,
        generation(12),
        "R survives via the non-excluded carrier: the rewind stays rejected"
    );

    let reset_both = {
        let mut judgment = Judgment::default();
        let mut excluded = Set::default();
        excluded.insert(carrier_a.cert.digest().into());
        excluded.insert(carrier_b.cert.digest().into());
        judgment.resets.insert(host(), excluded);
        judgment
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

// ───── review fix #4: D16 succession forks ─────

#[test]
fn d16_succession_forks_surface_and_stop_eligibility() -> TestResult {
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
        state.pending.len(),
        2,
        "both unproven branches badge pending"
    );
    Ok(())
}

mod props {
    use super::*;

    /// Verification target 7: the derivation is a function of the
    /// evidence SET — any permutation (here: reversal and rotation) of
    /// store insertion order yields identical output. The pool
    /// includes carried statements, standalone statements, resets, and
    /// acceptances — the inputs that made the first implementation
    /// order-dependent.
    #[test]
    fn derivation_is_insertion_order_insensitive() {
        bolero::check!()
            .with_type::<(Vec<(u8, u8, u64, u64, bool)>, usize)>()
            .for_each(|(specs, rotate_by)| {
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

                // Judgment: an acceptance PLUS a reset excluding one
                // carrier — exclusion closure is where order
                // dependence hid the first time.
                let mut judgment = accept(doc(specs[0].0 % 3), &bindings[0]);
                let mut excluded = Set::default();
                excluded.insert(bindings[bindings.len() - 1].cert.digest().into());
                judgment.resets.insert(host(), excluded);

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

                let mut items: Vec<Item> = bindings
                    .iter()
                    .map(|b| Item::Record(b.cert.clone()))
                    .collect();
                items.extend([
                    Item::Record(carrier_x.cert.clone()),
                    Item::Record(carrier_y.cert.clone()),
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

                let run = |store: &Store| {
                    VerifierState::compute(
                        store,
                        UnixSeconds::from(NOW),
                        &judgment,
                        &Map::default(),
                        &validator,
                        &MemoryAuthority::default(),
                    )
                };

                let baseline = run(&forward);
                assert_eq!(baseline, run(&reversed), "reversal changed the verdict");
                assert_eq!(baseline, run(&rotated), "rotation changed the verdict");
            });
    }
}
