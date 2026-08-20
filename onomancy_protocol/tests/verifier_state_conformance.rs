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
use onomancy_protocol::{
    test_utils::{
        Binding, binding, binding_carrying, chain, doc, generation, host, rotation, succession,
        window,
    },
    verifier_state::{
        VerifierState,
        judgment::{Acceptance, Claim, Judgment},
        memory::{MemoryAuthority, MemoryValidator},
        output::{BindingGrade, HostState},
        seam::ChainProof,
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
fn sole_fresh_record_is_accepted_confirmed() {
    // Fresh window covering NOW.
    let b = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50);
    let state = run(&[&b], &Judgment::default(), vec![]);

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(1));
    assert_eq!(accepted.generation, generation(11));
    assert_eq!(accepted.grade, BindingGrade::Confirmed);
    assert_eq!(state.effective_serial, Some(Serial::from(100)));
    assert!(!state.contested && !state.unbound && state.pending.is_empty());
}

#[test]
fn sole_stale_first_contact_is_provisional_incumbent() {
    // B10: sole candidate, only stale evidence.
    let b = binding(1, 11, 1, 100, (NOW - 5000, NOW - 1000), 50);
    let state = run(&[&b], &Judgment::default(), vec![]);

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.grade, BindingGrade::Provisional);
}

#[test]
fn b1_stale_unproven_challenger_is_pending_never_displacing() {
    // Acceptance-backed incumbent (doc 1), stale challenger (doc 2)
    // with a strictly later zone-state key and no proof.
    let incumbent = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50);
    let challenger = binding(2, 22, 2, 999, (NOW - 1500, NOW - 100), 60);

    let state = run(
        &[&incumbent, &challenger],
        &accept(doc(1), &incumbent),
        vec![],
    );

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(1), "incumbent stands");
    assert_eq!(state.pending, vec![doc(2)], "challenger quarantined");
}

#[test]
fn b2_fresh_challenger_is_eligible_and_displaces() {
    let incumbent = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50);
    let challenger = binding(2, 22, 2, 999, (NOW - 100, NOW + 1000), 60);

    let state = run(
        &[&incumbent, &challenger],
        &accept(doc(1), &incumbent),
        vec![],
    );

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(2), "fresh evidence is eligible");
    assert_eq!(accepted.grade, BindingGrade::Confirmed);
    assert!(state.pending.is_empty());
}

#[test]
fn succession_proof_makes_a_stale_challenger_eligible() {
    let incumbent = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50);
    let challenger = binding(2, 22, 2, 999, (NOW - 1500, NOW - 100), 60);

    // A valid successor statement doc1 → doc2 for this hostname.
    let state = run(
        &[&incumbent, &challenger],
        &accept(doc(1), &incumbent),
        vec![Item::Successor(succession(1, 2, 9))],
    );

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(2), "proof chains from incumbent");
    assert!(state.pending.is_empty());
}

#[test]
fn d4a_fresh_record_with_lower_serial_wins_and_resets_the_ratchet() {
    // Same document: stale record with a huge serial, fresh record
    // with a small one. Fresh wins rung 0; effective serial follows
    // the WINNER (the downward move is the surfaced ratchet reset).
    let stale_high = binding(1, 11, 1, 999, (NOW - 5000, NOW - 1000), 50);
    let fresh_low = binding(1, 11, 2, 7, (NOW - 500, NOW + 500), 60);

    let state = run(&[&stale_high, &fresh_low], &Judgment::default(), vec![]);

    assert_eq!(state.effective_serial, Some(Serial::from(7)));
    assert_eq!(
        state.accepted.expect("accepted").grade,
        BindingGrade::Confirmed
    );
}

#[test]
fn b13_zone_equivocation_is_contested_with_empty_output() {
    // Two unconnected documents, both stale, equal (window_end,
    // serial) — issued_at differs but MUST NOT resolve it.
    let a = binding(1, 11, 1, 100, (NOW - 5000, NOW - 1000), 50);
    let b = binding(2, 22, 2, 100, (NOW - 5000, NOW - 1000), 99);

    let state = run(&[&a, &b], &Judgment::default(), vec![]);

    assert!(state.contested);
    assert!(state.accepted.is_none(), "contested output is empty");
    assert!(state.effective_serial.is_none());
}

#[test]
fn stale_candidates_with_ordered_keys_pick_the_later_provisionally() {
    // The narrowed B13: strictly ordered windows are NOT contested.
    let earlier = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50);
    let later = binding(2, 22, 2, 100, (NOW - 4000, NOW - 1000), 50);

    let state = run(&[&earlier, &later], &Judgment::default(), vec![]);

    assert!(!state.contested);
    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(2), "later zone state wins");
    assert_eq!(accepted.grade, BindingGrade::Provisional);
}

#[test]
fn d10_fresh_record_not_threading_g_is_rejected() {
    let b = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50);

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
}

#[test]
fn b8_reset_excludes_the_challenger() {
    let incumbent = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50);
    let poison = binding(2, 22, 2, 999, (NOW - 100, NOW + 1000), 60);

    // Fresh challenger would displace (see B2) — but it is excluded.
    let mut judgment = accept(doc(1), &incumbent);
    let mut excluded = Set::default();
    excluded.insert(poison.cert.digest().into());
    judgment.resets.insert(host(), excluded);

    let state = run(&[&incumbent, &poison], &judgment, vec![]);

    let accepted = state.accepted.expect("accepted");
    assert_eq!(accepted.document, doc(1), "excluded evidence is inert");
    assert!(state.pending.is_empty(), "excluded ≠ pending");
}

#[test]
fn far_future_serials_are_deferred() {
    // Serial (ms convention) more than 5 minutes past NOW.
    let poisoned = binding(
        1,
        11,
        1,
        NOW * 1000 + 6 * 60 * 1000,
        (NOW - 1000, NOW + 1000),
        50,
    );

    let state = run(&[&poisoned], &Judgment::default(), vec![]);
    assert!(state.accepted.is_none(), "deferred, not considered");
}

#[test]
fn b12_fresh_absence_with_later_leaf_inception_unbinds() {
    let b = binding(1, 11, 1, 100, (NOW - 5000, NOW - 1000), 50);

    let absence_chain = chain(9);
    let validator = MemoryValidator::default()
        .with(host(), &b.chain, b.proof.clone())
        .with(
            host(),
            &absence_chain,
            ChainProof::Absence {
                // Strictly later than the binding's leaf inception.
                leaf_inception: UnixSeconds::from(NOW - 500),
                window: window(NOW - 500, NOW + 500),
            },
        );

    let mut store = Store::default();
    store.insert(Item::Record(b.cert.clone()));
    store.insert(Item::Absence {
        hostname: host(),
        chain: absence_chain,
    });

    let derivation = VerifierState::compute(
        &store,
        UnixSeconds::from(NOW),
        &Judgment::default(),
        &Map::default(),
        &validator,
        &MemoryAuthority::default(),
    );

    let state = derivation.hosts.get(&host()).cloned().unwrap_or_default();
    assert!(state.unbound);
    assert!(state.accepted.is_none(), "unbound output is empty");
}

#[test]
fn divergent_claims_badge_but_do_not_move_bindings() {
    let b = binding(1, 11, 1, 100, (NOW - 1000, NOW + 1000), 50);

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
}

// ───── ADR-042: the protected prefix and fork repair ─────

#[test]
fn d12_protected_prefix_survives_a_fork() {
    // Lineage G11→G12→G13, then a fork at G13 (→G14 and →G15).
    // A stale record attesting the PROTECTED G11 is still a provable
    // rewind — the fork buys no immunity below the fork point — while
    // a record attesting fork-implicated G14 survives, surfaced.
    let rewind = binding(1, 11, 1, 50, (NOW - 9000, NOW - 5000), 10);
    let branch = binding(1, 14, 2, 60, (NOW - 4000, NOW - 1000), 20);

    let lineage = vec![
        Item::Rotation(rotation(1, 11, 12)),
        Item::Rotation(rotation(1, 12, 13)),
        Item::Rotation(rotation(1, 13, 14)),
        Item::Rotation(rotation(1, 13, 15)),
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
}

#[test]
fn fork_repair_by_convergence_merge_settles_the_lineage() {
    // Same fork, repaired: both branch heads retire into fresh G16
    // (a double-successor MERGE — legal, only G16's holder can mint
    // it). Single head again: retired branches rejoin the protected
    // prefix, the current generation is accepted, the historical fork
    // stays surfaced.
    let stale_branch = binding(1, 14, 1, 50, (NOW - 9000, NOW - 5000), 10);
    let current = binding(1, 16, 2, 60, (NOW - 1000, NOW + 1000), 20);

    let lineage = vec![
        Item::Rotation(rotation(1, 11, 12)),
        Item::Rotation(rotation(1, 12, 13)),
        Item::Rotation(rotation(1, 13, 14)),
        Item::Rotation(rotation(1, 13, 15)),
        Item::Rotation(rotation(1, 14, 16)),
        Item::Rotation(rotation(1, 15, 16)),
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
}

#[test]
fn b9_unauthorized_statements_have_no_lineage_effect() {
    // The rotation's carriage fails authority verification: it must
    // be discarded entirely — no D12, no fork evidence.
    let old_gen = binding(1, 11, 1, 50, (NOW - 1000, NOW + 1000), 10);

    let mut validator =
        MemoryValidator::default().with(host(), &old_gen.chain, old_gen.proof.clone());
    let _ = &mut validator;
    let mut store = Store::default();
    store.insert(Item::Record(old_gen.cert.clone()));
    store.insert(Item::Rotation(rotation(1, 11, 12)));

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
}

// ───── review fix #1: extraction closure under resets ─────

#[test]
fn statements_survive_resets_via_independent_carriers() {
    // Rotation R (G11→G12) is carried by BOTH cert A and cert B.
    // Excluding only A leaves R in force via B; excluding both
    // removes it — and neither outcome depends on insertion order.
    let statement = rotation(1, 11, 12);
    let carrier_a = binding_carrying(
        1,
        12,
        1,
        50,
        (NOW - 5000, NOW - 1000),
        10,
        vec![statement.clone()],
    );
    let carrier_b = binding_carrying(
        1,
        12,
        2,
        60,
        (NOW - 4000, NOW - 500),
        20,
        vec![statement.clone()],
    );
    let rewind = binding(1, 11, 3, 70, (NOW - 3000, NOW - 200), 30);

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
}

// ───── review fix #4: D16 succession forks ─────

#[test]
fn d16_succession_forks_surface_and_stop_eligibility() {
    // Two valid successor statements from doc1: →doc2 and →doc3.
    // Provable equivocation: surfaced, and NEITHER branch can ride
    // the forked proof graph past the incumbent.
    let incumbent = binding(1, 11, 1, 100, (NOW - 5000, NOW - 2000), 50);
    let branch_x = binding(2, 22, 2, 999, (NOW - 1500, NOW - 100), 60);
    let branch_y = binding(3, 33, 3, 998, (NOW - 1500, NOW - 100), 60);

    let proofs = vec![
        Item::Successor(succession(1, 2, 21)),
        Item::Successor(succession(1, 3, 22)),
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
                let carried = rotation(specs[0].0 % 3, 40, 41);
                let carrier_x = binding_carrying(
                    specs[0].0 % 3,
                    (specs[0].0 % 3) + 10,
                    100,
                    7,
                    (NOW - 8000, NOW - 7000),
                    1,
                    vec![carried.clone()],
                );
                let carrier_y = binding_carrying(
                    specs[0].0 % 3,
                    (specs[0].0 % 3) + 10,
                    101,
                    8,
                    (NOW - 8000, NOW - 6900),
                    2,
                    vec![carried.clone()],
                );
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
                    Item::Rotation(rotation(specs[0].0 % 3, 41, 42)),
                    Item::Successor(succession(specs[0].0 % 3, (specs[0].0 % 3) + 1, 45)),
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
