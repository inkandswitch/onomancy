//! Pruning: local storage reclamation bounded by one rule — it MUST
//! NOT change any output of `derive`.
//!
//! An item may be dropped only when nothing can ever make it relevant
//! again, decided from static data. Retained per hostname:
//!
//! - the component-wise Pareto frontier of records per candidate
//!   document (a record is dominated only when a same-document,
//!   same-generation sibling is at least as good in EVERY component —
//!   inception, window end, serial, `issued_at` — so no future `now`
//!   revives it)
//! - the earliest-inception record per document (tenure's left
//!   endpoint, retained despite domination)
//! - every statement (rotation and successor — potential fork
//!   evidence and bridging receipts, ceremony-bounded anyway)
//! - every record cited by an acceptance (pruning a receipt would
//!   render the acceptance not-yet-evaluable)
//!
//! The one sanctioned exception to the invariant: records whose
//! serial exceeds `now` by more than the **deferral horizon** (one
//! year) MAY be dropped — an honest publisher's clock is never a year
//! fast, and the record would have contributed nothing until then.

use alloc::vec::Vec;

use onomancy_core::{
    anchor::doc::DocAnchor,
    collections::{Map, Set},
    digest::{Blake3, Digest},
    time::UnixSeconds,
};

use onomancy_dnssec::chain_proof::ChainValidator;

use super::{
    Attestation, BindingEvidence,
    authority_verifier::AuthorityVerifier,
    decisions::Decisions,
    store::{Store, item::Item},
    validate_and_extract,
};

/// The deferral horizon: serials more than one year (in the serial's
/// millisecond convention) past `now` are prunable.
pub const DEFERRAL_HORIZON_MS: u64 = 365 * 24 * 60 * 60 * 1000;

/// A pruned copy of the store: `derive` over the result equals
/// `derive` over the input, for every `now` from this one forward
/// (the property the conformance suite pins).
#[must_use]
pub fn prune<V: ChainValidator, A: AuthorityVerifier>(
    store: &Store,
    now: UnixSeconds,
    decisions: &Decisions,
    validator: &V,
    authority: &A,
) -> Store {
    let evidence = validate_and_extract(store, validator, authority);

    // Everything an acceptance cites is load-bearing.
    let mut cited: Set<Digest<Blake3, [u8]>> = Set::default();
    for acceptances in decisions.acceptances.values() {
        for acceptance in acceptances {
            cited.extend(acceptance.cited.iter().copied());
        }
    }

    // Group binding evidence by (hostname, document); decide per item.
    let mut keep: Set<Digest<Blake3, [u8]>> = cited.clone();
    let mut groups: Map<(&str, DocAnchor), Vec<&BindingEvidence>> = Map::default();
    for record in &evidence.records {
        groups
            .entry((record.hostname.as_str(), record.document))
            .or_default()
            .push(record);
    }

    let horizon = now
        .value()
        .saturating_mul(1000)
        .saturating_add(DEFERRAL_HORIZON_MS);

    for group in groups.values() {
        // The component-wise Pareto frontier, minus the horizon drops.
        let frontier: Vec<&&BindingEvidence> = group
            .iter()
            .filter(|record| record.key.serial.value() <= horizon)
            .filter(|record| !group.iter().any(|other| dominates(other, record)))
            .collect();

        for record in &frontier {
            keep.insert(record.hash);
        }

        // Tenure's left endpoint: some kept record must achieve the
        // group's earliest inception; add one only when the frontier
        // doesn't already.
        let earliest = group.iter().map(|r| r.window.inception()).min();
        if let Some(min_inception) = earliest
            && !frontier
                .iter()
                .any(|record| record.window.inception() == min_inception)
            && let Some(endpoint) = group
                .iter()
                .filter(|record| record.window.inception() == min_inception)
                .min_by_key(|record| record.hash)
        {
            keep.insert(endpoint.hash);
        }
    }

    store
        .items()
        .iter()
        .filter(|item| match item {
            // Statements are ceremony-bounded and always potentially
            // relevant (forks, bridging).
            Item::Rotation(_) | Item::Successor(_) => true,
            Item::Record(_) | Item::ChainRefresh { .. } => keep.contains(&item.content_hash()),
        })
        .cloned()
        .collect()
}

/// Component-wise domination: `other` makes `record` permanently
/// irrelevant. Requires the same document AND generation (a lineage
/// statement can re-weigh generations, so cross-generation domination
/// is never safe from static data), at-least-as-good in every
/// component, and STRICTLY better in at least one.
fn dominates(other: &BindingEvidence, record: &BindingEvidence) -> bool {
    // A refresh row never prunes a certificate: candidacy is
    // certificate-attested, so a ChainOnly item component-wise
    // beating a document's last certificate would leave the pruned
    // store unable to derive the binding at all — an invariant
    // violation from static data.
    let attestation_allows = !(other.attestation == Attestation::ChainOnly
        && record.attestation == Attestation::Certificate);

    let at_least_as_good = other.window.inception() <= record.window.inception()
        && other.window.expiration() >= record.window.expiration()
        && other.key.serial >= record.key.serial
        && other.key.issued_at >= record.key.issued_at;

    // Strictness is what makes the relation antisymmetric. Items
    // equal in every component would otherwise dominate each other
    // MUTUALLY — both fall off the frontier and a hash-arbitrary
    // tenure endpoint survives alone, which a reset addressing the
    // dropped sibling by hash can then no longer exclude: the pruned
    // derivation diverges. Equal-component classes are kept whole.
    let strictly_better = other.window.inception() < record.window.inception()
        || other.window.expiration() > record.window.expiration()
        || other.key.serial > record.key.serial
        || other.key.issued_at > record.key.issued_at;

    other.hash != record.hash
        && attestation_allows
        && other.document == record.document
        && other.generation == record.generation
        && at_least_as_good
        && strictly_better
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::{
        test_utils::{Binding, binding, doc, host, rotation},
        verifier::state::{
            VerifierState,
            decisions::Acceptance,
            memory::{authority::MemoryAuthority, validator::MemoryValidator},
        },
    };
    use alloc::{vec, vec::Vec};
    use testresult::TestResult;

    const NOW: u64 = 1_755_000_000;

    fn setup(bindings: &[&Binding], extra: Vec<Item>) -> (Store, MemoryValidator) {
        let mut store = Store::default();
        let mut validator = MemoryValidator::default();

        for b in bindings {
            store.insert(Item::Record(b.cert.clone()));
            validator = validator.with(host(), &b.chain, b.proof.clone());
        }
        for item in extra {
            store.insert(item);
        }

        (store, validator)
    }

    /// The invariant itself: derive(prune(store)) == derive(store).
    fn assert_prune_invariant(
        store: &Store,
        validator: &MemoryValidator,
        decisions: &Decisions,
    ) -> Store {
        let authority = MemoryAuthority::default();
        let now = UnixSeconds::from(NOW);
        let pins = Map::default();

        let pruned = prune(store, now, decisions, validator, &authority);

        assert_eq!(
            VerifierState::compute(store, now, decisions, &pins, validator, &authority),
            VerifierState::compute(&pruned, now, decisions, &pins, validator, &authority),
            "pruning changed the derivation"
        );

        pruned
    }

    #[test]
    fn dominated_records_are_dropped_and_derivation_is_preserved() -> TestResult {
        // Same document/generation, same inception (so tenure and
        // the leaf comparator lose nothing): a longer-lived sibling
        // with a higher serial and later issuance dominates.
        let weak = binding(1, 11, 1, 50, (NOW - 5_000, NOW - 1_000), 10)?;
        let strong = binding(1, 11, 2, 100, (NOW - 5_000, NOW + 1_000), 20)?;

        let (store, validator) = setup(&[&weak, &strong], vec![]);
        let pruned = assert_prune_invariant(&store, &validator, &Decisions::default());

        assert_eq!(pruned.items().len(), 1, "the dominated record is gone");
        Ok(())
    }

    #[test]
    fn incomparable_records_and_tenure_endpoints_survive() -> TestResult {
        // Earlier inception vs higher serial: neither dominates, and
        // the earliest-inception record is tenure's left endpoint.
        let early = binding(1, 11, 1, 100, (NOW - 9_000, NOW - 5_000), 10)?;
        let late = binding(1, 11, 2, 200, (NOW - 4_000, NOW + 1_000), 20)?;

        let (store, validator) = setup(&[&early, &late], vec![]);
        let pruned = assert_prune_invariant(&store, &validator, &Decisions::default());

        let kept: Set<_> = pruned.items().iter().map(Item::content_hash).collect();
        assert!(
            kept.contains(&early.cert.digest().erase())
                && kept.contains(&late.cert.digest().erase()),
            "BOTH incomparable records survive — by identity, not count"
        );
        assert_eq!(pruned.items().len(), 2);
        Ok(())
    }

    #[test]
    fn statements_and_cited_receipts_are_never_pruned() -> TestResult {
        let weak = binding(1, 11, 1, 50, (NOW - 4_000, NOW - 1_000), 10)?;
        let strong = binding(1, 11, 2, 100, (NOW - 5_000, NOW + 1_000), 20)?;

        // An acceptance citing the WEAK record pins it in place.
        let mut cited = Set::default();
        cited.insert(weak.cert.digest().erase());
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

        let statement = rotation(1, 40, 41)?;
        let (store, validator) = setup(&[&weak, &strong], vec![Item::Rotation(statement.clone())]);
        let pruned = assert_prune_invariant(&store, &validator, &decisions);

        let kept: Set<_> = pruned.items().iter().map(Item::content_hash).collect();
        assert!(
            kept.contains(&weak.cert.digest().erase()),
            "the cited receipt survives"
        );
        assert!(
            kept.contains(&strong.cert.digest().erase()),
            "the dominating record survives"
        );
        assert!(
            kept.contains(&Item::Rotation(statement).content_hash()),
            "the statement survives"
        );
        assert_eq!(
            pruned.items().len(),
            3,
            "cited receipt + dominating record + statement all survive"
        );
        Ok(())
    }

    #[test]
    fn far_future_records_fall_past_the_horizon() -> TestResult {
        // Serial more than a year (ms) past NOW: prunable even though
        // nothing dominates it.
        let poisoned = binding(
            1,
            11,
            1,
            NOW * 1000 + DEFERRAL_HORIZON_MS + 1,
            (NOW - 1_000, NOW + 1_000),
            10,
        )?;

        let (store, validator) = setup(&[&poisoned], vec![]);
        let pruned = assert_prune_invariant(&store, &validator, &Decisions::default());

        // Alone, it survives as the tenure endpoint (keeping more
        // than needed is always safe).
        assert_eq!(pruned.items().len(), 1);

        // With an earlier-inception sibling covering tenure, the
        // horizon drop applies — the one sanctioned exception to the
        // invariant (a derivation more than a year out could differ,
        // and that is accepted).
        let anchor_record = binding(1, 11, 2, 100, (NOW - 5_000, NOW + 1_000), 20)?;
        let (store, validator) = setup(&[&poisoned, &anchor_record], vec![]);
        let pruned = assert_prune_invariant(&store, &validator, &Decisions::default());

        assert_eq!(pruned.items().len(), 1, "past the horizon: dropped");
        Ok(())
    }

    #[test]
    fn the_horizon_boundary_is_closed_at_exactly_one_year() -> TestResult {
        // The `<=` vs `<` mutation: a serial at EXACTLY `now·1000 +
        // horizon` is within bounds and survives beside a covering
        // sibling; one past it drops (the previous test's case).
        let at_horizon = binding(
            1,
            11,
            1,
            NOW * 1000 + DEFERRAL_HORIZON_MS,
            (NOW - 1_000, NOW + 1_000),
            10,
        )?;
        let anchor_record = binding(1, 11, 2, 100, (NOW - 5_000, NOW + 1_000), 20)?;

        let (store, validator) = setup(&[&at_horizon, &anchor_record], vec![]);
        let pruned = assert_prune_invariant(&store, &validator, &Decisions::default());

        let kept: Set<_> = pruned.items().iter().map(Item::content_hash).collect();
        assert!(
            kept.contains(&at_horizon.cert.digest().erase()),
            "exactly at the horizon is within bounds"
        );
        Ok(())
    }

    #[test]
    fn a_chain_refresh_never_prunes_a_certificate() -> TestResult {
        // The `attestation_allows` guard: a bare refresh row
        // component-wise better than the document's certificate —
        // wider window, higher serial, and (with the certificate
        // issued at 0) an equal issued_at — must NOT prune it:
        // candidacy is certificate-attested, and a store holding only
        // the zone's word cannot derive the binding at all.
        let cert = binding(1, 11, 1, 50, (NOW - 4_000, NOW - 2_000), 0)?;
        let refresh = binding(1, 11, 2, 100, (NOW - 5_000, NOW + 1_000), 0)?;

        let (mut store, mut validator) = setup(&[&cert], vec![]);
        validator = validator.with(host(), &refresh.chain, refresh.proof.clone());
        store.insert(Item::ChainRefresh {
            hostname: host(),
            chain: refresh.chain.clone(),
        });

        let pruned = assert_prune_invariant(&store, &validator, &Decisions::default());

        let kept: Set<_> = pruned.items().iter().map(Item::content_hash).collect();
        assert!(
            kept.contains(&cert.cert.digest().erase()),
            "the zone's word alone never evicts the document's own \
             direction"
        );
        Ok(())
    }

    #[test]
    fn a_certificate_may_prune_a_chain_refresh() -> TestResult {
        // The reverse direction carries no such hazard: a certificate
        // strictly better in every component drops the refresh row
        // (refresh issued_at is 0 by construction, so any certificate
        // issuance is at least as good).
        let refresh = binding(1, 11, 2, 50, (NOW - 4_000, NOW - 2_000), 0)?;
        let cert = binding(1, 11, 1, 100, (NOW - 5_000, NOW + 1_000), 20)?;

        let (mut store, mut validator) = setup(&[&cert], vec![]);
        validator = validator.with(host(), &refresh.chain, refresh.proof.clone());
        store.insert(Item::ChainRefresh {
            hostname: host(),
            chain: refresh.chain.clone(),
        });

        let refresh_item = Item::ChainRefresh {
            hostname: host(),
            chain: refresh.chain.clone(),
        };
        let pruned = assert_prune_invariant(&store, &validator, &Decisions::default());

        let kept: Set<_> = pruned.items().iter().map(Item::content_hash).collect();
        assert!(
            !kept.contains(&refresh_item.content_hash()),
            "the dominated refresh row is reclaimed"
        );
        assert!(kept.contains(&cert.cert.digest().erase()));
        Ok(())
    }

    #[test]
    fn equal_component_duplicates_are_kept_whole_and_survive_resets() -> TestResult {
        // Two certificates identical in every ladder component —
        // same document, generation, window, serial, issued_at — but
        // distinct bytes (one carries a lineage statement). Without
        // strictness they would dominate each other mutually: both
        // fall off the frontier, a hash-arbitrary tenure endpoint
        // survives alone, and a reset naming the dropped sibling by
        // hash loses its target — derive(pruned) diverges from
        // derive(store). Equal-component classes are kept whole.
        use crate::test_utils::binding_carrying;

        let plain = binding(1, 11, 1, 100, (NOW - 5_000, NOW + 1_000), 20)?;
        let carrying = binding_carrying(
            1,
            11,
            1,
            100,
            (NOW - 5_000, NOW + 1_000),
            20,
            vec![rotation(9, 40, 41)?],
        )?;
        assert_ne!(
            plain.cert.digest(),
            carrying.cert.digest(),
            "fixture sanity: distinct items"
        );

        // The reset names the record that a hash-arbitrary survivor
        // choice may or may not have kept.
        let excluded = if plain.cert.digest().erase() < carrying.cert.digest().erase() {
            &plain
        } else {
            &carrying
        };
        let mut resets = Map::default();
        let mut set = Set::default();
        set.insert(excluded.cert.digest().erase());
        resets.insert(host(), set);
        let decisions = Decisions {
            resets,
            ..Decisions::default()
        };

        let (store, validator) = setup(&[&plain, &carrying], vec![]);
        let pruned = assert_prune_invariant(&store, &validator, &decisions);

        assert_eq!(
            pruned.items().len(),
            2,
            "equal-component classes are kept whole"
        );
        Ok(())
    }

    mod props {
        use super::*;
        use crate::{
            test_utils::window,
            verifier::state::{Attestation, store::item::Item},
        };
        use onomancy_dnssec::{txt::serial::Serial, zone_state_key::ZoneStateKey};

        /// Build one `BindingEvidence` row from compact seeds — the
        /// direct-domination-law fixture.
        fn arb_record(tag: u8, seed: (u8, u64, u64, u64, u64)) -> BindingEvidence {
            let (doc_seed, from, span, serial, issued_at) = seed;
            let from = from % 1_000;

            BindingEvidence {
                attestation: if tag.is_multiple_of(2) {
                    Attestation::Certificate
                } else {
                    Attestation::ChainOnly
                },
                document: crate::test_utils::doc(doc_seed % 2),
                generation: crate::test_utils::generation((doc_seed % 2) + 10),
                hash: Digest::hash(&[tag, doc_seed]),
                hostname: host(),
                key: ZoneStateKey {
                    window_end: UnixSeconds::from(from + (span % 1_000)),
                    serial: Serial::from(serial % 64),
                    issued_at: UnixSeconds::from(issued_at % 64),
                },
                generation_on_path: true,
                window: window(from, from + (span % 1_000)),
            }
        }

        /// `dominates` is irreflexive and antisymmetric — the
        /// strictness clause, as a law rather than one example.
        #[test]
        fn dominates_is_irreflexive_and_antisymmetric() {
            bolero::check!()
                .with_type::<((u8, u64, u64, u64, u64), (u8, u64, u64, u64, u64))>()
                .for_each(|(a_seed, b_seed)| {
                    let a = arb_record(0, *a_seed);
                    let b = arb_record(2, *b_seed);

                    assert!(!dominates(&a, &a), "irreflexive");
                    assert!(
                        !(dominates(&a, &b) && dominates(&b, &a)),
                        "antisymmetric: mutual domination would drop \
                         both off the frontier"
                    );
                });
        }

        /// The generated-store pool the frontier and preservation
        /// properties share: up to six records over two documents,
        /// serials bounded far under the horizon.
        fn build_store(specs: &[(bool, u64, u64, u64, u64)]) -> (Store, MemoryValidator) {
            let mut store = Store::default();
            let mut validator = MemoryValidator::default();

            for (i, (second_doc, serial, from, span, issued_at)) in specs.iter().take(6).enumerate()
            {
                #[allow(clippy::cast_possible_truncation)]
                let tag = i as u8;
                let doc_seed = u8::from(*second_doc) + 1;
                let from = NOW - 10_000 + (from % 9_000);

                let Ok(b) = binding(
                    doc_seed,
                    doc_seed + 10,
                    tag,
                    serial % 1_000,
                    (from, from + (span % 2_000)),
                    issued_at % 100,
                ) else {
                    continue;
                };
                store.insert(Item::Record(b.cert.clone()));
                validator = validator.with(host(), &b.chain, b.proof.clone());
            }

            (store, validator)
        }

        /// The frontier, both directions: every dropped record is
        /// dominated by a kept one, and a kept-but-dominated record
        /// is only ever the tenure endpoint (its group's earliest
        /// inception).
        #[test]
        fn prune_keeps_exactly_the_frontier() {
            bolero::check!()
                .with_type::<Vec<(bool, u64, u64, u64, u64)>>()
                .for_each(|specs| {
                    let (store, validator) = build_store(specs);
                    let authority = MemoryAuthority::default();
                    let now = UnixSeconds::from(NOW);

                    let before = validate_and_extract(&store, &validator, &authority);
                    let pruned = prune(&store, now, &Decisions::default(), &validator, &authority);
                    let after = validate_and_extract(&pruned, &validator, &authority);

                    let kept: Vec<&BindingEvidence> = after.records.iter().collect();

                    for record in &before.records {
                        let was_kept = kept.iter().any(|k| k.hash == record.hash);

                        if was_kept {
                            // A kept record dominated by another KEPT
                            // record must be its group's tenure
                            // endpoint.
                            if kept.iter().any(|k| dominates(k, record)) {
                                let group_min = before
                                    .records
                                    .iter()
                                    .filter(|r| r.document == record.document)
                                    .map(|r| r.window.inception())
                                    .min();
                                assert_eq!(
                                    Some(record.window.inception()),
                                    group_min,
                                    "a dominated survivor must be the \
                                     tenure endpoint"
                                );
                            }
                        } else {
                            // Every dropped record is dominated by a
                            // kept one (no horizon drops: serials are
                            // bounded small by construction).
                            assert!(
                                kept.iter().any(|k| dominates(k, record)),
                                "a dropped record must be dominated by \
                                 a kept one"
                            );
                        }
                    }
                });
        }

        /// The invariant, generatively: `derive(prune(s)) ==
        /// derive(s)` at `now` and later clocks within the horizon —
        /// and pruning is idempotent.
        #[test]
        fn prune_never_changes_the_derivation_and_is_idempotent() {
            bolero::check!()
                .with_type::<Vec<(bool, u64, u64, u64, u64)>>()
                .for_each(|specs| {
                    let (store, validator) = build_store(specs);
                    let authority = MemoryAuthority::default();
                    let decisions = Decisions::default();
                    let pins = Map::default();
                    let now = UnixSeconds::from(NOW);

                    let pruned = prune(&store, now, &decisions, &validator, &authority);

                    // One hour and thirty days out — both far inside
                    // the one-year horizon.
                    for later in [NOW, NOW + 3_600, NOW + 30 * 24 * 3_600] {
                        let at = UnixSeconds::from(later);
                        assert_eq!(
                            VerifierState::compute(
                                &store, at, &decisions, &pins, &validator, &authority
                            ),
                            VerifierState::compute(
                                &pruned, at, &decisions, &pins, &validator, &authority
                            ),
                            "pruning changed the derivation at now + {}",
                            later - NOW
                        );
                    }

                    let twice = prune(&pruned, now, &decisions, &validator, &authority);
                    assert_eq!(
                        pruned.items().len(),
                        twice.items().len(),
                        "pruning is idempotent"
                    );
                });
        }
    }
}
