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
    // certificate-attested (B14), so a ChainOnly item component-wise
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

        let (store, validator) = setup(
            &[&weak, &strong],
            vec![Item::Rotation(rotation(1, 40, 41)?)],
        );
        let pruned = assert_prune_invariant(&store, &validator, &decisions);

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
    fn equal_component_duplicates_are_kept_whole_and_survive_resets() -> TestResult {
        // Review probe D: two certificates identical in every ladder
        // component — same document, generation, window, serial,
        // issued_at — but distinct bytes (one carries a lineage
        // statement). Under a non-strict domination relation they
        // dominated each other MUTUALLY: both fell off the frontier,
        // a hash-arbitrary tenure endpoint survived alone, and a
        // reset naming the dropped sibling by hash silently lost its
        // target — derive(pruned) diverged from derive(store).
        // Domination is strict now; equal classes are kept whole.
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
}
