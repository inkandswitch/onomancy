//! The comparison ladder: which record is the zone's later word.
//!
//! Given two records for the same hostname, the ladder determines
//! which is *current* by precedence rungs, each consulted only when
//! stronger rungs are silent:
//!
//! ```text
//! rung 0  chain freshness            (DNSSEC-vouched)
//!   │     fresh ✓ beats stale ⚠ outright
//!   ▼
//! rung 1  succession / lineage       (the document's keys)
//!   │     signed descent orders; equivocation → fork, never picked
//!   ▼
//! rung 2  zone-state key             (DNSSEC, then zone, then signer)
//!         (window_end, serial, issued_at) lexicographic;
//!         issued_at ties only WITHIN a document — cross-document
//!         (window_end, serial) equality is zone equivocation
//! ```
//!
//! The ladder orders **currency**, never *continuity* (only a
//! succession proof confers that) and never *movement* (displacing an
//! incumbent additionally requires eligibility — the binding-cache
//! derivation's job). Rung 1's verdict is an input here: evaluating
//! succession proofs and lineage descent requires the pooled-evidence
//! statement graph, which the derivation owns.
//!
//! Determinism is a conformance target: two verifiers holding the same
//! evidence MUST reach the same verdict.

use core::cmp::Ordering;

use onomancy_core::anchor::doc::DocAnchor;
use onomancy_dnssec::{freshness::Freshness, zone_state_key::ZoneStateKey};

/// One record's ladder-relevant facts, extracted by the derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Contender {
    /// The document the record attests.
    pub document: DocAnchor,

    /// The record's chain grade at `now` (deferred records are not
    /// contenders at all).
    pub freshness: Freshness,

    /// The record's zone-state sort key.
    pub key: ZoneStateKey,
}

/// Rung 1's verdict, supplied by the caller from the pooled evidence:
/// valid succession statements across documents, or signed lineage
/// descent within one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Continuity {
    /// Competing valid statements: provable equivocation. Surface,
    /// never pick.
    Fork,

    /// The statement graph orders the left contender newer.
    LeftNewer,

    /// The statement graph orders the right contender newer.
    RightNewer,

    /// No statement orders the pair (absent or incomparable lineage is
    /// never evidence).
    #[default]
    Silent,
}

/// The ladder's deterministic outcome for one pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// Identical zone state for the same document: neither is the
    /// later word (replay territory — domination is the derivation's
    /// call).
    Equal,

    /// Cross-document equality at `(window_end, serial)`: zone
    /// equivocation. Contested, surfaced, never auto-resolved — and
    /// never resolved by the signer-claimed `issued_at`.
    Equivocation,

    /// Rung 1 found competing valid statements: surfaced, never
    /// picked.
    Fork,

    /// The left contender is the later word.
    Left,

    /// The right contender is the later word.
    Right,
}

/// Compare two contenders for the same hostname.
///
/// `continuity` is rung 1's verdict over the pooled evidence (pass
/// [`Continuity::Silent`] when no statements bear on the pair).
#[must_use]
pub fn compare(left: &Contender, right: &Contender, continuity: Continuity) -> Verdict {
    // Rung 0: a fresh ✓ record beats any stale ⚠ one outright.
    match (left.freshness, right.freshness) {
        (Freshness::Fresh, Freshness::Stale) => return Verdict::Left,
        (Freshness::Stale, Freshness::Fresh) => return Verdict::Right,
        _ => (),
    }

    // Rung 1: signed statement order, when it speaks.
    match continuity {
        Continuity::Fork => return Verdict::Fork,
        Continuity::LeftNewer => return Verdict::Left,
        Continuity::RightNewer => return Verdict::Right,
        Continuity::Silent => (),
    }

    // Rung 2: the zone-state key.
    if left.document == right.document {
        match left.key.cmp(&right.key) {
            Ordering::Greater => Verdict::Left,
            Ordering::Less => Verdict::Right,
            Ordering::Equal => Verdict::Equal,
        }
    } else {
        // Cross-document: issued_at is signer-claimed and MUST NOT
        // resolve what would otherwise be zone equivocation.
        match left.key.zone_vouched().cmp(&right.key.zone_vouched()) {
            Ordering::Greater => Verdict::Left,
            Ordering::Less => Verdict::Right,
            Ordering::Equal => Verdict::Equivocation,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use onomancy_core::time::UnixSeconds;
    use onomancy_dnssec::txt::serial::Serial;

    fn doc(seed: u8) -> DocAnchor {
        DocAnchor::from(SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    fn key(window_end: u64, serial: u64, issued_at: u64) -> ZoneStateKey {
        ZoneStateKey {
            window_end: UnixSeconds::from(window_end),
            serial: Serial::from(serial),
            issued_at: UnixSeconds::from(issued_at),
        }
    }

    fn contender(doc_seed: u8, freshness: Freshness, k: ZoneStateKey) -> Contender {
        Contender {
            document: doc(doc_seed),
            freshness,
            key: k,
        }
    }

    #[test]
    fn fresh_beats_stale_outright_even_with_a_lower_key() {
        // The D4a case: fresh wins rung 0 including with a lower
        // serial — the downward move surfaces as a ratchet reset, but
        // the ladder's pick is deterministic.
        let fresh_low = contender(1, Freshness::Fresh, key(10, 1, 1));
        let stale_high = contender(2, Freshness::Stale, key(99, 99, 99));

        assert_eq!(
            compare(&fresh_low, &stale_high, Continuity::Silent),
            Verdict::Left
        );
        assert_eq!(
            compare(&stale_high, &fresh_low, Continuity::Silent),
            Verdict::Right
        );
    }

    #[test]
    fn continuity_orders_within_a_freshness_class() {
        // Between two stale artifacts, the lineage-descendant wins;
        // the serial is only a tiebreak when lineage is silent.
        let old = contender(1, Freshness::Stale, key(99, 99, 99));
        let new = contender(2, Freshness::Stale, key(1, 1, 1));

        assert_eq!(compare(&old, &new, Continuity::RightNewer), Verdict::Right);
        assert_eq!(compare(&old, &new, Continuity::Silent), Verdict::Left);
    }

    #[test]
    fn forks_are_surfaced_never_picked() {
        let a = contender(1, Freshness::Stale, key(2, 2, 2));
        let b = contender(2, Freshness::Stale, key(1, 1, 1));

        assert_eq!(compare(&a, &b, Continuity::Fork), Verdict::Fork);
    }

    #[test]
    fn rung_zero_outranks_rung_one() {
        // A fresh chain vs a valid superseding statement is D12a fork
        // territory upstream, but at ladder level rung 0 speaks first;
        // the fork input only matters within a freshness class.
        let fresh = contender(1, Freshness::Fresh, key(1, 1, 1));
        let stale = contender(2, Freshness::Stale, key(2, 2, 2));

        assert_eq!(
            compare(&fresh, &stale, Continuity::RightNewer),
            Verdict::Left
        );
    }

    #[test]
    fn issued_at_ties_within_a_document_only() {
        // Same document: issued_at breaks the tie.
        let earlier = contender(1, Freshness::Stale, key(5, 5, 1));
        let later = contender(1, Freshness::Stale, key(5, 5, 2));
        assert_eq!(compare(&later, &earlier, Continuity::Silent), Verdict::Left);

        // Different documents, equal (window_end, serial): zone
        // equivocation regardless of issued_at.
        let other = contender(2, Freshness::Stale, key(5, 5, 9));
        assert_eq!(
            compare(&earlier, &other, Continuity::Silent),
            Verdict::Equivocation
        );
    }

    #[test]
    fn identical_same_document_keys_are_equal_not_equivocation() {
        let a = contender(1, Freshness::Stale, key(5, 5, 5));
        let b = contender(1, Freshness::Stale, key(5, 5, 5));

        assert_eq!(compare(&a, &b, Continuity::Silent), Verdict::Equal);
    }

    mod props {
        use super::*;

        fn arb_contender(seed: (u8, bool, u64, u64, u64)) -> Contender {
            let (doc_seed, fresh, w, s, i) = seed;
            contender(
                doc_seed % 4,
                if fresh {
                    Freshness::Fresh
                } else {
                    Freshness::Stale
                },
                key(w % 4, s % 4, i % 4),
            )
        }

        /// Swapping the operands (and the continuity verdict's
        /// orientation) mirrors the outcome: no left-hand bias, so
        /// evidence enumeration order cannot decide anything.
        #[test]
        fn compare_is_antisymmetric() {
            bolero::check!()
                .with_type::<((u8, bool, u64, u64, u64), (u8, bool, u64, u64, u64), u8)>()
                .for_each(|(l, r, c)| {
                    let left = arb_contender(*l);
                    let right = arb_contender(*r);

                    let continuity = match c % 4 {
                        0 => Continuity::Silent,
                        1 => Continuity::LeftNewer,
                        2 => Continuity::RightNewer,
                        _ => Continuity::Fork,
                    };
                    let mirrored = match continuity {
                        Continuity::LeftNewer => Continuity::RightNewer,
                        Continuity::RightNewer => Continuity::LeftNewer,
                        Continuity::Fork => Continuity::Fork,
                        Continuity::Silent => Continuity::Silent,
                    };

                    let forward = compare(&left, &right, continuity);
                    let backward = compare(&right, &left, mirrored);

                    let expected = match forward {
                        Verdict::Left => Verdict::Right,
                        Verdict::Right => Verdict::Left,
                        Verdict::Equal => Verdict::Equal,
                        Verdict::Equivocation => Verdict::Equivocation,
                        Verdict::Fork => Verdict::Fork,
                    };

                    assert_eq!(backward, expected);
                });
        }

        /// With continuity silent, rung 0+2 comparison is transitive
        /// in its strict wins — the no-cycles property the single
        /// lexicographic key exists to buy.
        #[test]
        fn silent_ladder_never_cycles() {
            bolero::check!()
                .with_type::<(
                    (u8, bool, u64, u64, u64),
                    (u8, bool, u64, u64, u64),
                    (u8, bool, u64, u64, u64),
                )>()
                .for_each(|(x, y, z)| {
                    let a = arb_contender(*x);
                    let b = arb_contender(*y);
                    let c = arb_contender(*z);

                    // a beats b, b beats c ⇒ c must not beat a.
                    if compare(&a, &b, Continuity::Silent) == Verdict::Left
                        && compare(&b, &c, Continuity::Silent) == Verdict::Left
                    {
                        assert_ne!(
                            compare(&c, &a, Continuity::Silent),
                            Verdict::Left,
                            "ladder cycle: a > b > c > a"
                        );
                    }
                });
        }
    }
}
