//! Path resolution: the greedy namestore walk.
//!
//! Implements the Onomancy Path Resolution specification: anchor
//! resolution has already produced a *root namestore*, and this module
//! walks the remaining segments — greedy longest-key match, one hop
//! per matched key, no backtracking — terminating in at most
//! `len(segments)` hops.
//!
//! # Sans-IO by Specification
//!
//! The walk performs no IO *because the spec says so*, not merely as an
//! implementation style: resolution reads locally-replicated documents,
//! and a namestore that is not locally available is the
//! [`PartialReason::UnsyncedTarget`](resolution::PartialReason::UnsyncedTarget)
//! outcome — data that is unavailable, not wrong. Replication is
//! somebody else's job (and somebody else's crate).
//!
//! ```text
//! Name { anchor, segments }
//!         │ anchoring (elsewhere) ─► root namestore
//!         ▼
//! ┌─► segments empty? ──yes──► Resolved (weakest grade crossed)
//! │       │ no
//! │       ▼
//! │   greedy longest key matching a segment prefix?
//! │       │ none ──► Partial(DanglingSegment)
//! │       ▼
//! │   consume len(key) segments, look up target replica
//! │       │ absent ──► Partial(UnsyncedTarget)
//! └───────┘
//! ```
//!
//! # Module Organization
//!
//! - [`namestore`] — the [`Namestore`](namestore::Namestore) and
//!   [`Replicas`](namestore::Replicas) trait seams
//! - [`resolution`] — the [`Resolution`](resolution::Resolution)
//!   outcome type
//! - [`memory`] — in-memory implementations (test doubles, small tools)

pub mod namestore;
pub mod resolution;

use onomancy_core::name::segment::Segment;

use self::{
    namestore::{Namestore, Replicas, Vouched},
    resolution::{PartialReason, Resolution},
};

/// Walk `segments` from `root`, loading hop targets from `replicas`.
///
/// Pure and total: the outcome depends only on the arguments, and the
/// walk performs at most `segments.len()` hops (each hop consumes at
/// least one segment — the termination argument is structural, never a
/// hop limit).
///
/// Heads are not an input: a pinned name's root namestore is read *at*
/// its heads by the anchoring layer before this walk begins, and
/// pinning is deliberately not transitive.
///
/// The outcome's [`Authority`] is the weakest grade crossed — the
/// root's and every hop's, folded by min.
#[must_use]
pub fn resolve<N: Namestore, R: Replicas<Namestore = N>>(
    root: Vouched<N>,
    segments: &[Segment],
    replicas: &R,
) -> Resolution<N> {
    let (mut current, mut authority) = root.into_parts();
    let mut remaining = segments;
    let consumed = |remaining: &[Segment]| segments.len() - remaining.len();

    loop {
        if remaining.is_empty() {
            return Resolution::Resolved {
                target: current,
                authority,
            };
        }

        // Greedy longest-key match: try the whole remainder first,
        // shrinking one segment at a time. No backtracking — if the
        // selected edge later dead-ends, that outcome stands.
        let Some((matched_len, target)) = (1..=remaining.len()).rev().find_map(|n| {
            remaining
                .get(..n)
                .and_then(|prefix| current.reference(prefix).map(|target| (n, target)))
        }) else {
            return Resolution::Partial {
                consumed: consumed(remaining),
                reason: PartialReason::DanglingSegment,
            };
        };

        remaining = remaining.get(matched_len..).unwrap_or(&[]);

        match replicas.replica(&target) {
            Some(vouched) => {
                let (next, grade) = vouched.into_parts();
                current = next;
                authority = authority.min(grade);
            }
            None => {
                return Resolution::Partial {
                    consumed: consumed(remaining),
                    reason: PartialReason::UnsyncedTarget { target },
                };
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{
        namestore::{
            Authority,
            memory::{MemoryNamestore, MemoryReplicas},
        },
        *,
    };
    use alloc::vec::Vec;
    use ed25519_dalek::SigningKey;
    use onomancy_core::anchor::doc::DocAnchor;

    fn doc(seed: u8) -> DocAnchor {
        DocAnchor::from(SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    fn segments(path: &str) -> Vec<Segment> {
        path.split('/')
            .map(|s| Segment::parse(s).expect("test segments are valid"))
            .collect()
    }

    /// The spec's greedy-matching table: `{ "foo": a, "foo/bar/baz": b }`.
    fn spec_store() -> MemoryNamestore {
        MemoryNamestore::default()
            .with(&segments("foo"), doc(1))
            .with(&segments("foo/bar/baz"), doc(2))
    }

    /// A root vouched at the dev-bridge grade.
    fn trusted(store: MemoryNamestore) -> Vouched<MemoryNamestore> {
        Vouched::new(store, Authority::TrustedSubstrate)
    }

    #[test]
    fn empty_segments_resolve_to_the_root_itself() {
        let root = spec_store();
        let outcome = resolve(trusted(root.clone()), &[], &MemoryReplicas::default());
        assert_eq!(
            outcome,
            Resolution::Resolved {
                target: root,
                authority: Authority::TrustedSubstrate
            }
        );
    }

    #[test]
    fn longest_key_wins() {
        // `foo/bar/baz/quux`: matches the 3-segment key, hops to doc(2),
        // continues with [quux].
        let replicas = MemoryReplicas::default()
            .with(
                doc(2),
                MemoryNamestore::default().with(&segments("quux"), doc(3)),
            )
            .with(doc(3), MemoryNamestore::default());

        let outcome = resolve(
            trusted(spec_store()),
            &segments("foo/bar/baz/quux"),
            &replicas,
        );
        assert_eq!(
            outcome,
            Resolution::Resolved {
                target: MemoryNamestore::default(),
                authority: Authority::TrustedSubstrate
            }
        );
    }

    #[test]
    fn the_outcome_grade_is_the_weakest_link() {
        // Root and first hop are carriage-verified; the second hop is
        // only substrate-trusted — and drags the whole outcome down.
        let replicas = MemoryReplicas::default()
            .with_vouched(
                doc(1),
                MemoryNamestore::default().with(&segments("bar"), doc(2)),
                Authority::CarriageVerified,
            )
            .with(doc(2), MemoryNamestore::default());

        let root = MemoryNamestore::default().with(&segments("foo"), doc(1));

        let strong = resolve(
            Vouched::new(root.clone(), Authority::CarriageVerified),
            &segments("foo"),
            &replicas,
        );
        assert_eq!(
            strong,
            Resolution::Resolved {
                target: MemoryNamestore::default().with(&segments("bar"), doc(2)),
                authority: Authority::CarriageVerified
            }
        );

        let weakened = resolve(
            Vouched::new(root, Authority::CarriageVerified),
            &segments("foo/bar"),
            &replicas,
        );
        assert_eq!(
            weakened,
            Resolution::Resolved {
                target: MemoryNamestore::default(),
                authority: Authority::TrustedSubstrate
            }
        );
    }

    #[test]
    fn partial_prefix_of_long_key_falls_back_to_short_key() {
        // `foo/bar`: `foo/bar/baz` is NOT a prefix of the remaining
        // segments, so `foo` (1 segment) matches; hop to doc(1),
        // continue with [bar] — which dangles there.
        let replicas = MemoryReplicas::default().with(doc(1), MemoryNamestore::default());

        let outcome = resolve(trusted(spec_store()), &segments("foo/bar"), &replicas);
        assert_eq!(
            outcome,
            Resolution::Partial {
                consumed: 1,
                reason: PartialReason::DanglingSegment
            }
        );
    }

    #[test]
    fn unsynced_target_is_unavailable_not_wrong() {
        let outcome = resolve(
            trusted(spec_store()),
            &segments("foo/bar/baz"),
            &MemoryReplicas::default(),
        );
        assert_eq!(
            outcome,
            Resolution::Partial {
                consumed: 3,
                reason: PartialReason::UnsyncedTarget { target: doc(2) }
            }
        );
    }

    #[test]
    fn no_backtracking_after_a_greedy_dead_end() {
        // Both `a` and `a/b` exist. `a/b/c` greedily takes `a/b` into a
        // store with nothing; the resolver MUST NOT retry via `a`.
        let root = MemoryNamestore::default()
            .with(&segments("a"), doc(1))
            .with(&segments("a/b"), doc(2));
        let replicas = MemoryReplicas::default()
            .with(
                doc(1),
                MemoryNamestore::default()
                    .with(&segments("b"), doc(3))
                    .with(&segments("b/c"), doc(3)),
            )
            .with(doc(2), MemoryNamestore::default())
            .with(doc(3), MemoryNamestore::default());

        let outcome = resolve(trusted(root), &segments("a/b/c"), &replicas);
        assert_eq!(
            outcome,
            Resolution::Partial {
                consumed: 2,
                reason: PartialReason::DanglingSegment
            }
        );
    }

    #[test]
    fn cycles_are_harmless_because_hops_consume_segments() {
        // alice ↔ bob namestores referencing each other: the walk
        // `alice/bob/alice` still terminates (3 hops, 3 segments).
        let alice = doc(10);
        let bob = doc(11);
        let alice_store = MemoryNamestore::default().with(&segments("bob"), bob);
        let bob_store = MemoryNamestore::default().with(&segments("alice"), alice);
        let root = MemoryNamestore::default().with(&segments("alice"), alice);

        let replicas = MemoryReplicas::default()
            .with(alice, alice_store)
            .with(bob, bob_store);

        // Three segments, three hops: root's `alice` edge, alice's
        // `bob` edge, bob's `alice` edge — landing back in alice's
        // store. The two `alice` edges live in different namestores.
        let outcome = resolve(trusted(root), &segments("alice/bob/alice"), &replicas);
        let expected = MemoryNamestore::default().with(&segments("bob"), bob);
        assert_eq!(
            outcome,
            Resolution::Resolved {
                target: expected,
                authority: Authority::TrustedSubstrate
            }
        );
    }

    mod props {
        use super::*;

        /// Termination is structural: the number of replica loads never
        /// exceeds the segment count, for arbitrary namestore graphs —
        /// including cyclic ones.
        #[test]
        fn hops_never_exceed_segment_count() {
            bolero::check!()
                .with_type::<(Vec<(u8, Vec<u8>, u8)>, Vec<u8>)>()
                .for_each(|(edges, walk)| {
                    // Build an arbitrary graph over 8 documents whose
                    // keys are 1–2 segment paths drawn from a tiny
                    // alphabet, then walk an arbitrary segment list.
                    let seg = |b: &u8| {
                        Segment::parse(match b % 3 {
                            0 => "x",
                            1 => "y",
                            _ => "z",
                        })
                        .expect("static segments parse")
                    };

                    let mut stores: Vec<MemoryNamestore> =
                        (0..8).map(|_| MemoryNamestore::default()).collect();
                    for (owner, path, target) in edges {
                        let path: Vec<Segment> = path.iter().take(2).map(seg).collect();
                        if path.is_empty() {
                            continue;
                        }
                        if let Some(store) = stores.get_mut(usize::from(owner % 8)) {
                            *store = store.clone().with(&path, doc(target % 8));
                        }
                    }

                    let mut replicas = MemoryReplicas::counting();
                    for (i, store) in stores.iter().enumerate() {
                        #[allow(clippy::cast_possible_truncation)]
                        let id = doc(i as u8);
                        replicas = replicas.with(id, store.clone());
                    }

                    let walk: Vec<Segment> = walk.iter().take(6).map(seg).collect();
                    let root = stores.first().cloned().unwrap_or_default();

                    let _outcome = resolve(trusted(root), &walk, &replicas);
                    assert!(
                        replicas.loads() <= walk.len(),
                        "structural termination: ≤ one hop per segment"
                    );
                });
        }

        /// Outcomes are deterministic and local: adding replicas that
        /// the walk never reaches cannot change the outcome.
        #[test]
        fn unrelated_replicas_do_not_change_outcomes() {
            bolero::check!()
                .with_type::<(Vec<u8>, u8)>()
                .for_each(|(walk, extra_seed)| {
                    let seg = |b: &u8| {
                        Segment::parse(if b.is_multiple_of(2) { "x" } else { "y" })
                            .expect("static segments parse")
                    };
                    let walk: Vec<Segment> = walk.iter().take(4).map(seg).collect();

                    let root = MemoryNamestore::default()
                        .with(&segments("x"), doc(1))
                        .with(&segments("x/y"), doc(2));
                    let replicas =
                        MemoryReplicas::default().with(doc(1), MemoryNamestore::default());

                    let with_unreachable = replicas.clone().with(
                        doc(extra_seed % 8 + 40),
                        MemoryNamestore::default().with(&segments("x"), doc(1)),
                    );

                    assert_eq!(
                        resolve(trusted(root.clone()), &walk, &replicas),
                        resolve(trusted(root), &walk, &with_unreachable),
                        "unreachable replicas must not affect the walk"
                    );
                });
        }
    }
}
