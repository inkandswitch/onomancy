//! The greedy resolution walk over REAL Automerge documents: the
//! protocol's `resolve` driven through this crate's `Namestore`/
//! `Replicas` adapters, hopping across held documents.
//!
//! Everything else tests the pieces in isolation (the walk against
//! memory fakes, the adapters method-by-method); this is the seam
//! integration — the "vanilla Automerge docs can carry a namestore"
//! claim, exercised.

#![allow(clippy::panic)] // assertion failures in tests

use automerge::{Automerge, transaction::Transactable};
use ed25519_dalek::SigningKey;
use onomancy_automerge::namestore::{DocumentNamestore, HeldDocuments};
use onomancy_core::{anchor::doc::DocAnchor, name::segment::Segment};
use onomancy_protocol::resolve::{
    namestore::{Authority, Namestore as _, Vouched},
    resolution::{PartialReason, Resolution},
    resolve,
};
use testresult::TestResult;

fn anchor(seed: u8) -> DocAnchor {
    DocAnchor::from(SigningKey::from_bytes(&[seed; 32]).verifying_key())
}

fn segments(path: &[&str]) -> TestResult<Vec<Segment>> {
    path.iter().map(|raw| Ok(Segment::parse(raw)?)).collect()
}

/// A namestore document with the given key → reference entries.
fn namestore_doc(entries: &[(&str, &DocAnchor)]) -> TestResult<Automerge> {
    let mut doc = Automerge::new();
    doc.transact::<_, _, automerge::AutomergeError>(|tx| {
        for (key, target) in entries {
            tx.put(automerge::ROOT, *key, format!("automerge:{target}"))?;
        }
        Ok(())
    })
    .map_err(|failure| failure.error)?;
    Ok(doc)
}

#[test]
fn the_walk_hops_across_held_documents() -> TestResult {
    let bob = anchor(1);
    let pics = anchor(2);
    let marker = anchor(3);

    // root ── "bob" ──▶ bob ── "pics/best" ──▶ pics
    let root = DocumentNamestore::new(namestore_doc(&[("bob", &bob)])?);
    let held = HeldDocuments::default()
        .with(bob, namestore_doc(&[("pics/best", &pics)])?)
        // A marker edge only `pics` holds, so the landing document
        // is checkable, not merely reached.
        .with(pics, namestore_doc(&[("i-am-pics", &marker)])?);

    // Two hops: a single-segment edge, then a greedy multi-segment key.
    match resolve(
        Vouched::new(root, Authority::TrustedSubstrate),
        &segments(&["bob", "pics", "best"])?,
        &held,
    ) {
        Resolution::Resolved { target, authority } => {
            assert_eq!(authority, Authority::TrustedSubstrate);
            assert_eq!(
                target.reference(&segments(&["i-am-pics"])?),
                Some(marker),
                "the walk landed in `pics`, not some other document"
            );
            Ok(())
        }
        other @ Resolution::Partial { .. } => {
            panic!("expected full resolution, got {other:?}")
        }
    }
}

#[test]
fn greedy_matching_wins_across_documents_too() -> TestResult {
    let shallow = anchor(1);
    let deep = anchor(2);
    let marker = anchor(3);

    // Both "foo" and "foo/bar" exist: the walk MUST take "foo/bar"
    // (longest match), landing in `deep` — where "baz" resolves. Had
    // it taken "foo", `shallow` has no "bar".
    let root = DocumentNamestore::new(namestore_doc(&[("foo", &shallow), ("foo/bar", &deep)])?);
    let held = HeldDocuments::default()
        .with(shallow, namestore_doc(&[])?)
        .with(deep, namestore_doc(&[("baz", &marker)])?)
        .with(marker, namestore_doc(&[("i-am-marker", &shallow)])?);

    match resolve(
        Vouched::new(root, Authority::TrustedSubstrate),
        &segments(&["foo", "bar", "baz"])?,
        &held,
    ) {
        Resolution::Resolved { target, .. } => {
            assert_eq!(
                target.reference(&segments(&["i-am-marker"])?),
                Some(shallow),
                "the walk landed at `marker`, via the greedy edge"
            );
            Ok(())
        }
        other @ Resolution::Partial { .. } => {
            panic!("expected the greedy edge to reach `deep`, got {other:?}")
        }
    }
}

mod props {
    use super::*;

    /// Longest-key matching through REAL documents, for arbitrary
    /// labels: whenever one bound key is a proper segment-prefix of
    /// another, the walk consumes the longer one — asserted by
    /// making the short key's target a document where the residue
    /// cannot resolve.
    #[test]
    fn greedy_matching_holds_for_arbitrary_labels() {
        bolero::check!()
            .with_type::<(u8, u8, u8)>()
            .for_each(|(first, second, third)| {
                let label = |prefix: &str, seed: u8| format!("{prefix}{seed}");
                let (x, y, z) = (label("x", *first), label("y", *second), label("z", *third));

                let shallow = anchor(1);
                let deep = anchor(2);
                let marker = anchor(3);

                let build = || -> TestResult<Resolution<DocumentNamestore>> {
                    let long_key = format!("{x}/{y}");
                    let root = DocumentNamestore::new(namestore_doc(&[
                        (x.as_str(), &shallow),
                        (long_key.as_str(), &deep),
                    ])?);
                    let held = HeldDocuments::default()
                        .with(shallow, namestore_doc(&[])?)
                        .with(deep, namestore_doc(&[(z.as_str(), &marker)])?)
                        .with(marker, namestore_doc(&[])?);

                    Ok(resolve(
                        Vouched::new(root, Authority::TrustedSubstrate),
                        &segments(&[&x, &y, &z])?,
                        &held,
                    ))
                };

                assert!(
                    matches!(
                        build().expect("buildable fixture"),
                        Resolution::Resolved { .. }
                    ),
                    "only the greedy (longest) key reaches a store where \
                     the residue resolves"
                );
            });
    }
}

#[test]
fn unsynced_targets_surface_as_partial() -> TestResult {
    let missing = anchor(9);
    let root = DocumentNamestore::new(namestore_doc(&[("away", &missing)])?);
    let held = HeldDocuments::default(); // nothing replicated

    match resolve(
        Vouched::new(root, Authority::TrustedSubstrate),
        &segments(&["away", "further"])?,
        &held,
    ) {
        Resolution::Partial {
            reason: PartialReason::UnsyncedTarget { target },
            ..
        } => {
            assert_eq!(target, missing);
            Ok(())
        }
        other @ (Resolution::Resolved { .. } | Resolution::Partial { .. }) => {
            panic!("expected an unsynced-target partial, got {other:?}")
        }
    }
}
