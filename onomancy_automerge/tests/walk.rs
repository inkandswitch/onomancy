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
    namestore::{Authority, Vouched},
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

    // root ── "bob" ──▶ bob ── "pics/best" ──▶ pics
    let root = DocumentNamestore::new(namestore_doc(&[("bob", &bob)])?);
    let held = HeldDocuments::default()
        .with(bob, namestore_doc(&[("pics/best", &pics)])?)
        .with(pics, namestore_doc(&[])?);

    // Two hops: a single-segment edge, then a greedy multi-segment key.
    match resolve(
        Vouched::new(root, Authority::TrustedSubstrate),
        &segments(&["bob", "pics", "best"])?,
        &held,
    ) {
        Resolution::Resolved { authority, .. } => {
            assert_eq!(authority, Authority::TrustedSubstrate);
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
        .with(marker, namestore_doc(&[])?);

    match resolve(
        Vouched::new(root, Authority::TrustedSubstrate),
        &segments(&["foo", "bar", "baz"])?,
        &held,
    ) {
        Resolution::Resolved { .. } => Ok(()),
        other @ Resolution::Partial { .. } => {
            panic!("expected the greedy edge to reach `deep`, got {other:?}")
        }
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
