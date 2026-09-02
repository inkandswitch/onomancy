//! The petname store: writes over the user's own namestore, and the
//! divergence join (petname-anchor spec).
//!
//! A petname edge is a bare document reference under the user's own
//! authority — no metadata, no symlinks. The alleged name from an
//! introduction is NEVER stored on the edge: it lives as a claim in
//! the decision document, so renames move only the label and can
//! never sever divergence detection (P1).

use automerge::{Automerge, transaction::Transactable};
use onomancy_core::{
    anchor::doc::{self, DocAnchor},
    collections::Map,
    name::segment::Segment,
};
use onomancy_dnssec::dns_name::DnsName;
use onomancy_protocol::{resolve::namestore::Namestore, verifier::state::decisions::Decisions};

use crate::namestore::{DocumentNamestore, path_key};

/// Write access to the petname edges of the user's own root document.
///
/// Reads go through [`DocumentNamestore`] — this type only mutates,
/// and only under the caller's own authority (write control is the
/// substrate's job).
#[derive(Debug)]
pub struct PetnameStore<'a> {
    doc: &'a mut Automerge,
}

impl<'a> PetnameStore<'a> {
    /// Write access over the user's own (held, writable) document.
    pub const fn new(doc: &'a mut Automerge) -> Self {
        Self { doc }
    }

    /// Bind `path` to `target` — introduction or deliberate re-pin
    /// (the re-pin flow MUST reach user confirmation before calling
    /// this; divergence is never auto-accepted, P4).
    ///
    /// # Errors
    ///
    /// Returns [`WriteError::EmptyPath`] for a path with no segments,
    /// and [`WriteError`] when the substrate rejects the transaction.
    pub fn pin(&mut self, path: &[Segment], target: &DocAnchor) -> Result<(), WriteError> {
        let key = path_key(path).ok_or(WriteError::EmptyPath)?;
        let reference = format!("{}{target}", doc::SCHEME_PREFIX);

        self.doc
            // A name is a root key: `foo` is `root["foo"]`, flat, with
            // no container map to descend into.
            .transact::<_, _, automerge::AutomergeError>(|tx| {
                tx.put(automerge::ROOT, key.as_str(), reference.as_str())
            })
            .map_err(|failure| WriteError::Automerge(failure.error))?;

        Ok(())
    }

    /// Remove the edge at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`WriteError::MissingEdge`] when no well-formed edge
    /// exists there, or [`WriteError::Automerge`] when the substrate
    /// rejects the transaction.
    pub fn unpin(&mut self, path: &[Segment]) -> Result<(), WriteError> {
        let key = path_key(path).ok_or(WriteError::EmptyPath)?;
        self.existing_edge(path)?;

        self.doc
            .transact::<_, _, automerge::AutomergeError>(|tx| {
                tx.delete(automerge::ROOT, key.as_str())
            })
            .map_err(|failure| WriteError::Automerge(failure.error))?;

        Ok(())
    }

    /// Relabel an edge: trust never flows through the label, so this
    /// changes nothing but display — and cannot sever divergence
    /// detection, because the alleged-name claim lives in the
    /// decision document, not on the edge (P1).
    ///
    /// # Errors
    ///
    /// Returns [`WriteError::MissingEdge`] when `from` holds no
    /// well-formed edge, or [`WriteError::Automerge`] when the
    /// substrate rejects the transaction.
    pub fn rename(&mut self, from: &[Segment], to: &[Segment]) -> Result<(), WriteError> {
        let target = self.existing_edge(from)?;
        self.pin(to, &target)?;
        self.unpin(from)
    }

    /// The well-formed edge at `path`, or [`WriteError::MissingEdge`].
    fn existing_edge(&self, path: &[Segment]) -> Result<DocAnchor, WriteError> {
        DocumentNamestore::new(self.doc.clone())
            .reference(path)
            .ok_or(WriteError::MissingEdge)
    }
}

/// The user's pinned targets per hostname — derivation stage 8's
/// `pins` input, built by the divergence join (petname-anchor spec,
/// Divergence and Re-Pin): a claim links a hostname to a document,
/// and a petname edge targeting that document makes it a pinned
/// target for that hostname. No per-edge metadata — SSH
/// `known_hosts` semantics, by document-ID join.
#[must_use]
pub fn pins(namestore: &DocumentNamestore, decisions: &Decisions) -> Map<DnsName, Vec<DocAnchor>> {
    let mut pinned_targets: Vec<DocAnchor> = namestore
        .edges()
        .into_iter()
        .map(|(_, target)| target)
        .collect();
    pinned_targets.sort_unstable();
    pinned_targets.dedup();

    let mut pins: Map<DnsName, Vec<DocAnchor>> = Map::default();

    for claim in &decisions.claims {
        if pinned_targets.binary_search(&claim.document).is_ok() {
            let targets = pins.entry(claim.hostname.clone()).or_default();
            if !targets.contains(&claim.document) {
                targets.push(claim.document);
            }
        }
    }

    for targets in pins.values_mut() {
        targets.sort_unstable();
    }

    pins
}

/// A petname write failed.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// The substrate rejected the transaction.
    #[error(transparent)]
    Automerge(#[from] automerge::AutomergeError),

    /// The source path holds no well-formed petname edge.
    #[error("no petname edge at the source path")]
    MissingEdge,

    /// A path with no segments.
    ///
    /// There is no key for "no segments": keys MUST be one or more
    /// segments (path-resolution spec, Namestore Layout), and the
    /// obvious fallback of `""` would write a key no name can ever
    /// match — a write that appears to succeed and can never be read
    /// back through a name.
    #[error("a petname path needs at least one segment")]
    EmptyPath,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use onomancy_protocol::verifier::state::decisions::Claim;
    use testresult::TestResult;

    fn anchor(seed: u8) -> DocAnchor {
        DocAnchor::from(SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    fn segments(path: &[&str]) -> Vec<Segment> {
        path.iter()
            .map(|raw| Segment::parse(raw).expect("valid segment"))
            .collect()
    }

    fn hostname(raw: &str) -> DnsName {
        DnsName::parse(raw).expect("valid hostname")
    }

    #[test]
    fn pin_read_rename_unpin_roundtrip() -> TestResult {
        let mut doc = Automerge::new();
        let bob = anchor(1);
        let label = segments(&["bob"]);
        let relabel = segments(&["robert"]);

        PetnameStore::new(&mut doc).pin(&label, &bob)?;
        assert_eq!(
            DocumentNamestore::new(doc.clone()).reference(&label),
            Some(bob)
        );

        // Rename moves only the label.
        PetnameStore::new(&mut doc).rename(&label, &relabel)?;
        let store = DocumentNamestore::new(doc.clone());
        assert_eq!(store.reference(&label), None);
        assert_eq!(store.reference(&relabel), Some(bob));

        PetnameStore::new(&mut doc).unpin(&relabel)?;
        assert_eq!(
            DocumentNamestore::new(doc.clone()).reference(&relabel),
            None
        );
        Ok(())
    }

    #[test]
    fn writes_against_missing_edges_error() {
        let mut doc = Automerge::new();
        let mut store = PetnameStore::new(&mut doc);

        assert!(matches!(
            store.unpin(&segments(&["ghost"])),
            Err(WriteError::MissingEdge)
        ));
        assert!(matches!(
            store.rename(&segments(&["ghost"]), &segments(&["still-ghost"])),
            Err(WriteError::MissingEdge)
        ));
    }

    #[test]
    fn pins_join_claims_with_pinned_targets() -> TestResult {
        let bob = anchor(1);
        let carol = anchor(2);

        let mut doc = Automerge::new();
        PetnameStore::new(&mut doc).pin(&segments(&["bob"]), &bob)?;

        let decisions = Decisions {
            claims: vec![
                // Pinned target + claim: joins.
                Claim {
                    hostname: hostname("bob.example"),
                    document: bob,
                    note: None,
                },
                // Claim without a pinned edge: no pin entry.
                Claim {
                    hostname: hostname("carol.example"),
                    document: carol,
                    note: None,
                },
            ],
            ..Decisions::default()
        };

        let pins = pins(&DocumentNamestore::new(doc), &decisions);
        assert_eq!(pins.get(&hostname("bob.example")), Some(&vec![bob]));
        assert_eq!(pins.get(&hostname("carol.example")), None);
        Ok(())
    }

    #[test]
    fn renames_never_sever_the_divergence_join() -> TestResult {
        // The spec's P1 condition, end to end: the claim is frozen
        // evidence in the decision document, so relabeling the edge
        // leaves the hostname's pinned target untouched.
        let bob = anchor(1);
        let mut doc = Automerge::new();
        PetnameStore::new(&mut doc).pin(&segments(&["bob"]), &bob)?;

        let decisions = Decisions {
            claims: vec![Claim {
                hostname: hostname("bob.example"),
                document: bob,
                note: None,
            }],
            ..Decisions::default()
        };

        PetnameStore::new(&mut doc).rename(&segments(&["bob"]), &segments(&["robert"]))?;

        let pins = pins(&DocumentNamestore::new(doc), &decisions);
        assert_eq!(
            pins.get(&hostname("bob.example")),
            Some(&vec![bob]),
            "the join survives the rename"
        );
        Ok(())
    }

    /// Writing a name with no segments is refused rather than
    /// silently writing the empty key — a pin that appears to succeed
    /// and can never be resolved back.
    #[test]
    fn pinning_an_empty_path_is_refused() {
        let mut doc = Automerge::new();

        assert!(matches!(
            PetnameStore::new(&mut doc).pin(&[], &anchor(1)),
            Err(WriteError::EmptyPath)
        ));

        // And nothing was written: no empty key, no edge.
        let read = DocumentNamestore::new(doc).read();
        assert!(read.edges.is_empty());
        assert!(read.malformed_keys.is_empty());
    }
}
