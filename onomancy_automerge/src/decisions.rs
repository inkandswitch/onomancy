//! Reading the decision document (binding-cache spec, Schema).
//!
//! The schema is a data-shape contract, not a wire codec — the
//! substrate carries the bytes, and this module reads whatever state
//! it is handed. Write control is the document's own access
//! delegation, invisible here. Entries that do not match the shape
//! contribute nothing (the derivation never guesses); unknown schema
//! versions read as empty.

// Foreign-enum wildcards are the contract here: any value shape this
// reader does not recognize — including variants Automerge adds later —
// contributes nothing, by design.
#![allow(clippy::wildcard_enum_match_arm)]

use automerge::{Automerge, ObjId, ObjType, Prop, ReadDoc, ScalarValue, Value};
use onomancy_core::{
    anchor::doc::DocAnchor,
    collections::Set,
    digest::{Blake3, Digest},
    key,
};
use onomancy_dnssec::dns_name::DnsName;
use onomancy_protocol::verifier::state::decisions::{Acceptance, Claim, Decisions};

/// The decisions schema is protocol data, not names: a single root
/// key holding a versioned map, namespaced like every other reserved
/// entry. Its value is a map rather than a reference, so it takes no
/// part in path matching: non-reference values are absent from
/// matching (path-resolution spec, Error Conditions).
pub(crate) const DECISIONS_KEY: &str = ".well-known/onomancy/decisions";

/// The decisions schema version this reader understands.
pub const SCHEMA_VERSION: u64 = 0;

/// A read-only view over one decision document.
#[derive(Debug, Clone, Copy)]
pub struct DecisionsView<'a> {
    doc: &'a Automerge,
}

impl<'a> DecisionsView<'a> {
    /// View a held decision document.
    #[must_use]
    pub const fn new(doc: &'a Automerge) -> Self {
        Self { doc }
    }

    /// The decisions the document currently expresses.
    ///
    /// Total by construction: a missing reserved map, an unknown
    /// `v`, or a malformed entry never fails the read — unknown
    /// versions read nothing, malformed entries contribute nothing.
    #[must_use]
    pub fn decisions(self) -> Decisions {
        let Some(root) = self.schema_root() else {
            return Decisions::default();
        };

        Decisions {
            acceptances: self.acceptances(&root),
            claims: self.claims(&root),
            resets: self.resets(&root),
        }
    }

    /// The reserved map, gated on the schema version.
    fn schema_root(self) -> Option<ObjId> {
        let map = self.object(automerge::ROOT, DECISIONS_KEY, ObjType::Map)?;

        let (version, _) = self.doc.get(&map, "v").ok()??;
        let Value::Scalar(scalar) = version else {
            return None;
        };
        let recognized = match scalar.as_ref() {
            ScalarValue::Int(v) => u64::try_from(*v).ok() == Some(SCHEMA_VERSION),
            ScalarValue::Uint(v) => *v == SCHEMA_VERSION,
            _ => false,
        };

        recognized.then_some(map)
    }

    fn claims(self, root: &ObjId) -> Vec<Claim> {
        let Some(list) = self.object(root, "claims", ObjType::List) else {
            return Vec::new();
        };

        (0..self.doc.length(&list))
            .filter_map(|index| self.object(&list, index, ObjType::Map))
            .filter_map(|entry| {
                Some(Claim {
                    hostname: self.hostname(&entry, "hostname")?,
                    document: self.document(&entry, "document")?,
                    note: self.text(&entry, "note"),
                })
            })
            .collect()
    }

    fn acceptances(
        self,
        root: &ObjId,
    ) -> onomancy_core::collections::Map<DnsName, Vec<Acceptance>> {
        let mut acceptances = onomancy_core::collections::Map::default();
        let Some(map) = self.object(root, "acceptances", ObjType::Map) else {
            return acceptances;
        };

        for key in self.doc.keys(&map) {
            let Ok(hostname) = DnsName::from_canonical(key.as_bytes()) else {
                continue;
            };

            // The per-hostname register: concurrent writes surface as
            // conflicting values here — ALL of them are read, and the
            // receipts rule (derivation stage 5) picks the winner.
            let Ok(conflicting) = self.doc.get_all(&map, key.as_str()) else {
                continue;
            };

            let entries: Vec<Acceptance> = conflicting
                .into_iter()
                .filter(|(value, _)| matches!(value, Value::Object(ObjType::Map)))
                .filter_map(|(_, entry)| {
                    let cited = self.hash_list(&entry, "cited")?;
                    if cited.is_empty() {
                        return None; // receipts are non-empty by contract
                    }

                    Some(Acceptance {
                        document: self.document(&entry, "document")?,
                        cited,
                    })
                })
                .collect();

            if !entries.is_empty() {
                acceptances.insert(hostname, entries);
            }
        }

        acceptances
    }

    fn resets(
        self,
        root: &ObjId,
    ) -> onomancy_core::collections::Map<DnsName, Set<Digest<Blake3, [u8]>>> {
        let mut resets = onomancy_core::collections::Map::default();
        let Some(map) = self.object(root, "resets", ObjType::Map) else {
            return resets;
        };

        for key in self.doc.keys(&map) {
            let Ok(hostname) = DnsName::from_canonical(key.as_bytes()) else {
                continue;
            };
            let Some(excluded) = self.hash_list(&map, key.as_str()) else {
                continue;
            };

            if !excluded.is_empty() {
                resets.insert(hostname, excluded);
            }
        }

        resets
    }

    /// Shape reader: `None` means "contributes nothing" — the
    /// derivation never guesses. Every reader below shares this
    /// contract.
    fn object<O: AsRef<ObjId>, P: Into<Prop>>(
        self,
        obj: O,
        prop: P,
        expected: ObjType,
    ) -> Option<ObjId> {
        let (value, id) = self.doc.get(obj, prop).ok()??;
        matches!(value, Value::Object(kind) if kind == expected).then_some(id)
    }

    fn text<O: AsRef<ObjId>>(self, obj: O, prop: &str) -> Option<String> {
        let (value, _) = self.doc.get(obj, prop).ok()??;
        let Value::Scalar(scalar) = value else {
            return None;
        };
        match scalar.as_ref() {
            ScalarValue::Str(text) => Some(text.to_string()),
            _ => None,
        }
    }

    fn hostname<O: AsRef<ObjId>>(self, obj: O, prop: &str) -> Option<DnsName> {
        // Canonical form only (A-labels, lowercase, no trailing dot):
        // the schema mandates it, and the reader never normalizes.
        DnsName::from_canonical(self.text(obj, prop)?.as_bytes()).ok()
    }

    fn document<O: AsRef<ObjId>>(self, obj: O, prop: &str) -> Option<DocAnchor> {
        let bytes = self.bytes32(obj, prop)?;
        // Strict key decoding applies to decisions documents too: a
        // non-canonical "document" contributes nothing.
        let key = key::decode(&bytes).ok()?;
        Some(DocAnchor::from(key))
    }

    fn bytes32<O: AsRef<ObjId>, P: Into<Prop>>(self, obj: O, prop: P) -> Option<[u8; 32]> {
        let (value, _) = self.doc.get(obj, prop).ok()??;
        let Value::Scalar(scalar) = value else {
            return None;
        };
        match scalar.as_ref() {
            ScalarValue::Bytes(bytes) => bytes.as_slice().try_into().ok(),
            _ => None,
        }
    }

    /// A list of 32-byte content hashes; a single malformed element
    /// voids the whole entry (the derivation never guesses).
    fn hash_list<O: AsRef<ObjId>>(self, obj: O, prop: &str) -> Option<Set<Digest<Blake3, [u8]>>> {
        let list = self.object(obj, prop, ObjType::List)?;
        let mut hashes = Set::default();

        for index in 0..self.doc.length(&list) {
            hashes.insert(Digest::from_bytes(self.bytes32(&list, index)?));
        }

        Some(hashes)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use automerge::{ObjId, transaction::Transactable};
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use testresult::TestResult;

    fn anchor(seed: u8) -> DocAnchor {
        DocAnchor::from(SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    fn anchor_bytes(seed: u8) -> Vec<u8> {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .as_bytes()
            .to_vec()
    }

    fn hostname(raw: &str) -> DnsName {
        DnsName::parse(raw).expect("valid hostname")
    }

    /// A decision document skeleton: the decisions map with `v` and empty
    /// `claims` / `acceptances` / `resets` containers.
    fn skeleton(version: i64) -> TestResult<Automerge> {
        let mut doc = Automerge::new();
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            let root = tx.put_object(automerge::ROOT, DECISIONS_KEY, ObjType::Map)?;
            tx.put(&root, "v", version)?;
            tx.put_object(&root, "claims", ObjType::List)?;
            tx.put_object(&root, "acceptances", ObjType::Map)?;
            tx.put_object(&root, "resets", ObjType::Map)?;
            Ok(())
        })
        .map_err(|failure| failure.error)?;
        Ok(doc)
    }

    fn schema_object(doc: &Automerge, prop: &str) -> ObjId {
        let (_, root) = doc
            .get(automerge::ROOT, DECISIONS_KEY)
            .expect("read")
            .expect("reserved map");
        let (_, id) = doc.get(&root, prop).expect("read").expect("container");
        id
    }

    fn push_claim(
        doc: &mut Automerge,
        host: &str,
        document: &[u8],
        note: Option<&str>,
    ) -> TestResult {
        let claims = schema_object(doc, "claims");
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            let index = tx.length(&claims);
            let entry = tx.insert_object(&claims, index, ObjType::Map)?;
            tx.put(&entry, "hostname", host)?;
            tx.put(&entry, "document", document.to_vec())?;
            if let Some(note) = note {
                tx.put(&entry, "note", note)?;
            }
            Ok(())
        })
        .map_err(|failure| failure.error)?;
        Ok(())
    }

    fn put_acceptance(
        doc: &mut Automerge,
        host: &str,
        document: &[u8],
        cited: &[[u8; 32]],
    ) -> TestResult {
        let acceptances = schema_object(doc, "acceptances");
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            let entry = tx.put_object(&acceptances, host, ObjType::Map)?;
            tx.put(&entry, "document", document.to_vec())?;
            let list = tx.put_object(&entry, "cited", ObjType::List)?;
            for (index, hash) in cited.iter().enumerate() {
                tx.insert(&list, index, hash.to_vec())?;
            }
            Ok(())
        })
        .map_err(|failure| failure.error)?;
        Ok(())
    }

    #[test]
    fn a_conforming_document_reads_in_full() -> TestResult {
        let mut doc = skeleton(0)?;
        push_claim(&mut doc, "bob.example", &anchor_bytes(1), Some("QR scan"))?;
        push_claim(&mut doc, "carol.example", &anchor_bytes(2), None)?;
        put_acceptance(&mut doc, "bob.example", &anchor_bytes(1), &[[7; 32]])?;

        let resets = schema_object(&doc, "resets");
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            let list = tx.put_object(&resets, "mallory.example", ObjType::List)?;
            tx.insert(&list, 0, vec![9u8; 32])?;
            Ok(())
        })
        .map_err(|failure| failure.error)?;

        let decisions = DecisionsView::new(&doc).decisions();

        assert_eq!(decisions.claims.len(), 2);
        assert_eq!(decisions.claims[0].hostname, hostname("bob.example"));
        assert_eq!(decisions.claims[0].document, anchor(1));
        assert_eq!(decisions.claims[0].note.as_deref(), Some("QR scan"));
        assert_eq!(decisions.claims[1].note, None);

        let accepted = decisions
            .acceptances
            .get(&hostname("bob.example"))
            .expect("acceptance entry");
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].document, anchor(1));
        assert!(accepted[0].cited.contains(&Digest::from_bytes([7; 32])));

        let excluded = decisions
            .resets
            .get(&hostname("mallory.example"))
            .expect("reset entry");
        assert!(excluded.contains(&Digest::from_bytes([9; 32])));
        Ok(())
    }

    #[test]
    fn unknown_versions_read_nothing() -> TestResult {
        let mut doc = skeleton(1)?;
        push_claim(&mut doc, "bob.example", &anchor_bytes(1), None)?;

        assert_eq!(DecisionsView::new(&doc).decisions(), Decisions::default());
        Ok(())
    }

    #[test]
    fn documents_without_the_schema_read_empty() {
        let doc = Automerge::new();
        assert_eq!(DecisionsView::new(&doc).decisions(), Decisions::default());
    }

    /// Every spelling of `v` beyond the canonical `Int(0)`:
    /// `Uint(0)` is accepted (a JS writer plausibly produces it);
    /// negative, non-scalar, and missing `v` all read nothing. Each
    /// document plants a well-formed claim so acceptance is provable
    /// and rejection is non-vacuous.
    #[test]
    fn version_shapes_gate_the_whole_read() -> TestResult {
        let claim = |doc: &mut Automerge| push_claim(doc, "bob.example", &anchor_bytes(1), None);

        // Uint(0): accepted.
        let mut doc = skeleton(0)?;
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            let (_, root) = tx.get(automerge::ROOT, DECISIONS_KEY)?.expect("reserved");
            tx.put(&root, "v", ScalarValue::Uint(0))?;
            Ok(())
        })
        .map_err(|failure| failure.error)?;
        claim(&mut doc)?;
        assert_eq!(
            DecisionsView::new(&doc).decisions().claims.len(),
            1,
            "Uint(0) is version 0"
        );

        // Negative Int: refused (u64::try_from fails).
        let mut doc = skeleton(-1)?;
        claim(&mut doc)?;
        assert_eq!(DecisionsView::new(&doc).decisions(), Decisions::default());

        // Non-scalar v: refused.
        let mut doc = skeleton(0)?;
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            let (_, root) = tx.get(automerge::ROOT, DECISIONS_KEY)?.expect("reserved");
            tx.put_object(&root, "v", ObjType::Map)?;
            Ok(())
        })
        .map_err(|failure| failure.error)?;
        claim(&mut doc)?;
        assert_eq!(DecisionsView::new(&doc).decisions(), Decisions::default());

        // Missing v: refused.
        let mut doc = skeleton(0)?;
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            let (_, root) = tx.get(automerge::ROOT, DECISIONS_KEY)?.expect("reserved");
            tx.delete(&root, "v")?;
            Ok(())
        })
        .map_err(|failure| failure.error)?;
        claim(&mut doc)?;
        assert_eq!(DecisionsView::new(&doc).decisions(), Decisions::default());
        Ok(())
    }

    /// A single malformed element voids the WHOLE reset entry — the
    /// derivation never guesses which hashes the user meant. Same for
    /// a reset filed under a non-canonical hostname.
    #[test]
    fn a_malformed_reset_element_voids_the_whole_entry() -> TestResult {
        let mut doc = skeleton(0)?;
        let resets = schema_object(&doc, "resets");
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            // One good hash + one 3-byte element: the entry is void.
            let list = tx.put_object(&resets, "mallory.example", ObjType::List)?;
            tx.insert(&list, 0, vec![9u8; 32])?;
            tx.insert(&list, 1, vec![1u8, 2, 3])?;
            // A well-formed list under a NON-canonical hostname key:
            // the reader never normalizes.
            let list = tx.put_object(&resets, "Eve.Example", ObjType::List)?;
            tx.insert(&list, 0, vec![8u8; 32])?;
            // And one good entry, so the read provably ran.
            let list = tx.put_object(&resets, "good.example", ObjType::List)?;
            tx.insert(&list, 0, vec![7u8; 32])?;
            Ok(())
        })
        .map_err(|failure| failure.error)?;

        let decisions = DecisionsView::new(&doc).decisions();
        assert_eq!(decisions.resets.len(), 1, "only the well-formed entry");
        assert!(
            decisions
                .resets
                .get(&hostname("good.example"))
                .expect("good entry")
                .contains(&Digest::from_bytes([7; 32]))
        );
        Ok(())
    }

    #[test]
    fn malformed_entries_contribute_nothing() -> TestResult {
        let mut doc = skeleton(0)?;

        // Non-canonical hostname: the reader never normalizes.
        push_claim(&mut doc, "Bob.Example", &anchor_bytes(1), None)?;
        // A 32-byte document that is not a curve point (roughly half
        // of all byte strings decompress, so find one that does not).
        let non_point = (0u8..=255)
            .map(|byte| [byte; 32])
            .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
            .expect("some repeated byte fails decompression");
        push_claim(&mut doc, "eve.example", &non_point, None)?;
        // Wrong byte width.
        push_claim(&mut doc, "short.example", &[1, 2, 3], None)?;
        // Empty receipts: acceptances cite non-emptily by contract.
        put_acceptance(&mut doc, "bob.example", &anchor_bytes(1), &[])?;
        // An acceptance VALUE that is not a map.
        let acceptances = schema_object(&doc, "acceptances");
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            tx.put(&acceptances, "carol.example", "not a map")?;
            Ok(())
        })
        .map_err(|failure| failure.error)?;
        // One good claim so the read provably ran — with a NON-STRING
        // note, which reads as no note rather than voiding the claim.
        push_claim(&mut doc, "bob.example", &anchor_bytes(1), None)?;
        let claims = schema_object(&doc, "claims");
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            let (_, entry) = tx
                .get(&claims, tx.length(&claims) - 1)?
                .expect("just pushed");
            tx.put(&entry, "note", 7)?;
            Ok(())
        })
        .map_err(|failure| failure.error)?;

        let decisions = DecisionsView::new(&doc).decisions();
        assert_eq!(decisions.claims.len(), 1, "only the well-formed claim");
        assert_eq!(
            decisions.claims[0].note, None,
            "a non-string note reads as no note"
        );
        assert!(decisions.acceptances.is_empty(), "empty receipts are inert");
        Ok(())
    }

    #[test]
    fn concurrent_acceptances_surface_as_conflicting_entries() -> TestResult {
        // Two devices accept different documents concurrently: the
        // register holds BOTH values, and the derivation's receipts
        // rule (stage 5) — not this reader — picks the winner.
        let mut left = skeleton(0)?;
        let mut right = left.fork();

        put_acceptance(&mut left, "bob.example", &anchor_bytes(1), &[[1; 32]])?;
        put_acceptance(&mut right, "bob.example", &anchor_bytes(2), &[[2; 32]])?;
        left.merge(&mut right)?;

        let decisions = DecisionsView::new(&left).decisions();
        let entries = decisions
            .acceptances
            .get(&hostname("bob.example"))
            .expect("register present");

        assert_eq!(entries.len(), 2, "both sides of the MV conflict");
        let documents: Vec<DocAnchor> = entries.iter().map(|entry| entry.document).collect();
        assert!(documents.contains(&anchor(1)));
        assert!(documents.contains(&anchor(2)));
        Ok(())
    }

    mod props {
        use super::*;

        /// Parse-don't-validate soundness of the reader, fuzzed: for
        /// ANY shapes written into the schema, the read never panics,
        /// and everything it returns already passed its gates —
        /// canonical hostnames, curve-point documents, non-empty
        /// receipts and resets.
        #[test]
        fn reads_are_total_and_everything_returned_passed_the_gates() {
            bolero::check!()
                .with_type::<Vec<(String, Vec<u8>, u8)>>()
                .for_each(|claim_shapes| {
                    let mut doc = skeleton(0).expect("skeleton");

                    for (host, document, note_shape) in claim_shapes {
                        let note = match note_shape % 3 {
                            0 => None,
                            1 => Some("note"),
                            _ => Some(host.as_str()), // arbitrary text
                        };
                        push_claim(&mut doc, host, document, note).expect("write");
                        // Reuse the raw host string as an acceptance
                        // key and a reset key too.
                        put_acceptance(&mut doc, host, document, &[[7; 32]]).expect("write");
                        let resets = schema_object(&doc, "resets");
                        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
                            let list = tx.put_object(&resets, host.as_str(), ObjType::List)?;
                            tx.insert(&list, 0, document.clone())?;
                            Ok(())
                        })
                        .expect("write");
                    }

                    // Total: never panics, whatever was written.
                    let decisions = DecisionsView::new(&doc).decisions();

                    for claim in &decisions.claims {
                        assert_eq!(
                            DnsName::from_canonical(claim.hostname.as_str().as_bytes()).ok(),
                            Some(claim.hostname.clone()),
                            "returned hostnames are canonical"
                        );
                    }
                    for entries in decisions.acceptances.values() {
                        assert!(entries.iter().all(|entry| !entry.cited.is_empty()));
                    }
                    for excluded in decisions.resets.values() {
                        assert!(!excluded.is_empty());
                    }
                });
        }
    }
}
