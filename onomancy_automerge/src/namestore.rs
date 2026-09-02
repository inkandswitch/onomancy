//! The namestore seam over Automerge documents.
//!
//! A namestore is a flat map at the document's reserved location:
//! path keys (`foo/bar`) mapping to bare Automerge-URL references
//! (path-resolution spec, Namestore Layout / References). This module
//! reads it; the resolution walk (`onomancy_protocol::resolve`) does
//! the greedy longest-key matching above this seam.

use automerge::{Automerge, ReadDoc, ScalarValue, Value};
use onomancy_core::{
    anchor::doc::{self, DocAnchor},
    name::segment::Segment,
};
use onomancy_protocol::resolve::namestore::{Authority, Namestore, Replicas, Vouched};

/// The reserved top-level key Onomancy data lives under, in every
/// document role: the flat namestore map in namestore documents
/// (path-resolution spec, Namestore Layout), the decisions schema in
/// decision documents (binding-cache spec, Schema).
///
/// Protocol entries are keys **at the document root**, alongside
/// names and application data, namespaced by this prefix. There is no
/// container map: the namestore IS the root map, flat, and a name
/// `foo` is `root["foo"]`. Nesting the store under a container key
/// would make this prefix namespace against nothing, and the whole
/// point of it is that the map is shared.
///
/// Nothing needs a registry of these keys. A protocol entry holds a
/// value that is not a namestore reference, so it is absent from
/// matching by shape (path-resolution spec, Error Conditions) rather
/// than by a resolver knowing the
/// name — the same rule that keeps application data out of the way.
pub const RESERVED_PREFIX: &str = ".well-known/onomancy/";

/// A namestore read from one held Automerge document.
///
/// Non-conforming stored keys (empty, `.`, or `..` segments; `#`;
/// leading or trailing `/`) are absent from *lookup* by construction:
/// lookups are exact joins of already-valid [`Segment`]s, which no
/// malformed key can equal. [`Self::edges`] must exclude them
/// explicitly, since enumeration has no such protection. Values that
/// are not bare `automerge:`
/// references are absent too — a name where a reference belongs is
/// the symlink ban, and anything else is simply not an edge. That
/// non-reference values are absent from matching is what lets
/// non-name data share the reserved map: see
/// [`certificates`](crate::certificates), whose entries sit under
/// `.well-known/` and hold lists rather than references.
#[derive(Debug, Clone)]
pub struct DocumentNamestore {
    doc: Automerge,
}

impl DocumentNamestore {
    /// Wrap a held document. Reads answer from the document's state
    /// as given — pinning to heads is the caller's business (fork the
    /// document at those heads first).
    #[must_use]
    pub const fn new(doc: Automerge) -> Self {
        Self { doc }
    }

    /// The wrapped document.
    #[must_use]
    pub const fn document(&self) -> &Automerge {
        &self.doc
    }
}

impl DocumentNamestore {
    /// Every well-formed edge: `(path key, target)` pairs, in the
    /// document's deterministic key order. Malformed keys and
    /// non-reference values are skipped, matching
    /// [`Namestore::reference`]'s view — which is how protocol
    /// entries and ordinary application data coexist here without a
    /// registry of reserved names: a value that is not a reference is
    /// absent from matching (path-resolution spec, Error Conditions).
    #[must_use]
    pub fn edges(&self) -> Vec<(String, DocAnchor)> {
        self.read().edges
    }

    /// Every edge, plus everything skipped and why.
    ///
    /// The spec's error conditions are two clauses each: a MUST that
    /// says to ignore something, and a SHOULD that says to surface it
    /// anyway. [`Self::edges`] satisfies the first. This satisfies
    /// the second, and exists because "ignored" and "absent" look
    /// identical to a caller that can only see the edge list — a
    /// mistyped key and a key that was never written are the same
    /// silence, and only one of them is worth telling a user about.
    #[must_use]
    pub fn read(&self) -> NamestoreRead {
        let mut read = NamestoreRead::default();

        for key in self.doc.keys(automerge::ROOT) {
            // `reference` can only be asked about already-valid
            // segments, so a malformed key is unreachable through it.
            // Enumeration has no such protection and must exclude
            // them explicitly (E6).
            if !is_path_key(&key) {
                read.malformed_keys.push(key);
                continue;
            }

            // All values, not just the winner: a merge can leave
            // several, and the losers are worth surfacing even though
            // the winner is the one that resolves (E7).
            //
            // Infallible for ROOT (`get_all` errors only on an
            // invalid object id), so the `else` is unreachable rather
            // than a swallowed report.
            let Ok(conflicting) = self.doc.get_all(automerge::ROOT, key.as_str()) else {
                continue;
            };

            let mut targets = conflicting
                .into_iter()
                .map(|(value, _)| parse_bare_reference(&value));

            // The winner is the LAST element: `get` — what `reference`
            // and every other resolver-side read uses — takes
            // `.next_back()` of the same ops list `get_all` returns
            // (automerge 0.11, `get_for`). Taking the first here made
            // `edges` report a conflict's loser as the edge while
            // `reference` resolved its winner — the exact divergence
            // this struct's parity claim forbids.
            let Some(winner) = targets.next_back() else {
                continue;
            };

            for loser in targets.flatten() {
                read.conflicts.push((key.clone(), loser));
            }

            match winner {
                Some(target) => read.edges.push((key, target)),
                // A well-formed key whose value is not a reference:
                // absent from matching by shape, which is what lets
                // protocol entries share this map (E8).
                None => read.non_references.push(key),
            }
        }

        read
    }
}

/// One pass over a namestore: what resolves, and what was skipped.
///
/// Each non-edge list is a SHOULD in the spec's error table. Nothing
/// here changes what resolves — [`DocumentNamestore::edges`] and
/// [`Namestore::reference`] see exactly the `edges` field — it only
/// makes the skipping visible.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NamestoreRead {
    /// Well-formed keys with reference values: the resolvable edges.
    pub edges: Vec<(String, DocAnchor)>,

    /// Keys no name could match: empty, `.`/`..` segments, `#`,
    /// leading or trailing `/` (E6).
    pub malformed_keys: Vec<String>,

    /// Well-formed keys whose value is not a bare reference (E8).
    /// Protocol entries land here by design, so this is not on its
    /// own an error — it is the list a caller filters to find one.
    pub non_references: Vec<String>,

    /// Losing values from a merge conflict, per key (E7). The winner
    /// is in `edges`; these are what it won against.
    pub conflicts: Vec<(String, DocAnchor)>,
}

impl Namestore for DocumentNamestore {
    fn reference(&self, path: &[Segment]) -> Option<DocAnchor> {
        let (value, _) = self.doc.get(automerge::ROOT, path_key(path)?).ok()??;
        parse_bare_reference(&value)
    }
}

/// Whether a stored key is a well-formed path: one or more valid
/// segments joined by `/`.
///
/// The inverse of [`path_key`], and the check enumeration needs.
/// Rejects the empty key, empty segments (`a//b`), leading and
/// trailing `/`, and any segment [`Segment::parse`] refuses — `.`,
/// `..`, and `#` among them (Namestore Layout, E6).
fn is_path_key(key: &str) -> bool {
    !key.is_empty() && key.split('/').all(|raw| Segment::parse(raw).is_ok())
}

/// The flat-map key for a segment path: segments joined by `/` — the
/// only spelling of that path (Namestore Layout).
///
/// `None` for an empty path. Keys MUST be one or more segments
/// (Namestore Layout), so there is no key for "no segments": writing
/// one would put an empty key in the map, and looking one up would
/// ask whether the empty key is bound. Returning an `Option` makes
/// both callers say what they mean instead of silently using `""`.
pub(crate) fn path_key(path: &[Segment]) -> Option<String> {
    if path.is_empty() {
        return None;
    }

    let mut joined = String::new();
    for (index, segment) in path.iter().enumerate() {
        if index > 0 {
            joined.push('/');
        }
        joined.push_str(segment.as_str());
    }

    Some(joined)
}

/// A bare reference and nothing else: the `automerge:` scheme plus a
/// bs58check document ID. `DocAnchor::parse` rejects anything
/// carrying segments or heads (`/`, `#` are outside the bs58
/// alphabet), non-key IDs, and checksum failures.
///
/// A **scalar** string, never a `Text` object. A reference is an
/// immutable value; a `Text` is a collaborative document, and two
/// writers editing one concurrently could merge into a target neither
/// wrote — a redirect no signature covers.
///
/// Worth knowing when reading documents a JavaScript client wrote:
/// `doc[name] = "automerge:…"` stores a `Text` there, and reads back
/// as a string, so such a namestore resolves nowhere while looking
/// correct to the application that wrote it. The scalar spelling in
/// that binding is `RawString`. Such entries are reported by
/// [`DocumentNamestore::read`] under `non_references`, which is the
/// only signal the writer gets.
pub(crate) fn parse_bare_reference(value: &Value<'_>) -> Option<DocAnchor> {
    let Value::Scalar(scalar) = value else {
        return None;
    };
    let ScalarValue::Str(text) = scalar.as_ref() else {
        return None;
    };

    DocAnchor::parse(text.strip_prefix(doc::SCHEME_PREFIX)?).ok()
}

/// Locally-held documents, keyed by their self-certifying anchor —
/// the [`Replicas`] seam. `None` from [`Replicas::replica`] means
/// "not replicated here": the walk reports `UnsyncedTarget`, the
/// designed outcome under partition. Nothing here fetches.
///
/// Every held document carries the [`Authority`] grade it was vouched
/// at; the walk folds the weakest grade crossed into its outcome.
#[derive(Debug, Default)]
pub struct HeldDocuments {
    docs: onomancy_core::collections::Map<DocAnchor, (Automerge, Authority)>,
}

impl HeldDocuments {
    /// Add (or replace) the held replica for `anchor` at the
    /// dev-bridge grade ([`Authority::TrustedSubstrate`]),
    /// builder-style.
    #[must_use]
    pub fn with(self, anchor: DocAnchor, doc: Automerge) -> Self {
        self.with_vouched(anchor, doc, Authority::TrustedSubstrate)
    }

    /// Add (or replace) the held replica for `anchor` at an explicit
    /// grade, builder-style. The grade is the CALLER's claim — verify
    /// the carriage before claiming [`Authority::CarriageVerified`].
    #[must_use]
    pub fn with_vouched(mut self, anchor: DocAnchor, doc: Automerge, authority: Authority) -> Self {
        self.docs.insert(anchor, (doc, authority));
        self
    }

    /// The held document for `anchor`, if replicated here.
    ///
    /// Reads that are not the namestore walk — certificates at the
    /// reserved well-known path, say — go through this rather than
    /// [`Replicas::replica`], which wraps the document as a namestore
    /// and grades it.
    #[must_use]
    pub fn document(&self, anchor: &DocAnchor) -> Option<&Automerge> {
        self.docs.get(anchor).map(|(doc, _)| doc)
    }
}

impl Replicas for HeldDocuments {
    type Namestore = DocumentNamestore;

    fn replica(&self, target: &DocAnchor) -> Option<Vouched<Self::Namestore>> {
        self.docs
            .get(target)
            .map(|(doc, authority)| Vouched::new(DocumentNamestore::new(doc.clone()), *authority))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use automerge::transaction::Transactable;
    use ed25519_dalek::SigningKey;
    use testresult::TestResult;

    fn anchor(seed: u8) -> DocAnchor {
        DocAnchor::from(SigningKey::from_bytes(&[seed; 32]).verifying_key())
    }

    fn segments(path: &[&str]) -> Vec<Segment> {
        path.iter()
            .map(|raw| Segment::parse(raw).expect("valid segment"))
            .collect()
    }

    /// A namestore document with the given key → value entries.
    fn namestore_doc(entries: &[(&str, &str)]) -> TestResult<Automerge> {
        let mut doc = Automerge::new();
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            for (key, value) in entries {
                tx.put(automerge::ROOT, *key, *value)?;
            }
            Ok(())
        })
        .map_err(|failure| failure.error)?;
        Ok(doc)
    }

    #[test]
    fn exact_keys_resolve_to_their_anchors() -> TestResult {
        let target = anchor(1);
        let url = format!("automerge:{target}");
        let store = DocumentNamestore::new(namestore_doc(&[
            ("bob", url.as_str()),
            ("foo/bar/baz", url.as_str()),
        ])?);

        assert_eq!(store.reference(&segments(&["bob"])), Some(target));
        assert_eq!(
            store.reference(&segments(&["foo", "bar", "baz"])),
            Some(target),
            "multi-segment keys match at segment boundaries"
        );
        assert_eq!(
            store.reference(&segments(&["foo", "bar"])),
            None,
            "prefixes of a longer key are not entries; longest-match \
             selection is the walk's job, not the store's"
        );
        Ok(())
    }

    #[test]
    fn non_reference_values_are_absent() -> TestResult {
        let target = anchor(1);
        let store = DocumentNamestore::new(namestore_doc(&[
            // A name where a reference belongs: the symlink ban.
            ("sym", "@bob.example/pics"),
            // Missing scheme.
            ("bare", &target.to_string()),
            // Scheme with trailing junk: not a BARE reference.
            ("heads", &format!("automerge:{target}#abc")),
            ("path", &format!("automerge:{target}/photos")),
            ("garbage", "automerge:not-bs58-!!!"),
        ])?);

        for label in ["sym", "bare", "heads", "path", "garbage"] {
            assert_eq!(
                store.reference(&segments(&[label])),
                None,
                "{label} must be treated as absent"
            );
        }
        Ok(())
    }

    /// The prefix constant and the keys that use it must agree.
    ///
    /// They are separate string literals in separate modules, so a
    /// rename desynchronizes them silently. This is the only thing
    /// tying them together.
    #[test]
    fn reserved_keys_use_the_reserved_prefix() {
        assert!(crate::certificates::CERTIFICATES_KEY.starts_with(RESERVED_PREFIX));
        assert!(crate::decisions::DECISIONS_KEY.starts_with(RESERVED_PREFIX));
    }
    #[test]
    fn an_empty_document_has_no_names() {
        let store = DocumentNamestore::new(Automerge::new());
        assert_eq!(store.reference(&segments(&["anything"])), None);
    }

    /// The SHOULD half of E6/E7/E8: skipped entries are reported,
    /// not merely skipped.
    ///
    /// Without this a caller cannot distinguish "you mistyped the
    /// key" from "nothing is bound there" — both are silence — and
    /// only one of them is worth telling a user about.
    #[test]
    fn a_read_surfaces_what_it_skipped() -> TestResult {
        let reference = format!("automerge:{}", anchor(1));
        let read = DocumentNamestore::new(namestore_doc(&[
            ("ok", reference.as_str()),
            ("has#hash", reference.as_str()),
            (".well-known/onomancy/certificates", "not-a-reference"),
        ])?)
        .read();

        assert_eq!(
            read.edges.into_iter().map(|(k, _)| k).collect::<Vec<_>>(),
            vec!["ok"]
        );
        assert_eq!(read.malformed_keys, vec!["has#hash"], "E6 surfaced");
        assert_eq!(
            read.non_references,
            vec![".well-known/onomancy/certificates"],
            "E8 surfaced"
        );
        Ok(())
    }

    /// A path with no segments has no key, so neither reading nor
    /// writing may invent one. `""` would be a key no name can match:
    /// a write that appears to succeed and can never be read back.
    #[test]
    fn an_empty_path_has_no_key() {
        assert_eq!(path_key(&[]), None);
        assert_eq!(
            DocumentNamestore::new(Automerge::new()).reference(&[]),
            None
        );
    }
    #[test]
    fn held_documents_answer_only_what_they_hold() -> TestResult {
        let target = anchor(1);
        let held = HeldDocuments::default().with(target, namestore_doc(&[])?);

        assert!(held.replica(&target).is_some());
        assert!(
            held.replica(&anchor(2)).is_none(),
            "not replicated here — never fetched"
        );
        Ok(())
    }

    /// `edges` must see exactly what `reference` sees.
    ///
    /// `reference` is only ever asked about already-valid segments,
    /// so a malformed key is unreachable through it. Enumeration has
    /// no such protection, and without an explicit filter every one
    /// of these came back as an edge — shown to a caller as a name
    /// that no lookup could ever match (spec E6).
    #[test]
    fn enumeration_excludes_keys_no_name_could_match() -> TestResult {
        let target = format!("automerge:{}", anchor(1));
        let entries: Vec<(&str, &str)> =
            ["", ".", "..", "/lead", "a//b", "has#hash", "trail/", "ok"]
                .iter()
                .map(|key| (*key, target.as_str()))
                .collect();

        let store = DocumentNamestore::new(namestore_doc(&entries)?);
        let found: Vec<String> = store.edges().into_iter().map(|(key, _)| key).collect();

        assert_eq!(found, vec!["ok"], "only well-formed keys are edges");
        Ok(())
    }

    /// The other half of that parity: a well-formed key whose value
    /// is not a reference is not an edge either — which is what lets
    /// protocol entries sit beside names in one map.
    #[test]
    fn enumeration_excludes_non_reference_values() -> TestResult {
        let reference = format!("automerge:{}", anchor(1));
        let store = DocumentNamestore::new(namestore_doc(&[
            (".well-known/onomancy/certificates", "not-a-reference"),
            ("ok", reference.as_str()),
        ])?);

        let found: Vec<String> = store.edges().into_iter().map(|(key, _)| key).collect();

        assert_eq!(found, vec!["ok"]);
        Ok(())
    }

    /// Under a merge conflict, `edges` and `reference` must name the
    /// SAME winner, and the loser must be surfaced (E7).
    ///
    /// The winner is `get`'s answer — the last element of the ops
    /// list — because `reference` uses `get` and the parity between
    /// the two views is this module's contract. An earlier version
    /// took the first element, so under any real conflict `edges`
    /// showed one target while resolution followed another: the walk
    /// and the UI silently disagreed about where a name points.
    #[test]
    fn conflict_winner_matches_resolution_and_loser_is_surfaced() -> TestResult {
        let ours = anchor(1);
        let theirs = anchor(2);

        // A genuine concurrent write: fork, write both sides, merge.
        let mut left = namestore_doc(&[])?;
        let mut right = left.fork();
        left.transact::<_, _, automerge::AutomergeError>(|tx| {
            tx.put(automerge::ROOT, "bob", format!("automerge:{ours}"))?;
            Ok(())
        })
        .map_err(|failure| failure.error)?;
        right
            .transact::<_, _, automerge::AutomergeError>(|tx| {
                tx.put(automerge::ROOT, "bob", format!("automerge:{theirs}"))?;
                Ok(())
            })
            .map_err(|failure| failure.error)?;
        left.merge(&mut right)?;

        let store = DocumentNamestore::new(left);
        let resolved = store
            .reference(&segments(&["bob"]))
            .expect("a conflicted key still resolves");
        let read = store.read();

        assert_eq!(
            read.edges,
            vec![(String::from("bob"), resolved)],
            "enumeration must report the same winner resolution follows"
        );

        // Exactly one loser, and it is the other write.
        let loser = if resolved == ours { theirs } else { ours };
        assert_eq!(
            read.conflicts,
            vec![(String::from("bob"), loser)],
            "the losing value is surfaced, not silently dropped (E7)"
        );
        Ok(())
    }

    /// Concurrent in-place edits of a `Text` merge into a THIRD value
    /// neither writer wrote — the reason a reader must never accept
    /// mutable text as a reference, however lenient it wants to be.
    ///
    /// Established empirically: left splices one range, right splices
    /// another, and the merge contains both, spelling an identifier
    /// that was never written by anyone. A reader that accepted
    /// `Text` would follow it — a redirect no signature covers.
    /// Whole-VALUE assignment does not have this problem (map keys
    /// are last-writer-wins, always one of the two); in-place editing
    /// is the dangerous pattern.
    ///
    /// This reader rejects `Text` categorically, so the merged value
    /// is surfaced as a non-reference and never an edge — asserted
    /// here so leniency cannot creep in later.
    #[test]
    fn a_merged_text_is_a_third_value_and_still_not_an_edge() -> TestResult {
        let base = format!("automerge:{}", anchor(1));

        let mut left = Automerge::new();
        let text_id = left
            .transact::<_, _, automerge::AutomergeError>(|tx| {
                let id = tx.put_object(automerge::ROOT, "bob", automerge::ObjType::Text)?;
                tx.splice_text(&id, 0, 0, &base)?;
                Ok(id)
            })
            .map_err(|failure| failure.error)?
            .result;
        let mut right = left.fork();

        left.transact::<_, _, automerge::AutomergeError>(|tx| {
            tx.splice_text(&text_id, 10, 5, "LLLLL")?;
            Ok(())
        })
        .map_err(|failure| failure.error)?;
        right
            .transact::<_, _, automerge::AutomergeError>(|tx| {
                tx.splice_text(&text_id, 30, 5, "RRRRR")?;
                Ok(())
            })
            .map_err(|failure| failure.error)?;

        let left_view = left.text(&text_id)?;
        let right_view = right.text(&text_id)?;
        left.merge(&mut right)?;
        let merged = left.text(&text_id)?;

        // The CRDT property that makes mutable references unsafe.
        assert_ne!(merged, left_view, "merge is not left's write");
        assert_ne!(merged, right_view, "merge is not right's write");
        assert_ne!(merged, base, "merge is not the base");

        // And this reader never follows it.
        let read = DocumentNamestore::new(left).read();
        assert!(read.edges.is_empty(), "a Text is never an edge");
        assert_eq!(read.non_references, vec!["bob"], "and it is surfaced");
        Ok(())
    }
    /// A `Text` object is not a scalar string, and so is not a
    /// reference.
    ///
    /// This is a live interop hazard rather than a hypothetical:
    /// Automerge's **JavaScript** binding stores a plain string in a
    /// map as a `Text` object, so a JS writer that assigns
    /// `doc[name] = "automerge:…"` produces an entry no conforming
    /// resolver can match, while its own reader sees a string and
    /// reports success. `RawString` is the JS spelling that produces
    /// a scalar.
    ///
    /// The value is surfaced rather than merely skipped, because
    /// silence here is indistinguishable from an unwritten name and
    /// the writer has no other signal.
    #[test]
    fn a_text_object_is_not_a_reference_and_says_so() -> TestResult {
        let mut doc = Automerge::new();
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            let text = tx.put_object(automerge::ROOT, "written-by-js", automerge::ObjType::Text)?;
            tx.splice_text(&text, 0, 0, &format!("automerge:{}", anchor(1)))?;
            Ok(())
        })
        .map_err(|failure| failure.error)?;

        let read = DocumentNamestore::new(doc).read();

        assert!(read.edges.is_empty(), "a Text object cannot be an edge");
        assert_eq!(
            read.non_references,
            vec!["written-by-js"],
            "and the writer is told which key it was"
        );
        Ok(())
    }
}
