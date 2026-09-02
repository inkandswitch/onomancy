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
        self.doc
            .keys(automerge::ROOT)
            .filter_map(|key| {
                // Both halves, or this is not the view `reference`
                // has. That function can only be asked about
                // already-valid segments, so a malformed key is
                // unreachable through it; enumeration has to exclude
                // such keys explicitly, or it reports as an edge
                // something no name could ever match (spec E6).
                if !is_path_key(&key) {
                    return None;
                }

                let (value, _) = self.doc.get(automerge::ROOT, key.as_str()).ok()??;
                let target = parse_bare_reference(&value)?;

                Some((key, target))
            })
            .collect()
    }
}

impl Namestore for DocumentNamestore {
    fn reference(&self, path: &[Segment]) -> Option<DocAnchor> {
        let (value, _) = self.doc.get(automerge::ROOT, path_key(path)).ok()??;
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
pub(crate) fn path_key(path: &[Segment]) -> String {
    let mut joined = String::new();
    for (index, segment) in path.iter().enumerate() {
        if index > 0 {
            joined.push('/');
        }
        joined.push_str(segment.as_str());
    }
    joined
}

/// A bare reference and nothing else: the `automerge:` scheme plus a
/// bs58check document ID. `DocAnchor::parse` rejects anything
/// carrying segments or heads (`/`, `#` are outside the bs58
/// alphabet), non-key IDs, and checksum failures.
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
}
