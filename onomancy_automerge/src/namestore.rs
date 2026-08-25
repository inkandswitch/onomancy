//! The namestore seam over Automerge documents.
//!
//! A namestore is a flat map at the document's reserved location:
//! path keys (`foo/bar`) mapping to bare Automerge-URL references
//! (path-resolution spec, Namestore Layout / References). This module
//! reads it; the resolution walk (`onomancy_protocol::resolve`) does
//! the greedy longest-key matching above this seam.

use automerge::{Automerge, ObjType, ReadDoc, ScalarValue, Value};
use onomancy_core::{
    anchor::doc::{self, DocAnchor},
    name::segment::Segment,
};
use onomancy_protocol::resolve::namestore::{Authority, Namestore, Replicas, Vouched};

use crate::RESERVED_KEY;

/// A namestore read from one held Automerge document.
///
/// Non-conforming stored keys (empty, `.`, or `..` segments; `#`;
/// leading or trailing `/`) are absent by construction (spec E6):
/// lookups are exact joins of already-valid [`Segment`]s, which no
/// malformed key can equal. Values that are not bare `automerge:`
/// references are treated as absent (E5/References — a symlink or
/// composite value never resolves).
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
    /// The reserved flat map's object ID, when present and map-shaped.
    fn reserved_map(&self) -> Option<automerge::ObjId> {
        let (value, id) = self.doc.get(automerge::ROOT, RESERVED_KEY).ok()??;
        matches!(value, Value::Object(ObjType::Map)).then_some(id)
    }

    /// Every well-formed edge: `(path key, target)` pairs, in the
    /// map's deterministic key order. Malformed keys and non-bare
    /// values are skipped, matching [`Namestore::reference`]'s view.
    #[must_use]
    pub fn edges(&self) -> Vec<(String, DocAnchor)> {
        let Some(map) = self.reserved_map() else {
            return Vec::new();
        };

        self.doc
            .keys(&map)
            .filter_map(|key| {
                let (value, _) = self.doc.get(&map, key.as_str()).ok()??;
                let target = parse_bare_reference(&value)?;
                Some((key, target))
            })
            .collect()
    }
}

impl Namestore for DocumentNamestore {
    fn reference(&self, path: &[Segment]) -> Option<DocAnchor> {
        let (value, _) = self.doc.get(&self.reserved_map()?, path_key(path)).ok()??;
        parse_bare_reference(&value)
    }
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
fn parse_bare_reference(value: &Value<'_>) -> Option<DocAnchor> {
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
            let map = tx.put_object(automerge::ROOT, RESERVED_KEY, ObjType::Map)?;
            for (key, value) in entries {
                tx.put(&map, *key, *value)?;
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
            // A name where a reference belongs: the symlink ban (E5).
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

    #[test]
    fn documents_without_the_reserved_map_are_empty() {
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
}
