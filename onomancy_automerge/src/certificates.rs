//! Certificates held in a document, at the reserved well-known path.
//!
//! A bound document carries the certificates that name it, so a
//! verifier that replicates the document has the binding evidence
//! too — no second retrieval mechanism, no bespoke server (dns-anchor
//! spec, In the Bound Document).
//!
//! ```text
//! doc = {
//!   "team":                              "automerge:…",   ← names
//!   "team/john":                         "automerge:…",
//!   ".well-known/onomancy/certificates": [ <onc>, … ],    ← or a reference
//! }
//! ```
//!
//! Top-level keys, flat: a namestore is the document's own map, not a
//! container inside it. The certificate list sits beside the names
//! because its value is a list rather than a reference, so path
//! resolution passes over it (path-resolution spec, E8) without any
//! resolver needing to know the key.
//!
//! The prefix is a **writers' convention**, not an enforced
//! reservation. A writer may bind a name at this key; the spec says
//! so plainly, and such a writer has broken their own document. This
//! module does not police it.
//!
//! This module reads and writes bytes. It decodes only far enough to
//! honour the writer's replacement rule; judging a certificate is
//! `onomancy_protocol`'s job, and the dispositions for a list holding
//! several — foreign entries ignored, undecodable entries rejected
//! without poisoning their siblings — belong with the verifier that
//! knows which hostname it is resolving.

use automerge::{Automerge, ObjType, ReadDoc, ScalarValue, Value, transaction::Transactable as _};
use onomancy_core::anchor::doc::DocAnchor;
use onomancy_dnssec::certificate::Certificate;

use crate::namestore::{HeldDocuments, parse_bare_reference};

/// Where a document's certificates live, inside the reserved map.
///
/// Unreachable by any name: `.well-known` and the rest are valid
/// segments, but the value stored here is a list rather than a
/// reference, so resolution treats the key as absent (E8).
pub const CERTIFICATES_KEY: &str = ".well-known/onomancy/certificates";

/// Every certificate held in `doc` itself, ignoring any reference.
///
/// Entries that are not byte values are skipped rather than failing
/// the read: one malformed entry never poisons its siblings.
///
/// # Errors
///
/// Returns [`MalformedLocation::NotAListOrReference`] when the key
/// holds something that is neither a list nor a reference.
pub fn inline(doc: &Automerge) -> Result<Vec<Vec<u8>>, MalformedLocation> {
    match locate(doc)? {
        Located::Inline(entries) => Ok(entries),
        // A reference is somebody else's list; this reads one
        // document, so both cases are "nothing here".
        Located::Absent | Located::Elsewhere(_) => Ok(Vec::new()),
    }
}

/// Every certificate for `anchor`, following at most one reference.
///
/// A document MAY delegate its certificates to another document —
/// commonly one whose write authority matches its issuing authority,
/// so that collaborators cannot suppress a binding they could not
/// have issued. That indirection is **one hop**: the target MUST hold
/// its list inline.
///
/// An empty result means the certificates are unavailable *from this
/// source* — the document is not held, the key is absent, or the
/// target of a reference is not held. It never means the name is
/// unbound: absence is not provable.
///
/// # Errors
///
/// Returns [`MalformedLocation`] when the key holds neither a list nor
/// a reference, or when a referenced document itself stores a
/// reference (a second hop).
pub fn certificates(
    held: &HeldDocuments,
    anchor: &DocAnchor,
) -> Result<Vec<Vec<u8>>, MalformedLocation> {
    let Some(doc) = held.document(anchor) else {
        return Ok(Vec::new());
    };

    let target = match locate(doc)? {
        Located::Absent => return Ok(Vec::new()),
        Located::Inline(entries) => return Ok(entries),
        Located::Elsewhere(target) => target,
    };

    let Some(referenced) = held.document(&target) else {
        return Ok(Vec::new());
    };

    match locate(referenced)? {
        Located::Absent => Ok(Vec::new()),
        Located::Inline(entries) => Ok(entries),
        // One hop, and one only: chasing further would make
        // termination a hop limit rather than a structural property,
        // which is the invariant the no-symlink rule protects.
        Located::Elsewhere(_) => Err(MalformedLocation::SecondHop(Box::new(target))),
    }
}

/// Store `certificate`, replacing any entry with an identical signed
/// region rather than appending one.
///
/// Re-attaching a fresher chain produces the *same certificate*
/// carrying different evidence, so appending would grow the list
/// without bound while adding nothing. Entries differing in their
/// signed region are distinct certificates — normally one per bound
/// hostname — and are left alone, as are entries that do not decode.
///
/// # Errors
///
/// Returns [`WriteError`] when the key holds a reference or a
/// non-list value (write to the referenced document instead), or when
/// the document rejects the transaction.
pub fn put(doc: &mut Automerge, certificate: &Certificate) -> Result<(), WriteError> {
    let replacing = match locate(doc)? {
        Located::Elsewhere(target) => {
            return Err(WriteError::StoredElsewhere(Box::new(target)));
        }
        Located::Absent => None,
        Located::Inline(entries) => entries.iter().position(|stored| {
            Certificate::decode(stored).is_ok_and(|stored| stored.same_certificate(certificate))
        }),
    };

    let encoded = certificate.encode();

    doc.transact::<_, _, automerge::AutomergeError>(|tx| {
        // A root key, beside names and application data. The list is
        // not a reference, so it takes no part in matching (spec E8)
        // and needs no resolver to know its name.
        let list = match tx.get(automerge::ROOT, CERTIFICATES_KEY)? {
            Some((Value::Object(ObjType::List), id)) => id,
            _ => tx.put_object(automerge::ROOT, CERTIFICATES_KEY, ObjType::List)?,
        };

        match replacing {
            Some(index) => tx.put(&list, index, ScalarValue::Bytes(encoded))?,
            None => tx.insert(&list, tx.length(&list), ScalarValue::Bytes(encoded))?,
        }

        Ok(())
    })
    .map_err(|failure| WriteError::Transaction(failure.error))?;

    Ok(())
}

/// What the reserved key holds.
enum Located {
    /// No reserved map, or no entry at the key.
    Absent,
    /// A list; byte entries in list order, others skipped.
    Inline(Vec<Vec<u8>>),
    /// A bare reference to the document that holds them.
    Elsewhere(DocAnchor),
}

/// Read the key without interpreting what it means to find nothing.
fn locate(doc: &Automerge) -> Result<Located, MalformedLocation> {
    let Ok(Some((value, id))) = doc.get(automerge::ROOT, CERTIFICATES_KEY) else {
        return Ok(Located::Absent);
    };

    if let Some(target) = parse_bare_reference(&value) {
        return Ok(Located::Elsewhere(target));
    }

    if !matches!(value, Value::Object(ObjType::List)) {
        return Err(MalformedLocation::NotAListOrReference);
    }

    // Anything that is not a byte string is not a certificate unit.
    // Skipping rather than failing is the RRset disposition: one
    // malformed entry never poisons its siblings.
    let entries = (0..doc.length(&id))
        .filter_map(|index| {
            let (value, _) = doc.get(&id, index).ok()??;
            match value {
                Value::Scalar(scalar) => match scalar.as_ref() {
                    ScalarValue::Bytes(bytes) => Some(bytes.clone()),
                    ScalarValue::Str(_)
                    | ScalarValue::Int(_)
                    | ScalarValue::Uint(_)
                    | ScalarValue::F64(_)
                    | ScalarValue::Counter(_)
                    | ScalarValue::Timestamp(_)
                    | ScalarValue::Boolean(_)
                    | ScalarValue::Unknown { .. }
                    | ScalarValue::Null => None,
                },
                Value::Object(_) => None,
            }
        })
        .collect();

    Ok(Located::Inline(entries))
}

/// The certificate location holds something the specification does
/// not permit there.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MalformedLocation {
    /// Neither a list of certificates nor a reference to a document
    /// holding one.
    #[error("certificate location holds neither a list nor a reference")]
    NotAListOrReference,

    /// A referenced document stores another reference. Indirection is
    /// one hop; the target must hold its list inline.
    ///
    /// Boxed: a [`DocAnchor`] caches its decompressed curve point, so
    /// carrying one inline would widen every `Err` of this type.
    #[error("certificate location chains through {0}: indirection is one hop")]
    SecondHop(Box<DocAnchor>),
}

/// Writing the certificate failed.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// The location already holds a reference: the certificate
    /// belongs in the referenced document, not this one.
    #[error("certificates for this document are stored in {0}")]
    StoredElsewhere(Box<DocAnchor>),

    /// The location holds a value that is neither list nor reference.
    #[error(transparent)]
    Malformed(#[from] MalformedLocation),

    /// Automerge refused the transaction.
    #[error(transparent)]
    Transaction(#[from] automerge::AutomergeError),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use automerge::transaction::Transactable as _;
    use ed25519_dalek::SigningKey;
    use onomancy_core::{
        anchor::doc::DocAnchor, delegation_chain::DelegationChain, time::UnixSeconds,
    };
    use onomancy_dnssec::{certificate::CertificateParams, chain::DnssecChain, dns_name::DnsName};
    use onomancy_protocol::resolve::namestore::Namestore as _;
    use testresult::TestResult;

    use super::*;
    use crate::namestore::{DocumentNamestore, path_key};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn anchor(seed: u8) -> DocAnchor {
        DocAnchor::from(key(seed).verifying_key())
    }

    /// A certificate for `hostname`, signed by `seed`'s key.
    fn certificate(seed: u8, hostname: &str) -> Certificate {
        Certificate::sign(
            CertificateParams {
                root_doc: anchor(seed),
                issued_at: UnixSeconds::from(1_700_000_000),
                hostname: DnsName::parse(hostname).expect("valid hostname"),
                heads: Vec::new(),
                predecessor: None,
                delegation_chain: DelegationChain::default(),
                lineage: Vec::new(),
                chain: DnssecChain::default(),
            },
            &key(seed),
        )
        .expect("within the unit cap")
    }

    /// A document whose certificate location holds `value`.
    fn document_with(
        value: impl FnOnce(&mut automerge::transaction::Transaction<'_>, &automerge::ObjId),
    ) -> Automerge {
        let mut doc = Automerge::new();
        doc.transact::<_, _, automerge::AutomergeError>(|tx| {
            value(tx, &automerge::ROOT);
            Ok(())
        })
        .expect("build");
        doc
    }

    #[test]
    fn a_written_certificate_reads_back_verbatim() -> TestResult {
        let cert = certificate(1, "example.com");
        let mut doc = Automerge::new();
        put(&mut doc, &cert)?;

        assert_eq!(inline(&doc)?, vec![cert.encode()]);
        Ok(())
    }

    #[test]
    fn refreshing_replaces_rather_than_appends() -> TestResult {
        // Re-attaching evidence yields the SAME certificate carrying
        // different bytes. Appending would grow the list forever.
        let cert = certificate(1, "example.com");
        // One framed link: count 1, length 3, three bytes. Framing is
        // all `with_attachments` touches — link contents are the
        // validator's business, not this module's.
        let refreshed = cert.with_attachments(
            DelegationChain::default(),
            Vec::new(),
            DnssecChain::read_framed(&[1, 3, 0xAA, 0xBB, 0xCC])?,
        )?;

        assert!(cert.same_certificate(&refreshed), "same signed region");
        assert_ne!(cert.encode(), refreshed.encode(), "different bytes");

        let mut doc = Automerge::new();
        put(&mut doc, &cert)?;
        put(&mut doc, &refreshed)?;

        assert_eq!(
            inline(&doc)?,
            vec![refreshed.encode()],
            "one entry, the fresher evidence"
        );
        Ok(())
    }

    #[test]
    fn distinct_certificates_are_both_retained() -> TestResult {
        // One document, two hostnames: the normal case.
        let one = certificate(1, "example.com");
        let two = certificate(1, "other.example");

        let mut doc = Automerge::new();
        put(&mut doc, &one)?;
        put(&mut doc, &two)?;

        assert_eq!(inline(&doc)?.len(), 2);
        Ok(())
    }

    #[test]
    fn a_malformed_entry_does_not_poison_its_siblings() -> TestResult {
        let cert = certificate(1, "example.com");
        let encoded = cert.encode();

        let doc = document_with(|tx, reserved| {
            let list = tx
                .put_object(reserved, CERTIFICATES_KEY, ObjType::List)
                .expect("list");
            tx.insert(&list, 0, ScalarValue::Str("not bytes".into()))
                .expect("insert");
            tx.insert(&list, 1, ScalarValue::Bytes(encoded.clone()))
                .expect("insert");
        });

        assert_eq!(inline(&doc)?, vec![encoded], "the sibling survives");
        Ok(())
    }

    #[test]
    fn one_hop_of_indirection_resolves() -> TestResult {
        let cert = certificate(1, "example.com");
        let holder = anchor(2);

        let root = document_with(|tx, reserved| {
            tx.put(reserved, CERTIFICATES_KEY, format!("automerge:{holder}"))
                .expect("reference");
        });
        let mut elsewhere = Automerge::new();
        put(&mut elsewhere, &cert)?;

        let held = HeldDocuments::default()
            .with(anchor(1), root)
            .with(holder, elsewhere);

        assert_eq!(certificates(&held, &anchor(1))?, vec![cert.encode()]);
        Ok(())
    }

    #[test]
    fn a_second_hop_is_refused() {
        // Indirection is one hop. Chasing further would make
        // termination a hop limit rather than a structural property.
        let first = anchor(2);
        let second = anchor(3);

        let root = document_with(|tx, reserved| {
            tx.put(reserved, CERTIFICATES_KEY, format!("automerge:{first}"))
                .expect("reference");
        });
        let middle = document_with(|tx, reserved| {
            tx.put(reserved, CERTIFICATES_KEY, format!("automerge:{second}"))
                .expect("reference");
        });

        let held = HeldDocuments::default()
            .with(anchor(1), root)
            .with(first, middle)
            .with(second, Automerge::new());

        assert_eq!(
            certificates(&held, &anchor(1)),
            Err(MalformedLocation::SecondHop(Box::new(first)))
        );
    }

    #[test]
    fn an_unheld_target_is_unavailable_not_an_error() -> TestResult {
        // Unavailable is the designed outcome under partition; it
        // never means the name is unbound.
        let root = document_with(|tx, reserved| {
            tx.put(
                reserved,
                CERTIFICATES_KEY,
                format!("automerge:{}", anchor(2)),
            )
            .expect("reference");
        });
        let held = HeldDocuments::default().with(anchor(1), root);

        assert!(certificates(&held, &anchor(1))?.is_empty());
        assert!(
            certificates(&held, &anchor(9))?.is_empty(),
            "nor is an unheld root"
        );
        Ok(())
    }

    #[test]
    fn a_value_that_is_neither_list_nor_reference_is_malformed() {
        let doc = document_with(|tx, reserved| {
            tx.put(reserved, CERTIFICATES_KEY, ScalarValue::Int(7))
                .expect("scalar");
        });

        assert_eq!(inline(&doc), Err(MalformedLocation::NotAListOrReference));
    }

    #[test]
    fn the_location_is_invisible_to_the_namestore_walk() -> TestResult {
        // E8: the value is not a reference, so no name addresses it —
        // which is why the certificate can share the reserved map
        // with edges at all.
        let cert = certificate(1, "example.com");
        let mut doc = Automerge::new();
        put(&mut doc, &cert)?;

        let namestore = DocumentNamestore::new(doc);
        let segments: Vec<_> = CERTIFICATES_KEY
            .split('/')
            .map(|part| onomancy_core::name::segment::Segment::parse(part).expect("valid segment"))
            .collect();

        assert_eq!(
            path_key(&segments),
            CERTIFICATES_KEY,
            "the key IS spellable as a path"
        );
        assert_eq!(
            namestore.reference(&segments),
            None,
            "but the value is not a reference, so it never resolves"
        );
        assert!(namestore.edges().is_empty(), "and it is not an edge");
        Ok(())
    }
}
