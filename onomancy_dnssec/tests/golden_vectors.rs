//! Golden-vector conformance (specs/serialization.md, Test Vectors).
//!
//! The checked-in files under `tests/vectors/` gate codec changes:
//! canonical re-derivation (`encode(decode(b)) = b`) is load-bearing
//!, so a byte drift here is a wire-format break. Regenerate
//! deliberately with:
//!
//! ```sh
//! cargo run -p onomancy_dnssec --example generate_vectors
//! ```

#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::panic)]

#[path = "support/vectors_catalog.rs"]
mod vectors_catalog;

use std::{fs, path::PathBuf};

use onomancy_core::{
    digest::{Blake3, Digest},
    signed::payload::Malformed,
};
use onomancy_dnssec::{
    certificate::{Certificate, DecodeCertificateError},
    statement::{
        rotation::{DecodeRotationError, RotationStatement},
        successor::{DecodeSuccessorError, SuccessorStatement},
    },
};
use testresult::TestResult;
use vectors_catalog::{Expect, Vector, from_hex, to_hex, vectors};

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
}

fn checked_in(vector: &Vector) -> Vec<u8> {
    let path = vectors_dir().join(format!("{}.hex", vector.name));
    let hex = fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing vector file {} — regenerate", path.display()));
    from_hex(&hex)
}

/// The catalog and the checked-in files agree byte for byte: codec
/// changes cannot slip through as silent regeneration.
#[test]
fn vector_files_are_byte_stable() {
    for vector in vectors() {
        assert_eq!(
            to_hex(&vector.bytes),
            to_hex(&checked_in(&vector)),
            "{}: checked-in bytes drifted from the catalog",
            vector.name
        );
    }
}

/// Every accept vector decodes, re-encodes byte-identically, and
/// hashes to its recorded digest (hashes are over verbatim bytes).
#[test]
fn accept_vectors_roundtrip_with_stable_digests() -> TestResult {
    let digests = fs::read_to_string(vectors_dir().join("digests.txt"))?;
    let recorded = |name: &str| -> Option<&str> {
        digests
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
    };

    for vector in vectors() {
        let bytes = checked_in(&vector);

        let digest: Digest<Blake3, [u8]> = match vector.expect {
            Expect::Certificate => {
                let unit = Certificate::decode(&bytes)?;
                assert_eq!(bytes, unit.encode(), "{}: byte identity", vector.name);
                unit.digest().erase()
            }
            Expect::Rotation => {
                let unit = RotationStatement::decode(&bytes)?;
                assert_eq!(bytes, unit.encode(), "{}: byte identity", vector.name);
                unit.digest().erase()
            }
            Expect::Successor => {
                let unit = SuccessorStatement::decode(&bytes)?;
                assert_eq!(bytes, unit.encode(), "{}: byte identity", vector.name);
                unit.digest().erase()
            }
            Expect::RejectCertificate => continue,
        };

        assert_eq!(
            Some(digest.to_string().as_str()),
            recorded(vector.name),
            "{}: content hash drifted",
            vector.name
        );
    }

    Ok(())
}

/// Reject vectors fail decoding — with the precise canonical-form
/// error, not an incidental one.
#[test]
fn reject_vectors_fail_at_decode() {
    for vector in vectors() {
        if vector.expect != Expect::RejectCertificate {
            continue;
        }

        let result = Certificate::decode(&checked_in(&vector));
        match vector.name {
            "cert_heads_unsorted" | "cert_heads_duplicated" => assert!(
                matches!(result, Err(DecodeCertificateError::HeadsNotCanonical)),
                "{}: expected HeadsNotCanonical, got {result:?}",
                vector.name
            ),
            "cert_hostname_denormalized" => assert!(
                matches!(result, Err(DecodeCertificateError::Hostname(_))),
                "{}: expected a hostname canonicality error, got {result:?}",
                vector.name
            ),
            // Force every future reject vector to pin its variant
            // here — an unnamed vector asserting only is_err() could
            // fail for the wrong reason without anyone noticing.
            other => panic!("reject vector {other} has no variant assertion — add one"),
        }
    }
}

/// Cross-tag confusion: unit bytes offered to the wrong decoder fail
/// on the format tag, for every pairing.
#[test]
fn cross_tag_confusion_fails_on_the_tag() {
    let by_name = |name: &str| -> Vec<u8> {
        let vector = vectors()
            .into_iter()
            .find(|v| v.name == name)
            .expect("vector in catalog");
        checked_in(&vector)
    };

    let cert = by_name("cert_minimal");
    let rotation = by_name("rotation_valid");
    let successor = by_name("successor_valid");

    // All six pairings fail ON THE TAG — not on some incidental later
    // field — so type confusion is caught at the front door.
    assert!(matches!(
        Certificate::decode(&rotation),
        Err(DecodeCertificateError::Malformed(
            Malformed::WrongTag { .. }
        ))
    ));
    assert!(matches!(
        Certificate::decode(&successor),
        Err(DecodeCertificateError::Malformed(
            Malformed::WrongTag { .. }
        ))
    ));
    assert!(matches!(
        RotationStatement::decode(&cert),
        Err(DecodeRotationError::Malformed(Malformed::WrongTag { .. }))
    ));
    assert!(matches!(
        RotationStatement::decode(&successor),
        Err(DecodeRotationError::Malformed(Malformed::WrongTag { .. }))
    ));
    assert!(matches!(
        SuccessorStatement::decode(&cert),
        Err(DecodeSuccessorError::Malformed(Malformed::WrongTag { .. }))
    ));
    assert!(matches!(
        SuccessorStatement::decode(&rotation),
        Err(DecodeSuccessorError::Malformed(Malformed::WrongTag { .. }))
    ));
}

/// The re-attach pair: one certificate identity (same signed region),
/// two content hashes (the attached region is hashed too). Decoded
/// from the CHECKED-IN bytes, so the semantic claim is pinned to the
/// committed files, not just the in-process catalog.
#[test]
fn reattach_pair_shares_identity_but_not_hash() -> TestResult {
    let by_name = |name: &str| -> Vec<u8> {
        let vector = vectors()
            .into_iter()
            .find(|v| v.name == name)
            .expect("vector in catalog");
        checked_in(&vector)
    };

    let a = Certificate::decode(&by_name("cert_reattach_a"))?;
    let b = Certificate::decode(&by_name("cert_reattach_b"))?;

    assert!(a.same_certificate(&b), "same signed region");
    assert_ne!(
        a.digest().erase(),
        b.digest().erase(),
        "different attached regions, different hashes"
    );
    Ok(())
}
