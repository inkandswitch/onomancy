//! The golden-vector catalog: the single source of truth behind
//! `tests/vectors/` — shared by the regenerating example
//! (`examples/generate_vectors.rs`) and the conformance test
//! (`tests/golden_vectors.rs`) via `#[path]` inclusion. It lives
//! under `tests/support/` so cargo does not compile it as its own
//! test target.
//!
//! Every vector is deterministic: fixed seeds, fixed timestamps, no
//! ambient input. The checked-in files gate codec changes — canonical
//! re-derivation (`encode(decode(b)) = b`) is load-bearing (ADR-043),
//! so any byte drift here is a wire-format break, not a refactor.
//!
//! PROVISIONAL: vectors are generated from this implementation until
//! the Lean reference model can extract them
//! (specs/serialization.md, Test Vectors; design/verification.md).

// Included via `#[path]` from two targets: pub-ness is per-target
// (hence `unreachable_pub`), and each target uses a subset
// (`dead_code`). Panics here are catalog invariants, not prod paths.
#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::panic,
    dead_code,
    unreachable_pub
)]

use core::fmt::Write as _;
use ed25519_dalek::SigningKey;
use onomancy_core::{
    cert::{Certificate, CertificateParams, chain::DnssecChain},
    delegation::DelegationBytes,
    name::{
        dns::DnsName,
        doc::{DocAnchor, Head},
    },
    statement::{rotation::RotationStatement, successor::SuccessorStatement},
    time::UnixSeconds,
    txt::generation_key::GenerationKey,
};

/// One golden vector: canonical bytes plus the outcome a conforming
/// decoder MUST produce for them.
#[derive(Debug)]
pub struct Vector {
    /// File stem under `tests/vectors/` (`{name}.hex`).
    pub name: &'static str,
    /// The vector bytes.
    pub bytes: Vec<u8>,
    /// The mandated decode outcome.
    pub expect: Expect,
}

/// The decode outcome a vector mandates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// Decodes as a valid `ONC\x00` unit and re-encodes to identical
    /// bytes.
    Certificate,
    /// Decodes as a valid `ONR\x00` unit and re-encodes to identical
    /// bytes.
    Rotation,
    /// Decodes as a valid `ONS\x00` unit and re-encodes to identical
    /// bytes.
    Successor,
    /// `Certificate::decode` MUST reject these bytes.
    RejectCertificate,
}

/// A fixed issuance time inside the fixtures' era.
const ISSUED_AT: u64 = 1_755_000_000;

/// A deterministic signing key from seed bytes `[seed; 32]`.
pub fn signer(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// The document anchor of `signer(seed)`.
pub fn doc(seed: u8) -> DocAnchor {
    DocAnchor::from(signer(seed).verifying_key())
}

/// The generation key of `signer(seed)`.
pub fn generation(seed: u8) -> GenerationKey {
    GenerationKey::from(signer(seed).verifying_key())
}

/// The vectors' fixed hostname.
pub fn host() -> DnsName {
    DnsName::parse("example.com").expect("valid hostname literal")
}

/// The full, deterministic vector set.
#[allow(clippy::too_many_lines)] // a catalog is naturally one long list
pub fn vectors() -> Vec<Vector> {
    let minimal = certificate(minimal_params());
    let (reattach_a, reattach_b) = reattach_pair();
    let heads_base = certificate(CertificateParams {
        heads: vec![Head::from([0x41; 32]), Head::from([0x42; 32])],
        ..minimal_params()
    });

    vec![
        // ————— accept: certificates —————
        Vector {
            name: "cert_minimal",
            bytes: minimal.encode(),
            expect: Expect::Certificate,
        },
        Vector {
            name: "cert_full",
            bytes: certificate(full_params()).encode(),
            expect: Expect::Certificate,
        },
        // bijou64 tier boundary in a timestamp: 247 is the last
        // one-byte value, 248 the first two-byte one.
        Vector {
            name: "cert_issued_at_tier_edge_low",
            bytes: certificate(CertificateParams {
                issued_at: UnixSeconds::from(247),
                ..minimal_params()
            })
            .encode(),
            expect: Expect::Certificate,
        },
        Vector {
            name: "cert_issued_at_tier_edge_high",
            bytes: certificate(CertificateParams {
                issued_at: UnixSeconds::from(248),
                ..minimal_params()
            })
            .encode(),
            expect: Expect::Certificate,
        },
        // bijou64 tier boundary in a length: a 300-byte delegation
        // blob forces its length varint into the two-byte tier.
        Vector {
            name: "cert_long_delegation",
            bytes: certificate(CertificateParams {
                delegation_chain: vec![DelegationBytes::from(vec![0xCC; 300])],
                ..minimal_params()
            })
            .encode(),
            expect: Expect::Certificate,
        },
        // Chain re-attach: same signed bytes, different attached
        // region — one certificate identity, two content hashes.
        Vector {
            name: "cert_reattach_a",
            bytes: reattach_a.encode(),
            expect: Expect::Certificate,
        },
        Vector {
            name: "cert_reattach_b",
            bytes: reattach_b.encode(),
            expect: Expect::Certificate,
        },
        // ————— accept: statements —————
        Vector {
            name: "rotation_valid",
            bytes: RotationStatement::sign(
                &doc(1),
                &generation(2),
                &signer(3),
                vec![DelegationBytes::from(vec![0xAB; 5])],
            )
            .expect("under the unit cap")
            .encode(),
            expect: Expect::Rotation,
        },
        Vector {
            name: "successor_valid",
            bytes: SuccessorStatement::sign(
                &doc(1),
                &doc(2),
                &host(),
                &signer(3),
                vec![DelegationBytes::from(vec![0xCD; 7])],
            )
            .expect("under the unit cap")
            .encode(),
            expect: Expect::Successor,
        },
        // ————— reject: canonical-form mutations —————
        // Sorted heads [A, B] swapped to [B, A]: unsorted heads are
        // not the canonical encoding.
        Vector {
            name: "cert_heads_unsorted",
            bytes: replace(
                &heads_base.encode(),
                &concat(&[0x41; 32], &[0x42; 32]),
                &concat(&[0x42; 32], &[0x41; 32]),
            ),
            expect: Expect::RejectCertificate,
        },
        // [A, B] rewritten to [A, A]: duplicates are equally
        // non-canonical.
        Vector {
            name: "cert_heads_duplicated",
            bytes: replace(
                &heads_base.encode(),
                &concat(&[0x41; 32], &[0x42; 32]),
                &concat(&[0x41; 32], &[0x41; 32]),
            ),
            expect: Expect::RejectCertificate,
        },
        // An uppercase octet in the hostname: decoders reject,
        // never normalize.
        Vector {
            name: "cert_hostname_denormalized",
            bytes: replace(&minimal.encode(), b"example.com", b"Example.com"),
            expect: Expect::RejectCertificate,
        },
    ]
}

fn certificate(params: CertificateParams) -> Certificate {
    Certificate::sign(params, &signer(2)).expect("catalog vectors stay under the unit cap")
}

fn minimal_params() -> CertificateParams {
    CertificateParams {
        root_doc: doc(1),
        issued_at: UnixSeconds::from(ISSUED_AT),
        hostname: host(),
        heads: vec![],
        predecessor: None,
        delegation_chain: vec![],
        lineage: vec![],
        chain: DnssecChain::default(),
    }
}

/// Every optional region populated: heads, predecessor, delegation
/// chain, lineage, DNSSEC chain.
fn full_params() -> CertificateParams {
    CertificateParams {
        heads: vec![
            Head::from([0x41; 32]),
            Head::from([0x42; 32]),
            Head::from([0x43; 32]),
        ],
        predecessor: Some(
            SuccessorStatement::sign(
                &doc(4),
                &doc(1),
                &host(),
                &signer(5),
                vec![DelegationBytes::from(vec![1, 2, 3])],
            )
            .expect("under the unit cap"),
        ),
        delegation_chain: vec![DelegationBytes::from(vec![0xAA; 9])],
        lineage: vec![
            RotationStatement::sign(&doc(1), &generation(6), &signer(7), vec![])
                .expect("under the unit cap"),
        ],
        chain: DnssecChain::from(vec![vec![0xDD; 5].into()]),
        ..minimal_params()
    }
}

/// The re-attach pair: `b` carries different attachments over `a`'s
/// signed region.
pub fn reattach_pair() -> (Certificate, Certificate) {
    let a = certificate(full_params());
    let b = a
        .with_attachments(
            vec![DelegationBytes::from(vec![0xEE; 4])],
            vec![],
            DnssecChain::from(vec![vec![0xEF; 6].into()]),
        )
        .expect("under the unit cap");

    (a, b)
}

/// Same-length search-and-replace over unit bytes, for mutation
/// vectors. The needle MUST occur exactly once.
fn replace(bytes: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    assert_eq!(needle.len(), replacement.len(), "same-length mutation");

    let hits: Vec<usize> = bytes
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .map(|(at, _)| at)
        .collect();
    let [at] = hits.as_slice() else {
        panic!("mutation needle must occur exactly once, found {hits:?}");
    };

    let mut mutated = bytes.to_vec();
    mutated
        .get_mut(*at..*at + replacement.len())
        .expect("window position is in range")
        .copy_from_slice(replacement);
    mutated
}

fn concat(left: &[u8; 32], right: &[u8; 32]) -> Vec<u8> {
    let mut joined = left.to_vec();
    joined.extend_from_slice(right);
    joined
}

/// Lowercase hex, the vector files' on-disk form.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

/// Decode the vector files' hex form (whitespace-tolerant).
pub fn from_hex(hex: &str) -> Vec<u8> {
    let compact: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(compact.len().is_multiple_of(2), "hex length must be even");

    (0..compact.len())
        .step_by(2)
        .map(|at| {
            u8::from_str_radix(compact.get(at..at + 2).expect("stepped in range"), 16)
                .expect("valid hex digits")
        })
        .collect()
}
