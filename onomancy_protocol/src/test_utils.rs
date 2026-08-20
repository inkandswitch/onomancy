//! Deterministic evidence factories for conformance tests.
//!
//! Feature-gated (`test_utils`), never part of the protocol surface:
//! seeded keys, one-call binding records with matching validator
//! proofs, and statement factories. Downstream crates (e.g.
//! `onomancy_dnssec`'s conformance replay) share these so the same
//! scenarios run against every `ChainValidator` implementation.
//!
//! Seeds are stable: `doc(n)`, `generation(n)`, and signing keys all
//! derive from `[n; 32]`, so a `rotation(1, 11, 12)` in one crate is
//! byte-identical to the same call in another.

use alloc::{vec, vec::Vec};
use ed25519_dalek::SigningKey;

use onomancy_core::{
    cert::{Certificate, CertificateParams, chain::DnssecChain},
    freshness::ChainWindow,
    name::{dns::DnsName, doc::DocAnchor},
    statement::{rotation::RotationStatement, successor::SuccessorStatement},
    time::UnixSeconds,
    txt::{generation_key::GenerationKey, record::TxtRecord, serial::Serial},
    wire::OversizeUnit,
};

use crate::verifier_state::seam::ChainProof;

/// The fixed test hostname.
///
/// # Panics
///
/// Never: the literal is valid.
#[must_use]
#[allow(clippy::expect_used)]
pub fn host() -> DnsName {
    DnsName::parse("expede.wtf").expect("valid hostname literal")
}

/// A document anchor derived from seed bytes `[seed; 32]`.
#[must_use]
pub fn doc(seed: u8) -> DocAnchor {
    DocAnchor::from(SigningKey::from_bytes(&[seed; 32]).verifying_key())
}

/// A generation key derived from seed bytes `[seed; 32]` — the same
/// seed names the signing key that can act as this generation.
#[must_use]
pub fn generation(seed: u8) -> GenerationKey {
    GenerationKey::from(SigningKey::from_bytes(&[seed; 32]).verifying_key())
}

/// The signing key behind [`doc`]/[`generation`] of the same seed.
#[must_use]
pub fn signer(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A distinct opaque chain per tag byte.
#[must_use]
pub fn chain(tag: u8) -> DnssecChain {
    DnssecChain::from(vec![vec![tag; 8].into()])
}

/// A chain window over `[from, to]` seconds.
///
/// # Panics
///
/// Panics when `to < from` — test-vector construction error.
#[must_use]
#[allow(clippy::expect_used)]
pub fn window(from: u64, to: u64) -> ChainWindow {
    ChainWindow::new(UnixSeconds::from(from), UnixSeconds::from(to))
        .expect("test windows are ordered")
}

/// One binding record: a signed certificate plus the validator proof
/// its chain should yield.
#[derive(Debug, Clone)]
pub struct Binding {
    /// The signed certificate unit.
    pub cert: Certificate,
    /// Its (opaque) chain, for validator registration.
    pub chain: DnssecChain,
    /// The proof a real DNSSEC walk of `chain` would produce.
    pub proof: ChainProof,
}

/// A binding record with an empty attached region beyond its chain.
///
/// # Errors
///
/// Returns [`OversizeUnit`] when the unit would exceed the cap —
/// propagate with `?` in `TestResult` tests.
pub fn binding(
    doc_seed: u8,
    gen_seed: u8,
    chain_tag: u8,
    serial: u64,
    window_span: (u64, u64),
    issued_at: u64,
) -> Result<Binding, OversizeUnit> {
    binding_carrying(
        doc_seed,
        gen_seed,
        chain_tag,
        serial,
        window_span,
        issued_at,
        vec![],
    )
}

/// A binding record whose certificate carries lineage statements —
/// the extraction-closure input.
///
/// # Errors
///
/// Returns [`OversizeUnit`] when the unit would exceed the cap.
pub fn binding_carrying(
    doc_seed: u8,
    gen_seed: u8,
    chain_tag: u8,
    serial: u64,
    window_span: (u64, u64),
    issued_at: u64,
    lineage: Vec<RotationStatement>,
) -> Result<Binding, OversizeUnit> {
    let chain = chain(chain_tag);
    let cert = Certificate::sign(
        CertificateParams {
            root_doc: doc(doc_seed),
            issued_at: UnixSeconds::from(issued_at),
            hostname: host(),
            heads: vec![],
            predecessor: None,
            delegation_chain: vec![],
            lineage,
            chain: chain.clone(),
        },
        &signer(200 ^ doc_seed),
    )?;

    let proof = ChainProof {
        records: vec![TxtRecord::new(
            Serial::from(serial),
            generation(gen_seed),
            doc(doc_seed),
        )],
        window: window(window_span.0, window_span.1),
    };

    Ok(Binding { cert, chain, proof })
}

/// A rotation statement retiring `generation(replaced_seed)` in favor
/// of `generation(successor_seed)` — seed and signing key agree by
/// construction.
///
/// # Errors
///
/// Returns [`OversizeUnit`] when the unit would exceed the cap.
pub fn rotation(
    doc_seed: u8,
    replaced_seed: u8,
    successor_seed: u8,
) -> Result<RotationStatement, OversizeUnit> {
    RotationStatement::sign(
        &doc(doc_seed),
        &generation(replaced_seed),
        &signer(successor_seed),
        vec![],
    )
}

/// A successor statement migrating `doc(predecessor_seed)` to
/// `doc(successor_seed)` under the test hostname, signed by
/// `signer(signer_seed)`.
///
/// # Errors
///
/// Returns [`OversizeUnit`] when the unit would exceed the cap.
pub fn succession(
    predecessor_seed: u8,
    successor_seed: u8,
    signer_seed: u8,
) -> Result<SuccessorStatement, OversizeUnit> {
    SuccessorStatement::sign(
        &doc(predecessor_seed),
        &doc(successor_seed),
        &host(),
        &signer(signer_seed),
        vec![],
    )
}
