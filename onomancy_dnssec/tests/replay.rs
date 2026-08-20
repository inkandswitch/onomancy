//! The conformance replay: derive scenarios run twice — once against
//! `MemoryValidator` with declared proofs, once against the REAL
//! [`Validator`] walking real signed chains — and the derivations
//! must be identical.
//!
//! This is what makes every `derive_conformance` scenario trustworthy
//! evidence about production behavior: the fake and the real
//! implementation are interchangeable at the `ChainValidator` seam.

use ed25519_dalek::SigningKey;
use onomancy_core::{
    cert::{chain::DnssecChain, Certificate, CertificateParams},
    collections::{Map, Set},
    freshness::ChainWindow,
    time::UnixSeconds,
    txt::{record::TxtRecord, serial::Serial},
};
use onomancy_protocol::{
    test_utils as proto_utils,
    verifier_state::{
        judgment::{Acceptance, Judgment},
        memory::{MemoryAuthority, MemoryValidator},
        seam::ChainProof,
        store::{Item, Store},
        VerifierState,
    },
};
use testresult::TestResult;

use onomancy_dnssec::{
    test_utils::{binding_chain, fixtures, txt_record, ChainWindows},
    validator::Validator,
};

/// The derivation clock: inside the "fresh" windows below.
const NOW: u64 = 1_755_000_000;

/// One scenario record: a certificate embedding a REAL signed chain,
/// plus the proof `MemoryValidator` declares for it (which the real
/// walk must reproduce).
struct RealBinding {
    cert: Certificate,
    chain: DnssecChain,
    proof: ChainProof,
}

fn real_binding(
    doc_seed: u8,
    gen_seed: u8,
    serial: u64,
    window: (u32, u32),
    issued_at: u64,
) -> TestResult<RealBinding> {
    let hostname = proto_utils::host();
    let record = TxtRecord::new(
        Serial::from(serial),
        proto_utils::generation(gen_seed),
        proto_utils::doc(doc_seed),
    );

    let chain = binding_chain(
        &fixtures::fixture_root(),
        &fixtures::fixture_child(),
        txt_record(&hostname, &record.to_string()),
        ChainWindows::uniform(window),
    );

    let cert = Certificate::sign(
        CertificateParams {
            root_doc: proto_utils::doc(doc_seed),
            issued_at: UnixSeconds::from(issued_at),
            hostname: hostname.clone(),
            heads: vec![],
            predecessor: None,
            delegation_chain: vec![],
            lineage: vec![],
            chain: chain.clone(),
        },
        &SigningKey::from_bytes(&[200 ^ doc_seed; 32]),
    );

    let proof = ChainProof {
        records: vec![record],
        window: ChainWindow::new(
            UnixSeconds::from(u64::from(window.0)),
            UnixSeconds::from(u64::from(window.1)),
        )?,
    };

    Ok(RealBinding { cert, chain, proof })
}

/// Derive the same evidence twice — fake and real — and demand
/// identical output.
fn derive_both_ways(
    bindings: &[&RealBinding],
    judgment: &Judgment,
    extra: Vec<Item>,
) -> VerifierState {
    let hostname = proto_utils::host();

    let mut store = Store::default();
    let mut memory = MemoryValidator::default();
    for binding in bindings {
        store.insert(Item::Record(binding.cert.clone()));
        memory = memory.with(hostname.clone(), &binding.chain, binding.proof.clone());
    }
    for item in extra {
        store.insert(item);
    }

    let real = Validator::new(fixtures::fixture_anchor());
    let authority = MemoryAuthority::default();
    let pins = Map::default();
    let now = UnixSeconds::from(NOW);

    let with_real = VerifierState::compute(&store, now, judgment, &pins, &real, &authority);
    let with_fake = VerifierState::compute(&store, now, judgment, &pins, &memory, &authority);

    assert_eq!(
        with_real, with_fake,
        "the real walk and the declared proofs must derive identically"
    );

    with_real
}

fn accept(binding: &RealBinding) -> Judgment {
    let mut acceptances = Map::default();
    let mut cited = Set::default();
    cited.insert(binding.cert.digest().into());
    acceptances.insert(
        proto_utils::host(),
        vec![Acceptance {
            document: *binding.cert.root_doc(),
            cited,
        }],
    );

    Judgment {
        acceptances,
        ..Judgment::default()
    }
}

#[test]
fn fresh_binding_derives_identically() -> TestResult {
    // Window covers NOW: fresh, confirmed.
    let binding = real_binding(1, 11, 100, (1_754_000_000, 1_756_000_000), 50)?;

    let derivation = derive_both_ways(&[&binding], &Judgment::default(), vec![]);
    let state = derivation
        .hosts
        .get(&proto_utils::host())
        .cloned()
        .unwrap_or_default();

    let accepted = state.accepted.ok_or("expected an accepted binding")?;
    assert_eq!(accepted.document, proto_utils::doc(1));
    assert_eq!(state.effective_serial, Some(Serial::from(100)));
    Ok(())
}

#[test]
fn b1_pending_challenger_derives_identically() -> TestResult {
    // Acceptance-backed incumbent, stale unproven challenger with a
    // later zone-state key: pending, never displacing.
    let incumbent = real_binding(1, 11, 100, (1_744_000_000, 1_748_000_000), 50)?;
    let challenger = real_binding(2, 22, 999, (1_749_000_000, 1_752_000_000), 60)?;

    let derivation = derive_both_ways(&[&incumbent, &challenger], &accept(&incumbent), vec![]);
    let state = derivation
        .hosts
        .get(&proto_utils::host())
        .cloned()
        .unwrap_or_default();

    let accepted = state.accepted.ok_or("expected an accepted binding")?;
    assert_eq!(accepted.document, proto_utils::doc(1), "incumbent stands");
    assert_eq!(state.pending, vec![proto_utils::doc(2)]);
    Ok(())
}

#[test]
fn d4a_ratchet_reset_derives_identically() -> TestResult {
    // Same document: stale record with a huge serial, fresh record
    // with a small one — the fresh one wins and the serial resets.
    let stale_high = real_binding(1, 11, 999, (1_744_000_000, 1_748_000_000), 50)?;
    let fresh_low = real_binding(1, 11, 7, (1_754_000_000, 1_756_000_000), 60)?;

    let derivation = derive_both_ways(&[&stale_high, &fresh_low], &Judgment::default(), vec![]);
    let state = derivation
        .hosts
        .get(&proto_utils::host())
        .cloned()
        .unwrap_or_default();

    assert_eq!(state.effective_serial, Some(Serial::from(7)));
    Ok(())
}
