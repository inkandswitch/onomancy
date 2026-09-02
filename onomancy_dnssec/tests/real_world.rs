//! A real production chain, frozen: `_onomancy.brooklynzelenka.com`
//! as fetched from live DNS on 2026-08-20, captured with:
//! name), captured with:
//!
//! ```sh
//! onomancer resolve --hostname brooklynzelenka.com \
//!   --chain-out tests/fixtures/real_brooklynzelenka.chain
//! ```
//!
//! The walk is pure over bytes and anchors — the clock never appears
//! inside validation, only in grading — so this fixture never rots:
//! it validates forever, grades fresh ✓ at its capture instant, and
//! grades stale ⚠ after its RRSIG windows lapse (both asserted).
//!
//! This is also the golden-vector mandate's "multi-link chain
//! crossing a zone cut" case, with production signatures: root DNSKEY
//! → com DS/DNSKEY → brooklynzelenka.com DS/DNSKEY → TXT leaf.

#![allow(clippy::expect_used, clippy::panic)]

use std::{fs, path::PathBuf};

use onomancy_core::time::UnixSeconds;
use onomancy_dnssec::{
    chain::DnssecChain,
    dns_name::DnsName,
    freshness::{Freshness, Grade},
    txt::serial::Serial,
    validator::Validator,
};
use onomancy_protocol::verifier::{state::memory::authority::MemoryAuthority, verdict};
use testresult::TestResult;

/// The capture instant (seconds), inside every RRSIG window.
const CAPTURED_AT: u64 = 1_787_266_968;

/// Long after every RRSIG window has lapsed.
const YEARS_LATER: u64 = CAPTURED_AT + 10 * 365 * 24 * 60 * 60;

/// The published record's serial (ms, serial-as-timestamp).
const SERIAL: u64 = 1_787_265_184_651;

fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    fs::read(&path).unwrap_or_else(|_| panic!("missing fixture {}", path.display()))
}

fn hostname() -> DnsName {
    DnsName::parse("brooklynzelenka.com").expect("valid hostname")
}

#[test]
fn the_production_chain_validates_from_the_iana_anchors() -> TestResult {
    let chain = DnssecChain::read_framed(&fixture("real_brooklynzelenka.chain"))?;
    assert_eq!(chain.links().len(), 6, "root + two cuts + leaf");

    let proof = Validator::iana().validate_detailed(&hostname(), &chain)?;

    // The zone-vouched facts, exactly as published.
    let [record] = proof.records.as_slice() else {
        panic!("expected exactly one binding record, got {proof:?}");
    };
    assert_eq!(record.serial(), Serial::from(SERIAL));
    assert_eq!(
        record.to_string(),
        "v=ONO0;k=ed25519;n=1787265184651;\
         g=TWlLsXosx5DpotJgxopEAYBxZ+XOkzekly573m2h/FU=;\
         p=QBCvRMYouybwMRdlwOk6NFp89nTBFJ2OoVUPDCIihwc="
    );

    // Grading is where the clock enters: fresh at capture, stale —
    // never invalid — once the windows lapse.
    assert_eq!(
        proof.window.grade(UnixSeconds::from(CAPTURED_AT)),
        Grade::Fresh
    );
    assert_eq!(
        proof.window.grade(UnixSeconds::from(YEARS_LATER)),
        Grade::Stale
    );
    Ok(())
}

#[test]
fn the_production_certificate_verifies_end_to_end() -> TestResult {
    // MemoryAuthority is permissive, so the path-membership half is
    // vacuous here; the DNSSEC half is real.
    let verdict = verdict::verify(
        &fixture("real_brooklynzelenka.onc"),
        &hostname(),
        UnixSeconds::from(CAPTURED_AT),
        &Validator::iana(),
        &MemoryAuthority::default(),
    )?;

    assert_eq!(verdict.serial, Serial::from(SERIAL));
    assert_eq!(verdict.freshness, Freshness::Fresh);
    assert_eq!(
        verdict.document.to_string(),
        "VDTcixKK9uxrREEENGJUPLNLqJnx63hXYDA9gJ14gjVrLHosj"
    );

    // Stale-graded later, still verifiable: offline semantics.
    let later = verdict::verify(
        &fixture("real_brooklynzelenka.onc"),
        &hostname(),
        UnixSeconds::from(YEARS_LATER),
        &Validator::iana(),
        &MemoryAuthority::default(),
    )?;
    assert_eq!(later.freshness, Freshness::Stale);
    Ok(())
}
