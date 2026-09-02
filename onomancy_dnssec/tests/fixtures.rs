//! The checked-in fixtures still mean what the catalog says they
//! mean: every `tests/fixtures/*.chain` file is read back and
//! validated, and its outcome must match its declared
//! [`Expectation`]. Also pins byte-stability: regenerating the
//! catalog in-process must reproduce the committed bytes exactly.

#![allow(clippy::panic, clippy::indexing_slicing)]

use std::{fs, path::PathBuf};

use onomancy_dnssec::{
    chain::DnssecChain,
    chain_proof::ChainProof,
    test_utils::fixtures::{
        Expectation, FIXTURE_SERIAL, all_fixtures, fixture_anchor, fixture_hostname,
    },
    txt::serial::Serial,
    validator::Validator,
};
use testresult::TestResult;

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.chain"))
}

#[test]
fn committed_bytes_match_the_catalog() -> TestResult {
    for (name, chain, _) in all_fixtures() {
        let mut generated = Vec::new();
        chain.write_framed(&mut generated);

        let committed = fs::read(fixture_path(name))?;
        assert_eq!(
            committed, generated,
            "{name}.chain drifted from the catalog — regenerate (see README) \
             and review what changed"
        );
    }
    Ok(())
}

#[test]
fn every_fixture_produces_its_declared_outcome() -> TestResult {
    let validator = Validator::new(fixture_anchor());
    let hostname = fixture_hostname();

    for (name, _, expectation) in all_fixtures() {
        let bytes = fs::read(fixture_path(name))?;
        let chain = DnssecChain::read_framed(&bytes)?;
        let outcome = validator.validate_detailed(&hostname, &chain);

        match expectation {
            Expectation::Binding => {
                let ChainProof { records, .. } = outcome.unwrap_or_else(|error| {
                    panic!("{name}: expected a binding proof, got {error}")
                });
                assert_eq!(records.len(), 1, "{name}: one binding record");
                assert_eq!(
                    records[0].serial(),
                    Serial::from(FIXTURE_SERIAL),
                    "{name}: fixture serial"
                );
            }

            Expectation::Invalid(expected) => {
                // The EXACT variant: an adversarial fixture failing
                // for the wrong reason means the rejection branch it
                // was built to exercise has gone dead.
                assert_eq!(
                    outcome,
                    Err(expected),
                    "{name}: mutation vector MUST fail with its declared error"
                );
            }
        }
    }
    Ok(())
}
