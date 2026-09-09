//! A carriage from a peer that instantiated Keyhive over a
//! variable-width content reference (`Vec<u8>`) instead of the `[u8; 32]`
//! hash `kh0` names. Its one delegation is otherwise sound — root-issued,
//! Admin, to the signer — but `after_content` carries a length-prefixed
//! 10-byte reference where a bare 32-byte hash belongs, so the entry
//! cannot be read as a `kh0` event.
//!
//! The wire formats differ only when `after_content` is non-empty, which
//! minted carriages never are. This fixture pins the refusal: a proof in
//! the wrong encoding is undecodable, and undecodable vouches nothing —
//! it is never misread into an acceptance.

use core::str;

use ed25519_dalek::VerifyingKey;
use onomancy_core::{
    anchor::doc::DocAnchor,
    delegation_chain::{DelegationChain, SignedDelegationBytes},
};
use onomancy_dnssec::txt::generation_key::GenerationKey;
use onomancy_keyhive::{
    authority::KeyhiveAuthority,
    carriage::{Carriage, ParseCarriageError},
};
use onomancy_protocol::verifier::state::authority_verifier::AuthorityVerifier;
use testresult::TestResult;

const CARRIAGE: &str = include_str!("fixtures/variable_width_content_ref_carriage.hex");
const DOCUMENT: &str = "4d9a7593eaacded04a9773d34564a3a4cc280bab3e57eed908018250ba14243e";
const SIGNER: &str = "1423beeb0d6e8780f34ad031441269712c52345470bece360e256d642d66fff3";

fn unhex(hex: &str) -> TestResult<Vec<u8>> {
    let digits = hex.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return Err("odd-length hex".into());
    }

    digits
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(str::from_utf8(pair)?, 16)?))
        .collect()
}

fn key(hex: &str) -> TestResult<VerifyingKey> {
    let bytes: [u8; 32] = unhex(hex)?
        .try_into()
        .map_err(|_| "key fixture is not 32 bytes")?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

fn carriage() -> TestResult<DelegationChain> {
    let entries = CARRIAGE
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| unhex(line.trim()).map(SignedDelegationBytes::from))
        .collect::<TestResult<Vec<_>>>()?;
    Ok(DelegationChain::from(entries))
}

/// The delegation is entry 0; the prekey introductions after it carry
/// no content references and would decode under either instantiation.
#[test]
fn the_delegation_is_undecodable_and_named() -> TestResult {
    assert!(matches!(
        Carriage::parse(&carriage()?),
        Err(ParseCarriageError::UndecodableEvent { index: 0, .. })
    ));
    Ok(())
}

#[test]
fn an_undecodable_carriage_authorizes_nobody() -> TestResult {
    let root = DocAnchor::from(key(DOCUMENT)?);

    assert!(
        !KeyhiveAuthority.authorizes(&root, &key(SIGNER)?, &carriage()?),
        "the signer really is the delegate, and it still proves nothing"
    );
    Ok(())
}

#[test]
fn an_undecodable_carriage_puts_nothing_on_the_path() -> TestResult {
    let generation = GenerationKey::from(key(SIGNER)?);

    assert!(!KeyhiveAuthority.on_path(&carriage()?, &generation));
    Ok(())
}
