//! The issuance path: assembling a certificate from a signature made
//! outside the module.
//!
//! The point of the two-call shape is that the Wasm never holds a
//! signing key, so the only way to test it honestly is to sign here,
//! in the test, with a key the module never sees — exactly as a
//! browser would sign with one its own runtime holds.
//!
//! These tests stop at `decode`, not at a successful `verifyCertificate`.
//! Verification needs a DNSSEC chain that validates from the baked-in
//! IANA anchors, which needs a live zone whose TXT record names *this*
//! document — not something a repository fixture can supply for a
//! freshly generated key. What is checked here is that assembly
//! produces a well-formed, correctly-signed unit; that the chain is
//! then judged is `verify.rs`'s job, and the last test pins the seam
//! between them.

#![cfg(target_arch = "wasm32")]
// House pattern for test code: a failed `expect` here is the test
// failing, which is its job.
#![allow(clippy::expect_used, clippy::panic)]

use ed25519_dalek::{Signer as _, SigningKey};
use js_sys::Uint8Array;
use onomancy_core::anchor::doc::DocAnchor;
use onomancy_dnssec::certificate::Certificate;
use onomancy_wasm::{
    issue::{encode_certificate, signable_bytes},
    text::Text,
    verify::verify_certificate,
};
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

const HOST: &str = "example.com";

/// Well inside the plausibility bound, and not `Date.now()`.
const ISSUED_AT: f64 = 1_788_100_000.0;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// A hostname argument. Owned, so the caller's statement owns the
/// temporary; borrowing one out of a helper would need a leak.
fn host(raw: &str) -> Text {
    JsValue::from_str(raw).unchecked_into()
}

fn anchor() -> Text {
    host(&DocAnchor::from(key().verifying_key()).to_string())
}

fn signer_bytes() -> Vec<u8> {
    key().verifying_key().to_bytes().to_vec()
}

/// Sign the offered bytes with a key the module never receives.
fn sign_externally(offered: &Uint8Array) -> Vec<u8> {
    key().sign(&offered.to_vec()).to_bytes().to_vec()
}

/// The whole point, end to end: offer, sign outside, assemble, and
/// get back bytes that decode as the certificate that was signed.
#[wasm_bindgen_test]
fn an_externally_signed_certificate_assembles_and_decodes() {
    let offered = signable_bytes(&anchor(), &signer_bytes(), ISSUED_AT, &host(HOST))
        .expect("the fields are well formed");

    let bytes = encode_certificate(
        &anchor(),
        &signer_bytes(),
        ISSUED_AT,
        &host(HOST),
        &sign_externally(&offered),
        vec![],
        &[0x00],
    )
    .expect("a valid signature assembles");

    let decoded =
        Certificate::decode(&bytes.to_vec()).expect("the assembled unit is a valid certificate");

    // Decoding re-verifies the signature against the received bytes,
    // so reaching here already proves the external signature covered
    // the right region. These assert it covered the right *fields*.
    assert_eq!(decoded.hostname().as_str(), HOST);
    assert_eq!(
        decoded.root_doc().to_string(),
        DocAnchor::from(key().verifying_key()).to_string()
    );
}

/// A signature over the wrong bytes is refused at assembly rather
/// than producing a unit that fails later somewhere else — and with
/// the code the contract promises: `invalid-signature`, because the
/// signature is well-formed and does not cover these fields.
#[wasm_bindgen_test]
fn a_signature_over_different_fields_is_refused() {
    let offered = signable_bytes(&anchor(), &signer_bytes(), ISSUED_AT, &host(HOST))
        .expect("the fields are well formed");

    // Signed for one hostname, assembled for another.
    let Err(refused) = encode_certificate(
        &anchor(),
        &signer_bytes(),
        ISSUED_AT,
        &host("other.example.com"),
        &sign_externally(&offered),
        vec![],
        &[0x00],
    ) else {
        panic!("a signature that does not cover the assembled fields must be refused");
    };

    assert_eq!(reason_string(&refused), "invalid-signature");
}

/// The seam this file stops at, pinned so the stopping point is a
/// statement rather than an omission: assembly succeeds and the
/// *chain* is what verification then refuses.
#[wasm_bindgen_test]
fn an_assembled_certificate_without_a_chain_fails_at_the_chain() {
    let offered = signable_bytes(&anchor(), &signer_bytes(), ISSUED_AT, &host(HOST))
        .expect("the fields are well formed");

    let bytes = encode_certificate(
        &anchor(),
        &signer_bytes(),
        ISSUED_AT,
        &host(HOST),
        &sign_externally(&offered),
        vec![],
        &[0x00],
    )
    .expect("a valid signature assembles");

    let Err(refusal) = verify_certificate(&bytes.to_vec(), &host(HOST), Some(ISSUED_AT)) else {
        panic!("a certificate with no chain cannot verify");
    };

    let reason = js_sys::Reflect::get(&refusal, &JsValue::from_str("reason"))
        .ok()
        .and_then(|value| value.as_string())
        .expect("a substantive refusal carries a reason");

    // Not `malformed`, and not `invalid-signature`: the unit is well
    // formed and correctly signed. It is the evidence that is absent.
    assert_eq!(reason, "chain-rejected");
}

/// Every refusal that is a statement about the operation carries a
/// machine-readable `reason`, per the published contract — including
/// this surface, which threw bare `JsError`s until a review noticed.
#[wasm_bindgen_test]
fn issuance_refusals_carry_reason_codes() {
    let reason_of = |result: Result<js_sys::Uint8Array, JsValue>| -> String {
        let Err(refusal) = result else {
            panic!("expected a refusal");
        };
        reason_string(&refusal)
    };

    // End-user-visible inputs keep their specific codes…
    assert_eq!(
        reason_of(signable_bytes(
            &anchor(),
            &signer_bytes(),
            1_788_100_000_000.0, // Date.now(): milliseconds
            &host(HOST),
        )),
        "invalid-timestamp"
    );

    // …including values no clock produces: a silent cast would date
    // the certificate 1970 and grade everything against it. One case
    // suffices to prove the boundary routes through `clock::seconds`,
    // whose classification is property-tested on the host.
    assert_eq!(
        reason_of(signable_bytes(
            &anchor(),
            &signer_bytes(),
            f64::NAN,
            &host(HOST)
        )),
        "invalid-timestamp"
    );

    // …developer wiring gets the one generic code, with the message
    // naming the argument.
    assert_eq!(
        reason_of(signable_bytes(
            &anchor(),
            &[7u8; 31], // one byte short
            ISSUED_AT,
            &host(HOST),
        )),
        "invalid-argument"
    );

    // A signature that does not cover the fields is its own thing:
    // not a malformed argument, a signature that fails. The impostor
    // key also pins that `signer` is not a decoration the module
    // ignores.
    let offered = signable_bytes(&anchor(), &signer_bytes(), ISSUED_AT, &host(HOST))
        .expect("the fields are well formed");
    let impostor = SigningKey::from_bytes(&[9u8; 32]);
    let signature = impostor.sign(&offered.to_vec()).to_bytes().to_vec();

    assert_eq!(
        reason_of(encode_certificate(
            &anchor(),
            &signer_bytes(),
            ISSUED_AT,
            &host(HOST),
            &signature,
            vec![],
            &[0x00],
        )),
        "invalid-signature"
    );
}

/// The 1 MiB cap bites at `encodeCertificate` — after the external
/// signature was spent, which is why the code matters: the caller
/// must learn it is `invalid-argument` (the carriage is too big),
/// not a signature problem worth re-signing over.
#[wasm_bindgen_test]
fn an_oversize_carriage_is_refused_as_an_argument_problem() {
    let offered = signable_bytes(&anchor(), &signer_bytes(), ISSUED_AT, &host(HOST))
        .expect("the fields are well formed");

    // Past the unit cap on its own: the fields and chain are tiny.
    let fat = Uint8Array::new_with_length(1_100_000);

    let Err(refused) = encode_certificate(
        &anchor(),
        &signer_bytes(),
        ISSUED_AT,
        &host(HOST),
        &sign_externally(&offered),
        vec![fat],
        &[0x00],
    ) else {
        panic!("a unit over the cap must be refused at assembly");
    };

    assert_eq!(reason_string(&refused), "invalid-argument");
}

/// The machine-readable code on a refusal.
fn reason_string(refusal: &JsValue) -> String {
    js_sys::Reflect::get(refusal, &JsValue::from_str("reason"))
        .ok()
        .and_then(|value| value.as_string())
        .expect("a substantive refusal carries a reason")
}
