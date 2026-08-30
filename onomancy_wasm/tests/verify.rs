//! Certificate verification inside the wasm module, in Node.
//!
//! Network-free and browser-free: the point is that the whole check —
//! DNSSEC chain from the baked-in IANA anchors, the certificate's
//! signature, the zone's cross-check, and the Keyhive delegation
//! carriage — runs inside the module with nothing handed out to JS.
//!
//! `KeyhiveAuthority` replays each carriage into a throwaway instance
//! via `block_on`. That works here because the replay is pure
//! in-memory computation: it never awaits the JS event loop, so there
//! is nothing to deadlock on and no async seam to bridge.

#![cfg(target_arch = "wasm32")]

use onomancy_wasm::verify::verify_certificate;
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

/// The production capture, with a real delegation carriage attached.
/// Referenced rather than copied: the fixtures README pins these as
/// frozen captures ("do not regenerate"), so one source of truth.
const CERT: &[u8] =
    include_bytes!("../../onomancy_dnssec/tests/fixtures/real_brooklynzelenka_carriage.onc");

/// Well after the chain's RRSIG windows lapsed — the certificate is
/// stale, which is a risk signal and never a forgery signal.
const YEARS_LATER: f64 = 1_788_100_000_000.0;

fn field(verdict: &JsValue, key: &str) -> String {
    js_sys::Reflect::get(verdict, &JsValue::from_str(key))
        .ok()
        .and_then(|value| value.as_string())
        .unwrap_or_default()
}

#[wasm_bindgen_test]
fn a_real_certificate_verifies_inside_the_module() {
    let verdict = verify_certificate(
        CERT,
        &JsValue::from_str("brooklynzelenka.com"),
        Some(YEARS_LATER),
    )
    .expect("the production certificate verifies");

    assert_eq!(
        field(&verdict, "document"),
        "VDTcixKK9uxrREEENGJUPLNLqJnx63hXYDA9gJ14gjVrLHosj",
        "the document the zone named"
    );
    assert_eq!(field(&verdict, "hostname"), "brooklynzelenka.com");
    assert_eq!(field(&verdict, "serial"), "1787291588428");

    // Stale, because the captured chain's windows have lapsed. Never
    // invalid: staleness is about age, not authenticity.
    assert_eq!(field(&verdict, "freshness"), "stale");

    // The half a DNSSEC walk cannot do: the signer's authority
    // threads the attested generation key, checked by replaying the
    // carriage into a real Keyhive graph.
    assert_eq!(field(&verdict, "generation"), "on-path");
}

#[wasm_bindgen_test]
fn the_grading_inputs_come_back_with_the_grade() {
    let verdict = verify_certificate(
        CERT,
        &JsValue::from_str("brooklynzelenka.com"),
        Some(YEARS_LATER),
    )
    .expect("verifies");

    let window = js_sys::Reflect::get(&verdict, &JsValue::from_str("window")).expect("window");
    let expiration = js_sys::Reflect::get(&window, &JsValue::from_str("expiration"))
        .ok()
        .and_then(|value| value.as_f64())
        .expect("expiration");
    let checked_at = js_sys::Reflect::get(&verdict, &JsValue::from_str("checkedAt"))
        .ok()
        .and_then(|value| value.as_f64())
        .expect("checkedAt");

    // A caller can check the work rather than trust the label:
    // how far past expiry, and whose clock said so.
    assert!(checked_at > expiration, "stale means checked after expiry");
    assert_eq!(checked_at, YEARS_LATER / 1000.0);
}

#[wasm_bindgen_test]
fn a_certificate_for_another_hostname_is_refused() {
    let refused = verify_certificate(CERT, &JsValue::from_str("example.com"), Some(YEARS_LATER));

    assert!(
        refused.is_err(),
        "a certificate binds one hostname and says so in its signature"
    );
}

#[wasm_bindgen_test]
fn garbage_is_refused_without_panicking() {
    assert!(
        verify_certificate(
            &[0xFF; 64],
            &JsValue::from_str("brooklynzelenka.com"),
            Some(YEARS_LATER)
        )
        .is_err(),
        "unparseable bytes"
    );

    assert!(
        verify_certificate(&[], &JsValue::from_str("brooklynzelenka.com"), None).is_err(),
        "no bytes at all"
    );
}

#[wasm_bindgen_test]
fn a_non_string_hostname_is_a_plain_error() {
    // Not `RuntimeError: memory access out of bounds`: the parameter
    // is a JsValue precisely so untyped callers get a real message.
    let error =
        verify_certificate(CERT, &JsValue::from_f64(42.0), None).expect_err("42 is not a hostname");

    let value: JsValue = error.into();
    let message = value
        .unchecked_into::<js_sys::Error>()
        .message()
        .as_string()
        .unwrap_or_default();

    assert!(
        message.contains("must be a string"),
        "expected a type error, got: {message}"
    );
}
