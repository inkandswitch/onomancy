//! The exported TXT record rules, as JavaScript sees them: the
//! published object shapes, the string-typed serials, and the reason
//! codes on refusal. The rules themselves are tested on the host in
//! `records.rs`; this pins the boundary.

#![cfg(target_arch = "wasm32")]
// House pattern for test code: a failed `expect` here is the test
// failing, which is its job.
#![allow(clippy::expect_used, clippy::panic)]

use ed25519_dalek::SigningKey;
use js_sys::{Array, Reflect};
use onomancy_core::anchor::doc::DocAnchor;
use onomancy_dnssec::txt::{generation_key::GenerationKey, record::TxtRecord, serial::Serial};
use onomancy_wasm::{
    records::{classify_records, next_serial},
    text::Text,
};
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

const NOW_SECS: f64 = 1_787_266_968.0;

fn text(raw: &str) -> Text {
    JsValue::from_str(raw).unchecked_into()
}

fn record(serial: u64, generation: u8, document: u8) -> Text {
    let key = |seed: u8| SigningKey::from_bytes(&[seed; 32]).verifying_key();

    text(
        &TxtRecord::new(
            Serial::from(serial),
            GenerationKey::from(key(generation)),
            DocAnchor::from(key(document)),
        )
        .to_string(),
    )
}

fn get(object: &JsValue, key: &str) -> JsValue {
    Reflect::get(object, &JsValue::from_str(key)).expect("a plain object")
}

fn reason(error: &JsValue) -> String {
    get(error, "reason")
        .as_string()
        .expect("a substantive refusal carries a reason")
}

#[wasm_bindgen_test]
fn next_serial_is_a_decimal_string_past_the_floor() {
    assert_eq!(
        next_serial(None, Some(1_000.0)).expect("first binding"),
        "1000"
    );
    assert_eq!(
        next_serial(Some(text("5000")), Some(1_000.0)).expect("floor wins"),
        "5001"
    );
    assert_eq!(
        next_serial(Some(text("5000")), Some(9_000.0)).expect("clock wins"),
        "9000"
    );
}

/// Serials above 2^53 survive the boundary because they never become
/// a JavaScript `number`.
#[wasm_bindgen_test]
fn next_serial_keeps_u64_precision() {
    let big = "18446744073709551614"; // u64::MAX - 1

    assert_eq!(
        next_serial(Some(text(big)), Some(0.0)).expect("one below the ceiling"),
        "18446744073709551615"
    );
}

#[wasm_bindgen_test]
fn next_serial_refusals_are_argument_problems() {
    for (last, now_ms) in [
        (Some("18446744073709551615"), Some(0.0)), // exhausted
        (Some("007"), Some(0.0)),                  // not canonical
        (Some("abc"), Some(0.0)),
        (Some("1"), Some(-1.0)),
        (Some("1"), Some(1.5)),
        (Some("1"), Some(f64::NAN)),
    ] {
        let refused = next_serial(last.map(text), now_ms).expect_err("refused");
        assert_eq!(
            reason(&refused),
            "invalid-argument",
            "{last:?} @ {now_ms:?}"
        );
    }
}

#[wasm_bindgen_test]
fn a_classification_publishes_the_declared_shape() {
    let outcome = classify_records(
        vec![
            text("v=spf1 -all"),
            text("v=ONO9;future"),
            text("v=ONO0;k=ed25519;n=1;g=;p="),
            record(7, 1, 1),
            record(9, 1, 2),
        ],
        Some(NOW_SECS),
    )
    .expect("classified");
    let outcome = JsValue::from(outcome);

    assert_eq!(get(&outcome, "foreign").as_f64(), Some(1.0));
    assert_eq!(get(&outcome, "unknownVersion").as_f64(), Some(1.0));
    assert_eq!(get(&outcome, "malformed").as_f64(), Some(1.0));
    assert_eq!(get(&outcome, "deferred").as_f64(), Some(0.0));
    assert!(get(&outcome, "contested").is_undefined());

    let selected = get(&outcome, "selected");
    assert_eq!(get(&selected, "serial").as_string().as_deref(), Some("9"));
    assert!(
        get(&selected, "document")
            .as_string()
            .expect("string")
            .starts_with("automerge:")
    );
    assert_eq!(
        get(&selected, "generation").as_string().map(|g| g.len()),
        Some(44)
    );
}

#[wasm_bindgen_test]
fn a_contest_is_an_array_and_no_selection() {
    let outcome = classify_records(vec![record(9, 1, 1), record(9, 2, 1)], Some(NOW_SECS))
        .expect("classified");
    let outcome = JsValue::from(outcome);

    assert!(get(&outcome, "selected").is_undefined());
    let contested: Array = get(&outcome, "contested").unchecked_into();
    assert_eq!(contested.length(), 2);
}

#[wasm_bindgen_test]
fn a_millisecond_clock_is_refused_with_its_code() {
    let refused = classify_records(vec![record(1, 1, 1)], Some(NOW_SECS * 1000.0))
        .map(drop)
        .expect_err("Date.now() is not seconds");

    assert_eq!(reason(&refused), "invalid-timestamp");
}

/// A non-string element is a type error: reasonless, per the contract.
#[wasm_bindgen_test]
fn a_non_string_record_is_a_type_error() {
    let not_a_string: Text = JsValue::from_f64(1.0).unchecked_into();
    let refused = classify_records(vec![not_a_string], Some(NOW_SECS))
        .map(drop)
        .expect_err("type error");

    assert!(get(&refused, "reason").is_undefined());
}
