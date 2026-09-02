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
// House pattern for test code (see `certificates.rs`, `namestore.rs`):
// a failed `expect` here is the test failing, which is its job.
#![allow(clippy::expect_used, clippy::panic)]

use onomancy_wasm::{
    held::JsHeldDocuments,
    text::Text,
    verify::{verify_binding, verify_certificate},
};
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_test::wasm_bindgen_test;

/// The production capture, with a real delegation carriage attached.
/// Referenced rather than copied: the fixtures README pins these as
/// frozen captures ("do not regenerate"), so one source of truth.
const CERT: &[u8] =
    include_bytes!("../../onomancy_dnssec/tests/fixtures/real_brooklynzelenka_carriage.onc");

/// Well after the chain's RRSIG windows lapsed — the certificate is
/// stale, which is a risk signal and never a forgery signal.
///
/// In **seconds**, as the parameter is named — the constant asserts
/// the declared contract, never whatever scaling an implementation
/// happens to apply. A milliseconds constant would certify a
/// milliseconds bug instead of catching it.
const YEARS_LATER: f64 = 1_788_100_000.0;

/// One second before this certificate's chain window opens
/// (inception `1787201748`) — the deferral case.
const BEFORE_INCEPTION: f64 = 1_787_201_747.0;

/// The `record`-made capture: a real certificate with an EMPTY
/// delegation carriage, so its attested generation key is on no path.
const OFF_PATH_CERT: &[u8] =
    include_bytes!("../../onomancy_dnssec/tests/fixtures/real_brooklynzelenka.onc");

/// Inside that certificate's window (`1787241600` → `1787355259`),
/// where an off-path generation is refused outright.
const MID_OFF_PATH_WINDOW: f64 = 1_787_300_000.0;

/// Past it, where the same condition is only `provisional`.
const AFTER_OFF_PATH_WINDOW: f64 = 1_787_400_000.0;

/// A hostname argument. The published type is `string`, so the cast
/// is what a TypeScript caller gets for free at compile time and a
/// JavaScript one gets checked at runtime.
///
/// Returned owned so the caller's statement owns the temporary:
/// borrowing one out of here would need a leak to outlive the call,
/// which is a memory bug wearing a lifetime fix's clothing.
fn host(raw: &str) -> Text {
    JsValue::from_str(raw).unchecked_into()
}

fn field(verdict: &JsValue, key: &str) -> String {
    js_sys::Reflect::get(verdict, &JsValue::from_str(key))
        .ok()
        .and_then(|value| value.as_string())
        .unwrap_or_default()
}

/// The machine-readable code on a refusal — the discriminator the
/// published contract promises (`"reason" in error`).
fn reason_of(value: &JsValue) -> String {
    js_sys::Reflect::get(value, &JsValue::from_str("reason"))
        .ok()
        .and_then(|value| value.as_string())
        .expect("a substantive refusal carries a reason")
}

/// A held-document set whose one document carries `CERT` at the
/// reserved well-known path — what a verifier that replicated the
/// bound document actually holds.
fn held_with_certificate() -> (JsHeldDocuments, Text) {
    let cert = onomancy_dnssec::certificate::Certificate::decode(CERT)
        .expect("the frozen capture decodes");
    let anchor = format!("automerge:{}", cert.root_doc());

    let mut doc = automerge::Automerge::new();
    onomancy_automerge::certificates::put(&mut doc, &cert).expect("stored at the reserved key");

    let mut held = JsHeldDocuments::new();
    held.hold(&host(&anchor), &doc.save()).expect("held");

    (held, host(&anchor))
}

#[wasm_bindgen_test]
fn a_real_certificate_verifies_inside_the_module() {
    let verdict = verify_certificate(CERT, &host("brooklynzelenka.com"), Some(YEARS_LATER))
        .expect("the production certificate verifies");

    assert_eq!(
        field(&verdict, "document"),
        "automerge:VDTcixKK9uxrREEENGJUPLNLqJnx63hXYDA9gJ14gjVrLHosj",
        "the document the zone named, spelled as the declared `automerge:` \
         anchor — round-trippable into `new Name(document)`"
    );
    assert_eq!(field(&verdict, "hostname"), "brooklynzelenka.com");
    assert_eq!(field(&verdict, "serial"), "1787291588428");

    // Stale, because the captured chain's windows have lapsed. Never
    // invalid: staleness is about age, not authenticity.
    assert_eq!(field(&verdict, "freshness"), "stale");

    // The half a DNSSEC walk cannot do: the signer's authority
    // threads the attested generation key, checked by replaying the
    // carriage into a throwaway Keyhive instance.
    assert_eq!(field(&verdict, "generation"), "on-path");
}

#[wasm_bindgen_test]
fn the_grading_inputs_come_back_with_the_grade() {
    let verdict = verify_certificate(CERT, &host("brooklynzelenka.com"), Some(YEARS_LATER))
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

    // `now_seconds` is seconds and `checkedAt` is seconds, so a
    // supplied clock must round-trip identically. Any scaling in
    // between is a bug, whichever direction it goes.
    //
    // Compared as integers: these are epoch seconds that merely
    // travel as `f64` across the JS boundary, so float equality
    // would be asserting the wrong thing about the right values.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // epoch seconds fit
    let (checked, expected) = (checked_at as u64, YEARS_LATER as u64);

    assert_eq!(checked, expected, "the supplied clock must round-trip");
}

#[wasm_bindgen_test]
fn a_certificate_for_another_hostname_is_refused() {
    let Err(refused) = verify_certificate(CERT, &host("example.com"), Some(YEARS_LATER)) else {
        panic!("a certificate binds one hostname and says so in its signature");
    };

    // The CODE, not just "some error": retargeting this arm to a
    // security-signal reason must fail here, not ship.
    assert_eq!(reason_of(&refused), "hostname-mismatch");
}

#[wasm_bindgen_test]
fn garbage_is_refused_without_panicking() {
    let Err(refused) =
        verify_certificate(&[0xFF; 64], &host("brooklynzelenka.com"), Some(YEARS_LATER))
    else {
        panic!("unparsable bytes");
    };

    // A wiring bug, not a forgery: `malformed`, never a security
    // signal.
    assert_eq!(reason_of(&refused), "malformed");

    // No bytes at all is the same class of wiring bug.
    let Err(empty) = verify_certificate(&[], &host("brooklynzelenka.com"), None) else {
        panic!("no bytes at all");
    };
    assert_eq!(reason_of(&empty), "malformed");
}

#[wasm_bindgen_test]
fn a_non_string_hostname_is_a_plain_error() {
    // Not `RuntimeError: memory access out of bounds`: the parameter
    // is a JsValue precisely so untyped callers get a real message.
    let Err(value) = verify_certificate(CERT, JsValue::from_f64(42.0).unchecked_ref(), None) else {
        panic!("42 is not a hostname");
    };

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

/// The third grade, as a value rather than a throw.
///
/// Before this, `deferred` was the one freshness state a caller could
/// not read from the returned object — it arrived as an exception,
/// so a three-state type wired to this function silently never saw
/// it. Graded before the chain's window opens.
#[wasm_bindgen_test]
fn a_not_yet_valid_chain_grades_deferred_rather_than_throwing() {
    let verdict = verify_certificate(CERT, &host("brooklynzelenka.com"), Some(BEFORE_INCEPTION))
        .expect("deferral is a grade, not a refusal");

    assert_eq!(field(&verdict, "freshness"), "deferred");

    // Proven, just not in force: the binding is still reported.
    assert_eq!(
        field(&verdict, "document"),
        "automerge:VDTcixKK9uxrREEENGJUPLNLqJnx63hXYDA9gJ14gjVrLHosj"
    );

    // The generation-path check was never reached, and `null` says so where a
    // missing key could not.
    assert!(
        js_sys::Reflect::get(&verdict, &JsValue::from_str("generation"))
            .expect("generation")
            .is_null(),
        "generation must be null when the check was not made"
    );

    // The claim is "usually a clock difference" — these are what let
    // a caller check that rather than believe it.
    let window = js_sys::Reflect::get(&verdict, &JsValue::from_str("window")).expect("window");
    let inception = js_sys::Reflect::get(&window, &JsValue::from_str("inception"))
        .ok()
        .and_then(|value| value.as_f64())
        .expect("inception");

    assert!(
        BEFORE_INCEPTION < inception,
        "deferred means the clock has not reached the window"
    );
}

/// Revocation must not be mistakable for a network fault.
///
/// An off-path generation on a FRESH chain is the zone saying the key
/// was rotated away — revocation working as designed. Thrown, because
/// there is no verdict; but a `catch` that reads every exception as a
/// transport failure would tell the user to retry, which is precisely
/// the wrong remedy. The `reason` property is what makes the two
/// distinguishable without parsing prose.
#[wasm_bindgen_test]
fn a_revoked_generation_is_refused_with_a_machine_readable_reason() {
    // The `record`-made fixture: no carriage, so the attested
    // generation key lies on no path. Graded inside its own window,
    // where strictness is highest.
    let Err(value) = verify_certificate(
        OFF_PATH_CERT,
        &host("brooklynzelenka.com"),
        Some(MID_OFF_PATH_WINDOW),
    ) else {
        panic!("a fresh chain with an off-path generation is refused");
    };

    let reason = js_sys::Reflect::get(&value, &JsValue::from_str("reason"))
        .ok()
        .and_then(|value| value.as_string())
        .expect("a substantive refusal carries a reason");

    assert_eq!(reason, "generation-off-path");

    // And the prose still explains it to a person.
    let message = value
        .unchecked_into::<js_sys::Error>()
        .message()
        .as_string()
        .unwrap_or_default();

    assert!(
        message.contains("rotated away"),
        "the message should name revocation: {message}"
    );
}

/// The same bytes, past their window, are a grade rather than a
/// refusal — the inversion, asserted so it cannot silently flip.
#[wasm_bindgen_test]
fn the_same_certificate_is_provisional_once_stale() {
    let verdict = verify_certificate(
        OFF_PATH_CERT,
        &host("brooklynzelenka.com"),
        Some(AFTER_OFF_PATH_WINDOW),
    )
    .expect("stale evidence is unrefreshed, not authoritative");

    assert_eq!(field(&verdict, "freshness"), "stale");
    assert_eq!(field(&verdict, "generation"), "provisional");
}

/// `verifyBinding` over a held document must agree with
/// `verifyCertificate` over the same bytes: the document route reads
/// the certificate out of the reserved well-known path and judges it
/// with the same verifier.
#[wasm_bindgen_test]
fn verify_binding_agrees_with_verify_certificate() {
    let (held, anchor) = held_with_certificate();

    let from_document = verify_binding(
        &held,
        &anchor,
        &host("brooklynzelenka.com"),
        Some(YEARS_LATER),
    )
    .expect("the stored certificate verifies");
    let from_bytes = verify_certificate(CERT, &host("brooklynzelenka.com"), Some(YEARS_LATER))
        .expect("the same bytes verify");

    for key in ["document", "hostname", "serial", "freshness", "generation"] {
        assert_eq!(
            field(&from_document, key),
            field(&from_bytes, key),
            "`{key}` must not depend on which entry point judged the evidence"
        );
    }
}

/// An empty or unheld document is absence, not refutation — and the
/// code says which: `no-certificate-held`, never a security signal.
#[wasm_bindgen_test]
fn an_empty_document_is_absence_with_its_own_code() {
    let cert = onomancy_dnssec::certificate::Certificate::decode(CERT).expect("decodes");
    let anchor = format!("automerge:{}", cert.root_doc());

    let mut held = JsHeldDocuments::new();
    held.hold(&host(&anchor), &automerge::Automerge::new().save())
        .expect("held");

    let Err(refused) = verify_binding(
        &held,
        &host(&anchor),
        &host("brooklynzelenka.com"),
        Some(YEARS_LATER),
    ) else {
        panic!("an empty document holds no certificate");
    };
    assert_eq!(reason_of(&refused), "no-certificate-held");

    // Unheld is the same absence arriving one lookup earlier.
    let Err(unheld) = verify_binding(
        &JsHeldDocuments::new(),
        &host(&anchor),
        &host("brooklynzelenka.com"),
        Some(YEARS_LATER),
    ) else {
        panic!("an unheld document holds no certificate");
    };
    assert_eq!(reason_of(&unheld), "no-certificate-held");
}

/// A document that binds OTHER hostnames is honest absence for this
/// one: `hostname-mismatch` is a security signal about a unit, not
/// the answer to "does this document bind that name".
#[wasm_bindgen_test]
fn another_hostnames_certificate_is_absence_not_a_mismatch() {
    let (held, anchor) = held_with_certificate();

    let Err(refused) = verify_binding(&held, &anchor, &host("example.com"), Some(YEARS_LATER))
    else {
        panic!("this document holds no certificate for example.com");
    };

    assert_eq!(reason_of(&refused), "no-certificate-held");
}

/// Selection is order-insensitive: a stale certificate stored at
/// index 0 must not mask a fresh one at index 1. The two frozen
/// captures overlap so that at this instant one is stale
/// (`real_brooklynzelenka`, window ends 1787355259) and the other
/// fresh (`…_carriage`, window ends 1787381748) — a
/// first-that-verifies loop would let list order pick the verdict,
/// which is what this pins against.
#[wasm_bindgen_test]
fn a_stale_certificate_first_in_the_list_does_not_mask_a_fresh_one() {
    const BOTH_HELD_ONE_FRESH: f64 = 1_787_360_000.0;

    let stale_first = onomancy_dnssec::certificate::Certificate::decode(OFF_PATH_CERT)
        .expect("the record-made capture decodes");
    let fresh_second = onomancy_dnssec::certificate::Certificate::decode(CERT)
        .expect("the carriage capture decodes");
    let anchor = format!("automerge:{}", fresh_second.root_doc());

    let mut doc = automerge::Automerge::new();
    onomancy_automerge::certificates::put(&mut doc, &stale_first).expect("stored at index 0");
    onomancy_automerge::certificates::put(&mut doc, &fresh_second).expect("stored at index 1");

    let mut held = JsHeldDocuments::new();
    held.hold(&host(&anchor), &doc.save()).expect("held");

    let verdict = verify_binding(
        &held,
        &host(&anchor),
        &host("brooklynzelenka.com"),
        Some(BOTH_HELD_ONE_FRESH),
    )
    .expect("both certificates verify; the ladder picks");

    assert_eq!(
        field(&verdict, "freshness"),
        "fresh",
        "the fresh candidate must win whatever its list position"
    );
    assert_eq!(
        field(&verdict, "serial"),
        "1787291588428",
        "and it is the carriage capture's verdict, not the stale one's"
    );
}

/// A certificate entry that is neither a list nor a reference refuses
/// with `broken-indirection` — a stable fact about the document, not
/// `malformed` (nothing needs re-minting) and not a bare throw.
///
/// Reachable by an application writing its own data at the reserved
/// key, which no library call polices: the prefix is a writers'
/// convention.
#[wasm_bindgen_test]
fn a_clobbered_certificate_entry_names_the_pointer_problem() {
    use automerge::transaction::Transactable as _;
    use onomancy_wasm::held::JsHeldDocuments;

    let mut doc = automerge::Automerge::new();
    doc.transact::<_, _, automerge::AutomergeError>(|tx| {
        // An app's own write at the reserved key: legal, unpoliced,
        // and neither a certificate list nor a reference.
        tx.put(
            automerge::ROOT,
            onomancy_automerge::certificates::CERTIFICATES_KEY,
            42,
        )?;
        Ok(())
    })
    .expect("build");

    let mut held = JsHeldDocuments::new();
    let anchor = "automerge:2nBeEMDjAzFa9Ev2pxwejYrgCRmSLx96SbA24uhdMMTUktJWvK";
    held.hold(&host(anchor), &doc.save()).expect("held");

    let Err(refusal) = onomancy_wasm::verify::verify_binding(
        &held,
        &host(anchor),
        &host("example.com"),
        Some(1_788_100_000.0),
    ) else {
        panic!("a clobbered entry cannot verify");
    };

    let reason = js_sys::Reflect::get(&refusal, &JsValue::from_str("reason"))
        .ok()
        .and_then(|value| value.as_string())
        .expect("a substantive refusal carries a reason");

    assert_eq!(reason, "broken-indirection");
}

/// Deferral has TWO causes, and `verifyBinding` grades both as
/// deferred rather than erroring: a window not yet open, and a serial
/// beyond the clock's skew bound.
///
/// At this instant the record capture's window has not opened
/// (window-deferral) and the carriage capture's serial — a mint-time
/// timestamp in milliseconds — reads ~71,000 s in the future
/// (serial-deferral). Both defer, so the verdict is deferred; the
/// serial case previously reached JS only through `verifyCertificate`.
///
/// This exists in place of a deferred-vs-accepted contest, which the
/// fixtures cannot stage: for the record capture to window-defer the
/// clock must sit before `1_787_241_600`, and by then the carriage
/// capture's serial (`1_787_291_588_428` ms) is far-future — the two
/// deferral rules overlap so that no instant leaves exactly one
/// candidate standing. The rank claim itself is pinned by a unit test
/// on `freshness_rank`, the function the selection key calls.
#[wasm_bindgen_test]
fn both_deferral_causes_grade_deferred_through_a_held_document() {
    /// After the carriage capture's inception (1_787_201_748), before
    /// the record capture's (1_787_241_600) — and before both serials.
    const BEFORE_EVERYTHING_SETTLES: f64 = 1_787_220_000.0;

    let window_deferred = onomancy_dnssec::certificate::Certificate::decode(OFF_PATH_CERT)
        .expect("the record-made capture decodes");
    let serial_deferred = onomancy_dnssec::certificate::Certificate::decode(CERT)
        .expect("the carriage capture decodes");
    let anchor = format!("automerge:{}", serial_deferred.root_doc());

    let mut doc = automerge::Automerge::new();
    onomancy_automerge::certificates::put(&mut doc, &window_deferred).expect("stored at index 0");
    onomancy_automerge::certificates::put(&mut doc, &serial_deferred).expect("stored at index 1");

    let mut held = JsHeldDocuments::new();
    held.hold(&host(&anchor), &doc.save()).expect("held");

    let verdict = verify_binding(
        &held,
        &host(&anchor),
        &host("brooklynzelenka.com"),
        Some(BEFORE_EVERYTHING_SETTLES),
    )
    .expect("deferral is a grade, not a refusal, whichever rule caused it");

    assert_eq!(field(&verdict, "freshness"), "deferred");

    // Proven evidence, not in force: the binding is still reported…
    assert_eq!(
        field(&verdict, "document"),
        "automerge:VDTcixKK9uxrREEENGJUPLNLqJnx63hXYDA9gJ14gjVrLHosj"
    );

    // …and the D10 check was never made, which `null` says.
    assert!(
        js_sys::Reflect::get(&verdict, &JsValue::from_str("generation"))
            .expect("generation")
            .is_null()
    );
}
