//! In-browser conformance for the JS bindings: the wasm module must
//! load, run, and honor the three-anchor grammar inside a REAL
//! browser (chromedriver or geckodriver via `wasm-bindgen-test-runner`
//! — see the `ci-browser` flake app).
//!
//! Network-free. The live `resolveHostname` path is `browser_live.rs`
//! (feature `live`).

#![cfg(target_arch = "wasm32")]

use onomancy_wasm::JsName;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

/// The browser-side analogue of `TestResult`: `?` on any JS-facing
/// failure fails the test.
type JsTestResult = Result<(), JsValue>;

#[wasm_bindgen_test]
fn dns_anchors_parse() -> JsTestResult {
    let name = JsName::new("@expede.wtf/foo/bar")?;

    assert_eq!(name.anchor_kind(), "dns");
    assert_eq!(name.anchor(), "@expede.wtf");
    assert_eq!(name.segments(), vec!["foo".to_string(), "bar".to_string()]);
    Ok(())
}

#[wasm_bindgen_test]
fn local_anchors_parse() -> JsTestResult {
    let name = JsName::new("~/bob/pics")?;

    assert_eq!(name.anchor_kind(), "local");
    Ok(())
}

#[wasm_bindgen_test]
fn doc_anchors_parse_with_heads() -> JsTestResult {
    let name = JsName::new("automerge:VDTcixKK9uxrREEENGJUPLNLqJnx63hXYDA9gJ14gjVrLHosj/pics")?;

    assert_eq!(name.anchor_kind(), "doc");
    assert_eq!(name.segments(), vec!["pics".to_string()]);
    Ok(())
}

#[wasm_bindgen_test]
fn garbage_is_rejected() {
    // A dotless `@` is a flat parse error (ADR-017), even in JS.
    assert!(JsName::new("@nodots/path").is_err());
    assert!(JsName::new("").is_err());
}
