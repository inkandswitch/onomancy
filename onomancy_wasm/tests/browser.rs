//! In-browser conformance for the JS bindings: the wasm module must
//! load, run, and honor the three-anchor grammar inside a REAL
//! browser (chromedriver or geckodriver via `wasm-bindgen-test-runner`
//! — see the `ci-browser` flake app).
//!
//! Network-free. The live `resolveHostname` path is `browser_live.rs`
//! (feature `live`).

#![cfg(target_arch = "wasm32")]

use onomancy_wasm::{name::JsName, text::Text};
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

/// The browser-side analogue of `TestResult`: `?` on any JS-facing
/// failure fails the test.
type JsTestResult = Result<(), JsValue>;

#[wasm_bindgen_test]
fn dns_anchors_parse() -> JsTestResult {
    let name = JsName::new(&text("@expede.wtf/foo/bar"))?;

    assert_eq!(name.anchor_kind(), "dns");
    assert_eq!(name.anchor(), "@expede.wtf");
    assert_eq!(name.segments(), vec!["foo".to_string(), "bar".to_string()]);
    Ok(())
}

#[wasm_bindgen_test]
fn local_anchors_parse() -> JsTestResult {
    let name = JsName::new(&text("~/bob/pics"))?;

    assert_eq!(name.anchor_kind(), "local");
    Ok(())
}

#[wasm_bindgen_test]
fn doc_anchors_parse_with_heads() -> JsTestResult {
    let name = JsName::new(&text(
        "automerge:VDTcixKK9uxrREEENGJUPLNLqJnx63hXYDA9gJ14gjVrLHosj/pics",
    ))?;

    assert_eq!(name.anchor_kind(), "doc");
    assert_eq!(name.segments(), vec!["pics".to_string()]);
    Ok(())
}

#[wasm_bindgen_test]
fn garbage_is_rejected() {
    // A dotless `@` is a flat parse error, even in JS.
    assert!(JsName::new(&text("@nodots/path")).is_err());
    assert!(JsName::new(&text("")).is_err());
}

/// Documents naming documents, entirely in-tab: mint three docs,
/// wire two edges, and walk a doc-anchored name across them.
#[wasm_bindgen_test]
async fn held_documents_resolve_names_across_documents() -> JsTestResult {
    use onomancy_wasm::held::JsHeldDocuments;

    let mut held = JsHeldDocuments::new();
    let root = held.create_document()?;
    let gallery = held.create_document()?;
    let year = held.create_document()?;

    held.set_note(&year, "🎉")?;
    held.bind(&root, "pics/best", &gallery)?;
    held.bind(&gallery, "2026", &year)?;

    let verdict = held
        .resolve(&format!("{root}/pics/best/2026"), None, None)
        .await?;

    let status = js_sys::Reflect::get(&verdict, &JsValue::from_str("status"))?;
    assert_eq!(status.as_string().as_deref(), Some("resolved"));
    let document = js_sys::Reflect::get(&verdict, &JsValue::from_str("document"))?;
    assert_eq!(document.as_string().as_deref(), Some(year.as_str()));
    let note = js_sys::Reflect::get(&verdict, &JsValue::from_str("note"))?;
    assert_eq!(note.as_string().as_deref(), Some("🎉"));
    Ok(())
}

/// A hop to an unheld document is the designed partial outcome.
#[wasm_bindgen_test]
async fn unsynced_targets_walk_partially() -> JsTestResult {
    use onomancy_wasm::held::JsHeldDocuments;

    let mut held = JsHeldDocuments::new();
    let root = held.create_document()?;
    let elsewhere = held.create_document()?;
    held.bind(&root, "away", &elsewhere)?;

    // A second store holding only the root: the edge dangles there.
    let mut sparse = JsHeldDocuments::new();
    let sparse_root = sparse.create_document()?;
    sparse.bind(&sparse_root, "away", &elsewhere)?;

    let verdict = sparse
        .resolve(&format!("{sparse_root}/away/deeper"), None, None)
        .await?;

    let status = js_sys::Reflect::get(&verdict, &JsValue::from_str("status"))?;
    assert_eq!(status.as_string().as_deref(), Some("partial"));
    let reason = js_sys::Reflect::get(&verdict, &JsValue::from_str("reason"))?;
    assert_eq!(reason.as_string().as_deref(), Some("unsynced target"));
    Ok(())
}

/// Real document bytes round-trip through save → hold, and an unheld
/// ROOT reports the same structured partial as any unsynced hop.
#[wasm_bindgen_test]
async fn saved_documents_rehold_and_unheld_roots_are_partials() -> JsTestResult {
    use onomancy_wasm::held::JsHeldDocuments;

    let mut origin = JsHeldDocuments::new();
    let root = origin.create_document()?;
    let leaf = origin.create_document()?;
    origin.set_note(&leaf, "carried across")?;
    origin.bind(&root, "over/here", &leaf)?;

    // A second tab: nothing held, so even the ROOT is an unsynced target.
    let mut other = JsHeldDocuments::new();
    let verdict = other
        .resolve(&format!("{root}/over/here"), None, None)
        .await?;
    let status = js_sys::Reflect::get(&verdict, &JsValue::from_str("status"))?;
    assert_eq!(status.as_string().as_deref(), Some("partial"));
    let target = js_sys::Reflect::get(&verdict, &JsValue::from_str("target"))?;
    assert_eq!(target.as_string().as_deref(), Some(root.as_str()));

    // Carry the real bytes across (the demo does this over HTTP).
    other.hold(&root, &origin.save(&root)?)?;
    other.hold(&leaf, &origin.save(&leaf)?)?;

    let verdict = other
        .resolve(&format!("{root}/over/here"), None, None)
        .await?;
    let status = js_sys::Reflect::get(&verdict, &JsValue::from_str("status"))?;
    assert_eq!(status.as_string().as_deref(), Some("resolved"));
    let note = js_sys::Reflect::get(&verdict, &JsValue::from_str("note"))?;
    assert_eq!(note.as_string().as_deref(), Some("carried across"));
    Ok(())
}

/// A name argument, owned so the call site's statement owns it.
fn text(raw: &str) -> Text {
    JsValue::from_str(raw).unchecked_into()
}
