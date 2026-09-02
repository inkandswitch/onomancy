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
    assert_eq!(name.anchor(), "~");
    assert_eq!(name.segments(), vec!["bob".to_string(), "pics".to_string()]);
    assert_eq!(name.value(), "~/bob/pics");
    Ok(())
}

/// Names carry no version pins: heads are certificate state, so a
/// `#`-suffixed name is a parse error, not a doc anchor with extras.
#[wasm_bindgen_test]
fn doc_anchors_parse_and_version_pins_are_rejected() -> JsTestResult {
    const ANCHOR: &str = "automerge:VDTcixKK9uxrREEENGJUPLNLqJnx63hXYDA9gJ14gjVrLHosj";

    let name = JsName::new(&text(&format!("{ANCHOR}/pics")))?;

    assert_eq!(name.anchor_kind(), "doc");
    assert_eq!(name.anchor(), ANCHOR);
    assert_eq!(name.segments(), vec!["pics".to_string()]);

    assert!(
        JsName::new(&text(&format!("{ANCHOR}/pics#head"))).is_err(),
        "a version-pinned name must be a flat parse error"
    );
    Ok(())
}

#[wasm_bindgen_test]
fn garbage_is_rejected_with_a_parse_message() {
    // A dotless `@` is a flat parse error, even in JS — and a real
    // `Error` with prose, not a wasm trap or a bare throw.
    for garbage in ["@nodots/path", ""] {
        let Err(value) = JsName::new(&text(garbage)) else {
            panic!("{garbage:?} is not a name");
        };

        let message = JsValue::from(value)
            .unchecked_into::<js_sys::Error>()
            .message()
            .as_string()
            .unwrap_or_default();
        assert!(
            !message.is_empty(),
            "a parse refusal must say what is wrong"
        );
    }
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

    held.bind(&text(&root), &text("pics/best"), &text(&gallery))?;
    held.bind(&text(&gallery), &text("2026"), &text(&year))?;

    let verdict = held
        .resolve(&text(&format!("{root}/pics/best/2026")), None, None)
        .await?;

    let status = js_sys::Reflect::get(&verdict, &JsValue::from_str("status"))?;
    assert_eq!(status.as_string().as_deref(), Some("resolved"));
    let document = js_sys::Reflect::get(&verdict, &JsValue::from_str("document"))?;
    assert_eq!(document.as_string().as_deref(), Some(year.as_str()));
    Ok(())
}

/// A hop to an unheld document is the designed partial outcome.
#[wasm_bindgen_test]
async fn unsynced_targets_walk_partially() -> JsTestResult {
    use onomancy_wasm::held::JsHeldDocuments;

    let mut held = JsHeldDocuments::new();
    let root = held.create_document()?;
    let elsewhere = held.create_document()?;
    held.bind(&text(&root), &text("away"), &text(&elsewhere))?;

    // A second store holding only the root: the edge dangles there.
    let mut sparse = JsHeldDocuments::new();
    let sparse_root = sparse.create_document()?;
    sparse.bind(&text(&sparse_root), &text("away"), &text(&elsewhere))?;

    let verdict = sparse
        .resolve(&text(&format!("{sparse_root}/away/deeper")), None, None)
        .await?;

    let status = js_sys::Reflect::get(&verdict, &JsValue::from_str("status"))?;
    assert_eq!(status.as_string().as_deref(), Some("partial"));
    let reason = js_sys::Reflect::get(&verdict, &JsValue::from_str("reason"))?;
    assert_eq!(reason.as_string().as_deref(), Some("unsynced target"));

    // The declared shape's whole point: WHERE it stopped (one segment
    // consumed by the hop to `elsewhere`) and WHAT is missing (the
    // unheld document, so a caller can `holdAt` it and retry).
    let consumed = js_sys::Reflect::get(&verdict, &JsValue::from_str("consumed"))?;
    assert_eq!(consumed.as_f64(), Some(1.0));
    let target = js_sys::Reflect::get(&verdict, &JsValue::from_str("target"))?;
    assert_eq!(target.as_string().as_deref(), Some(elsewhere.as_str()));
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
    origin.bind(&text(&root), &text("over/here"), &text(&leaf))?;

    // A second tab: nothing held, so even the ROOT is an unsynced target.
    let mut other = JsHeldDocuments::new();
    let verdict = other
        .resolve(&text(&format!("{root}/over/here")), None, None)
        .await?;
    let status = js_sys::Reflect::get(&verdict, &JsValue::from_str("status"))?;
    assert_eq!(status.as_string().as_deref(), Some("partial"));
    let target = js_sys::Reflect::get(&verdict, &JsValue::from_str("target"))?;
    assert_eq!(target.as_string().as_deref(), Some(root.as_str()));

    // Carry the real bytes across (the demo does this over HTTP).
    other.hold(&text(&root), &origin.save(&text(&root))?)?;
    other.hold(&text(&leaf), &origin.save(&text(&leaf))?)?;

    let verdict = other
        .resolve(&text(&format!("{root}/over/here")), None, None)
        .await?;
    let status = js_sys::Reflect::get(&verdict, &JsValue::from_str("status"))?;
    assert_eq!(status.as_string().as_deref(), Some("resolved"));

    // The bytes carried across resolve to the same document, which is
    // the point: a namestore is the document, not a view of it.
    let document = js_sys::Reflect::get(&verdict, &JsValue::from_str("document"))?;
    assert_eq!(document.as_string().as_deref(), Some(leaf.as_str()));
    Ok(())
}

/// A name argument, owned so the call site's statement owns it.
fn text(raw: &str) -> Text {
    JsValue::from_str(raw).unchecked_into()
}

/// A loaded module says which build it is: the package version, and
/// a revision that is never empty (the builder's fallback is the
/// literal `unknown`, so an empty string would mean the plumbing
/// broke).
#[wasm_bindgen_test]
fn build_info_identifies_the_module() -> JsTestResult {
    let info = JsValue::from(onomancy_wasm::build_info());
    let get = |key: &str| js_sys::Reflect::get(&info, &JsValue::from_str(key));

    assert_eq!(
        get("version")?.as_string(),
        Some(env!("CARGO_PKG_VERSION").to_owned())
    );

    let revision = get("revision")?.as_string().unwrap_or_default();
    assert!(!revision.is_empty(), "revision is never empty");
    Ok(())
}
