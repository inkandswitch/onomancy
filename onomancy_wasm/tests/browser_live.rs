//! The full `DoH` walk inside a real browser, against production DNS —
//! the automated version of the demo page. Behind the `live` feature:
//! `cargo test -p onomancy_wasm --target wasm32-unknown-unknown
//! --features live`.

#![cfg(all(target_arch = "wasm32", feature = "live"))]

use js_sys::Reflect;
use onomancy_wasm::text::Text;
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn the_first_bound_name_resolves_fresh_in_the_browser() -> Result<(), JsValue> {
    let verdict =
        onomancy_wasm::resolve::resolve_hostname(&name("brooklynzelenka.com"), None, None).await?;
    let freshness = Reflect::get(&verdict, &JsValue::from_str("freshness"))?;

    assert_eq!(freshness.as_string().as_deref(), Some("fresh"));

    // Not just the label: the proof carried records and links, and
    // the chain bytes are present — the field browser minting
    // actually depends on (`encodeCertificate` embeds them).
    let records = Reflect::get(&verdict, &JsValue::from_str("records"))?;
    assert!(
        js_sys::Array::from(&records).length() > 0,
        "a fresh verdict proves at least one record"
    );

    let links = Reflect::get(&verdict, &JsValue::from_str("links"))?;
    assert!(links.as_f64().unwrap_or_default() > 0.0, "links counted");

    let chain = Reflect::get(&verdict, &JsValue::from_str("chain"))?;
    assert!(
        js_sys::Uint8Array::new(&chain).length() > 0,
        "the validated chain rides along for minting"
    );
    Ok(())
}

/// A hostname argument, owned so the call site's statement owns it.
fn name(raw: &str) -> Text {
    JsValue::from_str(raw).unchecked_into()
}
