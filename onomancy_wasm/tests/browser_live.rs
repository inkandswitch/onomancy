//! The full `DoH` walk inside a real browser, against production DNS —
//! the automated version of the demo page. Behind the `live` feature:
//! `cargo test -p onomancy_wasm --target wasm32-unknown-unknown
//! --features live`.

#![cfg(all(target_arch = "wasm32", feature = "live"))]

use js_sys::Reflect;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn the_first_bound_name_resolves_fresh_in_the_browser() -> Result<(), JsValue> {
    let verdict = onomancy_wasm::doh::resolve_hostname("brooklynzelenka.com", None).await?;
    let freshness = Reflect::get(&verdict, &JsValue::from_str("freshness"))?;

    assert_eq!(freshness.as_string().as_deref(), Some("fresh"));
    Ok(())
}
