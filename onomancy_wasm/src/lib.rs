//! Wasm/JavaScript bindings for Onomancer (the Onomancy reference
//! implementation).

#![forbid(unsafe_code)]

// Unconditional: both `verify` (always present) and `resolve`
// (behind `doh`) grade against it.
pub mod clock;
pub mod refusal;
pub mod shapes;
pub mod text;

#[cfg(feature = "doh")]
pub mod doh;
#[cfg(feature = "names")]
pub mod held;
pub mod issue;
pub mod name;
pub mod records;
#[cfg(feature = "doh")]
pub mod resolve;
pub mod verify;

use js_sys::{Object, Reflect};
use wasm_bindgen::prelude::*;

/// One-time setup for panic reporting in the browser console.
#[wasm_bindgen(start)]
pub fn setup() {
    console_error_panic_hook::set_once();
}

/// The package version this module was built as.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The source revision this module was built from: a short commit
/// hash, `-dirty` when the tree had uncommitted changes, or `unknown`
/// when the builder supplied nothing.
pub const REVISION: &str = env!("ONOMANCY_GIT_REV");

/// Identify this build: `{ version, revision }`.
///
/// The version alone does not identify an artifact — two builds can
/// share one — and nothing else in a workspace-built module names its
/// source, so this is the only reliable way to tell which bytes are
/// loaded.
#[wasm_bindgen(js_name = buildInfo)]
#[must_use]
pub fn build_info() -> shapes::JsBuildInfo {
    let object = Object::new();

    for (key, value) in [("version", VERSION), ("revision", REVISION)] {
        // Reflect::set on a fresh plain object cannot fail.
        drop(Reflect::set(
            &object,
            &JsValue::from_str(key),
            &JsValue::from_str(value),
        ));
    }

    JsValue::from(object).into()
}
