//! Wasm/JavaScript bindings for Onomancer (the Onomancy reference
//! implementation).

#![forbid(unsafe_code)]

#[cfg(feature = "doh")]
pub mod doh;
#[cfg(feature = "names")]
pub mod held;
pub mod name;
#[cfg(feature = "doh")]
pub mod resolve;

use wasm_bindgen::prelude::*;

/// One-time setup for panic reporting in the browser console.
#[wasm_bindgen(start)]
pub fn setup() {
    console_error_panic_hook::set_once();
}
