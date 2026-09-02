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
#[cfg(feature = "doh")]
pub mod resolve;
pub mod verify;

use wasm_bindgen::prelude::*;

/// One-time setup for panic reporting in the browser console.
#[wasm_bindgen(start)]
pub fn setup() {
    console_error_panic_hook::set_once();
}
