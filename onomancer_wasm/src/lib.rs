//! Wasm/JavaScript bindings for Onomancer.

#![forbid(unsafe_code)]

use onomancer_core::name::Name;
use wasm_bindgen::prelude::*;

/// One-time setup for panic reporting in the browser console.
#[wasm_bindgen(start)]
pub fn setup() {
    console_error_panic_hook::set_once();
}

/// A validated name (see [`onomancer_core::name::Name`]).
#[wasm_bindgen(js_name = Name)]
#[derive(Debug, Clone)]
pub struct JsName(Name);

#[wasm_bindgen(js_class = Name)]
impl JsName {
    /// Parse a raw string into a `Name`, trimming surrounding whitespace.
    ///
    /// # Errors
    ///
    /// Throws if the trimmed input is empty.
    #[wasm_bindgen(constructor)]
    pub fn new(raw: &str) -> Result<JsName, JsError> {
        Ok(Self(Name::parse(raw)?))
    }

    /// The underlying string.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn value(&self) -> String {
        self.0.as_str().into()
    }
}
