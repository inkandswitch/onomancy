//! Wasm/JavaScript bindings for Onomancer (the Onomancy reference
//! implementation).

#![forbid(unsafe_code)]

#[cfg(feature = "doh")]
pub mod doh;

use onomancy_core::name::{Name, anchor::Anchor};
use wasm_bindgen::prelude::*;

/// One-time setup for panic reporting in the browser console.
#[wasm_bindgen(start)]
pub fn setup() {
    console_error_panic_hook::set_once();
}

/// A parsed edgename (see [`onomancy_core::name::Name`]).
#[wasm_bindgen(js_name = Name)]
#[derive(Debug, Clone)]
pub struct JsName(Name);

#[wasm_bindgen(js_class = Name)]
impl JsName {
    /// Parse a raw string into a `Name`.
    ///
    /// # Errors
    ///
    /// Throws when the sigil is missing, the anchor is malformed, or any
    /// path segment is invalid.
    #[wasm_bindgen(constructor)]
    pub fn new(raw: &str) -> Result<JsName, JsError> {
        Ok(Self(Name::parse(raw)?))
    }

    /// The canonical (normalized) printed form.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn value(&self) -> String {
        self.0.to_string()
    }

    /// The trust anchor kind: `"local"`, `"dns"`, or `"doc"`.
    #[wasm_bindgen(getter, js_name = anchorKind)]
    #[must_use]
    pub fn anchor_kind(&self) -> String {
        match self.0.anchor() {
            Anchor::Local => "local".into(),
            Anchor::Dns(_) => "dns".into(),
            Anchor::Doc(_) => "doc".into(),
        }
    }

    /// The anchor in printed form (`~`, `@expede.wtf`, or `automerge:…`).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn anchor(&self) -> String {
        self.0.anchor().to_string()
    }

    /// The path segments, one edge hop each.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn segments(&self) -> Vec<String> {
        self.0
            .segments()
            .iter()
            .map(|s| s.as_str().into())
            .collect()
    }

    /// Pinned heads on the anchor document (bs58check strings). Empty
    /// for live names; only ever non-empty for `"doc"` anchors.
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn heads(&self) -> Vec<String> {
        self.0
            .heads()
            .iter()
            .map(std::string::ToString::to_string)
            .collect()
    }
}
