//! The `Name` binding: parsed edgenames for JavaScript.

use onomancy_dnssec::supported_name::SupportedName;
use wasm_bindgen::prelude::*;

/// A parsed edgename (see `onomancy_dnssec::supported_name::SupportedName`).
#[wasm_bindgen(js_name = Name)]
#[derive(Debug, Clone)]
pub struct JsName(SupportedName);

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
        Ok(Self(SupportedName::parse(raw)?))
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
        match self.0 {
            SupportedName::Local(_) => "local".into(),
            SupportedName::Dns(_) => "dns".into(),
            SupportedName::Doc(_) => "doc".into(),
        }
    }

    /// The anchor in printed form (`~`, `@expede.wtf`, or `automerge:…`).
    #[wasm_bindgen(getter)]
    #[must_use]
    pub fn anchor(&self) -> String {
        self.0.anchor_string()
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
}
