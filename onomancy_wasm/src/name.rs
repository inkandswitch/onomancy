//! The `Name` binding: parsed edgenames for JavaScript.

use crate::text::{self, Text};
use onomancy_core::anchor::doc::{DocAnchor, SCHEME_PREFIX};
use onomancy_dnssec::supported_name::SupportedName;
use wasm_bindgen::prelude::*;

/// The 32 payload bytes of a doc anchor: the root document id, which
/// is an ed25519 verifying key.
///
/// The bytes-side counterpart of the `automerge:` anchors this module
/// emits (`RecordCandidate.document`, resolution outcomes): a consumer
/// whose own vocabulary is raw ids can convert without carrying a
/// bs58check decoder of its own. Accepts the anchor with or without
/// its scheme prefix.
///
/// # Errors
///
/// Throws for non-string input and for anything `Name` would reject as
/// a doc anchor: bad checksums, legacy 16-byte ids, non-canonical keys.
#[wasm_bindgen(js_name = docAnchorBytes)]
pub fn doc_anchor_bytes(anchor: &Text) -> Result<Vec<u8>, JsError> {
    let raw = text::read(anchor, "a document anchor")?;
    let parsed = DocAnchor::parse(raw.strip_prefix(SCHEME_PREFIX).unwrap_or(&raw))
        .map_err(|error| JsError::new(&error.to_string()))?;

    Ok(parsed.verifying_key().as_bytes().to_vec())
}

/// A parsed edgename (see `onomancy_dnssec::supported_name::SupportedName`).
#[wasm_bindgen(js_name = Name)]
#[derive(Debug, Clone)]
pub struct JsName(SupportedName);

#[wasm_bindgen(js_class = Name)]
impl JsName {
    /// Parse a raw string into a `Name`.
    ///
    /// Takes a `JsValue` rather than a `&str` on purpose: a `&str`
    /// parameter makes wasm-bindgen read `.length` off whatever it is
    /// handed, so `new Name(42)` faults inside the module and surfaces
    /// as `RuntimeError: memory access out of bounds` — an alarming
    /// diagnostic for an ordinary type error, in an API whose callers
    /// are untyped by construction.
    ///
    /// # Errors
    ///
    /// Throws a plain error for non-string input, and when the sigil is
    /// missing, the anchor is malformed, or any path segment is invalid.
    #[wasm_bindgen(constructor)]
    pub fn new(raw: &Text) -> Result<JsName, JsError> {
        let raw = text::read(raw, "a name")?;

        Ok(Self(SupportedName::parse(&raw)?))
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
