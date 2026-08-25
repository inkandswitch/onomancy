//! The live-resolution JS export: fetch, validate, and grade a
//! hostname's Onomancy binding in one call.

use js_sys::{Array, Date, Object, Reflect};
use onomancy_core::time::UnixSeconds;
use onomancy_dnssec::{
    chain_provider::ChainProvider, dns_name::DnsName, freshness::Grade, validator::Validator,
};
use wasm_bindgen::{JsError, JsValue, prelude::wasm_bindgen};

use crate::doh::DohProvider;

/// Resolve a hostname's Onomancy binding live over `DoH`: fetch the
/// chain, validate it from the baked-in IANA anchors, and grade it at
/// the current time.
///
/// Returns `{ hostname, links, freshness, records: string[] }`.
///
/// # Errors
///
/// Rejects (as a JS error) on malformed hostnames, transport
/// failures, and invalid chains.
#[wasm_bindgen(js_name = resolveHostname)]
pub async fn resolve_hostname(hostname: &str, doh_url: Option<String>) -> Result<JsValue, JsError> {
    let hostname =
        DnsName::parse_display(hostname).map_err(|error| JsError::new(&error.to_string()))?;
    let provider = doh_url.map_or_else(DohProvider::cloudflare, DohProvider::new);

    let chain = provider
        .chain(&hostname)
        .await
        .map_err(|error| JsError::new(&error.to_string()))?;

    let proof = Validator::iana()
        .validate_detailed(&hostname, &chain)
        .map_err(|error| JsError::new(&error.to_string()))?;

    // The JS clock, as a value — grading is the only place it enters.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // epoch seconds fit
    let now = UnixSeconds::from((Date::now() / 1000.0) as u64);
    let freshness = match proof.window.grade(now) {
        Grade::Fresh => "fresh",
        Grade::Stale => "stale",
        Grade::NotYetBegun => "deferred",
    };

    let records = Array::new();
    for record in &proof.records {
        records.push(&JsValue::from_str(&record.to_string()));
    }

    let links = match u32::try_from(chain.links().len()) {
        Ok(count) => count,
        // No chain holds four billion links; saturate for JS.
        Err(_) => u32::MAX,
    };

    let verdict = Object::new();
    let set = |key: &str, value: &JsValue| {
        // Reflect::set on a fresh plain object cannot fail.
        drop(Reflect::set(&verdict, &JsValue::from_str(key), value));
    };
    set("hostname", &JsValue::from_str(hostname.as_str()));
    set("links", &JsValue::from_f64(links.into()));
    set("freshness", &JsValue::from_str(freshness));
    set("records", &records.into());

    Ok(verdict.into())
}
