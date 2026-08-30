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
/// `now_seconds` (default: the host clock).
///
/// Returns:
///
/// ```js
/// {
///   hostname, links, records: string[],
///   freshness: "fresh" | "stale" | "deferred",
///   window: { inception, expiration },   // epoch seconds
///   checkedAt,                           // the clock reading used
/// }
/// ```
///
/// `window` and `checkedAt` are the **inputs** to the freshness
/// decision, returned alongside it so a caller can check the work:
/// `checkedAt - window.expiration` is how far a stale chain has
/// lapsed (the graded-freshness spec asks verifiers to render
/// staleness by magnitude), and comparing `checkedAt` against the
/// caller's own clock detects skew, which is otherwise
/// indistinguishable from genuine staleness.
///
/// `now_seconds` makes grading deterministic for tests: chain
/// validation is pure over bytes and anchors, so one captured chain
/// can be graded at any instant.
///
/// # Errors
///
/// Rejects (as a JS error) on malformed hostnames, transport
/// failures, and invalid chains.
#[wasm_bindgen(js_name = resolveHostname)]
pub async fn resolve_hostname(
    hostname: &JsValue,
    doh_url: Option<String>,
    now_seconds: Option<f64>,
) -> Result<JsValue, JsError> {
    // `&JsValue` rather than `&str`: see `JsName::new` — a `&str`
    // parameter faults inside the module on non-string input.
    let hostname = hostname
        .as_string()
        .ok_or_else(|| JsError::new("a hostname must be a string"))?;

    let hostname =
        DnsName::parse_display(&hostname).map_err(|error| JsError::new(&error.to_string()))?;
    let provider = doh_url.map_or_else(DohProvider::cloudflare, DohProvider::new);

    let chain = provider
        .chain(&hostname)
        .await
        .map_err(|error| JsError::new(&error.to_string()))?;

    let proof = Validator::iana()
        .validate_detailed(&hostname, &chain)
        .map_err(|error| JsError::new(&error.to_string()))?;

    // The clock, as a value — grading is the only place it enters,
    // and the caller may supply it.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // epoch seconds fit
    let now = UnixSeconds::from((now_seconds.unwrap_or_else(Date::now).max(0.0) / 1000.0) as u64);
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
    // Epoch seconds are exact in an f64 for any reachable value.
    #[allow(clippy::cast_precision_loss)]
    let seconds = |value: UnixSeconds| JsValue::from_f64(value.value() as f64);

    let window = Object::new();
    // Same invariant as `set`: a fresh plain object cannot refuse a key.
    drop(Reflect::set(
        &window,
        &JsValue::from_str("inception"),
        &seconds(proof.window.inception()),
    ));
    drop(Reflect::set(
        &window,
        &JsValue::from_str("expiration"),
        &seconds(proof.window.expiration()),
    ));

    set("hostname", &JsValue::from_str(hostname.as_str()));
    set("links", &JsValue::from_f64(links.into()));
    set("freshness", &JsValue::from_str(freshness));
    set("records", &records.into());
    set("window", &window.into());
    set("checkedAt", &seconds(now));

    Ok(verdict.into())
}
