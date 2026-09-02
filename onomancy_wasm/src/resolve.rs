//! The live-resolution JS export: fetch, validate, and grade a
//! hostname's Onomancy binding in one call.

use js_sys::{Array, Object, Reflect, Uint8Array};
use onomancy_core::time::UnixSeconds;
use onomancy_dnssec::{
    chain_provider::ChainProvider, dns_name::DnsName, freshness::Grade, validator::Validator,
};
use wasm_bindgen::{JsCast as _, JsError, JsValue, prelude::wasm_bindgen};

use crate::{
    clock,
    doh::DohProvider,
    refusal,
    shapes::JsResolution,
    text::{self, Text},
};

/// Resolve a hostname's Onomancy binding live over `DoH`: fetch the
/// chain, validate it from the baked-in IANA anchors, and grade it at
/// `now_seconds` (default: the host clock).
///
/// Returns:
///
/// ```js
/// {
///   hostname, links, records: string[],
///   chain,                               // the validated chain, framed
///   freshness: "fresh" | "stale" | "deferred",
///   window: { inception, expiration },   // epoch seconds
///   checkedAt,                           // the clock reading used
/// }
/// ```
///
/// `chain` is the DNSSEC chain this call fetched and validated, in the
/// framing a certificate embeds. A certificate must carry its own
/// chain and this is the only call that obtains one, so minting from a
/// browser needs these bytes — pass them straight to
/// `encodeCertificate`.
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
    hostname: &Text,
    doh_url: Option<String>,
    now_seconds: Option<f64>,
) -> Result<JsResolution, JsValue> {
    // Typed `string` for TypeScript, checked at runtime anyway: a
    // `&str` parameter faults inside the module on non-string input.
    // No `reason`: a wrong-typed argument is a caller bug, not a
    // finding about the name.
    let hostname = text::read(hostname, "a hostname").map_err(JsValue::from)?;

    let hostname = DnsName::parse_display(&hostname).map_err(|error| {
        refusal::error(&error.to_string(), refusal::RefusalReason::InvalidHostname)
    })?;

    // Checked before the fetch, so a malformed resolver URL surfaces
    // as the caller error it is — never as `transport`, which invites
    // a retry that can never succeed.
    if let Some(url) = doh_url.as_deref()
        && web_sys::Url::new(url).is_err()
    {
        return Err(JsValue::from(JsError::new(&format!(
            "dohUrl is not a valid URL: {url}"
        ))));
    }

    let provider = doh_url.map_or_else(DohProvider::cloudflare, DohProvider::new);

    let chain = provider
        .chain(&hostname)
        .await
        .map_err(|error| refusal::error(&error.to_string(), refusal::walk_reason(&error)))?;

    let proof = Validator::iana()
        .validate_detailed(&hostname, &chain)
        .map_err(|error| refusal::error(&error.to_string(), refusal::validation_reason(&error)))?;

    let now = clock::resolve(now_seconds)
        .map_err(|error| JsValue::from(JsError::new(&error.to_string())))?;
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

    // The validated chain itself, framed exactly as
    // `CertificateParams.chain` consumes it. Returned because a
    // certificate must EMBED its chain, and this call is the only
    // thing that fetched one: reporting a link count while dropping
    // the bytes left a browser able to verify a binding and unable to
    // mint one.
    let mut framed = Vec::new();
    chain.write_framed(&mut framed);

    set("hostname", &JsValue::from_str(hostname.as_str()));
    set("chain", &Uint8Array::from(framed.as_slice()).into());
    set("links", &JsValue::from_f64(links.into()));
    set("freshness", &JsValue::from_str(freshness));
    set("records", &records.into());
    set("window", &window.into());
    set("checkedAt", &seconds(now));

    Ok(verdict.unchecked_into())
}
