//! DNS-over-HTTPS chain courier (RFC 8484) for browsers and workers.
//!
//! The same [`chain_assembly`](onomancy_hickory::chain_assembly)
//! logic as the host courier, over `fetch()` instead of sockets: POST
//! `application/dns-message` bodies to one `DoH` endpoint, message ID 0
//! (RFC 8484 cache friendliness). The transport is exactly as
//! untrusted as the socket one — the verifier's own DNSSEC
//! validation is the only trust boundary, and `DoH` merely narrows who
//! sees the queries (the on-path observer becomes the `DoH` resolver).

use hickory_proto::{
    op::Message,
    rr::{Name, Record, RecordType},
};
use js_sys::{Reflect, Uint8Array};
use onomancy_core::{cert::chain::DnssecChain, name::dns::DnsName};
use onomancy_hickory::chain_assembly::{self, AssembleError, Query, Refused};
use onomancy_protocol::chain_provider::ChainProvider;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, Response};

/// The RFC 8484 media type, both directions.
const DNS_MESSAGE: &str = "application/dns-message";

/// The `DoH` chain courier: [`ChainProvider`] over one `DoH` endpoint.
#[derive(Debug, Clone)]
pub struct DohProvider {
    url: String,
}

impl DohProvider {
    /// A provider `POSTing` to `url` (a full `DoH` endpoint, e.g.
    /// `https://cloudflare-dns.com/dns-query`).
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }

    /// Cloudflare's public `DoH` endpoint.
    #[must_use]
    pub fn cloudflare() -> Self {
        Self::new("https://cloudflare-dns.com/dns-query")
    }

    /// One HTTP exchange: wire-format query out, wire-format
    /// response back.
    async fn exchange(&self, wire: &[u8]) -> Result<Vec<u8>, DohError> {
        let headers = Headers::new().map_err(|failure| js_failure(&failure))?;
        headers
            .set("content-type", DNS_MESSAGE)
            .map_err(|failure| js_failure(&failure))?;
        headers
            .set("accept", DNS_MESSAGE)
            .map_err(|failure| js_failure(&failure))?;

        let init = RequestInit::new();
        init.set_method("POST");
        init.set_headers(&headers.into());
        init.set_body(&Uint8Array::from(wire).into());

        let request = Request::new_with_str_and_init(&self.url, &init)
            .map_err(|failure| js_failure(&failure))?;

        // `fetch` from the global scope: works in windows, workers,
        // and other JS hosts alike (no `Window` assumption).
        let global = js_sys::global();
        let fetch: js_sys::Function = Reflect::get(&global, &JsValue::from_str("fetch"))
            .map_err(|failure| js_failure(&failure))?
            .dyn_into()
            .map_err(|_| DohError::NoFetch)?;
        let promise: js_sys::Promise = fetch
            .call1(&global, &request)
            .map_err(|failure| js_failure(&failure))?
            .dyn_into()
            .map_err(|_| DohError::NoFetch)?;

        let response: Response = JsFuture::from(promise)
            .await
            .map_err(|failure| js_failure(&failure))?
            .dyn_into()
            .map_err(|_| DohError::NotAResponse)?;

        if !response.ok() {
            return Err(DohError::Status {
                code: response.status(),
            });
        }

        let buffer = JsFuture::from(
            response
                .array_buffer()
                .map_err(|failure| js_failure(&failure))?,
        )
        .await
        .map_err(|failure| js_failure(&failure))?;
        Ok(Uint8Array::new(&buffer).to_vec())
    }
}

impl Query for DohProvider {
    type Error = DohError;

    async fn answers(&self, name: &Name, rtype: RecordType) -> Result<Vec<Record>, DohError> {
        // ID 0 per RFC 8484: DoH responses are matched by the HTTP
        // exchange, and a fixed ID keeps them cacheable.
        let request = chain_assembly::build_query(name, rtype, 0);
        let wire = request.to_vec().map_err(|_| DohError::Encode)?;

        let message =
            Message::from_vec(&self.exchange(&wire).await?).map_err(|_| DohError::Malformed)?;

        if message.metadata.id != 0 {
            return Err(DohError::IdMismatch);
        }

        Ok(chain_assembly::accepted_answers(message)?)
    }
}

impl ChainProvider for DohProvider {
    type Error = AssembleError<DohError>;

    async fn chain(&self, hostname: &DnsName) -> Result<DnssecChain, Self::Error> {
        chain_assembly::assemble(self, hostname).await
    }
}

/// A JS-side failure, stringified: `JsValue` is neither `Send` nor
/// `Error`, so the message is all that can cross this boundary.
fn js_failure(value: &JsValue) -> DohError {
    DohError::Js {
        message: format!("{value:?}"),
    }
}

/// A `DoH` exchange failed at the transport level — never a validity
/// verdict.
#[derive(Debug, thiserror::Error)]
pub enum DohError {
    /// The request could not be encoded (oversized name, internal).
    #[error("query could not be encoded")]
    Encode,

    /// The response ID was not the fixed `DoH` ID.
    #[error("response ID mismatch")]
    IdMismatch,

    /// A JS API failed (network error, CORS, invalid URL, …).
    #[error("fetch failed: {message}")]
    Js {
        /// The stringified JS error.
        message: String,
    },

    /// The response bytes did not parse as a DNS message.
    #[error("malformed DNS response")]
    Malformed,

    /// No `fetch` in the global scope (not a browser/worker host).
    #[error("no global fetch()")]
    NoFetch,

    /// `fetch` resolved to something other than a `Response`.
    #[error("fetch yielded a non-Response")]
    NotAResponse,

    /// The upstream refused the query (SERVFAIL, REFUSED, …).
    #[error(transparent)]
    Refused(#[from] Refused),

    /// A non-2xx HTTP status.
    #[error("HTTP status {code}")]
    Status {
        /// The status code.
        code: u16,
    },
}

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
#[wasm_bindgen::prelude::wasm_bindgen(js_name = resolveHostname)]
pub async fn resolve_hostname(
    hostname: &str,
    doh_url: Option<String>,
) -> Result<JsValue, wasm_bindgen::JsError> {
    use wasm_bindgen::JsError;

    let hostname =
        DnsName::parse_display(hostname).map_err(|error| JsError::new(&error.to_string()))?;
    let provider = doh_url.map_or_else(DohProvider::cloudflare, DohProvider::new);

    let chain = provider
        .chain(&hostname)
        .await
        .map_err(|error| JsError::new(&error.to_string()))?;

    let proof = onomancy_dnssec::validator::Validator::iana()
        .validate_detailed(&hostname, &chain)
        .map_err(|error| JsError::new(&error.to_string()))?;

    // The JS clock, as a value — grading is the only place it enters.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // epoch seconds fit
    let now = onomancy_core::time::UnixSeconds::from((js_sys::Date::now() / 1000.0) as u64);
    let freshness = match proof.window.grade(now) {
        onomancy_core::freshness::Grade::Fresh => "fresh",
        onomancy_core::freshness::Grade::Stale => "stale",
        onomancy_core::freshness::Grade::NotYetBegun => "deferred",
    };

    let records = js_sys::Array::new();
    for record in &proof.records {
        records.push(&JsValue::from_str(&record.to_string()));
    }

    let verdict = js_sys::Object::new();
    let set = |key: &str, value: &JsValue| {
        // Reflect::set on a fresh plain object cannot fail.
        drop(Reflect::set(&verdict, &JsValue::from_str(key), value));
    };
    set("hostname", &JsValue::from_str(hostname.as_str()));
    set(
        "links",
        &JsValue::from_f64(
            u32::try_from(chain.links().len())
                .unwrap_or(u32::MAX)
                .into(),
        ),
    );
    set("freshness", &JsValue::from_str(freshness));
    set("records", &records.into());

    Ok(verdict.into())
}
