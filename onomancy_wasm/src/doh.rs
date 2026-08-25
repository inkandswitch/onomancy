//! DNS-over-HTTPS chain courier (RFC 8484) for browsers and workers.
//!
//! The same sans-IO chain builder (`onomancy_chain`) as the
//! host courier, driven over `fetch()` instead of sockets: POST
//! `application/dns-message` bodies to one `DoH` endpoint, message ID 0
//! (RFC 8484 cache friendliness). The transport is exactly as
//! untrusted as the socket one — the verifier's own DNSSEC
//! validation is the only trust boundary, and `DoH` merely narrows who
//! sees the queries (the on-path observer becomes the `DoH` resolver).

use hickory_proto::{ProtoError, op::Message, rr::Record, serialize::binary::DecodeError};
use js_sys::{Function, Promise, Reflect, Uint8Array, global};
use onomancy_chain::{
    answer::{self, Refused},
    builder::{BuildError, ChainBuilder, Step},
    question::Question,
};
use onomancy_core::{cert::chain::DnssecChain, name::dns::DnsName};
use onomancy_protocol::chain_provider::ChainProvider;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, Response};

/// The RFC 8484 media type, both directions.
const DNS_MESSAGE: &str = "application/dns-message";

/// The largest body accepted from a `DoH` endpoint: the DNS wire
/// maximum (a 16-bit message length). Anything larger cannot be a DNS
/// message, and buffering it unbounded would hand a malicious
/// endpoint the verifier's memory.
const MAX_RESPONSE_BYTES: u64 = 65_535;

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
        let scope = global();
        let fetch: Function = Reflect::get(&scope, &JsValue::from_str("fetch"))
            .map_err(|failure| js_failure(&failure))?
            .dyn_into()
            .map_err(|_| DohError::NoFetch)?;
        let promise: Promise = fetch
            .call1(&scope, &request)
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

        // Refuse oversized bodies before buffering when the endpoint
        // declares a length; chunked responses carry none and are
        // re-checked after.
        if let Ok(Some(declared)) = response.headers().get("content-length")
            && let Ok(bytes) = declared.parse::<u64>()
            && bytes > MAX_RESPONSE_BYTES
        {
            return Err(DohError::Oversized { bytes });
        }

        let buffer = JsFuture::from(
            response
                .array_buffer()
                .map_err(|failure| js_failure(&failure))?,
        )
        .await
        .map_err(|failure| js_failure(&failure))?;

        let array = Uint8Array::new(&buffer);
        let bytes = u64::from(array.length());
        if bytes > MAX_RESPONSE_BYTES {
            return Err(DohError::Oversized { bytes });
        }

        Ok(array.to_vec())
    }

    /// Answer one of the chain builder's questions over `DoH`.
    async fn query(&self, question: &Question) -> Result<Vec<Record>, DohError> {
        // ID 0 per RFC 8484: DoH responses are matched by the HTTP
        // exchange, and a fixed ID keeps them cacheable.
        let request = question.message(0);
        let wire = request.to_vec().map_err(DohError::Encode)?;

        let message =
            Message::from_vec(&self.exchange(&wire).await?).map_err(DohError::Malformed)?;

        if message.metadata.id != 0 {
            return Err(DohError::IdMismatch);
        }

        Ok(answer::accepted(message)?)
    }
}

impl ChainProvider for DohProvider {
    type Error = FetchChainError;

    async fn chain(&self, hostname: &DnsName) -> Result<DnssecChain, Self::Error> {
        let (mut builder, mut question) = ChainBuilder::start(hostname)?;

        loop {
            let records = self.query(&question).await?;

            match builder.answer(records)? {
                Step::Ask(next, asked) => {
                    builder = next;
                    question = asked;
                }
                Step::Done(chain) => return Ok(chain),
            }
        }
    }
}

/// The `DoH` courier failed to fetch a chain — in the machine or on
/// the wire, never a validity verdict (that is the validator's).
#[derive(Debug, thiserror::Error)]
pub enum FetchChainError {
    /// The answers could not be framed into a chain.
    #[error(transparent)]
    Build(#[from] BuildError),

    /// A `DoH` exchange failed at the transport level.
    #[error(transparent)]
    Transport(#[from] DohError),
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
    /// The request could not be encoded to wire form.
    #[error("query could not be encoded")]
    Encode(#[source] ProtoError),

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
    Malformed(#[source] DecodeError),

    /// No `fetch` in the global scope (not a browser/worker host).
    #[error("no global fetch()")]
    NoFetch,

    /// `fetch` resolved to something other than a `Response`.
    #[error("fetch yielded a non-Response")]
    NotAResponse,

    /// The response body exceeds the DNS wire maximum.
    #[error("response of {bytes} bytes exceeds the DNS wire maximum")]
    Oversized {
        /// The declared or buffered body length.
        bytes: u64,
    },

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
