//! Offline transport tests for the `DoH` courier: a fake
//! `globalThis.fetch` returning synthesized `Response`s, so every
//! error path of `exchange`/`query` runs deterministically with no
//! network — under the same `ci-browser` job as the rest of the wasm
//! suite. Before this file, those paths ran only in the off-CI live
//! smoke, i.e. never.

#![cfg(all(target_arch = "wasm32", feature = "doh"))]
// House pattern for test code: a failed `expect` here is the test
// failing, which is its job.
#![allow(clippy::expect_used, clippy::panic)]

use std::{cell::RefCell, rc::Rc};

use hickory_proto::op::{Message, MessageType, OpCode};
use js_sys::{Object, Promise, Reflect, Uint8Array};
use onomancy_dnssec::{chain_provider::ChainProvider as _, dns_name::DnsName};
use onomancy_wasm::{
    doh::{DohError, DohProvider, FetchChainError},
    text::Text,
};
use wasm_bindgen::{closure::Closure, JsCast as _, JsValue};
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::wasm_bindgen_test;
use web_sys::{Headers, Request, Response, ResponseInit};

/// Install a fake `globalThis.fetch` that answers every request with
/// `respond(request)`. Overwrites any previous fake; each test
/// installs its own.
fn install_fetch(respond: impl Fn(Request) -> Promise + 'static) {
    let fetch = Closure::wrap(Box::new(respond) as Box<dyn Fn(Request) -> Promise>);
    Reflect::set(
        &js_sys::global(),
        &JsValue::from_str("fetch"),
        fetch.as_ref().unchecked_ref(),
    )
    .expect("global fetch is writable");
    fetch.forget();
}

/// A promise already resolved with `value` — typed through `JsValue`
/// so `Promise::resolve`'s generic has one answer.
fn resolved(value: JsValue) -> Promise {
    Promise::resolve(&value)
}

/// A synthesized `Response` with `status` and `body`.
fn response(status: u16, body: &[u8]) -> Response {
    let init = ResponseInit::new();
    init.set_status(status);

    let mut bytes = body.to_vec();
    Response::new_with_opt_u8_array_and_init(Some(&mut bytes), &init)
        .expect("a Response synthesizes")
}

/// One drive of the courier: the fake fetch answers the FIRST
/// question (the root DNSKEY), which is as far as any of these
/// scripted failures lets the walk get.
async fn fetch_outcome() -> Result<(), FetchChainError> {
    let hostname = DnsName::parse("example.com").expect("valid hostname");
    DohProvider::new("https://doh.test/dns-query")
        .chain(&hostname)
        .await
        .map(|_| ())
}

/// A non-2xx status is `Status` with the code — transport, never a
/// validity verdict.
#[wasm_bindgen_test]
async fn a_non_2xx_status_is_a_transport_error() {
    install_fetch(|_| resolved(response(500, &[]).into()));

    match fetch_outcome().await {
        Err(FetchChainError::Transport(DohError::Status { code: 500 })) => {}
        other => panic!("expected HTTP 500 to surface as Status, got {other:?}"),
    }
}

/// A declared `content-length` over the DNS wire maximum is refused
/// BEFORE buffering — the header, not the body, is what this arm
/// reads.
#[wasm_bindgen_test]
async fn an_oversized_declared_length_is_refused_before_buffering() {
    install_fetch(|_| {
        let headers = Headers::new().expect("headers");
        headers
            .set("content-length", "70000")
            .expect("content-length is settable on a synthesized response");

        let init = ResponseInit::new();
        init.set_status(200);
        init.set_headers(&headers.into());

        let mut bytes = vec![0u8; 4];
        let response = Response::new_with_opt_u8_array_and_init(Some(&mut bytes), &init)
            .expect("a Response synthesizes");
        resolved(response.into())
    });

    match fetch_outcome().await {
        Err(FetchChainError::Transport(DohError::Oversized { bytes: 70_000 })) => {}
        other => panic!("expected the declared length to be refused, got {other:?}"),
    }
}

/// A body over the DNS wire maximum with no declared length is
/// refused after buffering — the chunked-response half of the guard.
#[wasm_bindgen_test]
async fn an_oversized_buffered_body_is_refused() {
    install_fetch(|_| resolved(response(200, &vec![0u8; 70_000]).into()));

    match fetch_outcome().await {
        Err(FetchChainError::Transport(DohError::Oversized { bytes: 70_000 })) => {}
        other => panic!("expected the buffered length to be refused, got {other:?}"),
    }
}

/// Bytes that are not a DNS message are `Malformed` — a parse
/// failure, not a validity verdict and not a panic.
#[wasm_bindgen_test]
async fn garbage_bytes_are_malformed() {
    install_fetch(|_| resolved(response(200, &[0xFF; 10]).into()));

    match fetch_outcome().await {
        Err(FetchChainError::Transport(DohError::Malformed(_))) => {}
        other => panic!("expected garbage to be Malformed, got {other:?}"),
    }
}

/// A well-formed response under any ID but the fixed `DoH` ID (0) is
/// rejected: RFC 8484 matches responses by the HTTP exchange, so a
/// nonzero ID is an upstream answering some other question.
#[wasm_bindgen_test]
async fn a_nonzero_response_id_is_rejected() {
    install_fetch(|_| {
        let wire = Message::new(7, MessageType::Response, OpCode::Query)
            .to_vec()
            .expect("responses encode");
        resolved(response(200, &wire).into())
    });

    match fetch_outcome().await {
        Err(FetchChainError::Transport(DohError::IdMismatch)) => {}
        other => panic!("expected ID 7 to be rejected, got {other:?}"),
    }
}

/// `fetch` resolving to something that is not a `Response` is its own
/// error, not a trap inside the module.
#[wasm_bindgen_test]
async fn a_non_response_is_its_own_error() {
    install_fetch(|_| resolved(Object::new().into()));

    match fetch_outcome().await {
        Err(FetchChainError::Transport(DohError::NotAResponse)) => {}
        other => panic!("expected a non-Response to be refused, got {other:?}"),
    }
}

/// The RFC 8484 request shape: POST, `application/dns-message` both
/// directions, and query ID 0 (cache friendliness) — asserted by
/// capturing what the courier actually sends.
#[wasm_bindgen_test]
async fn the_request_is_rfc_8484_shaped() {
    #[derive(Debug, Default)]
    struct Captured {
        method: String,
        content_type: Option<String>,
        accept: Option<String>,
        id: [u8; 2],
    }

    let captured: Rc<RefCell<Option<Captured>>> = Rc::new(RefCell::new(None));
    let sink = Rc::clone(&captured);

    install_fetch(move |request: Request| {
        let sink = Rc::clone(&sink);
        wasm_bindgen_futures::future_to_promise(async move {
            let headers = request.headers();
            let body = JsFuture::from(request.array_buffer()?).await?;
            let bytes = Uint8Array::new(&body).to_vec();

            *sink.borrow_mut() = Some(Captured {
                method: request.method(),
                content_type: headers.get("content-type").unwrap_or(None),
                accept: headers.get("accept").unwrap_or(None),
                id: [
                    bytes.first().copied().unwrap_or(0xFF),
                    bytes.get(1).copied().unwrap_or(0xFF),
                ],
            });

            // Fail the exchange cheaply; the request was the point.
            Ok(response(500, &[]).into())
        })
    });

    let _outcome = fetch_outcome().await;

    let captured = captured.borrow_mut().take().expect("a request was sent");
    assert_eq!(captured.method, "POST");
    assert_eq!(
        captured.content_type.as_deref(),
        Some("application/dns-message")
    );
    assert_eq!(captured.accept.as_deref(), Some("application/dns-message"));
    assert_eq!(captured.id, [0, 0], "query ID 0 per RFC 8484");
}

/// A `dohUrl` that does not parse is `invalid-resolver-url`, decided
/// BEFORE any fetch — so this is offline-safe, and a regression to
/// `transport` (inviting a retry that can never succeed) fails here.
#[wasm_bindgen_test]
async fn a_malformed_resolver_url_is_the_callers_error_not_transport() {
    let text = |raw: &str| -> Text { JsValue::from_str(raw).unchecked_into() };

    let Err(refused) = onomancy_wasm::resolve::resolve_hostname(
        &text("example.com"),
        Some(text("not a url")),
        None,
    )
    .await
    else {
        panic!("a malformed resolver URL cannot resolve anything");
    };

    let reason = Reflect::get(&refused, &JsValue::from_str("reason"))
        .ok()
        .and_then(|value| value.as_string())
        .expect("a substantive refusal carries a reason");

    assert_eq!(reason, "invalid-resolver-url");
}
