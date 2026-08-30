//! Certificate verification: the half a DNSSEC walk cannot do.
//!
//! `resolveHostname` proves what a *zone* published — that
//! `example.com` names document `D`. That is one direction, and DNS
//! can only ever carry one direction: anyone who controls any signed
//! zone may point it at any document. What closes the loop is a
//! certificate, issued by a key the document delegated, naming the
//! hostname back.
//!
//! ```text
//! DNS  ──▶ "example.com is bound to D"       zone-attested, DNSSEC-proven
//!            ⇕  both required
//! cert ──▶ "D accepts example.com"           signed by a delegate of D
//! ```
//!
//! Both checks run locally, from the baked-in IANA anchors and the
//! certificate's own delegation carriage. The carriage is replayed
//! into a throwaway Keyhive instance per question and discarded, so
//! nothing here shares state with a host's own Keyhive — verdicts
//! depend only on the evidence presented.

use js_sys::{Date, Object, Reflect};
use onomancy_core::time::UnixSeconds;
use onomancy_dnssec::{dns_name::DnsName, freshness::Freshness, validator::Validator};
use onomancy_keyhive::authority::KeyhiveAuthority;
use onomancy_protocol::verifier::verdict::{self, GenerationCheck, Rejection, Verdict};
use wasm_bindgen::{JsError, JsValue, prelude::wasm_bindgen};

// Reading a certificate OUT OF a document needs the document
// substrate; verifying bytes does not. Only the former is gated.
#[cfg(feature = "names")]
use {
    crate::held::JsHeldDocuments,
    onomancy_automerge::{certificates, namestore::HeldDocuments},
    onomancy_core::anchor::doc::DocAnchor,
};

/// Verify one certificate against `hostname` at `now_seconds`
/// (default: the host clock).
///
/// Use this for bytes that arrived out of band — gossiped at a
/// campout, carried on a USB stick, scanned from a QR code. A
/// certificate is self-authenticating, so where it came from confers
/// nothing and costs nothing: a hostile courier can withhold or serve
/// stale, never forge.
///
/// Returns the verdict described in [`verdict_object`].
///
/// # Errors
///
/// Rejects for a malformed hostname, and for any certificate that
/// fails verification — see [`rejection_message`] for what each
/// refusal means.
#[wasm_bindgen(js_name = verifyCertificate)]
pub fn verify_certificate(
    bytes: &[u8],
    hostname: &JsValue,
    now_seconds: Option<f64>,
) -> Result<JsValue, JsError> {
    let hostname = parse_hostname(hostname)?;
    let now = clock(now_seconds);

    let verdict = verdict::verify(bytes, &hostname, now, &Validator::iana(), &KeyhiveAuthority)
        .map_err(|rejection| JsError::new(&rejection_message(&rejection)))?;

    Ok(verdict_object(&verdict, now))
}

/// Verify the binding a held document claims for `hostname`.
///
/// Reads the document's certificates from the reserved well-known
/// path, following at most one hop of indirection, and verifies each
/// against `hostname`. The first that verifies wins; a document
/// naming several hostnames carries several certificates, and the
/// ones for other names are simply not this hostname's.
///
/// The document must already be held — replication is the substrate's
/// job, not this module's. Use `hold()` to supply it.
///
/// # Errors
///
/// Rejects for a malformed hostname or anchor, a malformed
/// certificate location, and when no certificate in the document
/// verifies for this hostname.
#[cfg(feature = "names")]
#[wasm_bindgen(js_name = verifyBinding)]
pub fn verify_binding(
    held: &JsHeldDocuments,
    anchor: &str,
    hostname: &JsValue,
    now_seconds: Option<f64>,
) -> Result<JsValue, JsError> {
    let hostname = parse_hostname(hostname)?;
    let now = clock(now_seconds);
    let anchor = parse_anchor(anchor)?;

    let mut documents = HeldDocuments::default();
    for (held_anchor, doc) in held.documents() {
        documents = documents.with(*held_anchor, doc.clone());
    }

    let stored = certificates::certificates(&documents, &anchor)
        .map_err(|malformed| JsError::new(&malformed.to_string()))?;

    if stored.is_empty() {
        // Unavailable from this source is never proof of no binding:
        // absence is not provable.
        return Err(JsError::new(
            "no certificate held for this document — it may be unavailable rather than absent",
        ));
    }

    let mut last = None;
    for bytes in &stored {
        match verdict::verify(bytes, &hostname, now, &Validator::iana(), &KeyhiveAuthority) {
            Ok(verdict) => return Ok(verdict_object(&verdict, now)),
            // A certificate for one of the document's OTHER hostnames
            // is not an error; keep looking.
            Err(rejection) => last = Some(rejection),
        }
    }

    Err(JsError::new(&match last {
        Some(rejection) => format!(
            "no certificate in this document binds that hostname (last: {})",
            rejection_message(&rejection)
        ),
        None => String::from("no certificate in this document binds that hostname"),
    }))
}

/// The shape both entry points return:
///
/// ```text
/// {
///   hostname, document, serial,
///   freshness: "fresh" | "stale",
///   generation: "on-path" | "provisional",
///   window: { inception, expiration },
///   checkedAt,
/// }
/// ```
///
/// `window` and `checkedAt` are the inputs to the freshness decision,
/// returned so a caller can check the work: `checkedAt -
/// window.expiration` is how far a stale chain has lapsed, and
/// comparing `checkedAt` to the caller's own clock detects skew,
/// which is otherwise indistinguishable from staleness.
fn verdict_object(verdict: &Verdict, now: UnixSeconds) -> JsValue {
    let object = Object::new();
    let set = |key: &str, value: &JsValue| {
        // Reflect::set on a fresh plain object cannot fail.
        drop(Reflect::set(&object, &JsValue::from_str(key), value));
    };

    // Epoch seconds are exact in an f64 for any reachable value.
    #[allow(clippy::cast_precision_loss)]
    let seconds = |value: UnixSeconds| JsValue::from_f64(value.value() as f64);

    let window = Object::new();
    drop(Reflect::set(
        &window,
        &JsValue::from_str("inception"),
        &seconds(verdict.window.inception()),
    ));
    drop(Reflect::set(
        &window,
        &JsValue::from_str("expiration"),
        &seconds(verdict.window.expiration()),
    ));

    set(
        "hostname",
        &JsValue::from_str(verdict.certificate.hostname().as_str()),
    );
    set(
        "document",
        &JsValue::from_str(&verdict.document.to_string()),
    );
    set("serial", &JsValue::from_str(&verdict.serial.to_string()));
    set(
        "freshness",
        &JsValue::from_str(match verdict.freshness {
            Freshness::Fresh => "fresh",
            Freshness::Stale => "stale",
        }),
    );
    set(
        "generation",
        &JsValue::from_str(match verdict.generation_check {
            GenerationCheck::OnPath => "on-path",
            GenerationCheck::Provisional => "provisional",
        }),
    );
    set("window", &window.into());
    set("checkedAt", &seconds(now));

    object.into()
}

/// Why a certificate was refused, in terms a caller can act on.
///
/// Deliberately not the `Debug` form: these strings reach users, and
/// a rejection is a statement about evidence, not a stack trace.
fn rejection_message(rejection: &Rejection) -> String {
    match rejection {
        Rejection::Deferred => String::from(
            "not considered yet: the chain's validity window has not opened \
             (usually a clock difference, never a forgery)",
        ),
        Rejection::GenerationOffPath => String::from(
            "the signer's generation is no longer attested by the zone — \
             the key was rotated away, which is how revocation works",
        ),
        // The rest already say what they mean.
        other @ (Rejection::ChainRejected
        | Rejection::Decode(_)
        | Rejection::HostnameMismatch { .. }) => other.to_string(),
    }
}

/// Segments and hostnames arrive from untyped callers; a `&str`
/// parameter would fault inside the module on non-string input.
fn parse_hostname(raw: &JsValue) -> Result<DnsName, JsError> {
    let raw = raw
        .as_string()
        .ok_or_else(|| JsError::new("a hostname must be a string"))?;

    DnsName::parse_display(&raw).map_err(|error| JsError::new(&error.to_string()))
}

#[cfg(feature = "names")]
fn parse_anchor(raw: &str) -> Result<DocAnchor, JsError> {
    let bare = raw
        .strip_prefix(onomancy_core::anchor::doc::SCHEME_PREFIX)
        .unwrap_or(raw);

    DocAnchor::parse(bare).map_err(|error| JsError::new(&error.to_string()))
}

/// The clock, as a value — grading is the only place it enters, and
/// the caller may supply it so a captured chain grades deterministically.
fn clock(now_seconds: Option<f64>) -> UnixSeconds {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // epoch seconds fit
    UnixSeconds::from((now_seconds.unwrap_or_else(Date::now).max(0.0) / 1000.0) as u64)
}
