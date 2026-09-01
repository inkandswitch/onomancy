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

use crate::{
    clock, refusal,
    shapes::JsVerdict,
    text::{self, Text},
};
use js_sys::{Object, Reflect};
use onomancy_core::time::UnixSeconds;
use onomancy_dnssec::{
    dns_name::DnsName,
    freshness::{Freshness, ValidityWindow},
    validator::Validator,
};
use onomancy_keyhive::authority::KeyhiveAuthority;
use onomancy_protocol::verifier::verdict::{
    self, DeferredEvidence, GenerationCheck, Rejection, Verdict,
};
use wasm_bindgen::{JsCast as _, JsError, JsValue, prelude::wasm_bindgen};

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
/// Returns:
///
/// Returns a `Verdict`; its members and their unions are declared in
/// the published `.d.ts`.
///
/// `freshness` carries the same three grades as `resolveHostname`, so
/// one axis is read one way across both. `deferred` means the
/// evidence is proven but its window has not opened — usually a clock
/// difference, never a forgery — and `window` against `checkedAt` is
/// what lets a caller tell those apart rather than take the label's
/// word for it.
///
/// Note the inversion: **strictness rises with freshness**. A fresh
/// chain whose generation key is off-path is refused, because a fresh
/// chain is authoritative enough to convict; the same condition on a
/// stale chain is only `"provisional"`, because stale evidence is
/// unrefreshed rather than authoritative. `if (fresh) accept` has
/// this backwards.
///
/// # Errors
///
/// Rejects for a malformed hostname, and for any certificate that
/// fails verification — see [`rejection_message`] for what each
/// refusal means.
#[wasm_bindgen(js_name = verifyCertificate)]
pub fn verify_certificate(
    bytes: &[u8],
    hostname: &Text,
    now_seconds: Option<f64>,
) -> Result<JsVerdict, JsValue> {
    let hostname = parse_hostname(hostname).map_err(JsValue::from)?;
    let now = clock::resolve(now_seconds);

    match verdict::verify(bytes, &hostname, now, &Validator::iana(), &KeyhiveAuthority) {
        Ok(verdict) => Ok(verdict_object(&verdict, now)),

        // Deferral is a grade, not a refusal: the evidence is proven
        // and simply not in force yet. Returned as a value so one
        // freshness axis is read one way across both entry points.
        Err(Rejection::Deferred(evidence)) => Ok(deferred_object(&hostname, &evidence, now)),

        Err(rejection) => Err(refusal::error(
            &rejection_message(&rejection),
            refusal::reason(&rejection),
        )),
    }
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
    hostname: &Text,
    now_seconds: Option<f64>,
) -> Result<JsVerdict, JsValue> {
    let hostname = parse_hostname(hostname).map_err(JsValue::from)?;
    let now = clock::resolve(now_seconds);
    let anchor = parse_anchor(anchor).map_err(JsValue::from)?;

    let mut documents = HeldDocuments::default();
    for (held_anchor, doc) in held.documents() {
        documents = documents.with(*held_anchor, doc.clone());
    }

    let stored = certificates::certificates(&documents, &anchor)
        .map_err(|malformed| JsValue::from(JsError::new(&malformed.to_string())))?;

    if stored.is_empty() {
        // Unavailable from this source is never proof of no binding:
        // absence is not provable, so this reason is deliberately
        // distinct from a refusal of evidence actually seen.
        return Err(refusal::error(
            "no certificate held for this document — it may be unavailable rather than absent",
            "no-certificate-held",
        ));
    }

    let mut last = None;
    for bytes in &stored {
        match verdict::verify(bytes, &hostname, now, &Validator::iana(), &KeyhiveAuthority) {
            Ok(verdict) => return Ok(verdict_object(&verdict, now)),

            // A deferred certificate is this hostname's and proven;
            // only its window is ahead of the clock. Grading it here
            // keeps both entry points on one freshness axis.
            Err(Rejection::Deferred(evidence)) => {
                return Ok(deferred_object(&hostname, &evidence, now));
            }

            // A certificate for one of the document's OTHER hostnames
            // is not an error; keep looking.
            Err(rejection) => last = Some(rejection),
        }
    }

    match last {
        Some(rejection) => Err(refusal::error(
            &format!(
                "no certificate in this document binds that hostname (last: {})",
                rejection_message(&rejection)
            ),
            refusal::reason(&rejection),
        )),
        None => Err(refusal::error(
            "no certificate in this document binds that hostname",
            "no-certificate-held",
        )),
    }
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
fn verdict_object(verdict: &Verdict, now: UnixSeconds) -> JsVerdict {
    grade_object(
        verdict.certificate.hostname().as_str(),
        &verdict.document.to_string(),
        &verdict.serial.to_string(),
        match verdict.freshness {
            Freshness::Fresh => "fresh",
            Freshness::Stale => "stale",
        },
        Some(match verdict.generation_check {
            GenerationCheck::OnPath => "on-path",
            GenerationCheck::Provisional => "provisional",
        }),
        &verdict.window,
        now,
    )
}

/// A deferred grade: proven evidence that is not in force yet.
///
/// Same key set as a verdict, because a caller should read one
/// freshness axis one way. `generation` is explicitly `null` rather
/// than absent: deferral precedes the D10 decision, so the check was
/// not made — which is a different thing from being made and
/// forgotten, and a missing key cannot say so.
fn deferred_object(hostname: &DnsName, evidence: &DeferredEvidence, now: UnixSeconds) -> JsVerdict {
    grade_object(
        hostname.as_str(),
        &evidence.document.to_string(),
        &evidence.serial.to_string(),
        "deferred",
        None,
        &evidence.window,
        now,
    )
}

/// The one shape both grades share.
fn grade_object(
    hostname: &str,
    document: &str,
    serial: &str,
    freshness: &str,
    generation: Option<&str>,
    validity: &ValidityWindow,
    now: UnixSeconds,
) -> JsVerdict {
    let object = Object::new();
    let set = |target: &Object, key: &str, value: &JsValue| {
        // Reflect::set on a fresh plain object cannot fail.
        drop(Reflect::set(target, &JsValue::from_str(key), value));
    };

    // Epoch seconds are exact in an f64 for any reachable value.
    #[allow(clippy::cast_precision_loss)]
    let seconds = |value: UnixSeconds| JsValue::from_f64(value.value() as f64);

    let window = Object::new();
    set(&window, "inception", &seconds(validity.inception()));
    set(&window, "expiration", &seconds(validity.expiration()));

    set(&object, "hostname", &JsValue::from_str(hostname));
    set(&object, "document", &JsValue::from_str(document));
    set(&object, "serial", &JsValue::from_str(serial));
    set(&object, "freshness", &JsValue::from_str(freshness));
    set(
        &object,
        "generation",
        &generation.map_or(JsValue::NULL, JsValue::from_str),
    );
    set(&object, "window", &window.into());
    set(&object, "checkedAt", &seconds(now));

    object.unchecked_into()
}

/// Why a certificate was refused, in terms a caller can act on.
///
/// Deliberately not the `Debug` form: these strings reach users, and
/// a rejection is a statement about evidence, not a stack trace.
fn rejection_message(rejection: &Rejection) -> String {
    match rejection {
        Rejection::GenerationOffPath => String::from(
            "the signer's generation is no longer attested by the zone — \
             the key was rotated away, which is how revocation works",
        ),
        // Deferral is returned as a grade, never as a refusal.
        Rejection::Deferred(_) => String::from(
            "not considered yet: the chain's validity window has not opened \
             (usually a clock difference, never a forgery)",
        ),
        // The rest already say what they mean.
        other @ (Rejection::ChainRejected
        | Rejection::Decode(_)
        | Rejection::HostnameMismatch { .. }) => other.to_string(),
    }
}

/// Typed `string` for TypeScript, checked at runtime anyway — see
/// [`crate::hostname`] for why the declaration and the check are
/// separate concerns here.
fn parse_hostname(raw: &Text) -> Result<DnsName, JsError> {
    let raw = text::read(raw, "a hostname")?;

    DnsName::parse_display(&raw).map_err(|error| JsError::new(&error.to_string()))
}

#[cfg(feature = "names")]
fn parse_anchor(raw: &str) -> Result<DocAnchor, JsError> {
    let bare = raw
        .strip_prefix(onomancy_core::anchor::doc::SCHEME_PREFIX)
        .unwrap_or(raw);

    DocAnchor::parse(bare).map_err(|error| JsError::new(&error.to_string()))
}
