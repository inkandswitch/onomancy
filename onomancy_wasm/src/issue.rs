//! Minting a certificate without holding a key.
//!
//! A Keyhive document's root signing key is destroyed at creation
//! (`EphemeralSigner`), so the only key able to sign a certificate for
//! such a document is an admin key held by whatever runtime owns it —
//! in a browser, that is Keyhive's own. Handing that key across this
//! boundary to save a round trip would trade the property worth having
//! for a convenience.
//!
//! So issuance is two calls with the signing in between:
//!
//! ```js
//! const fields = { rootDoc, signer, issuedAt, hostname };
//! const signature = await hive.signData(signableBytes(fields));
//! const bytes = encodeCertificate(fields, signature, carriage, chain);
//! ```
//!
//! This module never sees a signing key, which makes it a serializer
//! rather than a trusted party — the same posture `verifyCertificate`
//! has by taking bytes rather than a document set.
//!
//! Carriage entries are `bincode(StaticEvent)` blobs, the wire form
//! Keyhive already produces. Taking the wire form rather than a shape
//! mirroring any one extraction keeps this agnostic to who assembled
//! it: a hand-filtered bundle today, a scoped export later.

use js_sys::Uint8Array;
use onomancy_core::{anchor::doc::DocAnchor, delegation_chain::DelegationChain, time::UnixSeconds};
use onomancy_dnssec::{
    certificate::{Certificate, CertificateParams},
    chain::DnssecChain,
    dns_name::DnsName,
};
use wasm_bindgen::{JsError, prelude::wasm_bindgen};

use crate::text::{self, Text};

/// The bytes a signature must cover for this certificate.
///
/// Hand the result to whatever holds the admin key, then pass the
/// signature to [`encode_certificate`] with the *same* fields. The two
/// calls must agree: a signature covers the bytes it was given, so
/// changing a field in between produces a certificate that verifies
/// nowhere.
///
/// `signer` is the verifying key that will sign — supplied rather than
/// derived, because there is no signing key here to derive it from.
///
/// # Errors
///
/// Rejects for a malformed hostname, anchor, or signer key.
#[wasm_bindgen(js_name = signableBytes)]
pub fn signable_bytes(
    root_doc: &str,
    signer: &[u8],
    issued_at: f64,
    hostname: &Text,
) -> Result<Uint8Array, JsError> {
    let (params, signer) = parts(root_doc, signer, issued_at, hostname)?;

    Ok(Uint8Array::from(
        Certificate::signable_bytes(&params, signer).as_slice(),
    ))
}

/// Assemble a certificate from fields, an outside signature, a
/// carriage, and a DNSSEC chain.
///
/// The fields must be **byte-identical** to those passed to
/// [`signable_bytes`], since the signature covers them.
///
/// `carriage` is a list of `bincode(StaticEvent)` blobs. `chain` is a
/// framed `DnssecChain` — `resolveHostname` returns one ready to pass
/// straight through.
///
/// Neither the carriage nor the chain is validated here. They are
/// unsigned evidence and the verifier judges them; a second judge at
/// assembly could only disagree with the first, and refusing at birth
/// for a reason the verifier would have accepted is worse than failing
/// where the judging happens.
///
/// # Errors
///
/// Rejects for malformed inputs, a signature that does not cover the
/// signed region under `signer`, and an assembled unit over the cap.
#[wasm_bindgen(js_name = encodeCertificate)]
// `Vec<Uint8Array>` rather than a slice: wasm-bindgen's ABI has no
// `RefFromWasmAbi` for `[Uint8Array]`, and the owned form is what
// publishes as `Uint8Array[]` in the `.d.ts`.
#[allow(clippy::needless_pass_by_value)]
pub fn encode_certificate(
    root_doc: &str,
    signer: &[u8],
    issued_at: f64,
    hostname: &Text,
    signature: &[u8],
    carriage: Vec<Uint8Array>,
    chain: &[u8],
) -> Result<Uint8Array, JsError> {
    let (mut params, signer) = parts(root_doc, signer, issued_at, hostname)?;

    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| JsError::new("a signature must be 64 bytes"))?;

    params.delegation_chain = DelegationChain::from(
        carriage
            .iter()
            .map(|entry| entry.to_vec().into())
            .collect::<Vec<_>>(),
    );

    params.chain = DnssecChain::read_framed(chain)
        .map_err(|error| JsError::new(&format!("chain: {error}")))?;

    let certificate = Certificate::from_parts(params, signer, signature.into())
        .map_err(|error| JsError::new(&error.to_string()))?;

    Ok(Uint8Array::from(certificate.encode().as_slice()))
}

/// The shared field parsing, so the two calls cannot disagree about
/// what they were given.
fn parts(
    root_doc: &str,
    signer: &[u8],
    issued_at: f64,
    hostname: &Text,
) -> Result<(CertificateParams, ed25519_dalek::VerifyingKey), JsError> {
    let root_doc = DocAnchor::parse(root_doc.trim_start_matches("automerge:"))
        .map_err(|error| JsError::new(&format!("rootDoc: {error}")))?;

    let signer: [u8; 32] = signer
        .try_into()
        .map_err(|_| JsError::new("a signer key must be 32 bytes"))?;

    let signer = ed25519_dalek::VerifyingKey::from_bytes(&signer)
        .map_err(|_| JsError::new("signer: not a valid ed25519 verifying key"))?;

    let hostname = DnsName::parse_display(&text::read(hostname, "a hostname")?)
        .map_err(|error| JsError::new(&error.to_string()))?;

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // epoch seconds fit
    let issued_at = UnixSeconds::from(issued_at.max(0.0) as u64);

    Ok((
        CertificateParams {
            root_doc,
            issued_at,
            hostname,
            heads: Vec::new(),
            predecessor: None,
            delegation_chain: DelegationChain::default(),
            lineage: Vec::new(),
            chain: DnssecChain::default(),
        },
        signer,
    ))
}
